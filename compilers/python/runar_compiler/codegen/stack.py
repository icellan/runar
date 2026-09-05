"""Stack IR lowering -- converts ANF IR to Stack IR (Bitcoin Script stack ops).

This is the core code-generation pass of the Runar compiler.  It takes the
A-Normal Form intermediate representation and produces a sequence of abstract
stack-machine operations that map 1-to-1 to Bitcoin Script opcodes.

Port of ``compilers/go/codegen/stack.go``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFProperty,
    ANFValue,
    MERGED_LOCAL_TEMP_PREFIX,
    SourceLocation,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_STACK_DEPTH = 800


# ---------------------------------------------------------------------------
# State-field type classification helpers.
#
# These mirror ``is_numeric_state_type`` / ``is_variable_length_state_type`` in
# ``compilers/rust/src/codegen/stack.rs``.  The validator accepts 14 property
# types but only three shapes matter for deserialization:
#
#   * Numeric / script-number:   require OP_BIN2NUM after extraction.
#   * Variable-length:           stored with a push-data length prefix and
#                                must be parsed with ``emit_push_data_decode``
#                                instead of a fixed OP_SPLIT.
#   * Fixed-length byte strings: extracted with a plain fixed-size OP_SPLIT.
# ---------------------------------------------------------------------------

_NUMERIC_STATE_TYPES: frozenset[str] = frozenset({
    "bigint",
    "boolean",
    # RabinSig / RabinPubKey are bigint aliases -- same 8-byte script-number
    # layout in state.
    "RabinSig",
    "RabinPubKey",
})

_VARIABLE_LENGTH_STATE_TYPES: frozenset[str] = frozenset({
    "ByteString",
    "Sig",
    "SigHashPreimage",
})


def is_numeric_state_type(t: str) -> bool:
    """State types that are stored as script numbers (need OP_BIN2NUM)."""
    return t in _NUMERIC_STATE_TYPES


def is_variable_length_state_type(t: str) -> bool:
    """State types that are stored with a push-data length prefix."""
    return t in _VARIABLE_LENGTH_STATE_TYPES

# ---------------------------------------------------------------------------
# Stack IR types
# ---------------------------------------------------------------------------


@dataclass
class PushValue:
    """Typed value for a push operation."""

    kind: str = ""           # "bigint", "bool", "bytes"
    big_int: Optional[int] = None
    bool_val: bool = False
    bytes_val: Optional[bytes] = None


@dataclass
class StackOp:
    """A single stack-machine operation."""

    op: str = ""             # "push", "dup", "swap", "roll", "pick", "drop",
                             # "opcode", "if", "nip", "over", "rot", "tuck",
                             # "placeholder", "raw_bytes"
    value: Optional[PushValue] = None   # for push ops
    depth: int = 0           # for roll/pick (informational)
    code: str = ""           # for opcode ops (e.g. "OP_ADD")
    then: list[StackOp] = field(default_factory=list)      # for if ops
    else_ops: list[StackOp] = field(default_factory=list)   # for if ops
    param_index: int = 0     # for placeholder ops -- index into constructor params
    param_name: str = ""     # for placeholder ops -- name of constructor param
    source_loc: Optional[SourceLocation] = None  # debug source location for source maps

    # raw_bytes -- opaque opcode-byte span emitted verbatim by a raw_script
    # ANF node. Stack effect is declared via in_arity / out_arity; the bytes
    # are never inspected and the peephole optimizer treats this op as a
    # hard barrier.
    raw_bytes: Optional[bytes] = None
    in_arity: int = 0
    out_arity: int = 0


@dataclass
class StackMethod:
    """Stack-lowered form of a single contract method."""

    name: str = ""
    ops: list[StackOp] = field(default_factory=list)
    max_stack_depth: int = 0
    # True if the unlocking script is prefixed with _codePart — needed for
    # continuation builders OR terminal methods that read variable-length
    # (ByteString) state (issue #100). Propagated to ABIMethod.usesCodePart.
    uses_code_part: bool = False


# ---------------------------------------------------------------------------
# OP_PUSH_TX on-chain signature derivation (BUG-100 fix)
# ---------------------------------------------------------------------------
#
# The insecure legacy checkPreimage accepted a witness signature over the real
# spending transaction and checked it against pubkey G, never reading the pushed
# preimage — so the preimage was decoupled from the tx. This derives the ECDSA
# signature FROM the preimage on-chain (s = (hash256(preimage) + r)*k^-1 mod n,
# fixed nonce, privkey d=1, low-S, minimal DER), so OP_CHECKSIG passes only when
# hash256(preimage) equals the real tx sighash.
#
# The construction compiles to a FIXED byte sequence identical across all seven
# tiers; it is the canonical output of the TypeScript reference
# (packages/runar-compiler/src/passes/oppushtx-codegen.ts). Emitted as a single
# opaque raw_bytes op (peephole barrier). The cross-tier conformance suite
# guards that this constant matches every other tier byte-for-byte.
_CHECK_PREIMAGE_BINDING_HEX = (
    "76aa007c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e"
    "7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f"
    "7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c"
    "7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c51"
    "7f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b"
    "7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c"
    "7501007e8121e59e705cb909acaba73cef8c4b8e775cd87cc0956e4045306d7ded41947f04c6"
    "009320a1201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f952141"
    "4136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e977b757893"
    "7c977620a0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7fa078"
    "21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007c8d7c94"
    "9594826b012080007c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c51"
    "7f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b"
    "7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c"
    "517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b"
    "7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e"
    "7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f7b7b7c7e7c517f"
    "7b7b7c7e7c756c01207c947f777682775180527c7e7c7e768277012393518023022100c6047f"
    "9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50130527a7e7c7e7c7e"
    "01417e210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad"
)

# SIGHASH_ALL | SIGHASH_FORKID — default appended sighash flag byte in the
# binding blob above. The append is encoded ``01<flag>7e`` (OP_DATA_1, flag byte,
# OP_CAT); this pattern occurs exactly once in the canonical blob (issue #123).
_SIGHASH_ALL_FORKID = 0x41
_DEFAULT_SIGHASH_APPEND = "01417e"


def _binding_hex_with_sighash_flag(sighash_flag: int) -> str:
    """Return the canonical preimage-binding blob with its appended sighash flag
    byte swapped for ``sighash_flag`` (issue #123).

    The default blob appends ``push(0x41) OP_CAT`` (``01417e``) exactly once. A
    non-default @sighash mode changes ONLY that byte — byte-exact equivalent to
    the TS reference regenerating the blob with a different flag.
    """
    replacement = f"01{sighash_flag & 0xFF:02x}7e"
    if _CHECK_PREIMAGE_BINDING_HEX.count(_DEFAULT_SIGHASH_APPEND) != 1:
        # Defensive: the anchor must be unique or the substitution is unsafe.
        raise AssertionError(
            "check-preimage binding blob no longer has a unique sighash-flag anchor"
        )
    return _CHECK_PREIMAGE_BINDING_HEX.replace(_DEFAULT_SIGHASH_APPEND, replacement)


# ---------------------------------------------------------------------------
# Builtin function -> opcode mapping
# ---------------------------------------------------------------------------

BUILTIN_OPCODES: dict[str, list[str]] = {
    "sha256":        ["OP_SHA256"],
    "ripemd160":     ["OP_RIPEMD160"],
    "hash160":       ["OP_HASH160"],
    "hash256":       ["OP_HASH256"],
    "checkSig":      ["OP_CHECKSIG"],
    "checkMultiSig": ["OP_CHECKMULTISIG"],
    "len":           ["OP_SIZE"],
    "cat":           ["OP_CAT"],
    "num2bin":       ["OP_NUM2BIN"],
    "bin2num":       ["OP_BIN2NUM"],
    "abs":           ["OP_ABS"],
    "min":           ["OP_MIN"],
    "max":           ["OP_MAX"],
    "within":        ["OP_WITHIN"],
    "split":         ["OP_SPLIT"],
    "left":          ["OP_SPLIT", "OP_DROP"],
    "int2str":       ["OP_NUM2BIN"],
    "bool":          ["OP_0NOTEQUAL"],
    "unpack":        ["OP_BIN2NUM"],
}

# ---------------------------------------------------------------------------
# Binary operator -> opcode mapping
# ---------------------------------------------------------------------------

BINOP_OPCODES: dict[str, list[str]] = {
    "+":   ["OP_ADD"],
    "-":   ["OP_SUB"],
    "*":   ["OP_MUL"],
    "/":   ["OP_DIV"],
    "%":   ["OP_MOD"],
    "===": ["OP_NUMEQUAL"],
    "!==": ["OP_NUMEQUAL", "OP_NOT"],
    "<":   ["OP_LESSTHAN"],
    ">":   ["OP_GREATERTHAN"],
    "<=":  ["OP_LESSTHANOREQUAL"],
    ">=":  ["OP_GREATERTHANOREQUAL"],
    "&&":  ["OP_BOOLAND"],
    "||":  ["OP_BOOLOR"],
    "&":   ["OP_AND"],
    "|":   ["OP_OR"],
    "^":   ["OP_XOR"],
    "<<":  ["OP_LSHIFT"],
    ">>":  ["OP_RSHIFT"],
}

# ---------------------------------------------------------------------------
# Unary operator -> opcode mapping
# ---------------------------------------------------------------------------

UNARYOP_OPCODES: dict[str, list[str]] = {
    "!": ["OP_NOT"],
    "-": ["OP_NEGATE"],
    "~": ["OP_INVERT"],
}


# ---------------------------------------------------------------------------
# Stack map -- tracks named values on the stack
# ---------------------------------------------------------------------------

class StackMap:
    """Tracks named values on the stack.

    Element is variable name or ``""`` for anonymous values.
    """

    __slots__ = ("slots",)

    def __init__(self, initial: Optional[list[str]] = None) -> None:
        self.slots: list[str] = list(initial) if initial else []

    def depth(self) -> int:
        return len(self.slots)

    def push(self, name: str) -> None:
        self.slots.append(name)

    def pop(self) -> str:
        if not self.slots:
            raise RuntimeError("stack underflow")
        return self.slots.pop()

    def find_depth(self, name: str) -> int:
        """Return distance from top of stack to *name*.  0 = TOS.  -1 if absent."""
        for i in range(len(self.slots) - 1, -1, -1):
            if self.slots[i] == name:
                return len(self.slots) - 1 - i
        return -1

    def has(self, name: str) -> bool:
        return name in self.slots

    def remove_at_depth(self, depth_from_top: int) -> str:
        index = len(self.slots) - 1 - depth_from_top
        if index < 0 or index >= len(self.slots):
            raise RuntimeError(f"invalid stack depth: {depth_from_top}")
        removed = self.slots[index]
        del self.slots[index]
        return removed

    def peek_at_depth(self, depth_from_top: int) -> str:
        index = len(self.slots) - 1 - depth_from_top
        if index < 0 or index >= len(self.slots):
            raise RuntimeError(f"invalid stack depth: {depth_from_top}")
        return self.slots[index]

    def clone(self) -> StackMap:
        sm = StackMap()
        sm.slots = list(self.slots)
        return sm

    def swap(self) -> None:
        n = len(self.slots)
        if n < 2:
            raise RuntimeError("stack underflow on swap")
        self.slots[n - 1], self.slots[n - 2] = self.slots[n - 2], self.slots[n - 1]

    def dup(self) -> None:
        if not self.slots:
            raise RuntimeError("stack underflow on dup")
        self.slots.append(self.slots[-1])

    def rename_at_depth(self, depth_from_top: int, new_name: Optional[str]) -> None:
        """Rename a slot at a given depth from top."""
        idx = len(self.slots) - 1 - depth_from_top
        if idx < 0 or idx >= len(self.slots):
            raise RuntimeError(f"invalid stack depth for rename: {depth_from_top}")
        self.slots[idx] = new_name if new_name is not None else ""

    def named_slots(self) -> set[str]:
        """Return the set of all non-empty slot names."""
        return {s for s in self.slots if s}

    def debug_slots(self) -> str:
        """Debug string of the slot names (bottom -> top) for error messages."""
        return ", ".join(self.slots)


# ---------------------------------------------------------------------------
# Use analysis -- determine last-use sites for each variable
# ---------------------------------------------------------------------------

def compute_last_uses(bindings: list[ANFBinding]) -> dict[str, int]:
    last_use: dict[str, int] = {}
    # Pre-scan: map each array_literal binding to its element refs. Used to
    # propagate last-use across the array indirection (the array binding is
    # pure metadata in _lower_array_literal -- its elements must remain live
    # until the array's consumer, not until the array_literal binding itself).
    array_elems: dict[str, list[str]] = {}
    for b in bindings:
        if b.value.kind == "array_literal":
            array_elems[b.name] = list(b.value.elements)
    for i, binding in enumerate(bindings):
        # array_literal is metadata-only -- do NOT advance its elements'
        # last-use to here; defer to the array's consumer.
        if binding.value.kind == "array_literal":
            continue
        refs = collect_refs(binding.value)
        for ref in refs:
            last_use[ref] = i
            if ref in array_elems:
                for e in array_elems[ref]:
                    last_use[e] = i
    return last_use


def collect_deep_binding_names(bindings: list[ANFBinding]) -> set[str]:
    """Collect every binding name defined anywhere in a binding sequence,
    recursing into nested if-branches and loop bodies. Used by _lower_loop to
    distinguish loop-internal (re)definitions from true outer-scope refs.
    """
    names: set[str] = set()

    def walk(bs: list[ANFBinding]) -> None:
        for b in bs:
            names.add(b.name)
            if b.value.kind == "if":
                walk(b.value.then)
                walk(b.value.else_)
            elif b.value.kind == "loop":
                walk(b.value.body)

    walk(bindings)
    return names


def collect_loop_carried_rebinds(body: list[ANFBinding]) -> set[str]:
    """Locals a loop body REBINDS and then READS AGAIN in the same iteration.

    ``compute_last_uses`` maps a name to the MAXIMUM index that references it,
    so for a body like::

        t3   = acc + step     (index 1 -- reads the value carried in)
        acc  = @ref:t3        (index 2 -- rebinds: renames t3's slot to `acc`)
        t4   = wacc + acc     (index 3 -- reads the value just rebound)

    ``acc`` gets last-use 3. Index 1 is therefore NOT a last use and copies
    (PICK) instead of consuming, leaving the incoming slot on the stack under
    the same name as the rebound one; index 3 then IS the last use, and
    ``find_depth`` resolves to the topmost match -- so it consumes the UPDATED
    value and leaves the dead incoming one. The next iteration reads that dead
    slot, and every iteration recomputes from the pre-loop value:
    ``for (let i = 0n; i < N; i++) { acc = acc + step; wacc = wacc + acc; }``
    produced ``wacc = step*N`` where the source says ``step*N*(N+1)/2`` --
    silently in a stateless contract, and as a permanently unspendable UTXO in
    a stateful one (the covenant commits to a continuation the SDK never
    builds). ``outer_refs`` does not cover it: ``acc`` is excluded there
    precisely because the body binds it.

    The value these names hold at the end of an iteration is live at the start
    of the next one, so ``_lower_loop`` protects them from consumption exactly
    like an outer ref. The incoming slot each rebinding shadows is left behind
    and drained with the rest of the frame at method exit -- a name always
    resolves to its newest slot, so the reads stay correct.

    Both halves of the predicate are load-bearing:

    - read BEFORE the first rebinding: the name is carried IN from the
      enclosing scope, rather than being a body-private temp that merely
      happens to be read after it is bound;
    - read AFTER the last rebinding: without it the rebound value is dead at
      the end of the iteration and consuming it is correct. This is what keeps
      every shipped accumulator (``sum = sum + i``, ``off = off + len``)
      byte-for-byte unchanged.

    NESTED loops: the scan runs over ``flatten_nested_loop_bodies(body)``, not
    over ``body`` itself. A name rebound only inside an INNER loop is bound at
    no top-level index of the outer body, so the raw scan classified it as
    neither an outer ref (``collect_deep_binding_names`` excludes it -- the
    body does bind it, deeply) nor a carried rebind, and the outer loop never
    marked it live. The inner loop's final iteration then consumed it, because
    ``used_after_loop`` asks the enclosing scope and the enclosing scope had
    not been told either, so every outer iteration restarted from the slot the
    previous one left behind:
    ``for (i<2) { for (j<2) { acc = acc + step; wacc = wacc + acc; } }`` with
    step = 3 produced ``wacc = 24`` where the source says 30. Splicing the
    inner body in at the loop's position preserves the read/rebind/read
    ordering the inner level already sees, so the outer level draws the same
    conclusion.
    """
    flat = flatten_nested_loop_bodies(body)

    first_bind: dict[str, int] = {}
    last_bind: dict[str, int] = {}
    for i, b in enumerate(flat):
        if b.name not in first_bind:
            first_bind[b.name] = i
        last_bind[b.name] = i

    read_before_bind: set[str] = set()
    read_after_bind: set[str] = set()
    for i, b in enumerate(flat):
        for ref in collect_refs(b.value):
            first = first_bind.get(ref)
            if first is not None and i < first:
                read_before_bind.add(ref)
            last = last_bind.get(ref)
            if last is not None and i > last:
                read_after_bind.add(ref)

    return read_before_bind & read_after_bind


def flatten_nested_loop_bodies(body: list[ANFBinding]) -> list[ANFBinding]:
    """The binding sequence with every nested ``loop`` binding -- and every
    ``if`` binding -- replaced, in place, by its own (recursively flattened)
    body.

    Only ``collect_loop_carried_rebinds`` uses this, and only to order reads
    against rebindings. Neither replaced binding contributes a stack slot that
    predicate reasons about, so dropping it loses nothing; splicing the sub-body
    in at its position is what lets an enclosing loop see a rebinding one level
    down.

    ``if`` arms ARE spliced, in ``then ++ else`` order, even though they are
    alternatives rather than a sequence. The predicate asks only "is this name
    read, then rebound, then read again", and treating the arms as a sequence
    can only ADD names to the carried set, never remove one -- conservative in
    the safe direction. Without it a local rebound ONLY inside an ``if`` arm was
    bound at no index the predicate could see: neither an outer ref
    (``collect_deep_binding_names`` excludes it, since the body does bind it,
    deeply) nor a carried rebind. The loop consumed it and the next iteration
    had nothing to read, so ``for (i<2) { if (i<5) { acc = acc + step; }
    wacc = wacc + acc; }`` was REJECTED outright with
    ``Value 'acc' not found on stack`` -- the loud face of the same gap the
    merged-local protection in ``_lower_if`` fixes silently at K>=2.

    The ``if`` binding itself is NOT re-appended after its arms. Appending it
    would count the arms' reads a second time at an index past every arm
    rebinding, making a local that BOTH arms rebind look "read after its last
    rebinding" -- which protected a K=1 alias that must stay consumable.

    A body with no nested loop and no ``if`` is returned entry-for-entry
    unchanged, which is what makes this byte-neutral for every flat loop.
    """
    if not any(b.value.kind in ("loop", "if") for b in body):
        return body
    flat: list[ANFBinding] = []
    for b in body:
        if b.value.kind == "loop":
            flat.extend(flatten_nested_loop_bodies(b.value.body))
        elif b.value.kind == "if":
            flat.extend(flatten_nested_loop_bodies(b.value.then))
            flat.extend(flatten_nested_loop_bodies(b.value.else_))
        else:
            flat.append(b)
    return flat


def collect_refs(value: ANFValue) -> list[str]:
    refs: list[str] = []
    kind = value.kind

    if kind == "load_param":
        refs.append(value.name)
    elif kind in ("load_prop", "get_state_script"):
        pass  # no refs
    elif kind == "load_const":
        if value.const_string is not None and len(value.const_string) > 5 and value.const_string[:5] == "@ref:":
            refs.append(value.const_string[5:])
    elif kind == "bin_op":
        refs.append(value.left)
        refs.append(value.right)
    elif kind == "unary_op":
        refs.append(value.operand)
    elif kind == "call":
        refs.extend(value.args)
    elif kind == "method_call":
        refs.append(value.object)
        refs.extend(value.args)
    elif kind == "if":
        refs.append(value.cond)
        for b in value.then:
            refs.extend(collect_refs(b.value))
        for b in value.else_:
            refs.extend(collect_refs(b.value))
    elif kind == "loop":
        for b in value.body:
            refs.extend(collect_refs(b.value))
    elif kind == "assert":
        refs.append(value.value_ref)
    elif kind == "update_prop":
        refs.append(value.value_ref)
    elif kind == "check_preimage":
        refs.append(value.preimage)
    elif kind == "deserialize_state":
        refs.append(value.preimage)
    elif kind == "add_output":
        refs.append(value.satoshis)
        refs.extend(value.state_values)
        if value.preimage:
            refs.append(value.preimage)
    elif kind == "add_raw_output":
        refs.append(value.satoshis)
        refs.append(value.script_bytes)
    elif kind == "add_data_output":
        refs.append(value.satoshis)
        refs.append(value.script_bytes)
    elif kind == "array_literal":
        refs.extend(value.elements)
    elif kind == "raw_script":
        # Opaque byte span -- no SSA operand refs. Stack effect is declared
        # via in_arity / out_arity.
        pass
    else:
        # Exhaustiveness guard. A silent empty-refs fall-through would let
        # computeLastUses miss a live operand and corrupt the stack plan.
        from runar_compiler.ir.unknown_anf_kind_error import UnknownANFKindError
        raise UnknownANFKindError(kind, "stack.collect_refs")

    return refs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def big_int_push(n: int) -> PushValue:
    return PushValue(kind="bigint", big_int=n)


def _hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


# ---------------------------------------------------------------------------
# Lowering context
# ---------------------------------------------------------------------------

class _LoweringContext:
    """Mutable state for the stack-lowering pass."""

    def __init__(self, params: Optional[list[str]], properties: list[ANFProperty]) -> None:
        self.sm: StackMap = StackMap(params if params else [])
        self.ops: list[StackOp] = []
        self.max_depth: int = 0
        self.properties: list[ANFProperty] = properties
        self.private_methods: dict[str, ANFMethod] = {}
        self.local_bindings: dict[str, bool] = {}
        self.outer_protected_refs: Optional[set[str]] = None
        self.inside_branch: bool = False
        self.current_source_loc: Optional[SourceLocation] = None
        self.const_values: dict[str, int | str | bool] = {}
        # Element counts for array_literal bindings (used by checkMultiSig).
        self.array_lengths: dict[str, int] = {}
        # Element refs for array_literal bindings (used by checkMultiSig).
        self.array_elements: dict[str, list[str]] = {}
        # EXPERIMENTAL EC size options (constant pool, sign lattice / reduction
        # sinking, fixed-base comb), handed down to the EC and NIST curve
        # emitters. None -- not an all-false instance -- when nothing is
        # enabled, so those emitters take their untouched default path and the
        # emitted bytes are provably identical to the shipping ones.
        self.ec_codegen = None

        # Issue #130 (stack layer): a method param whose name collides with a
        # MUTABLE property gets a duplicate stackMap slot once
        # ``deserialize_state`` pushes that property under the same name. Name
        # lookups resolve to the shallowest match (the deserialized property),
        # so ``load_param`` would read the stale on-chain state instead of the
        # witness value. Rename the colliding param's slot to a reserved,
        # collision-proof name up front and remember the mapping so
        # ``_lower_load_param`` targets the real param slot. Only mutable
        # properties are deserialized onto the stack, so readonly shadows
        # (handled purely by ANF resolution) never enter this map, and
        # non-colliding contracts get an empty map -- byte-identical output.
        self.renamed_params: dict[str, str] = {}
        mutable_prop_names = {p.name for p in properties if not p.readonly}
        for name in (params or []):
            if name in mutable_prop_names:
                renamed = f"__param_{name}"
                self.sm.rename_at_depth(self.sm.find_depth(name), renamed)
                self.renamed_params[name] = renamed

        self._track_depth()

    def _track_depth(self) -> None:
        if self.sm.depth() > self.max_depth:
            self.max_depth = self.sm.depth()

    def emit_op(self, op: StackOp) -> None:
        if self.current_source_loc and op.source_loc is None:
            op.source_loc = self.current_source_loc
        self.ops.append(op)
        self._track_depth()

    def emit_varint_encoding(self) -> None:
        """Emit Bitcoin varint encoding of the length on top of the stack.

        Expects stack: [..., script, len]
        Leaves stack:  [..., script, varint_bytes]

        Bitcoin varint format:
          len < 0xfd:        1 byte (len itself)
          len <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
          len <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
          otherwise:         0xff + 8 bytes LE                (9 bytes — never
                                                               used in practice
                                                               for BSV scripts)

        We must support all four shapes; emitting a 3-byte varint for a script
        whose length exceeds 0xffff produces a truncated value that no longer
        matches what the BSV node uses for hashOutputs, breaking the
        state-continuation hash equality assertion downstream. (This is the
        second of the two bugs fixed alongside the variable-length state
        varint stripping — see `integration/go/contracts/RollupBug.runar.go`.)

        OP_NUM2BIN uses sign-magnitude encoding where high-bit values need an
        extra sign byte; we generate one extra byte and then SPLIT off the
        unsigned low bytes to get the correct unsigned varint payload.
        """
        # Stack: [..., script, len]

        # emit_num_to_low_bytes: [..., len] -> [..., low_n_bytes]. Uses
        # NUM2BIN(n+1) then SPLIT(n) DROP to drop the sign byte.
        def emit_num_to_low_bytes(n_bytes: int) -> None:
            self.emit_op(StackOp(op="push", value=big_int_push(n_bytes + 1)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(n_bytes)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

        # emit_prefix: [..., script, low_bytes] -> [..., script, prefix||low_bytes].
        def emit_prefix(prefix_byte: int) -> None:
            self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([prefix_byte]))))
            self.sm.push("")
            self.emit_op(StackOp(op="swap"))
            self.sm.swap()
            self.sm.pop()
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_CAT"))
            self.sm.push("")

        # IF len < 253: 1-byte varint.
        self.emit_op(StackOp(op="dup"))
        self.sm.dup()
        self.emit_op(StackOp(op="push", value=big_int_push(253)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_IF"))
        self.sm.pop()
        sm_at_1_byte = self.sm.clone()
        emit_num_to_low_bytes(1)
        self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
        self.sm = sm_at_1_byte.clone()

        # ELSE-IF len <= 0xffff: 0xfd + 2-byte LE.
        self.emit_op(StackOp(op="dup"))
        self.sm.dup()
        self.emit_op(StackOp(op="push", value=big_int_push(0x10000)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_IF"))
        self.sm.pop()
        sm_at_3_byte = self.sm.clone()
        emit_num_to_low_bytes(2)
        emit_prefix(0xFD)
        self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
        self.sm = sm_at_3_byte.clone()

        # ELSE-IF len <= 0xffffffff: 0xfe + 4-byte LE.
        self.emit_op(StackOp(op="dup"))
        self.sm.dup()
        self.emit_op(StackOp(op="push", value=big_int_push(0x100000000)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_IF"))
        self.sm.pop()
        sm_at_5_byte = self.sm.clone()
        emit_num_to_low_bytes(4)
        emit_prefix(0xFE)
        self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
        self.sm = sm_at_5_byte.clone()

        # ELSE: 0xff + 8-byte LE. (>= 4 GiB script — practically unreachable
        # on BSV but kept for spec completeness so we never silently truncate.)
        emit_num_to_low_bytes(8)
        emit_prefix(0xFF)

        self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
        self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
        self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
        # --- Stack: [..., script, varint] ---

    def emit_push_data_encode(self) -> None:
        """Emit push-data encoding for a ByteString value on top of the stack.

        Expects stack: [..., bs_value]
        Leaves stack:  [..., pushdata_encoded_value]
        """
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
        self.sm.push("")
        self.emit_op(StackOp(op="dup"))
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(76)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_IF"))
        self.sm.pop()
        sm_after_outer_if = self.sm.clone()

        # THEN: len <= 75
        self.emit_op(StackOp(op="push", value=big_int_push(2)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(1)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="drop")); self.sm.pop()
        self.emit_op(StackOp(op="swap")); self.sm.swap()
        self.sm.pop(); self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")
        sm_end_target = self.sm.clone()

        self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
        self.sm = sm_after_outer_if.clone()

        self.emit_op(StackOp(op="dup"))
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(256)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_IF"))
        self.sm.pop()
        sm_after_inner_if = self.sm.clone()

        # THEN: 76-255 -> 0x4c + 1-byte
        self.emit_op(StackOp(op="push", value=big_int_push(2)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(1)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="drop")); self.sm.pop()
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0x4C]))))
        self.sm.push("")
        self.emit_op(StackOp(op="swap")); self.sm.swap()
        self.sm.pop(); self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")
        self.emit_op(StackOp(op="swap")); self.sm.swap()
        self.sm.pop(); self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
        self.sm = sm_after_inner_if

        # ELSE: >= 256 -> 0x4d + 2-byte LE
        self.emit_op(StackOp(op="push", value=big_int_push(4)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(2)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="drop")); self.sm.pop()
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0x4D]))))
        self.sm.push("")
        self.emit_op(StackOp(op="swap")); self.sm.swap()
        self.sm.pop(); self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")
        self.emit_op(StackOp(op="swap")); self.sm.swap()
        self.sm.pop(); self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
        self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
        self.sm = sm_end_target

    def emit_push_data_decode(self) -> None:
        """Emit push-data decoding for a ByteString state field.

        Expects stack: [..., state_bytes]
        Leaves stack:  [..., data, remaining_state]
        """
        self.emit_op(StackOp(op="push", value=big_int_push(1)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="swap")); self.sm.swap()
        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
        self.emit_op(StackOp(op="dup"))
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(76)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_IF"))
        self.sm.pop()
        sm_after_outer_if = self.sm.clone()

        # THEN: fb < 76 -> direct length
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        sm_end_target = self.sm.clone()

        self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
        self.sm = sm_after_outer_if.clone()

        self.emit_op(StackOp(op="dup"))
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(77)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUMEQUAL"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_IF"))
        self.sm.pop()
        sm_after_inner_if = self.sm.clone()

        # THEN: fb == 77 -> 2-byte LE
        self.emit_op(StackOp(op="drop")); self.sm.pop()
        self.emit_op(StackOp(op="push", value=big_int_push(2)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="swap")); self.sm.swap()
        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
        self.sm = sm_after_inner_if

        # ELSE: fb == 76 -> 1-byte
        self.emit_op(StackOp(op="drop")); self.sm.pop()
        self.emit_op(StackOp(op="push", value=big_int_push(1)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="swap")); self.sm.swap()
        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
        self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
        self.sm = sm_end_target

    # -----------------------------------------------------------------
    # bring_to_top
    # -----------------------------------------------------------------

    def bring_to_top(self, name: str, consume: bool) -> None:
        """Move *name* to TOS.  ROLL if *consume*, else PICK (copy)."""
        depth = self.sm.find_depth(name)
        if depth < 0:
            raise RuntimeError(f"value {name!r} not found on stack")

        if depth == 0:
            if not consume:
                self.emit_op(StackOp(op="dup"))
                self.sm.dup()
            return

        if depth == 1 and consume:
            self.emit_op(StackOp(op="swap"))
            self.sm.swap()
            return

        if consume:
            if depth == 2:
                # ROT is ROLL 2
                self.emit_op(StackOp(op="rot"))
                removed = self.sm.remove_at_depth(2)
                self.sm.push(removed)
            else:
                self.emit_op(StackOp(op="push", value=big_int_push(depth)))
                self.sm.push("")  # temporary depth literal on stack map
                self.emit_op(StackOp(op="roll", depth=depth))
                self.sm.pop()  # remove depth literal
                rolled = self.sm.remove_at_depth(depth)
                self.sm.push(rolled)
        else:
            if depth == 1:
                self.emit_op(StackOp(op="over"))
                picked = self.sm.peek_at_depth(1)
                self.sm.push(picked)
            else:
                self.emit_op(StackOp(op="push", value=big_int_push(depth)))
                self.sm.push("")  # temporary depth literal
                self.emit_op(StackOp(op="pick", depth=depth))
                self.sm.pop()  # remove depth literal
                picked = self.sm.peek_at_depth(depth)
                self.sm.push(picked)

        self._track_depth()

    def drop_slot_at_depth(self, depth: int) -> None:
        """Physically remove the stack slot ``depth`` places below the top."""
        if depth == 0:
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            return
        if depth == 1:
            self.emit_op(StackOp(op="nip"))
            self.sm.remove_at_depth(1)
            return
        self.emit_op(StackOp(op="push", value=big_int_push(depth)))
        self.sm.push("")
        self.emit_op(StackOp(op="roll", depth=depth))
        self.sm.pop()
        rolled = self.sm.remove_at_depth(depth)
        self.sm.push(rolled)
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()

    def drain_branch_private_residue(self, pre_if_names: set[str]) -> None:
        """Drain branch-private residue from below TOS at the end of a branch
        body, so both branches converge to a layout the parent stack model can
        faithfully describe before OP_ENDIF (issue #36).

        A slot is residue when its name is NOT in ``pre_if_names`` (the
        snapshot of the parent's named slots taken before the branch ran).
        This catches both anonymous slots (empty-named, pushed by intrinsics
        like substr's OP_SPLIT residue) and named branch-local bindings that
        lingered past their last-use (e.g. dead-code load_const intermediates
        the optimizer didn't fold).

        Slots whose name was already in ``pre_if_names`` are kept --
        including duplicates created by reassigning an outer-scope local from
        inside the branch. The TOS slot is also kept regardless.
        """
        drain_depths: list[int] = []
        for d in range(1, self.sm.depth()):
            name = self.sm.peek_at_depth(d)
            if not name:
                drain_depths.append(d)
            elif name not in pre_if_names:
                drain_depths.append(d)
        if not drain_depths:
            return
        drain_depths.sort(reverse=True)
        for depth in drain_depths:
            if depth == 1:
                self.emit_op(StackOp(op="nip"))
                self.sm.remove_at_depth(1)
            else:
                self.emit_op(StackOp(op="push", value=big_int_push(depth)))
                self.sm.push("")
                self.emit_op(StackOp(op="roll", depth=depth))
                self.sm.pop()
                rolled = self.sm.remove_at_depth(depth)
                self.sm.push(rolled)
                self.emit_op(StackOp(op="drop"))
                self.sm.pop()

    def _is_last_use(self, ref: str, current_index: int, last_uses: dict[str, int]) -> bool:
        last = last_uses.get(ref)
        if last is None:
            return True
        return last <= current_index

    def _operand_consume(self, ref: str, operands: list[str], binding_index: int,
                         last_uses: dict[str, int]) -> bool:
        """Consume-vs-copy decision for one operand of a multi-operand ANF value.

        ``operands`` is the FULL operand-ref list of the value (including
        ``ref`` itself). The load may consume (ROLL / move) the ref only when
        this binding is the ref's last use AND the ref occurs exactly once in
        the operand list. A ref read at more than one operand position of the
        same value must be copied (PICK / DUP) at EVERY position: a
        consume-mode bring_to_top of a ref already on top of the stack is a
        no-op, so two consume-mode loads of the same ref would leave a single
        slot for an opcode that pops one item per operand (e.g. ``t := x + x``
        underflowing OP_ADD), or silently pair the opcode with the wrong slot.
        The original then stays on the stack and the existing method epilogue
        cleans it up. Unreachable from the frontend (pass 04 gives every
        operand a fresh temp); reachable via compile_from_ir hand-written ANF.
        """
        if not self._is_last_use(ref, binding_index, last_uses):
            return False
        return operands.count(ref) <= 1

    # -----------------------------------------------------------------
    # lower_bindings
    # -----------------------------------------------------------------

    def lower_bindings(self, bindings: list[ANFBinding], terminal_assert: bool) -> None:
        self.local_bindings = {b.name: True for b in bindings}
        last_uses = compute_last_uses(bindings)

        # Protect parent-scope refs that are still needed after this scope
        if self.outer_protected_refs is not None:
            for ref in self.outer_protected_refs:
                last_uses[ref] = len(bindings)

        # Find terminal binding index
        last_assert_idx = -1
        terminal_if_idx = -1
        if terminal_assert:
            last_binding = bindings[-1]
            if last_binding.value.kind == "if":
                terminal_if_idx = len(bindings) - 1
            else:
                for i in range(len(bindings) - 1, -1, -1):
                    if bindings[i].value.kind == "assert":
                        last_assert_idx = i
                        break

        for i, binding in enumerate(bindings):
            # Propagate source location from ANF binding to StackOps
            self.current_source_loc = binding.source_loc
            if binding.value.kind == "assert" and i == last_assert_idx:
                # Terminal assert: leave value on stack instead of OP_VERIFY
                self._lower_assert(binding.value.value_ref, i, last_uses, True)
            elif binding.value.kind == "if" and i == terminal_if_idx:
                # Terminal if: propagate terminalAssert into both branches
                self._lower_if(
                    binding.name, binding.value.cond,
                    binding.value.then, binding.value.else_,
                    binding.value.results or [],
                    i, last_uses, True,
                )
            else:
                self._lower_binding(binding, i, last_uses)
            self.current_source_loc = None

    def _lower_bindings_protected(self, bindings: list[ANFBinding], protected_names: set[str]) -> None:
        """Like lower_bindings but never consumes protected names."""
        last_uses = compute_last_uses(bindings)

        # Remove + re-add with very high index so isLastUse always returns false
        for name in protected_names:
            last_uses[name] = (1 << 31) - 1

        for i, binding in enumerate(bindings):
            self.current_source_loc = binding.source_loc
            self._lower_binding(binding, i, last_uses)
            self.current_source_loc = None

    # -----------------------------------------------------------------
    # lower_binding dispatch
    # -----------------------------------------------------------------

    def _lower_binding(self, binding: ANFBinding, binding_index: int, last_uses: dict[str, int]) -> None:
        name = binding.name
        value = binding.value
        kind = value.kind

        if kind == "load_param":
            self._lower_load_param(name, value.name, binding_index, last_uses)
        elif kind == "load_prop":
            self._lower_load_prop(name, value.name)
        elif kind == "load_const":
            self._lower_load_const(name, value, binding_index, last_uses)
        elif kind == "bin_op":
            self._lower_bin_op(name, value.op, value.left, value.right, binding_index, last_uses, value.result_type)
        elif kind == "unary_op":
            self._lower_unary_op(name, value.op, value.operand, binding_index, last_uses)
        elif kind == "call":
            self._lower_call(name, value.func, value.args, binding_index, last_uses)
        elif kind == "method_call":
            self._lower_method_call(name, value.object, value.method, value.args, binding_index, last_uses)
        elif kind == "if":
            self._lower_if(name, value.cond, value.then, value.else_,
                           value.results or [], binding_index, last_uses)
        elif kind == "loop":
            self._lower_loop(name, value.count, value.body, value.iter_var,
                             value.start, value.step, binding_index, last_uses)
        elif kind == "assert":
            self._lower_assert(value.value_ref, binding_index, last_uses, False)
        elif kind == "update_prop":
            self._lower_update_prop(value.name, value.value_ref, binding_index, last_uses)
        elif kind == "get_state_script":
            self._lower_get_state_script(name)
        elif kind == "check_preimage":
            self._lower_check_preimage(name, value.preimage, value.sighash_flag, binding_index, last_uses)
        elif kind == "deserialize_state":
            self._lower_deserialize_state(value.preimage, binding_index, last_uses)
        elif kind == "add_output":
            self._lower_add_output(name, value.satoshis, value.state_values, value.preimage, binding_index, last_uses)
        elif kind == "add_raw_output":
            self._lower_add_raw_output(name, value.satoshis, value.script_bytes, binding_index, last_uses)
        elif kind == "add_data_output":
            # Wire shape is identical to add_raw_output; the distinction only
            # matters at the continuation-hash composition stage in ANF.
            self._lower_add_raw_output(name, value.satoshis, value.script_bytes, binding_index, last_uses)
        elif kind == "array_literal":
            self._lower_array_literal(name, value.elements, binding_index, last_uses)
        elif kind == "raw_script":
            self._lower_raw_script(name, value.bytes, value.in_arity, value.out_arity)
        else:
            # Exhaustiveness guard. A silent no-op fall-through would emit
            # zero opcodes for a binding the caller expects to leave a value
            # on the stack, desynchronizing every subsequent lowering step.
            from runar_compiler.ir.unknown_anf_kind_error import UnknownANFKindError
            raise UnknownANFKindError(kind, "stack.lower_binding")

    # -----------------------------------------------------------------
    # Individual lowering methods
    # -----------------------------------------------------------------

    def _lower_load_param(self, binding_name: str, param_name: str,
                          binding_index: int, last_uses: dict[str, int]) -> None:
        # The parameter is already on the stack under its original name -- or,
        # for a param that shadows a mutable property, under a reserved renamed
        # slot (issue #130) so it is not confused with the deserialized
        # property slot.
        slot_name = self.renamed_params.get(param_name, param_name)
        if self.sm.has(slot_name):
            is_last = self._is_last_use(param_name, binding_index, last_uses)
            self.bring_to_top(slot_name, is_last)
            self.sm.pop()
            self.sm.push(binding_name)
        else:
            # Parameter no longer on the stack -- a compiler invariant
            # violation (historically caused by unrolled loops consuming outer
            # refs; see _lower_loop). Silently emitting OP_0 here produced
            # scripts that compiled, passed the env-based interpreter, and then
            # failed on chain -- fail loudly instead.
            raise RuntimeError(
                f"Stack lowering: method parameter '{param_name}' is not on the "
                f"stack at a post-consumption reference (stack: [{self.sm.debug_slots()}]). "
                f"Refusing to emit a silent OP_0 placeholder."
            )

    def _lower_load_prop(self, binding_name: str, prop_name: str) -> None:
        prop: Optional[ANFProperty] = None
        for p in self.properties:
            if p.name == prop_name:
                prop = p
                break

        if self.sm.has(prop_name):
            # Property has been updated -- use the stack value
            self.bring_to_top(prop_name, False)
            self.sm.pop()
        elif prop is not None and prop.initial_value is not None:
            self._push_property_value(prop.initial_value)
        else:
            # Property value will be provided at deployment time; emit placeholder
            # for its constructor slot.
            #
            # #119 tail (H1): a property that reaches this fallback with no
            # matching constructor slot has no deploy-time bytes of its own. The
            # previous behaviour left param_index at the count of ctor-param
            # props, silently emitting a placeholder for an UNRELATED
            # constructor argument's slot and splicing the wrong deploy-time
            # bytes into the locking script -- a silent-wrong-code path. Fail
            # loudly instead. (A real constructor-param property -- readonly, or
            # a mutable state field whose initial value is spliced at deploy --
            # is found here and is unaffected.)
            param_index = 0
            found = False
            ctor_params: list[str] = []
            for p in self.properties:
                if p.initial_value is not None:
                    continue
                ctor_params.append(p.name)
                if p.name == prop_name:
                    found = True
                    break
                param_index += 1
            # A true ghost is a name absent from a NON-EMPTY registered
            # constructor-param list -- exactly the silent-wrong-code case where
            # the old code coerced it onto an unrelated registered slot. When no
            # constructor-param property is registered (an empty ``ctor_params``
            # -- e.g. a ``.runar.ts`` contract whose only constructor param is
            # declared inline as ``readonly n`` and never surfaces as a property
            # in this tier's TS parser), the name may still be a legitimate
            # slot-0 argument, so preserve the historical placeholder rather than
            # false-positive on a valid deploy-time slot.
            if not found and ctor_params:
                loc = ""
                if self.current_source_loc is not None:
                    sl = self.current_source_loc
                    loc = f" at {sl.file}:{sl.line}:{sl.column}"
                raise RuntimeError(
                    f"Stack lowering: property '{prop_name}'{loc} is neither on "
                    f"the stack, initialized, nor a constructor parameter, so it "
                    f"has no deploy-time slot. Refusing to emit a placeholder for "
                    f"an unrelated constructor argument (slot 0). Known "
                    f"constructor-param properties: [{', '.join(ctor_params)}]."
                )
            self.emit_op(StackOp(op="placeholder", param_index=param_index, param_name=prop_name))
        self.sm.push(binding_name)

    def _push_property_value(self, val: object) -> None:
        if isinstance(val, bool):
            self.emit_op(StackOp(op="push", value=PushValue(kind="bool", bool_val=val)))
        elif isinstance(val, int):
            self.emit_op(StackOp(op="push", value=big_int_push(val)))
        elif isinstance(val, float):
            self.emit_op(StackOp(op="push", value=big_int_push(int(val))))
        elif isinstance(val, str):
            self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=_hex_to_bytes(val))))
        else:
            self.emit_op(StackOp(op="push", value=big_int_push(0)))

    def _lower_load_const(self, binding_name: str, value: ANFValue,
                          binding_index: int, last_uses: dict[str, int]) -> None:
        # Handle @ref: aliases (ANF variable aliasing)
        if (value.const_string is not None
                and len(value.const_string) > 5
                and value.const_string[:5] == "@ref:"):
            ref_name = value.const_string[5:]
            # Special case: aliasing an array_literal (metadata-only binding,
            # not present in the stack-map). Copy the array metadata under
            # the new binding name and emit no stack moves.
            if ref_name in self.array_elements:
                self.array_elements[binding_name] = list(self.array_elements[ref_name])
                if ref_name in self.array_lengths:
                    self.array_lengths[binding_name] = self.array_lengths[ref_name]
                return
            if self.sm.has(ref_name):
                # CRITICAL: Only consume (ROLL) if the ref target is a local binding
                # in the current scope.  Outer-scope refs must be copied (PICK) so
                # the parent stackMap stays in sync.
                consume = (
                    self.local_bindings.get(ref_name, False)
                    and self._is_last_use(ref_name, binding_index, last_uses)
                )
                self.bring_to_top(ref_name, consume)
                self.sm.pop()
                self.sm.push(binding_name)
            else:
                # Referenced value no longer on the stack -- a compiler
                # invariant violation (see _lower_load_param for the
                # loop-consumption history). Fail loudly instead of silently
                # emitting OP_0.
                raise RuntimeError(
                    f"Stack lowering: value '{ref_name}' referenced by "
                    f"'{binding_name}' is not on the stack "
                    f"(stack: [{self.sm.debug_slots()}]). "
                    f"Refusing to emit a silent OP_0 placeholder."
                )
            return

        # Handle @this marker -- compile-time concept, not a runtime value
        if value.const_string is not None and value.const_string == "@this":
            self.emit_op(StackOp(op="push", value=big_int_push(0)))
            self.sm.push(binding_name)
            return

        if value.const_bool is not None:
            self.emit_op(StackOp(op="push", value=PushValue(kind="bool", bool_val=value.const_bool)))
            self.const_values[binding_name] = value.const_bool
        elif value.const_int is not None:
            self.emit_op(StackOp(op="push", value=big_int_push(value.const_int)))
            self.const_values[binding_name] = value.const_int
        elif value.const_string is not None:
            self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=_hex_to_bytes(value.const_string))))
            self.const_values[binding_name] = value.const_string
        else:
            # Fallback: push 0
            self.emit_op(StackOp(op="push", value=big_int_push(0)))
        self.sm.push(binding_name)

    # -----------------------------------------------------------------
    # Binary / unary ops
    # -----------------------------------------------------------------

    def _lower_bin_op(self, binding_name: str, op: str, left: str, right: str,
                      binding_index: int, last_uses: dict[str, int], result_type: str) -> None:
        left_consume = self._operand_consume(left, [left, right], binding_index, last_uses)
        self.bring_to_top(left, left_consume)

        right_consume = self._operand_consume(right, [left, right], binding_index, last_uses)
        self.bring_to_top(right, right_consume)

        self.sm.pop()
        self.sm.pop()

        # For equality operators, choose OP_EQUAL vs OP_NUMEQUAL based on operand type
        if result_type == "bytes" and op in ("===", "!=="):
            self.emit_op(StackOp(op="opcode", code="OP_EQUAL"))
            if op == "!==":
                self.emit_op(StackOp(op="opcode", code="OP_NOT"))
        elif result_type == "bytes" and op == "+":
            # ByteString concatenation: + on byte types emits OP_CAT, not OP_ADD.
            self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        else:
            opcodes = BINOP_OPCODES.get(op)
            if opcodes is None:
                raise RuntimeError(f"unknown binary operator: {op}")
            for code in opcodes:
                self.emit_op(StackOp(op="opcode", code=code))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_unary_op(self, binding_name: str, op: str, operand: str,
                        binding_index: int, last_uses: dict[str, int]) -> None:
        is_last = self._is_last_use(operand, binding_index, last_uses)
        self.bring_to_top(operand, is_last)
        self.sm.pop()

        opcodes = UNARYOP_OPCODES.get(op)
        if opcodes is None:
            raise RuntimeError(f"unknown unary operator: {op}")
        for code in opcodes:
            self.emit_op(StackOp(op="opcode", code=code))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # call
    # -----------------------------------------------------------------

    def _lower_call(self, binding_name: str, func_name: str, args: list[str],
                    binding_index: int, last_uses: dict[str, int]) -> None:
        # Special handling for assert
        if func_name == "assert":
            if args:
                is_last = self._is_last_use(args[0], binding_index, last_uses)
                self.bring_to_top(args[0], is_last)
                self.sm.pop()
                self.emit_op(StackOp(op="opcode", code="OP_VERIFY"))
                self.sm.push(binding_name)
            return

        # exit(condition) => condition OP_VERIFY — same as assert
        if func_name == "exit":
            if args:
                is_last = self._is_last_use(args[0], binding_index, last_uses)
                self.bring_to_top(args[0], is_last)
                self.sm.pop()
                self.emit_op(StackOp(op="opcode", code="OP_VERIFY"))
                self.sm.push(binding_name)
            return

        # super() in constructor
        if func_name == "super":
            self.sm.push(binding_name)
            return

        # checkMultiSig(sigs, pks) -- special handling for OP_CHECKMULTISIG.
        if func_name == "checkMultiSig" and len(args) == 2:
            self._lower_check_multi_sig(binding_name, args, binding_index, last_uses)
            return

        if func_name == "reverseBytes":
            self._lower_reverse_bytes(binding_name, args, binding_index, last_uses)
            return

        if func_name == "__array_access":
            self._lower_array_access(binding_name, args, binding_index, last_uses)
            return

        if func_name == "substr":
            self._lower_substr(binding_name, args, binding_index, last_uses)
            return

        if func_name == "verifyRabinSig":
            self._lower_verify_rabin_sig(binding_name, args, binding_index, last_uses)
            return

        if func_name == "verifyWOTS":
            self._lower_verify_wots(binding_name, args, binding_index, last_uses)
            return

        if func_name.startswith("verifySLHDSA_SHA2_"):
            param_key = func_name[len("verifySLHDSA_"):]
            self._lower_verify_slh_dsa(binding_name, param_key, args, binding_index, last_uses)
            return

        if func_name == "sha256Compress":
            self._lower_sha256_compress(binding_name, args, binding_index, last_uses)
            return

        if func_name == "sha256Finalize":
            self._lower_sha256_finalize(binding_name, args, binding_index, last_uses)
            return

        if func_name == "blake3Compress":
            self._lower_blake3_compress(binding_name, args, binding_index, last_uses)
            return

        if func_name == "blake3Hash":
            self._lower_blake3_hash(binding_name, args, binding_index, last_uses)
            return

        if _is_ec_builtin(func_name):
            self._lower_ec_builtin(binding_name, func_name, args, binding_index, last_uses)
            return

        if _is_nist_ec_builtin(func_name):
            self._lower_nist_ec_builtin(binding_name, func_name, args, binding_index, last_uses)
            return

        if func_name in ("verifyECDSA_P256", "verifyECDSA_P384"):
            self._lower_verify_ecdsa(binding_name, func_name, args, binding_index, last_uses)
            return

        if _is_bb_builtin(func_name):
            self._lower_bb_builtin(binding_name, func_name, args, binding_index, last_uses)
            return

        if _is_kb_builtin(func_name):
            self._lower_kb_builtin(binding_name, func_name, args, binding_index, last_uses)
            return

        if _is_bn254_builtin(func_name):
            self._lower_bn254_builtin(binding_name, func_name, args, binding_index, last_uses)
            return

        if func_name == "merkleRootPoseidon2KB":
            self._lower_merkle_root_poseidon2_kb(binding_name, args, binding_index, last_uses)
            return

        if _is_merkle_builtin(func_name):
            self._lower_merkle_root(binding_name, func_name, args, binding_index, last_uses)
            return

        if func_name in ("safediv", "safemod"):
            self._lower_safe_div_mod(binding_name, func_name, args, binding_index, last_uses)
            return

        if func_name == "clamp":
            self._lower_clamp(binding_name, args, binding_index, last_uses)
            return

        if func_name == "pow":
            self._lower_pow(binding_name, args, binding_index, last_uses)
            return

        if func_name == "mulDiv":
            self._lower_mul_div(binding_name, args, binding_index, last_uses)
            return

        if func_name == "percentOf":
            self._lower_percent_of(binding_name, args, binding_index, last_uses)
            return

        if func_name == "sqrt":
            self._lower_sqrt(binding_name, args, binding_index, last_uses)
            return

        if func_name == "gcd":
            self._lower_gcd(binding_name, args, binding_index, last_uses)
            return

        if func_name == "divmod":
            self._lower_divmod(binding_name, args, binding_index, last_uses)
            return

        if func_name == "log2":
            self._lower_log2(binding_name, args, binding_index, last_uses)
            return

        if func_name == "sign":
            self._lower_sign(binding_name, args, binding_index, last_uses)
            return

        if func_name == "right":
            self._lower_right(binding_name, args, binding_index, last_uses)
            return

        # pack() and toByteString() are type-level casts -- no-ops at the script level
        if func_name in ("pack", "toByteString"):
            if args:
                arg = args[0]
                is_last = self._is_last_use(arg, binding_index, last_uses)
                self.bring_to_top(arg, is_last)
                self.sm.pop()
                self.sm.push(binding_name)
            return

        # computeStateOutputHash(preimage, stateBytes)
        if func_name == "computeStateOutputHash":
            self._lower_compute_state_output_hash(binding_name, args, binding_index, last_uses)
            return

        # computeStateOutput(preimage, stateBytes) — same as computeStateOutputHash
        # but returns raw output bytes WITHOUT the final OP_HASH256
        if func_name == "computeStateOutput":
            self._lower_compute_state_output(binding_name, args, binding_index, last_uses)
            return

        # buildChangeOutput(pkh, amount) — builds a P2PKH output serialization
        if func_name == "buildChangeOutput":
            self._lower_build_change_output(binding_name, args, binding_index, last_uses)
            return

        # Preimage field extractors
        if len(func_name) > 7 and func_name[:7] == "extract":
            self._lower_extractor(binding_name, func_name, args, binding_index, last_uses)
            return

        # General builtin: push args in order, then emit opcodes
        for arg in args:
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)

        # Pop all args
        for _ in args:
            self.sm.pop()

        opcodes = BUILTIN_OPCODES.get(func_name)
        if opcodes is None:
            # Unknown function -- push placeholder
            self.emit_op(StackOp(op="push", value=big_int_push(0)))
            self.sm.push(binding_name)
            return

        for code in opcodes:
            self.emit_op(StackOp(op="opcode", code=code))

        # Some builtins produce two outputs
        if func_name == "split":
            self.sm.push("")            # left part
            self.sm.push(binding_name)  # right part (top)
        elif func_name == "len":
            self.emit_op(StackOp(op="opcode", code="OP_NIP"))  # remove original value, keep only size
            self.sm.push(binding_name)
        else:
            self.sm.push(binding_name)

        self._track_depth()

    # -----------------------------------------------------------------
    # method_call
    # -----------------------------------------------------------------

    def _lower_method_call(self, binding_name: str, _obj: str, method: str,
                           args: list[str], binding_index: int, last_uses: dict[str, int]) -> None:
        if method == "getStateScript":
            # Consume the @this object reference — compile-time concept, not a runtime value.
            if self.sm.has(_obj):
                self.bring_to_top(_obj, True)
                self.emit_op(StackOp(op="drop"))
                self.sm.pop()
            self._lower_get_state_script(binding_name)
            return

        # Check if this is a private method call that should be inlined
        private_method = self.private_methods.get(method)
        if private_method is not None:
            # Consume the @this object reference — compile-time concept, not a runtime value.
            if self.sm.has(_obj):
                self.bring_to_top(_obj, True)
                self.emit_op(StackOp(op="drop"))
                self.sm.pop()
            self._inline_method_call(binding_name, private_method, args, binding_index, last_uses)
            return

        # For other method calls, treat like a function call
        self._lower_call(binding_name, method, args, binding_index, last_uses)

    def _inline_method_call(self, binding_name: str, method: ANFMethod,
                            args: list[str], binding_index: int, last_uses: dict[str, int]) -> None:
        """Inline a private method by lowering its body in the current context."""
        # Track shadowed names so we can restore them after the body runs.
        # When a param name already exists on the stack, temporarily rename
        # the existing entry to avoid duplicate names which break Set-based
        # branch reconciliation in lower_if.
        shadowed: list[dict[str, object]] = []

        # Bring all args to top and rename them to the method param names
        for i, arg in enumerate(args):
            if i < len(method.params):
                param_name = method.params[i].name
                consume = self._operand_consume(arg, args, binding_index, last_uses)
                self.bring_to_top(arg, consume)
                self.sm.pop()

                # If param_name already exists on the stack, temporarily rename
                # the existing entry to prevent duplicate-name issues.
                if self.sm.has(param_name):
                    existing_depth = self.sm.find_depth(param_name)
                    shadowed_name = f"__shadowed_{binding_index}_{param_name}"
                    self.sm.rename_at_depth(existing_depth, shadowed_name)
                    shadowed.append({"param_name": param_name, "shadowed_name": shadowed_name})

                self.sm.push(param_name)

        # Lower the method body
        self.lower_bindings(method.body, False)

        # Restore shadowed names so the caller's scope sees its original entries.
        for entry in shadowed:
            sn = str(entry["shadowed_name"])
            pn = str(entry["param_name"])
            if self.sm.has(sn):
                depth = self.sm.find_depth(sn)
                self.sm.rename_at_depth(depth, pn)

        # The last binding's result should be on top of the stack.
        # Rename it to the calling binding name.
        if method.body:
            last_binding_name = method.body[-1].name
            if self.sm.depth() > 0:
                top_name = self.sm.peek_at_depth(0)
                if top_name == last_binding_name:
                    self.sm.pop()
                    self.sm.push(binding_name)

    # -----------------------------------------------------------------
    # if
    # -----------------------------------------------------------------

    def _lower_if(self, binding_name: str, cond: str,
                  then_bindings: list[ANFBinding], else_bindings: list[ANFBinding],
                  results: list[str],
                  binding_index: int, last_uses: dict[str, int],
                  terminal_assert: bool = False) -> None:
        """``results`` is the ``if`` node's declared result slots, deepest
        first (see ``ANFValue.results``).  Empty for an ``if`` that carries at
        most one result, and then every path below behaves exactly as it did
        before the multi-result contract existed.
        """
        # The ANF wire format has no version field, and ``--ir`` / ``--ir-parity``
        # are documented surfaces that feed a checked-in ANF JSON straight into
        # this pass. An ANF produced BEFORE the multi-result node carries the
        # trailing ``__merge$`` block WITHOUT ``results`` -- back then the block
        # was a naming CONVENTION this pass recognised, and no tier recognises
        # it any more. It deserialises cleanly, the declared count is 0, and the
        # result count falls back to ``then_depth - parent_depth``, which counts
        # the arm's untrimmed block residue as results. Refuse it: the block can
        # only be emitted by ``_append_branch_results``, which only runs for an
        # ``if`` that declares ``results``. Emits no opcodes.
        if not results:
            for _b in list(then_bindings) + list(else_bindings):
                if _b.name.startswith(MERGED_LOCAL_TEMP_PREFIX):
                    raise ValueError(
                        f"ANF produced by a pre-multi-result compiler: the "
                        f"conditional's arm carries a '{MERGED_LOCAL_TEMP_PREFIX}' "
                        f"block but the node declares no results (binding "
                        f"'{_b.name}'). That block used to be a naming convention "
                        f"this pass inferred results from; it is now a declared "
                        f"contract, and no tier reads the convention any more. "
                        f"Recompile the source with the current compiler instead "
                        f"of reusing the stored ANF. binding='{binding_name}'."
                    )

        # Result slots are identified BY NAME -- two identically-named results
        # are indistinguishable, so the layout assertion would be satisfied by
        # coincidence while one value silently replaced the other. ANF lowering
        # refuses the source shape; this guards the ``--ir`` path, where the
        # list arrives as data.
        if len(results) > 1 and len(set(results)) != len(results):
            raise ValueError(
                f"Internal codegen error: the conditional declares duplicate "
                f"result names [{', '.join(results)}]. Result slots are matched "
                f"by name, so duplicates cannot be told apart and one value "
                f"would silently replace the other. binding='{binding_name}'."
            )

        is_last = self._is_last_use(cond, binding_index, last_uses)
        self.bring_to_top(cond, is_last)
        self.sm.pop()  # OP_IF consumes the condition

        # Identify parent-scope items still needed after this if-expression.
        protected_refs: set[str] = set()
        for ref, last_idx in last_uses.items():
            if last_idx > binding_index and self.sm.has(ref):
                protected_refs.add(ref)

        # The K>=2 merged-local block reads every merged local in BOTH arms, and
        # that read is RECONCILIATION, not a use: it is what makes each arm
        # leave exactly K equally-named result slots for the N>=2 reconcile
        # below to adopt. So the merged locals must be copied, never consumed --
        # regardless of whether the ENCLOSING scope reads them again.
        #
        # ``_append_merged_local_results`` (ANF lowering) states that as its
        # premise: "pass 1 always COPIES ... because a local live after the
        # ``if`` is in ``outer_protected_refs``". Enclosing-scope liveness is
        # the wrong question, and the premise silently failed for every merged
        # local whose last enclosing use IS this ``if`` -- which is EVERY merged
        # local of an ``if`` in a loop body, since the body's last-use map ends
        # at the ``if`` itself.
        #
        # What happened then: pass 1 ROLLED instead of picking, the arm's stack
        # effect stopped being +K, the arms ended at different depths, phase 3
        # padded the shortfall with EMPTY pushes, the N-result layout check saw
        # an unnamed slot where it needed the merged name, and control fell
        # through to the single-slot fallback ``push(binding_name)`` -- ONE
        # stackMap name registered for K physical results, with ``acc``/``wacc``
        # still naming the dead pre-``if`` slots.
        # ``for (i<2) { if (i<5) { acc = acc + step; wacc = wacc + acc; } }``
        # with step = 3 produced wacc = 3 where the source says 9: silently in a
        # stateless contract, and as a permanently unspendable UTXO in a
        # stateful one.
        #
        # Byte-neutral for every program whose merged locals were already live
        # after the ``if``: those names are already protected above, which is
        # precisely why those programs compiled correctly.
        #
        # Now driven by the node's DECLARED results instead of by recognising a
        # trailing ``__merge$`` block, so an arm-written property is protected
        # on the same footing as a rebound local.
        for name in results:
            if self.sm.has(name):
                protected_refs.add(name)

        # Snapshot parent stackMap names before branches run
        pre_if_names = self.sm.named_slots()

        # Lower then-branch
        then_ctx = _LoweringContext(None, self.properties)
        # Inherit the EXPERIMENTAL EC size options: branch-guarded crypto lives
        # in the arms, so dropping them here made the flags a no-op for exactly
        # the shape that needs them — and diverged from Java/Zig, which inherit.
        then_ctx.ec_codegen = self.ec_codegen
        then_ctx.sm = self.sm.clone()
        then_ctx.outer_protected_refs = protected_refs
        then_ctx.inside_branch = True
        then_ctx.lower_bindings(then_bindings, terminal_assert)

        then_ctx.drain_branch_private_residue(pre_if_names)

        if terminal_assert and then_ctx.sm.depth() > 1:
            excess = then_ctx.sm.depth() - 1
            for _ in range(excess):
                then_ctx.emit_op(StackOp(op="nip"))
                then_ctx.sm.remove_at_depth(1)

        # Lower else-branch
        else_ctx = _LoweringContext(None, self.properties)
        # Inherit the EXPERIMENTAL EC size options: branch-guarded crypto lives
        # in the arms, so dropping them here made the flags a no-op for exactly
        # the shape that needs them — and diverged from Java/Zig, which inherit.
        else_ctx.ec_codegen = self.ec_codegen
        else_ctx.sm = self.sm.clone()
        else_ctx.outer_protected_refs = protected_refs
        else_ctx.inside_branch = True
        else_ctx.lower_bindings(else_bindings, terminal_assert)

        else_ctx.drain_branch_private_residue(pre_if_names)

        if terminal_assert and else_ctx.sm.depth() > 1:
            excess = else_ctx.sm.depth() - 1
            for _ in range(excess):
                else_ctx.emit_op(StackOp(op="nip"))
                else_ctx.sm.remove_at_depth(1)

        # Balance stack between branches so both end at the same depth.
        # When addOutput is inside an if-then with no else, the then-branch
        # consumes stack items and pushes a serialized output, while the
        # else-branch leaves the stack unchanged. Both must end at the same
        # depth for correct execution after OP_ENDIF.
        #
        # Fix: identify items consumed by the then-branch (present in parent
        # but gone after then). Emit targeted ROLL+DROP in the else-branch
        # to remove those same items, then push empty bytes as placeholder.
        # OP_CAT with empty bytes is identity (no-op for output hashing).
        # Phase 1: collect consumed names from both directions.
        post_then_names = then_ctx.sm.named_slots()
        consumed_names = [n for n in pre_if_names
                          if n not in post_then_names and else_ctx.sm.has(n)]
        post_else_names = else_ctx.sm.named_slots()
        else_consumed_names = [n for n in pre_if_names
                               if n not in post_else_names and then_ctx.sm.has(n)]

        # Phase 2: perform ALL drops before any placeholder pushes.
        # This prevents double-placeholder when bilateral drops balance each other.
        if consumed_names:
            depths = sorted([else_ctx.sm.find_depth(n) for n in consumed_names], reverse=True)
            for depth in depths:
                if depth == 0:
                    else_ctx.emit_op(StackOp(op="drop"))
                    else_ctx.sm.pop()
                elif depth == 1:
                    else_ctx.emit_op(StackOp(op="nip"))
                    else_ctx.sm.remove_at_depth(1)
                else:
                    else_ctx.emit_op(StackOp(op="push", value=big_int_push(depth)))
                    else_ctx.sm.push("")
                    else_ctx.emit_op(StackOp(op="roll", depth=depth))
                    else_ctx.sm.pop()  # remove depth literal
                    rolled = else_ctx.sm.remove_at_depth(depth)
                    else_ctx.sm.push(rolled)
                    else_ctx.emit_op(StackOp(op="drop"))
                    else_ctx.sm.pop()
        if else_consumed_names:
            depths = sorted([then_ctx.sm.find_depth(n) for n in else_consumed_names], reverse=True)
            for depth in depths:
                if depth == 0:
                    then_ctx.emit_op(StackOp(op="drop"))
                    then_ctx.sm.pop()
                elif depth == 1:
                    then_ctx.emit_op(StackOp(op="nip"))
                    then_ctx.sm.remove_at_depth(1)
                else:
                    then_ctx.emit_op(StackOp(op="push", value=big_int_push(depth)))
                    then_ctx.sm.push("")
                    then_ctx.emit_op(StackOp(op="roll", depth=depth))
                    then_ctx.sm.pop()
                    rolled = then_ctx.sm.remove_at_depth(depth)
                    then_ctx.sm.push(rolled)
                    then_ctx.emit_op(StackOp(op="drop"))
                    then_ctx.sm.pop()

        # Branch-merged locals: trim each arm down to exactly its K result slots.
        #
        # ANF lowering ends both arms with an identical K-binding block that
        # rebinds every merged local from a ``__merge$<i>`` temp (see
        # _append_merged_local_results). That block leaves the K live values on
        # top in the same canonical order in both arms — but BENEATH them each
        # arm still holds whatever its own body produced, and those differ per
        # arm, which is exactly what the N>=2 reconcile further down compares.
        # Everything beneath the K results is dead: the block copied each merged
        # local before rebinding it, and a branch-local binding is not visible
        # after the ``if``.
        #
        # Runs AFTER the phase-2 consumption drops, so both arms have given up
        # the same parent slots and share one base depth.
        n_declared = len(results)
        if n_declared >= 1:
            still_held = then_ctx.sm.named_slots()
            consumed_from_parent = sum(
                1 for name in pre_if_names
                if name not in still_held and self.sm.has(name)
            )
            target_depth = self.sm.depth() - consumed_from_parent + n_declared
            for arm_ctx in (then_ctx, else_ctx):
                while arm_ctx.sm.depth() > target_depth:
                    arm_ctx.drop_slot_at_depth(n_declared)

            # The declared contract, checked rather than assumed: after the
            # trim, each arm's top N slots must BE the declared results, in the
            # declared order (``results[0]`` deepest).  ``_append_branch_results``
            # is what makes this true; if it ever stops being true the arms
            # disagree on layout, which is precisely the failure that produced
            # the 2026-08 miscompile family.  Emits no opcodes.
            for label, arm_ctx in (("then", then_ctx), ("else", else_ctx)):
                if arm_ctx.sm.depth() != target_depth:
                    raise RuntimeError(
                        "internal codegen error: branch result layout mismatch "
                        f"— the {label}-arm of the conditional ends at depth "
                        f"{arm_ctx.sm.depth()}, but its {n_declared} declared "
                        f"result(s) require depth {target_depth}; "
                        f"binding={binding_name!r}"
                    )
                for i in range(n_declared):
                    want = results[n_declared - 1 - i]
                    got = arm_ctx.sm.peek_at_depth(i)
                    if got != want:
                        raise RuntimeError(
                            "internal codegen error: branch result layout "
                            f"mismatch — the {label}-arm of the conditional "
                            f"holds {got!r} where the node declares {want!r} "
                            f"(slot {n_declared - 1 - i} of "
                            f"[{', '.join(results)}]); every later operand "
                            "would resolve to the wrong slot; "
                            f"binding={binding_name!r}"
                        )

        # Phase 3: depth-balance reconciliation after ALL drops.
        #
        # Compensate the FULL depth difference between the branches — NOT just a
        # single item. A conditional write of N state fields leaves N result
        # values on the then-branch, so the (empty) else-branch must preserve N
        # old values. Issue #99 Bug 1: the previous single-shot check only
        # balanced a 1-item difference, leaving N>=2 conditional writes
        # imbalanced by (N-1) and the update branch unspendable.
        while then_ctx.sm.depth() > else_ctx.sm.depth():
            result_depth = then_ctx.sm.depth() - else_ctx.sm.depth() - 1
            then_name = then_ctx.sm.peek_at_depth(result_depth)
            if (not else_bindings and then_name
                    and else_ctx.sm.has(then_name)):
                var_depth = else_ctx.sm.find_depth(then_name)
                if var_depth == 0:
                    else_ctx.emit_op(StackOp(op="dup"))
                else:
                    else_ctx.emit_op(StackOp(op="push", value=big_int_push(var_depth)))
                    else_ctx.sm.push("")
                    else_ctx.emit_op(StackOp(op="pick", depth=var_depth))
                    else_ctx.sm.pop()
                else_ctx.sm.push(then_name)
            else:
                else_ctx.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=b"")))
                else_ctx.sm.push("")
        while else_ctx.sm.depth() > then_ctx.sm.depth():
            then_ctx.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=b"")))
            then_ctx.sm.push("")

        # Layer B — branch-balance invariant (#99 Bug 1 guard). After
        # reconciliation the two arms of an OP_IF/OP_ELSE MUST leave the stack at
        # identical depth; otherwise the post-ENDIF code (generated against a
        # single assumed depth) is only correct for the branch the spender does
        # not take, producing a silently-unspendable script.
        if then_ctx.sm.depth() != else_ctx.sm.depth():
            raise RuntimeError(
                "internal codegen error: conditional emitted stack-imbalanced "
                f"branches (then depth {then_ctx.sm.depth()} != else depth "
                f"{else_ctx.sm.depth()}); would produce an unspendable script "
                f"(see GitHub issue #99); binding={binding_name!r}"
            )

        then_ops = then_ctx.ops
        else_ops = else_ctx.ops

        if_op = StackOp(op="if", then=then_ops)
        if else_ops:
            if_op.else_ops = else_ops
        self.emit_op(if_op)

        # Physical slots this method drops AFTER OP_ENDIF, while reconciling the
        # parent stackMap against the arms' results.  Counted because the
        # invariant at the end of lower_if cannot compare the two depths
        # directly: the post-ENDIF reconcile legitimately ROLL/DROPs stale slots
        # out from under the results, so those drops have to be added back
        # before comparing.
        post_endif_drops = 0

        # Reconcile parent stackMap: remove items consumed by the branches.
        post_branch_names = then_ctx.sm.named_slots()
        for name in pre_if_names:
            if name not in post_branch_names and self.sm.has(name):
                depth = self.sm.find_depth(name)
                self.sm.remove_at_depth(depth)

        # C27: the N>=2 result reconcile below also applies when the else-branch
        # is PRESENT and BOTH arms wrote the same N mutable fields (e.g. each
        # branch runs `this.a = ...; this.b = ...`). This is the else-present
        # twin of the empty-else fix (#99 Bug 1). Without it, lower_if falls
        # through to `push(binding_name)` further down — registering ONE stackMap
        # name for N physical results — so the state serialization emits against
        # the wrong slot (OP_NUM2BIN on a byte string) and the continuation is
        # unspendable (a funds-safety bug). Only fire when both arms leave the
        # identical top-N property names in the identical order, so a single
        # post-ENDIF reconcile is valid regardless of which branch the spender
        # takes. The single-field same-property case (N==1, "turn flip") is
        # unaffected — it still takes the dedicated path below. An empty slot
        # name ("") is treated as "not a match".
        n_results = then_ctx.sm.depth() - self.sm.depth()
        else_matches_then_n_result_layout = (
            len(else_bindings) > 0
            and n_results >= 2
            and else_ctx.sm.depth() - self.sm.depth() == n_results
            and all(
                then_ctx.sm.peek_at_depth(i) != ""
                and then_ctx.sm.peek_at_depth(i) == else_ctx.sm.peek_at_depth(i)
                for i in range(n_results)
            )
        )

        # The if expression may produce a result value on top.
        if n_declared >= 1:
            # DECLARED RESULTS.  Both arms were normalised by
            # ``_append_branch_results`` and the layout check above proved they
            # hold exactly ``results``, so the parent adopts them BY THE
            # DECLARED ORDER -- no counting of trailing ``__merge$`` bindings,
            # no comparison of arm depths, no inference of which names are still
            # live.  ``results[0]`` is the deepest slot, matching the order pass
            # 2 of the normalisation rebound them in.
            #
            # Then each parent slot the block shadows (the pre-``if`` binding of
            # a merged local, the stale value of a written property) is
            # physically rolled out from under the results, exactly as the
            # pre-existing N>=2 reconcile did -- which is why the four
            # ``__merge$`` goldens keep their bytes.
            for name in results:
                self.sm.push(name)
            # How far below the result block the deepest stale slot sat.
            # Adopting a result puts it ON TOP, but its pre-``if`` binding lived
            # at depth ``d``, i.e. BENEATH the ``d - n_declared`` slots in
            # between.  Removing the stale copy does not reorder those
            # in-between slots, so after the loop the adopted result has crossed
            # them: the layout is rotated even though the NAME SET and the DEPTH
            # are both unchanged.  That is invisible to the reconcile's name-set
            # check and to Layer C's depth check, and it is the whole of issue
            # #149 -- see ``sink_below`` below.
            sink_below = 0
            for i in range(n_declared - 1, -1, -1):
                name = results[i]
                d = n_declared
                while d < self.sm.depth():
                    if self.sm.peek_at_depth(d) == name:
                        self.emit_op(StackOp(op="push", value=big_int_push(d)))
                        self.sm.push("")
                        self.emit_op(StackOp(op="roll", depth=d + 1))
                        self.sm.pop()
                        rolled = self.sm.remove_at_depth(d)
                        self.sm.push(rolled)
                        self.emit_op(StackOp(op="drop"))
                        self.sm.pop()
                        post_endif_drops += 1
                        if d - n_declared > sink_below:
                            sink_below = d - n_declared
                        break
                    d += 1

            # Restore the inherited layout: sink the whole result block back
            # under the ``sink_below`` slots it just crossed, so BOTH paths of
            # the enclosing ``if`` leave the same slot order and every
            # post-OP_ENDIF read resolves against the layout it was generated
            # for.  Rolling the deepest item of the ``n_declared + sink_below``
            # window to the top, ``sink_below`` times, lifts those slots back
            # above the results while preserving their own relative order.
            # Applied unconditionally, NOT gated on this ``if``'s own else.  The
            # asymmetry that makes #149 unspendable belongs to the ENCLOSING
            # ``if`` (whose fall-through path keeps the pre-``if`` layout), and
            # ``lower_if`` has no view of its parent here.  Gating on
            # ``not else_bindings`` was measured and is WRONG: the #149 inner
            # ``if`` has a real else, so the gate disables the repair exactly
            # where it is needed.  Restoring the pre-``if`` order unconditionally
            # keeps the parent's own model -- names at the depths it recorded
            # before the branch -- true on every path.
            if sink_below > 0:
                window_size = n_declared + sink_below
                for _j in range(sink_below):
                    self.emit_op(
                        StackOp(op="push", value=big_int_push(window_size - 1))
                    )
                    self.sm.push("")
                    self.emit_op(StackOp(op="roll", depth=window_size))
                    self.sm.pop()
                    lifted = self.sm.remove_at_depth(window_size - 1)
                    self.sm.push(lifted)
        elif (then_ctx.sm.depth() > self.sm.depth()
                and n_results >= 2
                and (not else_bindings or else_matches_then_n_result_layout)):
            # #99 Bug 1: a conditional write of N>=2 state fields leaves N result
            # values on top (new values if taken, preserved old values if
            # skipped). Record the N results in their on-stack order, then
            # physically remove the N stale old property values beneath them.
            result_count = then_ctx.sm.depth() - self.sm.depth()
            for i in range(result_count - 1, -1, -1):
                name = then_ctx.sm.peek_at_depth(i) or binding_name
                self.sm.push(name)
            result_names = [self.sm.peek_at_depth(i) for i in range(result_count)]
            for name in result_names:
                if not name:
                    continue
                d = result_count
                while d < self.sm.depth():
                    if self.sm.peek_at_depth(d) == name:
                        self.emit_op(StackOp(op="push", value=big_int_push(d)))
                        self.sm.push("")
                        self.emit_op(StackOp(op="roll", depth=d + 1))
                        self.sm.pop()
                        rolled = self.sm.remove_at_depth(d)
                        self.sm.push(rolled)
                        self.emit_op(StackOp(op="drop"))
                        self.sm.pop()
                        post_endif_drops += 1
                        break
                    d += 1
        elif then_ctx.sm.depth() > self.sm.depth():
            then_top = then_ctx.sm.peek_at_depth(0)
            else_top = else_ctx.sm.peek_at_depth(0) if else_ctx.sm.depth() > 0 else ""
            is_property = any(p.name == then_top for p in self.properties)
            if (is_property and then_top and then_top == else_top
                    and then_top != binding_name and self.sm.has(then_top)):
                # Both branches did update_prop for the same property
                self.sm.push(then_top)
                for d in range(1, self.sm.depth()):
                    if self.sm.peek_at_depth(d) == then_top:
                        if d == 1:
                            self.emit_op(StackOp(op="nip"))
                            self.sm.remove_at_depth(1)
                        else:
                            self.emit_op(StackOp(op="push", value=big_int_push(d)))
                            self.sm.push("")
                            self.emit_op(StackOp(op="roll", depth=d + 1))
                            self.sm.pop()
                            rolled = self.sm.remove_at_depth(d)
                            self.sm.push(rolled)
                            self.emit_op(StackOp(op="drop"))
                            self.sm.pop()
                        post_endif_drops += 1
                        break
            elif (then_top and not is_property and len(else_bindings) == 0
                    and then_top != binding_name and self.sm.has(then_top)):
                # If-without-else: then-branch reassigned a local variable that
                # was PICKed (outer-protected), leaving a stale copy on the stack.
                # Push the local name and remove the stale entry.
                self.sm.push(then_top)
                for d in range(1, self.sm.depth()):
                    if self.sm.peek_at_depth(d) == then_top:
                        if d == 1:
                            self.emit_op(StackOp(op="nip"))
                            self.sm.remove_at_depth(1)
                        else:
                            self.emit_op(StackOp(op="push", value=big_int_push(d)))
                            self.sm.push("")
                            self.emit_op(StackOp(op="roll", depth=d + 1))
                            self.sm.pop()
                            rolled = self.sm.remove_at_depth(d)
                            self.sm.push(rolled)
                            self.emit_op(StackOp(op="drop"))
                            self.sm.pop()
                        post_endif_drops += 1
                        break
            else:
                self.sm.push(binding_name)
        elif else_ctx.sm.depth() > self.sm.depth():
            self.sm.push(binding_name)
        else:
            pass  # Void if — don't push phantom

        # Layer C — branch result-depth invariant.
        #
        # The stackMap is the compiler's ONLY model of the stack, so a stackMap
        # that names FEWER slots than the arms physically left is not detectable
        # anywhere downstream: every later operand silently resolves N slots
        # off.  That single failure mode produced the whole 2026-08 branch/loop
        # miscompile family -- wrong-but-accepted state continuations at best,
        # and scripts the interpreter rejects outright (locked funds) at worst.
        #
        # What must hold when lower_if returns: the parent stackMap describes
        # exactly the physical stack.  Both arms ended at arm_depth (the
        # branch-balance guard above proves they agree), OP_ENDIF changes
        # nothing, and the only physical effect after it is the
        # post_endif_drops stale-slot drops the reconcile emitted.  So:
        #
        #     self.sm.depth() + post_endif_drops == arm_depth
        #
        # The naive self.sm.depth() == arm_depth is WRONG -- the reconcile
        # legitimately ROLL/DROPs stale slots out from under the results, which
        # is exactly what post_endif_drops counts.
        #
        # A failure here is always a codegen bug, never a user error.  Emits no
        # opcodes: byte-neutral by construction.  Same genre as the
        # branch-balance guard (#99), added for the same reason.
        arm_depth = then_ctx.sm.depth()
        if self.sm.depth() + post_endif_drops != arm_depth:
            raise RuntimeError(
                "internal codegen error: branch result depth mismatch — the "
                "parent stack model does not describe the physical stack after "
                f"OP_ENDIF (stackMap depth {self.sm.depth()} + "
                f"{post_endif_drops} post-ENDIF drop(s) != arm depth "
                f"{arm_depth}); the arms leave "
                f"{arm_depth - self.sm.depth() - post_endif_drops} more "
                "physical slot(s) than the compiler recorded, so every later "
                "operand would resolve to the wrong slot and the script would "
                f"be wrong or unspendable; binding={binding_name!r}"
            )

        self._track_depth()

        if then_ctx.max_depth > self.max_depth:
            self.max_depth = then_ctx.max_depth
        if else_ctx.max_depth > self.max_depth:
            self.max_depth = else_ctx.max_depth

    # -----------------------------------------------------------------
    # loop
    # -----------------------------------------------------------------

    def _lower_loop(self, binding_name: str, count: int,
                    body: list[ANFBinding], iter_var: str,
                    start: Optional[int] = None, step: Optional[int] = None,
                    loop_binding_index: Optional[int] = None,
                    enclosing_last_uses: Optional[dict[str, int]] = None) -> None:
        # Iterator start value and step direction (issue #121). Older ANF
        # payloads without start/step describe zero-start counting-up loops.
        start_val = start if start is not None else 0
        step_val = step if step is not None else 1
        # Collect body binding names
        body_binding_names: dict[str, bool] = {b.name: True for b in body}

        # Names (re)defined anywhere inside the loop body, nested branches
        # included. A name the body itself binds is NOT an outer ref --
        # reassigned locals (e.g. `off = off + ...` inside an if) flow through
        # _lower_if's branch-reassignment reconciliation, not through
        # protection here.
        deep_body_binding_names = collect_deep_binding_names(body)

        # Collect ALL outer-scope refs used anywhere in the body -- including
        # refs that only occur inside nested if-branches (collect_refs
        # recurses). The previous top-level-only scan missed nested references:
        # a const defined before the loop and referenced only inside an
        # if-branch was consumed by the first iteration, making iteration 2
        # fail with "Value 'X' not found on stack".
        outer_refs: set[str] = set()
        for b in body:
            for ref in collect_refs(b.value):
                if ref != iter_var and ref not in deep_body_binding_names:
                    outer_refs.add(ref)

        # A local the body REBINDS and then READS AGAIN in the same iteration
        # is carried across iterations through the rebound slot, so it must
        # survive the body exactly like an outer ref. deep_body_binding_names
        # above excludes it precisely because the body binds it -- which is
        # what made the updated value consumable. See
        # collect_loop_carried_rebinds.
        for ref in collect_loop_carried_rebinds(body):
            if ref != iter_var:
                outer_refs.add(ref)

        # Temporarily extend localBindings with body binding names
        prev_local_bindings = self.local_bindings
        new_local_bindings = dict(prev_local_bindings)
        new_local_bindings.update(body_binding_names)
        self.local_bindings = new_local_bindings

        for i in range(count):
            # Push the iteration variable value (in case the loop body uses it).
            # Iteration ``i`` binds ``start + i*step`` (issue #121); zero-start
            # counting-up loops (start=0, step=1) reduce to ``i``, preserving
            # the historical byte-for-byte lowering.
            self.emit_op(StackOp(op="push", value=big_int_push(start_val + i * step_val)))
            self.sm.push(iter_var)

            last_uses = compute_last_uses(body)

            # Prevent outer-scope refs from being consumed by setting their
            # last-use beyond any body binding index:
            #  - in non-final iterations: always (the next iteration re-reads
            #    them);
            #  - in the FINAL iteration: when the enclosing scope still
            #    references them AFTER the loop. Previously the final iteration
            #    consumed every outer ref at its last body use, so a method
            #    param (or const) referenced after the loop was gone from the
            #    stack and was silently lowered to an OP_0/empty push --
            #    compilation succeeded, the env-based interpreter passed, but
            #    the emitted Script failed at runtime (silent interpreter <->
            #    Script divergence).
            is_final_iteration = i == count - 1
            for ref_name in outer_refs:
                used_after_loop = (
                    enclosing_last_uses is not None
                    and loop_binding_index is not None
                    and enclosing_last_uses.get(ref_name, -1) > loop_binding_index
                )
                if (not is_final_iteration) or used_after_loop:
                    last_uses[ref_name] = len(body)

            for j, binding in enumerate(body):
                self._lower_binding(binding, j, last_uses)

            # Clean up the iteration variable if it was not consumed
            if self.sm.has(iter_var):
                depth = self.sm.find_depth(iter_var)
                if depth == 0:
                    self.emit_op(StackOp(op="drop"))
                    self.sm.pop()

        # Restore localBindings
        self.local_bindings = prev_local_bindings

        # NOTE: loops are statements, not expressions -- they don't produce a
        # physical stack value.  Do NOT push a dummy stackMap entry.
        _ = binding_name
        self._track_depth()

    # -----------------------------------------------------------------
    # assert
    # -----------------------------------------------------------------

    def _lower_assert(self, value_ref: str, binding_index: int,
                      last_uses: dict[str, int], terminal: bool) -> None:
        is_last = self._is_last_use(value_ref, binding_index, last_uses)
        self.bring_to_top(value_ref, is_last)
        if terminal:
            # Terminal assert: leave value on stack for Bitcoin Script's
            # final truthiness check.
            pass
        else:
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_VERIFY"))
        self._track_depth()

    # -----------------------------------------------------------------
    # update_prop
    # -----------------------------------------------------------------

    def _lower_update_prop(self, prop_name: str, value_ref: str,
                           binding_index: int, last_uses: dict[str, int]) -> None:
        is_last = self._is_last_use(value_ref, binding_index, last_uses)
        self.bring_to_top(value_ref, is_last)
        self.sm.pop()
        self.sm.push(prop_name)

        # When NOT inside an if-branch, remove the old property entry from
        # the stack. After liftBranchUpdateProps transforms conditional
        # property updates into flat if-expressions + top-level update_prop,
        # the old value is dead and must be removed to keep stack depth correct.
        # Inside branches, the old value is kept for lower_if's same-property
        # detection to handle correctly.
        if not self.inside_branch:
            for d in range(1, self.sm.depth()):
                if self.sm.peek_at_depth(d) == prop_name:
                    if d == 1:
                        self.emit_op(StackOp(op="nip"))
                        self.sm.remove_at_depth(1)
                    else:
                        self.emit_op(StackOp(op="push", value=big_int_push(d)))
                        self.sm.push("")
                        self.emit_op(StackOp(op="roll", depth=d + 1))
                        self.sm.pop()
                        rolled = self.sm.remove_at_depth(d)
                        self.sm.push(rolled)
                        self.emit_op(StackOp(op="drop"))
                        self.sm.pop()
                    break

        self._track_depth()

    # -----------------------------------------------------------------
    # get_state_script
    # -----------------------------------------------------------------

    def _lower_get_state_script(self, binding_name: str) -> None:
        state_props = [p for p in self.properties if not p.readonly]

        if not state_props:
            self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=b"")))
            self.sm.push(binding_name)
            return

        first = True
        for prop in state_props:
            if self.sm.has(prop.name):
                self.bring_to_top(prop.name, True)  # consume
            elif prop.initial_value is not None:
                self._push_property_value(prop.initial_value)
                self.sm.push("")
            else:
                self.emit_op(StackOp(op="push", value=big_int_push(0)))
                self.sm.push("")

            # Convert numeric/boolean values to fixed-width bytes via OP_NUM2BIN
            if prop.type == "bigint":
                self.emit_op(StackOp(op="push", value=big_int_push(8)))
                self.sm.push("")
                self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
                self.sm.pop()  # pop the width
            elif prop.type == "boolean":
                self.emit_op(StackOp(op="push", value=big_int_push(1)))
                self.sm.push("")
                self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
                self.sm.pop()  # pop the width
            elif prop.type == "ByteString":
                # Prepend push-data length prefix (matching SDK format)
                self.emit_push_data_encode()

            if not first:
                self.sm.pop()
                self.sm.pop()
                self.emit_op(StackOp(op="opcode", code="OP_CAT"))
                self.sm.push("")
            first = False

        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # compute_state_output_hash
    # -----------------------------------------------------------------

    def _lower_compute_state_output_hash(self, binding_name: str, args: list[str],
                                         binding_index: int, last_uses: dict[str, int]) -> None:
        """Uses _codePart implicit parameter for the code portion and extracts
        the amount from the preimage's scriptCode field."""
        preimage_ref = args[0]
        state_bytes_ref = args[1]

        # Bring stateBytes to stack first.
        state_consume = self._operand_consume(
            state_bytes_ref, [preimage_ref, state_bytes_ref], binding_index, last_uses)
        self.bring_to_top(state_bytes_ref, state_consume)

        # Extract amount from preimage for the continuation output.
        pre_consume = self._operand_consume(
            preimage_ref, [preimage_ref, state_bytes_ref], binding_index, last_uses)
        self.bring_to_top(preimage_ref, pre_consume)

        # Extract amount: last 52 bytes, take 8 bytes at offset 0.
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(52)))  # 8 (amount) + 44 (tail)
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SUB"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))  # [prefix, amountAndTail]
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")  # prefix
        self.sm.push("")  # amountAndTail
        self.emit_op(StackOp(op="nip"))  # drop prefix
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(8)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))  # [amount(8), tail(44)]
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")  # amount
        self.sm.push("")  # tail
        self.emit_op(StackOp(op="drop"))  # drop tail
        self.sm.pop()
        # --- Stack: [..., stateBytes, amount(8LE)] ---

        # Save amount to altstack
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
        self.sm.pop()

        # Bring _codePart to top (PICK -- never consume, reused across outputs)
        self.bring_to_top("_codePart", False)
        # --- Stack: [..., stateBytes, codePart] ---

        # Append OP_RETURN + stateBytes
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0x6A]))))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., stateBytes, codePart+OP_RETURN] ---

        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

        # Compute varint prefix for script length
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
        self.sm.push("")
        self.emit_varint_encoding()

        # Prepend varint to script
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")
        # --- Stack: [..., varint+script] ---

        # Prepend amount from altstack
        self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
        self.sm.push("")
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., amount+varint+script] ---

        # Hash with SHA256d
        self.emit_op(StackOp(op="opcode", code="OP_HASH256"))

        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # compute_state_output (raw bytes, no hash)
    # -----------------------------------------------------------------

    def _lower_compute_state_output(self, binding_name: str, args: list[str],
                                     binding_index: int, last_uses: dict[str, int]) -> None:
        """computeStateOutput(preimage, stateBytes, newAmount) -- builds the
        continuation output using _newAmount instead of sourceSatoshis.
        Uses _codePart implicit parameter instead of extracting from preimage."""
        preimage_ref = args[0]
        state_bytes_ref = args[1]
        new_amount_ref = args[2]

        cso_operands = [preimage_ref, state_bytes_ref, new_amount_ref]

        # Consume preimage ref (no longer needed -- we use _codePart and _newAmount).
        pre_consume = self._operand_consume(preimage_ref, cso_operands, binding_index, last_uses)
        self.bring_to_top(preimage_ref, pre_consume)
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()

        # Step 1: Convert _newAmount to 8-byte LE and save to altstack.
        amount_consume = self._operand_consume(new_amount_ref, cso_operands, binding_index, last_uses)
        self.bring_to_top(new_amount_ref, amount_consume)
        self.emit_op(StackOp(op="push", value=big_int_push(8)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
        self.sm.pop()

        # Step 2: Bring stateBytes to stack.
        state_consume = self._operand_consume(state_bytes_ref, cso_operands, binding_index, last_uses)
        self.bring_to_top(state_bytes_ref, state_consume)

        # Step 3: Bring _codePart to top (PICK -- never consume, reused across outputs)
        self.bring_to_top("_codePart", False)
        # --- Stack: [..., stateBytes, codePart] ---

        # Step 4: Append OP_RETURN + stateBytes
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0x6A]))))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., stateBytes, codePart+OP_RETURN] ---

        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

        # Step 5: Compute varint prefix for script length
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
        self.sm.push("")
        self.emit_varint_encoding()

        # Prepend varint to script
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")
        # --- Stack: [..., varint+script] ---

        # Step 6: Prepend _newAmount (8-byte LE) from altstack.
        self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
        self.sm.push("")
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., amount(8LE)+varint+script] --- (NO hash)

        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # build_change_output
    # -----------------------------------------------------------------

    def _lower_build_change_output(self, binding_name: str, args: list[str],
                                    binding_index: int, last_uses: dict[str, int]) -> None:
        """Build a P2PKH output serialization: amount(8LE) + 0x19 + 76a914 <pkh:20bytes> 88ac."""
        pkh_ref = args[0]
        amount_ref = args[1]

        # Step 1: Build the P2PKH locking script with length prefix.
        # Push prefix: varint(25) + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 = 0x1976a914
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0x19, 0x76, 0xa9, 0x14]))))
        self.sm.push("")

        # Push the 20-byte PKH
        self.bring_to_top(
            pkh_ref,
            self._operand_consume(pkh_ref, [pkh_ref, amount_ref], binding_index, last_uses))
        # CAT: prefix || pkh
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")

        # Push suffix: OP_EQUALVERIFY + OP_CHECKSIG = 0x88ac
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0x88, 0xac]))))
        self.sm.push("")
        # CAT: (prefix || pkh) || suffix
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., 0x1976a914{pkh}88ac] ---

        # Step 2: Prepend amount as 8-byte LE.
        self.bring_to_top(
            amount_ref,
            self._operand_consume(amount_ref, [pkh_ref, amount_ref], binding_index, last_uses))
        self.emit_op(StackOp(op="push", value=big_int_push(8)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop()  # pop width
        # Stack: [..., script, amount(8LE)]
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        # Stack: [..., amount(8LE), script]
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., amount(8LE)+0x1976a914{pkh}88ac] ---

        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # deserialize_state
    # -----------------------------------------------------------------

    def _lower_deserialize_state(self, preimage_ref: str,
                                 binding_index: int, last_uses: dict[str, int]) -> None:
        state_props: list[ANFProperty] = []
        prop_sizes: list[int] = []
        has_variable_length = False
        for p in self.properties:
            if p.readonly:
                continue
            state_props.append(p)
            if p.type == "bigint":
                sz = 8
            # RabinSig / RabinPubKey are bigint aliases -- same 8-byte layout.
            elif p.type in ("RabinSig", "RabinPubKey"):
                sz = 8
            elif p.type == "boolean":
                sz = 1
            elif p.type == "PubKey":
                sz = 33
            elif p.type == "Addr":
                sz = 20
            # Ripemd160 is 20 bytes (same underlying size as Addr).
            elif p.type == "Ripemd160":
                sz = 20
            elif p.type == "Sha256":
                sz = 32
            elif p.type == "Point":
                sz = 64
            # P-256 point: x[32] || y[32] = 64 bytes (same shape as Point).
            elif p.type == "P256Point":
                sz = 64
            # P-384 point: x[48] || y[48] = 96 bytes.
            elif p.type == "P384Point":
                sz = 96
            # ByteString-typed variable-length fields -- treated the same as
            # ByteString (push-data prefixed in state).
            elif p.type in ("ByteString", "Sig", "SigHashPreimage"):
                sz = -1
                has_variable_length = True
            else:
                raise RuntimeError(f"deserialize_state: unsupported type: {p.type}")
            prop_sizes.append(sz)

        if not state_props:
            return

        is_last = self._is_last_use(preimage_ref, binding_index, last_uses)
        self.bring_to_top(preimage_ref, is_last)

        # 1. Skip first 104 bytes (header), drop prefix
        self.emit_op(StackOp(op="push", value=big_int_push(104)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="nip"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")

        # 2. Drop tail 44 bytes
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(44)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SUB"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()

        # 3. Drop amount (last 8 bytes)
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(8)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SUB"))
        self.sm.pop(); self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop(); self.sm.pop()
        self.sm.push(""); self.sm.push("")
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()

        if not has_variable_length:
            state_len = sum(prop_sizes)

            # 4. Extract last stateLen bytes
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(state_len)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SUB"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop(); self.sm.pop()
            self.sm.push(""); self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")

            # 5. Split fixed-size fields
            self._split_fixed_state_fields(state_props, prop_sizes)
        elif not self.sm.has("_codePart"):
            # Variable-length state but _codePart not available (terminal method).
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
        else:
            # Variable-length path: strip varint, use _codePart to find state.
            #
            # BIP-143 scriptCode is prefixed by a Bitcoin varint:
            #   length < 0xfd:        1 byte (length itself)
            #   length <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
            #   length <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
            #   otherwise:            0xff + 8 bytes LE                (9 bytes)
            #
            # We must support all four shapes, otherwise scripts whose scriptCode
            # exceeds 65,535 bytes (e.g. embedded BN254 verifiers) silently
            # strip too few varint bytes and corrupt the subsequent
            # state-extraction OP_SPLITs (this is the bug fixed here — see
            # `integration/go/contracts/RollupBug.runar.go`).
            self.emit_op(StackOp(op="push", value=big_int_push(1)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")  # firstByte
            self.sm.push("")  # rest
            self.emit_op(StackOp(op="swap"))
            self.sm.swap()
            # Zero-pad firstByte before BIN2NUM so 0xfd/0xfe/0xff aren't read
            # as negative script numbers.
            self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0]))))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_CAT"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
            # Stack: [..., rest, fb_num]

            # emit_drop_more_varint_bytes drops `n` additional varint bytes
            # from the top-of-stack `rest`. [..., rest] -> [..., rest_minus_n].
            def emit_drop_more_varint_bytes(n: int) -> None:
                self.emit_op(StackOp(op="push", value=big_int_push(n)))
                self.sm.push("")
                self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
                self.sm.pop(); self.sm.pop()
                self.sm.push(""); self.sm.push("")
                self.emit_op(StackOp(op="nip"))
                self.sm.pop(); self.sm.pop()
                self.sm.push("")

            # IF fb_num < 253: 1-byte varint, drop fb_num.
            self.emit_op(StackOp(op="dup"))
            self.sm.dup()
            self.emit_op(StackOp(op="push", value=big_int_push(253)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_IF"))
            self.sm.pop()
            sm_at_1_byte_if = self.sm.clone()
            # THEN: 1-byte varint.
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
            self.sm = sm_at_1_byte_if.clone()
            # ELSE: fb_num >= 253. Check 0xfe (5-byte varint) next.
            self.emit_op(StackOp(op="dup"))
            self.sm.dup()
            self.emit_op(StackOp(op="push", value=big_int_push(254)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_NUMEQUAL"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_IF"))
            self.sm.pop()
            sm_at_fe_if = self.sm.clone()
            # THEN: 5-byte varint (0xfe + 4 bytes LE).
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            emit_drop_more_varint_bytes(4)
            self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
            self.sm = sm_at_fe_if.clone()
            # ELSE: fb_num != 254. Check 0xff (9-byte varint) next.
            self.emit_op(StackOp(op="dup"))
            self.sm.dup()
            self.emit_op(StackOp(op="push", value=big_int_push(255)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_NUMEQUAL"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_IF"))
            self.sm.pop()
            sm_at_ff_if = self.sm.clone()
            # THEN: 9-byte varint (0xff + 8 bytes LE).
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            emit_drop_more_varint_bytes(8)
            self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
            self.sm = sm_at_ff_if.clone()
            # ELSE: fb_num must be 253 (0xfd) — 3-byte varint.
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            emit_drop_more_varint_bytes(2)
            self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
            self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))
            self.emit_op(StackOp(op="opcode", code="OP_ENDIF"))

            # Compute skip = SIZE(_codePart) - codeSepIdx
            self.bring_to_top("_codePart", False)
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push_codesep_index"))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SUB"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")

            # Split scriptCode at skip to get state
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop(); self.sm.pop()
            self.sm.push(""); self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")

            # Parse variable-length state fields
            self._parse_variable_length_state_fields(state_props, prop_sizes)

        self._track_depth()

    def _split_fixed_state_fields(self, state_props: list[ANFProperty], prop_sizes: list[int]) -> None:
        if len(state_props) == 1:
            prop = state_props[0]
            if is_numeric_state_type(prop.type):
                self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
            self.sm.pop()
            self.sm.push(prop.name)
        else:
            for i, prop in enumerate(state_props):
                sz = prop_sizes[i]
                if i < len(state_props) - 1:
                    self.emit_op(StackOp(op="push", value=big_int_push(sz)))
                    self.sm.push("")
                    self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
                    self.sm.pop(); self.sm.pop()
                    self.sm.push(""); self.sm.push("")
                    self.emit_op(StackOp(op="swap"))
                    self.sm.swap()
                    if is_numeric_state_type(prop.type):
                        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
                    self.emit_op(StackOp(op="swap"))
                    self.sm.swap()
                    self.sm.pop(); self.sm.pop()
                    self.sm.push(prop.name)
                    self.sm.push("")
                else:
                    if is_numeric_state_type(prop.type):
                        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
                    self.sm.pop()
                    self.sm.push(prop.name)

    def _parse_variable_length_state_fields(self, state_props: list[ANFProperty], prop_sizes: list[int]) -> None:
        if len(state_props) == 1:
            prop = state_props[0]
            if is_variable_length_state_type(prop.type):
                # Single variable-length byte-string: decode push-data prefix,
                # drop the trailing empty remainder.
                self.emit_push_data_decode()  # [..., data, remaining]
                self.emit_op(StackOp(op="drop")); self.sm.pop()
            elif is_numeric_state_type(prop.type):
                self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
            self.sm.pop()
            self.sm.push(prop.name)
        else:
            for i, prop in enumerate(state_props):
                if i < len(state_props) - 1:
                    if is_variable_length_state_type(prop.type):
                        # Variable-length field: decode push-data prefix,
                        # extract data.
                        self.emit_push_data_decode()  # [..., data, rest]
                        self.sm.pop(); self.sm.pop()
                        self.sm.push(prop.name)
                        self.sm.push("")  # rest on top
                    else:
                        sz = prop_sizes[i]
                        self.emit_op(StackOp(op="push", value=big_int_push(sz)))
                        self.sm.push("")
                        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
                        self.sm.pop(); self.sm.pop()
                        self.sm.push(""); self.sm.push("")
                        self.emit_op(StackOp(op="swap")); self.sm.swap()
                        if is_numeric_state_type(prop.type):
                            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
                        self.emit_op(StackOp(op="swap")); self.sm.swap()
                        self.sm.pop(); self.sm.pop()
                        self.sm.push(prop.name)
                        self.sm.push("")
                else:
                    if is_variable_length_state_type(prop.type):
                        # Last variable-length field: decode push-data prefix,
                        # drop the trailing empty remainder.
                        self.emit_push_data_decode()  # [..., data, remaining]
                        self.emit_op(StackOp(op="drop")); self.sm.pop()
                    elif is_numeric_state_type(prop.type):
                        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
                    self.sm.pop()
                    self.sm.push(prop.name)

    # -----------------------------------------------------------------
    # add_output
    # -----------------------------------------------------------------

    def _lower_add_output(self, binding_name: str, satoshis: str,
                          state_values: list[str], _preimage: str,
                          binding_index: int,
                          last_uses: dict[str, int]) -> None:
        # Build a full BIP-143 output serialization:
        #   amount(8LE) + varint(scriptLen) + codePart + OP_RETURN + stateBytes
        # Uses _codePart implicit parameter (passed by SDK) instead of extracting
        # codePart from the preimage. This is simpler and works with OP_CODESEPARATOR.
        state_props = [p for p in self.properties if not p.readonly]
        output_operands = [satoshis, *state_values]

        # Step 1: Bring _codePart to top (PICK -- never consume, reused across outputs)
        self.bring_to_top("_codePart", False)
        # --- Stack: [..., codePart] ---

        # Step 2: Append OP_RETURN byte (0x6a).
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0x6A]))))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        # --- Stack: [..., codePart+OP_RETURN] ---

        # Step 3: Serialize each state value and concatenate.
        for i in range(min(len(state_values), len(state_props))):
            value_ref = state_values[i]
            prop = state_props[i]

            consume = self._operand_consume(value_ref, output_operands, binding_index, last_uses)
            self.bring_to_top(value_ref, consume)

            # Convert numeric/boolean values to fixed-width bytes
            if prop.type == "bigint":
                self.emit_op(StackOp(op="push", value=big_int_push(8)))
                self.sm.push("")
                self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
                self.sm.pop()
            elif prop.type == "boolean":
                self.emit_op(StackOp(op="push", value=big_int_push(1)))
                self.sm.push("")
                self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
                self.sm.pop()
            elif prop.type == "ByteString":
                # Prepend push-data length prefix (matching SDK format)
                self.emit_push_data_encode()
            # Other byte types used as-is

            # Concatenate with accumulator
            self.sm.pop()
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_CAT"))
            self.sm.push("")

        # --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

        # Step 4: Compute varint prefix for the full script length.
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))  # [script, len]
        self.sm.push("")
        self.emit_varint_encoding()
        # --- Stack: [..., script, varint] ---

        # Step 5: Prepend varint to script: SWAP CAT
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")
        # --- Stack: [..., varint+script] ---

        # Step 6: Prepend satoshis as 8-byte LE.
        satoshis_consume = self._operand_consume(satoshis, output_operands, binding_index, last_uses)
        self.bring_to_top(satoshis, satoshis_consume)
        self.emit_op(StackOp(op="push", value=big_int_push(8)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop()  # pop the width
        # Stack: [..., varint+script, satoshis(8LE)]
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))  # satoshis || varint+script
        self.sm.push("")
        # --- Stack: [..., amount(8LE)+varint+scriptPubKey] ---

        # Rename top to binding name
        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # add_raw_output
    # -----------------------------------------------------------------

    def _lower_add_raw_output(self, binding_name: str, satoshis: str,
                               script_bytes: str, binding_index: int,
                               last_uses: dict[str, int]) -> None:
        """Build a raw output serialization:
          amount(8LE) + varint(scriptLen) + scriptBytes
        The scriptBytes are used as-is (no codePart/state insertion).
        """
        # Step 1: Bring scriptBytes to top
        script_consume = self._operand_consume(
            script_bytes, [satoshis, script_bytes], binding_index, last_uses)
        self.bring_to_top(script_bytes, script_consume)

        # Step 2: Compute varint prefix for script length
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
        self.sm.push("")
        self.emit_varint_encoding()
        # --- Stack: [..., script, varint] ---

        # Step 3: Prepend varint to script: SWAP CAT
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")

        # Step 4: Prepend satoshis as 8-byte LE
        sat_consume = self._operand_consume(
            satoshis, [satoshis, script_bytes], binding_index, last_uses)
        self.bring_to_top(satoshis, sat_consume)
        self.emit_op(StackOp(op="push", value=big_int_push(8)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop()  # pop width
        # Stack: [..., varint+script, satoshis(8LE)]
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))  # satoshis || varint+script
        self.sm.push("")

        # Rename top to binding name
        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # array_literal
    # -----------------------------------------------------------------

    def _lower_array_literal(self, binding_name: str, elements: list[str],
                              binding_index: int, last_uses: dict[str, int]) -> None:
        """Metadata-only. Array literals in Rúnar today only feed into
        checkMultiSig. Pre-laying the elements onto the runtime stack here
        would desync the stack-map from the runtime stack (the map can only
        model one slot per binding, but an array binding spans N runtime
        slots). _lower_check_multi_sig pulls each element to TOS at the use site.
        """
        del binding_index, last_uses
        self.array_lengths[binding_name] = len(elements)
        self.array_elements[binding_name] = list(elements)

    # -----------------------------------------------------------------
    # raw_script
    # -----------------------------------------------------------------

    def _lower_raw_script(self, binding_name: str, bytes_hex: str | None,
                          in_arity: int | None, out_arity: int | None) -> None:
        """Lower a raw_script ANF node to a single opaque raw_bytes StackOp.

        The bytes pass through verbatim -- the emit pass writes them as-is,
        and the peephole optimizer must not bridge across them. Stack-tracker
        bookkeeping consumes in_arity items and pushes out_arity items named
        after the binding so downstream PICK/ROLL/DROP refer to the correct
        logical slot.
        """
        in_arity = in_arity or 0
        out_arity = out_arity or 0
        if self.sm.depth() < in_arity:
            raise ValueError(
                f"raw_script binding '{binding_name}' requires {in_arity} "
                f"stack items but only {self.sm.depth()} are present"
            )
        try:
            raw = bytes.fromhex(bytes_hex or "")
        except ValueError as exc:
            raise ValueError(
                f"raw_script binding '{binding_name}' has invalid hex bytes: {exc}"
            ) from exc
        self.emit_op(StackOp(
            op="raw_bytes",
            raw_bytes=raw,
            in_arity=in_arity,
            out_arity=out_arity,
        ))
        for _ in range(in_arity):
            self.sm.pop()
        for i in range(out_arity):
            slot_name = binding_name
            if out_arity != 1:
                slot_name = f"{binding_name}.{i}"
            self.sm.push(slot_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # checkMultiSig
    # -----------------------------------------------------------------

    def _lower_check_multi_sig(self, binding_name: str, args: list[str],
                                binding_index: int, last_uses: dict[str, int]) -> None:
        """Lower checkMultiSig([sig1..sigN], [pk1..pkM]).

        OP_CHECKMULTISIG expects the stack (bottom -> top):
          <dummy=OP_0> <sig1> ... <sigN> <N> <pk1> ... <pkM> <M>

        args[0] and args[1] are bindings produced by array_literal. Those
        bindings are NOT physical stack slots -- their element refs live on
        the stack-map as individual named bindings. We pull each element to
        TOS via bring_to_top. compute_last_uses propagates each element's
        last-use through the array indirection to THIS binding.
        """
        sigs_ref = args[0]
        pks_ref = args[1]
        sig_elems = self.array_elements.get(sigs_ref)
        pk_elems = self.array_elements.get(pks_ref)
        if sig_elems is None or pk_elems is None:
            raise RuntimeError(
                f"checkMultiSig: array_literal metadata missing (sigs={sigs_ref!r}, pks={pks_ref!r})"
            )

        # Dummy OP_0 (historical CHECKMULTISIG off-by-one).
        self.emit_op(StackOp(op="push", value=big_int_push(0)))
        self.sm.push("")

        # A ref repeated across the combined element list (e.g. the same
        # pubkey twice) must be copied at every position -- see _operand_consume.
        msig_operands = [*sig_elems, *pk_elems]

        # Bring each sig element to TOS in declaration order.
        for sig in sig_elems:
            consume = self._operand_consume(sig, msig_operands, binding_index, last_uses)
            self.bring_to_top(sig, consume)

        # Push nSigs.
        self.emit_op(StackOp(op="push", value=big_int_push(len(sig_elems))))
        self.sm.push("")

        # Bring each pubkey element to TOS in declaration order.
        for pk in pk_elems:
            consume = self._operand_consume(pk, msig_operands, binding_index, last_uses)
            self.bring_to_top(pk, consume)

        # Push nPKs.
        self.emit_op(StackOp(op="push", value=big_int_push(len(pk_elems))))
        self.sm.push("")

        # OP_CHECKMULTISIG consumes: dummy + N sigs + nSigs + M pks + nPKs.
        consumed = 1 + len(sig_elems) + 1 + len(pk_elems) + 1
        for _ in range(consumed):
            self.sm.pop()

        self.emit_op(StackOp(op="opcode", code="OP_CHECKMULTISIG"))
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # check_preimage (OP_PUSH_TX)
    # -----------------------------------------------------------------

    def _lower_check_preimage(self, binding_name: str, preimage: str,
                              sighash_flag: int | None,
                              binding_index: int, last_uses: dict[str, int]) -> None:
        # OP_PUSH_TX: verify the pushed BIP-143 sighash preimage is bound to the
        # current spending transaction. The signature is DERIVED FROM THE PREIMAGE
        # ON CHAIN (Optimal OP_PUSH_TX): s = (hash256(preimage) + r)*k^-1 mod n,
        # with fixed nonce k and privkey d=1 (pubkey = G). OP_CHECKSIG(sig, G)
        # then passes iff hash256(preimage) equals the node's real tx sighash —
        # closing BUG-100. The unlocking script pushes ONLY <preimage> (no
        # witness signature). See _emit_check_preimage_binding for the
        # construction.

        # Step 0: Emit OP_CODESEPARATOR so that the scriptCode in the BIP-143
        # preimage is only the code after this point. This reduces preimage size
        # for large scripts and is required for scripts > ~32KB.
        self.emit_op(StackOp(op="opcode", code="OP_CODESEPARATOR"))

        # Step 1: Bring preimage to top (non-consuming; kept for field extractors)
        is_last = self._is_last_use(preimage, binding_index, last_uses)
        self.bring_to_top(preimage, is_last)

        # Step 2: Derive + verify the signature on-chain (single opaque raw_bytes
        # blob). For the default ALL|FORKID (sighash_flag None) the blob is
        # byte-identical to the pinned cross-tier constant; issue #123 lets a
        # method declare a different mode, which only changes the appended
        # sighash flag byte. Net stack effect is zero.
        self._emit_check_preimage_binding(sighash_flag)

        # Preimage remains on top.  Rename for field extractors.
        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    def _emit_check_preimage_binding(self, sighash_flag: int | None = None) -> None:
        """Emit the on-chain preimage binding as one opaque raw_bytes op.

        Net stack effect is 0 (preimage in -> preimage out), declared as
        in_arity=1 / out_arity=1 so the static analyzer keeps the depth
        consistent. The bytes are the canonical BUG-100 construction, identical
        across all seven tiers and guarded by the cross-tier conformance suite.

        Issue #123: a non-default @sighash mode changes ONLY the single appended
        sighash flag byte in the derived DER signature (``push(flag) OP_CAT``,
        encoded ``01<flag>7e`` in the blob). This substitution is byte-exact
        equivalent to regenerating the blob with a different flag (the TS
        reference's ``emitCheckPreimageBinding(emit, sighashFlag)`` differs only
        in that push), so the default (None) blob is unchanged (zero golden
        churn) and every other mode swaps exactly that one byte.
        """
        blob_hex = _CHECK_PREIMAGE_BINDING_HEX
        if sighash_flag is not None and sighash_flag != _SIGHASH_ALL_FORKID:
            blob_hex = _binding_hex_with_sighash_flag(sighash_flag)
        self.emit_op(StackOp(
            op="raw_bytes",
            raw_bytes=bytes.fromhex(blob_hex),
            in_arity=1,
            out_arity=1,
        ))

    # -----------------------------------------------------------------
    # Preimage field extractors
    # -----------------------------------------------------------------

    def _lower_extractor(self, binding_name: str, func_name: str,
                         args: list[str], binding_index: int,
                         last_uses: dict[str, int]) -> None:
        if not args:
            raise RuntimeError(f"{func_name} requires 1 argument")

        arg = args[0]
        is_last = self._is_last_use(arg, binding_index, last_uses)
        self.bring_to_top(arg, is_last)
        self.sm.pop()  # consume the preimage from stack map

        if func_name == "extractVersion":
            self.emit_op(StackOp(op="push", value=big_int_push(4)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))

        elif func_name == "extractHashPrevouts":
            self.emit_op(StackOp(op="push", value=big_int_push(4)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(32)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()  # pop position (32)
            self.sm.pop()  # pop data being split
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

        elif func_name == "extractHashSequence":
            self.emit_op(StackOp(op="push", value=big_int_push(36)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(32)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()  # pop position (32)
            self.sm.pop()  # pop data being split
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

        elif func_name == "extractOutpoint":
            self.emit_op(StackOp(op="push", value=big_int_push(68)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(36)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()  # pop position (36)
            self.sm.pop()  # pop data being split
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

        elif func_name == "extractSigHashType":
            # End-relative: last 4 bytes
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(4)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SUB"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))

        elif func_name == "extractLocktime":
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(8)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SUB"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(4)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()  # pop position (4)
            self.sm.pop()  # pop value being split
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))

        elif func_name in ("extractOutputHash", "extractOutputs"):
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(40)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SUB"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(32)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

        elif func_name == "extractAmount":
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(52)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SUB"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(8)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()  # pop position (8)
            self.sm.pop()  # pop value being split
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))

        elif func_name == "extractSequence":
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(44)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SUB"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(4)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))

        elif func_name == "extractScriptCode":
            self.emit_op(StackOp(op="push", value=big_int_push(104)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(52)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SUB"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

        elif func_name == "extractInputIndex":
            self.emit_op(StackOp(op="push", value=big_int_push(100)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop()
            self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="push", value=big_int_push(4)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop()  # pop position (4)
            self.sm.pop()  # pop value being split
            self.sm.push("")
            self.sm.push("")
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))

        else:
            raise RuntimeError(f"unknown extractor: {func_name}")

        # Rename top of stack to the binding name
        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # reverseBytes
    # -----------------------------------------------------------------

    def _lower_reverse_bytes(self, binding_name: str, args: list[str],
                             binding_index: int, last_uses: dict[str, int]) -> None:
        if not args:
            raise RuntimeError("reverseBytes requires 1 argument")

        arg = args[0]
        is_last = self._is_last_use(arg, binding_index, last_uses)
        self.bring_to_top(arg, is_last)
        self.sm.pop()

        # Push empty result (OP_0), swap so data is on top
        self.emit_op(StackOp(op="push", value=big_int_push(0)))
        self.emit_op(StackOp(op="swap"))

        # 520 iterations (max BSV element size)
        for _ in range(520):
            self.emit_op(StackOp(op="opcode", code="OP_DUP"))
            self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
            self.emit_op(StackOp(op="nip"))
            self.emit_op(StackOp(
                op="if",
                then=[
                    StackOp(op="push", value=big_int_push(1)),
                    StackOp(op="opcode", code="OP_SPLIT"),
                    StackOp(op="swap"),
                    StackOp(op="rot"),
                    StackOp(op="opcode", code="OP_CAT"),
                    StackOp(op="swap"),
                ],
            ))

        # Drop empty remainder
        self.emit_op(StackOp(op="drop"))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # __array_access (byte-level indexing)
    # -----------------------------------------------------------------

    def _lower_array_access(self, binding_name: str, args: list[str],
                            binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError("__array_access requires 2 arguments (object, index)")

        obj, index = args[0], args[1]

        obj_consume = self._operand_consume(obj, args, binding_index, last_uses)
        self.bring_to_top(obj, obj_consume)

        index_consume = self._operand_consume(index, args, binding_index, last_uses)
        self.bring_to_top(index, index_consume)

        # OP_SPLIT at index
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.push("")  # left part
        self.sm.push("")  # right part

        # OP_NIP: discard left
        self.emit_op(StackOp(op="nip"))
        self.sm.pop()
        right_part = self.sm.pop()
        self.sm.push(right_part)

        # Push 1 for the next split
        self.emit_op(StackOp(op="push", value=big_int_push(1)))
        self.sm.push("")

        # OP_SPLIT
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.push("")  # first byte
        self.sm.push("")  # rest

        # OP_DROP rest
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")

        # OP_BIN2NUM
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # substr
    # -----------------------------------------------------------------

    def _lower_substr(self, binding_name: str, args: list[str],
                      binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 3:
            raise RuntimeError("substr requires 3 arguments")

        data, start, length = args[0], args[1], args[2]

        data_consume = self._operand_consume(data, args, binding_index, last_uses)
        self.bring_to_top(data, data_consume)

        start_consume = self._operand_consume(start, args, binding_index, last_uses)
        self.bring_to_top(start, start_consume)

        # Split at start position
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.push("")  # left (discard)
        self.sm.push("")  # right (keep)

        # NIP
        self.emit_op(StackOp(op="nip"))
        self.sm.pop()
        right_part = self.sm.pop()
        self.sm.push(right_part)

        # Push length
        len_consume = self._operand_consume(length, args, binding_index, last_uses)
        self.bring_to_top(length, len_consume)

        # Split at length
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.push("")  # result (keep)
        self.sm.push("")  # remainder (discard)

        # DROP remainder
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()
        self.sm.pop()

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # verifyRabinSig
    # -----------------------------------------------------------------

    def _lower_verify_rabin_sig(self, binding_name: str, args: list[str],
                                binding_index: int, last_uses: dict[str, int]) -> None:
        """Lower verifyRabinSig(msg, sig, padding, pubKey).

        The 10-opcode emission delegates to ``codegen.rabin``.
        Stack input (bottom->top): msg sig padding pubKey -> Stack output: bool
        """
        if len(args) < 4:
            raise RuntimeError("verifyRabinSig requires 4 arguments")

        # Bring all 4 args to the top in argument order: msg sig padding pubKey
        for arg in args:
            self.bring_to_top(arg, self._operand_consume(arg, args, binding_index, last_uses))

        # Pop all 4 args
        for _ in range(4):
            self.sm.pop()

        from runar_compiler.codegen.rabin import emit_verify_rabin_sig
        emit_verify_rabin_sig(lambda op: self.emit_op(op))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # sign
    # -----------------------------------------------------------------

    def _lower_sign(self, binding_name: str, args: list[str],
                    binding_index: int, last_uses: dict[str, int]) -> None:
        if not args:
            raise RuntimeError("sign requires 1 argument")
        x = args[0]

        x_is_last = self._is_last_use(x, binding_index, last_uses)
        self.bring_to_top(x, x_is_last)
        self.sm.pop()

        self.emit_op(StackOp(op="opcode", code="OP_DUP"))
        self.emit_op(StackOp(
            op="if",
            then=[
                StackOp(op="opcode", code="OP_DUP"),
                StackOp(op="opcode", code="OP_ABS"),
                StackOp(op="swap"),
                StackOp(op="opcode", code="OP_DIV"),
            ],
        ))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # right
    # -----------------------------------------------------------------

    def _lower_right(self, binding_name: str, args: list[str],
                     binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError("right requires 2 arguments")
        data, length = args[0], args[1]

        data_consume = self._operand_consume(data, args, binding_index, last_uses)
        self.bring_to_top(data, data_consume)

        length_consume = self._operand_consume(length, args, binding_index, last_uses)
        self.bring_to_top(length, length_consume)

        self.sm.pop()
        self.sm.pop()

        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="opcode", code="OP_SIZE"))
        self.emit_op(StackOp(op="rot"))
        self.emit_op(StackOp(op="opcode", code="OP_SUB"))
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.emit_op(StackOp(op="nip"))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # Math builtins
    # -----------------------------------------------------------------

    def _lower_safe_div_mod(self, binding_name: str, func_name: str,
                            args: list[str], binding_index: int,
                            last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError(f"{func_name} requires 2 arguments")
        a, b = args[0], args[1]

        a_consume = self._operand_consume(a, args, binding_index, last_uses)
        self.bring_to_top(a, a_consume)

        b_consume = self._operand_consume(b, args, binding_index, last_uses)
        self.bring_to_top(b, b_consume)

        # DUP b, check non-zero, then divide/mod
        self.emit_op(StackOp(op="opcode", code="OP_DUP"))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_0NOTEQUAL"))
        self.emit_op(StackOp(op="opcode", code="OP_VERIFY"))
        self.sm.pop()

        self.sm.pop()
        self.sm.pop()
        opcode = "OP_DIV" if func_name == "safediv" else "OP_MOD"
        self.emit_op(StackOp(op="opcode", code=opcode))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_clamp(self, binding_name: str, args: list[str],
                     binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 3:
            raise RuntimeError("clamp requires 3 arguments")
        val, lo, hi = args[0], args[1], args[2]

        val_consume = self._operand_consume(val, args, binding_index, last_uses)
        self.bring_to_top(val, val_consume)

        lo_consume = self._operand_consume(lo, args, binding_index, last_uses)
        self.bring_to_top(lo, lo_consume)

        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_MAX"))
        self.sm.push("")

        hi_consume = self._operand_consume(hi, args, binding_index, last_uses)
        self.bring_to_top(hi, hi_consume)

        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_MIN"))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_pow(self, binding_name: str, args: list[str],
                   binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError("pow requires 2 arguments")
        base, exp = args[0], args[1]

        base_consume = self._operand_consume(base, args, binding_index, last_uses)
        self.bring_to_top(base, base_consume)

        exp_consume = self._operand_consume(exp, args, binding_index, last_uses)
        self.bring_to_top(exp, exp_consume)

        self.sm.pop()
        self.sm.pop()

        self.emit_op(StackOp(op="swap"))                          # exp base
        self.emit_op(StackOp(op="push", value=big_int_push(1)))   # exp base 1(acc)

        MAX_POW_ITERATIONS = 32
        for i in range(MAX_POW_ITERATIONS):
            self.emit_op(StackOp(op="push", value=big_int_push(2)))
            self.emit_op(StackOp(op="opcode", code="OP_PICK"))
            self.emit_op(StackOp(op="push", value=big_int_push(i)))
            self.emit_op(StackOp(op="opcode", code="OP_GREATERTHAN"))
            self.emit_op(StackOp(
                op="if",
                then=[
                    StackOp(op="over"),
                    StackOp(op="opcode", code="OP_MUL"),
                ],
            ))
        # Stack: exp base result
        self.emit_op(StackOp(op="nip"))  # exp result
        self.emit_op(StackOp(op="nip"))  # result

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_mul_div(self, binding_name: str, args: list[str],
                       binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 3:
            raise RuntimeError("mulDiv requires 3 arguments")
        a, b, c = args[0], args[1], args[2]

        a_consume = self._operand_consume(a, args, binding_index, last_uses)
        self.bring_to_top(a, a_consume)
        b_consume = self._operand_consume(b, args, binding_index, last_uses)
        self.bring_to_top(b, b_consume)

        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_MUL"))
        self.sm.push("")

        c_consume = self._operand_consume(c, args, binding_index, last_uses)
        self.bring_to_top(c, c_consume)

        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_DIV"))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_percent_of(self, binding_name: str, args: list[str],
                          binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError("percentOf requires 2 arguments")
        amount, bps = args[0], args[1]

        amount_consume = self._operand_consume(amount, args, binding_index, last_uses)
        self.bring_to_top(amount, amount_consume)
        bps_consume = self._operand_consume(bps, args, binding_index, last_uses)
        self.bring_to_top(bps, bps_consume)

        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_MUL"))
        self.sm.push("")

        self.emit_op(StackOp(op="push", value=big_int_push(10000)))
        self.sm.push("")

        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_DIV"))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_sqrt(self, binding_name: str, args: list[str],
                    binding_index: int, last_uses: dict[str, int]) -> None:
        if not args:
            raise RuntimeError("sqrt requires 1 argument")
        n = args[0]

        n_is_last = self._is_last_use(n, binding_index, last_uses)
        self.bring_to_top(n, n_is_last)
        self.sm.pop()

        self.emit_op(StackOp(op="opcode", code="OP_DUP"))

        # Build Newton iteration ops for the then-branch
        newton_ops: list[StackOp] = []
        newton_ops.append(StackOp(op="opcode", code="OP_DUP"))  # n guess(=n)

        SQRT_ITERATIONS = 16
        for _ in range(SQRT_ITERATIONS):
            newton_ops.append(StackOp(op="over"))
            newton_ops.append(StackOp(op="over"))
            newton_ops.append(StackOp(op="opcode", code="OP_DIV"))
            newton_ops.append(StackOp(op="opcode", code="OP_ADD"))
            newton_ops.append(StackOp(op="push", value=big_int_push(2)))
            newton_ops.append(StackOp(op="opcode", code="OP_DIV"))

        newton_ops.append(StackOp(op="nip"))  # result (drop n)

        self.emit_op(StackOp(op="if", then=newton_ops))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_gcd(self, binding_name: str, args: list[str],
                   binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError("gcd requires 2 arguments")
        a, b = args[0], args[1]

        a_consume = self._operand_consume(a, args, binding_index, last_uses)
        self.bring_to_top(a, a_consume)
        b_consume = self._operand_consume(b, args, binding_index, last_uses)
        self.bring_to_top(b, b_consume)

        self.sm.pop()
        self.sm.pop()

        # Stack: a b -> |a| |b|
        self.emit_op(StackOp(op="opcode", code="OP_ABS"))
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="opcode", code="OP_ABS"))
        self.emit_op(StackOp(op="swap"))

        GCD_ITERATIONS = 256
        for _ in range(GCD_ITERATIONS):
            self.emit_op(StackOp(op="opcode", code="OP_DUP"))
            self.emit_op(StackOp(op="opcode", code="OP_0NOTEQUAL"))
            self.emit_op(StackOp(
                op="if",
                then=[
                    StackOp(op="opcode", code="OP_TUCK"),
                    StackOp(op="opcode", code="OP_MOD"),
                ],
            ))

        self.emit_op(StackOp(op="drop"))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_divmod(self, binding_name: str, args: list[str],
                      binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError("divmod requires 2 arguments")
        a, b = args[0], args[1]

        a_consume = self._operand_consume(a, args, binding_index, last_uses)
        self.bring_to_top(a, a_consume)
        b_consume = self._operand_consume(b, args, binding_index, last_uses)
        self.bring_to_top(b, b_consume)

        self.sm.pop()
        self.sm.pop()

        self.emit_op(StackOp(op="opcode", code="OP_2DUP"))
        self.emit_op(StackOp(op="opcode", code="OP_DIV"))
        self.emit_op(StackOp(op="opcode", code="OP_ROT"))
        self.emit_op(StackOp(op="opcode", code="OP_ROT"))
        self.emit_op(StackOp(op="opcode", code="OP_MOD"))
        self.emit_op(StackOp(op="drop"))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_log2(self, binding_name: str, args: list[str],
                    binding_index: int, last_uses: dict[str, int]) -> None:
        if not args:
            raise RuntimeError("log2 requires 1 argument")
        n = args[0]

        n_is_last = self._is_last_use(n, binding_index, last_uses)
        self.bring_to_top(n, n_is_last)
        self.sm.pop()

        # Push counter = 0
        self.emit_op(StackOp(op="push", value=big_int_push(0)))

        LOG2_ITERATIONS = 64
        for _ in range(LOG2_ITERATIONS):
            self.emit_op(StackOp(op="swap"))
            self.emit_op(StackOp(op="opcode", code="OP_DUP"))
            self.emit_op(StackOp(op="push", value=big_int_push(1)))
            self.emit_op(StackOp(op="opcode", code="OP_GREATERTHAN"))
            self.emit_op(StackOp(
                op="if",
                then=[
                    StackOp(op="push", value=big_int_push(2)),
                    StackOp(op="opcode", code="OP_DIV"),
                    StackOp(op="swap"),
                    StackOp(op="opcode", code="OP_1ADD"),
                    StackOp(op="swap"),
                ],
            ))
            self.emit_op(StackOp(op="swap"))

        # Drop input, keep counter
        self.emit_op(StackOp(op="nip"))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # WOTS+ signature verification
    # -----------------------------------------------------------------

    def _lower_verify_wots(self, binding_name: str, args: list[str],
                           binding_index: int, last_uses: dict[str, int]) -> None:
        """Brings all 3 args to the top, pops them, delegates to
        wots.emit_verify_wots, and pushes the boolean result."""
        if len(args) < 3:
            raise RuntimeError("verifyWOTS requires 3 arguments: msg, sig, pubkey")

        # Bring args to top
        for arg in args:
            self.bring_to_top(arg, self._operand_consume(arg, args, binding_index, last_uses))
        for _ in range(3):
            self.sm.pop()

        # Delegate to the WOTS+ codegen module
        from runar_compiler.codegen.wots import emit_verify_wots
        emit_verify_wots(lambda op: self.emit_op(op))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # SLH-DSA (FIPS 205)
    # -----------------------------------------------------------------

    def _lower_verify_slh_dsa(self, binding_name: str, param_key: str,
                              args: list[str], binding_index: int,
                              last_uses: dict[str, int]) -> None:
        if len(args) < 3:
            raise RuntimeError("verifySLHDSA requires 3 arguments: msg, sig, pubkey")

        for arg in args:
            self.bring_to_top(arg, self._operand_consume(arg, args, binding_index, last_uses))
        for _ in range(3):
            self.sm.pop()

        # Delegate to the SLH-DSA codegen module
        try:
            from runar_compiler.codegen.slh_dsa import emit_verify_slh_dsa
            emit_verify_slh_dsa(lambda op: self.emit_op(op), param_key)
        except ImportError:
            raise RuntimeError(
                "SLH-DSA codegen module not available. "
                "Please implement runar_compiler.codegen.slh_dsa."
            )

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # SHA-256 compression
    # -----------------------------------------------------------------

    def _lower_sha256_compress(self, binding_name: str, args: list[str],
                                binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError("sha256Compress requires 2 arguments: state, block")
        for arg in args:
            self.bring_to_top(arg, self._operand_consume(arg, args, binding_index, last_uses))
        for _ in range(2):
            self.sm.pop()

        from runar_compiler.codegen.sha256 import emit_sha256_compress
        emit_sha256_compress(lambda op: self.emit_op(op))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_sha256_finalize(self, binding_name: str, args: list[str],
                                binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 3:
            raise RuntimeError("sha256Finalize requires 3 arguments: state, remaining, msgBitLen")
        for arg in args:
            self.bring_to_top(arg, self._operand_consume(arg, args, binding_index, last_uses))
        for _ in range(3):
            self.sm.pop()

        from runar_compiler.codegen.sha256 import emit_sha256_finalize
        emit_sha256_finalize(lambda op: self.emit_op(op))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # BLAKE3 compression
    # -----------------------------------------------------------------

    def _lower_blake3_compress(self, binding_name: str, args: list[str],
                                binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 2:
            raise RuntimeError("blake3Compress requires 2 arguments: chainingValue, block")
        for arg in args:
            self.bring_to_top(arg, self._operand_consume(arg, args, binding_index, last_uses))
        for _ in range(2):
            self.sm.pop()

        from runar_compiler.codegen.blake3 import emit_blake3_compress
        emit_blake3_compress(lambda op: self.emit_op(op))

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_blake3_hash(self, binding_name: str, args: list[str],
                            binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 1:
            raise RuntimeError("blake3Hash requires 1 argument: message")
        for arg in args:
            self.bring_to_top(arg, self._operand_consume(arg, args, binding_index, last_uses))
        for _ in range(1):
            self.sm.pop()

        from runar_compiler.codegen.blake3 import emit_blake3_hash
        emit_blake3_hash(lambda op: self.emit_op(op))

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # EC builtins
    # -----------------------------------------------------------------

    def _lower_ec_builtin(self, binding_name: str, func_name: str,
                          args: list[str], binding_index: int,
                          last_uses: dict[str, int]) -> None:
        # Bring args to top in order
        for arg in args:
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)
        for _ in args:
            self.sm.pop()

        # Delegate to the EC codegen module
        try:
            from runar_compiler.codegen import ec as ec_mod
        except ImportError:
            raise RuntimeError(
                "EC codegen module not available. "
                "Please implement runar_compiler.codegen.ec."
            )

        emit_fn = lambda op: self.emit_op(op)

        dispatch = {
            "ecAdd": ec_mod.emit_ec_add,
            "ecMul": ec_mod.emit_ec_mul,
            "ecMulGen": ec_mod.emit_ec_mul_gen,
            "ecNegate": ec_mod.emit_ec_negate,
            "ecOnCurve": ec_mod.emit_ec_on_curve,
            "ecModReduce": ec_mod.emit_ec_mod_reduce,
            "ecEncodeCompressed": ec_mod.emit_ec_encode_compressed,
            "ecMakePoint": ec_mod.emit_ec_make_point,
            "ecPointX": ec_mod.emit_ec_point_x,
            "ecPointY": ec_mod.emit_ec_point_y,
        }

        fn = dispatch.get(func_name)
        if fn is None:
            raise RuntimeError(f"unknown EC builtin: {func_name}")
        if func_name in ("ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecOnCurve"):
            fn(emit_fn, self.ec_codegen)
        else:
            fn(emit_fn)

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # NIST EC builtins (P-256 and P-384)
    # -----------------------------------------------------------------

    def _lower_nist_ec_builtin(self, binding_name: str, func_name: str,
                               args: list[str], binding_index: int,
                               last_uses: dict[str, int]) -> None:
        for arg in args:
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)
        for _ in args:
            self.sm.pop()

        from runar_compiler.codegen import p256_p384 as nist_mod

        dispatch = {
            "p256Add":              nist_mod.emit_p256_add,
            "p256Mul":              nist_mod.emit_p256_mul,
            "p256MulGen":           nist_mod.emit_p256_mul_gen,
            "p256Negate":           nist_mod.emit_p256_negate,
            "p256OnCurve":          nist_mod.emit_p256_on_curve,
            "p256EncodeCompressed": nist_mod.emit_p256_encode_compressed,
            "p384Add":              nist_mod.emit_p384_add,
            "p384Mul":              nist_mod.emit_p384_mul,
            "p384MulGen":           nist_mod.emit_p384_mul_gen,
            "p384Negate":           nist_mod.emit_p384_negate,
            "p384OnCurve":          nist_mod.emit_p384_on_curve,
            "p384EncodeCompressed": nist_mod.emit_p384_encode_compressed,
        }

        fn = dispatch.get(func_name)
        if fn is None:
            raise RuntimeError(f"unknown NIST EC builtin: {func_name}")
        if func_name.endswith("EncodeCompressed"):
            fn(lambda op: self.emit_op(op))
        else:
            fn(lambda op: self.emit_op(op), self.ec_codegen)

        self.sm.push(binding_name)
        self._track_depth()

    def _lower_verify_ecdsa(self, binding_name: str, func_name: str,
                            args: list[str], binding_index: int,
                            last_uses: dict[str, int]) -> None:
        for arg in args:
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)
        for _ in args:
            self.sm.pop()

        from runar_compiler.codegen import p256_p384 as nist_mod

        emit_fn = lambda op: self.emit_op(op)
        if func_name == "verifyECDSA_P256":
            nist_mod.emit_verify_ecdsa_p256(emit_fn, self.ec_codegen)
        else:
            nist_mod.emit_verify_ecdsa_p384(emit_fn, self.ec_codegen)

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # Baby Bear field arithmetic builtins
    # -----------------------------------------------------------------

    def _lower_bb_builtin(self, binding_name: str, func_name: str,
                          args: list[str], binding_index: int,
                          last_uses: dict[str, int]) -> None:
        # Bring args to top in order
        for arg in args:
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)
        for _ in args:
            self.sm.pop()

        # Delegate to the Baby Bear codegen module
        from runar_compiler.codegen.babybear import dispatch_bb_builtin
        emit_fn = lambda op: self.emit_op(op)
        dispatch_bb_builtin(func_name, emit_fn)

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # KoalaBear field arithmetic builtins
    # -----------------------------------------------------------------

    def _lower_kb_builtin(self, binding_name: str, func_name: str,
                          args: list[str], binding_index: int,
                          last_uses: dict[str, int]) -> None:
        # Bring args to top in order
        for arg in args:
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)
        for _ in args:
            self.sm.pop()

        # Delegate to the KoalaBear codegen module
        from runar_compiler.codegen.koalabear import dispatch_kb_builtin
        emit_fn = lambda op: self.emit_op(op)
        dispatch_kb_builtin(func_name, emit_fn)

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # BN254 field and G1 builtins
    # -----------------------------------------------------------------

    def _lower_bn254_builtin(self, binding_name: str, func_name: str,
                             args: list[str], binding_index: int,
                             last_uses: dict[str, int]) -> None:
        # Bring args to top in order
        for arg in args:
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)
        for _ in args:
            self.sm.pop()

        # Delegate to the BN254 codegen module
        from runar_compiler.codegen.bn254 import dispatch_bn254_builtin
        emit_fn = lambda op: self.emit_op(op)
        dispatch_bn254_builtin(func_name, emit_fn)

        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # Poseidon2 KoalaBear Merkle proof verification
    # -----------------------------------------------------------------

    def _lower_merkle_root_poseidon2_kb(self, binding_name: str, args: list[str],
                                         binding_index: int,
                                         last_uses: dict[str, int]) -> None:
        # args: [leaf_0..leaf_7, sib0_0..sib0_7, ..., sib(D-1)_0..sib(D-1)_7, index, depth]
        # depth must be a compile-time constant (last argument)
        n_args = len(args)
        if n_args < 10:
            raise RuntimeError(
                f"merkleRootPoseidon2KB requires at least 10 arguments, got {n_args}"
            )

        # Extract depth constant from tracked constant values (last arg)
        depth_arg = args[n_args - 1]
        depth_value = self.const_values.get(depth_arg)
        if depth_value is None or not isinstance(depth_value, int):
            raise RuntimeError(
                f"merkleRootPoseidon2KB: depth (last argument) must be a compile-time "
                f"constant integer literal. Got a runtime value for '{depth_arg}'."
            )
        depth = int(depth_value)
        if depth < 1 or depth > 64:
            raise RuntimeError(
                f"merkleRootPoseidon2KB: depth must be between 1 and 64, got {depth}"
            )

        # Validate argument count: 8 leaf + depth*8 proof + 1 index + 1 depth
        expected_args = 8 + depth * 8 + 1 + 1
        if n_args != expected_args:
            raise RuntimeError(
                f"merkleRootPoseidon2KB: expected {expected_args} arguments "
                f"(8 leaf + {depth}*8 proof + index + depth), got {n_args}"
            )

        # Remove depth from the real stack FIRST (compile-time constant, not runtime)
        if self.sm.has(depth_arg):
            self.bring_to_top(depth_arg, True)
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

        # Bring all runtime args (leaf*8 + proof*depth*8 + index) to stack top in order
        runtime_arg_count = n_args - 1  # all except depth
        for i in range(runtime_arg_count):
            arg = args[i]
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)
        # Pop all runtime args -- the codegen consumes them and produces 8 results
        for _ in range(runtime_arg_count):
            self.sm.pop()

        from runar_compiler.codegen.poseidon2_merkle import emit_poseidon2_merkle_root
        emit_fn = lambda op: self.emit_op(op)
        emit_poseidon2_merkle_root(emit_fn, depth)

        # The codegen leaves 8 elements on the stack (root_0..root_7, root_7 on top).
        # The type system returns a single bigint, so only root_7 (top) is accessible.
        # Drop the lower 7 elements with OP_NIP to keep the stack clean.
        for _ in range(7):
            self.emit_op(StackOp(op="nip"))
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # Merkle proof verification builtins
    # -----------------------------------------------------------------

    def _lower_merkle_root(self, binding_name: str, func_name: str,
                           args: list[str], binding_index: int,
                           last_uses: dict[str, int]) -> None:
        # args: [leaf, proof, index, depth]
        # depth must be a compile-time constant
        if len(args) != 4:
            raise RuntimeError(
                f"{func_name} requires exactly 4 arguments (leaf, proof, index, depth)"
            )

        # Extract depth constant from ANF binding
        depth_arg = args[3]
        depth_value = self.const_values.get(depth_arg)
        if depth_value is None or not isinstance(depth_value, int):
            raise RuntimeError(
                f"{func_name}: depth (4th argument) must be a compile-time constant "
                f"integer literal. Got a runtime value for '{depth_arg}'."
            )
        depth = int(depth_value)
        if depth < 1 or depth > 64:
            raise RuntimeError(
                f"{func_name}: depth must be between 1 and 64, got {depth}"
            )

        # Remove depth from the real stack FIRST (compile-time constant, not runtime).
        if self.sm.has(depth_arg):
            self.bring_to_top(depth_arg, True)
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

        # Bring leaf, proof, index to stack top for the codegen
        for i in range(3):
            arg = args[i]
            consume = self._operand_consume(arg, args, binding_index, last_uses)
            self.bring_to_top(arg, consume)
        # Pop the 3 args -- the codegen consumes them and produces 1 result
        for _ in range(3):
            self.sm.pop()

        from runar_compiler.codegen.merkle import (
            emit_merkle_root_sha256,
            emit_merkle_root_hash256,
        )
        emit_fn = lambda op: self.emit_op(op)

        if func_name == "merkleRootSha256":
            emit_merkle_root_sha256(emit_fn, depth)
        else:
            emit_merkle_root_hash256(emit_fn, depth)

        self.sm.push(binding_name)
        self._track_depth()


# ---------------------------------------------------------------------------
# EC builtin names
# ---------------------------------------------------------------------------

_EC_BUILTIN_NAMES = frozenset({
    "ecAdd", "ecMul", "ecMulGen",
    "ecNegate", "ecOnCurve", "ecModReduce",
    "ecEncodeCompressed", "ecMakePoint",
    "ecPointX", "ecPointY",
})


def _is_ec_builtin(name: str) -> bool:
    return name in _EC_BUILTIN_NAMES


# ---------------------------------------------------------------------------
# NIST EC builtin names (P-256 and P-384)
# ---------------------------------------------------------------------------

_NIST_EC_BUILTIN_NAMES = frozenset({
    "p256Add", "p256Mul", "p256MulGen",
    "p256Negate", "p256OnCurve", "p256EncodeCompressed",
    "p384Add", "p384Mul", "p384MulGen",
    "p384Negate", "p384OnCurve", "p384EncodeCompressed",
})


def _is_nist_ec_builtin(name: str) -> bool:
    return name in _NIST_EC_BUILTIN_NAMES


# ---------------------------------------------------------------------------
# Baby Bear builtin names
# ---------------------------------------------------------------------------

_BB_BUILTIN_NAMES = frozenset({
    "bbFieldAdd", "bbFieldSub", "bbFieldMul", "bbFieldInv",
    "bbExt4Mul0", "bbExt4Mul1", "bbExt4Mul2", "bbExt4Mul3",
    "bbExt4Inv0", "bbExt4Inv1", "bbExt4Inv2", "bbExt4Inv3",
})


def _is_bb_builtin(name: str) -> bool:
    return name in _BB_BUILTIN_NAMES


# ---------------------------------------------------------------------------
# KoalaBear builtin names
# ---------------------------------------------------------------------------

_KB_BUILTIN_NAMES = frozenset({
    "kbFieldAdd", "kbFieldSub", "kbFieldMul", "kbFieldInv",
    "kbExt4Mul0", "kbExt4Mul1", "kbExt4Mul2", "kbExt4Mul3",
    "kbExt4Inv0", "kbExt4Inv1", "kbExt4Inv2", "kbExt4Inv3",
})


def _is_kb_builtin(name: str) -> bool:
    return name in _KB_BUILTIN_NAMES


# ---------------------------------------------------------------------------
# BN254 builtin names
# ---------------------------------------------------------------------------

_BN254_BUILTIN_NAMES = frozenset({
    "bn254FieldAdd", "bn254FieldSub", "bn254FieldMul",
    "bn254FieldInv", "bn254FieldNeg",
    "bn254G1Add", "bn254G1ScalarMul",
    "bn254G1Negate", "bn254G1OnCurve",
})


def _is_bn254_builtin(name: str) -> bool:
    return name in _BN254_BUILTIN_NAMES


# ---------------------------------------------------------------------------
# Merkle builtin names
# ---------------------------------------------------------------------------

_MERKLE_BUILTIN_NAMES = frozenset({
    "merkleRootSha256", "merkleRootHash256",
})


def _is_merkle_builtin(name: str) -> bool:
    return name in _MERKLE_BUILTIN_NAMES


# ---------------------------------------------------------------------------
# methodUsesCheckPreimage
# ---------------------------------------------------------------------------

def _method_uses_check_preimage(
    bindings: list[ANFBinding],
    private_methods: dict | None = None,
    seen: set[str] | None = None,
) -> bool:
    """Recursively check whether `bindings` (and any private methods
    they call, transitively) contain a check_preimage. 2026-04-30
    audit finding F7: previous implementation was a shallow scan that
    missed manual checkPreimage calls inside if/loop bodies and
    private helpers, causing stack lowering to fail with
    `Value '_opPushTxSig' not found on stack`."""
    if seen is None:
        seen = set()
    for b in bindings:
        if b.value.kind == "check_preimage":
            return True
        if b.value.kind == "if":
            if _method_uses_check_preimage(b.value.then, private_methods, seen):
                return True
            if _method_uses_check_preimage(b.value.else_ or [], private_methods, seen):
                return True
        if b.value.kind == "loop":
            if _method_uses_check_preimage(b.value.body, private_methods, seen):
                return True
        if b.value.kind == "method_call" and private_methods is not None:
            target = private_methods.get(b.value.method)
            if target is not None and target.name not in seen:
                next_seen = seen | {target.name}
                if _method_uses_check_preimage(target.body, private_methods, next_seen):
                    return True
    return False


def _method_uses_code_part(bindings: list[ANFBinding]) -> bool:
    """Check whether a method has add_output, add_raw_output, add_data_output,
    or computeStateOutput/computeStateOutputHash calls (recursively). Only
    methods that construct continuation outputs need the _codePart implicit
    parameter."""
    for b in bindings:
        if b.value.kind in ("add_output", "add_raw_output", "add_data_output"):
            return True
        # Single-output stateful continuation uses computeStateOutput/computeStateOutputHash
        if b.value.kind == "call" and getattr(b.value, "func", None) in ("computeStateOutput", "computeStateOutputHash"):
            return True
        # Recurse into if-else branches and loops
        if b.value.kind == "if":
            then_bindings = getattr(b.value, "then", None) or []
            else_bindings = getattr(b.value, "else_", None) or []
            if _method_uses_code_part(then_bindings) or _method_uses_code_part(else_bindings):
                return True
        if b.value.kind == "loop":
            body_bindings = getattr(b.value, "body", None) or []
            if _method_uses_code_part(body_bindings):
                return True
    return False


def _method_reads_var_len_state(
    bindings: list[ANFBinding],
    var_len_props: set[str],
    private_methods: dict | None = None,
    seen: set[str] | None = None,
) -> bool:
    """Whether a method READS a mutable variable-length (ByteString) state
    field's value (via load_prop). Issue #100: such a terminal method needs
    _codePart for the preimage-relative state offset. Narrowed to the live
    var-length read so methods that only read readonly fields (baked into the
    locking script) or fixed-size fields keep their original terminal codegen.

    Deep-review finding C18: private methods are INLINED into the caller's
    stack context, so a read that happens inside a private helper is a read by
    the public caller. Recurse through private method_call targets (cycle-
    guarded via `seen`) exactly like the sibling _method_uses_check_preimage --
    otherwise _codePart is never pushed and the load_prop falls through to the
    deploy-time constructor placeholder instead of the live on-chain state."""
    if seen is None:
        seen = set()
    for b in bindings:
        if b.value.kind == "load_prop" and getattr(b.value, "name", None) in var_len_props:
            return True
        if b.value.kind == "if":
            then_bindings = getattr(b.value, "then", None) or []
            else_bindings = getattr(b.value, "else_", None) or []
            if (_method_reads_var_len_state(then_bindings, var_len_props, private_methods, seen)
                    or _method_reads_var_len_state(else_bindings, var_len_props, private_methods, seen)):
                return True
        if b.value.kind == "loop":
            body_bindings = getattr(b.value, "body", None) or []
            if _method_reads_var_len_state(body_bindings, var_len_props, private_methods, seen):
                return True
        if b.value.kind == "method_call" and private_methods is not None:
            target = private_methods.get(b.value.method)
            if target is not None and target.name not in seen:
                next_seen = seen | {target.name}
                if _method_reads_var_len_state(target.body, var_len_props, private_methods, next_seen):
                    return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lower_to_stack(program: ANFProgram, ec_codegen=None) -> list[StackMethod]:
    """Convert an ANF program to a list of StackMethods.

    Private methods are inlined at call sites rather than compiled separately.
    The constructor is skipped since it's not emitted to Bitcoin Script.

    Catches any internal errors (stack underflow, unknown operators, type
    mismatches, etc.) and converts them to RuntimeError with a descriptive
    message instead of letting raw exceptions propagate.
    """
    from runar_compiler.ir.unknown_anf_kind_error import UnknownANFKindError
    try:
        return _lower_to_stack_inner(program, ec_codegen)
    except RuntimeError:
        # RuntimeError messages are already descriptive (e.g. "stack underflow",
        # "unknown binary operator: ...", "value 'x' not found on stack").
        # Re-raise as-is so callers get a clear error.
        raise
    except UnknownANFKindError:
        # Typed exhaustiveness guard -- preserve the kind / location so the
        # regression test (and any caller) can pattern-match on it.
        raise
    except Exception as e:
        raise RuntimeError(f"stack lowering: {e}") from e


def _lower_to_stack_inner(program: ANFProgram, ec_codegen=None) -> list[StackMethod]:
    """Inner implementation of lower_to_stack (unwrapped)."""
    # Build map of private methods for inlining
    private_methods: dict[str, ANFMethod] = {}
    for m in program.methods:
        if not m.is_public and m.name != "constructor":
            private_methods[m.name] = m

    methods: list[StackMethod] = []

    for method in program.methods:
        # Skip constructor and private methods
        if method.name == "constructor" or (not method.is_public and method.name != "constructor"):
            continue
        sm = _lower_method_with_private_methods(
            method, program.properties, private_methods, ec_codegen)
        methods.append(sm)

    return methods


def _lower_method_with_private_methods(
    method: ANFMethod,
    properties: list[ANFProperty],
    private_methods: dict[str, ANFMethod],
    ec_codegen=None,
) -> StackMethod:
    param_names = [p.name for p in method.params]

    # If the method uses checkPreimage, the unlocking script pushes implicit
    # params before all declared parameters (OP_PUSH_TX pattern).
    # _codePart: full code script (locking script minus state) as ByteString.
    # (BUG-100 fix: the OP_PUSH_TX signature is now derived on-chain from the
    # preimage — see _lower_check_preimage — so NO _opPushTxSig witness item is
    # pushed. The unlocking script provides only the preimage.)
    # _codePart is needed for continuation builders (add_output/add_raw_output)
    # OR when the method reads a mutable variable-length (ByteString) state
    # field — the deserialization needs it for the preimage-relative offset
    # (issue #100).
    var_len_props = {
        p.name for p in properties if not p.readonly and p.type == "ByteString"
    }
    uses_code_part = (
        _method_uses_check_preimage(method.body, private_methods)
        and (_method_uses_code_part(method.body)
             or _method_reads_var_len_state(method.body, var_len_props, private_methods))
    )
    if _method_uses_check_preimage(method.body, private_methods) and uses_code_part:
        param_names = ["_codePart"] + param_names

    ctx = _LoweringContext(param_names, properties)
    ctx.ec_codegen = ec_codegen
    ctx.private_methods = private_methods
    # Pass terminalAssert=true for public methods
    ctx.lower_bindings(method.body, method.is_public)

    # Clean up excess stack items below the top-of-stack boolean (CLEANSTACK).
    # Excess items can come from deserialize_state (stateful methods reading
    # mutable fields) or from readonly-field-binding patterns in all-readonly
    # terminal methods. The depth>1 guard keeps this a no-op for already-clean
    # methods.
    if method.is_public and ctx.sm.depth() > 1:
        excess = ctx.sm.depth() - 1
        for _ in range(excess):
            ctx.emit_op(StackOp(op="nip"))
            ctx.sm.remove_at_depth(1)

    if ctx.max_depth > MAX_STACK_DEPTH:
        raise RuntimeError(
            f"method '{method.name}' exceeds maximum stack depth of {MAX_STACK_DEPTH} "
            f"(actual: {ctx.max_depth}). Simplify the contract logic"
        )

    return StackMethod(
        name=method.name,
        ops=ctx.ops,
        max_stack_depth=ctx.max_depth,
        uses_code_part=uses_code_part,
    )


def _lower_method(
    method: ANFMethod,
    properties: list[ANFProperty],
    ec_codegen=None,
) -> StackMethod:
    param_names = [p.name for p in method.params]

    ctx = _LoweringContext(param_names, properties)
    ctx.ec_codegen = ec_codegen
    ctx.lower_bindings(method.body, method.is_public)

    # Clean up excess stack items below the top-of-stack boolean (CLEANSTACK).
    # Excess items can come from deserialize_state (stateful methods reading
    # mutable fields) or from readonly-field-binding patterns in all-readonly
    # terminal methods. The depth>1 guard keeps this a no-op for already-clean
    # methods.
    if method.is_public and ctx.sm.depth() > 1:
        excess = ctx.sm.depth() - 1
        for _ in range(excess):
            ctx.emit_op(StackOp(op="nip"))
            ctx.sm.remove_at_depth(1)

    if ctx.max_depth > MAX_STACK_DEPTH:
        raise RuntimeError(
            f"method '{method.name}' exceeds maximum stack depth of {MAX_STACK_DEPTH} "
            f"(actual: {ctx.max_depth}). Simplify the contract logic"
        )

    return StackMethod(
        name=method.name,
        ops=ctx.ops,
        max_stack_depth=ctx.max_depth,
    )
