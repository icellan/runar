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
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_STACK_DEPTH = 800

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
                             # "placeholder"
    value: Optional[PushValue] = None   # for push ops
    depth: int = 0           # for roll/pick (informational)
    code: str = ""           # for opcode ops (e.g. "OP_ADD")
    then: list[StackOp] = field(default_factory=list)      # for if ops
    else_ops: list[StackOp] = field(default_factory=list)   # for if ops
    param_index: int = 0     # for placeholder ops -- index into constructor params
    param_name: str = ""     # for placeholder ops -- name of constructor param


@dataclass
class StackMethod:
    """Stack-lowered form of a single contract method."""

    name: str = ""
    ops: list[StackOp] = field(default_factory=list)
    max_stack_depth: int = 0


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


# ---------------------------------------------------------------------------
# Use analysis -- determine last-use sites for each variable
# ---------------------------------------------------------------------------

def compute_last_uses(bindings: list[ANFBinding]) -> dict[str, int]:
    last_use: dict[str, int] = {}
    for i, binding in enumerate(bindings):
        refs = collect_refs(binding.value)
        for ref in refs:
            last_use[ref] = i
    return last_use


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
    elif kind == "array_literal":
        refs.extend(value.elements)

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
        self._track_depth()

    def _track_depth(self) -> None:
        if self.sm.depth() > self.max_depth:
            self.max_depth = self.sm.depth()

    def emit_op(self, op: StackOp) -> None:
        self.ops.append(op)
        self._track_depth()

    def emit_varint_encoding(self) -> None:
        """Emit Bitcoin varint encoding of the length on top of the stack.

        Expects stack: [..., script, len]
        Leaves stack:  [..., script, varint_bytes]

        OP_NUM2BIN uses sign-magnitude encoding where values 128-255 need
        2 bytes (sign bit). To produce a correct 1-byte unsigned varint,
        we use OP_NUM2BIN 2 then SPLIT to extract only the low byte.
        Similarly for 2-byte unsigned varint, we use OP_NUM2BIN 4 then SPLIT.
        """
        # Stack: [..., script, len]
        self.emit_op(StackOp(op="dup"))  # [script, len, len]
        self.sm.dup()
        self.emit_op(StackOp(op="push", value=big_int_push(253)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")

        self.emit_op(StackOp(op="opcode", code="OP_IF"))
        self.sm.pop()  # pop condition

        # Then: 1-byte varint (len < 253)
        self.emit_op(StackOp(op="push", value=big_int_push(2)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(1)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")  # lowByte
        self.sm.push("")  # highByte
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()

        self.emit_op(StackOp(op="opcode", code="OP_ELSE"))

        # Else: 0xfd + 2-byte LE varint (len >= 253)
        self.emit_op(StackOp(op="push", value=big_int_push(4)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="push", value=big_int_push(2)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")  # low2bytes
        self.sm.push("")  # high2bytes
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=bytes([0xFD]))))
        self.sm.push("")
        self.emit_op(StackOp(op="swap"))
        self.sm.swap()
        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))
        self.sm.push("")

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

    def _is_last_use(self, ref: str, current_index: int, last_uses: dict[str, int]) -> bool:
        last = last_uses.get(ref)
        if last is None:
            return True
        return last <= current_index

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
            if binding.value.kind == "assert" and i == last_assert_idx:
                # Terminal assert: leave value on stack instead of OP_VERIFY
                self._lower_assert(binding.value.value_ref, i, last_uses, True)
            elif binding.value.kind == "if" and i == terminal_if_idx:
                # Terminal if: propagate terminalAssert into both branches
                self._lower_if(
                    binding.name, binding.value.cond,
                    binding.value.then, binding.value.else_,
                    i, last_uses, True,
                )
            else:
                self._lower_binding(binding, i, last_uses)

    def _lower_bindings_protected(self, bindings: list[ANFBinding], protected_names: set[str]) -> None:
        """Like lower_bindings but never consumes protected names."""
        last_uses = compute_last_uses(bindings)

        # Remove + re-add with very high index so isLastUse always returns false
        for name in protected_names:
            last_uses[name] = (1 << 31) - 1

        for i, binding in enumerate(bindings):
            self._lower_binding(binding, i, last_uses)

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
            self._lower_if(name, value.cond, value.then, value.else_, binding_index, last_uses)
        elif kind == "loop":
            self._lower_loop(name, value.count, value.body, value.iter_var)
        elif kind == "assert":
            self._lower_assert(value.value_ref, binding_index, last_uses, False)
        elif kind == "update_prop":
            self._lower_update_prop(value.name, value.value_ref, binding_index, last_uses)
        elif kind == "get_state_script":
            self._lower_get_state_script(name)
        elif kind == "check_preimage":
            self._lower_check_preimage(name, value.preimage, binding_index, last_uses)
        elif kind == "deserialize_state":
            self._lower_deserialize_state(value.preimage, binding_index, last_uses)
        elif kind == "add_output":
            self._lower_add_output(name, value.satoshis, value.state_values, value.preimage, binding_index, last_uses)
        elif kind == "add_raw_output":
            self._lower_add_raw_output(name, value.satoshis, value.script_bytes, binding_index, last_uses)
        elif kind == "array_literal":
            self._lower_array_literal(name, value.elements, binding_index, last_uses)

    # -----------------------------------------------------------------
    # Individual lowering methods
    # -----------------------------------------------------------------

    def _lower_load_param(self, binding_name: str, param_name: str,
                          binding_index: int, last_uses: dict[str, int]) -> None:
        if self.sm.has(param_name):
            is_last = self._is_last_use(param_name, binding_index, last_uses)
            self.bring_to_top(param_name, is_last)
            self.sm.pop()
            self.sm.push(binding_name)
        else:
            self.emit_op(StackOp(op="push", value=big_int_push(0)))
            self.sm.push(binding_name)

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
            param_index = 0
            for i, p in enumerate(self.properties):
                if p.name == prop_name:
                    param_index = i
                    break
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
                # Referenced value not on stack -- push placeholder
                self.emit_op(StackOp(op="push", value=big_int_push(0)))
                self.sm.push(binding_name)
            return

        # Handle @this marker -- compile-time concept, not a runtime value
        if value.const_string is not None and value.const_string == "@this":
            self.emit_op(StackOp(op="push", value=big_int_push(0)))
            self.sm.push(binding_name)
            return

        if value.const_bool is not None:
            self.emit_op(StackOp(op="push", value=PushValue(kind="bool", bool_val=value.const_bool)))
        elif value.const_int is not None:
            self.emit_op(StackOp(op="push", value=big_int_push(value.const_int)))
        elif value.const_string is not None:
            self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=_hex_to_bytes(value.const_string))))
        else:
            # Fallback: push 0
            self.emit_op(StackOp(op="push", value=big_int_push(0)))
        self.sm.push(binding_name)

    # -----------------------------------------------------------------
    # Binary / unary ops
    # -----------------------------------------------------------------

    def _lower_bin_op(self, binding_name: str, op: str, left: str, right: str,
                      binding_index: int, last_uses: dict[str, int], result_type: str) -> None:
        left_is_last = self._is_last_use(left, binding_index, last_uses)
        self.bring_to_top(left, left_is_last)

        right_is_last = self._is_last_use(right, binding_index, last_uses)
        self.bring_to_top(right, right_is_last)

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
            is_last = self._is_last_use(arg, binding_index, last_uses)
            self.bring_to_top(arg, is_last)

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
            self.sm.push("")            # original value still present
            self.sm.push(binding_name)  # size on top
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
                is_last = self._is_last_use(arg, binding_index, last_uses)
                self.bring_to_top(arg, is_last)
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
                  binding_index: int, last_uses: dict[str, int],
                  terminal_assert: bool = False) -> None:
        is_last = self._is_last_use(cond, binding_index, last_uses)
        self.bring_to_top(cond, is_last)
        self.sm.pop()  # OP_IF consumes the condition

        # Identify parent-scope items still needed after this if-expression.
        protected_refs: set[str] = set()
        for ref, last_idx in last_uses.items():
            if last_idx > binding_index and self.sm.has(ref):
                protected_refs.add(ref)

        # Snapshot parent stackMap names before branches run
        pre_if_names = self.sm.named_slots()

        # Lower then-branch
        then_ctx = _LoweringContext(None, self.properties)
        then_ctx.sm = self.sm.clone()
        then_ctx.outer_protected_refs = protected_refs
        then_ctx.inside_branch = True
        then_ctx.lower_bindings(then_bindings, terminal_assert)

        if terminal_assert and then_ctx.sm.depth() > 1:
            excess = then_ctx.sm.depth() - 1
            for _ in range(excess):
                then_ctx.emit_op(StackOp(op="nip"))
                then_ctx.sm.remove_at_depth(1)

        # Lower else-branch
        else_ctx = _LoweringContext(None, self.properties)
        else_ctx.sm = self.sm.clone()
        else_ctx.outer_protected_refs = protected_refs
        else_ctx.inside_branch = True
        else_ctx.lower_bindings(else_bindings, terminal_assert)

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

        # Phase 3: single depth-balance check after ALL drops.
        # Push placeholder only if one branch is still deeper than the other.
        if then_ctx.sm.depth() > else_ctx.sm.depth():
            # When the then-branch reassigned a local variable (if-without-else),
            # push a COPY of that variable in the else-branch instead of a generic
            # placeholder.
            then_top_p3 = then_ctx.sm.peek_at_depth(0)
            if (not else_bindings and then_top_p3
                    and else_ctx.sm.has(then_top_p3)):
                var_depth = else_ctx.sm.find_depth(then_top_p3)
                if var_depth == 0:
                    else_ctx.emit_op(StackOp(op="dup"))
                else:
                    else_ctx.emit_op(StackOp(op="push", value=big_int_push(var_depth)))
                    else_ctx.sm.push("")
                    else_ctx.emit_op(StackOp(op="pick", depth=var_depth))
                    else_ctx.sm.pop()
                else_ctx.sm.push(then_top_p3)
            else:
                else_ctx.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=b"")))
                else_ctx.sm.push("")
        elif else_ctx.sm.depth() > then_ctx.sm.depth():
            then_ctx.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=b"")))
            then_ctx.sm.push("")

        then_ops = then_ctx.ops
        else_ops = else_ctx.ops

        if_op = StackOp(op="if", then=then_ops)
        if else_ops:
            if_op.else_ops = else_ops
        self.emit_op(if_op)

        # Reconcile parent stackMap: remove items consumed by the branches.
        post_branch_names = then_ctx.sm.named_slots()
        for name in pre_if_names:
            if name not in post_branch_names and self.sm.has(name):
                depth = self.sm.find_depth(name)
                self.sm.remove_at_depth(depth)

        # The if expression may produce a result value on top.
        if then_ctx.sm.depth() > self.sm.depth():
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
                        break
            else:
                self.sm.push(binding_name)
        elif else_ctx.sm.depth() > self.sm.depth():
            self.sm.push(binding_name)
        else:
            pass  # Void if — don't push phantom

        self._track_depth()

        if then_ctx.max_depth > self.max_depth:
            self.max_depth = then_ctx.max_depth
        if else_ctx.max_depth > self.max_depth:
            self.max_depth = else_ctx.max_depth

    # -----------------------------------------------------------------
    # loop
    # -----------------------------------------------------------------

    def _lower_loop(self, binding_name: str, count: int,
                    body: list[ANFBinding], iter_var: str) -> None:
        # Collect body binding names
        body_binding_names: dict[str, bool] = {b.name: True for b in body}

        # Collect outer-scope names referenced in the loop body
        outer_refs: set[str] = set()
        for b in body:
            if b.value.kind == "load_param" and b.value.name != iter_var:
                outer_refs.add(b.value.name)
            # Also protect @ref: targets from outer scope (not redefined in body)
            if (b.value.kind == "load_const"
                    and b.value.const_string is not None
                    and len(b.value.const_string) > 5
                    and b.value.const_string[:5] == "@ref:"):
                ref_name = b.value.const_string[5:]
                if ref_name not in body_binding_names:
                    outer_refs.add(ref_name)

        # Temporarily extend localBindings with body binding names
        prev_local_bindings = self.local_bindings
        new_local_bindings = dict(prev_local_bindings)
        new_local_bindings.update(body_binding_names)
        self.local_bindings = new_local_bindings

        for i in range(count):
            self.emit_op(StackOp(op="push", value=big_int_push(i)))
            self.sm.push(iter_var)

            last_uses = compute_last_uses(body)

            # In non-final iterations, prevent outer-scope refs from being consumed
            if i < count - 1:
                for ref_name in outer_refs:
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
        state_last = self._is_last_use(state_bytes_ref, binding_index, last_uses)
        self.bring_to_top(state_bytes_ref, state_last)

        # Extract amount from preimage for the continuation output.
        pre_last = self._is_last_use(preimage_ref, binding_index, last_uses)
        self.bring_to_top(preimage_ref, pre_last)

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

        # Consume preimage ref (no longer needed -- we use _codePart and _newAmount).
        pre_last = self._is_last_use(preimage_ref, binding_index, last_uses)
        self.bring_to_top(preimage_ref, pre_last)
        self.emit_op(StackOp(op="drop"))
        self.sm.pop()

        # Step 1: Convert _newAmount to 8-byte LE and save to altstack.
        amount_last = self._is_last_use(new_amount_ref, binding_index, last_uses)
        self.bring_to_top(new_amount_ref, amount_last)
        self.emit_op(StackOp(op="push", value=big_int_push(8)))
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
        self.sm.pop()
        self.sm.pop()
        self.sm.push("")
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
        self.sm.pop()

        # Step 2: Bring stateBytes to stack.
        state_last = self._is_last_use(state_bytes_ref, binding_index, last_uses)
        self.bring_to_top(state_bytes_ref, state_last)

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
        self.bring_to_top(pkh_ref, self._is_last_use(pkh_ref, binding_index, last_uses))
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
        self.bring_to_top(amount_ref, self._is_last_use(amount_ref, binding_index, last_uses))
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
            elif p.type == "boolean":
                sz = 1
            elif p.type == "PubKey":
                sz = 33
            elif p.type == "Addr":
                sz = 20
            elif p.type == "Sha256":
                sz = 32
            elif p.type == "Point":
                sz = 64
            elif p.type == "ByteString":
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
            # Variable-length path: strip varint, use _codePart
            self.emit_op(StackOp(op="push", value=big_int_push(1)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop(); self.sm.pop()
            self.sm.push(""); self.sm.push("")
            self.emit_op(StackOp(op="swap"))
            self.sm.swap()
            self.emit_op(StackOp(op="dup"))
            self.sm.push(self.sm.peek_at_depth(0))
            # Zero-pad before BIN2NUM to prevent sign-bit misinterpretation (0xfd → -125 without pad)
            self.emit_op(StackOp(op="push", value=bytes([0])))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_CAT"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
            self.emit_op(StackOp(op="push", value=big_int_push(253)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_LESSTHAN"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")

            self.emit_op(StackOp(op="opcode", code="OP_IF"))
            self.sm.pop()
            sm_at_varint_if = self.sm.clone()
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()

            self.emit_op(StackOp(op="opcode", code="OP_ELSE"))
            self.sm = sm_at_varint_if.clone()
            self.emit_op(StackOp(op="drop"))
            self.sm.pop()
            self.emit_op(StackOp(op="push", value=big_int_push(2)))
            self.sm.push("")
            self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
            self.sm.pop(); self.sm.pop()
            self.sm.push(""); self.sm.push("")
            self.emit_op(StackOp(op="nip"))
            self.sm.pop(); self.sm.pop()
            self.sm.push("")

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
            if prop.type in ("bigint", "boolean"):
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
                    if prop.type in ("bigint", "boolean"):
                        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
                    self.emit_op(StackOp(op="swap"))
                    self.sm.swap()
                    self.sm.pop(); self.sm.pop()
                    self.sm.push(prop.name)
                    self.sm.push("")
                else:
                    if prop.type in ("bigint", "boolean"):
                        self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
                    self.sm.pop()
                    self.sm.push(prop.name)

    def _parse_variable_length_state_fields(self, state_props: list[ANFProperty], prop_sizes: list[int]) -> None:
        if len(state_props) == 1:
            prop = state_props[0]
            if prop.type == "ByteString":
                # Single ByteString field: decode push-data prefix, drop trailing empty
                self.emit_push_data_decode()  # [..., data, remaining]
                self.emit_op(StackOp(op="drop")); self.sm.pop()
            elif prop.type in ("bigint", "boolean"):
                self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
            self.sm.pop()
            self.sm.push(prop.name)
        else:
            for i, prop in enumerate(state_props):
                if i < len(state_props) - 1:
                    if prop.type == "ByteString":
                        # ByteString: decode push-data prefix, extract data
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
                        if prop.type in ("bigint", "boolean"):
                            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
                        self.emit_op(StackOp(op="swap")); self.sm.swap()
                        self.sm.pop(); self.sm.pop()
                        self.sm.push(prop.name)
                        self.sm.push("")
                else:
                    if prop.type == "ByteString":
                        # Last ByteString: decode push-data prefix, drop trailing empty
                        self.emit_push_data_decode()  # [..., data, remaining]
                        self.emit_op(StackOp(op="drop")); self.sm.pop()
                    elif prop.type in ("bigint", "boolean"):
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

            is_last = self._is_last_use(value_ref, binding_index, last_uses)
            self.bring_to_top(value_ref, is_last)

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
        is_last_sat = self._is_last_use(satoshis, binding_index, last_uses)
        self.bring_to_top(satoshis, is_last_sat)
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
        script_is_last = self._is_last_use(script_bytes, binding_index, last_uses)
        self.bring_to_top(script_bytes, script_is_last)

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
        sat_is_last = self._is_last_use(satoshis, binding_index, last_uses)
        self.bring_to_top(satoshis, sat_is_last)
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
        """Lower an array_literal by bringing each element to the top of the stack.

        The elements remain as individual stack entries; the binding name tracks
        the last element so that callers (e.g. checkMultiSig) can find them.
        """
        for elem in elements:
            is_last = self._is_last_use(elem, binding_index, last_uses)
            self.bring_to_top(elem, is_last)
            self.sm.pop()
            self.sm.push("")  # anonymous stack entry for intermediate elements
        # Rename the topmost entry to the binding name
        if elements:
            self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # checkMultiSig
    # -----------------------------------------------------------------

    def _lower_check_multi_sig(self, binding_name: str, args: list[str],
                                binding_index: int, last_uses: dict[str, int]) -> None:
        """Emit OP_CHECKMULTISIG with the OP_0 dummy workaround.

        Bitcoin Script stack layout:
          OP_0 <sig1> ... <sigN> <nSigs> <pk1> ... <pkM> <nPKs> OP_CHECKMULTISIG

        The two args reference array_literal bindings whose individual elements
        are already on the stack.
        """
        # Push OP_0 dummy (Bitcoin CHECKMULTISIG off-by-one bug workaround)
        self.emit_op(StackOp(op="push", value=big_int_push(0)))
        self.sm.push("")

        # Bring sigs array ref to top
        sigs_is_last = self._is_last_use(args[0], binding_index, last_uses)
        self.bring_to_top(args[0], sigs_is_last)

        # Bring pks array ref to top
        pks_is_last = self._is_last_use(args[1], binding_index, last_uses)
        self.bring_to_top(args[1], pks_is_last)

        # Pop all args + dummy
        self.sm.pop()  # pks
        self.sm.pop()  # sigs
        self.sm.pop()  # OP_0 dummy

        self.emit_op(StackOp(op="opcode", code="OP_CHECKMULTISIG"))
        self.sm.push(binding_name)
        self._track_depth()

    # -----------------------------------------------------------------
    # check_preimage (OP_PUSH_TX)
    # -----------------------------------------------------------------

    def _lower_check_preimage(self, binding_name: str, preimage: str,
                              binding_index: int, last_uses: dict[str, int]) -> None:
        # Step 0: Emit OP_CODESEPARATOR so that the scriptCode in the BIP-143
        # preimage is only the code after this point. This reduces preimage size
        # for large scripts and is required for scripts > ~32KB.
        self.emit_op(StackOp(op="opcode", code="OP_CODESEPARATOR"))

        # Step 1: Bring preimage to top (non-consuming)
        is_last = self._is_last_use(preimage, binding_index, last_uses)
        self.bring_to_top(preimage, is_last)

        # Step 2: Bring the implicit _opPushTxSig to top (consuming)
        self.bring_to_top("_opPushTxSig", True)

        # Step 3: Push compressed secp256k1 generator point G (33 bytes)
        G = bytes([
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
            0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
            0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
            0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
            0x98,
        ])
        self.emit_op(StackOp(op="push", value=PushValue(kind="bytes", bytes_val=G)))
        self.sm.push("")  # G on stack

        # Step 4: OP_CHECKSIGVERIFY
        self.emit_op(StackOp(op="opcode", code="OP_CHECKSIGVERIFY"))
        self.sm.pop()  # G consumed
        self.sm.pop()  # _opPushTxSig consumed

        # Preimage remains on top.  Rename for field extractors.
        self.sm.pop()
        self.sm.push(binding_name)
        self._track_depth()

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

        obj_is_last = self._is_last_use(obj, binding_index, last_uses)
        self.bring_to_top(obj, obj_is_last)

        index_is_last = self._is_last_use(index, binding_index, last_uses)
        self.bring_to_top(index, index_is_last)

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

        data_is_last = self._is_last_use(data, binding_index, last_uses)
        self.bring_to_top(data, data_is_last)

        start_is_last = self._is_last_use(start, binding_index, last_uses)
        self.bring_to_top(start, start_is_last)

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
        len_is_last = self._is_last_use(length, binding_index, last_uses)
        self.bring_to_top(length, len_is_last)

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
        if len(args) < 4:
            raise RuntimeError("verifyRabinSig requires 4 arguments")

        msg, sig, padding, pub_key = args[0], args[1], args[2], args[3]

        msg_is_last = self._is_last_use(msg, binding_index, last_uses)
        self.bring_to_top(msg, msg_is_last)

        sig_is_last = self._is_last_use(sig, binding_index, last_uses)
        self.bring_to_top(sig, sig_is_last)

        padding_is_last = self._is_last_use(padding, binding_index, last_uses)
        self.bring_to_top(padding, padding_is_last)

        pub_key_is_last = self._is_last_use(pub_key, binding_index, last_uses)
        self.bring_to_top(pub_key, pub_key_is_last)

        # Pop all 4 args
        for _ in range(4):
            self.sm.pop()

        # Rabin sig verification opcode sequence
        self.emit_op(StackOp(op="opcode", code="OP_SWAP"))
        self.emit_op(StackOp(op="opcode", code="OP_ROT"))
        self.emit_op(StackOp(op="opcode", code="OP_DUP"))
        self.emit_op(StackOp(op="opcode", code="OP_MUL"))
        self.emit_op(StackOp(op="opcode", code="OP_ADD"))
        self.emit_op(StackOp(op="opcode", code="OP_SWAP"))
        self.emit_op(StackOp(op="opcode", code="OP_MOD"))
        self.emit_op(StackOp(op="opcode", code="OP_SWAP"))
        self.emit_op(StackOp(op="opcode", code="OP_SHA256"))
        self.emit_op(StackOp(op="opcode", code="OP_EQUAL"))

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

        data_is_last = self._is_last_use(data, binding_index, last_uses)
        self.bring_to_top(data, data_is_last)

        length_is_last = self._is_last_use(length, binding_index, last_uses)
        self.bring_to_top(length, length_is_last)

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

        a_is_last = self._is_last_use(a, binding_index, last_uses)
        self.bring_to_top(a, a_is_last)

        b_is_last = self._is_last_use(b, binding_index, last_uses)
        self.bring_to_top(b, b_is_last)

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

        val_is_last = self._is_last_use(val, binding_index, last_uses)
        self.bring_to_top(val, val_is_last)

        lo_is_last = self._is_last_use(lo, binding_index, last_uses)
        self.bring_to_top(lo, lo_is_last)

        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_MAX"))
        self.sm.push("")

        hi_is_last = self._is_last_use(hi, binding_index, last_uses)
        self.bring_to_top(hi, hi_is_last)

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

        base_is_last = self._is_last_use(base, binding_index, last_uses)
        self.bring_to_top(base, base_is_last)

        exp_is_last = self._is_last_use(exp, binding_index, last_uses)
        self.bring_to_top(exp, exp_is_last)

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

        a_is_last = self._is_last_use(a, binding_index, last_uses)
        self.bring_to_top(a, a_is_last)
        b_is_last = self._is_last_use(b, binding_index, last_uses)
        self.bring_to_top(b, b_is_last)

        self.sm.pop()
        self.sm.pop()
        self.emit_op(StackOp(op="opcode", code="OP_MUL"))
        self.sm.push("")

        c_is_last = self._is_last_use(c, binding_index, last_uses)
        self.bring_to_top(c, c_is_last)

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

        amount_is_last = self._is_last_use(amount, binding_index, last_uses)
        self.bring_to_top(amount, amount_is_last)
        bps_is_last = self._is_last_use(bps, binding_index, last_uses)
        self.bring_to_top(bps, bps_is_last)

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

        a_is_last = self._is_last_use(a, binding_index, last_uses)
        self.bring_to_top(a, a_is_last)
        b_is_last = self._is_last_use(b, binding_index, last_uses)
        self.bring_to_top(b, b_is_last)

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

        a_is_last = self._is_last_use(a, binding_index, last_uses)
        self.bring_to_top(a, a_is_last)
        b_is_last = self._is_last_use(b, binding_index, last_uses)
        self.bring_to_top(b, b_is_last)

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

    def _emit_wots_one_chain(self, chain_index: int) -> None:
        """Emit one WOTS+ chain verification."""
        # Save steps_copy = 15 - digit to alt
        self.emit_op(StackOp(op="opcode", code="OP_DUP"))
        self.emit_op(StackOp(op="push", value=big_int_push(15)))
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="opcode", code="OP_SUB"))
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))

        # Save endpt, csum to alt
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))

        # Split 32B sig element
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="push", value=big_int_push(32)))
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
        self.emit_op(StackOp(op="swap"))

        # Hash loop
        for j in range(15):
            adrs_bytes = bytes([chain_index, j])
            self.emit_op(StackOp(op="opcode", code="OP_DUP"))
            self.emit_op(StackOp(op="opcode", code="OP_0NOTEQUAL"))
            self.emit_op(StackOp(
                op="if",
                then=[
                    StackOp(op="opcode", code="OP_1SUB"),
                ],
                else_ops=[
                    StackOp(op="swap"),
                    StackOp(op="push", value=big_int_push(2)),
                    StackOp(op="opcode", code="OP_PICK"),
                    StackOp(op="push", value=PushValue(kind="bytes", bytes_val=adrs_bytes)),
                    StackOp(op="opcode", code="OP_CAT"),
                    StackOp(op="swap"),
                    StackOp(op="opcode", code="OP_CAT"),
                    StackOp(op="opcode", code="OP_SHA256"),
                    StackOp(op="swap"),
                ],
            ))
        self.emit_op(StackOp(op="drop"))

        # Restore from altstack
        self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
        self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
        self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
        self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))

        # csum += steps_copy
        self.emit_op(StackOp(op="opcode", code="OP_ROT"))
        self.emit_op(StackOp(op="opcode", code="OP_ADD"))

        # Concat endpoint to endpt_acc
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="push", value=big_int_push(3)))
        self.emit_op(StackOp(op="opcode", code="OP_ROLL"))
        self.emit_op(StackOp(op="opcode", code="OP_CAT"))

    def _lower_verify_wots(self, binding_name: str, args: list[str],
                           binding_index: int, last_uses: dict[str, int]) -> None:
        if len(args) < 3:
            raise RuntimeError("verifyWOTS requires 3 arguments: msg, sig, pubkey")

        # Bring args to top
        for arg in args:
            self.bring_to_top(arg, self._is_last_use(arg, binding_index, last_uses))
        for _ in range(3):
            self.sm.pop()

        # Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
        self.emit_op(StackOp(op="push", value=big_int_push(32)))
        self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))

        # Rearrange: put pubSeed at bottom, hash msg
        self.emit_op(StackOp(op="opcode", code="OP_ROT"))
        self.emit_op(StackOp(op="opcode", code="OP_ROT"))
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="opcode", code="OP_SHA256"))

        # Canonical layout
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="push", value=big_int_push(0)))
        self.emit_op(StackOp(op="opcode", code="OP_0"))
        self.emit_op(StackOp(op="push", value=big_int_push(3)))
        self.emit_op(StackOp(op="opcode", code="OP_ROLL"))

        # Process 32 bytes -> 64 message chains
        for byte_idx in range(32):
            if byte_idx < 31:
                self.emit_op(StackOp(op="push", value=big_int_push(1)))
                self.emit_op(StackOp(op="opcode", code="OP_SPLIT"))
                self.emit_op(StackOp(op="swap"))
            # Unsigned byte conversion
            self.emit_op(StackOp(op="push", value=big_int_push(0)))
            self.emit_op(StackOp(op="push", value=big_int_push(1)))
            self.emit_op(StackOp(op="opcode", code="OP_NUM2BIN"))
            self.emit_op(StackOp(op="opcode", code="OP_CAT"))
            self.emit_op(StackOp(op="opcode", code="OP_BIN2NUM"))
            # Extract nibbles
            self.emit_op(StackOp(op="opcode", code="OP_DUP"))
            self.emit_op(StackOp(op="push", value=big_int_push(16)))
            self.emit_op(StackOp(op="opcode", code="OP_DIV"))
            self.emit_op(StackOp(op="swap"))
            self.emit_op(StackOp(op="push", value=big_int_push(16)))
            self.emit_op(StackOp(op="opcode", code="OP_MOD"))

            if byte_idx < 31:
                self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
                self.emit_op(StackOp(op="swap"))
                self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
            else:
                self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))

            self._emit_wots_one_chain(byte_idx * 2)  # high nibble chain

            if byte_idx < 31:
                self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
                self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
                self.emit_op(StackOp(op="swap"))
                self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
            else:
                self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))

            self._emit_wots_one_chain(byte_idx * 2 + 1)  # low nibble chain

            if byte_idx < 31:
                self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))

        # Checksum digits
        self.emit_op(StackOp(op="swap"))
        # d66
        self.emit_op(StackOp(op="opcode", code="OP_DUP"))
        self.emit_op(StackOp(op="push", value=big_int_push(16)))
        self.emit_op(StackOp(op="opcode", code="OP_MOD"))
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
        # d65
        self.emit_op(StackOp(op="opcode", code="OP_DUP"))
        self.emit_op(StackOp(op="push", value=big_int_push(16)))
        self.emit_op(StackOp(op="opcode", code="OP_DIV"))
        self.emit_op(StackOp(op="push", value=big_int_push(16)))
        self.emit_op(StackOp(op="opcode", code="OP_MOD"))
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
        # d64
        self.emit_op(StackOp(op="push", value=big_int_push(256)))
        self.emit_op(StackOp(op="opcode", code="OP_DIV"))
        self.emit_op(StackOp(op="push", value=big_int_push(16)))
        self.emit_op(StackOp(op="opcode", code="OP_MOD"))
        self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))

        # 3 checksum chains (indices 64, 65, 66)
        for ci in range(3):
            self.emit_op(StackOp(op="opcode", code="OP_TOALTSTACK"))
            self.emit_op(StackOp(op="push", value=big_int_push(0)))
            self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
            self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
            self._emit_wots_one_chain(64 + ci)
            self.emit_op(StackOp(op="swap"))
            self.emit_op(StackOp(op="drop"))

        # Final comparison
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="drop"))
        self.emit_op(StackOp(op="opcode", code="OP_SHA256"))
        self.emit_op(StackOp(op="opcode", code="OP_FROMALTSTACK"))
        self.emit_op(StackOp(op="opcode", code="OP_EQUAL"))
        # Clean up pubSeed
        self.emit_op(StackOp(op="swap"))
        self.emit_op(StackOp(op="drop"))

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
            self.bring_to_top(arg, self._is_last_use(arg, binding_index, last_uses))
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
            self.bring_to_top(arg, self._is_last_use(arg, binding_index, last_uses))
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
            self.bring_to_top(arg, self._is_last_use(arg, binding_index, last_uses))
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
            self.bring_to_top(arg, self._is_last_use(arg, binding_index, last_uses))
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
            self.bring_to_top(arg, self._is_last_use(arg, binding_index, last_uses))
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
            is_last = self._is_last_use(arg, binding_index, last_uses)
            self.bring_to_top(arg, is_last)
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
        fn(emit_fn)

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
# methodUsesCheckPreimage
# ---------------------------------------------------------------------------

def _method_uses_check_preimage(bindings: list[ANFBinding]) -> bool:
    for b in bindings:
        if b.value.kind == "check_preimage":
            return True
    return False


def _method_uses_code_part(bindings: list[ANFBinding]) -> bool:
    """Check whether a method has add_output, add_raw_output, or computeStateOutput/
    computeStateOutputHash calls (recursively). Only methods that construct
    continuation outputs need the _codePart implicit parameter."""
    for b in bindings:
        if b.value.kind in ("add_output", "add_raw_output"):
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lower_to_stack(program: ANFProgram) -> list[StackMethod]:
    """Convert an ANF program to a list of StackMethods.

    Private methods are inlined at call sites rather than compiled separately.
    The constructor is skipped since it's not emitted to Bitcoin Script.
    """
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
        sm = _lower_method_with_private_methods(method, program.properties, private_methods)
        methods.append(sm)

    return methods


def _lower_method_with_private_methods(
    method: ANFMethod,
    properties: list[ANFProperty],
    private_methods: dict[str, ANFMethod],
) -> StackMethod:
    param_names = [p.name for p in method.params]

    # If the method uses checkPreimage, the unlocking script pushes implicit
    # params before all declared parameters (OP_PUSH_TX pattern).
    # _codePart: full code script (locking script minus state) as ByteString
    # _opPushTxSig: ECDSA signature for OP_PUSH_TX verification
    # These are inserted at the base of the stack so they can be consumed later.
    if _method_uses_check_preimage(method.body):
        param_names = ["_opPushTxSig"] + param_names
        # _codePart is needed when the method has add_output or add_raw_output
        # (it provides the code script for continuation output construction),
        # or when deserializing variable-length (ByteString) state fields.
        if _method_uses_code_part(method.body):
            param_names = ["_codePart"] + param_names
        # No else needed — terminal methods without addOutput don't need _codePart

    ctx = _LoweringContext(param_names, properties)
    ctx.private_methods = private_methods
    # Pass terminalAssert=true for public methods
    ctx.lower_bindings(method.body, method.is_public)

    # Clean up excess stack items left by deserialize_state.
    has_deserialize_state = any(b.value.kind == "deserialize_state" for b in method.body)
    if method.is_public and has_deserialize_state and ctx.sm.depth() > 1:
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


def _lower_method(
    method: ANFMethod,
    properties: list[ANFProperty],
) -> StackMethod:
    param_names = [p.name for p in method.params]

    ctx = _LoweringContext(param_names, properties)
    ctx.lower_bindings(method.body, method.is_public)

    # Clean up excess stack items left by deserialize_state.
    has_deserialize_state = any(b.value.kind == "deserialize_state" for b in method.body)
    if method.is_public and has_deserialize_state and ctx.sm.depth() > 1:
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
