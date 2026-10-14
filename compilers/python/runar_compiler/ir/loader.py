"""ANF IR loader and validator for the Runar compiler.

Direct port of ``compilers/go/ir/loader.go``.  Provides functions to load
ANF IR from JSON (file path or string), validate the structure, and decode
typed constant values.
"""

from __future__ import annotations

import json
from pathlib import Path

from .required_fields import assert_required_ir_fields
from .stateful_scaffold import stateful_scaffold_error
from .synthetic_array_chain import assert_synthetic_array_chains
from .rabin_key_provenance import assert_rabin_key_provenance
from .types import (
    ANFBinding,
    ANFMethod,
    ANFProgram,
    anf_program_from_dict,
    decode_constants,
)
from runar_compiler.frontend.input_limits import MAX_CALL_DEPTH, call_depth_message


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum number of loop iterations allowed in a single loop binding.
#: Prevents resource exhaustion from malicious or accidental extremely large
#: loop counts during loop unrolling.
MAX_LOOP_COUNT: int = 10_000

#: Set of all valid ANF value kinds.
KNOWN_KINDS: frozenset[str] = frozenset({
    "load_param",
    "load_prop",
    "load_const",
    "bin_op",
    "unary_op",
    "call",
    "method_call",
    "if",
    "loop",
    "assert",
    "update_prop",
    "get_state_script",
    "check_preimage",
    "deserialize_state",
    "add_output",
    "add_raw_output",
    "add_data_output",
    "array_literal",
    "raw_script",
})


def _is_hex_string(s: str) -> bool:
    """Return True if *s* contains only hex digits (0-9, a-f, A-F).

    An empty string is considered valid hex.
    """
    for c in s:
        if not (("0" <= c <= "9") or ("a" <= c <= "f") or ("A" <= c <= "F")):
            return False
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_ir(source: str) -> ANFProgram:
    """Load an ANF IR program from a JSON string.

    Parses the JSON, decodes typed constant values, and validates the
    structure.  Raises ``ValueError`` on any error.

    Rejects oversized (>MAX_IR_BYTES) or deeply-nested (>MAX_IR_NESTING)
    payloads with a typed
    :class:`runar_compiler.ir.input_limits.IRSizeExceededError` /
    :class:`runar_compiler.ir.input_limits.IRNestingExceededError`
    BEFORE :func:`json.loads` runs. BUG-008 follow-up.
    """
    from .input_limits import (
        IRFloatValueError,
        assert_ir_bytes_under_limit,
        assert_ir_nesting_under_limit,
        reject_json_constant,
        reject_json_float,
    )

    # DoS-bound guards run before json.loads so a malicious payload
    # cannot exhaust memory (size) or the Python interpreter recursion
    # stack (nesting) inside the deserializer.
    assert_ir_bytes_under_limit(source)
    assert_ir_nesting_under_limit(source)

    # N-131: `parse_float` / `parse_constant` refuse a number written in
    # float syntax DURING the parse, so no float is ever constructed. The
    # narrowing that follows (`int()` in decode_constants, `range()` in stack
    # lowering) used to be where a float surfaced, as a TypeError reported as
    # "this is a compiler bug" — or, for `{"step":1.5}`, not at all.
    try:
        d = json.loads(
            source,
            parse_float=reject_json_float,
            parse_constant=reject_json_constant,
        )
    except IRFloatValueError as exc:
        raise ValueError(str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid IR JSON: {exc}") from exc

    # N-069: required fields present and correctly typed, with the field path
    # in the diagnostic, before anf_program_from_dict defaults anything.
    assert_required_ir_fields(d)

    program = anf_program_from_dict(d)

    # N-060 / N-065: no name the compiler mints (shared diagnostic, 7 tiers).
    _assert_no_reserved_ir_names(program)

    # Decode typed constant values from raw JSON
    try:
        decode_constants(program)
    except ValueError as exc:
        raise ValueError(f"decoding constants: {exc}") from exc

    errors = validate_ir(program)
    if errors:
        raise ValueError(f"IR validation: {errors[0]}")

    # N-096: a syntheticArrayChain must be one expand-fixed-arrays could have
    # written (shared rule and diagnostic, 7 tiers).
    assert_synthetic_array_chains(program)

    # N-205: F-286's verifyRabinSig key provenance, and the write rule for a
    # mutable key property (shared rule and diagnostics, 7 tiers).
    assert_rabin_key_provenance(program)

    return program


def _assert_no_reserved_ir_names(program: ANFProgram) -> None:
    """N-060 / N-065 -- ``--ir`` names that alias a name the compiler mints.

    Stack lowering keeps its own slots (``_codePart``, ``__param_<name>``,
    ``__shadowed_<n>_<name>``, ``_pub_<n>``) in the same name map as the
    program's parameters and bindings and resolves every reference by name,
    so an IR that declares or references one aliases a compiler slot. A
    parameter, property, method or loop variable named like an ANF temp
    (``t<digits>``, ``__merge$<digits>``) aliases the bindings that ARE spelled
    that way; binding names in those families stay legal. Mirrors
    ``assertNoReservedIrNames`` in packages/runar-compiler/src/index.ts, with
    the source validator's message, shared verbatim by all seven tiers.
    """
    from runar_compiler.frontend.reserved_names import (
        is_reserved_ir_name,
        reserved_name_message,
    )

    def check(name, declaration: bool) -> None:
        if isinstance(name, str) and is_reserved_ir_name(name, declaration):
            raise ValueError(reserved_name_message(name))

    def walk(bindings) -> None:
        for b in bindings or []:
            check(b.name, False)
            v = b.value
            k = v.kind
            if k in ("load_param", "load_prop"):
                check(v.name, True)
            elif k == "update_prop":
                check(v.name, True)
                check(v.raw_value, False)
            elif k == "load_const":
                raw = v.raw_value
                if isinstance(raw, str) and raw.startswith("@ref:"):
                    check(raw[5:], False)
            elif k == "loop":
                check(v.iter_var, True)
            else:
                for r in (v.left, v.right, v.operand, v.cond, v.object,
                          v.preimage, v.satoshis, v.script_bytes):
                    check(r, False)
                if k == "assert":
                    check(v.raw_value, False)
                for lst in (v.args, v.state_values, v.elements):
                    for r in lst or []:
                        check(r, False)
            walk(v.body)
            walk(v.then)
            walk(v.else_)

    for prop in program.properties:
        check(prop.name, True)
    for method in program.methods:
        check(method.name, True)
        for param in method.params:
            check(param.name, True)
        walk(method.body)


def load_ir_from_file(path: str | Path) -> ANFProgram:
    """Load an ANF IR program from a JSON file on disk.

    Convenience wrapper around :func:`load_ir` that reads the file first.
    """
    file_path = Path(path)
    try:
        data = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"reading IR file: {exc}") from exc

    return load_ir(data)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_ir(program: ANFProgram) -> list[str]:
    """Validate the structure of a parsed ANF program.

    Returns a list of error strings (empty if valid).
    """
    errors: list[str] = []

    if not program.contract_name:
        errors.append("contractName is required")

    # R-126 / CL-BUG-164: an add_output must name exactly one state value per
    # MUTABLE property. Counted once, up front.
    mutable_count = sum(1 for p in program.properties if not p.readonly)
    # F-014 / CL-BUG-266: readonly properties, for the update_prop rule below.
    readonly_props = frozenset(p.name for p in program.properties if p.readonly)
    declared_props = frozenset(p.name for p in program.properties)

    # N-265: --ir never runs frontend/validator.py's _check_no_recursion,
    # which enforces both the call-graph cycle rule and N-180's
    # MAX_CALL_DEPTH (128) bound. Stack lowering (codegen/stack.py's
    # method_call inlining) inlines every method_call to a private method by
    # lowering its body in place, with no cycle or depth guard, so a
    # self/mutually-recursive method recurses the host call stack until
    # RecursionError, and an acyclic chain past the bound recurses it just as
    # deep. Checked first, same order as Go's F-004 checkIRFrontendRules
    # (recursion before parentClass).
    recursion_error = _recursion_error(program)
    if recursion_error:
        errors.append(recursion_error)

    # N-087: the source validator's parentClass rules (see
    # _parent_class_error). Ahead of the per-binding checks so that, as in
    # the other six tiers, it outranks the F-014 readonly-write diagnostic.
    parent_class_error = _parent_class_error(program)
    if parent_class_error:
        errors.append(parent_class_error)

    for i, method in enumerate(program.methods):
        if not method.name:
            errors.append(f"method[{i}] has empty name")
        for j, param in enumerate(method.params):
            if not param.name:
                errors.append(
                    f"method {method.name} param[{j}] has empty name"
                )
            if not param.type:
                errors.append(
                    f"method {method.name} param {param.name} has empty type"
                )
        errors.extend(
            _validate_bindings(
                method.body, method.name, mutable_count, readonly_props, declared_props
            )
        )

    for i, prop in enumerate(program.properties):
        if not prop.name:
            errors.append(f"property[{i}] has empty name")
        if not prop.type:
            errors.append(f"property {prop.name} has empty type")

    # F-014 / CL-BUG-266: the source validator requires every public
    # method to end with assert() (frontend/validator.py
    # ``_ends_with_assert``; UnsafeSmartContract may instead end with a
    # terminal asm() of out_arity 1). --ir runs no frontend, so a public
    # body of just ``load_const true`` compiled to 51 (OP_TRUE) --
    # anyone-can-spend. Appended after the structural checks so a malformed
    # binding keeps priority. IR carries no parentClass, so the terminal
    # raw_script form is accepted without the UnsafeSmartContract gate.
    for method in program.methods:
        if (
            method.is_public
            and method.name != "constructor"
            and not _ends_with_assert(method.body)
        ):
            # N-071: the sentence is shared verbatim by all seven tiers.
            errors.append(
                f"public method '{method.name}' must end with an assert() call "
                f"(or an if/else whose arms both do, or a terminal raw_script "
                f"with out_arity 1); otherwise the value its last binding "
                f"leaves on the stack decides the spend"
            )

    # N-101: a StatefulSmartContract (declared or inferred) must carry exactly
    # the scaffolding the frontend injects into each public method. Runs only
    # on IR every check above accepted. See ir/stateful_scaffold.py.
    if not errors and _effective_parent_class(program) == "StatefulSmartContract":
        scaffold_error = stateful_scaffold_error(program)
        if scaffold_error:
            errors.append(scaffold_error)

    # N-113 / R-081: a contract with no public method has no spending entry
    # point and emits an EMPTY locking script -- which is anyone-can-spend, not
    # merely useless. On the real @bsv/sdk `Spend` engine under full consensus
    # rules, an empty locking script with the one-byte push-only witness OP_1
    # (0x51) validates. Before this guard the --ir path exited 0 and handed the
    # SDKs a well-formed artifact whose "script" was "".
    #
    # The source pipeline already rejects the same shape in
    # frontend/validator.py; validate_ir is reached only from the IR loader, so
    # this closes the rule's gap on externally supplied IR.
    #
    # Appended LAST so the structural diagnostics above keep priority -- a
    # malformed binding is the more actionable error when both are present.
    # Mirrors compilers/go/ir/loader.go, including the ordering.
    #
    # N-113: the CONSTRUCTOR does not count. This check mirrors
    # frontend/validator.py, but runs over a differently-shaped list: the AST
    # keeps the constructor in `self.contract.constructor` while ANF lowering
    # flattens it INTO `program.methods`, so one `isPublic: true` on the
    # constructor walked past the guard. It is never a spending entry point
    # (emit and stack lowering both filter it out by NAME) and the contract
    # emitted an EMPTY locking script at exit 0.
    if not any(m.is_public and m.name != "constructor" for m in program.methods):
        errors.append(
            f"contract {program.contract_name} has no public methods "
            f"— no spending entry points; an empty locking script is "
            f"anyone-can-spend"
        )

    return errors


# ---------------------------------------------------------------------------
# Builtin call arity (R-128 / R-165)
# ---------------------------------------------------------------------------
#
# The source pipeline type-checks every call before codegen. ``--ir`` runs no
# frontend at all, so a call with the wrong number of arguments used to reach
# stack lowering, where each dispatch family pops ``len(args)`` from the stack
# MODEL and then emits a FIXED-arity opcode blob. Measured through the six
# ``--ir`` CLIs on one file:
#
#   cat(1 arg, needs 2)   go / ruby / rust / python compiled it to ``7e``,
#                         a bare OP_CAT with nothing beneath it
#   assert(0 args)        the same four emitted an EMPTY script -- the only
#                         guard in the contract vanished, which is
#                         anyone-can-spend, not merely wrong
#                         (java and zig refused both)
#
# The table is READ from the frontend's own signature map rather than copied,
# so the two cannot drift. Two builtins accept more than one count, both
# special-cased in ``typecheck`` for the same reason (an optional trailing
# argument the signature table cannot express), and one is variadic by a rule.

_VARIABLE_ARITY: dict[str, tuple[int, ...]] = {
    "assert": (1, 2),
    "extractPrevOutputScript": (2, 3),
}


def _merkle_poseidon2_arity_ok(got: int) -> tuple[bool, str]:
    """merkleRootPoseidon2KB takes 8 leaf + 8 per level + index + depth."""
    if got < 10:
        return False, "at least 10 arguments (8 leaf + index + depth)"
    if (got - 10) % 8 != 0:
        return False, "8*depth + 10 arguments"
    return True, ""


def _allowed_arity(name: str):
    """Allowed argument counts for a builtin, or None when it is not one."""
    from runar_compiler.frontend.typecheck import BUILTIN_FUNCTIONS

    if name in _VARIABLE_ARITY:
        return _VARIABLE_ARITY[name]
    sig = BUILTIN_FUNCTIONS.get(name)
    if sig is None:
        return None
    return (len(sig.params),)


_STATEFUL_ONLY_KINDS = frozenset({
    "add_output", "add_raw_output", "add_data_output",
    "get_state_script", "deserialize_state",
})


def _walk_values(bindings: list[ANFBinding] | None):
    for binding in bindings or []:
        yield binding.value
        yield from _walk_values(binding.value.then)
        yield from _walk_values(binding.value.else_)
        yield from _walk_values(binding.value.body)


# ---------------------------------------------------------------------------
# N-265: IR method_call graph -- recursion + N-180 call-depth bound
# ---------------------------------------------------------------------------
#
# Ported from Go's F-071 checkIRNoRecursion (compilers/go/compiler/
# ir_frontend_rules.go), made iterative there too under this item, and
# extended with N-180's depth bound -- Go's existing IR-path check was
# cycle-only, and this tier had no IR-path recursion check at all. Two
# passes, cycles checked before depth (a cyclic graph has no finite depth to
# measure), both iterative (explicit stack, no host recursion -- the Python
# interpreter's own recursion limit is exactly what an unbounded chain or
# cycle hit before this).

def _recursion_error(program: ANFProgram) -> str | None:
    """The first ANF method_call cycle or call-depth violation, or ``None``.

    Reports a cycle (a method strictly ON it, the exact "hit" a recursive
    depth-first search would report the moment it finds a back edge) before
    a depth violation, since a cyclic graph has no finite depth to measure.
    """
    callees: dict[str, list[str]] = {
        m.name: [v.method for v in _walk_values(m.body) if v.kind == "method_call" and v.method is not None]
        for m in program.methods
        if m.name != "constructor"
    }
    cycle = _ir_cycle_method(program.methods, callees)
    if cycle is not None:
        return (
            f"recursion detected: method '{cycle}' calls itself directly or indirectly. "
            "Private methods are inlined at every call site, so a cyclic call graph has "
            "no finite lowering"
        )
    return _ir_call_depth_error(program.methods, callees)


def _ir_cycle_method(methods: list[ANFMethod], callees: dict[str, list[str]]) -> str | None:
    """Iterative (explicit-stack), three-state DFS over the IR method_call
    graph. Declaration order only decides which root the search starts from;
    the name returned is whichever back edge is found first."""
    unvisited, on_stack, done_state = 0, 1, 2
    state: dict[str, int] = {}

    for m in methods:
        root = m.name
        if root == "constructor" or state.get(root, unvisited) != unvisited:
            continue
        stack: list[dict] = [{"name": root, "next": 0}]
        state[root] = on_stack
        while stack:
            top = stack[-1]
            calls = callees.get(top["name"], [])
            if top["next"] >= len(calls):
                state[top["name"]] = done_state
                stack.pop()
                continue
            callee = calls[top["next"]]
            top["next"] += 1
            if callee not in callees:
                continue
            callee_state = state.get(callee, unvisited)
            if callee_state == on_stack:
                return callee
            if callee_state == unvisited:
                state[callee] = on_stack
                stack.append({"name": callee, "next": 0})
    return None


def _ir_call_depth_error(methods: list[ANFMethod], callees: dict[str, list[str]]) -> str | None:
    """Iterative longest-path walk over the (by this point known-acyclic) IR
    call graph, no host recursion. Returns the diagnostic for the first
    method (declaration order) past MAX_CALL_DEPTH, or ``None``."""
    depth: dict[str, int] = {}
    done: set[str] = set()

    for m in methods:
        root = m.name
        if root == "constructor" or root in done:
            continue
        stack: list[dict] = [{"name": root, "next": 0, "depth": 0}]
        while stack:
            top = stack[-1]
            calls = callees.get(top["name"], [])
            if top["next"] < len(calls):
                callee = calls[top["next"]]
                top["next"] += 1
                if callee not in callees:
                    continue
                if callee in done:
                    d = 1 + depth.get(callee, 0)
                    if d > top["depth"]:
                        top["depth"] = d
                else:
                    stack.append({"name": callee, "next": 0, "depth": 0})
                continue
            finished = stack.pop()
            done.add(finished["name"])
            depth[finished["name"]] = finished["depth"]
            if stack:
                parent = stack[-1]
                d = 1 + finished["depth"]
                if d > parent["depth"]:
                    parent["depth"] = d

    for m in methods:
        if m.name == "constructor":
            continue
        d = depth.get(m.name, 0)
        if d > MAX_CALL_DEPTH:
            return call_depth_message(m.name)
    return None


def _effective_parent_class(program: ANFProgram) -> str:
    """The declared parentClass, or the N-087 fail-closed inference for IR
    without one (see ``_parent_class_error``)."""
    flat = {v.kind for m in program.methods for v in _walk_values(m.body)}
    return program.parent_class or (
        "StatefulSmartContract" if flat & _STATEFUL_ONLY_KINDS
        else "UnsafeSmartContract" if "raw_script" in flat
        else "SmartContract"
    )


def _parent_class_error(program: ANFProgram) -> str | None:
    """N-087: the source validator's parentClass rules, which --ir never ran.

    A SmartContract property declared readonly:false got no constructor slot,
    so ``update_prop owner = x; assert(owner == x)`` compiled to 76767b8777,
    which any key spends. Checked in this order, with the diagnostics all
    seven tiers share (conformance/negatives/ir-parent-class-cases.json):
    (1) SmartContract / UnsafeSmartContract properties must be readonly;
    (2) stateful-only nodes require StatefulSmartContract; (3) raw_script
    (asm) requires UnsafeSmartContract. An absent parentClass (IR older than
    F-038) is inferred fail-closed: StatefulSmartContract only from a
    stateful-only node, else UnsafeSmartContract from a raw_script, else
    SmartContract.
    """
    kinds = [
        [v.kind for v in _walk_values(m.body)] for m in program.methods
    ]
    pc = _effective_parent_class(program)
    if pc != "StatefulSmartContract":
        for prop in program.properties:
            if not prop.readonly:
                return (
                    f"Property '{prop.name}' in {pc} must be readonly. "
                    f"Use StatefulSmartContract for mutable state."
                )
        for method, ks in zip(program.methods, kinds):
            for k in ks:
                if k in _STATEFUL_ONLY_KINDS:
                    return (
                        f"'{k}' in method '{method.name}' is only available "
                        f"in StatefulSmartContract; got {pc}"
                    )
    if pc != "UnsafeSmartContract":
        for method, ks in zip(program.methods, kinds):
            if "raw_script" in ks:
                return (
                    f"'raw_script' in method '{method.name}' is only available "
                    f"in contracts extending UnsafeSmartContract; got {pc}"
                )
    return None


def _ends_with_assert(bindings: list[ANFBinding]) -> bool:
    """ANF analogue of the source validator's ``_ends_with_assert`` (plus the
    UnsafeSmartContract terminal-asm form): the last binding is an ``assert``,
    a ``raw_script`` with out_arity 1, or an ``if`` whose two arms both end
    that way."""
    if not bindings:
        return False
    value = bindings[-1].value
    if value.kind == "assert":
        return True
    if value.kind == "raw_script":
        return value.out_arity == 1
    if value.kind == "if":
        return _ends_with_assert(value.then or []) and _ends_with_assert(
            value.else_ or []
        )
    return False


def _validate_bindings(
    bindings: list[ANFBinding],
    method_name: str,
    mutable_count: int,
    readonly_props: frozenset[str] = frozenset(),
    declared_props: frozenset[str] | None = None,
    enclosing_loop_count: int = 1,
) -> list[str]:
    """Validate a list of ANF bindings, including nested ones.

    ``enclosing_loop_count`` is the product of every loop count already
    entered on the path from the method body down to ``bindings`` (1 at the
    top). F-283 / CL-GAP-164: the per-binding ``MAX_LOOP_COUNT`` check below
    bounds a single loop's own count but never the PRODUCT across nesting --
    two loops of 10,000 each, one inside the other, each pass that check
    independently while the real unrolled work is 10,000 x 10,000 =
    100,000,000.
    """
    errors: list[str] = []

    for i, binding in enumerate(bindings):
        if not binding.name:
            errors.append(
                f"method {method_name} binding[{i}] has empty name"
            )

        kind = binding.value.kind
        if not kind:
            errors.append(
                f"method {method_name} binding {binding.name} has empty kind"
            )
            continue

        if kind not in KNOWN_KINDS:
            errors.append(
                f"method {method_name} binding {binding.name} "
                f"has unknown kind {kind!r}"
            )

        # R-128 / R-165: builtin call arity, checked here because `--ir` runs
        # no frontend and stack lowering emits a fixed-arity blob regardless.
        if kind == "call":
            func_name = binding.value.func or ""
            got = len(binding.value.args or [])
            if func_name == "merkleRootPoseidon2KB":
                ok, rule = _merkle_poseidon2_arity_ok(got)
                if not ok:
                    errors.append(
                        f"method {method_name} binding {binding.name} calls "
                        f"{func_name}() with {got} argument(s); it takes {rule}"
                    )
            else:
                allowed = _allowed_arity(func_name)
                if allowed is not None and got not in allowed:
                    wanted = (
                        str(allowed[0])
                        if len(allowed) == 1
                        else ", ".join(str(a) for a in allowed[:-1]) + f" or {allowed[-1]}"
                    )
                    errors.append(
                        f"method {method_name} binding {binding.name} calls "
                        f"{func_name}() with {got} argument(s); it takes {wanted}"
                    )

        # R-164 / CL-BUG-134: ``super`` outside a constructor.
        #
        # ``super`` emits no opcodes -- the constructor args are already on the
        # stack -- but stack lowering pushes a stackMap slot for it anyway:
        # +1 model, +0 physical. Invisible on the SOURCE path (the constructor
        # is never lowered to script) and reachable via ``--ir``, where every
        # subsequent PICK/ROLL depth is off by one. Refusing beats inventing a
        # physical push for a call with no runtime meaning.
        if kind == "call" and (binding.value.func or "") == "super" and method_name != "constructor":
            errors.append(
                f"super() is only valid in a constructor; method '{method_name}' "
                f"calls it. It emits no opcodes -- the constructor args are already "
                f"on the stack -- so stack lowering pushes a model slot with no "
                f"physical value, and every later PICK/ROLL depth in the method is "
                f"off by one."
            )

        # R-126 / CL-BUG-164: add_output state-value arity.
        #
        # The source pipeline counts addOutput arity in the typechecker (the
        # N20 / N23 / N26 negatives). ``--ir`` runs no frontend, so such a node
        # reached stack lowering directly, and ``lower_add_output`` serializes
        # the OP_RETURN payload with the MIN of the two lists. Under-arity
        # emitted an output carrying fewer state fields than the contract has;
        # over-arity silently dropped the surplus. Measured through each tier's
        # own --ir CLI on a two-mutable-field contract (correct arity = 1394
        # hexchars): go, rust, zig, ruby, python and java ALL accepted, emitting
        # 1388 and 1396 hexchars respectively.
        #
        # CL-BUG-164 settled the cost: every SDK's StateSerializer writes ALL
        # mutable fields, so a short-payload continuation is spendable only by a
        # hand-crafted transaction, and the successor it produces is permanently
        # unspendable because the next call's deserialize_state slices at fixed
        # offsets. The message is shared verbatim with the other six tiers.
        if kind == "add_output":
            got = len(binding.value.state_values or [])
            if got != mutable_count:
                errors.append(
                    f"add_output in method '{method_name}' carries {got} state "
                    f"values, but the contract declares {mutable_count} mutable "
                    f"properties. The output's OP_RETURN payload is serialized "
                    f"from this list while deserialize_state slices the declared "
                    f"properties at fixed offsets, so any other count commits to "
                    f"a state payload no SDK-built transaction can produce and a "
                    f"successor that cannot be spent."
                )

        # F-014 / CL-BUG-266: readonly properties may only be assigned in the
        # constructor (frontend/validator.py ``_check_readonly_writes``). --ir
        # runs no frontend, so an update_prop on one compiled clean.
        # N-087: an update_prop naming no declared property is refused too,
        # with Go F-004's sentence.
        if kind == "update_prop" and method_name != "constructor":
            prop_name = binding.value.name or ""
            if declared_props is not None and prop_name not in declared_props:
                errors.append(
                    f"method '{method_name}' assigns to undeclared property '{prop_name}'"
                )
            elif prop_name in readonly_props:
                errors.append(
                    f"cannot assign to readonly property '{prop_name}' in "
                    f"method '{method_name}' (binding {binding.name}). readonly "
                    f"properties may only be assigned in the constructor."
                )

        # Validate nested bindings
        if kind == "if":
            if binding.value.then:
                errors.extend(
                    _validate_bindings(binding.value.then, method_name, mutable_count, readonly_props, declared_props, enclosing_loop_count)
                )
            if binding.value.else_:
                errors.extend(
                    _validate_bindings(binding.value.else_, method_name, mutable_count, readonly_props, declared_props, enclosing_loop_count)
                )

        if kind == "loop":
            count = binding.value.count or 0
            if count < 0:
                errors.append(
                    f"method {method_name} binding {binding.name} "
                    f"has negative loop count {count}"
                )
            if count > MAX_LOOP_COUNT:
                errors.append(
                    f"method {method_name} binding {binding.name} "
                    f"has loop count {count} exceeding maximum {MAX_LOOP_COUNT}"
                )
            # F-283 / CL-GAP-164: the product check. Only meaningful once the
            # per-binding count is itself sane (non-negative and within
            # MAX_LOOP_COUNT) -- otherwise the checks above already named the
            # problem and this would just be a confusing second diagnostic
            # for the same single binding.
            effective_count = 0 if count < 0 else count
            total_loop_count = enclosing_loop_count * effective_count
            if 0 <= count <= MAX_LOOP_COUNT and total_loop_count > MAX_LOOP_COUNT:
                errors.append(
                    f"method {method_name} binding {binding.name} has loop "
                    f"count {count} nested inside an enclosing loop of total "
                    f"count {enclosing_loop_count}, producing "
                    f"{total_loop_count} total iterations, exceeding "
                    f"maximum {MAX_LOOP_COUNT}"
                )
            if binding.value.body:
                errors.extend(
                    _validate_bindings(binding.value.body, method_name, mutable_count, readonly_props, declared_props, total_loop_count)
                )

        if kind == "raw_script":
            body = binding.value.bytes or ""
            # N-113 / R-079: an empty span is a claim the emitter cannot
            # honour. Stack lowering models a raw_script purely from its
            # declared arities (it pops in_arity and pushes out_arity) because
            # the bytes are opaque to it, while emission writes nothing at all
            # for a zero-length span. The stack model and the script then
            # disagree, and every later PICK/ROLL depth derived from that model
            # addresses the wrong slot -- the span silently degrades to the
            # identity function and a different witness spends the output than
            # the IR declared.
            #
            # The source path already rejects this ("asm() body must be a
            # non-empty hex string literal", frontend/validator.py); --ir is the
            # same rule at the external-input trust boundary. All empty bodies
            # are rejected, including the degenerate in=0/out=0 case, because
            # mirroring the source validator exactly is worth more than an
            # arity-conditional rule that would differ from the rule one pass
            # earlier.
            if not body:
                errors.append(
                    f"method {method_name} binding {binding.name} "
                    f"raw_script has an empty bytes body but declares "
                    f"in_arity {binding.value.in_arity or 0} / "
                    f"out_arity {binding.value.out_arity or 0}; a span that "
                    f"emits no bytes cannot have a stack effect"
                )
            if len(body) % 2 != 0:
                errors.append(
                    f"method {method_name} binding {binding.name} "
                    f"raw_script bytes have odd hex length {len(body)}"
                )
            if not _is_hex_string(body):
                errors.append(
                    f"method {method_name} binding {binding.name} "
                    f"raw_script bytes contain non-hex characters"
                )
            in_arity = binding.value.in_arity or 0
            if in_arity < 0:
                errors.append(
                    f"method {method_name} binding {binding.name} "
                    f"raw_script has negative in_arity {in_arity}"
                )
            out_arity = binding.value.out_arity or 0
            if out_arity < 0:
                errors.append(
                    f"method {method_name} binding {binding.name} "
                    f"raw_script has negative out_arity {out_arity}"
                )

    return errors
