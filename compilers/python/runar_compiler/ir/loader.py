"""ANF IR loader and validator for the Runar compiler.

Direct port of ``compilers/go/ir/loader.go``.  Provides functions to load
ANF IR from JSON (file path or string), validate the structure, and decode
typed constant values.
"""

from __future__ import annotations

import json
from pathlib import Path

from .types import (
    ANFBinding,
    ANFProgram,
    anf_program_from_dict,
    decode_constants,
)


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
        assert_ir_bytes_under_limit,
        assert_ir_nesting_under_limit,
    )

    # DoS-bound guards run before json.loads so a malicious payload
    # cannot exhaust memory (size) or the Python interpreter recursion
    # stack (nesting) inside the deserializer.
    assert_ir_bytes_under_limit(source)
    assert_ir_nesting_under_limit(source)

    try:
        d = json.loads(source)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid IR JSON: {exc}") from exc

    program = anf_program_from_dict(d)

    # Decode typed constant values from raw JSON
    try:
        decode_constants(program)
    except ValueError as exc:
        raise ValueError(f"decoding constants: {exc}") from exc

    errors = validate_ir(program)
    if errors:
        raise ValueError(f"IR validation: {errors[0]}")

    return program


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
            _validate_bindings(method.body, method.name, mutable_count)
        )

    for i, prop in enumerate(program.properties):
        if not prop.name:
            errors.append(f"property[{i}] has empty name")
        if not prop.type:
            errors.append(f"property {prop.name} has empty type")

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
    if not any(m.is_public for m in program.methods):
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


def _validate_bindings(
    bindings: list[ANFBinding], method_name: str, mutable_count: int
) -> list[str]:
    """Validate a list of ANF bindings, including nested ones."""
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

        # Validate nested bindings
        if kind == "if":
            if binding.value.then:
                errors.extend(
                    _validate_bindings(binding.value.then, method_name, mutable_count)
                )
            if binding.value.else_:
                errors.extend(
                    _validate_bindings(binding.value.else_, method_name, mutable_count)
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
            if binding.value.body:
                errors.extend(
                    _validate_bindings(binding.value.body, method_name, mutable_count)
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
