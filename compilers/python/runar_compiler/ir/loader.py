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
        errors.extend(_validate_bindings(method.body, method.name))

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


def _validate_bindings(
    bindings: list[ANFBinding], method_name: str
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

        # Validate nested bindings
        if kind == "if":
            if binding.value.then:
                errors.extend(
                    _validate_bindings(binding.value.then, method_name)
                )
            if binding.value.else_:
                errors.extend(
                    _validate_bindings(binding.value.else_, method_name)
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
                    _validate_bindings(binding.value.body, method_name)
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
