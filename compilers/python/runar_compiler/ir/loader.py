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
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_ir(source: str) -> ANFProgram:
    """Load an ANF IR program from a JSON string.

    Parses the JSON, decodes typed constant values, and validates the
    structure.  Raises ``ValueError`` on any error.
    """
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

    return errors
