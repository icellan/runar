"""CLI entry point for the Runar Python compiler.

Usage:
    python -m runar_compiler --source Contract.runar.py --output artifact.json
    python -m runar_compiler --ir program.json --output artifact.json
    python -m runar_compiler --source Contract.runar.py --hex
    python -m runar_compiler --source Contract.runar.py --asm
    python -m runar_compiler --source Contract.runar.py --emit-ir

Direct port of ``compilers/go/main.go``.
"""

from __future__ import annotations

import argparse
import json
import sys

from runar_compiler.compiler import (
    CompilationError,
    artifact_to_json,
    compile_from_ir,
    compile_from_source,
    compile_source_to_ir,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="runar-compiler-python",
        description="Runar smart contract compiler (Python implementation).",
    )
    parser.add_argument(
        "--ir",
        metavar="PATH",
        help="Path to ANF IR JSON file",
    )
    parser.add_argument(
        "--source",
        metavar="PATH",
        help="Path to .runar.* source file",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Output artifact path (default: stdout)",
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="Output only the script hex (no artifact JSON)",
    )
    parser.add_argument(
        "--asm",
        action="store_true",
        help="Output only the script ASM (no artifact JSON)",
    )
    parser.add_argument(
        "--emit-ir",
        action="store_true",
        help="Output only the ANF IR JSON (requires --source)",
    )

    args = parser.parse_args()

    if not args.ir and not args.source:
        print(
            "Usage: runar-compiler-python [--ir <path> | --source <path>] "
            "[--output <path>] [--hex] [--asm] [--emit-ir]",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        print(
            "Phase 1: Compile from ANF IR JSON to Bitcoin Script (--ir).",
            file=sys.stderr,
        )
        print(
            "Phase 2: Compile from source to Bitcoin Script (--source).",
            file=sys.stderr,
        )
        sys.exit(1)

    # Handle --emit-ir: dump ANF IR JSON and exit
    if args.emit_ir:
        if not args.source:
            print("--emit-ir requires --source", file=sys.stderr)
            sys.exit(1)
        try:
            program = compile_source_to_ir(args.source)
        except CompilationError as e:
            print(f"Compilation error: {e}", file=sys.stderr)
            sys.exit(1)
        # Serialize the ANFProgram to camelCase JSON (matching Go/TS output)
        ir_json = json.dumps(_anf_to_camel_dict(program), indent=2, default=str)
        print(ir_json)
        return

    try:
        if args.source:
            artifact = compile_from_source(args.source)
        else:
            artifact = compile_from_ir(args.ir)
    except CompilationError as e:
        print(f"Compilation error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Compilation error: {e}", file=sys.stderr)
        sys.exit(1)

    # Determine output
    if args.hex:
        output = artifact.script
    elif args.asm:
        output = artifact.asm
    else:
        output = artifact_to_json(artifact)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


_SNAKE_TO_CAMEL = {
    "contract_name": "contractName",
    "is_public": "isPublic",
    "iter_var": "iterVar",
    "state_values": "stateValues",
    "initial_value": "initialValue",
    "else_": "else",
    # These stay as snake_case to match Go/TS IR format
    "result_type": "result_type",
    # Both raw_value and value_ref map to "value" in Go JSON (they never coexist)
    "value_ref": "value",
    "raw_value": "value",
}

# Fields that should be excluded from IR output (internal decoded fields)
_IR_EXCLUDED_FIELDS = frozenset({
    "const_string", "const_big_int", "const_bool", "const_int",
})


def _snake_key(k: str) -> str:
    return _SNAKE_TO_CAMEL.get(k, k)


def _anf_to_camel_dict(obj: object) -> object:
    """Convert an ANF dataclass tree to a dict matching Go/TS IR JSON format."""
    import json as _json
    from dataclasses import fields, is_dataclass
    if is_dataclass(obj) and not isinstance(obj, type):
        d: dict = {}
        has_raw_value = False
        for f in fields(obj):
            if f.name in _IR_EXCLUDED_FIELDS:
                continue
            v = getattr(obj, f.name)
            if v is None:
                continue
            # raw_value is the canonical Go JSON "value" field — parse and emit its content
            if f.name == "raw_value":
                try:
                    d["value"] = _json.loads(v)
                except (ValueError, TypeError):
                    d["value"] = v
                has_raw_value = True
                continue
            # Skip value_ref if raw_value was already emitted as "value"
            if f.name == "value_ref" and has_raw_value:
                continue
            key = _snake_key(f.name)
            d[key] = _anf_to_camel_dict(v)
        return d
    if isinstance(obj, list):
        return [_anf_to_camel_dict(item) for item in obj]
    return obj


if __name__ == "__main__":
    main()
