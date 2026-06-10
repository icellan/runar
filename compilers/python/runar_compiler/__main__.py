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
import os
import sys

from runar_compiler.compiler import (
    CompilationError,
    artifact_to_json,
    compile_from_ir,
    compile_from_source,
    compile_source_to_ir,
)


# GAP-011: source-map sourceFile values must be repo-relative (POSIX) so
# goldens stay stable across worktree paths and developer machines. Walk up
# from the source file looking for pnpm-workspace.yaml (the canonical repo
# root marker); fall back to the basename if no marker is found. Strings
# that aren't absolute paths are returned unchanged.
def _repo_relative_file_name(src_path: str) -> str:
    if not os.path.isabs(src_path):
        return src_path
    d = os.path.dirname(src_path)
    while True:
        if os.path.exists(os.path.join(d, "pnpm-workspace.yaml")):
            return os.path.relpath(src_path, d).replace(os.sep, "/")
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return os.path.basename(src_path)


def main() -> None:
    # Subcommand dispatch: a non-flag first arg is treated as a subcommand,
    # matching the Go and Rust compilers. Keeps the legacy flag surface
    # untouched while letting us add modes like `debug` (G-6) cleanly.
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        if sys.argv[1] == "debug":
            _run_debug_subcommand(sys.argv[2:])
            return
        # Unknown positional: fall through to argparse, which will emit a
        # standard usage error.

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
    parser.add_argument(
        "--parse-only",
        dest="parse_only",
        action="store_true",
        help=(
            "Stop after parse + validate; print 'parser ok' on success "
            "(requires --source). Used by the conformance runner's "
            "--parser-only universal-frontend coverage check."
        ),
    )
    parser.add_argument(
        "--disable-constant-folding",
        action="store_true",
        help="Disable the ANF constant folding pass",
    )
    parser.add_argument(
        "--emit-source-map",
        dest="emit_source_map",
        metavar="PATH",
        help="After a successful compile, write artifact.sourceMap JSON to this path",
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

    # Handle --parse-only: read source, run parse + validate; print
    # "parser ok" on success or diagnostics on failure. Universal
    # parser-coverage entry point used by the conformance runner.
    if args.parse_only:
        if not args.source:
            print("--parse-only requires --source", file=sys.stderr)
            sys.exit(1)
        try:
            from runar_compiler.compiler import _parse_source, _validate, _read_file
        except ImportError as e:
            print(f"Compilation error: {e}", file=sys.stderr)
            sys.exit(1)
        try:
            src = _read_file(args.source)
            parse_result = _parse_source(src, args.source)
            if parse_result.errors:
                print(
                    "parse errors:\n  " + "\n  ".join(parse_result.error_strings()),
                    file=sys.stderr,
                )
                sys.exit(1)
            if parse_result.contract is None:
                print(f"parse error: no contract found in {args.source}", file=sys.stderr)
                sys.exit(1)
            valid = _validate(parse_result.contract)
            if valid.errors:
                print(
                    "validation errors:\n  " + "\n  ".join(valid.error_strings()),
                    file=sys.stderr,
                )
                sys.exit(1)
        except Exception as e:
            print(f"parse error: {e}", file=sys.stderr)
            sys.exit(1)
        print("parser ok")
        return

    # Handle --emit-ir: dump ANF IR JSON and exit
    if args.emit_ir:
        if not args.source:
            print("--emit-ir requires --source", file=sys.stderr)
            sys.exit(1)
        try:
            program = compile_source_to_ir(
                args.source,
                disable_constant_folding=args.disable_constant_folding,
            )
        except CompilationError as e:
            print(f"Compilation error: {e}", file=sys.stderr)
            sys.exit(1)
        # Serialize the ANFProgram to camelCase JSON (matching Go/TS output)
        ir_json = json.dumps(_anf_to_camel_dict(program), indent=2, default=str)
        print(ir_json)
        return

    try:
        if args.source:
            artifact = compile_from_source(
                args.source,
                disable_constant_folding=args.disable_constant_folding,
            )
        else:
            artifact = compile_from_ir(
                args.ir,
                disable_constant_folding=args.disable_constant_folding,
            )
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

    # --emit-source-map: write the artifact's sourceMap field as canonical
    # JSON ({"mappings":[...]}) to the requested path. Always emit the
    # wrapper object so downstream tooling sees a uniform shape even when
    # the underlying mapping table is empty.
    if args.emit_source_map:
        sm = artifact.source_map  # list of SourceMapping or None
        if sm:
            from runar_compiler.codegen.emit import SourceMapping
            mappings = [
                {
                    "opcodeIndex": m.opcode_index,
                    # GAP-011: normalize sourceFile to repo-relative POSIX.
                    "sourceFile": _repo_relative_file_name(m.source_file),
                    "line": m.line,
                    "column": m.column,
                }
                if isinstance(m, SourceMapping)
                else {**m, "sourceFile": _repo_relative_file_name(m.get("sourceFile", ""))}
                for m in sm
            ]
        else:
            mappings = []
        os.makedirs(os.path.dirname(os.path.abspath(args.emit_source_map)) or ".", exist_ok=True)
        with open(args.emit_source_map, "w") as f:
            json.dump({"mappings": mappings}, f, indent=2)
            f.write("\n")
        print(f"Source map written to {args.emit_source_map}", file=sys.stderr)

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
    "script_bytes": "scriptBytes",
    "else_": "else",
    "is_auto_injected_state_check": "isAutoInjectedStateCheck",
    # These stay as snake_case to match Go/TS IR format
    "result_type": "result_type",
    # Both raw_value and value_ref map to "value" in Go JSON (they never coexist)
    "value_ref": "value",
    "raw_value": "value",
}

# Fields that should be excluded from IR output (internal decoded fields)
_IR_EXCLUDED_FIELDS = frozenset({
    "const_string", "const_big_int", "const_bool", "const_int",
    "source_loc",  # debug-only, not part of conformance
    # Python-only metadata used internally by expand_fixed_arrays.
    # Other compilers don't emit this field in --emit-ir output.
    "synthetic_array_chain",
    # In-memory carrier for the artifact's top-level parentClass field.
    # Excluded from --emit-ir so it never affects cross-tier ANF parity.
    "parent_class",
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
        kind_val = getattr(obj, "kind", None)
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
            # Auto-injected stateful-continuation marker: emit only on
            # `assert` nodes and only when True so checked-in fold-OFF
            # goldens stay stable for developer asserts.
            if f.name == "is_auto_injected_state_check":
                if not v or kind_val != "assert":
                    continue
            key = _snake_key(f.name)
            d[key] = _anf_to_camel_dict(v)
        return d
    if isinstance(obj, list):
        return [_anf_to_camel_dict(item) for item in obj]
    return obj


def _run_debug_subcommand(argv: list[str]) -> None:
    """`debug` subcommand: step-trace a Bitcoin Script via the runar-py
    ScriptVM (which wraps the bsv-sdk Spend interpreter).

    Wraps ``runar.sdk.script_vm.ScriptVM`` from the ``packages/runar-py``
    package — runar-py must be importable (typically: ``pip install runar``
    in the same env, or set ``PYTHONPATH=packages/runar-py``). The ScriptVM
    itself needs the optional ``bsv-sdk`` dependency
    (``pip install runar[script-vm]``).

    G-6 (audits/cross-language-completeness-20260514.md §5.1).
    """
    parser = argparse.ArgumentParser(
        prog="runar-compiler-python debug",
        description=(
            "Step-trace a Bitcoin Script via the bsv-sdk Spend interpreter, "
            "printing the main stack after each opcode."
        ),
    )
    parser.add_argument("--script", metavar="HEX",
                        help="locking-script hex (required unless --artifact is used)")
    parser.add_argument("--unlock", metavar="HEX", default="",
                        help="unlocking-script hex (default: empty)")
    parser.add_argument("--artifact", metavar="PATH",
                        help="compiled artifact JSON path (uses its 'script' field)")
    parser.add_argument("--max-stack-bytes", type=int, default=32,
                        help="max bytes of each stack element to print (0 = full)")
    args = parser.parse_args(argv)

    locking_hex = args.script
    if not locking_hex and args.artifact:
        try:
            with open(args.artifact, "r", encoding="utf-8") as f:
                art = json.load(f)
        except (OSError, ValueError) as e:
            print(f"read artifact: {e}", file=sys.stderr)
            sys.exit(1)
        locking_hex = art.get("script")
        if not isinstance(locking_hex, str):
            print("artifact has no 'script' field", file=sys.stderr)
            sys.exit(1)
    if not locking_hex:
        parser.print_usage(sys.stderr)
        print("debug: --script or --artifact is required", file=sys.stderr)
        sys.exit(1)

    # Lazy import so the rest of the CLI keeps working without bsv-sdk /
    # runar-py installed. The runar-py ScriptVM does its own bsv-sdk
    # detection and raises ImportError on first use with a helpful hint.
    try:
        from runar.sdk.script_vm import ScriptVM  # type: ignore
    except ImportError as e:
        print(
            "debug: cannot import runar.sdk.script_vm — install runar-py "
            "(e.g. `pip install runar[script-vm]`) or set PYTHONPATH to "
            "packages/runar-py.",
            file=sys.stderr,
        )
        print(f"  detail: {e}", file=sys.stderr)
        sys.exit(1)

    vm = ScriptVM()
    try:
        vm.load_hex(args.unlock, locking_hex)
    except ImportError as e:
        # Raised lazily by runar.sdk.script_vm when bsv-sdk is missing.
        print(f"debug: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001 — surface upstream errors verbatim
        print(f"debug: {e}", file=sys.stderr)
        sys.exit(1)

    step_n = 0
    while (step := vm.step()) is not None:
        step_n += 1
        stack_repr = _format_stack(step.main_stack, args.max_stack_bytes)
        print(
            f"step={step_n}  ctx={step.context}  offset={step.offset}  "
            f"op={step.opcode}  stack={stack_repr}"
        )
        if step.error:
            print(f"  error: {step.error}")
    if step_n == 0:
        print("(no opcodes executed)")

    status = "pass" if vm.is_success else "fail"
    final_stack = _format_stack(vm.current_stack, args.max_stack_bytes)
    print(f"final: {status}  ops={step_n}  stack={final_stack}")


def _format_stack(stack: list, max_bytes: int) -> str:
    """Render a stack as ``[hex1, hex2, ...]``. Top of stack is last."""
    if not stack:
        return "[]"
    parts = []
    for e in stack:
        b = bytes(e)
        if max_bytes > 0 and len(b) > max_bytes:
            parts.append(b[:max_bytes].hex() + f"…(+{len(b) - max_bytes})")
        else:
            parts.append(b.hex() if b else "<empty>")
    return "[" + ", ".join(parts) + "]"


if __name__ == "__main__":
    main()
