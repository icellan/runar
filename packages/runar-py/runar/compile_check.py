"""Runar compile_check — validates contracts through the Python Rúnar frontend.

Mirrors the Go / Rust / Zig pattern: parse → validate → typecheck.
"""

import os


def compile_check(source_or_path: str, file_name: str | None = None) -> None:
    """Run Rúnar frontend (parse → validate → typecheck) on a contract source.

    Args:
        source_or_path: Either a file path to a .runar.{py,ts,sol,move,go,rs,rb,zig}
            file, or the source code string.
        file_name: Optional file name for error messages when passing source code
            directly. Must carry the `.runar.*` extension so the parser dispatcher
            picks the right frontend.

    Raises:
        RuntimeError: If any frontend pass reports errors.
    """
    if "\n" not in source_or_path and os.path.isfile(source_or_path):
        with open(source_or_path) as f:
            source = f.read()
        file_name = file_name or source_or_path
    else:
        source = source_or_path
        file_name = file_name or "contract.runar.py"

    try:
        from runar_compiler.frontend.parser_dispatch import parse_source
        from runar_compiler.frontend.validator import validate
        from runar_compiler.frontend.typecheck import type_check
    except ImportError as exc:
        raise RuntimeError(
            f"runar_compiler package not available — install the Python compiler "
            f"(cd compilers/python && pip install -e .): {exc}"
        ) from exc

    parse_result = parse_source(source, file_name)
    if parse_result.errors:
        raise RuntimeError(
            f"Parse errors in {file_name}:\n  "
            + "\n  ".join(parse_result.error_strings())
        )
    if parse_result.contract is None:
        raise RuntimeError(f"Parse returned no contract for {file_name}")

    validation = validate(parse_result.contract)
    if validation.errors:
        raise RuntimeError(
            f"Validation errors in {file_name}:\n  "
            + "\n  ".join(validation.error_strings())
        )

    typecheck = type_check(parse_result.contract)
    if typecheck.errors:
        raise RuntimeError(
            f"Type-check errors in {file_name}:\n  "
            + "\n  ".join(typecheck.error_strings())
        )
