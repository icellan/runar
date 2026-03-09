"""Runar compile_check — validates Python contracts through the Runar frontend.

This is a placeholder that will use the Python compiler once it's implemented.
For now, it validates that the source file exists and has basic Python contract
structure.
"""

import os


def compile_check(source_or_path: str, file_name: str | None = None) -> None:
    """Run Runar frontend (parse -> validate -> typecheck) on a contract source.

    Args:
        source_or_path: Either a file path to a .runar.py file, or the source code string.
        file_name: Optional file name for error messages when passing source code directly.

    Raises:
        RuntimeError: If the contract fails any frontend check.
    """
    if '\n' not in source_or_path and os.path.isfile(source_or_path):
        with open(source_or_path) as f:
            source = f.read()
        file_name = file_name or source_or_path
    else:
        source = source_or_path
        file_name = file_name or 'contract.runar.py'

    # Basic structural validation
    if 'class ' not in source:
        raise RuntimeError(f"No class declaration found in {file_name}")

    if 'SmartContract' not in source and 'StatefulSmartContract' not in source:
        raise RuntimeError(
            f"Contract class must extend SmartContract or StatefulSmartContract in {file_name}"
        )

    # When the Python compiler is implemented, this will invoke:
    #   from runar_compiler.frontend.parser_dispatch import parse_source
    #   from runar_compiler.frontend.validator import validate
    #   from runar_compiler.frontend.typecheck import typecheck
    #   result = parse_source(source, file_name)
    #   if result.errors:
    #       raise RuntimeError(f"Parse errors: {'; '.join(result.errors)}")
    #   validate(result.contract)
    #   typecheck(result.contract)
