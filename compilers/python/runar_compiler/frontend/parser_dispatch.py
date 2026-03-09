"""Parser dispatch — routes source files to the appropriate format parser."""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.frontend.ast_nodes import ContractNode


class ParseResult:
    __slots__ = ("contract", "errors")

    def __init__(self, contract: ContractNode | None = None, errors: list[str] | None = None):
        self.contract = contract
        self.errors = errors or []


def parse_source(source: str, file_name: str) -> ParseResult:
    """Dispatch to the appropriate parser based on file extension."""
    lower = file_name.lower()

    if lower.endswith(".runar.py"):
        from runar_compiler.frontend.parser_python import parse_python
        return parse_python(source, file_name)
    elif lower.endswith(".runar.ts"):
        from runar_compiler.frontend.parser_ts import parse_ts
        return parse_ts(source, file_name)
    elif lower.endswith(".runar.sol"):
        from runar_compiler.frontend.parser_sol import parse_sol
        return parse_sol(source, file_name)
    elif lower.endswith(".runar.move"):
        from runar_compiler.frontend.parser_move import parse_move
        return parse_move(source, file_name)
    elif lower.endswith(".runar.go"):
        from runar_compiler.frontend.parser_go import parse_go
        return parse_go(source, file_name)
    elif lower.endswith(".runar.rs"):
        from runar_compiler.frontend.parser_rust import parse_rust
        return parse_rust(source, file_name)
    else:
        return ParseResult(errors=[f"unsupported file extension: {file_name}"])
