"""Parser dispatch — routes source files to the appropriate format parser."""

from __future__ import annotations
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.frontend.ast_nodes import ContractNode

from runar_compiler.frontend.diagnostic import Diagnostic, Severity


# Author-facing comment directives honoured ONLY on the TypeScript (.runar.ts)
# surface (parser_ts reads leading trivia): ``@sighash <FLAGS>`` (#123,
# per-method sighash type) and ``@embedAlways`` (#109, readonly-field DCE
# opt-out). The eight non-TS surface parsers ignore comments, so a directive in
# one of those sources would be silently dropped and change signing / DCE
# semantics. Fail closed on those formats rather than miscompile — this mirrors
# the Go/Rust/Zig/Ruby/Java tiers. Word-boundary anchored to mirror the TS
# ``/@sighash\b/`` / ``/@embedAlways\b/`` scans so an identifier like
# ``sighashType`` does not trip the guard. No conformance fixture uses either
# directive, so this has zero golden impact.
_SIGHASH_DIRECTIVE_RE = re.compile(r"@sighash\b")
_EMBED_ALWAYS_DIRECTIVE_RE = re.compile(r"@embedAlways\b")
_BINDING_VARIANT_DIRECTIVE_RE = re.compile(r"@bindingVariant\b")

# Non-TS extension -> human-readable surface name for the diagnostic.
# ``.runar.ts`` is intentionally absent: parser_ts honours the directives.
_NON_TS_SURFACES = {
    ".runar.sol": "Solidity",
    ".runar.move": "Move",
    ".runar.py": "Python",
    ".runar.go": "Go DSL",
    ".runar.rs": "Rust",
    ".runar.rb": "Ruby",
    ".runar.zig": "Zig",
    ".runar.java": "Java",
}


def _unsupported_directive_error(source: str, surface_name: str) -> str | None:
    """Return a fail-closed diagnostic message when ``source`` carries a
    ``@sighash`` (#123) or ``@embedAlways`` (#109) directive on a non-TS surface
    whose parser ignores comments (so the directive would be silently dropped),
    else ``None``.
    """
    if _SIGHASH_DIRECTIVE_RE.search(source):
        return (
            f"@sighash directive (issue #123) is not supported by the {surface_name} "
            "surface parser; write the contract in TypeScript (.runar.ts) where "
            "@sighash is honoured"
        )
    if _EMBED_ALWAYS_DIRECTIVE_RE.search(source):
        return (
            f"@embedAlways directive (issue #109) is not supported by the {surface_name} "
            "surface parser; write the contract in TypeScript (.runar.ts) where "
            "@embedAlways is honoured"
        )
    if _BINDING_VARIANT_DIRECTIVE_RE.search(source):
        return (
            f"@bindingVariant directive is not supported by the {surface_name} "
            "surface parser; write the contract in TypeScript (.runar.ts) where "
            "@bindingVariant is honoured"
        )
    return None


class ParseResult:
    __slots__ = ("contract", "errors")

    def __init__(self, contract: ContractNode | None = None, errors: list[Diagnostic] | None = None):
        self.contract = contract
        self.errors = errors or []

    def error_strings(self) -> list[str]:
        """Return formatted error messages as plain strings."""
        return [d.format_message() for d in self.errors]


def parse_source(source: str, file_name: str) -> ParseResult:
    """Dispatch to the appropriate parser based on file extension."""
    # DoS-bound size guard. Reject oversized source BEFORE any
    # format-specific parser touches the input. Raises
    # :class:`SourceSizeExceededError` on rejection. BUG-008 follow-up.
    from runar_compiler.frontend.input_limits import assert_source_bytes_under_limit
    assert_source_bytes_under_limit(source)

    lower = file_name.lower()

    # Fail-closed directive guard: reject ``@sighash`` / ``@embedAlways`` on any
    # non-TS surface (whose parser ignores comments) before dispatching. The
    # ``.runar.ts`` branch is exempt because parser_ts honours the directives.
    for ext, surface_name in _NON_TS_SURFACES.items():
        if lower.endswith(ext):
            directive_error = _unsupported_directive_error(source, surface_name)
            if directive_error is not None:
                return ParseResult(errors=[Diagnostic(
                    message=directive_error,
                    severity=Severity.ERROR,
                )])
            break

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
    elif lower.endswith(".runar.rb"):
        from runar_compiler.frontend.parser_ruby import parse_ruby
        return parse_ruby(source, file_name)
    elif lower.endswith(".runar.zig"):
        from runar_compiler.frontend.parser_zig import parse_zig
        return parse_zig(source, file_name)
    elif lower.endswith(".runar.java"):
        from runar_compiler.frontend.parser_java import parse_java
        return parse_java(source, file_name)
    else:
        return ParseResult(errors=[Diagnostic(
            message=f"unsupported file extension: {file_name}",
            severity=Severity.ERROR,
        )])
