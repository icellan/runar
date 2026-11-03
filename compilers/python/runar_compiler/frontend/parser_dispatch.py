"""Parser dispatch — routes source files to the appropriate format parser."""

from __future__ import annotations
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.frontend.ast_nodes import ContractNode

from runar_compiler.frontend.diagnostic import Diagnostic, Severity


# Author-facing comment directives ``@sighash <FLAGS>`` (#123, per-method
# sighash type) and ``@embedAlways`` (#109, readonly-field DCE opt-out) are read
# from COMMENTS only on the TypeScript (.runar.ts) surface (parser_ts reads
# leading trivia). The eight non-TS surfaces spell both directives natively
# instead (N-093, user decision R38: a modifier mirroring each surface's
# readonly idiom -- see _NON_TS_SURFACES), and their parsers drop comments, so
# a COMMENT directive in one of those sources would be silently ignored and
# change signing / DCE semantics. Fail closed on those formats rather than
# miscompile, and name the native spelling to use. None of the native
# spellings contains either marker, so this guard never trips on them.
# ``@embedAlways`` is word-boundary anchored so an identifier like
# ``sighashType`` does not trip the guard; ``@sighash`` is not (N-244): N-039
# made every occurrence of the marker a directive, so a glued
# ``@sighashSINGLE|FORKID`` is refused here too. The message is identical in
# all seven tiers.
_SIGHASH_DIRECTIVE_RE = re.compile(r"@sighash")
_EMBED_ALWAYS_DIRECTIVE_RE = re.compile(r"@embedAlways\b")

# Non-TS extension -> (human-readable surface name, format doc, native
# @sighash spelling, native @embedAlways spelling) (N-093). ``.runar.ts`` is
# intentionally absent: parser_ts honours the comment directives.
_NON_TS_SURFACES: dict[str, tuple[str, str, str, str]] = {
    ".runar.sol": ("Solidity", "solidity", "the function modifier sighash(<FLAGS>)", "the property modifier embedAlways"),
    ".runar.move": ("Move", "move", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"),
    ".runar.py": ("Python", "python", '@public(sighash="<FLAGS>")', "the wrapper type EmbedAlways[T]"),
    ".runar.go": ("Go DSL", "go", "the directive //runar:sighash <FLAGS>", 'the struct tag option runar:"readonly,embedAlways"'),
    ".runar.rs": ("Rust", "rust", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"),
    ".runar.rb": ("Ruby", "ruby", "runar_sighash '<FLAGS>'", "the prop option embed_always: true"),
    ".runar.zig": ("Zig", "zig", 'the return type runar.Sighash("<FLAGS>")', "the type function runar.EmbedAlways(T)"),
    ".runar.java": ("Java", "java", 'the annotation @Sighash("<FLAGS>")', "the annotation @EmbedAlways"),
}


def _unsupported_directive_error(
    source: str,
    surface_name: str,
    doc: str,
    sighash_spelling: str,
    embed_spelling: str,
) -> str | None:
    """Return a fail-closed diagnostic message when ``source`` carries a
    ``@sighash`` (#123) or ``@embedAlways`` (#109) COMMENT directive on a non-TS
    surface whose parser ignores comments (so the directive would be silently
    dropped), else ``None``. The message names the surface's native spelling
    (N-093).
    """
    if _SIGHASH_DIRECTIVE_RE.search(source):
        return (
            f"@sighash directive (issue #123) is not supported as a comment by the {surface_name} "
            f"surface parser; write it as {sighash_spelling} (see docs/formats/{doc}.md)"
        )
    if _EMBED_ALWAYS_DIRECTIVE_RE.search(source):
        return (
            f"@embedAlways directive (issue #109) is not supported as a comment by the {surface_name} "
            f"surface parser; write it as {embed_spelling} (see docs/formats/{doc}.md)"
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
    result = _parse_source_dispatch(source, file_name)
    # N-115: `10 > i` is `i < 10`; every later pass sees the canonical form.
    if result.contract is not None:
        from runar_compiler.frontend.loop_condition import normalize_loop_conditions
        normalize_loop_conditions(result.contract)
    return result


def _parse_source_dispatch(source: str, file_name: str) -> ParseResult:
    # DoS-bound size guard. Reject oversized source BEFORE any
    # format-specific parser touches the input. Raises
    # :class:`SourceSizeExceededError` on rejection. BUG-008 follow-up.
    from runar_compiler.frontend.input_limits import assert_source_bytes_under_limit
    assert_source_bytes_under_limit(source)

    lower = file_name.lower()

    # Fail-closed directive guard: reject ``@sighash`` / ``@embedAlways`` on any
    # non-TS surface (whose parser ignores comments) before dispatching. The
    # ``.runar.ts`` branch is exempt because parser_ts honours the directives.
    for ext, (surface_name, doc, sighash_spelling, embed_spelling) in _NON_TS_SURFACES.items():
        if lower.endswith(ext):
            directive_error = _unsupported_directive_error(
                source, surface_name, doc, sighash_spelling, embed_spelling,
            )
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
        result = parse_ts(source, file_name)
        # N-342: ``const`` locals cannot be reassigned (``.runar.ts`` only).
        if result.contract is not None:
            from runar_compiler.frontend.const_reassign import check_const_reassignment
            result.errors.extend(check_const_reassignment(result.contract))
        return result
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
        result = parse_rust(source, file_name)
        # N-344: an immutable ``let`` (no ``mut``) cannot be reassigned.
        if result.contract is not None:
            from runar_compiler.frontend.const_reassign import check_const_reassignment
            result.errors.extend(check_const_reassignment(result.contract))
        return result
    elif lower.endswith(".runar.rb"):
        from runar_compiler.frontend.parser_ruby import parse_ruby
        return parse_ruby(source, file_name)
    elif lower.endswith(".runar.zig"):
        from runar_compiler.frontend.parser_zig import parse_zig
        result = parse_zig(source, file_name)
        # N-344: a ``const`` local cannot be reassigned.
        if result.contract is not None:
            from runar_compiler.frontend.const_reassign import check_const_reassignment
            result.errors.extend(check_const_reassignment(result.contract))
        return result
    elif lower.endswith(".runar.java"):
        from runar_compiler.frontend.parser_java import parse_java
        return parse_java(source, file_name)
    else:
        return ParseResult(errors=[Diagnostic(
            message=f"unsupported file extension: {file_name}",
            severity=Severity.ERROR,
        )])
