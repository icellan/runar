"""Structured compiler diagnostics."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from runar_compiler.frontend.ast_nodes import SourceLocation


class Severity:
    ERROR = "error"
    WARNING = "warning"


@dataclass
class Diagnostic:
    """A single compiler diagnostic (error or warning)."""
    message: str
    severity: str  # Severity.ERROR or Severity.WARNING
    loc: Optional[SourceLocation] = None

    def format_message(self) -> str:
        """Format with optional file:line:column prefix."""
        if self.loc and self.loc.file:
            if self.loc.column > 0:
                return f"{self.loc.file}:{self.loc.line}:{self.loc.column}: {self.message}"
            return f"{self.loc.file}:{self.loc.line}: {self.message}"
        return self.message

    def __str__(self) -> str:
        return self.format_message()


# F-011's shared diagnostic (the TS reference's UNTERMINATED_STRING_LITERAL):
# every hand-written tokenizer emits it, at the opening quote, for a quoted
# literal that reaches a line break or end of file before its closing quote.
# On .runar.rs, for Python triple-quoted strings and for .runar.go backtick
# raw strings, which may span lines, only end of file counts.
UNTERMINATED_STRING_LITERAL = "unterminated string literal"

# F-026: a .runar.zig call argument list or array literal whose elements are
# not separated by commas (the TS reference's ZIG_LIST_COMMA).
ZIG_LIST_COMMA = "expected ',' between list elements"

# F-026: a second .runar.py statement on the same line (the TS reference's
# PY_STATEMENT_LINE_BREAK).
PY_STATEMENT_LINE_BREAK = "expected a line break between statements"

# The TS reference's refusal of a Java char literal.
JAVA_CHAR_LITERAL = "char literals are unsupported in Rúnar Java contracts"


def static_method_message(name: str) -> str:
    """N-050's refusal of a static or class-level method (the TS reference's
    staticMethodMessage): ``static`` on .runar.ts / .runar.java,
    ``@staticmethod`` / ``@classmethod`` on .runar.py, ``def self.m`` on
    .runar.rb, and a ``pub fn`` without a self receiver on .runar.rs /
    .runar.zig. ``name`` is the method name as written in the source."""
    return f"static methods are not allowed in Rúnar contracts; method '{name}' is declared static"


def lex_error(message: str, file: str, line: int, column: int) -> Diagnostic:
    """A tokenizer diagnostic located at line:column of file."""
    return Diagnostic(message=message, severity=Severity.ERROR,
                      loc=SourceLocation(file=file, line=line, column=column))


def with_lex_errors(result, lex: list):
    """Put a tokenizer's diagnostics (F-011) in front of a ParseResult's own."""
    if lex:
        result.errors = list(lex) + list(result.errors or [])
    return result
