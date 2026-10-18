"""Structured compiler diagnostics."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from runar_compiler.frontend.ast_nodes import CustomType, SourceLocation


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
        """Format with optional file:line:column prefix.

        The column is 0-based (N-078, R88a), so column 0 is a real position
        and prints as ``:0``; only an unknown line (0) drops the column.
        """
        if self.loc and self.loc.file:
            if self.loc.line > 0:
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

# N-121 (user decision R85; the TS reference's OPTIONAL_CHAINING): a .runar.ts
# ``?.``, located at the ``?``. Only the first ``?.`` in a file is reported.
OPTIONAL_CHAINING = "optional chaining '?.' is not supported"

# F-203 (the TS reference's invalidEscapeSequenceMessage): a .runar.py string
# or bytes escape CPython does not define for that literal kind, a ``\x`` not
# followed by two hex digits, an octal escape above 0o377, or (in a plain
# string) ``\N{..}`` / ``\u`` / ``\U``, which the surface does not support.
# ``escape`` is the backslash plus the escape letter, or the whole octal escape.
def invalid_escape_sequence_message(escape: str) -> str:
    return f"invalid escape sequence '{escape}'"


# F-203: CPython's refusal of a non-ASCII character inside b'..' / b"..".
PY_BYTES_NON_ASCII = "bytes can only contain ASCII literal characters"

# F-026: a .runar.zig call argument list or array literal whose elements are
# not separated by commas (the TS reference's ZIG_LIST_COMMA).
ZIG_LIST_COMMA = "expected ',' between list elements"

# F-026: a second .runar.py statement on the same line (the TS reference's
# PY_STATEMENT_LINE_BREAK).
PY_STATEMENT_LINE_BREAK = "expected a line break between statements"

# The TS reference's refusal of a Java char literal.
JAVA_CHAR_LITERAL = "char literals are unsupported in Rúnar Java contracts"


def unsupported_statement_message(token: str) -> str:
    """N-053's refusal of a .runar.rb / .runar.py statement whose first token
    can begin neither a statement nor an expression (the TS reference's
    unsupportedStatementMessage). ``token`` is the token's source text."""
    return f"Unsupported statement starting with '{token}'"


def unexpected_class_body_token_message(token: str) -> str:
    """N-004's refusal of a .runar.rb class-body token that is not ``prop``,
    ``runar_public``, ``params``, ``def`` or a bare ``private`` / ``public``
    marker (the TS reference's unexpectedClassBodyTokenMessage). It used to be
    skipped, so an indented ``=begin`` (lexed as ``=``, ``begin``) let a
    "commented-out" method become the only spend path."""
    return f"Unexpected token in class body: '{token}'"


def unexpected_token_after_class_message(token: str) -> str:
    """N-004's refusal of the first token after a .runar.rb class's ``end``
    (the TS reference's unexpectedTokenAfterClassMessage)."""
    return f"Unexpected token after class end: '{token}'"


def unknown_return_type_message(t, method: str) -> Optional[str]:
    """N-331's refusal of a method whose RETURN-type annotation names a type
    that is not a Rúnar type (the TS reference's ``checkReturnType``). The AST
    keeps no return type, so every surface parser calls this where the
    annotation is spelled. ``None`` for any other type; ``unknown`` is the
    missing-annotation placeholder, diagnosed elsewhere."""
    if isinstance(t, CustomType) and t.name != "unknown":
        return f"Type '{t.name}' of the return value of method '{method}' is not a Rúnar type"
    return None


def reject_unknown_return_type(errors: list, t, method: str, loc: Optional[SourceLocation]) -> None:
    """N-331: append the unknown-return-type diagnostic to ``errors`` when
    ``t`` (the parsed return annotation) is not a Rúnar type."""
    msg = unknown_return_type_message(t, method)
    if msg is not None:
        errors.append(Diagnostic(message=msg, severity=Severity.ERROR, loc=loc))


def static_method_message(name: str) -> str:
    """N-050's refusal of a static or class-level method (the TS reference's
    staticMethodMessage): ``static`` on .runar.ts / .runar.java,
    ``@staticmethod`` / ``@classmethod`` on .runar.py, ``def self.m`` on
    .runar.rb, and a ``pub fn`` without a self receiver on .runar.rs /
    .runar.zig. ``name`` is the method name as written in the source."""
    return f"static methods are not allowed in Rúnar contracts; method '{name}' is declared static"


def bare_java_property_assignment_message(name: str) -> str:
    """N-023's (R49) refusal, on the .runar.java surface, of an assignment
    (=, op=, ++, --) to a bare property name that no local or parameter
    shadows (the TS reference's bareJavaPropertyAssignmentMessage). In Java
    that bare name IS the field."""
    return f"bare assignment to property '{name}' is not allowed; write `this.{name} = ...`"


def lex_error(message: str, file: str, line: int, column: int) -> Diagnostic:
    """A tokenizer diagnostic located at line:column of file."""
    return Diagnostic(message=message, severity=Severity.ERROR,
                      loc=SourceLocation(file=file, line=line, column=column))


def with_lex_errors(result, lex: list):
    """Put a tokenizer's diagnostics (F-011) in front of a ParseResult's own."""
    if lex:
        result.errors = list(lex) + list(result.errors or [])
    return result
