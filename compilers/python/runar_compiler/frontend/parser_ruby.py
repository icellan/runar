"""Ruby format parser (.runar.rb) for the Runar compiler.

Ported from packages/runar-compiler/src/passes/01-parse-ruby.ts.
Hand-written tokenizer + recursive descent parser.

Ruby syntax conventions used in Runar contracts:
  - ``class Foo < Runar::SmartContract`` /
    ``class Foo < Runar::StatefulSmartContract``
  - ``runar_public`` marker for public methods (with optional param types)
  - ``@instance_var`` for property access (maps to ``this.prop``)
  - ``prop :name, Type [, readonly: true]`` for typed property declarations
  - ``assert expr`` for assertions (keyword, no parentheses required)
  - snake_case names converted to camelCase in AST
  - ``and``/``or``/``not`` for boolean operators alongside ``&&``/``||``/``!``
  - ``end`` keyword terminates blocks (no significant whitespace)
  - ``unless`` maps to if with negated condition
  - ``for i in 0...n`` / ``for i in 0..n`` for bounded loops
"""

from __future__ import annotations

import re

from runar_compiler.frontend.ast_nodes import (
    ArrayLiteralExpr,
    ContractNode, PropertyNode, MethodNode, ParamNode, SourceLocation,
    PrimitiveType, FixedArrayType, CustomType, TypeNode,
    BigIntLiteral, BoolLiteral, ByteStringLiteral, Identifier,
    PropertyAccessExpr, MemberExpr, BinaryExpr, UnaryExpr, CallExpr,
    TernaryExpr, IndexAccessExpr, IncrementExpr,
    VariableDeclStmt, AssignmentStmt, ExpressionStmt, IfStmt, ForStmt,
    ReturnStmt, Expression, Statement, is_primitive_type,
)
from runar_compiler.frontend.parser_dispatch import ParseResult


# ---------------------------------------------------------------------------
# Token types
# ---------------------------------------------------------------------------

TOK_EOF = 0
TOK_IDENT = 1
TOK_NUMBER = 2
TOK_HEXSTRING = 3   # single-quoted string → hex ByteString
TOK_STRING = 4      # double-quoted string
TOK_SYMBOL = 5      # :name
TOK_IVAR = 6        # @name
TOK_LPAREN = 7      # (
TOK_RPAREN = 8      # )
TOK_LBRACKET = 9    # [
TOK_RBRACKET = 10   # ]
TOK_COMMA = 11      # ,
TOK_DOT = 12        # .
TOK_COLON = 13      # :
TOK_COLONCOLON = 14 # ::
TOK_ASSIGN = 15     # =
TOK_EQEQ = 16       # ==
TOK_NOTEQ = 17      # !=
TOK_LT = 18         # <
TOK_LTEQ = 19       # <=
TOK_GT = 20         # >
TOK_GTEQ = 21       # >=
TOK_PLUS = 22       # +
TOK_MINUS = 23      # -
TOK_STAR = 24       # *
TOK_SLASH = 25      # /
TOK_PERCENT = 26    # %
TOK_STARSTAR = 27   # **
TOK_BANG = 28       # !
TOK_TILDE = 29      # ~
TOK_AMP = 30        # &
TOK_PIPE = 31       # |
TOK_CARET = 32      # ^
TOK_AMPAMP = 33     # &&
TOK_PIPEPIPE = 34   # ||
TOK_LSHIFT = 35     # <<
TOK_RSHIFT = 36     # >>
TOK_PLUSEQ = 37     # +=
TOK_MINUSEQ = 38    # -=
TOK_STAREQ = 39     # *=
TOK_SLASHEQ = 40    # /=
TOK_PERCENTEQ = 41  # %=
TOK_DOTDOT = 42     # ..
TOK_DOTDOTDOT = 43  # ...
TOK_QUESTION = 44   # ?
TOK_NEWLINE = 45

# Keywords
TOK_CLASS = 50
TOK_DEF = 51
TOK_IF = 52
TOK_ELSIF = 53
TOK_ELSE = 54
TOK_UNLESS = 55
TOK_FOR = 56
TOK_IN = 57
TOK_END = 58
TOK_RETURN = 59
TOK_TRUE = 60
TOK_FALSE = 61
TOK_NIL = 62
TOK_AND = 63
TOK_OR = 64
TOK_NOT = 65
TOK_SUPER = 66
TOK_REQUIRE = 67
TOK_ASSERT = 68
TOK_DO = 69

_KEYWORDS: dict[str, int] = {
    "class": TOK_CLASS,
    "def": TOK_DEF,
    "if": TOK_IF,
    "elsif": TOK_ELSIF,
    "else": TOK_ELSE,
    "unless": TOK_UNLESS,
    "for": TOK_FOR,
    "in": TOK_IN,
    "end": TOK_END,
    "return": TOK_RETURN,
    "true": TOK_TRUE,
    "false": TOK_FALSE,
    "nil": TOK_NIL,
    "and": TOK_AND,
    "or": TOK_OR,
    "not": TOK_NOT,
    "super": TOK_SUPER,
    "require": TOK_REQUIRE,
    "assert": TOK_ASSERT,
    "do": TOK_DO,
}


class Token:
    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind: int, value: str, line: int, col: int):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# Special name mappings (snake_case → camelCase)
# ---------------------------------------------------------------------------

_SPECIAL_NAMES: dict[str, str] = {
    "initialize": "constructor",
    "check_sig": "checkSig",
    "check_multi_sig": "checkMultiSig",
    "check_preimage": "checkPreimage",
    "verify_wots": "verifyWOTS",
    "verify_slh_dsa_sha2_128s": "verifySLHDSA_SHA2_128s",
    "verify_slh_dsa_sha2_128f": "verifySLHDSA_SHA2_128f",
    "verify_slh_dsa_sha2_192s": "verifySLHDSA_SHA2_192s",
    "verify_slh_dsa_sha2_192f": "verifySLHDSA_SHA2_192f",
    "verify_slh_dsa_sha2_256s": "verifySLHDSA_SHA2_256s",
    "verify_slh_dsa_sha2_256f": "verifySLHDSA_SHA2_256f",
    "verify_rabin_sig": "verifyRabinSig",
    "ec_add": "ecAdd",
    "ec_mul": "ecMul",
    "ec_mul_gen": "ecMulGen",
    "ec_negate": "ecNegate",
    "ec_on_curve": "ecOnCurve",
    "ec_mod_reduce": "ecModReduce",
    "ec_encode_compressed": "ecEncodeCompressed",
    "ec_make_point": "ecMakePoint",
    "ec_point_x": "ecPointX",
    "ec_point_y": "ecPointY",
    "add_output": "addOutput",
    "add_raw_output": "addRawOutput",
    "get_state_script": "getStateScript",
    "extract_locktime": "extractLocktime",
    "extract_output_hash": "extractOutputHash",
    "extract_amount": "extractAmount",
    "extract_version": "extractVersion",
    "extract_sequence": "extractSequence",
    "extract_nsequence": "extractNSequence",
    "extract_hash_prevouts": "extractHashPrevouts",
    "extract_hash_sequence": "extractHashSequence",
    "extract_outpoint": "extractOutpoint",
    "extract_script_code": "extractScriptCode",
    "extract_input_index": "extractInputIndex",
    "extract_sig_hash_type": "extractSigHashType",
    "extract_outputs": "extractOutputs",
    "mul_div": "mulDiv",
    "percent_of": "percentOf",
    "reverse_bytes": "reverseBytes",
    "safe_div": "safediv",
    "safe_mod": "safemod",
    "div_mod": "divmod",
    # SHA-256 partial verification (explicit for documentation clarity)
    "sha256_compress": "sha256Compress",
    "sha256_finalize": "sha256Finalize",
    "sha256": "sha256",
    "ripemd160": "ripemd160",
    "hash160": "hash160",
    "hash256": "hash256",
    "num2bin": "num2bin",
    "bin2num": "bin2num",
    "log2": "log2",
    # EC constants — pass through unchanged
    "EC_P": "EC_P",
    "EC_N": "EC_N",
    "EC_G": "EC_G",
}

# Names that pass through unchanged (no snake_case conversion)
_PASSTHROUGH_NAMES: frozenset[str] = frozenset({
    "bool", "abs", "min", "max", "len", "pow", "cat", "within",
    "safediv", "safemod", "clamp", "sign", "sqrt", "gcd", "divmod",
    "log2", "substr",
})


def _snake_to_camel(name: str) -> str:
    """Convert a snake_case identifier to camelCase.

    Only capitalizes lowercase letters and digits after underscores, matching
    the TS reference: ``name.replace(/_([a-z0-9])/g, ...)``.  This means
    ``EC_P`` passes through unchanged (uppercase P is not matched).

    Leading underscores are stripped so that ``_require_owner`` becomes
    ``requireOwner`` (not ``RequireOwner``).
    """
    leading = len(name) - len(name.lstrip("_"))
    if leading > 0:
        return re.sub(r"_([a-z0-9])", lambda m: m.group(1).upper(), name[leading:])
    return re.sub(r"_([a-z0-9])", lambda m: m.group(1).upper(), name)


def _map_builtin_name(name: str) -> str:
    """Map a Ruby snake_case name to its Runar AST callee name."""
    if name in _SPECIAL_NAMES:
        return _SPECIAL_NAMES[name]
    if name in _PASSTHROUGH_NAMES:
        return name
    return _snake_to_camel(name)


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, str] = {
    "Bigint": "bigint",
    "Integer": "bigint",
    "Int": "bigint",
    "Fixnum": "bigint",
    "Boolean": "boolean",
    "TrueClass": "boolean",
    "FalseClass": "boolean",
    "ByteString": "ByteString",
    "PubKey": "PubKey",
    "Sig": "Sig",
    "Addr": "Addr",
    "Sha256": "Sha256",
    "Ripemd160": "Ripemd160",
    "SigHashPreimage": "SigHashPreimage",
    "RabinSig": "RabinSig",
    "RabinPubKey": "RabinPubKey",
    "Point": "Point",
}


def _map_rb_type(name: str) -> TypeNode:
    """Map a Ruby type name to a Runar TypeNode."""
    mapped = _TYPE_MAP.get(name, name)
    if is_primitive_type(mapped):
        return PrimitiveType(name=mapped)
    return CustomType(name=mapped)


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

_SINGLE_CHAR_TOKENS: dict[str, int] = {
    ",": TOK_COMMA,
    ".": TOK_DOT,
    ":": TOK_COLON,
    "+": TOK_PLUS,
    "-": TOK_MINUS,
    "*": TOK_STAR,
    "/": TOK_SLASH,
    "%": TOK_PERCENT,
    "!": TOK_BANG,
    "~": TOK_TILDE,
    "&": TOK_AMP,
    "|": TOK_PIPE,
    "^": TOK_CARET,
    "?": TOK_QUESTION,
    "<": TOK_LT,
    ">": TOK_GT,
    "=": TOK_ASSIGN,
}

_COMPOUND_OPS: dict[int, str] = {
    TOK_PLUSEQ: "+",
    TOK_MINUSEQ: "-",
    TOK_STAREQ: "*",
    TOK_SLASHEQ: "/",
    TOK_PERCENTEQ: "%",
}


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _tokenize(source: str) -> list[Token]:
    """Tokenise a Ruby Runar source file line by line.

    The tokenizer processes one line at a time, tracking parenthesis depth to
    suppress NEWLINE tokens inside multi-line expressions.  This matches the
    behavior of the TypeScript reference implementation.
    """
    tokens: list[Token] = []
    lines = source.split("\n")
    paren_depth = 0

    for line_idx, raw_line in enumerate(lines):
        line_num = line_idx + 1

        # Strip trailing carriage return
        line = raw_line.rstrip("\r")

        # Skip blank lines and comment-only lines
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue

        # Tokenise the content of this line
        pos = len(line) - len(stripped)  # starting position (after indent)

        while pos < len(line):
            ch = line[pos]
            col = pos + 1  # 1-based column

            # Whitespace within a line
            if ch in (" ", "\t"):
                pos += 1
                continue

            # Comment — rest of line is ignored
            if ch == "#":
                break

            # Instance variable: @name → single ivar token
            if ch == "@":
                pos += 1
                name_start = pos
                while pos < len(line) and _is_ident_part(line[pos]):
                    pos += 1
                name = line[name_start:pos]
                if name:
                    tokens.append(Token(TOK_IVAR, name, line_num, col))
                else:
                    # Bare @ (unusual, but safe to skip)
                    pass
                continue

            # Three-dot range operator (must be tried before two-dot)
            if ch == "." and pos + 2 < len(line) and line[pos + 1] == "." and line[pos + 2] == ".":
                tokens.append(Token(TOK_DOTDOTDOT, "...", line_num, col))
                pos += 3
                continue

            # Two-dot range operator
            if ch == "." and pos + 1 < len(line) and line[pos + 1] == ".":
                tokens.append(Token(TOK_DOTDOT, "..", line_num, col))
                pos += 2
                continue

            # Two-character operators (longest match first)
            if pos + 1 < len(line):
                two = line[pos:pos + 2]
                if two == "**":
                    tokens.append(Token(TOK_STARSTAR, "**", line_num, col))
                    pos += 2
                    continue
                if two == "::":
                    tokens.append(Token(TOK_COLONCOLON, "::", line_num, col))
                    pos += 2
                    continue
                if two == "==":
                    tokens.append(Token(TOK_EQEQ, "==", line_num, col))
                    pos += 2
                    continue
                if two == "!=":
                    tokens.append(Token(TOK_NOTEQ, "!=", line_num, col))
                    pos += 2
                    continue
                if two == "<=":
                    tokens.append(Token(TOK_LTEQ, "<=", line_num, col))
                    pos += 2
                    continue
                if two == ">=":
                    tokens.append(Token(TOK_GTEQ, ">=", line_num, col))
                    pos += 2
                    continue
                if two == "<<":
                    tokens.append(Token(TOK_LSHIFT, "<<", line_num, col))
                    pos += 2
                    continue
                if two == ">>":
                    tokens.append(Token(TOK_RSHIFT, ">>", line_num, col))
                    pos += 2
                    continue
                if two == "&&":
                    tokens.append(Token(TOK_AMPAMP, "&&", line_num, col))
                    pos += 2
                    continue
                if two == "||":
                    tokens.append(Token(TOK_PIPEPIPE, "||", line_num, col))
                    pos += 2
                    continue
                if two == "+=":
                    tokens.append(Token(TOK_PLUSEQ, "+=", line_num, col))
                    pos += 2
                    continue
                if two == "-=":
                    tokens.append(Token(TOK_MINUSEQ, "-=", line_num, col))
                    pos += 2
                    continue
                if two == "*=":
                    tokens.append(Token(TOK_STAREQ, "*=", line_num, col))
                    pos += 2
                    continue
                if two == "/=":
                    tokens.append(Token(TOK_SLASHEQ, "/=", line_num, col))
                    pos += 2
                    continue
                if two == "%=":
                    tokens.append(Token(TOK_PERCENTEQ, "%=", line_num, col))
                    pos += 2
                    continue

            # Parentheses (track depth for multi-line suppression)
            if ch == "(":
                paren_depth += 1
                tokens.append(Token(TOK_LPAREN, "(", line_num, col))
                pos += 1
                continue
            if ch == ")":
                paren_depth = max(0, paren_depth - 1)
                tokens.append(Token(TOK_RPAREN, ")", line_num, col))
                pos += 1
                continue
            if ch == "[":
                paren_depth += 1
                tokens.append(Token(TOK_LBRACKET, "[", line_num, col))
                pos += 1
                continue
            if ch == "]":
                paren_depth = max(0, paren_depth - 1)
                tokens.append(Token(TOK_RBRACKET, "]", line_num, col))
                pos += 1
                continue

            # Symbol: :name (but not :: which was handled above)
            if ch == ":" and pos + 1 < len(line) and _is_ident_start(line[pos + 1]):
                pos += 1  # skip ':'
                name_start = pos
                while pos < len(line) and _is_ident_part(line[pos]):
                    pos += 1
                symbol_name = line[name_start:pos]
                tokens.append(Token(TOK_SYMBOL, symbol_name, line_num, col))
                continue

            # Single-character operators and delimiters
            if ch in _SINGLE_CHAR_TOKENS:
                tokens.append(Token(_SINGLE_CHAR_TOKENS[ch], ch, line_num, col))
                pos += 1
                continue

            # Single-quoted string literal → hex ByteString
            if ch == "'":
                pos += 1  # skip opening quote
                val_chars: list[str] = []
                while pos < len(line) and line[pos] != "'":
                    if line[pos] == "\\" and pos + 1 < len(line):
                        pos += 1  # skip backslash
                        val_chars.append(line[pos])
                        pos += 1
                    else:
                        val_chars.append(line[pos])
                        pos += 1
                if pos < len(line):
                    pos += 1  # skip closing quote
                tokens.append(Token(TOK_HEXSTRING, "".join(val_chars), line_num, col))
                continue

            # Double-quoted string literal
            if ch == '"':
                pos += 1  # skip opening quote
                val_chars = []
                while pos < len(line) and line[pos] != '"':
                    if line[pos] == "\\" and pos + 1 < len(line):
                        pos += 1  # skip backslash
                        val_chars.append(line[pos])
                        pos += 1
                    else:
                        val_chars.append(line[pos])
                        pos += 1
                if pos < len(line):
                    pos += 1  # skip closing quote
                tokens.append(Token(TOK_STRING, "".join(val_chars), line_num, col))
                continue

            # Numbers (decimal and hex)
            if ch.isdigit():
                num_chars: list[str] = []
                if (ch == "0" and pos + 1 < len(line)
                        and line[pos + 1] in ("x", "X")):
                    num_chars.append("0x")
                    pos += 2
                    while pos < len(line) and (line[pos] in "0123456789abcdefABCDEF_"):
                        if line[pos] != "_":
                            num_chars.append(line[pos])
                        pos += 1
                else:
                    while pos < len(line) and (line[pos].isdigit() or line[pos] == "_"):
                        if line[pos] != "_":
                            num_chars.append(line[pos])
                        pos += 1
                tokens.append(Token(TOK_NUMBER, "".join(num_chars), line_num, col))
                continue

            # Identifiers and keywords
            if _is_ident_start(ch):
                name_start = pos
                while pos < len(line) and _is_ident_part(line[pos]):
                    pos += 1
                # Ruby trailing ? or ! (e.g. empty?, include!)
                if pos < len(line) and line[pos] in ("?", "!"):
                    pos += 1
                word = line[name_start:pos]
                kw = _KEYWORDS.get(word)
                if kw is not None:
                    tokens.append(Token(kw, word, line_num, col))
                else:
                    tokens.append(Token(TOK_IDENT, word, line_num, col))
                continue

            # Skip unrecognized characters
            pos += 1

        # Emit NEWLINE at end of significant line (only if not inside parens)
        if paren_depth == 0:
            tokens.append(Token(TOK_NEWLINE, "", line_num, len(line) + 1))

    tokens.append(Token(TOK_EOF, "", len(lines) + 1, 1))
    return tokens


# ---------------------------------------------------------------------------
# Bare method call rewriting
# ---------------------------------------------------------------------------

def _rewrite_bare_method_calls(stmts: list[Statement], method_names: set[str]) -> None:
    """Rewrite bare function calls to declared contract methods as this.method().

    In Ruby, ``compute_threshold(a, b)`` inside a contract method is equivalent
    to ``self.compute_threshold(a, b)``, which should produce the same AST node
    as ``this.computeThreshold(a, b)`` in TypeScript.
    """

    def rewrite_expr(expr: Expression) -> Expression:
        if isinstance(expr, CallExpr):
            expr.args = [rewrite_expr(a) for a in expr.args]
            if isinstance(expr.callee, Identifier) and expr.callee.name in method_names:
                expr.callee = PropertyAccessExpr(property=expr.callee.name)
            else:
                expr.callee = rewrite_expr(expr.callee)
            return expr
        if isinstance(expr, BinaryExpr):
            expr.left = rewrite_expr(expr.left)
            expr.right = rewrite_expr(expr.right)
            return expr
        if isinstance(expr, UnaryExpr):
            expr.operand = rewrite_expr(expr.operand)
            return expr
        if isinstance(expr, TernaryExpr):
            expr.condition = rewrite_expr(expr.condition)
            expr.consequent = rewrite_expr(expr.consequent)
            expr.alternate = rewrite_expr(expr.alternate)
            return expr
        return expr

    def rewrite_stmt(stmt: Statement) -> None:
        if isinstance(stmt, ExpressionStmt):
            stmt.expr = rewrite_expr(stmt.expr)
        elif isinstance(stmt, VariableDeclStmt):
            stmt.init = rewrite_expr(stmt.init)
        elif isinstance(stmt, AssignmentStmt):
            stmt.value = rewrite_expr(stmt.value)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                stmt.value = rewrite_expr(stmt.value)
        elif isinstance(stmt, IfStmt):
            stmt.condition = rewrite_expr(stmt.condition)
            _rewrite_bare_method_calls(stmt.then, method_names)
            if stmt.else_:
                _rewrite_bare_method_calls(stmt.else_, method_names)
        elif isinstance(stmt, ForStmt):
            _rewrite_bare_method_calls(stmt.body, method_names)

    for stmt in stmts:
        rewrite_stmt(stmt)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _RbParser:
    """Recursive descent parser for Ruby-format Runar contracts."""

    def __init__(self, tokens: list[Token], file_name: str):
        self._tokens = tokens
        self._pos = 0
        self._file = file_name
        self._errors: list[str] = []
        # Track locally declared variables per method scope
        self._declared_locals: set[str] = set()

    # -----------------------------------------------------------------------
    # Token navigation
    # -----------------------------------------------------------------------

    def _current(self) -> Token:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return self._tokens[-1]  # EOF

    def _advance(self) -> Token:
        tok = self._current()
        if self._pos < len(self._tokens) - 1:
            self._pos += 1
        return tok

    def _peek(self) -> Token:
        return self._current()

    def _peek_ahead(self, offset: int = 1) -> Token:
        idx = self._pos + offset
        if idx < len(self._tokens):
            return self._tokens[idx]
        return self._tokens[-1]

    def _match(self, kind: int) -> bool:
        if self._current().kind == kind:
            self._advance()
            return True
        return False

    def _expect(self, kind: int, label: str = "") -> Token:
        tok = self._current()
        if tok.kind != kind:
            desc = label or str(kind)
            self._errors.append(
                f"{self._file}:{tok.line}:{tok.col}: "
                f"expected '{desc}', got '{tok.value or tok.kind}'"
            )
        return self._advance()

    def _check_ident(self, name: str) -> bool:
        tok = self._current()
        return tok.kind == TOK_IDENT and tok.value == name

    def _loc(self) -> SourceLocation:
        tok = self._current()
        return SourceLocation(file=self._file, line=tok.line, column=tok.col)

    def _skip_newlines(self) -> None:
        while self._current().kind == TOK_NEWLINE:
            self._advance()

    # -----------------------------------------------------------------------
    # Top-level parsing
    # -----------------------------------------------------------------------

    def parse(self) -> ParseResult:
        from runar_compiler.frontend.diagnostic import Diagnostic, Severity

        self._skip_newlines()

        # Consume ``require 'runar'`` lines
        while self._peek().kind == TOK_REQUIRE:
            self._parse_require_line()
            self._skip_newlines()

        contract = self._parse_class()
        diagnostics = [Diagnostic(message=e, severity=Severity.ERROR) for e in self._errors]
        if contract is None:
            return ParseResult(errors=diagnostics)
        return ParseResult(contract=contract, errors=diagnostics)

    def _parse_require_line(self) -> None:
        self._advance()  # 'require'
        while self._peek().kind not in (TOK_NEWLINE, TOK_EOF):
            self._advance()
        self._skip_newlines()

    def _parse_class(self) -> ContractNode | None:
        self._skip_newlines()

        if self._peek().kind != TOK_CLASS:
            self._errors.append(
                f"{self._file}:{self._peek().line}: expected class declaration"
            )
            return None
        self._advance()  # 'class'

        name_tok = self._expect(TOK_IDENT, "class name")
        contract_name = name_tok.value

        # Expect ``< Runar::SmartContract`` or ``< Runar::StatefulSmartContract``
        self._expect(TOK_LT, "<")

        first_part = self._advance()  # 'Runar' or the class name directly
        if self._peek().kind == TOK_COLONCOLON:
            self._advance()  # '::'
            class_part = self._advance()
            parent_class = class_part.value
        else:
            parent_class = first_part.value

        self._skip_newlines()

        if parent_class not in ("SmartContract", "StatefulSmartContract"):
            self._errors.append(
                f"{self._file}:{first_part.line}: unknown parent class: {parent_class}"
            )
            return None

        # Parse class body until ``end``
        properties: list[PropertyNode] = []
        methods: list[MethodNode] = []
        constructor: MethodNode | None = None

        # Pending visibility/param types for the next method
        pending_visibility: str | None = None
        pending_param_types: dict[str, TypeNode] | None = None

        while self._peek().kind not in (TOK_END, TOK_EOF):
            self._skip_newlines()
            if self._peek().kind in (TOK_END, TOK_EOF):
                break

            # ``prop :name, Type [, readonly: true]``
            if self._check_ident("prop"):
                prop = self._parse_prop(parent_class)
                if prop is not None:
                    properties.append(prop)
                self._skip_newlines()
                continue

            # ``runar_public [key: Type, ...]``
            if self._check_ident("runar_public"):
                self._advance()  # 'runar_public'
                pending_visibility = "public"
                pending_param_types = self._parse_optional_param_types()
                self._skip_newlines()
                continue

            # ``params key: Type, ...``
            if self._check_ident("params"):
                self._advance()  # 'params'
                pending_param_types = self._parse_optional_param_types()
                self._skip_newlines()
                continue

            # Method definition
            if self._peek().kind == TOK_DEF:
                method = self._parse_method(pending_visibility, pending_param_types)
                if method.name == "constructor":
                    constructor = method
                else:
                    methods.append(method)
                pending_visibility = None
                pending_param_types = None
                self._skip_newlines()
                continue

            # Skip unknown tokens
            self._advance()

        self._match(TOK_END)  # end of class

        # Auto-generate constructor if not provided
        if constructor is None:
            constructor = self._auto_generate_constructor(properties)

        # Back-fill constructor param types from prop declarations.
        # Ruby ``def initialize(pub_key_hash)`` has no type annotations —
        # we infer them from the matching ``prop :pub_key_hash, Addr``.
        prop_type_map = {p.name: p.type for p in properties}
        for param in constructor.params:
            if (isinstance(param.type, CustomType)
                    and param.type.name == "unknown"):
                prop_type = prop_type_map.get(param.name)
                if prop_type is not None:
                    param.type = prop_type

        # Rewrite bare calls to declared methods and intrinsics as this.method().
        # In Ruby, bare calls like `add_output(...)` are equivalent to
        # `self.add_output(...)` / `this.addOutput(...)`.
        _INTRINSIC_METHODS = {"addOutput", "addRawOutput", "getStateScript"}
        method_names = {m.name for m in methods} | _INTRINSIC_METHODS
        for method in methods:
            _rewrite_bare_method_calls(method.body, method_names)

        # Implicit return conversion for private methods.
        #
        # Ruby methods implicitly return the value of their last expression.
        # Private helper methods that return computed values (e.g. a fee
        # calculation) rely on this — without conversion, the calling method
        # would receive no return value and the type checker would reject
        # the call.  We detect ExpressionStmt as the final statement and
        # promote it to a ReturnStmt so the AST has an explicit return node
        # for ANF lowering and type checking to consume.
        for method in methods:
            if method.visibility == "private" and method.body:
                last = method.body[-1]
                if isinstance(last, ExpressionStmt):
                    method.body[-1] = ReturnStmt(
                        value=last.expr,
                        source_location=getattr(last, "source_location", None),
                    )

        return ContractNode(
            name=contract_name,
            parent_class=parent_class,
            properties=properties,
            constructor=constructor,
            methods=methods,
            source_file=self._file,
        )

    def _parse_optional_param_types(self) -> dict[str, TypeNode] | None:
        """Parse optional ``key: Type`` pairs after ``runar_public`` or ``params``.

        Returns ``None`` if there are no pairs on this line.
        """
        if self._peek().kind in (TOK_NEWLINE, TOK_EOF, TOK_DEF):
            return None

        param_types: dict[str, TypeNode] = {}

        while self._peek().kind not in (TOK_NEWLINE, TOK_EOF):
            name_tok = self._advance()
            raw_name = name_tok.value

            self._expect(TOK_COLON, ":")
            type_node = self._parse_type()
            param_types[raw_name] = type_node

            if not self._match(TOK_COMMA):
                break

        return param_types if param_types else None

    def _parse_prop(self, parent_class: str) -> PropertyNode | None:
        """Parse a ``prop :name, Type [, readonly: true|false]`` declaration."""
        loc = self._loc()
        self._advance()  # 'prop'

        if self._peek().kind != TOK_SYMBOL:
            self._errors.append(
                f"{self._file}:{self._peek().line}: "
                f"expected symbol after 'prop', got '{self._peek().value}'"
            )
            while self._peek().kind not in (TOK_NEWLINE, TOK_EOF):
                self._advance()
            return None

        raw_name = self._advance().value  # symbol value (without colon)
        self._expect(TOK_COMMA, ",")

        type_node = self._parse_type()

        is_readonly = False
        initializer: Expression | None = None

        # Check for optional trailing ``readonly: true`` or ``default: value``
        while self._peek().kind == TOK_COMMA:
            self._advance()  # ','

            if self._check_ident("readonly"):
                self._advance()  # 'readonly'
                self._expect(TOK_COLON, ":")
                if self._peek().kind == TOK_TRUE:
                    self._advance()
                    is_readonly = True
                elif self._peek().kind == TOK_FALSE:
                    self._advance()
                    is_readonly = False

            elif self._check_ident("default"):
                self._advance()  # 'default'
                self._expect(TOK_COLON, ":")
                initializer = self._parse_primary()

        # In stateless contracts, all properties are always readonly
        if parent_class == "SmartContract":
            is_readonly = True

        # Skip rest of line
        while self._peek().kind not in (TOK_NEWLINE, TOK_EOF):
            self._advance()

        return PropertyNode(
            name=_snake_to_camel(raw_name),
            type=type_node,
            readonly=is_readonly,
            initializer=initializer,
            source_location=loc,
        )

    def _parse_type(self) -> TypeNode:
        """Parse a Ruby type name, including ``FixedArray[T, N]``."""
        tok = self._advance()
        raw_name = tok.value

        # FixedArray[T, N] style generic
        if raw_name == "FixedArray" and self._peek().kind == TOK_LBRACKET:
            self._advance()  # '['
            elem_type = self._parse_type()
            self._expect(TOK_COMMA, ",")
            size_tok = self._expect(TOK_NUMBER, "number")
            size = int(size_tok.value)
            self._expect(TOK_RBRACKET, "]")
            return FixedArrayType(element=elem_type, length=size)

        return _map_rb_type(raw_name)

    def _parse_method(
        self,
        pending_visibility: str | None,
        pending_param_types: dict[str, TypeNode] | None,
    ) -> MethodNode:
        """Parse a ``def name(params...) ... end`` method definition."""
        loc = self._loc()
        self._expect(TOK_DEF, "def")

        name_tok = self._advance()
        raw_name = name_tok.value

        # Reset local variable tracking for this method scope
        self._declared_locals = set()

        # Parse parameters (parentheses optional for no-arg methods)
        if self._peek().kind == TOK_LPAREN:
            self._expect(TOK_LPAREN, "(")
            params = self._parse_params(pending_param_types)
            self._expect(TOK_RPAREN, ")")
        else:
            params = []

        self._skip_newlines()

        body = self._parse_statements()
        self._expect(TOK_END, "end")

        # ``initialize`` maps to ``constructor``
        if raw_name == "initialize":
            return MethodNode(
                name="constructor",
                params=params,
                body=body,
                visibility="public",
                source_location=loc,
            )

        is_public = pending_visibility == "public"
        method_name = _snake_to_camel(raw_name)

        return MethodNode(
            name=method_name,
            params=params,
            body=body,
            visibility="public" if is_public else "private",
            source_location=loc,
        )

    def _parse_params(
        self, param_types: dict[str, TypeNode] | None
    ) -> list[ParamNode]:
        """Parse a comma-separated parameter list (names only in Ruby)."""
        params: list[ParamNode] = []

        while self._peek().kind not in (TOK_RPAREN, TOK_EOF):
            name_tok = self._advance()
            raw_name = name_tok.value
            camel_name = _snake_to_camel(raw_name)

            type_node: TypeNode | None = None
            if param_types:
                type_node = param_types.get(raw_name)

            params.append(ParamNode(
                name=camel_name,
                type=type_node if type_node is not None else CustomType(name="unknown"),
            ))

            if not self._match(TOK_COMMA):
                break

        return params

    def _auto_generate_constructor(
        self, properties: list[PropertyNode]
    ) -> MethodNode:
        """Generate a default constructor from property declarations.

        Produces:
          super(prop1, prop2, ...)
          @prop1 = prop1
          @prop2 = prop2
          ...
        """
        # Exclude properties that have initializers (they don't need constructor params)
        required_props = [p for p in properties if p.initializer is None]

        params = [
            ParamNode(name=p.name, type=p.type)
            for p in required_props
        ]

        super_args: list[Expression] = [
            Identifier(name=p.name) for p in required_props
        ]

        loc = SourceLocation(file=self._file, line=1, column=0)

        super_call = ExpressionStmt(
            expr=CallExpr(
                callee=Identifier(name="super"),
                args=super_args,
            ),
            source_location=loc,
        )

        assignments: list[Statement] = [
            AssignmentStmt(
                target=PropertyAccessExpr(property=p.name),
                value=Identifier(name=p.name),
                source_location=loc,
            )
            for p in required_props
        ]

        return MethodNode(
            name="constructor",
            params=params,
            body=[super_call, *assignments],
            visibility="public",
            source_location=loc,
        )

    # -----------------------------------------------------------------------
    # Statements
    # -----------------------------------------------------------------------

    def _parse_statements(self) -> list[Statement]:
        """Parse statements until ``end``, ``elsif``, ``else``, or EOF."""
        stmts: list[Statement] = []

        while self._peek().kind not in (
            TOK_END, TOK_ELSIF, TOK_ELSE, TOK_EOF
        ):
            self._skip_newlines()
            if self._peek().kind in (TOK_END, TOK_ELSIF, TOK_ELSE, TOK_EOF):
                break

            stmt = self._parse_statement()
            if stmt is not None:
                stmts.append(stmt)
            self._skip_newlines()

        return stmts

    def _parse_statement(self) -> Statement | None:
        loc = self._loc()
        kind = self._peek().kind

        if kind == TOK_ASSERT:
            return self._parse_assert_statement(loc)
        if kind == TOK_IF:
            return self._parse_if_statement(loc)
        if kind == TOK_UNLESS:
            return self._parse_unless_statement(loc)
        if kind == TOK_FOR:
            return self._parse_for_statement(loc)
        if kind == TOK_RETURN:
            return self._parse_return_statement(loc)
        if kind == TOK_SUPER:
            return self._parse_super_call(loc)
        if kind == TOK_IVAR:
            return self._parse_ivar_statement(loc)
        if kind == TOK_IDENT:
            return self._parse_ident_statement(loc)

        # Skip unrecognized token
        self._advance()
        return None

    def _parse_assert_statement(self, loc: SourceLocation) -> Statement:
        self._advance()  # 'assert'
        expr = self._parse_expression()
        return ExpressionStmt(
            expr=CallExpr(
                callee=Identifier(name="assert"),
                args=[expr],
            ),
            source_location=loc,
        )

    def _parse_if_statement(self, loc: SourceLocation) -> Statement:
        self._advance()  # 'if'
        condition = self._parse_expression()
        self._skip_newlines()

        then_stmts = self._parse_statements()

        else_stmts: list[Statement] | None = None

        if self._peek().kind == TOK_ELSIF:
            elif_loc = self._loc()
            else_stmts = [self._parse_elsif_statement(elif_loc)]
        elif self._peek().kind == TOK_ELSE:
            self._advance()  # 'else'
            self._skip_newlines()
            else_stmts = self._parse_statements()

        self._expect(TOK_END, "end")

        return IfStmt(
            condition=condition,
            then=then_stmts,
            else_=else_stmts or [],
            source_location=loc,
        )

    def _parse_elsif_statement(self, loc: SourceLocation) -> Statement:
        self._advance()  # 'elsif'
        condition = self._parse_expression()
        self._skip_newlines()

        then_stmts = self._parse_statements()

        else_stmts: list[Statement] | None = None

        if self._peek().kind == TOK_ELSIF:
            elif_loc = self._loc()
            else_stmts = [self._parse_elsif_statement(elif_loc)]
        elif self._peek().kind == TOK_ELSE:
            self._advance()  # 'else'
            self._skip_newlines()
            else_stmts = self._parse_statements()

        # Note: the outer ``end`` is consumed by the parent ``_parse_if_statement``.
        # ``elsif`` branches do not consume their own ``end``.

        return IfStmt(
            condition=condition,
            then=then_stmts,
            else_=else_stmts or [],
            source_location=loc,
        )

    def _parse_unless_statement(self, loc: SourceLocation) -> Statement:
        self._advance()  # 'unless'
        raw_condition = self._parse_expression()
        self._skip_newlines()

        body = self._parse_statements()
        self._expect(TOK_END, "end")

        # ``unless cond`` maps to ``if !cond``
        condition: Expression = UnaryExpr(op="!", operand=raw_condition)

        return IfStmt(
            condition=condition,
            then=body,
            else_=[],
            source_location=loc,
        )

    def _parse_for_statement(self, loc: SourceLocation) -> Statement:
        self._advance()  # 'for'

        iter_tok = self._advance()  # loop variable name
        var_name = _snake_to_camel(iter_tok.value)

        self._expect(TOK_IN, "in")

        start_expr = self._parse_expression()

        # Expect range operator ``..`` (inclusive) or ``...`` (exclusive)
        is_exclusive = False
        if self._peek().kind == TOK_DOTDOTDOT:
            is_exclusive = True
            self._advance()
        elif self._peek().kind == TOK_DOTDOT:
            is_exclusive = False
            self._advance()
        else:
            self._errors.append(
                f"{self._file}:{self._peek().line}: "
                "expected range operator '..' or '...' in for loop"
            )

        end_expr = self._parse_expression()

        # Optional ``do`` keyword
        self._match(TOK_DO)
        self._skip_newlines()

        body = self._parse_statements()
        self._expect(TOK_END, "end")

        # Construct a C-style for loop AST node (same as TS reference)
        loop_var_loc = SourceLocation(file=self._file, line=iter_tok.line, column=iter_tok.col)
        init = VariableDeclStmt(
            name=var_name,
            type=PrimitiveType(name="bigint"),
            mutable=True,
            init=start_expr,
            source_location=loop_var_loc,
        )

        condition: Expression = BinaryExpr(
            op="<" if is_exclusive else "<=",
            left=Identifier(name=var_name),
            right=end_expr,
        )

        update = ExpressionStmt(
            expr=IncrementExpr(
                operand=Identifier(name=var_name),
                prefix=False,
            ),
            source_location=loc,
        )

        return ForStmt(
            init=init,
            condition=condition,
            update=update,
            body=body,
            source_location=loc,
        )

    def _parse_return_statement(self, loc: SourceLocation) -> Statement:
        self._advance()  # 'return'
        value: Expression | None = None
        if self._peek().kind not in (TOK_NEWLINE, TOK_END, TOK_EOF):
            value = self._parse_expression()
        return ReturnStmt(value=value, source_location=loc)

    def _parse_super_call(self, loc: SourceLocation) -> Statement:
        """Parse ``super(args...)`` in a constructor."""
        self._advance()  # 'super'
        self._expect(TOK_LPAREN, "(")
        args: list[Expression] = []
        while self._peek().kind not in (TOK_RPAREN, TOK_EOF):
            args.append(self._parse_expression())
            if not self._match(TOK_COMMA):
                break
        self._expect(TOK_RPAREN, ")")
        return ExpressionStmt(
            expr=CallExpr(
                callee=Identifier(name="super"),
                args=args,
            ),
            source_location=loc,
        )

    def _parse_ivar_statement(self, loc: SourceLocation) -> Statement:
        """Parse ``@var = expr``, ``@var += expr``, or ``@var`` as expression."""
        ivar_tok = self._advance()  # ivar token
        raw_name = ivar_tok.value
        prop_name = _snake_to_camel(raw_name)
        target: Expression = PropertyAccessExpr(property=prop_name)

        # Simple assignment: @var = expr
        if self._match(TOK_ASSIGN):
            value = self._parse_expression()
            return AssignmentStmt(target=target, value=value, source_location=loc)

        # Compound assignment: @var += expr, @var -= expr, etc.
        op_kind = self._peek().kind
        if op_kind in _COMPOUND_OPS:
            self._advance()
            right = self._parse_expression()
            value = BinaryExpr(op=_COMPOUND_OPS[op_kind], left=target, right=right)
            return AssignmentStmt(target=target, value=value, source_location=loc)

        # Expression statement: bare ``@var`` (e.g. followed by ``.method(...)``)
        expr: Expression = target
        expr = self._parse_postfix_from(expr)
        return ExpressionStmt(expr=expr, source_location=loc)

    def _parse_ident_statement(self, loc: SourceLocation) -> Statement | None:
        """Parse a statement starting with an identifier."""
        name_tok = self._peek()
        raw_name = name_tok.value

        # Simple ``name = expr`` (variable declaration or reassignment)
        if self._peek_ahead(1).kind == TOK_ASSIGN:
            self._advance()  # consume ident
            self._advance()  # consume '='
            value = self._parse_expression()
            camel_name = _snake_to_camel(raw_name)

            if camel_name in self._declared_locals:
                return AssignmentStmt(
                    target=Identifier(name=camel_name),
                    value=value,
                    source_location=loc,
                )
            self._declared_locals.add(camel_name)
            return VariableDeclStmt(
                name=camel_name,
                mutable=True,
                init=value,
                source_location=loc,
            )

        # Parse as expression
        expr = self._parse_expression()

        # Simple assignment (e.g. ``a.b = expr``)
        if self._match(TOK_ASSIGN):
            value = self._parse_expression()
            return AssignmentStmt(target=expr, value=value, source_location=loc)

        # Compound assignment
        op_kind = self._peek().kind
        if op_kind in _COMPOUND_OPS:
            self._advance()
            right = self._parse_expression()
            value = BinaryExpr(op=_COMPOUND_OPS[op_kind], left=expr, right=right)
            return AssignmentStmt(target=expr, value=value, source_location=loc)

        return ExpressionStmt(expr=expr, source_location=loc)

    # -----------------------------------------------------------------------
    # Expressions (precedence climbing)
    # -----------------------------------------------------------------------

    def _parse_expression(self) -> Expression:
        return self._parse_ternary()

    def _parse_ternary(self) -> Expression:
        expr = self._parse_or()
        if self._peek().kind == TOK_QUESTION:
            self._advance()  # '?'
            consequent = self._parse_expression()
            self._expect(TOK_COLON, ":")
            alternate = self._parse_expression()
            return TernaryExpr(condition=expr, consequent=consequent, alternate=alternate)
        return expr

    def _parse_or(self) -> Expression:
        left = self._parse_and()
        while self._peek().kind in (TOK_OR, TOK_PIPEPIPE):
            self._advance()
            right = self._parse_and()
            left = BinaryExpr(op="||", left=left, right=right)
        return left

    def _parse_and(self) -> Expression:
        left = self._parse_not()
        while self._peek().kind in (TOK_AND, TOK_AMPAMP):
            self._advance()
            right = self._parse_not()
            left = BinaryExpr(op="&&", left=left, right=right)
        return left

    def _parse_not(self) -> Expression:
        if self._peek().kind in (TOK_NOT, TOK_BANG):
            self._advance()
            operand = self._parse_not()
            return UnaryExpr(op="!", operand=operand)
        return self._parse_bitwise_or()

    def _parse_bitwise_or(self) -> Expression:
        left = self._parse_bitwise_xor()
        while self._peek().kind == TOK_PIPE:
            self._advance()
            right = self._parse_bitwise_xor()
            left = BinaryExpr(op="|", left=left, right=right)
        return left

    def _parse_bitwise_xor(self) -> Expression:
        left = self._parse_bitwise_and()
        while self._peek().kind == TOK_CARET:
            self._advance()
            right = self._parse_bitwise_and()
            left = BinaryExpr(op="^", left=left, right=right)
        return left

    def _parse_bitwise_and(self) -> Expression:
        left = self._parse_equality()
        while self._peek().kind == TOK_AMP:
            self._advance()
            right = self._parse_equality()
            left = BinaryExpr(op="&", left=left, right=right)
        return left

    def _parse_equality(self) -> Expression:
        left = self._parse_comparison()
        while True:
            kind = self._peek().kind
            if kind == TOK_EQEQ:
                self._advance()
                right = self._parse_comparison()
                left = BinaryExpr(op="===", left=left, right=right)
            elif kind == TOK_NOTEQ:
                self._advance()
                right = self._parse_comparison()
                left = BinaryExpr(op="!==", left=left, right=right)
            else:
                break
        return left

    def _parse_comparison(self) -> Expression:
        left = self._parse_shift()
        while True:
            kind = self._peek().kind
            if kind == TOK_LT:
                self._advance()
                right = self._parse_shift()
                left = BinaryExpr(op="<", left=left, right=right)
            elif kind == TOK_LTEQ:
                self._advance()
                right = self._parse_shift()
                left = BinaryExpr(op="<=", left=left, right=right)
            elif kind == TOK_GT:
                self._advance()
                right = self._parse_shift()
                left = BinaryExpr(op=">", left=left, right=right)
            elif kind == TOK_GTEQ:
                self._advance()
                right = self._parse_shift()
                left = BinaryExpr(op=">=", left=left, right=right)
            else:
                break
        return left

    def _parse_shift(self) -> Expression:
        left = self._parse_add_sub()
        while True:
            kind = self._peek().kind
            if kind == TOK_LSHIFT:
                self._advance()
                right = self._parse_add_sub()
                left = BinaryExpr(op="<<", left=left, right=right)
            elif kind == TOK_RSHIFT:
                self._advance()
                right = self._parse_add_sub()
                left = BinaryExpr(op=">>", left=left, right=right)
            else:
                break
        return left

    def _parse_add_sub(self) -> Expression:
        left = self._parse_mul_div()
        while True:
            kind = self._peek().kind
            if kind == TOK_PLUS:
                self._advance()
                right = self._parse_mul_div()
                left = BinaryExpr(op="+", left=left, right=right)
            elif kind == TOK_MINUS:
                self._advance()
                right = self._parse_mul_div()
                left = BinaryExpr(op="-", left=left, right=right)
            else:
                break
        return left

    def _parse_mul_div(self) -> Expression:
        left = self._parse_unary()
        while True:
            kind = self._peek().kind
            if kind == TOK_STAR:
                self._advance()
                right = self._parse_unary()
                left = BinaryExpr(op="*", left=left, right=right)
            elif kind == TOK_SLASH:
                self._advance()
                right = self._parse_unary()
                left = BinaryExpr(op="/", left=left, right=right)
            elif kind == TOK_PERCENT:
                self._advance()
                right = self._parse_unary()
                left = BinaryExpr(op="%", left=left, right=right)
            else:
                break
        return left

    def _parse_unary(self) -> Expression:
        kind = self._peek().kind
        if kind == TOK_MINUS:
            self._advance()
            return UnaryExpr(op="-", operand=self._parse_unary())
        if kind == TOK_TILDE:
            self._advance()
            return UnaryExpr(op="~", operand=self._parse_unary())
        if kind == TOK_BANG:
            self._advance()
            return UnaryExpr(op="!", operand=self._parse_unary())
        return self._parse_power()

    def _parse_power(self) -> Expression:
        base = self._parse_postfix()
        # ``**`` is right-associative and maps to ``pow(base, exp)``
        if self._peek().kind == TOK_STARSTAR:
            self._advance()
            exp = self._parse_power()  # right-recursive for right-associativity
            return CallExpr(
                callee=Identifier(name="pow"),
                args=[base, exp],
            )
        return base

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()
        return self._parse_postfix_from(expr)

    def _parse_postfix_from(self, expr: Expression) -> Expression:
        """Parse postfix operations (method calls, property access, indexing)."""
        while True:
            kind = self._peek().kind

            # Method call or property access: ``expr.name`` or ``expr.name(...)``
            if kind == TOK_DOT:
                self._advance()  # '.'
                prop_tok = self._advance()
                prop_name = _map_builtin_name(prop_tok.value)

                if self._peek().kind == TOK_LPAREN:
                    args = self._parse_call_args()
                    if isinstance(expr, Identifier) and expr.name == "this":
                        expr = CallExpr(
                            callee=MemberExpr(
                                object=Identifier(name="this"),
                                property=prop_name,
                            ),
                            args=args,
                        )
                    else:
                        expr = CallExpr(
                            callee=MemberExpr(object=expr, property=prop_name),
                            args=args,
                        )
                else:
                    # Property access
                    if isinstance(expr, Identifier) and expr.name == "this":
                        expr = PropertyAccessExpr(property=prop_name)
                    else:
                        expr = MemberExpr(object=expr, property=prop_name)
                continue

            # Function call: ``expr(args...)``
            if kind == TOK_LPAREN:
                args = self._parse_call_args()
                expr = CallExpr(callee=expr, args=args)
                continue

            # Index access: ``expr[index]``
            if kind == TOK_LBRACKET:
                self._advance()  # '['
                index = self._parse_expression()
                self._expect(TOK_RBRACKET, "]")
                expr = IndexAccessExpr(object=expr, index=index)
                continue

            break

        return expr

    def _parse_primary(self) -> Expression:
        tok = self._peek()
        kind = tok.kind

        # Number literal
        if kind == TOK_NUMBER:
            self._advance()
            return BigIntLiteral(value=int(tok.value, 0))

        # Boolean literals
        if kind == TOK_TRUE:
            self._advance()
            return BoolLiteral(value=True)
        if kind == TOK_FALSE:
            self._advance()
            return BoolLiteral(value=False)

        # Hex string literal (single-quoted)
        if kind == TOK_HEXSTRING:
            self._advance()
            return ByteStringLiteral(value=tok.value)

        # Double-quoted string literal
        if kind == TOK_STRING:
            self._advance()
            return ByteStringLiteral(value=tok.value)

        # ``nil`` → 0
        if kind == TOK_NIL:
            self._advance()
            return BigIntLiteral(value=0)

        # Instance variable: ``@var`` → property access
        if kind == TOK_IVAR:
            self._advance()
            prop_name = _snake_to_camel(tok.value)
            return PropertyAccessExpr(property=prop_name)

        # Parenthesised expression
        if kind == TOK_LPAREN:
            self._advance()
            expr = self._parse_expression()
            self._expect(TOK_RPAREN, ")")
            return expr

        # Array literal: ``[elem, ...]``
        if kind == TOK_LBRACKET:
            self._advance()
            elements: list[Expression] = []
            while self._peek().kind not in (TOK_RBRACKET, TOK_EOF):
                elements.append(self._parse_expression())
                if not self._match(TOK_COMMA):
                    break
            self._expect(TOK_RBRACKET, "]")
            return ArrayLiteralExpr(elements=elements)

        # Identifier or function call (including ``assert`` as identifier)
        if kind in (TOK_IDENT, TOK_ASSERT):
            self._advance()
            raw_name = tok.value
            name = _map_builtin_name(raw_name)
            return Identifier(name=name)

        # ``super`` as expression
        if kind == TOK_SUPER:
            self._advance()
            return Identifier(name="super")

        self._errors.append(
            f"{self._file}:{tok.line}:{tok.col}: "
            f"unexpected token in expression: '{tok.value or tok.kind}'"
        )
        self._advance()
        return BigIntLiteral(value=0)

    def _parse_call_args(self) -> list[Expression]:
        """Parse ``(arg, arg, ...)``."""
        self._expect(TOK_LPAREN, "(")
        args: list[Expression] = []
        while self._peek().kind not in (TOK_RPAREN, TOK_EOF):
            args.append(self._parse_expression())
            if not self._match(TOK_COMMA):
                break
        self._expect(TOK_RPAREN, ")")
        return args


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_ruby(source: str, file_name: str = "contract.runar.rb") -> ParseResult:
    """Parse a Ruby-format Runar contract (.runar.rb) and return a ParseResult."""
    tokens = _tokenize(source)
    parser = _RbParser(tokens, file_name)
    return parser.parse()
