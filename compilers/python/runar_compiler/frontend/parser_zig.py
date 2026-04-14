"""Zig format parser (.runar.zig) for the Runar compiler.

Ported from packages/runar-compiler/src/passes/01-parse-zig.ts.
Hand-written tokenizer + recursive descent parser.

Zig syntax conventions used in Runar contracts:
  - ``const runar = @import("runar");``
  - ``pub const Name = struct { ... };``
  - ``pub const Contract = runar.SmartContract;`` /
    ``pub const Contract = runar.StatefulSmartContract;``
  - Zig struct fields: ``name: runar.Type [= default],``
  - ``pub fn init(...)`` for constructor
  - ``pub fn method(self: *const T, ...)`` for public methods
  - ``fn helper(self: *const T, ...)`` for private methods
  - ``self.property`` for property access
  - ``runar.builtin()`` calls lowered to bare builtin identifiers
  - ``and``/``or`` keywords map to ``&&``/``||``
  - ``while (cond) : (update) { body }`` for bounded loops
  - ``@divTrunc(a, b)`` → ``/``, ``@mod(a, b)`` → ``%``, etc.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
    ArrayLiteralExpr,
    ContractNode, PropertyNode, MethodNode, ParamNode, SourceLocation,
    PrimitiveType, FixedArrayType, CustomType, TypeNode,
    BigIntLiteral, BoolLiteral, ByteStringLiteral, Identifier,
    PropertyAccessExpr, MemberExpr, BinaryExpr, UnaryExpr, CallExpr,
    TernaryExpr, IndexAccessExpr, IncrementExpr, DecrementExpr,
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
TOK_STRING = 3

TOK_LPAREN = 10      # (
TOK_RPAREN = 11      # )
TOK_LBRACE = 12      # {
TOK_RBRACE = 13      # }
TOK_LBRACKET = 14    # [
TOK_RBRACKET = 15    # ]
TOK_SEMICOLON = 16   # ;
TOK_COMMA = 17       # ,
TOK_DOT = 18         # .
TOK_COLON = 19       # :
TOK_AT = 20          # @

TOK_PLUS = 30        # +
TOK_MINUS = 31       # -
TOK_STAR = 32        # *
TOK_SLASH = 33       # /
TOK_PERCENT = 34     # %
TOK_AMP = 35         # &
TOK_PIPE = 36        # |
TOK_CARET = 37       # ^
TOK_TILDE = 38       # ~
TOK_BANG = 39        # !

TOK_EQEQ = 40       # ==
TOK_NOTEQ = 41       # !=
TOK_LT = 42          # <
TOK_LTEQ = 43        # <=
TOK_GT = 44          # >
TOK_GTEQ = 45        # >=
TOK_AMPAMP = 46      # &&
TOK_PIPEPIPE = 47    # ||
TOK_LSHIFT = 48      # <<
TOK_RSHIFT = 49      # >>

TOK_ASSIGN = 50      # =
TOK_PLUSEQ = 51      # +=
TOK_MINUSEQ = 52     # -=
TOK_STAREQ = 53      # *=
TOK_SLASHEQ = 54     # /=
TOK_PERCENTEQ = 55   # %=

# Keywords
TOK_PUB = 60
TOK_CONST = 61
TOK_VAR = 62
TOK_FN = 63
TOK_STRUCT = 64
TOK_IF = 65
TOK_ELSE = 66
TOK_FOR = 67
TOK_WHILE = 68
TOK_RETURN = 69
TOK_TRUE = 70
TOK_FALSE = 71
TOK_VOID = 72

_KEYWORDS: dict[str, int] = {
    "pub": TOK_PUB,
    "const": TOK_CONST,
    "var": TOK_VAR,
    "fn": TOK_FN,
    "struct": TOK_STRUCT,
    "if": TOK_IF,
    "else": TOK_ELSE,
    "for": TOK_FOR,
    "while": TOK_WHILE,
    "return": TOK_RETURN,
    "true": TOK_TRUE,
    "false": TOK_FALSE,
    "void": TOK_VOID,
    "and": TOK_AMPAMP,
    "or": TOK_PIPEPIPE,
}

# Compound assignment operator → binary operator mapping
_COMPOUND_OPS: dict[int, str] = {
    TOK_PLUSEQ: "+",
    TOK_MINUSEQ: "-",
    TOK_STAREQ: "*",
    TOK_SLASHEQ: "/",
    TOK_PERCENTEQ: "%",
}


class Token:
    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind: int, value: str, line: int, col: int):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

_ZIG_TYPE_MAP: dict[str, str] = {
    "i8": "bigint",
    "i16": "bigint",
    "i32": "bigint",
    "i64": "bigint",
    "i128": "bigint",
    "isize": "bigint",
    "u8": "bigint",
    "u16": "bigint",
    "u32": "bigint",
    "u64": "bigint",
    "u128": "bigint",
    "usize": "bigint",
    "comptime_int": "bigint",
    "bool": "boolean",
    "void": "void",
    "Bigint": "bigint",
    "ByteString": "ByteString",
    "PubKey": "PubKey",
    "Sig": "Sig",
    "Sha256": "Sha256",
    "Ripemd160": "Ripemd160",
    "Addr": "Addr",
    "SigHashPreimage": "SigHashPreimage",
    "RabinSig": "RabinSig",
    "RabinPubKey": "RabinPubKey",
    "Point": "Point",
}


def _map_zig_type(name: str) -> str:
    return _ZIG_TYPE_MAP.get(name, name)


def _make_type_node(name: str) -> TypeNode:
    if is_primitive_type(name):
        return PrimitiveType(name=name)
    return CustomType(name=name)


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _tokenize(source: str) -> list[Token]:
    """Tokenize a Zig Runar source file."""
    tokens: list[Token] = []
    pos = 0
    line = 1
    col = 1
    length = len(source)

    while pos < length:
        ch = source[pos]
        tok_line = line
        tok_col = col

        # Whitespace
        if ch in (" ", "\t", "\r"):
            pos += 1
            col += 1
            continue

        if ch == "\n":
            pos += 1
            line += 1
            col = 1
            continue

        # Line comment: //
        if ch == "/" and pos + 1 < length and source[pos + 1] == "/":
            while pos < length and source[pos] != "\n":
                pos += 1
            continue

        # Block comment: /* ... */
        if ch == "/" and pos + 1 < length and source[pos + 1] == "*":
            pos += 2
            col += 2
            while pos < length - 1:
                if source[pos] == "*" and source[pos + 1] == "/":
                    pos += 2
                    col += 2
                    break
                if source[pos] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                pos += 1
            continue

        # Two-character operators (longest match first)
        if pos + 1 < length:
            two = source[pos:pos + 2]
            tok2: int | None = None
            if two == "==":
                tok2 = TOK_EQEQ
            elif two == "!=":
                tok2 = TOK_NOTEQ
            elif two == "<=":
                tok2 = TOK_LTEQ
            elif two == ">=":
                tok2 = TOK_GTEQ
            elif two == "<<":
                tok2 = TOK_LSHIFT
            elif two == ">>":
                tok2 = TOK_RSHIFT
            elif two == "&&":
                tok2 = TOK_AMPAMP
            elif two == "||":
                tok2 = TOK_PIPEPIPE
            elif two == "+=":
                tok2 = TOK_PLUSEQ
            elif two == "-=":
                tok2 = TOK_MINUSEQ
            elif two == "*=":
                tok2 = TOK_STAREQ
            elif two == "/=":
                tok2 = TOK_SLASHEQ
            elif two == "%=":
                tok2 = TOK_PERCENTEQ

            if tok2 is not None:
                tokens.append(Token(tok2, two, tok_line, tok_col))
                pos += 2
                col += 2
                continue

        # Single-character tokens
        _SINGLES: dict[str, int] = {
            "(": TOK_LPAREN,
            ")": TOK_RPAREN,
            "{": TOK_LBRACE,
            "}": TOK_RBRACE,
            "[": TOK_LBRACKET,
            "]": TOK_RBRACKET,
            ";": TOK_SEMICOLON,
            ",": TOK_COMMA,
            ".": TOK_DOT,
            ":": TOK_COLON,
            "@": TOK_AT,
            "+": TOK_PLUS,
            "-": TOK_MINUS,
            "*": TOK_STAR,
            "/": TOK_SLASH,
            "%": TOK_PERCENT,
            "<": TOK_LT,
            ">": TOK_GT,
            "=": TOK_ASSIGN,
            "&": TOK_AMP,
            "|": TOK_PIPE,
            "^": TOK_CARET,
            "~": TOK_TILDE,
            "!": TOK_BANG,
        }

        if ch in _SINGLES:
            tokens.append(Token(_SINGLES[ch], ch, tok_line, tok_col))
            pos += 1
            col += 1
            continue

        # String literal (double-quoted)
        if ch == '"':
            pos += 1
            col += 1
            val_chars: list[str] = []
            while pos < length and source[pos] != '"':
                if source[pos] == "\\" and pos + 1 < length:
                    pos += 1
                    col += 1
                    val_chars.append(source[pos])
                    pos += 1
                    col += 1
                else:
                    val_chars.append(source[pos])
                    pos += 1
                    col += 1
            if pos < length:
                pos += 1  # skip closing quote
                col += 1
            tokens.append(Token(TOK_STRING, "".join(val_chars), tok_line, tok_col))
            continue

        # Number literal
        if ch.isdigit():
            num_chars: list[str] = []
            if ch == "0" and pos + 1 < length and source[pos + 1] in ("x", "X"):
                num_chars.append("0x")
                pos += 2
                col += 2
                while pos < length and source[pos] in "0123456789abcdefABCDEF_":
                    if source[pos] != "_":
                        num_chars.append(source[pos])
                    pos += 1
                    col += 1
            else:
                while pos < length and (source[pos].isdigit() or source[pos] == "_"):
                    if source[pos] != "_":
                        num_chars.append(source[pos])
                    pos += 1
                    col += 1
            tokens.append(Token(TOK_NUMBER, "".join(num_chars), tok_line, tok_col))
            continue

        # Identifiers and keywords
        if _is_ident_start(ch):
            name_start = pos
            while pos < length and _is_ident_part(source[pos]):
                pos += 1
                col += 1
            word = source[name_start:pos]
            kw = _KEYWORDS.get(word)
            if kw is not None:
                tokens.append(Token(kw, word, tok_line, tok_col))
            else:
                tokens.append(Token(TOK_IDENT, word, tok_line, tok_col))
            continue

        # Skip unrecognized character
        pos += 1
        col += 1

    tokens.append(Token(TOK_EOF, "", line, col))
    return tokens


# ---------------------------------------------------------------------------
# Bare method call rewriting
# ---------------------------------------------------------------------------

def _rewrite_bare_method_calls(
    stmts: list[Statement],
    method_names: set[str],
    scope: set[str],
) -> None:
    """Rewrite bare function calls to declared contract methods as this.method().

    In Zig contracts, ``computeThreshold(a, b)`` should be rewritten as
    ``this.computeThreshold(a, b)`` in the AST.
    """

    def rewrite_expr(expr: Expression, scope: set[str]) -> Expression:
        if isinstance(expr, CallExpr):
            expr.args = [rewrite_expr(a, scope) for a in expr.args]
            if (isinstance(expr.callee, Identifier)
                    and expr.callee.name in method_names
                    and expr.callee.name not in scope):
                expr.callee = PropertyAccessExpr(property=expr.callee.name)
            else:
                expr.callee = rewrite_expr(expr.callee, scope)
            return expr
        if isinstance(expr, BinaryExpr):
            expr.left = rewrite_expr(expr.left, scope)
            expr.right = rewrite_expr(expr.right, scope)
            return expr
        if isinstance(expr, UnaryExpr):
            expr.operand = rewrite_expr(expr.operand, scope)
            return expr
        if isinstance(expr, TernaryExpr):
            expr.condition = rewrite_expr(expr.condition, scope)
            expr.consequent = rewrite_expr(expr.consequent, scope)
            expr.alternate = rewrite_expr(expr.alternate, scope)
            return expr
        if isinstance(expr, MemberExpr):
            expr.object = rewrite_expr(expr.object, scope)
            return expr
        if isinstance(expr, IndexAccessExpr):
            expr.object = rewrite_expr(expr.object, scope)
            expr.index = rewrite_expr(expr.index, scope)
            return expr
        if isinstance(expr, (IncrementExpr,)):
            expr.operand = rewrite_expr(expr.operand, scope)
            return expr
        if isinstance(expr, ArrayLiteralExpr):
            expr.elements = [rewrite_expr(e, scope) for e in expr.elements]
            return expr
        return expr

    def rewrite_stmts(stmts: list[Statement], scope: set[str]) -> None:
        current_scope = set(scope)
        for stmt in stmts:
            rewrite_stmt(stmt, current_scope)
            if isinstance(stmt, VariableDeclStmt):
                current_scope.add(stmt.name)

    def rewrite_stmt(stmt: Statement, scope: set[str]) -> None:
        if isinstance(stmt, ExpressionStmt):
            if stmt.expr is not None:
                stmt.expr = rewrite_expr(stmt.expr, scope)
        elif isinstance(stmt, VariableDeclStmt):
            if stmt.init is not None:
                stmt.init = rewrite_expr(stmt.init, scope)
        elif isinstance(stmt, AssignmentStmt):
            if stmt.target is not None:
                stmt.target = rewrite_expr(stmt.target, scope)
            if stmt.value is not None:
                stmt.value = rewrite_expr(stmt.value, scope)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                stmt.value = rewrite_expr(stmt.value, scope)
        elif isinstance(stmt, IfStmt):
            if stmt.condition is not None:
                stmt.condition = rewrite_expr(stmt.condition, scope)
            rewrite_stmts(stmt.then, set(scope))
            if stmt.else_:
                rewrite_stmts(stmt.else_, set(scope))
        elif isinstance(stmt, ForStmt):
            loop_scope = set(scope)
            if stmt.init is not None:
                rewrite_stmt(stmt.init, loop_scope)
                if isinstance(stmt.init, VariableDeclStmt):
                    loop_scope.add(stmt.init.name)
            if stmt.condition is not None:
                stmt.condition = rewrite_expr(stmt.condition, loop_scope)
            if stmt.update is not None:
                rewrite_stmt(stmt.update, loop_scope)
            rewrite_stmts(stmt.body, loop_scope)

    rewrite_stmts(stmts, scope)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _ZigParser:
    """Recursive descent parser for Zig-format Runar contracts."""

    def __init__(self, tokens: list[Token], file_name: str):
        self._tokens = tokens
        self._pos = 0
        self._file = file_name
        self._errors: list[str] = []
        self._contract_name = "UnnamedContract"
        self._parent_class = "SmartContract"
        self._properties: list[PropertyNode] = []
        self._methods: list[MethodNode] = []
        self._constructor: MethodNode | None = None
        self._self_names: set[str] = set()
        self._stateful_context_names: set[str] = set()

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

    def _loc(self) -> SourceLocation:
        tok = self._current()
        return SourceLocation(file=self._file, line=tok.line, column=tok.col)

    # -----------------------------------------------------------------------
    # Top-level parsing
    # -----------------------------------------------------------------------

    def parse(self) -> ParseResult:
        from runar_compiler.frontend.diagnostic import Diagnostic, Severity

        self._skip_runar_import()

        # Scan for `pub const Name = struct { ... };`
        while self._current().kind != TOK_EOF:
            if (self._current().kind == TOK_PUB
                    and self._peek_ahead(1).kind == TOK_CONST
                    and self._peek_ahead(2).kind == TOK_IDENT
                    and self._peek_ahead(3).kind == TOK_ASSIGN):
                contract = self._try_parse_contract_decl()
                if contract is not None:
                    diagnostics = [Diagnostic(message=e, severity=Severity.ERROR)
                                   for e in self._errors]
                    return ParseResult(contract=contract, errors=diagnostics)
            self._advance()

        self._errors.append(
            f"{self._file}:1:1: Expected Zig contract declaration "
            "`pub const Name = struct {{ ... }};`"
        )
        diagnostics = [Diagnostic(message=e, severity=Severity.ERROR)
                       for e in self._errors]

        fallback = ContractNode(
            name=self._contract_name,
            parent_class=self._parent_class,
            properties=self._properties,
            constructor=self._create_fallback_constructor(),
            methods=self._methods,
            source_file=self._file,
        )
        return ParseResult(contract=fallback, errors=diagnostics)

    def _skip_runar_import(self) -> None:
        """Skip ``const runar = @import("runar");`` at the top."""
        start = self._pos
        if self._current().kind == TOK_CONST:
            self._advance()
            if self._current().kind == TOK_IDENT and self._current().value == "runar":
                self._advance()
                if self._match(TOK_ASSIGN):
                    if (self._match(TOK_AT)
                            and self._current().kind == TOK_IDENT
                            and self._current().value == "import"):
                        self._advance()  # 'import'
                        self._expect(TOK_LPAREN, "(")
                        if self._current().kind == TOK_STRING:
                            self._advance()
                        self._expect(TOK_RPAREN, ")")
                        self._match(TOK_SEMICOLON)
                        return

        self._pos = start
        self._errors.append(
            f'{self._file}:1:1: Expected `const runar = @import("runar");` '
            "at the top of the file"
        )

    def _try_parse_contract_decl(self) -> ContractNode | None:
        start = self._pos

        self._expect(TOK_PUB, "pub")
        self._expect(TOK_CONST, "const")
        name_tok = self._expect(TOK_IDENT, "identifier")

        if self._current().kind != TOK_ASSIGN:
            self._pos = start
            return None
        self._expect(TOK_ASSIGN, "=")

        if self._current().kind != TOK_STRUCT:
            self._pos = start
            return None

        self._contract_name = name_tok.value
        self._parent_class = "SmartContract"
        self._properties = []
        self._methods = []
        self._constructor = None

        self._expect(TOK_STRUCT, "struct")
        self._expect(TOK_LBRACE, "{")

        while self._current().kind != TOK_RBRACE and self._current().kind != TOK_EOF:
            # Contract marker: pub const Contract = runar.SmartContract;
            if (self._current().kind == TOK_PUB
                    and self._peek_ahead(1).kind == TOK_CONST
                    and self._peek_ahead(2).kind == TOK_IDENT
                    and self._peek_ahead(2).value == "Contract"):
                self._parse_contract_marker()
                continue

            # Public method: pub fn name(...)
            if (self._current().kind == TOK_PUB
                    and self._peek_ahead(1).kind == TOK_FN):
                method = self._parse_method(is_public=True)
                if method is not None:
                    self._methods.append(method)
                continue

            # Private method: fn name(...)
            if self._current().kind == TOK_FN:
                method = self._parse_method(is_public=False)
                if method is not None:
                    self._methods.append(method)
                continue

            # Field: name: type [= default],
            if self._current().kind == TOK_IDENT:
                self._properties.append(self._parse_field())
                continue

            self._advance()

        self._expect(TOK_RBRACE, "}")
        self._match(TOK_SEMICOLON)

        # Collect property names mutated in any method body so we can
        # determine readonly flags in stateful contracts.
        mutated: set[str] = set()
        for method in self._methods:
            _collect_mutated_properties(method.body, mutated)

        # Constructor param names (used to strip property initializers whose
        # value is overridden by an explicit ctor param — matches the Zig
        # compiler reference behaviour of omitting `initialValue`).
        ctor_param_names: set[str] = set()
        if self._constructor is not None:
            ctor_param_names = {p.name for p in self._constructor.params}

        for prop in self._properties:
            had_initializer = prop.initializer is not None
            if prop.name in ctor_param_names:
                prop.initializer = None
            if self._parent_class == "SmartContract":
                prop.readonly = True
            elif (not prop.readonly
                  and not had_initializer
                  and prop.name not in mutated):
                # Stateful fields with no default and no mutation are readonly.
                prop.readonly = True

        # Rewrite bare method calls
        _INTRINSIC_METHODS = {"addOutput", "addRawOutput", "getStateScript"}
        method_names = {m.name for m in self._methods} | _INTRINSIC_METHODS
        for method in self._methods:
            param_scope = {p.name for p in method.params}
            _rewrite_bare_method_calls(method.body, method_names, param_scope)
        if self._constructor is not None:
            param_scope = {p.name for p in self._constructor.params}
            _rewrite_bare_method_calls(self._constructor.body, method_names, param_scope)

        return ContractNode(
            name=self._contract_name,
            parent_class=self._parent_class,
            properties=self._properties,
            constructor=self._constructor or self._create_fallback_constructor(),
            methods=self._methods,
            source_file=self._file,
        )

    def _parse_contract_marker(self) -> None:
        """Parse ``pub const Contract = runar.SmartContract;``."""
        self._expect(TOK_PUB, "pub")
        self._expect(TOK_CONST, "const")
        self._expect(TOK_IDENT, "Contract")
        self._expect(TOK_ASSIGN, "=")

        if self._current().kind == TOK_IDENT and self._current().value == "runar":
            self._advance()
            self._expect(TOK_DOT, ".")
            parent = self._expect(TOK_IDENT, "identifier").value
            if parent == "StatefulSmartContract":
                self._parent_class = "StatefulSmartContract"
            else:
                self._parent_class = "SmartContract"

        self._match(TOK_SEMICOLON)

    def _parse_field(self) -> PropertyNode:
        """Parse a struct field: ``name: runar.Type [= default],``."""
        loc = self._loc()
        name = self._expect(TOK_IDENT, "field name").value
        self._expect(TOK_COLON, ":")
        parsed_type = self._parse_type()

        initializer: Expression | None = None
        is_readonly = parsed_type[2]  # readonly flag from type parsing

        if self._current().kind == TOK_ASSIGN:
            self._advance()
            initializer = self._parse_expression()

        self._match(TOK_COMMA)

        return PropertyNode(
            name=name,
            type=parsed_type[0],
            readonly=is_readonly,
            initializer=initializer,
            source_location=loc,
        )

    def _parse_method(self, is_public: bool) -> MethodNode | None:
        """Parse a method: ``[pub] fn name(params...) ReturnType { body }``."""
        loc = self._loc()
        if is_public:
            self._expect(TOK_PUB, "pub")
        self._expect(TOK_FN, "fn")
        name = self._expect(TOK_IDENT, "method name").value

        params, receiver_name, stateful_ctx_names = self._parse_param_list()

        # Parse optional return type (before the body block)
        if self._current().kind != TOK_LBRACE:
            self._parse_type()

        prev_self_names = self._self_names
        prev_stateful_ctx_names = self._stateful_context_names
        self._self_names = {receiver_name} if receiver_name else set()
        self._stateful_context_names = stateful_ctx_names

        if name == "init":
            self._constructor = self._parse_constructor(loc, params)
            self._self_names = prev_self_names
            self._stateful_context_names = prev_stateful_ctx_names
            return None

        body = self._parse_block_statements()
        self._self_names = prev_self_names
        self._stateful_context_names = prev_stateful_ctx_names

        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility="public" if is_public else "private",
            source_location=loc,
        )

    def _parse_param_list(self) -> tuple[list[ParamNode], str | None, set[str]]:
        """Parse function parameter list.

        Returns (params, receiverName, statefulContextNames).
        The first parameter that matches the contract name is treated as the
        receiver (self) and filtered from the param list.
        """
        self._expect(TOK_LPAREN, "(")
        params: list[ParamNode] = []
        receiver_name: str | None = None
        stateful_ctx_names: set[str] = set()
        index = 0

        while self._current().kind != TOK_RPAREN and self._current().kind != TOK_EOF:
            param_name = self._expect(TOK_IDENT, "parameter name").value
            self._expect(TOK_COLON, ":")
            parsed_type = self._parse_param_type()
            is_receiver = (index == 0 and parsed_type[1] == self._contract_name)

            if is_receiver:
                receiver_name = param_name
            else:
                if parsed_type[1] == "StatefulContext":
                    stateful_ctx_names.add(param_name)
                params.append(ParamNode(
                    name=param_name,
                    type=parsed_type[0],
                ))

            index += 1
            self._match(TOK_COMMA)

        self._expect(TOK_RPAREN, ")")
        return params, receiver_name, stateful_ctx_names

    def _parse_param_type(self) -> tuple[TypeNode, str, bool]:
        """Parse a parameter type, skipping pointer/const qualifiers."""
        # Skip pointer qualifiers: *, &, const
        while self._current().kind in (TOK_STAR, TOK_AMP):
            self._advance()
        if self._current().kind == TOK_CONST:
            self._advance()
        return self._parse_type()

    def _parse_type(self) -> tuple[TypeNode, str, bool]:
        """Parse a type and return (TypeNode, rawName, readonly).

        Handles:
        - ``[N]Type`` → FixedArrayType
        - ``runar.TypeName`` → mapped primitive or custom
        - ``runar.Readonly(Type)`` → inner type with readonly=True
        - ``void`` → void primitive
        - bare ident → mapped type
        """
        # Array type: [N]Element
        if self._current().kind == TOK_LBRACKET:
            self._advance()
            length_tok = self._expect(TOK_NUMBER, "array length")
            length = int(length_tok.value, 0) if length_tok.value else 0
            self._expect(TOK_RBRACKET, "]")
            elem = self._parse_type()
            return (
                FixedArrayType(element=elem[0], length=length),
                elem[1],
                False,
            )

        # runar.TypeName or runar.Readonly(Type)
        if (self._current().kind == TOK_IDENT
                and self._current().value == "runar"
                and self._peek_ahead(1).kind == TOK_DOT):
            self._advance()  # 'runar'
            self._expect(TOK_DOT, ".")
            name = self._expect(TOK_IDENT, "type name").value

            if name == "Readonly" and self._current().kind == TOK_LPAREN:
                self._expect(TOK_LPAREN, "(")
                inner = self._parse_type()
                self._expect(TOK_RPAREN, ")")
                return (inner[0], inner[1], True)

            mapped = _map_zig_type(name)
            return (_make_type_node(mapped), name, False)

        # void keyword
        if self._current().kind == TOK_VOID:
            self._advance()
            return (PrimitiveType(name="void"), "void", False)

        # Bare identifier type
        if self._current().kind == TOK_IDENT:
            name = self._advance().value
            mapped = _map_zig_type(name)
            return (_make_type_node(mapped), name, False)

        fallback = self._advance()
        return (CustomType(name="unknown"), fallback.value or "unknown", False)

    def _parse_constructor(self, loc: SourceLocation, params: list[ParamNode]) -> MethodNode:
        """Parse a constructor body (``fn init(...)``)."""
        body: list[Statement] = [self._create_super_call(params)]
        found_return_struct = False

        self._expect(TOK_LBRACE, "{")

        while self._current().kind != TOK_RBRACE and self._current().kind != TOK_EOF:
            # return .{ .field = value, ... };
            if (self._current().kind == TOK_RETURN
                    and self._peek_ahead(1).kind == TOK_DOT
                    and self._peek_ahead(2).kind == TOK_LBRACE):
                self._advance()  # 'return'
                body.extend(self._parse_struct_return_assignments())
                found_return_struct = True
                self._match(TOK_SEMICOLON)
                continue

            stmt = self._parse_statement()
            if stmt is not None:
                body.append(stmt)

        self._expect(TOK_RBRACE, "}")

        # If there was no return struct, generate property assignments from params
        if not found_return_struct:
            for prop in self._properties:
                if any(p.name == prop.name for p in params):
                    body.append(self._create_property_assignment(
                        prop.name, Identifier(name=prop.name)
                    ))

        return MethodNode(
            name="constructor",
            params=params,
            body=body,
            visibility="public",
            source_location=loc,
        )

    def _parse_struct_return_assignments(self) -> list[Statement]:
        """Parse ``.{ .field = value, ... }`` and return assignment statements."""
        assignments: list[Statement] = []
        self._expect(TOK_DOT, ".")
        self._expect(TOK_LBRACE, "{")

        while self._current().kind != TOK_RBRACE and self._current().kind != TOK_EOF:
            if self._current().kind == TOK_DOT:
                self._advance()
            field = self._expect(TOK_IDENT, "field name").value
            self._expect(TOK_ASSIGN, "=")
            value = self._parse_expression()
            assignments.append(self._create_property_assignment(field, value))
            self._match(TOK_COMMA)

        self._expect(TOK_RBRACE, "}")
        return assignments

    # -----------------------------------------------------------------------
    # Statements
    # -----------------------------------------------------------------------

    def _parse_block_statements(self) -> list[Statement]:
        """Parse a ``{ ... }`` block and return a list of statements."""
        self._expect(TOK_LBRACE, "{")
        body: list[Statement] = []

        while self._current().kind != TOK_RBRACE and self._current().kind != TOK_EOF:
            stmt = self._parse_statement()
            if stmt is not None:
                # Merge preceding var decl with while loop if they share the
                # same loop variable (Zig pattern: var i = 0; while (...))
                if (isinstance(stmt, ForStmt)
                        and stmt.init is not None
                        and isinstance(stmt.init, VariableDeclStmt)
                        and stmt.init.name == "__while_no_init"
                        and body):
                    last = body[-1]
                    update_name = self._get_loop_update_target_name(stmt)
                    if (isinstance(last, VariableDeclStmt)
                            and update_name is not None
                            and update_name == last.name):
                        body.pop()
                        stmt.init = last
                body.append(stmt)

        self._expect(TOK_RBRACE, "}")
        return body

    def _get_loop_update_target_name(self, stmt: ForStmt) -> str | None:
        if isinstance(stmt.update, AssignmentStmt) and isinstance(stmt.update.target, Identifier):
            return stmt.update.target.name
        if isinstance(stmt.update, ExpressionStmt) and isinstance(stmt.update.expr, Identifier):
            return stmt.update.expr.name
        return None

    def _parse_statement(self) -> Statement | None:
        loc = self._loc()

        # return [expr];
        if self._current().kind == TOK_RETURN:
            self._advance()
            value: Expression | None = None
            if self._current().kind != TOK_SEMICOLON:
                value = self._parse_expression()
            self._match(TOK_SEMICOLON)
            return ReturnStmt(value=value, source_location=loc)

        # if (cond) { ... } [else { ... }]
        if self._current().kind == TOK_IF:
            return self._parse_if_statement()

        # const/var declaration
        if self._current().kind in (TOK_CONST, TOK_VAR):
            return self._parse_variable_decl()

        # _ = expr; (discard)
        if (self._current().kind == TOK_IDENT
                and self._current().value == "_"
                and self._peek_ahead(1).kind == TOK_ASSIGN):
            self._advance()  # '_'
            self._advance()  # '='
            self._parse_expression()
            self._match(TOK_SEMICOLON)
            return None

        # while loop
        if self._current().kind == TOK_WHILE:
            return self._parse_while_statement()

        # for loop (unsupported in Zig Runar)
        if self._current().kind == TOK_FOR:
            self._errors.append(
                f"{self._file}:{loc.line}:{loc.column}: "
                "Unsupported Zig 'for' syntax -- use 'while' loops instead"
            )
            self._skip_unsupported_block()
            return None

        # Expression-based statement (assignment, compound assignment, or expr)
        target = self._parse_expression()

        # Simple assignment: expr = value
        if self._current().kind == TOK_ASSIGN:
            self._advance()
            value_expr = self._parse_expression()
            self._match(TOK_SEMICOLON)
            return AssignmentStmt(target=target, value=value_expr, source_location=loc)

        # Compound assignment: expr += value, etc.
        compound_op = self._parse_compound_assignment_operator()
        if compound_op is not None:
            rhs = self._parse_expression()
            self._match(TOK_SEMICOLON)
            return AssignmentStmt(
                target=target,
                value=BinaryExpr(op=compound_op, left=target, right=rhs),
                source_location=loc,
            )

        self._match(TOK_SEMICOLON)
        return ExpressionStmt(expr=target, source_location=loc)

    def _parse_variable_decl(self) -> Statement:
        loc = self._loc()
        mutable = self._current().kind == TOK_VAR
        self._advance()  # 'const' or 'var'
        name = self._expect(TOK_IDENT, "variable name").value

        type_node: TypeNode | None = None
        if self._current().kind == TOK_COLON:
            self._advance()
            type_node = self._parse_type()[0]

        self._expect(TOK_ASSIGN, "=")
        init = self._parse_expression()
        self._match(TOK_SEMICOLON)

        return VariableDeclStmt(
            name=name,
            type=type_node,
            mutable=mutable,
            init=init,
            source_location=loc,
        )

    def _parse_if_statement(self) -> Statement:
        loc = self._loc()
        self._expect(TOK_IF, "if")

        if self._current().kind == TOK_LPAREN:
            self._advance()
        condition = self._parse_expression()
        if self._current().kind == TOK_RPAREN:
            self._advance()

        then_branch = self._parse_block_statements()
        else_branch: list[Statement] = []

        if self._current().kind == TOK_ELSE:
            self._advance()
            if self._current().kind == TOK_IF:
                else_branch = [self._parse_if_statement()]
            else:
                else_branch = self._parse_block_statements()

        return IfStmt(
            condition=condition,
            then=then_branch,
            else_=else_branch,
            source_location=loc,
        )

    def _parse_while_statement(self) -> Statement:
        """Parse Zig while loop: ``while (cond) : (update_expr) { body }``."""
        loc = self._loc()
        self._expect(TOK_WHILE, "while")

        # Condition
        if self._current().kind == TOK_LPAREN:
            self._advance()
        condition = self._parse_expression()
        if self._current().kind == TOK_RPAREN:
            self._advance()

        # Continue expression: : (i += 1)
        update: Statement
        if self._current().kind == TOK_COLON:
            self._advance()
            if self._current().kind == TOK_LPAREN:
                self._advance()
            update_target = self._parse_expression()
            compound_op = self._parse_compound_assignment_operator()
            if compound_op is not None:
                rhs = self._parse_expression()
                update = AssignmentStmt(
                    target=update_target,
                    value=BinaryExpr(op=compound_op, left=update_target, right=rhs),
                    source_location=loc,
                )
            else:
                update = ExpressionStmt(expr=update_target, source_location=loc)
            if self._current().kind == TOK_RPAREN:
                self._advance()
        else:
            update = ExpressionStmt(
                expr=BigIntLiteral(value=0),
                source_location=loc,
            )

        body = self._parse_block_statements()

        # Emit a ForStmt with a placeholder init that may be patched
        # by _parse_block_statements if a preceding var decl matches.
        return ForStmt(
            init=VariableDeclStmt(
                name="__while_no_init",
                mutable=True,
                init=BigIntLiteral(value=0),
                source_location=loc,
            ),
            condition=condition,
            update=update,
            body=body,
            source_location=loc,
        )

    def _parse_compound_assignment_operator(self) -> str | None:
        kind = self._current().kind
        if kind in _COMPOUND_OPS:
            self._advance()
            return _COMPOUND_OPS[kind]
        return None

    def _skip_unsupported_block(self) -> None:
        while self._current().kind not in (TOK_LBRACE, TOK_SEMICOLON, TOK_EOF):
            self._advance()

        if self._current().kind == TOK_SEMICOLON:
            self._advance()
            return

        if self._current().kind != TOK_LBRACE:
            return

        depth = 0
        while self._current().kind != TOK_EOF:
            if self._current().kind == TOK_LBRACE:
                depth += 1
            if self._current().kind == TOK_RBRACE:
                depth -= 1
                self._advance()
                if depth <= 0:
                    break
                continue
            self._advance()

    # -----------------------------------------------------------------------
    # Expressions (precedence climbing)
    # -----------------------------------------------------------------------

    def _parse_expression(self) -> Expression:
        return self._parse_ternary()

    def _parse_ternary(self) -> Expression:
        # Zig does not have ternary `? :` but the TS reference parser still
        # supports it for completeness. We replicate the same behavior.
        expr = self._parse_or()
        return expr

    def _parse_or(self) -> Expression:
        left = self._parse_and()
        while self._current().kind == TOK_PIPEPIPE:
            self._advance()
            right = self._parse_and()
            left = BinaryExpr(op="||", left=left, right=right)
        return left

    def _parse_and(self) -> Expression:
        left = self._parse_bitwise_or()
        while self._current().kind == TOK_AMPAMP:
            self._advance()
            right = self._parse_bitwise_or()
            left = BinaryExpr(op="&&", left=left, right=right)
        return left

    def _parse_bitwise_or(self) -> Expression:
        left = self._parse_bitwise_xor()
        while self._current().kind == TOK_PIPE:
            self._advance()
            right = self._parse_bitwise_xor()
            left = BinaryExpr(op="|", left=left, right=right)
        return left

    def _parse_bitwise_xor(self) -> Expression:
        left = self._parse_bitwise_and()
        while self._current().kind == TOK_CARET:
            self._advance()
            right = self._parse_bitwise_and()
            left = BinaryExpr(op="^", left=left, right=right)
        return left

    def _parse_bitwise_and(self) -> Expression:
        left = self._parse_equality()
        while self._current().kind == TOK_AMP:
            self._advance()
            right = self._parse_equality()
            left = BinaryExpr(op="&", left=left, right=right)
        return left

    def _parse_equality(self) -> Expression:
        left = self._parse_comparison()
        while True:
            kind = self._current().kind
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
            kind = self._current().kind
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
            kind = self._current().kind
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
            kind = self._current().kind
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
            kind = self._current().kind
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
        kind = self._current().kind
        if kind == TOK_BANG:
            self._advance()
            return UnaryExpr(op="!", operand=self._parse_unary())
        if kind == TOK_MINUS:
            self._advance()
            return UnaryExpr(op="-", operand=self._parse_unary())
        if kind == TOK_TILDE:
            self._advance()
            return UnaryExpr(op="~", operand=self._parse_unary())

        expr = self._parse_primary()
        return self._parse_postfix_chain(expr)

    def _parse_primary(self) -> Expression:
        tok = self._current()

        # Zig anonymous struct literal: .{ elem, ... }
        if tok.kind == TOK_DOT and self._peek_ahead(1).kind == TOK_LBRACE:
            self._advance()  # '.'
            self._advance()  # '{'
            elements: list[Expression] = []
            while self._current().kind != TOK_RBRACE and self._current().kind != TOK_EOF:
                elements.append(self._parse_expression())
                self._match(TOK_COMMA)
            self._expect(TOK_RBRACE, "}")
            return ArrayLiteralExpr(elements=elements)

        # Number literal
        if tok.kind == TOK_NUMBER:
            self._advance()
            return BigIntLiteral(value=int(tok.value, 0))

        # String literal → ByteString
        if tok.kind == TOK_STRING:
            self._advance()
            return ByteStringLiteral(value=tok.value)

        # Boolean literals
        if tok.kind == TOK_TRUE:
            self._advance()
            return BoolLiteral(value=True)
        if tok.kind == TOK_FALSE:
            self._advance()
            return BoolLiteral(value=False)

        # Parenthesized expression
        if tok.kind == TOK_LPAREN:
            self._advance()
            expr = self._parse_expression()
            self._expect(TOK_RPAREN, ")")
            return expr

        # Array literal: [elem, ...]
        if tok.kind == TOK_LBRACKET:
            self._advance()
            elements = []
            while self._current().kind != TOK_RBRACKET and self._current().kind != TOK_EOF:
                elements.append(self._parse_expression())
                self._match(TOK_COMMA)
            self._expect(TOK_RBRACKET, "]")
            return ArrayLiteralExpr(elements=elements)

        # Zig @builtins: @divTrunc, @mod, @shlExact, @shrExact, @intCast, etc.
        if tok.kind == TOK_AT:
            self._advance()
            builtin_name = self._expect(TOK_IDENT, "builtin name").value

            if builtin_name in ("divTrunc", "mod", "shlExact", "shrExact"):
                self._expect(TOK_LPAREN, "(")
                left = self._parse_expression()
                self._expect(TOK_COMMA, ",")
                right = self._parse_expression()
                self._expect(TOK_RPAREN, ")")
                op_map = {
                    "divTrunc": "/",
                    "mod": "%",
                    "shlExact": "<<",
                    "shrExact": ">>",
                }
                return BinaryExpr(op=op_map[builtin_name], left=left, right=right)

            if builtin_name in ("intCast", "truncate", "as"):
                self._expect(TOK_LPAREN, "(")
                if builtin_name == "as":
                    self._parse_type()  # skip type arg
                    self._expect(TOK_COMMA, ",")
                inner = self._parse_expression()
                self._expect(TOK_RPAREN, ")")
                return inner

            if builtin_name == "import":
                self._expect(TOK_LPAREN, "(")
                self._parse_expression()
                self._expect(TOK_RPAREN, ")")
                return Identifier(name="__import")

            if builtin_name == "embedFile":
                self._expect(TOK_LPAREN, "(")
                arg = self._parse_expression()
                self._expect(TOK_RPAREN, ")")
                return arg

            # Unknown @builtin — try to parse call args
            if self._current().kind == TOK_LPAREN:
                self._advance()
                args: list[Expression] = []
                args.append(self._parse_expression())
                while self._current().kind == TOK_COMMA:
                    self._advance()
                    args.append(self._parse_expression())
                self._expect(TOK_RPAREN, ")")
                self._errors.append(
                    f"{self._file}:{tok.line}:{tok.col}: "
                    f"Unsupported Zig builtin '@{builtin_name}'"
                )
                return CallExpr(
                    callee=Identifier(name=builtin_name),
                    args=args,
                )

            self._errors.append(
                f"{self._file}:{tok.line}:{tok.col}: "
                f"Unsupported Zig builtin '@{builtin_name}'"
            )
            return Identifier(name=builtin_name)

        # Identifier (including `runar.builtin` stripping)
        if tok.kind == TOK_IDENT:
            self._advance()

            # runar.builtin → bare builtin identifier
            if tok.value == "runar" and self._current().kind == TOK_DOT:
                self._advance()  # '.'
                builtin = self._expect(TOK_IDENT, "builtin name").value

                # runar.bytesEq(a, b) → BinaryExpr(===)
                if builtin == "bytesEq" and self._current().kind == TOK_LPAREN:
                    self._advance()
                    left = self._parse_expression()
                    self._expect(TOK_COMMA, ",")
                    right = self._parse_expression()
                    self._expect(TOK_RPAREN, ")")
                    return BinaryExpr(op="===", left=left, right=right)

                return Identifier(name=builtin)

            return Identifier(name=tok.value)

        # Fallback
        self._advance()
        return Identifier(name=tok.value or "unknown")

    def _parse_postfix_chain(self, expr: Expression) -> Expression:
        """Parse postfix operations (call, member access, index access)."""
        while True:
            # Function/method call: expr(args...)
            if self._current().kind == TOK_LPAREN:
                self._advance()
                args: list[Expression] = []
                while self._current().kind != TOK_RPAREN and self._current().kind != TOK_EOF:
                    args.append(self._parse_expression())
                    self._match(TOK_COMMA)
                self._expect(TOK_RPAREN, ")")
                expr = CallExpr(callee=expr, args=args)
                continue

            # Member access: expr.prop
            if self._current().kind == TOK_DOT:
                self._advance()
                prop = self._current().value
                self._advance()

                # self.property → PropertyAccessExpr
                if isinstance(expr, Identifier) and expr.name in self._self_names:
                    expr = PropertyAccessExpr(property=prop)
                elif (isinstance(expr, Identifier)
                      and expr.name in self._stateful_context_names
                      and prop in ("txPreimage", "getStateScript", "addOutput", "addRawOutput")):
                    expr = PropertyAccessExpr(property=prop)
                else:
                    expr = MemberExpr(object=expr, property=prop)
                continue

            # Index access: expr[index]
            if self._current().kind == TOK_LBRACKET:
                self._advance()
                index = self._parse_expression()
                self._expect(TOK_RBRACKET, "]")
                expr = IndexAccessExpr(object=expr, index=index)
                continue

            break

        return expr

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _create_super_call(self, params: list[ParamNode]) -> Statement:
        loc = SourceLocation(file=self._file, line=1, column=1)
        return ExpressionStmt(
            expr=CallExpr(
                callee=Identifier(name="super"),
                args=[Identifier(name=p.name) for p in params],
            ),
            source_location=loc,
        )

    def _create_property_assignment(self, name: str, value: Expression) -> Statement:
        loc = SourceLocation(file=self._file, line=1, column=1)
        return AssignmentStmt(
            target=PropertyAccessExpr(property=name),
            value=value,
            source_location=loc,
        )

    def _create_fallback_constructor(self) -> MethodNode:
        """Generate a default constructor from property declarations."""
        required_props = [p for p in self._properties if p.initializer is None]
        params = [ParamNode(name=p.name, type=p.type) for p in required_props]
        loc = SourceLocation(file=self._file, line=1, column=1)

        body: list[Statement] = [self._create_super_call(params)]
        body.extend(
            self._create_property_assignment(p.name, Identifier(name=p.name))
            for p in required_props
        )

        return MethodNode(
            name="constructor",
            params=params,
            body=body,
            visibility="public",
            source_location=loc,
        )


# ---------------------------------------------------------------------------
# Mutation detection helpers
# ---------------------------------------------------------------------------

def _collect_mutated_properties(body, out):
    """Walk a list of statements, adding the names of any properties that
    are assigned or incremented/decremented to ``out`` (a set[str])."""
    for stmt in body or []:
        _collect_mutated_in_stmt(stmt, out)


def _collect_mutated_in_stmt(stmt, out):
    if isinstance(stmt, AssignmentStmt):
        if isinstance(stmt.target, PropertyAccessExpr):
            out.add(stmt.target.property)
        _collect_mutated_in_expr(stmt.target, out)
        _collect_mutated_in_expr(stmt.value, out)
    elif isinstance(stmt, VariableDeclStmt):
        _collect_mutated_in_expr(stmt.init, out)
    elif isinstance(stmt, ExpressionStmt):
        _collect_mutated_in_expr(stmt.expr, out)
    elif isinstance(stmt, ReturnStmt):
        _collect_mutated_in_expr(stmt.value, out)
    elif isinstance(stmt, IfStmt):
        _collect_mutated_in_expr(stmt.condition, out)
        _collect_mutated_properties(stmt.then, out)
        _collect_mutated_properties(stmt.else_, out)
    elif isinstance(stmt, ForStmt):
        if stmt.init is not None:
            _collect_mutated_in_expr(stmt.init.init, out)
        _collect_mutated_in_expr(stmt.condition, out)
        _collect_mutated_in_stmt(stmt.update, out)
        _collect_mutated_properties(stmt.body, out)


def _collect_mutated_in_expr(expr, out):
    if expr is None:
        return
    if isinstance(expr, BinaryExpr):
        _collect_mutated_in_expr(expr.left, out)
        _collect_mutated_in_expr(expr.right, out)
    elif isinstance(expr, UnaryExpr):
        _collect_mutated_in_expr(expr.operand, out)
    elif isinstance(expr, CallExpr):
        _collect_mutated_in_expr(expr.callee, out)
        for a in expr.args:
            _collect_mutated_in_expr(a, out)
    elif isinstance(expr, MemberExpr):
        _collect_mutated_in_expr(expr.object, out)
    elif isinstance(expr, TernaryExpr):
        _collect_mutated_in_expr(expr.condition, out)
        _collect_mutated_in_expr(expr.consequent, out)
        _collect_mutated_in_expr(expr.alternate, out)
    elif isinstance(expr, IndexAccessExpr):
        _collect_mutated_in_expr(expr.object, out)
        _collect_mutated_in_expr(expr.index, out)
    elif isinstance(expr, IncrementExpr) or isinstance(expr, DecrementExpr):
        if isinstance(expr.operand, PropertyAccessExpr):
            out.add(expr.operand.property)
        _collect_mutated_in_expr(expr.operand, out)
    elif isinstance(expr, ArrayLiteralExpr):
        for e in expr.elements:
            _collect_mutated_in_expr(e, out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_zig(source: str, file_name: str = "Contract.runar.zig") -> ParseResult:
    """Parse a Zig-format Runar contract (.runar.zig) and return a ParseResult."""
    tokens = _tokenize(source)
    parser = _ZigParser(tokens, file_name)
    return parser.parse()
