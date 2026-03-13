"""TypeScript format parser (.runar.ts) for the Runar compiler.

Ported from compilers/go/frontend/parser.go.
Hand-written tokenizer + recursive descent parser for TypeScript-like syntax.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
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
TOK_LBRACE = 4
TOK_RBRACE = 5
TOK_LPAREN = 6
TOK_RPAREN = 7
TOK_LBRACKET = 8
TOK_RBRACKET = 9
TOK_SEMICOLON = 10
TOK_COMMA = 11
TOK_DOT = 12
TOK_COLON = 13
TOK_ASSIGN = 14
TOK_EQEQ = 15       # ==
TOK_NOTEQ = 16      # !=
TOK_LT = 17
TOK_LTEQ = 18
TOK_GT = 19
TOK_GTEQ = 20
TOK_PLUS = 21
TOK_MINUS = 22
TOK_STAR = 23
TOK_SLASH = 24
TOK_PERCENT = 25
TOK_BANG = 26
TOK_TILDE = 27
TOK_AMP = 28
TOK_PIPE = 29
TOK_CARET = 30
TOK_AMPAMP = 31      # &&
TOK_PIPEPIPE = 32    # ||
TOK_PLUSEQ = 33      # +=
TOK_MINUSEQ = 34     # -=
TOK_STAREQ = 35      # *=
TOK_SLASHEQ = 36     # /=
TOK_PERCENTEQ = 37   # %=
TOK_QUESTION = 38     # ?
TOK_PLUSPLUS = 39     # ++
TOK_MINUSMINUS = 40  # --
TOK_EQEQEQ = 41     # ===
TOK_NOTEQEQ = 42    # !==
TOK_LSHIFT = 43      # <<
TOK_RSHIFT = 44      # >>
TOK_ARROW = 45        # =>


class Token:
    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind: int, value: str, line: int, col: int):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# Type mappings
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, str] = {
    "bigint": "bigint",
    "boolean": "boolean",
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
    "void": "void",
}


def _parse_ts_type_name(name: str) -> TypeNode:
    if name in _TYPE_MAP:
        return PrimitiveType(name=_TYPE_MAP[name])
    if is_primitive_type(name):
        return PrimitiveType(name=name)
    if name == "number":
        return PrimitiveType(name="bigint")
    return CustomType(name=name)


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_" or ch == "$"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_" or ch == "$"


def _is_hex_digit(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    line = 1
    col = 0
    i = 0
    n = len(source)

    while i < n:
        ch = source[i]

        # Newlines
        if ch == "\n":
            i += 1
            line += 1
            col = 0
            continue
        if ch == "\r":
            i += 1
            if i < n and source[i] == "\n":
                i += 1
            line += 1
            col = 0
            continue

        # Whitespace
        if ch in (" ", "\t"):
            i += 1
            col += 1
            continue

        # Single-line comment //
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n" and source[i] != "\r":
                i += 1
            continue

        # Multi-line comment /* ... */
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            i += 2
            col += 2
            while i + 1 < n:
                if source[i] == "*" and source[i + 1] == "/":
                    i += 2
                    col += 2
                    break
                if source[i] == "\n":
                    line += 1
                    col = 0
                else:
                    col += 1
                i += 1
            else:
                if i < n:
                    i += 1
            continue

        start_col = col

        # Template string literals (backticks)
        if ch == "`":
            i += 1
            col += 1
            start = i
            while i < n and source[i] != "`":
                if source[i] == "\\":
                    i += 1
                    col += 1
                if i < n:
                    if source[i] == "\n":
                        line += 1
                        col = 0
                    else:
                        col += 1
                    i += 1
            val = source[start:i]
            if i < n:
                i += 1
                col += 1
            tokens.append(Token(TOK_STRING, val, line, start_col))
            continue

        # String literals: single or double quotes
        if ch in ("'", '"'):
            quote = ch
            i += 1
            col += 1
            start = i
            while i < n and source[i] != quote:
                if source[i] == "\\":
                    i += 1
                    col += 1
                if i < n:
                    i += 1
                    col += 1
            val = source[start:i]
            if i < n:
                i += 1
                col += 1
            tokens.append(Token(TOK_STRING, val, line, start_col))
            continue

        # Numbers (including BigInt suffix 'n')
        if ch.isdigit():
            start = i
            if ch == "0" and i + 1 < n and source[i + 1] in ("x", "X"):
                i += 2
                col += 2
                while i < n and _is_hex_digit(source[i]):
                    i += 1
                    col += 1
            elif ch == "0" and i + 1 < n and source[i + 1] in ("o", "O"):
                i += 2
                col += 2
                while i < n and source[i] in "01234567":
                    i += 1
                    col += 1
            elif ch == "0" and i + 1 < n and source[i + 1] in ("b", "B"):
                i += 2
                col += 2
                while i < n and source[i] in "01":
                    i += 1
                    col += 1
            else:
                while i < n and (source[i].isdigit() or source[i] == "_"):
                    i += 1
                    col += 1
            num_str = source[start:i].replace("_", "")
            # Strip trailing BigInt suffix 'n'
            if i < n and source[i] == "n":
                i += 1
                col += 1
            tokens.append(Token(TOK_NUMBER, num_str, line, start_col))
            continue

        # Identifiers and keywords
        if _is_ident_start(ch):
            start = i
            while i < n and _is_ident_part(source[i]):
                i += 1
                col += 1
            word = source[start:i]
            tokens.append(Token(TOK_IDENT, word, line, start_col))
            continue

        # Three-character operators
        if i + 2 < n:
            three = source[i:i + 3]
            three_kind = {
                "===": TOK_EQEQEQ,
                "!==": TOK_NOTEQEQ,
            }.get(three)
            if three_kind is not None:
                tokens.append(Token(three_kind, three, line, start_col))
                i += 3
                col += 3
                continue

        # Two-character operators
        if i + 1 < n:
            two = source[i:i + 2]
            two_kind = {
                "==": TOK_EQEQ,
                "!=": TOK_NOTEQ,
                "<=": TOK_LTEQ,
                ">=": TOK_GTEQ,
                "+=": TOK_PLUSEQ,
                "-=": TOK_MINUSEQ,
                "*=": TOK_STAREQ,
                "/=": TOK_SLASHEQ,
                "%=": TOK_PERCENTEQ,
                "&&": TOK_AMPAMP,
                "||": TOK_PIPEPIPE,
                "++": TOK_PLUSPLUS,
                "--": TOK_MINUSMINUS,
                "<<": TOK_LSHIFT,
                ">>": TOK_RSHIFT,
                "=>": TOK_ARROW,
            }.get(two)
            if two_kind is not None:
                tokens.append(Token(two_kind, two, line, start_col))
                i += 2
                col += 2
                continue

        # Single-character operators
        one_map = {
            "(": TOK_LPAREN,
            ")": TOK_RPAREN,
            "[": TOK_LBRACKET,
            "]": TOK_RBRACKET,
            "{": TOK_LBRACE,
            "}": TOK_RBRACE,
            ",": TOK_COMMA,
            ".": TOK_DOT,
            ":": TOK_COLON,
            ";": TOK_SEMICOLON,
            "=": TOK_ASSIGN,
            "<": TOK_LT,
            ">": TOK_GT,
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
        }
        one_kind = one_map.get(ch)
        if one_kind is not None:
            tokens.append(Token(one_kind, ch, line, start_col))
            i += 1
            col += 1
            continue

        # Skip unknown characters
        i += 1
        col += 1

    tokens.append(Token(TOK_EOF, "", line, col))
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _TsParser:
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.tokens: list[Token] = []
        self.pos = 0
        self.errors: list[str] = []

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    # -- Token helpers -------------------------------------------------------

    def peek(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return Token(TOK_EOF, "", 0, 0)

    def advance(self) -> Token:
        tok = self.peek()
        if self.pos < len(self.tokens):
            self.pos += 1
        return tok

    def expect(self, kind: int) -> Token:
        tok = self.advance()
        if tok.kind != kind:
            self.add_error(
                f"line {tok.line}: expected token kind {kind}, got {tok.kind} ({tok.value!r})"
            )
        return tok

    def expect_ident(self, value: str) -> Token:
        tok = self.advance()
        if tok.kind != TOK_IDENT or tok.value != value:
            self.add_error(f"line {tok.line}: expected '{value}', got {tok.value!r}")
        return tok

    def check(self, kind: int) -> bool:
        return self.peek().kind == kind

    def check_ident(self, value: str) -> bool:
        tok = self.peek()
        return tok.kind == TOK_IDENT and tok.value == value

    def match(self, kind: int) -> bool:
        if self.check(kind):
            self.advance()
            return True
        return False

    def match_ident(self, value: str) -> bool:
        if self.check_ident(value):
            self.advance()
            return True
        return False

    def loc(self) -> SourceLocation:
        tok = self.peek()
        return SourceLocation(file=self.file_name, line=tok.line, column=tok.col)

    def skip_semicolons(self) -> None:
        while self.check(TOK_SEMICOLON):
            self.advance()

    # -- Top-level parsing ---------------------------------------------------

    def parse_contract(self) -> ContractNode:
        # Skip import statements, export keywords, and other top-level noise
        # until we find a class declaration
        while not self.check(TOK_EOF):
            # Skip import statements
            if self.check_ident("import"):
                self._skip_import()
                continue

            # export class ...
            if self.check_ident("export"):
                self.advance()
                if self.check_ident("class"):
                    return self._parse_class()
                # export default class, etc.
                if self.check_ident("default"):
                    self.advance()
                    if self.check_ident("class"):
                        return self._parse_class()
                # Other export statements — skip to next semicolon or brace
                self._skip_statement()
                continue

            # class ...
            if self.check_ident("class"):
                return self._parse_class()

            # Skip anything else at top level
            self._skip_statement()

        raise ValueError("no class extending SmartContract or StatefulSmartContract found")

    def _skip_import(self) -> None:
        """Skip an import statement."""
        # import ... from '...' ;
        # import type ... from '...' ;
        # First consume the 'import' keyword itself
        self.advance()
        while not self.check(TOK_EOF):
            tok = self.peek()
            if tok.kind == TOK_SEMICOLON:
                self.advance()
                return
            # If we hit a newline-ish boundary without semicolon, some TS files
            # omit semicolons. Detect end of import by seeing next top-level keyword.
            if tok.kind == TOK_IDENT and tok.value in ("import", "export", "class"):
                return
            self.advance()

    def _skip_statement(self) -> None:
        """Skip a statement we don't care about."""
        depth = 0
        while not self.check(TOK_EOF):
            tok = self.peek()
            if tok.kind == TOK_LBRACE:
                depth += 1
                self.advance()
            elif tok.kind == TOK_RBRACE:
                if depth <= 0:
                    return
                depth -= 1
                self.advance()
                if depth == 0:
                    return
            elif tok.kind == TOK_SEMICOLON and depth == 0:
                self.advance()
                return
            else:
                self.advance()

    def _parse_class(self) -> ContractNode:
        """Parse: class Name extends SmartContract { ... }"""
        self.expect_ident("class")

        name_tok = self.expect(TOK_IDENT)
        contract_name = name_tok.value

        # extends clause
        parent_class = "SmartContract"
        if self.match_ident("extends"):
            parent_tok = self.expect(TOK_IDENT)
            parent_class = parent_tok.value

        if parent_class not in ("SmartContract", "StatefulSmartContract"):
            raise ValueError(
                f"no class extending SmartContract or StatefulSmartContract found"
            )

        self.expect(TOK_LBRACE)

        properties: list[PropertyNode] = []
        constructor: MethodNode | None = None
        methods: list[MethodNode] = []

        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            self.skip_semicolons()
            if self.check(TOK_RBRACE) or self.check(TOK_EOF):
                break

            member = self._parse_class_member(parent_class)
            if member is None:
                continue

            if isinstance(member, PropertyNode):
                properties.append(member)
            elif isinstance(member, MethodNode):
                if member.name == "constructor":
                    if constructor is not None:
                        self.add_error("duplicate constructor")
                    constructor = member
                else:
                    methods.append(member)

        self.expect(TOK_RBRACE)

        if constructor is None:
            self.add_error("contract must have a constructor")
            constructor = MethodNode(
                name="constructor",
                params=[],
                body=[],
                visibility="public",
                source_location=SourceLocation(file=self.file_name, line=1, column=0),
            )

        return ContractNode(
            name=contract_name,
            parent_class=parent_class,
            properties=properties,
            constructor=constructor,
            methods=methods,
            source_file=self.file_name,
        )

    # -- Class members -------------------------------------------------------

    def _parse_class_member(self, parent_class: str) -> PropertyNode | MethodNode | None:
        """Parse a property or method from inside a class body."""
        location = self.loc()

        # Collect modifiers: public, private, readonly
        visibility = "private"
        is_readonly = False

        while True:
            if self.check_ident("public"):
                visibility = "public"
                self.advance()
            elif self.check_ident("private"):
                visibility = "private"
                self.advance()
            elif self.check_ident("protected"):
                visibility = "private"
                self.advance()
            elif self.check_ident("readonly"):
                is_readonly = True
                self.advance()
            else:
                break

        # constructor(...) { ... }
        if self.check_ident("constructor"):
            return self._parse_constructor_method(location)

        # name followed by ( means method
        # name followed by : or ; means property
        if self.peek().kind != TOK_IDENT:
            # Skip unknown token
            self.advance()
            return None

        name_tok = self.advance()
        member_name = name_tok.value

        # Method: name(...)
        if self.check(TOK_LPAREN):
            return self._parse_method(member_name, visibility, location)

        # Property: name: Type (possibly with ; at end)
        if self.check(TOK_COLON):
            self.advance()  # consume :
            type_node = self._parse_type()

            # Parse optional initializer: = value
            initializer = None
            if self.check(TOK_ASSIGN):
                self.advance()  # consume '='
                initializer = self._parse_expression()

            self.skip_semicolons()

            return PropertyNode(
                name=member_name,
                type=type_node,
                readonly=is_readonly,
                initializer=initializer,
                source_location=location,
            )

        # Property with no type annotation (just name;)
        if self.check(TOK_SEMICOLON):
            self.advance()
            self.add_error(
                f"property '{member_name}' must have an explicit type annotation"
            )
            return PropertyNode(
                name=member_name,
                type=CustomType(name="unknown"),
                readonly=is_readonly,
                source_location=location,
            )

        # Skip unknown
        self._skip_to_next_member()
        return None

    def _skip_to_next_member(self) -> None:
        """Skip tokens until we find something that looks like the start of
        a new class member or the closing brace."""
        depth = 0
        while not self.check(TOK_EOF):
            tok = self.peek()
            if tok.kind == TOK_LBRACE:
                depth += 1
                self.advance()
            elif tok.kind == TOK_RBRACE:
                if depth <= 0:
                    return
                depth -= 1
                self.advance()
            elif tok.kind == TOK_SEMICOLON and depth == 0:
                self.advance()
                return
            else:
                self.advance()

    # -- Constructor ---------------------------------------------------------

    def _parse_constructor_method(self, location: SourceLocation) -> MethodNode:
        self.expect_ident("constructor")
        params = self._parse_params()

        # Skip optional return type annotation
        if self.check(TOK_COLON):
            self.advance()
            self._parse_type()

        body = self._parse_block()

        return MethodNode(
            name="constructor",
            params=params,
            body=body,
            visibility="public",
            source_location=location,
        )

    # -- Methods -------------------------------------------------------------

    def _parse_method(
        self, name: str, visibility: str, location: SourceLocation
    ) -> MethodNode:
        params = self._parse_params()

        # Skip optional return type annotation
        if self.check(TOK_COLON):
            self.advance()
            self._parse_type()

        body = self._parse_block()

        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility=visibility,
            source_location=location,
        )

    # -- Parameters ----------------------------------------------------------

    def _parse_params(self) -> list[ParamNode]:
        self.expect(TOK_LPAREN)
        params: list[ParamNode] = []

        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            # Skip modifiers in constructor params (public, private, readonly)
            while self.peek().kind == TOK_IDENT and self.peek().value in (
                "public", "private", "protected", "readonly",
            ):
                self.advance()

            name_tok = self.expect(TOK_IDENT)
            param_name = name_tok.value

            # Optional ? for optional params
            self.match(TOK_QUESTION)

            typ: TypeNode | None = None
            if self.match(TOK_COLON):
                typ = self._parse_type()

            if typ is None:
                self.add_error(
                    f"parameter '{param_name}' must have an explicit type annotation"
                )
                typ = CustomType(name="unknown")

            params.append(ParamNode(name=param_name, type=typ))

            if not self.match(TOK_COMMA):
                break

        self.expect(TOK_RPAREN)
        return params

    # -- Type parsing --------------------------------------------------------

    def _parse_type(self) -> TypeNode:
        tok = self.peek()

        if tok.kind != TOK_IDENT:
            self.add_error(f"line {tok.line}: expected type name, got {tok.value!r}")
            self.advance()
            return CustomType(name="unknown")

        name = tok.value
        self.advance()

        # FixedArray<T, N>
        if name == "FixedArray":
            if self.match(TOK_LT):
                elem_type = self._parse_type()
                self.expect(TOK_COMMA)
                size_tok = self.expect(TOK_NUMBER)
                try:
                    size = int(size_tok.value)
                except ValueError:
                    size = 0
                    self.add_error(
                        f"line {size_tok.line}: FixedArray size must be a non-negative integer literal"
                    )
                self.expect(TOK_GT)
                return FixedArrayType(element=elem_type, length=size)
            return CustomType(name=name)

        # Generic types we don't support — skip type args
        if self.check(TOK_LT):
            self._skip_type_args()

        # Array type: bigint[] etc.
        if self.check(TOK_LBRACKET) and self._peek_next_kind() == TOK_RBRACKET:
            self.advance()  # [
            self.advance()  # ]
            # Treat T[] as unknown, we only support FixedArray
            self.add_error(f"use FixedArray<T, N> instead of {name}[]")

        return _parse_ts_type_name(name)

    def _skip_type_args(self) -> None:
        """Skip a <...> type argument list."""
        if not self.match(TOK_LT):
            return
        depth = 1
        while depth > 0 and not self.check(TOK_EOF):
            if self.check(TOK_LT):
                depth += 1
            elif self.check(TOK_GT):
                depth -= 1
            self.advance()

    def _peek_next_kind(self) -> int:
        """Peek at the token after the current one."""
        if self.pos + 1 < len(self.tokens):
            return self.tokens[self.pos + 1].kind
        return TOK_EOF

    # -- Block parsing -------------------------------------------------------

    def _parse_block(self) -> list[Statement]:
        self.expect(TOK_LBRACE)
        stmts: list[Statement] = []

        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            self.skip_semicolons()
            if self.check(TOK_RBRACE) or self.check(TOK_EOF):
                break
            stmt = self._parse_statement()
            if stmt is not None:
                stmts.append(stmt)

        self.expect(TOK_RBRACE)
        return stmts

    # -- Statement parsing ---------------------------------------------------

    def _parse_statement(self) -> Statement | None:
        location = self.loc()
        tok = self.peek()

        # Variable declarations: const, let
        if tok.kind == TOK_IDENT and tok.value in ("const", "let"):
            return self._parse_variable_decl(location)

        # If statement
        if tok.kind == TOK_IDENT and tok.value == "if":
            return self._parse_if(location)

        # For statement
        if tok.kind == TOK_IDENT and tok.value == "for":
            return self._parse_for(location)

        # Return statement
        if tok.kind == TOK_IDENT and tok.value == "return":
            return self._parse_return(location)

        # Expression statement (including assignments and calls)
        return self._parse_expression_statement(location)

    def _parse_variable_decl(self, loc: SourceLocation) -> Statement:
        keyword = self.advance()  # const or let
        is_mutable = keyword.value == "let"

        name_tok = self.expect(TOK_IDENT)
        var_name = name_tok.value

        type_node: TypeNode | None = None
        if self.match(TOK_COLON):
            type_node = self._parse_type()

        init: Expression | None = None
        if self.match(TOK_ASSIGN):
            init = self._parse_expression()

        if init is None:
            init = BigIntLiteral(value=0)

        self.skip_semicolons()

        return VariableDeclStmt(
            name=var_name,
            type=type_node,
            mutable=is_mutable,
            init=init,
            source_location=loc,
        )

    def _parse_if(self, loc: SourceLocation) -> Statement:
        self.expect_ident("if")
        self.expect(TOK_LPAREN)
        condition = self._parse_expression()
        self.expect(TOK_RPAREN)

        then_block = self._parse_block_or_statement()

        else_block: list[Statement] = []
        if self.match_ident("else"):
            if self.check_ident("if"):
                # else if ...
                elif_loc = self.loc()
                elif_stmt = self._parse_if(elif_loc)
                else_block = [elif_stmt]
            else:
                else_block = self._parse_block_or_statement()

        return IfStmt(
            condition=condition,
            then=then_block,
            else_=else_block,
            source_location=loc,
        )

    def _parse_block_or_statement(self) -> list[Statement]:
        """Parse either a braced block or a single statement."""
        if self.check(TOK_LBRACE):
            return self._parse_block()
        stmt = self._parse_statement()
        if stmt is not None:
            return [stmt]
        return []

    def _parse_for(self, loc: SourceLocation) -> Statement:
        self.expect_ident("for")
        self.expect(TOK_LPAREN)

        # Initializer: let i: bigint = 0n  or  let i = 0n
        init_loc = self.loc()
        init_stmt: VariableDeclStmt
        if self.check_ident("let") or self.check_ident("const"):
            stmt = self._parse_variable_decl(init_loc)
            if isinstance(stmt, VariableDeclStmt):
                init_stmt = stmt
            else:
                init_stmt = VariableDeclStmt(
                    name="_i",
                    mutable=True,
                    init=BigIntLiteral(value=0),
                    source_location=init_loc,
                )
        else:
            # Expression initializer — not standard for Runar for-loops
            init_stmt = VariableDeclStmt(
                name="_i",
                mutable=True,
                init=BigIntLiteral(value=0),
                source_location=init_loc,
            )
            # Skip to the semicolon
            while not self.check(TOK_SEMICOLON) and not self.check(TOK_EOF):
                self.advance()

        # The variable_decl already consumed the semicolon if it was there,
        # but we need to make sure we're past it
        self.match(TOK_SEMICOLON)

        # Condition
        condition: Expression
        if self.check(TOK_SEMICOLON):
            condition = BoolLiteral(value=False)
        else:
            condition = self._parse_expression()
        self.expect(TOK_SEMICOLON)

        # Update
        update_loc = self.loc()
        update: Statement
        if self.check(TOK_RPAREN):
            update = ExpressionStmt(
                expr=BigIntLiteral(value=0), source_location=update_loc
            )
        else:
            update_expr = self._parse_expression()
            update = ExpressionStmt(expr=update_expr, source_location=update_loc)

        self.expect(TOK_RPAREN)

        body = self._parse_block_or_statement()

        return ForStmt(
            init=init_stmt,
            condition=condition,
            update=update,
            body=body,
            source_location=loc,
        )

    def _parse_return(self, loc: SourceLocation) -> Statement:
        self.expect_ident("return")

        value: Expression | None = None
        if not self.check(TOK_SEMICOLON) and not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            value = self._parse_expression()

        self.skip_semicolons()
        return ReturnStmt(value=value, source_location=loc)

    def _parse_expression_statement(self, loc: SourceLocation) -> Statement | None:
        expr = self._parse_expression()

        # Check for assignment: expr = value
        if self.match(TOK_ASSIGN):
            value = self._parse_expression()
            self.skip_semicolons()
            return AssignmentStmt(target=expr, value=value, source_location=loc)

        # Compound assignments: +=, -=, *=, /=, %=
        compound_ops = {
            TOK_PLUSEQ: "+",
            TOK_MINUSEQ: "-",
            TOK_STAREQ: "*",
            TOK_SLASHEQ: "/",
            TOK_PERCENTEQ: "%",
        }
        for kind, bin_op in compound_ops.items():
            if self.match(kind):
                right = self._parse_expression()
                self.skip_semicolons()
                value = BinaryExpr(op=bin_op, left=expr, right=right)
                return AssignmentStmt(target=expr, value=value, source_location=loc)

        self.skip_semicolons()
        return ExpressionStmt(expr=expr, source_location=loc)

    # -- Expression parsing --------------------------------------------------
    # Operator precedence (lowest to highest):
    #   ternary (? :)
    #   logical or (||)
    #   logical and (&&)
    #   bitwise or (|)
    #   bitwise xor (^)
    #   bitwise and (&)
    #   equality (=== !==)
    #   comparison (< <= > >=)
    #   shift (<< >>)
    #   additive (+ -)
    #   multiplicative (* / %)
    #   unary (! - ~)
    #   postfix (. [] () ++ --)
    #   primary

    def _parse_expression(self) -> Expression:
        return self._parse_ternary()

    def _parse_ternary(self) -> Expression:
        expr = self._parse_or()
        if self.match(TOK_QUESTION):
            consequent = self._parse_ternary()
            self.expect(TOK_COLON)
            alternate = self._parse_ternary()
            return TernaryExpr(
                condition=expr, consequent=consequent, alternate=alternate
            )
        return expr

    def _parse_or(self) -> Expression:
        left = self._parse_and()
        while self.match(TOK_PIPEPIPE):
            right = self._parse_and()
            left = BinaryExpr(op="||", left=left, right=right)
        return left

    def _parse_and(self) -> Expression:
        left = self._parse_bitwise_or()
        while self.match(TOK_AMPAMP):
            right = self._parse_bitwise_or()
            left = BinaryExpr(op="&&", left=left, right=right)
        return left

    def _parse_bitwise_or(self) -> Expression:
        left = self._parse_bitwise_xor()
        while self.match(TOK_PIPE):
            right = self._parse_bitwise_xor()
            left = BinaryExpr(op="|", left=left, right=right)
        return left

    def _parse_bitwise_xor(self) -> Expression:
        left = self._parse_bitwise_and()
        while self.match(TOK_CARET):
            right = self._parse_bitwise_and()
            left = BinaryExpr(op="^", left=left, right=right)
        return left

    def _parse_bitwise_and(self) -> Expression:
        left = self._parse_equality()
        while self.match(TOK_AMP):
            right = self._parse_equality()
            left = BinaryExpr(op="&", left=left, right=right)
        return left

    def _parse_equality(self) -> Expression:
        left = self._parse_comparison()
        while True:
            if self.match(TOK_EQEQEQ):
                right = self._parse_comparison()
                left = BinaryExpr(op="===", left=left, right=right)
            elif self.match(TOK_NOTEQEQ):
                right = self._parse_comparison()
                left = BinaryExpr(op="!==", left=left, right=right)
            elif self.match(TOK_EQEQ):
                right = self._parse_comparison()
                left = BinaryExpr(op="===", left=left, right=right)
            elif self.match(TOK_NOTEQ):
                right = self._parse_comparison()
                left = BinaryExpr(op="!==", left=left, right=right)
            else:
                break
        return left

    def _parse_comparison(self) -> Expression:
        left = self._parse_shift()
        while True:
            if self.match(TOK_LT):
                right = self._parse_shift()
                left = BinaryExpr(op="<", left=left, right=right)
            elif self.match(TOK_LTEQ):
                right = self._parse_shift()
                left = BinaryExpr(op="<=", left=left, right=right)
            elif self.match(TOK_GT):
                right = self._parse_shift()
                left = BinaryExpr(op=">", left=left, right=right)
            elif self.match(TOK_GTEQ):
                right = self._parse_shift()
                left = BinaryExpr(op=">=", left=left, right=right)
            else:
                break
        return left

    def _parse_shift(self) -> Expression:
        left = self._parse_additive()
        while True:
            if self.match(TOK_LSHIFT):
                right = self._parse_additive()
                left = BinaryExpr(op="<<", left=left, right=right)
            elif self.match(TOK_RSHIFT):
                right = self._parse_additive()
                left = BinaryExpr(op=">>", left=left, right=right)
            else:
                break
        return left

    def _parse_additive(self) -> Expression:
        left = self._parse_multiplicative()
        while True:
            if self.match(TOK_PLUS):
                right = self._parse_multiplicative()
                left = BinaryExpr(op="+", left=left, right=right)
            elif self.match(TOK_MINUS):
                right = self._parse_multiplicative()
                left = BinaryExpr(op="-", left=left, right=right)
            else:
                break
        return left

    def _parse_multiplicative(self) -> Expression:
        left = self._parse_unary()
        while True:
            if self.match(TOK_STAR):
                right = self._parse_unary()
                left = BinaryExpr(op="*", left=left, right=right)
            elif self.match(TOK_SLASH):
                right = self._parse_unary()
                left = BinaryExpr(op="/", left=left, right=right)
            elif self.match(TOK_PERCENT):
                right = self._parse_unary()
                left = BinaryExpr(op="%", left=left, right=right)
            else:
                break
        return left

    def _parse_unary(self) -> Expression:
        if self.match(TOK_BANG):
            operand = self._parse_unary()
            return UnaryExpr(op="!", operand=operand)
        if self.match(TOK_MINUS):
            operand = self._parse_unary()
            return UnaryExpr(op="-", operand=operand)
        if self.match(TOK_TILDE):
            operand = self._parse_unary()
            return UnaryExpr(op="~", operand=operand)
        # Prefix ++ and --
        if self.match(TOK_PLUSPLUS):
            operand = self._parse_unary()
            return IncrementExpr(operand=operand, prefix=True)
        if self.match(TOK_MINUSMINUS):
            operand = self._parse_unary()
            return DecrementExpr(operand=operand, prefix=True)
        return self._parse_postfix()

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()
        while True:
            # Member access: expr.name
            if self.match(TOK_DOT):
                prop_tok = self.expect(TOK_IDENT)
                prop_name = prop_tok.value

                # Check for call: expr.name(...)
                if self.check(TOK_LPAREN):
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
                    if isinstance(expr, Identifier) and expr.name == "this":
                        expr = PropertyAccessExpr(property=prop_name)
                    else:
                        expr = MemberExpr(object=expr, property=prop_name)

            # Index access: expr[index]
            elif self.match(TOK_LBRACKET):
                index = self._parse_expression()
                self.expect(TOK_RBRACKET)
                expr = IndexAccessExpr(object=expr, index=index)

            # Direct call: expr(...)
            elif self.check(TOK_LPAREN) and self._is_callable(expr):
                args = self._parse_call_args()
                expr = CallExpr(callee=expr, args=args)

            # Postfix ++
            elif self.match(TOK_PLUSPLUS):
                expr = IncrementExpr(operand=expr, prefix=False)

            # Postfix --
            elif self.match(TOK_MINUSMINUS):
                expr = DecrementExpr(operand=expr, prefix=False)

            # TypeScript 'as' type assertion — skip the type, return expression
            elif self.check_ident("as"):
                self.advance()
                self._parse_type()

            # TypeScript non-null assertion '!'
            # Only consume if '!' immediately follows (no space)
            # Actually we can't tell spaces from tokens, so we handle
            # '!' only if next token is NOT an expression-starting token.
            # In practice, postfix '!' in TS is rare in Runar contracts.
            # We skip it here.

            else:
                break
        return expr

    def _is_callable(self, expr: Expression) -> bool:
        """Check if this expression can be directly called with ()."""
        return isinstance(expr, Identifier)

    def _parse_call_args(self) -> list[Expression]:
        self.expect(TOK_LPAREN)
        args: list[Expression] = []
        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            arg = self._parse_expression()
            args.append(arg)
            if not self.match(TOK_COMMA):
                break
        self.expect(TOK_RPAREN)
        return args

    def _parse_primary(self) -> Expression:
        tok = self.peek()

        # Number literal
        if tok.kind == TOK_NUMBER:
            self.advance()
            return _parse_number(tok.value)

        # String literal
        if tok.kind == TOK_STRING:
            self.advance()
            return ByteStringLiteral(value=tok.value)

        # Identifier, keyword, or call
        if tok.kind == TOK_IDENT:
            self.advance()
            name = tok.value

            if name == "true":
                return BoolLiteral(value=True)
            if name == "false":
                return BoolLiteral(value=False)
            if name == "this":
                return Identifier(name="this")
            if name == "super":
                return Identifier(name="super")

            # Function call: name(...)
            if self.check(TOK_LPAREN):
                args = self._parse_call_args()
                return CallExpr(callee=Identifier(name=name), args=args)

            return Identifier(name=name)

        # Parenthesized expression
        if tok.kind == TOK_LPAREN:
            self.advance()
            expr = self._parse_expression()
            self.expect(TOK_RPAREN)
            return expr

        # Array literal: [a, b, c]
        if tok.kind == TOK_LBRACKET:
            return self._parse_array_literal()

        self.add_error(f"line {tok.line}: unexpected token {tok.value!r}")
        self.advance()
        return BigIntLiteral(value=0)

    def _parse_array_literal(self) -> Expression:
        self.expect(TOK_LBRACKET)
        elements: list[Expression] = []
        while not self.check(TOK_RBRACKET) and not self.check(TOK_EOF):
            elem = self._parse_expression()
            elements.append(elem)
            if not self.match(TOK_COMMA):
                break
        self.expect(TOK_RBRACKET)
        return CallExpr(callee=Identifier(name="FixedArray"), args=elements)


def _parse_number(s: str) -> Expression:
    try:
        val = int(s, 0)
    except ValueError:
        val = 0
    # Check int64 overflow
    if val > 9223372036854775807 or val < -9223372036854775808:
        return BigIntLiteral(value=0)
    return BigIntLiteral(value=val)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_ts(source: str, file_name: str) -> ParseResult:
    """Parse a TypeScript-syntax Runar contract (.runar.ts)."""
    p = _TsParser(file_name)
    p.tokens = _tokenize(source)
    p.pos = 0

    try:
        contract = p.parse_contract()
    except ValueError as e:
        return ParseResult(errors=[str(e)])

    if p.errors:
        return ParseResult(contract=contract, errors=p.errors)
    return ParseResult(contract=contract)
