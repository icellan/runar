"""Solidity format parser (.runar.sol) for the Runar compiler.

Ported from compilers/go/frontend/parser_sol.go.
Hand-written tokenizer + recursive descent parser for Solidity-like syntax.
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
TOK_EQEQ = 15
TOK_NOTEQ = 16
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
TOK_AMPAMP = 31
TOK_PIPEPIPE = 32
TOK_PLUSPLUS = 33
TOK_MINUSMINUS = 34
TOK_PLUSEQ = 35
TOK_MINUSEQ = 36
TOK_STAREQ = 37
TOK_SLASHEQ = 38
TOK_PERCENTEQ = 39
TOK_QUESTION = 40
TOK_LSHIFT = 41
TOK_RSHIFT = 42


class Token:
    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind: int, value: str, line: int, col: int):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# Solidity type mapping
# ---------------------------------------------------------------------------

def _parse_sol_type(name: str) -> TypeNode:
    """Map Solidity-style type names to Runar types."""
    if name in ("uint", "uint256", "int", "int256"):
        return PrimitiveType(name="bigint")
    if name == "bool":
        return PrimitiveType(name="boolean")
    if name == "bytes":
        return PrimitiveType(name="ByteString")
    if name == "address":
        return PrimitiveType(name="Addr")
    if is_primitive_type(name):
        return PrimitiveType(name=name)
    return CustomType(name=name)


def _is_known_sol_type(name: str) -> bool:
    """Return True if *name* resolves to a primitive Runar type."""
    typ = _parse_sol_type(name)
    if isinstance(typ, PrimitiveType):
        return True
    return False


# ---------------------------------------------------------------------------
# Tokenizer helpers
# ---------------------------------------------------------------------------

def _is_hex_digit(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_" or ch == "$"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_" or ch == "$"


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

def _tokenize(source: str) -> list[Token]:
    """Tokenize Solidity-like source into a flat token list."""
    tokens: list[Token] = []
    line = 1
    col = 0
    i = 0
    n = len(source)

    while i < n:
        ch = source[i]

        # Newlines
        if ch == "\n":
            line += 1
            col = 0
            i += 1
            continue
        if ch == "\r":
            i += 1
            if i < n and source[i] == "\n":
                i += 1
            line += 1
            col = 0
            continue

        # Whitespace
        if ch == " " or ch == "\t":
            i += 1
            col += 1
            continue

        # Single-line comment //
        if i + 1 < n and ch == "/" and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                i += 1
            continue

        # Multi-line comment /* ... */
        if i + 1 < n and ch == "/" and source[i + 1] == "*":
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
            continue

        start_col = col

        # String literals
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            col += 1
            start = i
            while i < n and source[i] != quote:
                if source[i] == "\\":
                    i += 1
                    col += 1
                i += 1
                col += 1
            val = source[start:i]
            if i < n:
                i += 1
                col += 1
            tokens.append(Token(TOK_STRING, val, line, start_col))
            continue

        # Numbers
        if "0" <= ch <= "9":
            start = i
            if ch == "0" and i + 1 < n and source[i + 1] in ("x", "X"):
                i += 2
                col += 2
                while i < n and _is_hex_digit(source[i]):
                    i += 1
                    col += 1
            else:
                while i < n and "0" <= source[i] <= "9":
                    i += 1
                    col += 1
            # Skip trailing 'n' for bigint literals (from TS syntax)
            if i < n and source[i] == "n":
                i += 1
                col += 1
            tokens.append(Token(TOK_NUMBER, source[start:i], line, start_col))
            continue

        # Identifiers and keywords
        if _is_ident_start(ch):
            start = i
            while i < n and _is_ident_part(source[i]):
                i += 1
                col += 1
            tokens.append(Token(TOK_IDENT, source[start:i], line, start_col))
            continue

        # Two-character operators
        if i + 1 < n:
            two = source[i:i + 2]
            two_kind = {
                "==": TOK_EQEQ,
                "!=": TOK_NOTEQ,
                "<=": TOK_LTEQ,
                ">=": TOK_GTEQ,
                "&&": TOK_AMPAMP,
                "||": TOK_PIPEPIPE,
                "++": TOK_PLUSPLUS,
                "--": TOK_MINUSMINUS,
                "+=": TOK_PLUSEQ,
                "-=": TOK_MINUSEQ,
                "*=": TOK_STAREQ,
                "/=": TOK_SLASHEQ,
                "%=": TOK_PERCENTEQ,
                "<<": TOK_LSHIFT,
                ">>": TOK_RSHIFT,
            }.get(two)
            if two_kind is not None:
                tokens.append(Token(two_kind, two, line, start_col))
                i += 2
                col += 2
                continue

        # Single-character operators
        one_map = {
            "{": TOK_LBRACE,
            "}": TOK_RBRACE,
            "(": TOK_LPAREN,
            ")": TOK_RPAREN,
            "[": TOK_LBRACKET,
            "]": TOK_RBRACKET,
            ";": TOK_SEMICOLON,
            ",": TOK_COMMA,
            ".": TOK_DOT,
            ":": TOK_COLON,
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

class _SolParser:
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

    # -- Contract parsing ----------------------------------------------------

    def parse_contract(self) -> ContractNode:
        # Skip pragma
        if self.check_ident("pragma"):
            while not self.check(TOK_SEMICOLON) and not self.check(TOK_EOF):
                self.advance()
            self.match(TOK_SEMICOLON)

        # Skip import statements
        while self.check_ident("import"):
            while not self.check(TOK_SEMICOLON) and not self.check(TOK_EOF):
                self.advance()
            self.match(TOK_SEMICOLON)

        # contract Name is ParentClass {
        if not self.match_ident("contract"):
            raise ValueError("expected 'contract' keyword")

        name_tok = self.expect(TOK_IDENT)
        contract_name = name_tok.value

        parent_class = "SmartContract"
        if self.match_ident("is"):
            parent_tok = self.expect(TOK_IDENT)
            parent_class = parent_tok.value

        if parent_class not in ("SmartContract", "StatefulSmartContract"):
            raise ValueError(f"unknown parent class: {parent_class}")

        self.expect(TOK_LBRACE)

        properties: list[PropertyNode] = []
        constructor: MethodNode | None = None
        methods: list[MethodNode] = []

        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            if self.check_ident("function"):
                method = self.parse_function()
                methods.append(method)
            elif self.check_ident("constructor"):
                constructor = self.parse_sol_constructor(properties)
            else:
                # Try to parse as a property: Type [immutable] name;
                prop = self.parse_sol_property()
                if prop is not None:
                    properties.append(prop)

        self.expect(TOK_RBRACE)

        if constructor is None:
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

    # -- Property parsing: Type [immutable] name; ---------------------------

    def parse_sol_property(self) -> PropertyNode | None:
        location = self.loc()

        # Read type name
        type_tok = self.advance()
        if type_tok.kind != TOK_IDENT:
            # Skip unknown tokens
            return None

        type_name = type_tok.value

        # Check for immutable keyword
        is_readonly = False
        if self.check_ident("immutable"):
            self.advance()
            is_readonly = True

        # Property name
        name_tok = self.expect(TOK_IDENT)
        prop_name = name_tok.value

        # Parse optional initializer: = value
        initializer = None
        if self.match(TOK_ASSIGN):
            initializer = self.parse_expression()

        self.expect(TOK_SEMICOLON)

        return PropertyNode(
            name=prop_name,
            type=_parse_sol_type(type_name),
            readonly=is_readonly,
            initializer=initializer,
            source_location=location,
        )

    # -- Constructor parsing: constructor(Type _name, ...) { ... } ----------

    def parse_sol_constructor(self, properties: list[PropertyNode]) -> MethodNode:
        location = self.loc()
        self.expect_ident("constructor")
        params = self.parse_sol_params()
        body = self.parse_sol_block()

        # Build proper constructor body with super() call and assignments
        constructor_body: list[Statement] = []

        # super(...) call with all param names
        super_args: list[Expression] = [Identifier(name=p.name) for p in params]
        constructor_body.append(
            ExpressionStmt(
                expr=CallExpr(
                    callee=Identifier(name="super"),
                    args=super_args,
                ),
                source_location=location,
            )
        )

        # Append any additional statements from the body,
        # converting bare property name assignments to this.property form
        prop_names = {p.name for p in properties}
        for stmt in body:
            if isinstance(stmt, AssignmentStmt) and isinstance(stmt.target, Identifier):
                if stmt.target.name in prop_names:
                    stmt = AssignmentStmt(
                        target=PropertyAccessExpr(property=stmt.target.name),
                        value=stmt.value,
                        source_location=stmt.source_location,
                    )
            constructor_body.append(stmt)

        return MethodNode(
            name="constructor",
            params=params,
            body=constructor_body,
            visibility="public",
            source_location=location,
        )

    # -- Function parsing: function name(Type name, ...) [public|private] { ... }

    def parse_function(self) -> MethodNode:
        location = self.loc()
        self.expect_ident("function")

        name_tok = self.expect(TOK_IDENT)
        name = name_tok.value

        params = self.parse_sol_params()

        # Parse visibility modifiers
        visibility = "private"
        while (
            self.check_ident("public")
            or self.check_ident("private")
            or self.check_ident("external")
            or self.check_ident("internal")
            or self.check_ident("view")
            or self.check_ident("pure")
            or self.check_ident("returns")
            or self.check_ident("payable")
        ):
            tok = self.advance()
            if tok.value in ("public", "external"):
                visibility = "public"
            # Skip 'returns (Type)' clause
            if tok.value == "returns":
                if self.check(TOK_LPAREN):
                    self.advance()
                    depth = 1
                    while depth > 0 and not self.check(TOK_EOF):
                        if self.check(TOK_LPAREN):
                            depth += 1
                        if self.check(TOK_RPAREN):
                            depth -= 1
                        self.advance()

        body = self.parse_sol_block()

        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility=visibility,
            source_location=location,
        )

    # -- Parameter parsing: (Type name, Type name, ...) ---------------------

    def parse_sol_params(self) -> list[ParamNode]:
        self.expect(TOK_LPAREN)
        params: list[ParamNode] = []

        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            type_tok = self.expect(TOK_IDENT)
            type_name = type_tok.value

            # Skip memory/storage/calldata qualifiers
            while (
                self.check_ident("memory")
                or self.check_ident("storage")
                or self.check_ident("calldata")
            ):
                self.advance()

            name_tok = self.expect(TOK_IDENT)
            param_name = name_tok.value
            # Strip leading underscore if present (Solidity convention)
            if param_name.startswith("_"):
                param_name = param_name[1:]

            params.append(
                ParamNode(name=param_name, type=_parse_sol_type(type_name))
            )

            if not self.match(TOK_COMMA):
                break

        self.expect(TOK_RPAREN)
        return params

    # -- Block parsing: { statements... } -----------------------------------

    def parse_sol_block(self) -> list[Statement]:
        self.expect(TOK_LBRACE)
        stmts: list[Statement] = []
        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            stmt = self.parse_sol_statement()
            if stmt is not None:
                stmts.append(stmt)
        self.expect(TOK_RBRACE)
        return stmts

    # -- Statement parsing ---------------------------------------------------

    def parse_sol_statement(self) -> Statement | None:
        location = self.loc()

        # require(...) -> assert(...)
        if self.check_ident("require"):
            return self._parse_require(location)

        # if (...) { ... } [else { ... }]
        if self.check_ident("if"):
            return self._parse_if(location)

        # for (...) { ... }
        if self.check_ident("for"):
            return self._parse_for(location)

        # return ...;
        if self.check_ident("return"):
            return self._parse_return(location)

        # Variable declarations: Type name = expr;
        if self.peek().kind == TOK_IDENT and self._is_type_start():
            return self._parse_var_decl(location)

        # Assignment or expression statement
        return self._parse_expr_statement(location)

    def _is_type_start(self) -> bool:
        """Look ahead to check if this is a 'Type name' pattern."""
        if self.pos + 1 >= len(self.tokens):
            return False
        next_tok = self.tokens[self.pos + 1]
        # If next token is an identifier, this might be a type
        if next_tok.kind == TOK_IDENT:
            name = self.peek().value
            # Known primitive types
            if is_primitive_type(name) or _is_known_sol_type(name):
                return True
            # Capitalized names are likely type names
            if len(name) > 0 and name[0].isupper():
                return True
            # Common Solidity types
            if name in ("uint", "uint256", "int", "int256", "bool", "bytes", "address", "string"):
                return True
        return False

    def _parse_require(self, loc: SourceLocation) -> Statement:
        self.expect_ident("require")
        self.expect(TOK_LPAREN)
        expr = self.parse_expression()
        # Skip optional error message parameter
        if self.match(TOK_COMMA):
            self.parse_expression()
        self.expect(TOK_RPAREN)
        self.expect(TOK_SEMICOLON)
        return ExpressionStmt(
            expr=CallExpr(callee=Identifier(name="assert"), args=[expr]),
            source_location=loc,
        )

    def _parse_if(self, loc: SourceLocation) -> Statement:
        self.expect_ident("if")
        self.expect(TOK_LPAREN)
        condition = self.parse_expression()
        self.expect(TOK_RPAREN)

        then_block = self.parse_sol_block()

        else_block: list[Statement] = []
        if self.match_ident("else"):
            if self.check_ident("if"):
                # else if -- recurse
                else_stmt = self._parse_if(self.loc())
                else_block = [else_stmt]
            else:
                else_block = self.parse_sol_block()

        return IfStmt(
            condition=condition,
            then=then_block,
            else_=else_block,
            source_location=loc,
        )

    def _parse_for(self, loc: SourceLocation) -> Statement:
        self.expect_ident("for")
        self.expect(TOK_LPAREN)

        # Initializer
        if self._is_type_start() or self.check_ident("uint") or self.check_ident("int"):
            type_tok = self.advance()
            name_tok = self.expect(TOK_IDENT)
            self.expect(TOK_ASSIGN)
            init_expr = self.parse_expression()
            self.expect(TOK_SEMICOLON)
            init_stmt = VariableDeclStmt(
                name=name_tok.value,
                type=_parse_sol_type(type_tok.value),
                mutable=True,
                init=init_expr,
                source_location=loc,
            )
        else:
            self.expect(TOK_SEMICOLON)
            init_stmt = VariableDeclStmt(
                name="_i",
                mutable=True,
                init=BigIntLiteral(value=0),
                source_location=loc,
            )

        # Condition
        condition = self.parse_expression()
        self.expect(TOK_SEMICOLON)

        # Update
        update_expr = self.parse_expression()
        update: Statement = ExpressionStmt(expr=update_expr, source_location=loc)

        self.expect(TOK_RPAREN)

        body = self.parse_sol_block()

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
        if not self.check(TOK_SEMICOLON):
            value = self.parse_expression()
        self.expect(TOK_SEMICOLON)
        return ReturnStmt(value=value, source_location=loc)

    def _parse_var_decl(self, loc: SourceLocation) -> Statement:
        type_tok = self.advance()
        type_name = type_tok.value

        name_tok = self.expect(TOK_IDENT)
        var_name = name_tok.value

        init: Expression
        if self.match(TOK_ASSIGN):
            init = self.parse_expression()
        else:
            init = BigIntLiteral(value=0)

        self.expect(TOK_SEMICOLON)

        return VariableDeclStmt(
            name=var_name,
            type=_parse_sol_type(type_name),
            mutable=True,
            init=init,
            source_location=loc,
        )

    def _parse_expr_statement(self, loc: SourceLocation) -> Statement | None:
        expr = self.parse_expression()
        if expr is None:
            # Skip a token to avoid infinite loops
            self.advance()
            return None

        # Check for assignment
        if self.match(TOK_ASSIGN):
            value = self.parse_expression()
            self.expect(TOK_SEMICOLON)
            return AssignmentStmt(target=expr, value=value, source_location=loc)

        # Check for compound assignment
        compound_ops = {
            TOK_PLUSEQ: "+",
            TOK_MINUSEQ: "-",
            TOK_STAREQ: "*",
            TOK_SLASHEQ: "/",
            TOK_PERCENTEQ: "%",
        }
        for kind, bin_op in compound_ops.items():
            if self.match(kind):
                right = self.parse_expression()
                self.expect(TOK_SEMICOLON)
                value = BinaryExpr(op=bin_op, left=expr, right=right)
                return AssignmentStmt(target=expr, value=value, source_location=loc)

        self.expect(TOK_SEMICOLON)
        return ExpressionStmt(expr=expr, source_location=loc)

    # -- Expression parsing (recursive descent with precedence) --------------

    def parse_expression(self) -> Expression:
        return self._parse_ternary()

    def _parse_ternary(self) -> Expression:
        expr = self._parse_or()
        if self.match(TOK_QUESTION):
            consequent = self.parse_expression()
            self.expect(TOK_COLON)
            alternate = self.parse_expression()
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
            if self.match(TOK_EQEQ):
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
        # Prefix increment/decrement
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
            if self.match(TOK_DOT):
                prop_tok = self.expect(TOK_IDENT)
                prop_name = prop_tok.value

                # Check if this is a method call: obj.method(...)
                if self.check(TOK_LPAREN):
                    args = self._parse_call_args()
                    if isinstance(expr, Identifier) and expr.name == "this":
                        expr = CallExpr(
                            callee=MemberExpr(
                                object=Identifier(name="this"), property=prop_name
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

            elif self.match(TOK_LBRACKET):
                index = self.parse_expression()
                self.expect(TOK_RBRACKET)
                expr = IndexAccessExpr(object=expr, index=index)

            elif self.match(TOK_PLUSPLUS):
                expr = IncrementExpr(operand=expr, prefix=False)

            elif self.match(TOK_MINUSMINUS):
                expr = DecrementExpr(operand=expr, prefix=False)

            else:
                break
        return expr

    def _parse_primary(self) -> Expression:
        tok = self.peek()

        if tok.kind == TOK_NUMBER:
            self.advance()
            return _parse_sol_number(tok.value)

        if tok.kind == TOK_STRING:
            self.advance()
            return ByteStringLiteral(value=tok.value)

        if tok.kind == TOK_IDENT:
            self.advance()
            name = tok.value

            # Boolean literals
            if name == "true":
                return BoolLiteral(value=True)
            if name == "false":
                return BoolLiteral(value=False)
            if name == "this":
                return Identifier(name="this")

            # Function call
            if self.check(TOK_LPAREN):
                args = self._parse_call_args()
                return CallExpr(callee=Identifier(name=name), args=args)

            return Identifier(name=name)

        if tok.kind == TOK_LPAREN:
            self.advance()
            expr = self.parse_expression()
            self.expect(TOK_RPAREN)
            return expr

        self.add_error(f"line {tok.line}: unexpected token {tok.value!r}")
        self.advance()
        return BigIntLiteral(value=0)

    def _parse_call_args(self) -> list[Expression]:
        self.expect(TOK_LPAREN)
        args: list[Expression] = []
        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            arg = self.parse_expression()
            args.append(arg)
            if not self.match(TOK_COMMA):
                break
        self.expect(TOK_RPAREN)
        return args


# ---------------------------------------------------------------------------
# Number parsing
# ---------------------------------------------------------------------------

def _parse_sol_number(s: str) -> Expression:
    """Parse a numeric literal, stripping any trailing 'n' suffix."""
    if s.endswith("n"):
        s = s[:-1]
    try:
        val = int(s, 0)
    except ValueError:
        val = 0
    return BigIntLiteral(value=val)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _rewrite_bare_props(
    expr: Expression, prop_names: set[str], param_names: set[str],
    method_names: set[str] | None = None,
) -> Expression:
    """Recursively rewrite bare Identifier(name) -> PropertyAccessExpr(property) for property names,
    and bare method calls -> this.method() for contract method names."""
    if method_names is None:
        method_names = set()
    rw = lambda e: _rewrite_bare_props(e, prop_names, param_names, method_names)
    if isinstance(expr, Identifier):
        if expr.name in prop_names and expr.name not in param_names:
            return PropertyAccessExpr(property=expr.name)
        return expr
    if isinstance(expr, BinaryExpr):
        return BinaryExpr(op=expr.op, left=rw(expr.left), right=rw(expr.right))
    if isinstance(expr, UnaryExpr):
        return UnaryExpr(op=expr.op, operand=rw(expr.operand))
    if isinstance(expr, CallExpr):
        # Bare method call: computeThreshold(a, b) -> this.computeThreshold(a, b)
        if isinstance(expr.callee, Identifier) and expr.callee.name in method_names:
            return CallExpr(
                callee=MemberExpr(object=Identifier(name="this"), property=expr.callee.name),
                args=[rw(a) for a in expr.args],
            )
        return CallExpr(callee=rw(expr.callee), args=[rw(a) for a in expr.args])
    if isinstance(expr, TernaryExpr):
        return TernaryExpr(condition=rw(expr.condition), consequent=rw(expr.consequent), alternate=rw(expr.alternate))
    if isinstance(expr, IndexAccessExpr):
        return IndexAccessExpr(object=rw(expr.object), index=rw(expr.index))
    return expr


def _rewrite_stmt_props(
    stmt: Statement, prop_names: set[str], param_names: set[str], method_names: set[str],
) -> Statement:
    """Rewrite bare property references and method calls in a statement."""
    rw = lambda e: _rewrite_bare_props(e, prop_names, param_names, method_names)
    rs = lambda s: _rewrite_stmt_props(s, prop_names, param_names, method_names)
    if isinstance(stmt, ExpressionStmt):
        return ExpressionStmt(expr=rw(stmt.expr), source_location=stmt.source_location)
    if isinstance(stmt, VariableDeclStmt):
        new_params = param_names | {stmt.name}
        return VariableDeclStmt(
            name=stmt.name, type=stmt.type, mutable=stmt.mutable,
            init=_rewrite_bare_props(stmt.init, prop_names, new_params, method_names) if stmt.init else None,
            source_location=stmt.source_location,
        )
    if isinstance(stmt, AssignmentStmt):
        return AssignmentStmt(target=rw(stmt.target), value=rw(stmt.value), source_location=stmt.source_location)
    if isinstance(stmt, ReturnStmt):
        return ReturnStmt(value=rw(stmt.value) if stmt.value else None, source_location=stmt.source_location)
    if isinstance(stmt, IfStmt):
        return IfStmt(
            condition=rw(stmt.condition),
            then=[rs(s) for s in stmt.then],
            else_=[rs(s) for s in stmt.else_] if stmt.else_ else [],
            source_location=stmt.source_location,
        )
    if isinstance(stmt, ForStmt):
        return ForStmt(
            init=rs(stmt.init) if stmt.init else None,
            condition=rw(stmt.condition) if stmt.condition else None,
            update=rs(stmt.update) if stmt.update else None,
            body=[rs(s) for s in stmt.body],
            source_location=stmt.source_location,
        )
    return stmt


def _rewrite_contract_props(contract: ContractNode) -> None:
    """In-place rewrite: bare property names -> PropertyAccessExpr, bare method calls -> this.method()."""
    prop_names = {p.name for p in contract.properties}
    method_names = {m.name for m in contract.methods}
    if not prop_names and not method_names:
        return
    for method in contract.methods:
        param_names = {p.name for p in method.params}
        method.body[:] = [_rewrite_stmt_props(s, prop_names, param_names, method_names) for s in method.body]


def parse_sol(source: str, file_name: str) -> ParseResult:
    """Parse a Solidity-syntax Runar contract (.runar.sol)."""
    p = _SolParser(file_name)
    p.tokens = _tokenize(source)
    p.pos = 0

    try:
        contract = p.parse_contract()
    except ValueError as e:
        return ParseResult(errors=[str(e)])

    if contract is not None:
        _rewrite_contract_props(contract)

    if p.errors:
        return ParseResult(contract=contract, errors=p.errors)
    return ParseResult(contract=contract)
