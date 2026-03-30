"""Move format parser (.runar.move) for the Runar compiler.

Ported from compilers/go/frontend/parser_move.go.
Hand-written tokenizer + recursive descent parser for Move-style smart
contract syntax.
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
from runar_compiler.frontend.diagnostic import Diagnostic, Severity


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
TOK_COLONCOLON = 14
TOK_ASSIGN = 15
TOK_EQEQ = 16
TOK_NOTEQ = 17
TOK_LT = 18
TOK_LTEQ = 19
TOK_GT = 20
TOK_GTEQ = 21
TOK_PLUS = 22
TOK_MINUS = 23
TOK_STAR = 24
TOK_SLASH = 25
TOK_PERCENT = 26
TOK_BANG = 27
TOK_TILDE = 28
TOK_AMP = 29
TOK_PIPE = 30
TOK_CARET = 31
TOK_AMPAMP = 32
TOK_PIPEPIPE = 33
TOK_PLUSPLUS = 34
TOK_MINUSMINUS = 35
TOK_PLUSEQ = 36
TOK_MINUSEQ = 37
TOK_STAREQ = 38
TOK_SLASHEQ = 39
TOK_PERCENTEQ = 40
TOK_QUESTION = 41
TOK_ARROW = 42


class Token:
    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind: int, value: str, line: int, col: int):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# Name conversion: snake_case to camelCase
# ---------------------------------------------------------------------------

def _snake_to_camel(s: str) -> str:
    parts = s.split("_")
    if len(parts) <= 1:
        return s
    result = parts[0]
    for part in parts[1:]:
        if part:
            result += part[0].upper() + part[1:]
    return result


_MOVE_BUILTIN_MAP: dict[str, str] = {
    "check_sig":       "checkSig",
    "check_multi_sig": "checkMultiSig",
    "check_preimage":  "checkPreimage",
    "hash_160":        "hash160",
    "hash_256":        "hash256",
    "sha_256":         "sha256",
    "ripemd_160":      "ripemd160",
    "num_2_bin":       "num2bin",
    "bin_2_num":       "bin2num",
    "reverse_bytes":   "reverseBytes",
    "hash160":         "hash160",
    "hash256":         "hash256",
    "sha256":          "sha256",
    "ripemd160":       "ripemd160",
    "num2bin":         "num2bin",
    "bin2num":         "bin2num",
    "abs":             "abs",
    "min":             "min",
    "max":             "max",
    "within":          "within",
    "len":             "len",
    "pack":            "pack",
    "unpack":          "unpack",
}


def _move_map_builtin(name: str) -> str:
    if name in _MOVE_BUILTIN_MAP:
        return _MOVE_BUILTIN_MAP[name]
    return _snake_to_camel(name)


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

def _move_map_type(name: str) -> TypeNode:
    if name in ("u64", "u128", "u256", "Int", "Bigint"):
        return PrimitiveType(name="bigint")
    if name == "bool":
        return PrimitiveType(name="boolean")
    if name == "vector":
        return PrimitiveType(name="ByteString")
    camel = _snake_to_camel(name)
    if is_primitive_type(camel):
        return PrimitiveType(name=camel)
    if is_primitive_type(name):
        return PrimitiveType(name=name)
    return CustomType(name=camel)


# ---------------------------------------------------------------------------
# Tokenizer helpers
# ---------------------------------------------------------------------------

def _is_hex_digit(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

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
                i += 1  # skip closing quote
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
            # Skip trailing type suffixes like u8, u64, etc.
            if i < n and source[i] == "u":
                i += 1
                col += 1
                while i < n and "0" <= source[i] <= "9":
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
            # Handle assert! and assert_eq! macros
            if i < n and source[i] == "!":
                tokens.append(Token(TOK_IDENT, source[start:i] + "!", line, start_col))
                i += 1  # skip '!'
                col += 1
                continue
            tokens.append(Token(TOK_IDENT, source[start:i], line, start_col))
            continue

        # Two-character operators
        if i + 1 < n:
            two = source[i:i + 2]
            two_kind: int | None = {
                "::": TOK_COLONCOLON,
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
                "->": TOK_ARROW,
            }.get(two)
            if two_kind is not None:
                tokens.append(Token(two_kind, two, line, start_col))
                i += 2
                col += 2
                continue

        # Single-character operators
        one_kind: int | None = {
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
        }.get(ch)
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

class _MoveParser:
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.tokens: list[Token] = []
        self.pos = 0
        self.errors: list[Diagnostic] = []

    def add_error(self, msg: str) -> None:
        self.errors.append(Diagnostic(message=msg, severity=Severity.ERROR))

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

    # -- Module parsing ------------------------------------------------------

    def parse_module(self) -> ContractNode:
        # Skip use declarations at the top level before module
        while self.check_ident("use"):
            self._skip_use_decl()

        # module Name { ... }
        if not self.match_ident("module"):
            raise ValueError("expected 'module' keyword")

        name_tok = self.expect(TOK_IDENT)
        module_name = name_tok.value

        self.expect(TOK_LBRACE)

        properties: list[PropertyNode] = []
        methods: list[MethodNode] = []
        parent_class = "SmartContract"  # default

        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            # Skip use declarations inside the module
            if self.check_ident("use"):
                self._skip_use_decl()
                continue

            # resource struct or struct
            if self.check_ident("resource") or self.check_ident("struct"):
                is_resource = self.check_ident("resource")
                if is_resource:
                    self.advance()  # skip "resource"
                props = self._parse_move_struct()
                properties.extend(props)
                if is_resource or any(not p.readonly for p in props):
                    parent_class = "StatefulSmartContract"
                continue

            # public fun or fun
            if self.check_ident("public") or self.check_ident("fun"):
                method, has_mut = self._parse_move_function()
                if has_mut:
                    parent_class = "StatefulSmartContract"
                methods.append(method)
                continue

            # Skip unknown tokens
            self.advance()

        self.expect(TOK_RBRACE)

        # Build constructor from properties
        constructor = self._build_move_constructor(properties)

        return ContractNode(
            name=module_name,
            parent_class=parent_class,
            properties=properties,
            constructor=constructor,
            methods=methods,
            source_file=self.file_name,
        )

    def _skip_use_decl(self) -> None:
        # use path::to::module::{Type1, Type2};
        while not self.check(TOK_SEMICOLON) and not self.check(TOK_EOF):
            self.advance()
        self.match(TOK_SEMICOLON)

    # -- Struct parsing ------------------------------------------------------

    def _parse_move_struct(self) -> list[PropertyNode]:
        self.expect_ident("struct")

        # struct name
        self.expect(TOK_IDENT)  # skip struct name (same as module name)

        # Optional: has key, store, copy, drop abilities
        if self.check_ident("has"):
            self.advance()
            while self.peek().kind == TOK_IDENT or self.peek().kind == TOK_COMMA:
                self.advance()

        self.expect(TOK_LBRACE)

        props: list[PropertyNode] = []
        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            name_tok = self.expect(TOK_IDENT)
            field_name = _snake_to_camel(name_tok.value)

            self.expect(TOK_COLON)

            # Detect &mut prefix before parsing the type name
            is_mut = (
                self.check(TOK_AMP)
                and self.pos + 1 < len(self.tokens)
                and self.tokens[self.pos + 1].kind == TOK_IDENT
                and self.tokens[self.pos + 1].value == "mut"
            )
            type_name = self._parse_move_type_name()
            type_node = _move_map_type(type_name)

            # &mut fields are mutable; all others are readonly
            readonly = not is_mut

            # Parse optional initializer: = value
            initializer = None
            if self.match(TOK_ASSIGN):
                initializer = self.parse_expression()

            props.append(PropertyNode(
                name=field_name,
                type=type_node,
                readonly=readonly,
                initializer=initializer,
                source_location=self.loc(),
            ))

            self.match(TOK_COMMA)

        self.expect(TOK_RBRACE)
        return props

    def _parse_move_type_name(self) -> str:
        # Handle & references
        if self.match(TOK_AMP):
            # &mut or &
            self.match_ident("mut")

        name_tok = self.expect(TOK_IDENT)
        name = name_tok.value

        # Handle path types: module::Type
        while self.match(TOK_COLONCOLON):
            next_tok = self.expect(TOK_IDENT)
            name = next_tok.value  # use the final component

        # Handle generic types: Type<T>
        if self.match(TOK_LT):
            depth = 1
            while depth > 0 and not self.check(TOK_EOF):
                if self.check(TOK_LT):
                    depth += 1
                if self.check(TOK_GT):
                    depth -= 1
                self.advance()

        return name

    # -- Function parsing ----------------------------------------------------

    def _parse_move_function(self) -> tuple[MethodNode, bool]:
        """Returns (method, has_mut_receiver)."""
        location = self.loc()
        visibility = "private"

        if self.match_ident("public"):
            visibility = "public"
            # Skip optional (friend) or (script) visibility
            if self.check(TOK_LPAREN):
                self.advance()
                while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
                    self.advance()
                self.match(TOK_RPAREN)

        self.expect_ident("fun")

        name_tok = self.expect(TOK_IDENT)
        name = _snake_to_camel(name_tok.value)

        params, has_mut = self._parse_move_params()

        # Optional return type: : Type
        if self.match(TOK_COLON):
            self._parse_move_type_name()  # skip return type

        body = self._parse_move_block()

        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility=visibility,
            source_location=location,
        ), has_mut

    def _parse_move_params(self) -> tuple[list[ParamNode], bool]:
        """Returns (params, has_mut_receiver)."""
        self.expect(TOK_LPAREN)
        params: list[ParamNode] = []
        has_mut_receiver = False

        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            # Skip &self, self, &mut self, contract: &ContractName
            if self.check_ident("self"):
                self.advance()
                if self.match(TOK_COMMA):
                    continue
                break

            # Check for & prefix
            is_ref = False
            is_mut = False
            if self.check(TOK_AMP):
                is_ref = True
                self.advance()
                if self.match_ident("mut"):
                    is_mut = True

            name_tok = self.expect(TOK_IDENT)
            param_name = name_tok.value

            self.expect(TOK_COLON)

            # Check for & in type
            type_is_mut = False
            if self.check(TOK_AMP):
                self.advance()
                if self.match_ident("mut"):
                    type_is_mut = True

            type_name = self._parse_move_type_name()

            # Skip self/contract parameters
            if param_name in ("self", "contract"):
                if is_mut or type_is_mut:
                    has_mut_receiver = True
                if self.match(TOK_COMMA):
                    continue
                break

            camel_name = _snake_to_camel(param_name)
            params.append(ParamNode(
                name=camel_name,
                type=_move_map_type(type_name),
            ))

            if not self.match(TOK_COMMA):
                break

        self.expect(TOK_RPAREN)
        return params, has_mut_receiver

    # -- Block parsing -------------------------------------------------------

    def _parse_move_block(self) -> list[Statement]:
        self.expect(TOK_LBRACE)
        stmts: list[Statement] = []
        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            # Skip bare semicolons (e.g. after if {} else {};)
            if self.match(TOK_SEMICOLON):
                continue
            stmt = self._parse_move_statement()
            if stmt is not None:
                stmts.append(stmt)
        self.expect(TOK_RBRACE)
        return stmts

    # -- Statement parsing ---------------------------------------------------

    def _parse_move_statement(self) -> Statement | None:
        location = self.loc()

        # let [mut] name [: Type] = expr;
        if self.check_ident("let"):
            return self._parse_move_let_decl(location)

        # assert!(expr, code) or assert_eq!(a, b, code)
        if self.check_ident("assert!") or self.check_ident("assert_eq!"):
            return self._parse_move_assert(location)

        # if condition { ... } [else { ... }]
        if self.check_ident("if"):
            return self._parse_move_if(location)

        # while
        if self.check_ident("while"):
            return self._parse_move_while(location)

        # loop
        if self.check_ident("loop"):
            return self._parse_move_loop(location)

        # return expr;
        if self.check_ident("return"):
            return self._parse_move_return(location)

        # Expression statement or assignment
        return self._parse_move_expr_statement(location)

    def _parse_move_let_decl(self, loc: SourceLocation) -> Statement:
        self.expect_ident("let")

        mutable = False
        if self.match_ident("mut"):
            mutable = True

        name_tok = self.expect(TOK_IDENT)
        var_name = _snake_to_camel(name_tok.value)

        type_node: TypeNode | None = None
        if self.match(TOK_COLON):
            type_name = self._parse_move_type_name()
            type_node = _move_map_type(type_name)

        init: Expression
        if self.match(TOK_ASSIGN):
            init = self._parse_move_expression()
        else:
            init = BigIntLiteral(value=0)

        self.expect(TOK_SEMICOLON)

        return VariableDeclStmt(
            name=var_name,
            type=type_node,
            mutable=mutable,
            init=init,
            source_location=loc,
        )

    def _parse_move_assert(self, loc: SourceLocation) -> Statement:
        tok = self.advance()  # consume assert! or assert_eq!

        self.expect(TOK_LPAREN)

        if tok.value == "assert_eq!":
            # assert_eq!(a, b, code) -> assert(a === b)
            left = self._parse_move_expression()
            self.expect(TOK_COMMA)
            right = self._parse_move_expression()
            # Skip optional error code
            if self.match(TOK_COMMA):
                self._parse_move_expression()
            self.expect(TOK_RPAREN)
            self.expect(TOK_SEMICOLON)

            return ExpressionStmt(
                expr=CallExpr(
                    callee=Identifier(name="assert"),
                    args=[BinaryExpr(op="===", left=left, right=right)],
                ),
                source_location=loc,
            )

        # assert!(expr, code)
        expr = self._parse_move_expression()
        # Skip optional error code
        if self.match(TOK_COMMA):
            self._parse_move_expression()
        self.expect(TOK_RPAREN)
        self.expect(TOK_SEMICOLON)

        return ExpressionStmt(
            expr=CallExpr(callee=Identifier(name="assert"), args=[expr]),
            source_location=loc,
        )

    def _parse_move_if(self, loc: SourceLocation) -> Statement:
        self.expect_ident("if")

        # Move uses parens around conditions optionally
        has_paren = self.match(TOK_LPAREN)
        condition = self._parse_move_expression()
        if has_paren:
            self.expect(TOK_RPAREN)

        then_block = self._parse_move_block()

        else_block: list[Statement] = []
        if self.match_ident("else"):
            if self.check_ident("if"):
                else_stmt = self._parse_move_if(self.loc())
                else_block = [else_stmt]
            else:
                else_block = self._parse_move_block()

        return IfStmt(
            condition=condition,
            then=then_block,
            else_=else_block,
            source_location=loc,
        )

    def _parse_move_while(self, loc: SourceLocation) -> Statement:
        self.expect_ident("while")

        has_paren = self.match(TOK_LPAREN)
        condition = self._parse_move_expression()
        if has_paren:
            self.expect(TOK_RPAREN)

        body = self._parse_move_block()

        # Convert while loop to a for loop with no init/update for AST compatibility
        return ForStmt(
            init=VariableDeclStmt(
                name="_w", mutable=True, init=BigIntLiteral(value=0), source_location=loc,
            ),
            condition=condition,
            update=ExpressionStmt(expr=BigIntLiteral(value=0), source_location=loc),
            body=body,
            source_location=loc,
        )

    def _parse_move_loop(self, loc: SourceLocation) -> Statement:
        self.expect_ident("loop")

        body = self._parse_move_block()

        # Convert loop {} to for(;;) {} -- infinite loop with true condition
        return ForStmt(
            init=VariableDeclStmt(
                name="_l", mutable=True, init=BigIntLiteral(value=0), source_location=loc,
            ),
            condition=BoolLiteral(value=True),
            update=ExpressionStmt(expr=BigIntLiteral(value=0), source_location=loc),
            body=body,
            source_location=loc,
        )

    def _parse_move_return(self, loc: SourceLocation) -> Statement:
        self.expect_ident("return")
        value: Expression | None = None
        if not self.check(TOK_SEMICOLON) and not self.check(TOK_RBRACE):
            value = self._parse_move_expression()
        self.match(TOK_SEMICOLON)
        return ReturnStmt(value=value, source_location=loc)

    def _parse_move_expr_statement(self, loc: SourceLocation) -> Statement | None:
        expr = self._parse_move_expression()
        if expr is None:
            self.advance()
            return None

        # Check for assignment: expr = value
        if self.match(TOK_ASSIGN):
            value = self._parse_move_expression()
            self.expect(TOK_SEMICOLON)
            return AssignmentStmt(target=expr, value=value, source_location=loc)

        # Check for compound assignment
        compound_ops: dict[int, str] = {
            TOK_PLUSEQ: "+",
            TOK_MINUSEQ: "-",
            TOK_STAREQ: "*",
            TOK_SLASHEQ: "/",
            TOK_PERCENTEQ: "%",
        }
        for kind, bin_op in compound_ops.items():
            if self.match(kind):
                right = self._parse_move_expression()
                self.expect(TOK_SEMICOLON)
                value = BinaryExpr(op=bin_op, left=expr, right=right)
                return AssignmentStmt(target=expr, value=value, source_location=loc)

        self.match(TOK_SEMICOLON)
        return ExpressionStmt(expr=expr, source_location=loc)

    # -- Expression parsing (recursive descent with precedence) ---------------

    def _parse_move_expression(self) -> Expression:
        return self._parse_move_or()

    def _parse_move_or(self) -> Expression:
        left = self._parse_move_and()
        while self.match(TOK_PIPEPIPE):
            right = self._parse_move_and()
            left = BinaryExpr(op="||", left=left, right=right)
        return left

    def _parse_move_and(self) -> Expression:
        left = self._parse_move_bitwise_or()
        while self.match(TOK_AMPAMP):
            right = self._parse_move_bitwise_or()
            left = BinaryExpr(op="&&", left=left, right=right)
        return left

    def _parse_move_bitwise_or(self) -> Expression:
        left = self._parse_move_bitwise_xor()
        while self.match(TOK_PIPE):
            right = self._parse_move_bitwise_xor()
            left = BinaryExpr(op="|", left=left, right=right)
        return left

    def _parse_move_bitwise_xor(self) -> Expression:
        left = self._parse_move_bitwise_and()
        while self.match(TOK_CARET):
            right = self._parse_move_bitwise_and()
            left = BinaryExpr(op="^", left=left, right=right)
        return left

    def _parse_move_bitwise_and(self) -> Expression:
        left = self._parse_move_equality()
        while self.match(TOK_AMP):
            right = self._parse_move_equality()
            left = BinaryExpr(op="&", left=left, right=right)
        return left

    def _parse_move_equality(self) -> Expression:
        left = self._parse_move_comparison()
        while True:
            if self.match(TOK_EQEQ):
                right = self._parse_move_comparison()
                left = BinaryExpr(op="===", left=left, right=right)  # Map == to ===
            elif self.match(TOK_NOTEQ):
                right = self._parse_move_comparison()
                left = BinaryExpr(op="!==", left=left, right=right)  # Map != to !==
            else:
                break
        return left

    def _parse_move_comparison(self) -> Expression:
        left = self._parse_move_additive()
        while True:
            if self.match(TOK_LT):
                right = self._parse_move_additive()
                left = BinaryExpr(op="<", left=left, right=right)
            elif self.match(TOK_LTEQ):
                right = self._parse_move_additive()
                left = BinaryExpr(op="<=", left=left, right=right)
            elif self.match(TOK_GT):
                right = self._parse_move_additive()
                left = BinaryExpr(op=">", left=left, right=right)
            elif self.match(TOK_GTEQ):
                right = self._parse_move_additive()
                left = BinaryExpr(op=">=", left=left, right=right)
            else:
                break
        return left

    def _parse_move_additive(self) -> Expression:
        left = self._parse_move_multiplicative()
        while True:
            if self.match(TOK_PLUS):
                right = self._parse_move_multiplicative()
                left = BinaryExpr(op="+", left=left, right=right)
            elif self.match(TOK_MINUS):
                right = self._parse_move_multiplicative()
                left = BinaryExpr(op="-", left=left, right=right)
            else:
                break
        return left

    def _parse_move_multiplicative(self) -> Expression:
        left = self._parse_move_unary()
        while True:
            if self.match(TOK_STAR):
                right = self._parse_move_unary()
                left = BinaryExpr(op="*", left=left, right=right)
            elif self.match(TOK_SLASH):
                right = self._parse_move_unary()
                left = BinaryExpr(op="/", left=left, right=right)
            elif self.match(TOK_PERCENT):
                right = self._parse_move_unary()
                left = BinaryExpr(op="%", left=left, right=right)
            else:
                break
        return left

    def _parse_move_unary(self) -> Expression:
        if self.match(TOK_BANG):
            operand = self._parse_move_unary()
            return UnaryExpr(op="!", operand=operand)
        if self.match(TOK_MINUS):
            operand = self._parse_move_unary()
            return UnaryExpr(op="-", operand=operand)
        if self.match(TOK_TILDE):
            operand = self._parse_move_unary()
            return UnaryExpr(op="~", operand=operand)
        # Skip & (reference) -- it's a no-op in the Runar context
        if self.match(TOK_AMP):
            self.match_ident("mut")  # &mut expr -- skip both
            return self._parse_move_unary()
        # Dereference * -- also a no-op
        if self.check(TOK_STAR) and self._is_deref():
            self.advance()
            return self._parse_move_unary()
        return self._parse_move_postfix()

    def _is_deref(self) -> bool:
        # Simple heuristic: if * is followed by an identifier or (, it's a dereference
        if self.pos + 1 < len(self.tokens):
            nxt = self.tokens[self.pos + 1]
            return nxt.kind == TOK_IDENT or nxt.kind == TOK_LPAREN
        return False

    def _parse_move_postfix(self) -> Expression:
        expr = self._parse_move_primary()
        while True:
            if self.match(TOK_DOT):
                prop_tok = self.expect(TOK_IDENT)
                prop_name = _snake_to_camel(prop_tok.value)

                # Check if this is a method call
                if self.check(TOK_LPAREN):
                    args = self._parse_move_call_args()
                    # Handle contract.field -> PropertyAccessExpr
                    if isinstance(expr, Identifier) and expr.name in ("self", "contract"):
                        # contract.method() or self.method()
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
                    if isinstance(expr, Identifier) and expr.name in ("self", "contract"):
                        expr = PropertyAccessExpr(property=prop_name)
                    else:
                        expr = MemberExpr(object=expr, property=prop_name)

            elif self.match(TOK_LBRACKET):
                index = self._parse_move_expression()
                self.expect(TOK_RBRACKET)
                expr = IndexAccessExpr(object=expr, index=index)

            elif self.match(TOK_PLUSPLUS):
                expr = IncrementExpr(operand=expr, prefix=False)

            elif self.match(TOK_MINUSMINUS):
                expr = DecrementExpr(operand=expr, prefix=False)

            else:
                break
        return expr

    def _parse_move_primary(self) -> Expression:
        tok = self.peek()

        if tok.kind == TOK_NUMBER:
            self.advance()
            return _parse_move_number(tok.value)

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
            if name in ("self", "contract"):
                return Identifier(name=name)

            # Handle path access: module::function(...)
            if self.match(TOK_COLONCOLON):
                next_tok = self.expect(TOK_IDENT)
                name = next_tok.value
                # Continue consuming :: segments
                while self.match(TOK_COLONCOLON):
                    next_tok = self.expect(TOK_IDENT)
                    name = next_tok.value

            # Map builtins
            mapped_name = _move_map_builtin(name)

            # Function call
            if self.check(TOK_LPAREN):
                args = self._parse_move_call_args()
                return CallExpr(callee=Identifier(name=mapped_name), args=args)

            return Identifier(name=mapped_name)

        if tok.kind == TOK_LPAREN:
            self.advance()
            expr = self._parse_move_expression()
            self.expect(TOK_RPAREN)
            return expr

        self.add_error(f"line {tok.line}: unexpected token {tok.value!r}")
        self.advance()
        return BigIntLiteral(value=0)

    def _parse_move_call_args(self) -> list[Expression]:
        self.expect(TOK_LPAREN)
        args: list[Expression] = []
        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            arg = self._parse_move_expression()
            args.append(arg)
            if not self.match(TOK_COMMA):
                break
        self.expect(TOK_RPAREN)
        return args

    # -- Constructor builder -------------------------------------------------

    def _build_move_constructor(self, properties: list[PropertyNode]) -> MethodNode:
        # Only include properties without initializers as constructor params
        uninit_props = [p for p in properties if p.initializer is None]

        params: list[ParamNode] = []
        for prop in uninit_props:
            params.append(ParamNode(name=prop.name, type=prop.type))

        super_args: list[Expression] = [
            Identifier(name=prop.name) for prop in uninit_props
        ]

        loc = SourceLocation(file=self.file_name, line=1, column=0)
        body: list[Statement] = [
            ExpressionStmt(
                expr=CallExpr(
                    callee=Identifier(name="super"),
                    args=super_args,
                ),
                source_location=loc,
            ),
        ]
        # Add property assignments: this.prop = prop (only non-initialized)
        for prop in uninit_props:
            body.append(
                AssignmentStmt(
                    target=PropertyAccessExpr(property=prop.name),
                    value=Identifier(name=prop.name),
                    source_location=loc,
                )
            )

        return MethodNode(
            name="constructor",
            params=params,
            body=body,
            visibility="public",
            source_location=SourceLocation(
                file=self.file_name, line=1, column=0,
            ),
        )


# ---------------------------------------------------------------------------
# Number parsing
# ---------------------------------------------------------------------------

def _parse_move_number(s: str) -> Expression:
    # Strip type suffixes like u64, u128, etc.
    for suffix in ("u256", "u128", "u64", "u32", "u16", "u8"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    try:
        val = int(s, 0)
    except ValueError:
        val = 0
    return BigIntLiteral(value=val)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_move(source: str, file_name: str) -> ParseResult:
    """Parse a Move-syntax Runar contract (.runar.move)."""
    p = _MoveParser(file_name)
    p.tokens = _tokenize(source)
    p.pos = 0

    try:
        contract = p.parse_module()
    except ValueError as e:
        return ParseResult(errors=[Diagnostic(message=str(e), severity=Severity.ERROR)])

    if p.errors:
        return ParseResult(contract=contract, errors=p.errors)
    return ParseResult(contract=contract)
