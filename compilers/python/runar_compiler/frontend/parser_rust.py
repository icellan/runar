"""Rust DSL parser (.runar.rs) for the Runar compiler.

Ported from compilers/rust/src/frontend/parser_rustmacro.rs.
Hand-written tokenizer + recursive descent parser.
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
TOK_HEX_STRING = 3
TOK_LPAREN = 4
TOK_RPAREN = 5
TOK_LBRACE = 6
TOK_RBRACE = 7
TOK_LBRACKET = 8
TOK_RBRACKET = 9
TOK_SEMI = 10
TOK_COMMA = 11
TOK_DOT = 12
TOK_COLON = 13
TOK_COLONCOLON = 14
TOK_ARROW = 15
TOK_PLUS = 16
TOK_MINUS = 17
TOK_STAR = 18
TOK_SLASH = 19
TOK_PERCENT = 20
TOK_EQEQ = 21
TOK_BANGEQ = 22
TOK_LT = 23
TOK_LTEQ = 24
TOK_GT = 25
TOK_GTEQ = 26
TOK_AMPAMP = 27
TOK_PIPEPIPE = 28
TOK_AMP = 29
TOK_PIPE = 30
TOK_CARET = 31
TOK_TILDE = 32
TOK_BANG = 33
TOK_EQ = 34
TOK_PLUSEQ = 35
TOK_MINUSEQ = 36
TOK_HASH_BRACKET = 37
# Keywords
TOK_USE = 50
TOK_STRUCT = 51
TOK_IMPL = 52
TOK_FN = 53
TOK_PUB = 54
TOK_LET = 55
TOK_MUT = 56
TOK_IF = 57
TOK_ELSE = 58
TOK_FOR = 59
TOK_RETURN = 60
TOK_IN = 61
TOK_TRUE = 62
TOK_FALSE = 63
TOK_SELF = 64
TOK_ASSERT_MACRO = 65
TOK_ASSERT_EQ_MACRO = 66
TOK_LSHIFT = 67
TOK_RSHIFT = 68
TOK_DOTDOT = 69


class Token:
    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind: int, value: str, line: int, col: int):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# Name conversion: snake_case -> camelCase
# ---------------------------------------------------------------------------

_SPECIAL_BUILTINS: dict[str, str] = {
    "bool_cast": "bool",
    "verify_wots": "verifyWOTS",
    "verify_slh_dsa_sha2_128s": "verifySLHDSA_SHA2_128s",
    "verify_slh_dsa_sha2_128f": "verifySLHDSA_SHA2_128f",
    "verify_slh_dsa_sha2_192s": "verifySLHDSA_SHA2_192s",
    "verify_slh_dsa_sha2_192f": "verifySLHDSA_SHA2_192f",
    "verify_slh_dsa_sha2_256s": "verifySLHDSA_SHA2_256s",
    "verify_slh_dsa_sha2_256f": "verifySLHDSA_SHA2_256f",
    "bin_2_num": "bin2num",
    "int_2_str": "int2str",
    "to_byte_string": "toByteString",
}


def _snake_to_camel(name: str) -> str:
    """Convert snake_case to camelCase."""
    parts = name.split("_")
    if len(parts) <= 1:
        return name
    result = parts[0]
    for part in parts[1:]:
        if part:
            result += part[0].upper() + part[1:]
    return result


def _map_rust_builtin(name: str) -> str:
    """Map a Rust snake_case builtin name to the Runar camelCase equivalent."""
    if name in _SPECIAL_BUILTINS:
        return _SPECIAL_BUILTINS[name]

    camel = _snake_to_camel(name)

    # Known builtins where snake_to_camel produces the correct result
    _KNOWN: set[str] = {
        "hash160", "hash256", "sha256", "ripemd160",
        "checkSig", "checkMultiSig", "checkPreimage",
        "verifyRabinSig",
        "num2bin", "bin2num", "int2str",
        "extractLocktime", "extractOutputHash", "extractVersion",
        "extractHashPrevouts", "extractHashSequence", "extractOutpoint",
        "extractInputIndex", "extractScriptCode", "extractAmount",
        "extractSequence", "extractOutputs", "extractSigHashType",
        "addOutput", "reverseBytes", "toByteString",
    }
    if camel in _KNOWN:
        return camel

    return camel


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, str] = {
    "Bigint": "bigint",
    "Int": "bigint",
    "i64": "bigint",
    "u64": "bigint",
    "i128": "bigint",
    "u128": "bigint",
    "bigint": "bigint",
    "Bool": "boolean",
    "bool": "boolean",
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
}


def _map_rust_type(name: str) -> str:
    if name in _TYPE_MAP:
        return _TYPE_MAP[name]
    return name


def _parse_type_name(name: str) -> TypeNode:
    mapped = _map_rust_type(name)
    if is_primitive_type(mapped):
        return PrimitiveType(name=mapped)
    return CustomType(name=mapped)


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_KEYWORDS: dict[str, int] = {
    "use": TOK_USE,
    "struct": TOK_STRUCT,
    "impl": TOK_IMPL,
    "fn": TOK_FN,
    "pub": TOK_PUB,
    "let": TOK_LET,
    "mut": TOK_MUT,
    "if": TOK_IF,
    "else": TOK_ELSE,
    "for": TOK_FOR,
    "return": TOK_RETURN,
    "in": TOK_IN,
    "true": TOK_TRUE,
    "false": TOK_FALSE,
    "self": TOK_SELF,
}


def _is_hex_digit(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    chars = source
    n = len(chars)
    pos = 0
    line = 1
    col = 1

    while pos < n:
        ch = chars[pos]

        # Whitespace
        if ch in (" ", "\t", "\r", "\n"):
            if ch == "\n":
                line += 1
                col = 1
            else:
                col += 1
            pos += 1
            continue

        # Line comments
        if ch == "/" and pos + 1 < n and chars[pos + 1] == "/":
            while pos < n and chars[pos] != "\n":
                pos += 1
            continue

        # Block comments
        if ch == "/" and pos + 1 < n and chars[pos + 1] == "*":
            pos += 2
            col += 2
            while pos + 1 < n:
                if chars[pos] == "\n":
                    line += 1
                    col = 1
                if chars[pos] == "*" and chars[pos + 1] == "/":
                    pos += 2
                    col += 2
                    break
                pos += 1
                col += 1
            continue

        l = line
        c = col

        # #[ attribute
        if ch == "#" and pos + 1 < n and chars[pos + 1] == "[":
            tokens.append(Token(TOK_HASH_BRACKET, "#[", l, c))
            pos += 2
            col += 2
            continue

        # Two-character operators
        if pos + 1 < n:
            two = chars[pos:pos + 2]
            two_kind = {
                "::": TOK_COLONCOLON,
                "->": TOK_ARROW,
                "==": TOK_EQEQ,
                "!=": TOK_BANGEQ,
                "<=": TOK_LTEQ,
                ">=": TOK_GTEQ,
                "&&": TOK_AMPAMP,
                "||": TOK_PIPEPIPE,
                "+=": TOK_PLUSEQ,
                "-=": TOK_MINUSEQ,
                "<<": TOK_LSHIFT,
                ">>": TOK_RSHIFT,
                "..": TOK_DOTDOT,
            }.get(two)
            if two_kind is not None:
                tokens.append(Token(two_kind, two, l, c))
                pos += 2
                col += 2
                continue

        # Single-character tokens
        single_map = {
            "(": TOK_LPAREN,
            ")": TOK_RPAREN,
            "{": TOK_LBRACE,
            "}": TOK_RBRACE,
            "[": TOK_LBRACKET,
            "]": TOK_RBRACKET,
            ";": TOK_SEMI,
            ",": TOK_COMMA,
            ".": TOK_DOT,
            ":": TOK_COLON,
            "+": TOK_PLUS,
            "-": TOK_MINUS,
            "*": TOK_STAR,
            "/": TOK_SLASH,
            "%": TOK_PERCENT,
            "<": TOK_LT,
            ">": TOK_GT,
            "&": TOK_AMP,
            "|": TOK_PIPE,
            "^": TOK_CARET,
            "~": TOK_TILDE,
            "!": TOK_BANG,
            "=": TOK_EQ,
        }
        single_kind = single_map.get(ch)
        if single_kind is not None:
            tokens.append(Token(single_kind, ch, l, c))
            pos += 1
            col += 1
            continue

        # Hex literal: 0x...
        if ch == "0" and pos + 1 < n and chars[pos + 1] in ("x", "X"):
            pos += 2
            col += 2
            start = pos
            while pos < n and _is_hex_digit(chars[pos]):
                pos += 1
                col += 1
            val = chars[start:pos]
            tokens.append(Token(TOK_HEX_STRING, val, l, c))
            continue

        # Double-quoted string literal — treated as hex ByteString like in TS/Sol/Move
        if ch == '"':
            pos += 1
            col += 1
            start = pos
            while pos < n and chars[pos] != '"':
                if chars[pos] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                pos += 1
            val = chars[start:pos]
            if pos < n:
                pos += 1  # skip closing quote
                col += 1
            tokens.append(Token(TOK_HEX_STRING, val, l, c))
            continue

        # Number
        if ch.isdigit():
            start = pos
            while pos < n and (chars[pos].isdigit() or chars[pos] == "_"):
                pos += 1
                col += 1
            val = chars[start:pos].replace("_", "")
            tokens.append(Token(TOK_NUMBER, val, l, c))
            continue

        # Identifier / keyword
        if ch.isalpha() or ch == "_":
            start = pos
            while pos < n and (chars[pos].isalnum() or chars[pos] == "_"):
                pos += 1
                col += 1
            word = chars[start:pos]

            # Check for assert!/assert_eq!
            if word in ("assert", "assert_eq") and pos < n and chars[pos] == "!":
                pos += 1
                col += 1
                if word == "assert":
                    tokens.append(Token(TOK_ASSERT_MACRO, "assert!", l, c))
                else:
                    tokens.append(Token(TOK_ASSERT_EQ_MACRO, "assert_eq!", l, c))
                continue

            kw_kind = _KEYWORDS.get(word)
            if kw_kind is not None:
                tokens.append(Token(kw_kind, word, l, c))
            else:
                tokens.append(Token(TOK_IDENT, word, l, c))
            continue

        # Unknown character -- skip
        pos += 1
        col += 1

    tokens.append(Token(TOK_EOF, "", line, col))
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _RustParser:
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
        return self.tokens[-1] if self.tokens else Token(TOK_EOF, "", 0, 0)

    def advance(self) -> Token:
        tok = self.peek()
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return tok

    def expect(self, kind: int) -> Token:
        tok = self.peek()
        if tok.kind != kind:
            self.add_error(
                f"line {tok.line}:{tok.col}: expected token kind {kind}, "
                f"got {tok.kind} ({tok.value!r})"
            )
        return self.advance()

    def check(self, kind: int) -> bool:
        return self.peek().kind == kind

    def match_tok(self, kind: int) -> bool:
        if self.check(kind):
            self.advance()
            return True
        return False

    def loc(self) -> SourceLocation:
        tok = self.peek()
        return SourceLocation(file=self.file_name, line=tok.line, column=tok.col)

    # -- Attribute parsing ---------------------------------------------------

    def parse_attribute(self) -> str:
        """Parse #[...] attribute content. The #[ token is already current."""
        self.advance()  # consume #[
        attr = ""
        depth = 1
        while depth > 0 and not self.check(TOK_EOF):
            tok = self.peek()
            if tok.kind == TOK_LBRACKET:
                depth += 1
                self.advance()
            elif tok.kind == TOK_RBRACKET:
                depth -= 1
                if depth == 0:
                    self.advance()
                    break
                self.advance()
            elif tok.kind == TOK_IDENT:
                attr += tok.value
                self.advance()
            elif tok.kind == TOK_COLONCOLON:
                attr += "::"
                self.advance()
            elif tok.kind == TOK_LPAREN:
                attr += "("
                self.advance()
            elif tok.kind == TOK_RPAREN:
                attr += ")"
                self.advance()
            else:
                self.advance()
        return attr

    # -- Type parsing --------------------------------------------------------

    def parse_rust_type(self) -> TypeNode:
        tok = self.peek()
        if tok.kind == TOK_IDENT:
            name = tok.value
            self.advance()

            # Handle FixedArray<T, N> syntax (Vec<T> is not FixedArray)
            if name == "FixedArray" and self.check(TOK_LT):
                self.advance()  # consume <
                elem_type = self.parse_rust_type()
                self.expect(TOK_COMMA)
                size_tok = self.expect(TOK_NUMBER)
                try:
                    size = int(size_tok.value)
                except ValueError:
                    size = 0
                    self.add_error(f"line {size_tok.line}: FixedArray size must be integer")
                self.expect(TOK_GT)
                return FixedArrayType(element=elem_type, length=size)

            # Skip generic parameters like Vec<u8>
            if self.check(TOK_LT):
                self.advance()
                depth = 1
                while depth > 0 and not self.check(TOK_EOF):
                    if self.check(TOK_LT):
                        depth += 1
                    elif self.check(TOK_GT):
                        depth -= 1
                        if depth == 0:
                            self.advance()
                            break
                    self.advance()

            return _parse_type_name(name)

        self.advance()
        return CustomType(name="unknown")

    # -- Top-level parsing ---------------------------------------------------

    def parse_contract(self) -> ContractNode:
        # Skip use declarations
        while self.check(TOK_USE):
            while not self.check(TOK_SEMI) and not self.check(TOK_EOF):
                self.advance()
            if self.check(TOK_SEMI):
                self.advance()

        properties: list[PropertyNode] = []
        contract_name = ""
        parent_class = "SmartContract"
        methods: list[MethodNode] = []

        while not self.check(TOK_EOF):
            # Attribute: #[...]
            if self.check(TOK_HASH_BRACKET):
                attr = self.parse_attribute()

                if attr in ("runar::contract", "runar::stateful_contract"):
                    if attr == "runar::stateful_contract":
                        parent_class = "StatefulSmartContract"

                    # Parse struct
                    if self.check(TOK_PUB):
                        self.advance()
                    self.expect(TOK_STRUCT)

                    name_tok = self.peek()
                    if name_tok.kind == TOK_IDENT:
                        contract_name = name_tok.value
                        self.advance()

                    self.expect(TOK_LBRACE)

                    while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
                        # Check for #[readonly] attribute on field
                        readonly = False
                        if self.check(TOK_HASH_BRACKET):
                            field_attr = self.parse_attribute()
                            if field_attr == "readonly":
                                readonly = True

                        # Skip optional `pub` visibility modifier
                        if self.check(TOK_PUB):
                            self.advance()

                        field_loc = self.loc()
                        field_tok = self.peek()
                        if field_tok.kind == TOK_IDENT:
                            field_name = field_tok.value
                            self.advance()
                            self.expect(TOK_COLON)
                            field_type = self.parse_rust_type()
                            self.match_tok(TOK_COMMA)

                            # Skip txPreimage — implicit stateful param, not a contract property
                            camel_name = _snake_to_camel(field_name)
                            if camel_name != "txPreimage":
                                properties.append(PropertyNode(
                                    name=camel_name,
                                    type=field_type,
                                    readonly=readonly,
                                    source_location=field_loc,
                                ))
                        else:
                            self.advance()

                    self.expect(TOK_RBRACE)

                elif attr.startswith("runar::methods"):
                    # Parse impl block
                    if self.check(TOK_IMPL):
                        self.advance()
                    # Skip type name
                    if self.peek().kind == TOK_IDENT:
                        self.advance()
                    self.expect(TOK_LBRACE)

                    while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
                        # Check for #[public] attribute
                        visibility = "private"
                        if self.check(TOK_HASH_BRACKET):
                            method_attr = self.parse_attribute()
                            if method_attr == "public":
                                visibility = "public"
                        if self.check(TOK_PUB):
                            self.advance()
                            visibility = "public"
                        methods.append(self.parse_function(visibility))

                    self.expect(TOK_RBRACE)
                else:
                    # Unknown attribute, skip
                    continue
            else:
                self.advance()

        # Determine parent class from property mutability
        if any(not p.readonly for p in properties):
            parent_class = "StatefulSmartContract"

        if not contract_name:
            self.add_error("No Runar contract struct found")
            return ContractNode(
                name="",
                parent_class=parent_class,
                properties=properties,
                constructor=MethodNode(
                    name="constructor",
                    visibility="public",
                    source_location=SourceLocation(file=self.file_name, line=1, column=1),
                ),
                methods=methods,
                source_file=self.file_name,
            )

        # Extract init() method as property initializers, if present.
        # init() is a special private method that sets default values.
        final_methods: list[MethodNode] = []
        for m in methods:
            if m.name == "init" and len(m.params) == 0:
                for stmt in m.body:
                    if isinstance(stmt, AssignmentStmt) and isinstance(stmt.target, PropertyAccessExpr):
                        for prop in properties:
                            if prop.name == stmt.target.property:
                                prop.initializer = stmt.value
                                break
            else:
                final_methods.append(m)
        methods = final_methods

        # Build auto-generated constructor (only non-initialized properties)
        uninit_props = [p for p in properties if p.initializer is None]
        ctor_loc = SourceLocation(file=self.file_name, line=1, column=1)

        # super(...) call as first statement
        super_args: list[Expression] = [
            Identifier(name=p.name) for p in uninit_props
        ]
        super_call = ExpressionStmt(
            expr=CallExpr(
                callee=Identifier(name="super"),
                args=super_args,
            ),
            source_location=ctor_loc,
        )

        # Property assignments: this.x = x (only non-initialized)
        ctor_body: list[Statement] = [super_call]
        for p in uninit_props:
            ctor_body.append(AssignmentStmt(
                target=PropertyAccessExpr(property=p.name),
                value=Identifier(name=p.name),
                source_location=ctor_loc,
            ))

        constructor = MethodNode(
            name="constructor",
            params=[ParamNode(name=p.name, type=p.type) for p in uninit_props],
            body=ctor_body,
            visibility="public",
            source_location=ctor_loc,
        )

        return ContractNode(
            name=contract_name,
            parent_class=parent_class,
            properties=properties,
            constructor=constructor,
            methods=methods,
            source_file=self.file_name,
        )

    # -- Function parsing ----------------------------------------------------

    def parse_function(self, visibility: str) -> MethodNode:
        func_loc = self.loc()
        self.expect(TOK_FN)

        raw_name = "unknown"
        if self.peek().kind == TOK_IDENT:
            raw_name = self.peek().value
            self.advance()
        else:
            self.advance()

        name = _snake_to_camel(raw_name)

        self.expect(TOK_LPAREN)
        params: list[ParamNode] = []

        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            # Skip &self, &mut self
            if self.check(TOK_AMP):
                self.advance()
                if self.check(TOK_MUT):
                    self.advance()
                if self.check(TOK_SELF):
                    self.advance()
                    self.match_tok(TOK_COMMA)
                    continue
            if self.check(TOK_SELF):
                self.advance()
                self.match_tok(TOK_COMMA)
                continue

            param_tok = self.peek()
            if param_tok.kind == TOK_IDENT:
                param_name = param_tok.value
                self.advance()
                self.expect(TOK_COLON)
                # Skip & and &mut before type
                if self.check(TOK_AMP):
                    self.advance()
                    if self.check(TOK_MUT):
                        self.advance()
                param_type = self.parse_rust_type()
                params.append(ParamNode(
                    name=_snake_to_camel(param_name),
                    type=param_type,
                ))
            else:
                self.advance()
            self.match_tok(TOK_COMMA)

        self.expect(TOK_RPAREN)

        # Optional return type
        has_return_type = False
        if self.check(TOK_ARROW):
            has_return_type = True
            self.advance()
            self.parse_rust_type()

        self.expect(TOK_LBRACE)
        body: list[Statement] = []
        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            stmt = self.parse_statement()
            if stmt is not None:
                body.append(stmt)
        self.expect(TOK_RBRACE)

        # Rust implicit return: convert last ExpressionStmt to ReturnStmt
        if has_return_type and body and isinstance(body[-1], ExpressionStmt):
            last = body[-1]
            body[-1] = ReturnStmt(value=last.expr, source_location=last.source_location)

        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility=visibility,
            source_location=func_loc,
        )

    # -- Statement parsing ---------------------------------------------------

    def parse_statement(self) -> Statement | None:
        stmt_loc = self.loc()

        # assert!(expr)
        if self.check(TOK_ASSERT_MACRO):
            self.advance()
            self.expect(TOK_LPAREN)
            expr = self.parse_expression()
            self.expect(TOK_RPAREN)
            self.match_tok(TOK_SEMI)
            return ExpressionStmt(
                expr=CallExpr(
                    callee=Identifier(name="assert"),
                    args=[expr],
                ),
                source_location=stmt_loc,
            )

        # assert_eq!(a, b) -> assert(a === b)
        if self.check(TOK_ASSERT_EQ_MACRO):
            self.advance()
            self.expect(TOK_LPAREN)
            left = self.parse_expression()
            self.expect(TOK_COMMA)
            right = self.parse_expression()
            self.expect(TOK_RPAREN)
            self.match_tok(TOK_SEMI)
            return ExpressionStmt(
                expr=CallExpr(
                    callee=Identifier(name="assert"),
                    args=[BinaryExpr(op="===", left=left, right=right)],
                ),
                source_location=stmt_loc,
            )

        # let [mut] name [: type] = expr;
        if self.check(TOK_LET):
            self.advance()
            mutable = self.match_tok(TOK_MUT)

            var_name = "unknown"
            if self.peek().kind == TOK_IDENT:
                var_name = _snake_to_camel(self.peek().value)
                self.advance()
            else:
                self.advance()

            var_type: TypeNode | None = None
            if self.check(TOK_COLON):
                self.advance()
                if self.check(TOK_AMP):
                    self.advance()
                if self.check(TOK_MUT):
                    self.advance()
                var_type = self.parse_rust_type()

            self.expect(TOK_EQ)
            init = self.parse_expression()
            self.match_tok(TOK_SEMI)
            return VariableDeclStmt(
                name=var_name,
                type=var_type,
                mutable=mutable,
                init=init,
                source_location=stmt_loc,
            )

        # if
        if self.check(TOK_IF):
            self.advance()
            condition = self.parse_expression()
            self.expect(TOK_LBRACE)
            then_block: list[Statement] = []
            while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
                s = self.parse_statement()
                if s is not None:
                    then_block.append(s)
            self.expect(TOK_RBRACE)

            else_block: list[Statement] = []
            if self.check(TOK_ELSE):
                self.advance()
                if self.check(TOK_IF):
                    # else if -> nested IfStmt in else branch
                    nested = self.parse_statement()
                    if nested is not None:
                        else_block = [nested]
                else:
                    self.expect(TOK_LBRACE)
                    while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
                        s = self.parse_statement()
                        if s is not None:
                            else_block.append(s)
                    self.expect(TOK_RBRACE)

            return IfStmt(
                condition=condition,
                then=then_block,
                else_=else_block,
                source_location=stmt_loc,
            )

        # for var in start..end { ... }
        if self.check(TOK_FOR):
            self.advance()
            var_name = "i"
            if self.peek().kind == TOK_IDENT:
                var_name = _snake_to_camel(self.peek().value)
                self.advance()

            self.expect(TOK_IN)
            start_expr = self.parse_expression()

            # Expect .. range operator (single DotDot token)
            self.expect(TOK_DOTDOT)

            end_expr = self.parse_expression()

            self.expect(TOK_LBRACE)
            loop_body: list[Statement] = []
            while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
                s = self.parse_statement()
                if s is not None:
                    loop_body.append(s)
            self.expect(TOK_RBRACE)

            init_stmt = VariableDeclStmt(
                name=var_name,
                type=PrimitiveType(name="bigint"),
                mutable=True,
                init=start_expr,
                source_location=stmt_loc,
            )
            loop_condition = BinaryExpr(
                op="<",
                left=Identifier(name=var_name),
                right=end_expr,
            )
            update = ExpressionStmt(
                expr=IncrementExpr(operand=Identifier(name=var_name), prefix=False),
                source_location=stmt_loc,
            )

            return ForStmt(
                init=init_stmt,
                condition=loop_condition,
                update=update,
                body=loop_body,
                source_location=stmt_loc,
            )

        # return
        if self.check(TOK_RETURN):
            self.advance()
            value: Expression | None = None
            if not self.check(TOK_SEMI) and not self.check(TOK_RBRACE):
                value = self.parse_expression()
            self.match_tok(TOK_SEMI)
            return ReturnStmt(value=value, source_location=stmt_loc)

        # Expression statement (possibly assignment)
        expr = self.parse_expression()

        # Assignment: target = value
        if self.check(TOK_EQ):
            self.advance()
            value_expr = self.parse_expression()
            self.match_tok(TOK_SEMI)
            target = self._convert_self_access(expr)
            return AssignmentStmt(
                target=target,
                value=value_expr,
                source_location=stmt_loc,
            )

        # Compound assignment: +=
        if self.check(TOK_PLUSEQ):
            self.advance()
            rhs = self.parse_expression()
            self.match_tok(TOK_SEMI)
            target = self._convert_self_access(expr)
            return AssignmentStmt(
                target=target,
                value=BinaryExpr(op="+", left=target, right=rhs),
                source_location=stmt_loc,
            )

        # Compound assignment: -=
        if self.check(TOK_MINUSEQ):
            self.advance()
            rhs = self.parse_expression()
            self.match_tok(TOK_SEMI)
            target = self._convert_self_access(expr)
            return AssignmentStmt(
                target=target,
                value=BinaryExpr(op="-", left=target, right=rhs),
                source_location=stmt_loc,
            )

        self.match_tok(TOK_SEMI)
        return ExpressionStmt(expr=expr, source_location=stmt_loc)

    def _convert_self_access(self, expr: Expression) -> Expression:
        """Convert self.field -> PropertyAccessExpr."""
        if isinstance(expr, MemberExpr):
            if isinstance(expr.object, Identifier) and expr.object.name == "self":
                return PropertyAccessExpr(property=_snake_to_camel(expr.property))
        return expr

    # -- Expression parsing (precedence climbing) ----------------------------

    def parse_expression(self) -> Expression:
        return self._parse_or()

    def _parse_or(self) -> Expression:
        left = self._parse_and()
        while self.match_tok(TOK_PIPEPIPE):
            right = self._parse_and()
            left = BinaryExpr(op="||", left=left, right=right)
        return left

    def _parse_and(self) -> Expression:
        left = self._parse_bit_or()
        while self.match_tok(TOK_AMPAMP):
            right = self._parse_bit_or()
            left = BinaryExpr(op="&&", left=left, right=right)
        return left

    def _parse_bit_or(self) -> Expression:
        left = self._parse_bit_xor()
        while self.match_tok(TOK_PIPE):
            right = self._parse_bit_xor()
            left = BinaryExpr(op="|", left=left, right=right)
        return left

    def _parse_bit_xor(self) -> Expression:
        left = self._parse_bit_and()
        while self.match_tok(TOK_CARET):
            right = self._parse_bit_and()
            left = BinaryExpr(op="^", left=left, right=right)
        return left

    def _parse_bit_and(self) -> Expression:
        left = self._parse_equality()
        while self.match_tok(TOK_AMP):
            right = self._parse_equality()
            left = BinaryExpr(op="&", left=left, right=right)
        return left

    def _parse_equality(self) -> Expression:
        left = self._parse_comparison()
        while True:
            if self.match_tok(TOK_EQEQ):
                right = self._parse_comparison()
                left = BinaryExpr(op="===", left=left, right=right)
            elif self.match_tok(TOK_BANGEQ):
                right = self._parse_comparison()
                left = BinaryExpr(op="!==", left=left, right=right)
            else:
                break
        return left

    def _parse_comparison(self) -> Expression:
        left = self._parse_shift()
        while True:
            if self.match_tok(TOK_LT):
                right = self._parse_shift()
                left = BinaryExpr(op="<", left=left, right=right)
            elif self.match_tok(TOK_LTEQ):
                right = self._parse_shift()
                left = BinaryExpr(op="<=", left=left, right=right)
            elif self.match_tok(TOK_GT):
                right = self._parse_shift()
                left = BinaryExpr(op=">", left=left, right=right)
            elif self.match_tok(TOK_GTEQ):
                right = self._parse_shift()
                left = BinaryExpr(op=">=", left=left, right=right)
            else:
                break
        return left

    def _parse_shift(self) -> Expression:
        left = self._parse_add_sub()
        while True:
            if self.match_tok(TOK_LSHIFT):
                right = self._parse_add_sub()
                left = BinaryExpr(op="<<", left=left, right=right)
            elif self.match_tok(TOK_RSHIFT):
                right = self._parse_add_sub()
                left = BinaryExpr(op=">>", left=left, right=right)
            else:
                break
        return left

    def _parse_add_sub(self) -> Expression:
        left = self._parse_mul_div()
        while True:
            if self.match_tok(TOK_PLUS):
                right = self._parse_mul_div()
                left = BinaryExpr(op="+", left=left, right=right)
            elif self.match_tok(TOK_MINUS):
                right = self._parse_mul_div()
                left = BinaryExpr(op="-", left=left, right=right)
            else:
                break
        return left

    def _parse_mul_div(self) -> Expression:
        left = self._parse_unary()
        while True:
            if self.match_tok(TOK_STAR):
                right = self._parse_unary()
                left = BinaryExpr(op="*", left=left, right=right)
            elif self.match_tok(TOK_SLASH):
                right = self._parse_unary()
                left = BinaryExpr(op="/", left=left, right=right)
            elif self.match_tok(TOK_PERCENT):
                right = self._parse_unary()
                left = BinaryExpr(op="%", left=left, right=right)
            else:
                break
        return left

    def _parse_unary(self) -> Expression:
        if self.match_tok(TOK_BANG):
            return UnaryExpr(op="!", operand=self._parse_unary())
        if self.match_tok(TOK_MINUS):
            return UnaryExpr(op="-", operand=self._parse_unary())
        if self.match_tok(TOK_TILDE):
            return UnaryExpr(op="~", operand=self._parse_unary())
        # & and &mut are borrow operators -- ignore them for AST purposes
        if self.check(TOK_AMP):
            self.advance()
            if self.check(TOK_MUT):
                self.advance()
            return self._parse_postfix()
        return self._parse_postfix()

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()

        while True:
            # Function call: expr(args)
            if self.check(TOK_LPAREN):
                self.advance()
                args: list[Expression] = []
                while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
                    args.append(self.parse_expression())
                    if self.check(TOK_COMMA):
                        self.advance()
                self.expect(TOK_RPAREN)
                # `.clone()` is a Rust borrow-checker artifact — in Runar,
                # values are copied by default, so strip it and keep the
                # receiver expression unchanged.
                if (
                    not args
                    and isinstance(expr, MemberExpr)
                    and expr.property == "clone"
                ):
                    expr = expr.object
                    continue
                expr = CallExpr(callee=expr, args=args)

            # Member access: expr.field
            elif self.check(TOK_DOT):
                self.advance()
                prop = "unknown"
                if self.peek().kind == TOK_IDENT:
                    prop = _snake_to_camel(self.peek().value)
                    self.advance()
                else:
                    self.advance()

                # self.field -> PropertyAccessExpr
                if isinstance(expr, Identifier) and expr.name == "self":
                    expr = PropertyAccessExpr(property=prop)
                    continue

                expr = MemberExpr(object=expr, property=prop)

            # Path separator: expr::name
            elif self.check(TOK_COLONCOLON):
                self.advance()
                if self.peek().kind == TOK_IDENT:
                    name = _snake_to_camel(self.peek().value)
                    self.advance()
                    expr = Identifier(name=name)

            # Index access: expr[index]
            elif self.check(TOK_LBRACKET):
                self.advance()
                index = self.parse_expression()
                self.expect(TOK_RBRACKET)
                expr = IndexAccessExpr(object=expr, index=index)

            else:
                break

        return expr

    def _parse_primary(self) -> Expression:
        tok = self.peek()

        if tok.kind == TOK_NUMBER:
            self.advance()
            try:
                val = int(tok.value)
            except ValueError:
                val = 0
            return BigIntLiteral(value=val)

        if tok.kind == TOK_HEX_STRING:
            self.advance()
            return ByteStringLiteral(value=tok.value)

        if tok.kind == TOK_TRUE:
            self.advance()
            return BoolLiteral(value=True)

        if tok.kind == TOK_FALSE:
            self.advance()
            return BoolLiteral(value=False)

        if tok.kind == TOK_SELF:
            self.advance()
            return Identifier(name="self")

        if tok.kind == TOK_LPAREN:
            self.advance()
            expr = self.parse_expression()
            self.expect(TOK_RPAREN)
            return expr

        if tok.kind == TOK_LBRACKET:
            return self._parse_array_literal()

        if tok.kind == TOK_IDENT:
            self.advance()
            mapped = _map_rust_builtin(tok.value)
            return Identifier(name=mapped)

        self.add_error(
            f"unsupported token {tok.value!r} (kind {tok.kind}) "
            f"at {tok.line}:{tok.col}"
        )
        self.advance()
        return Identifier(name="unknown")

    def _parse_array_literal(self) -> Expression:
        """Parse [elem1, elem2, ...]."""
        self.expect(TOK_LBRACKET)
        elements: list[Expression] = []
        while not self.check(TOK_RBRACKET) and not self.check(TOK_EOF):
            elements.append(self.parse_expression())
            if not self.match_tok(TOK_COMMA):
                break
        self.expect(TOK_RBRACKET)
        return CallExpr(callee=Identifier(name="FixedArray"), args=elements)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_rust(source: str, file_name: str) -> ParseResult:
    """Parse a Rust-syntax Runar contract (.runar.rs)."""
    p = _RustParser(file_name)
    p.tokens = _tokenize(source)
    p.pos = 0

    try:
        contract = p.parse_contract()
    except Exception as e:
        return ParseResult(errors=[Diagnostic(message=str(e), severity=Severity.ERROR)])

    if p.errors:
        return ParseResult(contract=contract, errors=p.errors)
    return ParseResult(contract=contract)
