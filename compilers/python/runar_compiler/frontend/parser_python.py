"""Python format parser (.runar.py) for the Runar compiler.

Ported from compilers/go/frontend/parser_python.go.
Hand-written tokenizer with INDENT/DEDENT + recursive descent parser.
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
TOK_PLUSEQ = 33
TOK_MINUSEQ = 34
TOK_STAREQ = 35
TOK_SLASHEQ = 36
TOK_PERCENTEQ = 37
TOK_AT = 38
TOK_SLASHSLASH = 39
TOK_STARSTAR = 40
TOK_ARROW = 41
TOK_LSHIFT = 42
TOK_RSHIFT = 43
TOK_INDENT = 44
TOK_DEDENT = 45
TOK_NEWLINE = 46


class Token:
    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind: int, value: str, line: int, col: int):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# Special name mappings (snake_case -> camelCase)
# ---------------------------------------------------------------------------

_SPECIAL_NAMES: dict[str, str] = {
    "assert_": "assert",
    "__init__": "constructor",
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
    # P-256 (NIST secp256r1)
    "p256_add":               "p256Add",
    "p256_mul":               "p256Mul",
    "p256_mul_gen":           "p256MulGen",
    "p256_negate":            "p256Negate",
    "p256_on_curve":          "p256OnCurve",
    "p256_encode_compressed": "p256EncodeCompressed",
    "verify_ecdsa_p256":      "verifyECDSA_P256",
    # P-384 (NIST secp384r1)
    "p384_add":               "p384Add",
    "p384_mul":               "p384Mul",
    "p384_mul_gen":           "p384MulGen",
    "p384_negate":            "p384Negate",
    "p384_on_curve":          "p384OnCurve",
    "p384_encode_compressed": "p384EncodeCompressed",
    "verify_ecdsa_p384":      "verifyECDSA_P384",
    "add_output": "addOutput",
    "get_state_script": "getStateScript",
    "extract_locktime": "extractLocktime",
    "extract_output_hash": "extractOutputHash",
    "extract_sequence": "extractSequence",
    "extract_version": "extractVersion",
    "extract_amount": "extractAmount",
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
    "sha256": "sha256",
    "ripemd160": "ripemd160",
    "hash160": "hash160",
    "hash256": "hash256",
    "num2bin": "num2bin",
    "bin2num": "bin2num",
    "log2": "log2",
    "div_mod": "divmod",
    "EC_P": "EC_P",
    "EC_N": "EC_N",
    "EC_G": "EC_G",
}


def py_convert_name(name: str) -> str:
    """Convert a Python snake_case name to Runar camelCase."""
    # Check special names first
    if name in _SPECIAL_NAMES:
        return _SPECIAL_NAMES[name]

    # No underscores → return as-is
    if "_" not in name:
        return name

    # Dunder names
    if name.startswith("__") and name.endswith("__"):
        return name

    # Strip trailing underscore
    cleaned = name.rstrip("_")
    if cleaned != name:
        key = cleaned + "_"
        if key in _SPECIAL_NAMES:
            return _SPECIAL_NAMES[key]

    # Strip leading single underscore for private methods
    stripped = name
    if stripped.startswith("_") and not stripped.startswith("__"):
        stripped = stripped[1:]

    # General snake_case to camelCase
    parts = stripped.split("_")
    if len(parts) <= 1:
        return stripped

    result = parts[0]
    for part in parts[1:]:
        if part:
            result += part[0].upper() + part[1:]
    return result


# ---------------------------------------------------------------------------
# Byte string helpers
# ---------------------------------------------------------------------------

def _py_byte_string_to_hex(s: str) -> str:
    """Convert Python byte string content like \\xde\\xad to hex 'dead'."""
    result: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            if s[i + 1] == "x" and i + 3 < len(s):
                result.append(s[i + 2 : i + 4])
                i += 4
                continue
            elif s[i + 1] == "0":
                result.append("00")
                i += 2
                continue
        result.append(f"{ord(s[i]):02x}")
        i += 1
    return "".join(result)


# ---------------------------------------------------------------------------
# Type parsing
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, str] = {
    "int": "bigint",
    "Int": "bigint",
    "Bigint": "bigint",
    "bigint": "bigint",
    "bool": "boolean",
    "Bool": "boolean",
    "boolean": "boolean",
    "bytes": "ByteString",
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
    "P256Point": "P256Point",
    "P384Point": "P384Point",
}


def _parse_py_type(name: str) -> TypeNode:
    if name in _TYPE_MAP:
        return PrimitiveType(name=_TYPE_MAP[name])
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


def _is_hex_digit(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _tokenize_raw(source: str) -> list[Token]:
    """Produce tokens including NEWLINE but without INDENT/DEDENT."""
    tokens: list[Token] = []
    line = 1
    col = 0
    i = 0
    paren_depth = 0
    n = len(source)

    while i < n:
        ch = source[i]

        # Newlines
        if ch == "\n" or ch == "\r":
            if ch == "\r":
                i += 1
                if i < n and source[i] == "\n":
                    i += 1
            else:
                i += 1
            if paren_depth == 0:
                tokens.append(Token(TOK_NEWLINE, "\n", line, col))
            line += 1
            col = 0
            continue

        # Whitespace
        if ch == " " or ch == "\t":
            i += 1
            col += 1
            continue

        # Comment
        if ch == "#":
            while i < n and source[i] != "\n" and source[i] != "\r":
                i += 1
            continue

        start_col = col

        # Byte string literals: b'...' or b"..."
        if ch == "b" and i + 1 < n and source[i + 1] in ("'", '"'):
            quote = source[i + 1]
            i += 2
            col += 2
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
            hex_val = _py_byte_string_to_hex(val)
            tokens.append(Token(TOK_STRING, hex_val, line, start_col))
            continue

        # String literals
        if ch in ("'", '"'):
            quote = ch
            # Triple-quote — always a docstring in Rúnar. Skip without emitting a token.
            if i + 2 < n and source[i + 1] == quote and source[i + 2] == quote:
                i += 3
                col += 3
                while i + 2 < n:
                    if source[i] == quote and source[i + 1] == quote and source[i + 2] == quote:
                        break
                    if source[i] == "\n":
                        line += 1
                        col = 0
                    else:
                        col += 1
                    i += 1
                if i + 2 < n:
                    i += 3
                    col += 3
                continue
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
        if ch.isdigit():
            start = i
            if ch == "0" and i + 1 < n and source[i + 1] in ("x", "X"):
                i += 2
                col += 2
                while i < n and _is_hex_digit(source[i]):
                    i += 1
                    col += 1
            else:
                while i < n and (source[i].isdigit() or source[i] == "_"):
                    i += 1
                    col += 1
            num_str = source[start:i].replace("_", "")
            tokens.append(Token(TOK_NUMBER, num_str, line, start_col))
            continue

        # Identifiers and keywords
        if _is_ident_start(ch):
            start = i
            while i < n and _is_ident_part(source[i]):
                i += 1
                col += 1
            word = source[start:i]

            if word == "and":
                tokens.append(Token(TOK_AMPAMP, "and", line, start_col))
            elif word == "or":
                tokens.append(Token(TOK_PIPEPIPE, "or", line, start_col))
            elif word == "not":
                tokens.append(Token(TOK_BANG, "not", line, start_col))
            else:
                tokens.append(Token(TOK_IDENT, word, line, start_col))
            continue

        # Three-character operators
        if i + 2 < n:
            three = source[i : i + 3]
            if three == "//=":
                tokens.append(Token(TOK_SLASHEQ, "//=", line, start_col))
                i += 3
                col += 3
                continue

        # Two-character operators
        if i + 1 < n:
            two = source[i : i + 2]
            two_kind = {
                "==": TOK_EQEQ,
                "!=": TOK_NOTEQ,
                "<=": TOK_LTEQ,
                ">=": TOK_GTEQ,
                "+=": TOK_PLUSEQ,
                "-=": TOK_MINUSEQ,
                "*=": TOK_STAREQ,
                "%=": TOK_PERCENTEQ,
                "//": TOK_SLASHSLASH,
                "**": TOK_STARSTAR,
                "->": TOK_ARROW,
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
            "@": TOK_AT,
        }
        one_kind = one_map.get(ch)
        if one_kind is not None:
            if ch in ("(", "[", "{"):
                paren_depth += 1
            elif ch in (")", "]", "}"):
                if paren_depth > 0:
                    paren_depth -= 1
            tokens.append(Token(one_kind, ch, line, start_col))
            i += 1
            col += 1
            continue

        # Skip unknown
        i += 1
        col += 1

    # Ensure final NEWLINE
    if not tokens or tokens[-1].kind != TOK_NEWLINE:
        tokens.append(Token(TOK_NEWLINE, "\n", line, col))

    tokens.append(Token(TOK_EOF, "", line, col))
    return tokens


def _insert_indentation(raw: list[Token]) -> list[Token]:
    """Insert INDENT/DEDENT tokens based on leading whitespace."""
    result: list[Token] = []
    indent_stack = [0]
    at_line_start = True
    i = 0

    while i < len(raw):
        tok = raw[i]

        if tok.kind == TOK_NEWLINE:
            result.append(tok)
            at_line_start = True
            i += 1
            continue

        if tok.kind == TOK_EOF:
            while len(indent_stack) > 1:
                result.append(Token(TOK_DEDENT, "", tok.line, tok.col))
                indent_stack.pop()
            result.append(tok)
            break

        if at_line_start:
            at_line_start = False
            indent = tok.col
            current_indent = indent_stack[-1]

            if indent > current_indent:
                indent_stack.append(indent)
                result.append(Token(TOK_INDENT, "", tok.line, tok.col))
            elif indent < current_indent:
                while len(indent_stack) > 1 and indent_stack[-1] > indent:
                    indent_stack.pop()
                    result.append(Token(TOK_DEDENT, "", tok.line, tok.col))

        result.append(tok)
        i += 1

    return result


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _PyParser:
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
            self.add_error(f"line {tok.line}: expected token kind {kind}, got {tok.kind} ({tok.value!r})")
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

    def skip_newlines(self) -> None:
        while self.check(TOK_NEWLINE):
            self.advance()

    # -- Type parsing --------------------------------------------------------

    def parse_type_annotation(self) -> TypeNode:
        tok = self.peek()
        if tok.kind != TOK_IDENT:
            self.add_error(f"line {tok.line}: expected type name, got {tok.value!r}")
            self.advance()
            return CustomType(name="unknown")

        name = tok.value
        self.advance()

        if name == "Readonly":
            if self.match(TOK_LBRACKET):
                inner = self.parse_type_annotation()
                self.expect(TOK_RBRACKET)
                return inner
            return CustomType(name=name)

        if name == "FixedArray":
            if self.match(TOK_LBRACKET):
                elem_type = self.parse_type_annotation()
                self.expect(TOK_COMMA)
                size_tok = self.expect(TOK_NUMBER)
                try:
                    size = int(size_tok.value)
                except ValueError:
                    size = 0
                    self.add_error(f"line {size_tok.line}: FixedArray size must be integer")
                self.expect(TOK_RBRACKET)
                return FixedArrayType(element=elem_type, length=size)
            return CustomType(name=name)

        if self.check(TOK_LBRACKET):
            self.advance()
            depth = 1
            while depth > 0 and not self.check(TOK_EOF):
                if self.check(TOK_LBRACKET):
                    depth += 1
                if self.check(TOK_RBRACKET):
                    depth -= 1
                    if depth == 0:
                        self.advance()
                        break
                self.advance()
            return _parse_py_type(name)

        return _parse_py_type(name)

    # -- Contract parsing ----------------------------------------------------

    def parse_contract(self) -> ContractNode:
        self.skip_newlines()

        # Skip import statements
        while self.check_ident("from") or self.check_ident("import"):
            while not self.check(TOK_NEWLINE) and not self.check(TOK_EOF):
                self.advance()
            self.skip_newlines()

        if not self.match_ident("class"):
            raise ValueError("expected 'class' keyword")

        name_tok = self.expect(TOK_IDENT)
        contract_name = name_tok.value

        parent_class = "SmartContract"
        if self.match(TOK_LPAREN):
            parent_tok = self.expect(TOK_IDENT)
            parent_class = parent_tok.value
            self.expect(TOK_RPAREN)

        if parent_class not in ("SmartContract", "StatefulSmartContract"):
            raise ValueError(f"unknown parent class: {parent_class}")

        self.expect(TOK_COLON)
        self.skip_newlines()
        self.expect(TOK_INDENT)

        properties: list[PropertyNode] = []
        constructor: MethodNode | None = None
        methods: list[MethodNode] = []

        while not self.check(TOK_DEDENT) and not self.check(TOK_EOF):
            self.skip_newlines()
            if self.check(TOK_DEDENT) or self.check(TOK_EOF):
                break

            # Decorator
            if self.check(TOK_AT):
                self.advance()
                decorator_tok = self.expect(TOK_IDENT)
                decorator = decorator_tok.value
                self.skip_newlines()

                if self.check_ident("def"):
                    method = self.parse_method(decorator)
                    methods.append(method)
                else:
                    self.add_error(f"line {self.peek().line}: expected 'def' after @{decorator}")
                continue

            # def __init__ or def method
            if self.check_ident("def"):
                if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].value == "__init__":
                    constructor = self.parse_constructor(properties)
                else:
                    method = self.parse_method("private")
                    methods.append(method)
                continue

            # pass
            if self.match_ident("pass"):
                self.skip_newlines()
                continue

            # Property: name: Type
            if self.peek().kind == TOK_IDENT and self._is_property_decl():
                prop = self.parse_property(parent_class)
                if prop is not None:
                    properties.append(prop)
                continue

            self.advance()

        self.match(TOK_DEDENT)

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

    def _is_property_decl(self) -> bool:
        if self.pos + 1 >= len(self.tokens):
            return False
        return self.tokens[self.pos + 1].kind == TOK_COLON

    # -- Property parsing ----------------------------------------------------

    def parse_property(self, parent_class: str) -> PropertyNode | None:
        location = self.loc()
        name_tok = self.expect(TOK_IDENT)
        prop_name = py_convert_name(name_tok.value)
        self.expect(TOK_COLON)

        is_readonly = False
        if self.check_ident("Readonly"):
            is_readonly = True
        if parent_class == "SmartContract":
            is_readonly = True

        typ_node = self.parse_type_annotation()

        # Parse optional initializer: = value
        initializer = None
        if self.match(TOK_ASSIGN):
            initializer = self.parse_expression()

        self.skip_newlines()

        return PropertyNode(
            name=prop_name,
            type=typ_node,
            readonly=is_readonly,
            initializer=initializer,
            source_location=location,
        )

    # -- Constructor parsing -------------------------------------------------

    def parse_constructor(self, properties: list[PropertyNode]) -> MethodNode:
        location = self.loc()
        self.expect_ident("def")
        self.expect_ident("__init__")

        params = self.parse_params()

        if self.match(TOK_ARROW):
            self.advance()  # skip return type

        self.expect(TOK_COLON)
        body = self.parse_block()

        # Transform super().__init__(...) -> super(...) form
        constructor_body: list[Statement] = []
        found_super = False

        for stmt in body:
            if isinstance(stmt, ExpressionStmt):
                call = stmt.expr
                if isinstance(call, CallExpr) and isinstance(call.callee, MemberExpr):
                    me = call.callee
                    if me.property in ("__init__", "constructor"):
                        if isinstance(me.object, CallExpr):
                            super_call = me.object
                            if isinstance(super_call.callee, Identifier) and super_call.callee.name == "super":
                                constructor_body.append(ExpressionStmt(
                                    expr=CallExpr(
                                        callee=Identifier(name="super"),
                                        args=call.args,
                                    ),
                                    source_location=stmt.source_location,
                                ))
                                found_super = True
                                continue
            constructor_body.append(stmt)

        if not found_super:
            super_args = [Identifier(name=p.name) for p in params]
            constructor_body.insert(0, ExpressionStmt(
                expr=CallExpr(
                    callee=Identifier(name="super"),
                    args=super_args,
                ),
                source_location=location,
            ))

        return MethodNode(
            name="constructor",
            params=params,
            body=constructor_body,
            visibility="public",
            source_location=location,
        )

    # -- Method parsing ------------------------------------------------------

    def parse_method(self, visibility: str) -> MethodNode:
        location = self.loc()
        self.expect_ident("def")
        name_tok = self.expect(TOK_IDENT)
        name = py_convert_name(name_tok.value)

        params = self.parse_params()

        if self.match(TOK_ARROW):
            self.parse_type_annotation()  # skip return type

        self.expect(TOK_COLON)
        body = self.parse_block()

        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility=visibility,
            source_location=location,
        )

    # -- Parameter parsing ---------------------------------------------------

    def parse_params(self) -> list[ParamNode]:
        self.expect(TOK_LPAREN)
        params: list[ParamNode] = []

        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            name_tok = self.expect(TOK_IDENT)
            param_name = name_tok.value

            if param_name == "self":
                if not self.match(TOK_COMMA):
                    break
                continue

            typ: TypeNode | None = None
            if self.match(TOK_COLON):
                typ = self.parse_type_annotation()

            params.append(ParamNode(name=py_convert_name(param_name), type=typ))

            if not self.match(TOK_COMMA):
                break

        self.expect(TOK_RPAREN)
        return params

    # -- Block parsing -------------------------------------------------------

    def parse_block(self) -> list[Statement]:
        self.skip_newlines()
        self.expect(TOK_INDENT)

        stmts: list[Statement] = []
        while not self.check(TOK_DEDENT) and not self.check(TOK_EOF):
            self.skip_newlines()
            if self.check(TOK_DEDENT) or self.check(TOK_EOF):
                break
            stmt = self.parse_statement()
            if stmt is not None:
                stmts.append(stmt)

        self.match(TOK_DEDENT)
        return stmts

    # -- Statement parsing ---------------------------------------------------

    def parse_statement(self) -> Statement | None:
        location = self.loc()

        if self.check_ident("assert") or self.check_ident("assert_"):
            return self._parse_assert(location)

        if self.check_ident("if"):
            return self._parse_if(location)

        if self.check_ident("for"):
            return self._parse_for(location)

        if self.check_ident("return"):
            return self._parse_return(location)

        if self.match_ident("pass"):
            self.skip_newlines()
            return None

        return self._parse_expr_or_assign(location)

    def _parse_assert(self, loc: SourceLocation) -> Statement:
        tok = self.advance()

        if tok.value == "assert_":
            self.expect(TOK_LPAREN)
            expr = self.parse_expression()
            self.expect(TOK_RPAREN)
            self.skip_newlines()
            return ExpressionStmt(
                expr=CallExpr(callee=Identifier(name="assert"), args=[expr]),
                source_location=loc,
            )

        # assert keyword
        if self.check(TOK_LPAREN):
            self.advance()
            expr = self.parse_expression()
            self.expect(TOK_RPAREN)
            self.skip_newlines()
            return ExpressionStmt(
                expr=CallExpr(callee=Identifier(name="assert"), args=[expr]),
                source_location=loc,
            )

        expr = self.parse_expression()
        self.skip_newlines()
        return ExpressionStmt(
            expr=CallExpr(callee=Identifier(name="assert"), args=[expr]),
            source_location=loc,
        )

    def _parse_if(self, loc: SourceLocation) -> Statement:
        self.expect_ident("if")
        return self._parse_if_body(loc)

    def _parse_if_body(self, loc: SourceLocation) -> Statement:
        condition = self.parse_expression()
        self.expect(TOK_COLON)

        then_block = self.parse_block()

        else_block: list[Statement] = []
        self.skip_newlines()
        if self.check_ident("elif"):
            elif_loc = self.loc()
            self.advance()
            elif_stmt = self._parse_if_body(elif_loc)
            else_block = [elif_stmt]
        elif self.match_ident("else"):
            self.expect(TOK_COLON)
            else_block = self.parse_block()

        return IfStmt(
            condition=condition,
            then=then_block,
            else_=else_block,
            source_location=loc,
        )

    def _parse_for(self, loc: SourceLocation) -> Statement:
        self.expect_ident("for")
        var_tok = self.expect(TOK_IDENT)
        var_name = py_convert_name(var_tok.value)

        self.expect_ident("in")
        self.expect_ident("range")
        self.expect(TOK_LPAREN)

        first = self.parse_expression()

        if self.match(TOK_COMMA):
            init_expr = first
            limit_expr = self.parse_expression()
        else:
            init_expr = BigIntLiteral(value=0)
            limit_expr = first

        self.expect(TOK_RPAREN)
        self.expect(TOK_COLON)

        body = self.parse_block()

        init_stmt = VariableDeclStmt(
            name=var_name,
            type=PrimitiveType(name="bigint"),
            mutable=True,
            init=init_expr,
            source_location=loc,
        )

        condition = BinaryExpr(
            op="<",
            left=Identifier(name=var_name),
            right=limit_expr,
        )

        update = ExpressionStmt(
            expr=IncrementExpr(operand=Identifier(name=var_name), prefix=False),
            source_location=loc,
        )

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
        if not self.check(TOK_NEWLINE) and not self.check(TOK_DEDENT) and not self.check(TOK_EOF):
            value = self.parse_expression()
        self.skip_newlines()
        return ReturnStmt(value=value, source_location=loc)

    def _parse_expr_or_assign(self, loc: SourceLocation) -> Statement | None:
        # Variable declaration: name: Type = expr
        if (self.peek().kind == TOK_IDENT and
                self.pos + 1 < len(self.tokens) and
                self.tokens[self.pos + 1].kind == TOK_COLON):
            name_tok = self.advance()
            var_name = py_convert_name(name_tok.value)
            self.expect(TOK_COLON)
            typ_node = self.parse_type_annotation()

            init: Expression
            if self.match(TOK_ASSIGN):
                init = self.parse_expression()
            else:
                init = BigIntLiteral(value=0)
            self.skip_newlines()
            return VariableDeclStmt(
                name=var_name,
                type=typ_node,
                mutable=True,
                init=init,
                source_location=loc,
            )

        expr = self.parse_expression()
        if expr is None:
            self.advance()
            self.skip_newlines()
            return None

        # Assignment: target = value
        if self.match(TOK_ASSIGN):
            value = self.parse_expression()
            self.skip_newlines()
            if isinstance(expr, Identifier):
                return VariableDeclStmt(
                    name=expr.name,
                    type=None,
                    mutable=True,
                    init=value,
                    source_location=loc,
                )
            return AssignmentStmt(target=expr, value=value, source_location=loc)

        # Compound assignments
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
                self.skip_newlines()
                value = BinaryExpr(op=bin_op, left=expr, right=right)
                return AssignmentStmt(target=expr, value=value, source_location=loc)

        self.skip_newlines()
        return ExpressionStmt(expr=expr, source_location=loc)

    # -- Expression parsing --------------------------------------------------

    def parse_expression(self) -> Expression:
        return self._parse_ternary()

    def _parse_ternary(self) -> Expression:
        expr = self._parse_or()
        if self.check_ident("if"):
            self.advance()
            condition = self._parse_or()
            self.expect_ident("else")
            alternate = self._parse_ternary()
            return TernaryExpr(condition=condition, consequent=expr, alternate=alternate)
        return expr

    def _parse_or(self) -> Expression:
        left = self._parse_and()
        while self.match(TOK_PIPEPIPE):
            right = self._parse_and()
            left = BinaryExpr(op="||", left=left, right=right)
        return left

    def _parse_and(self) -> Expression:
        left = self._parse_not()
        while self.match(TOK_AMPAMP):
            right = self._parse_not()
            left = BinaryExpr(op="&&", left=left, right=right)
        return left

    def _parse_not(self) -> Expression:
        if self.match(TOK_BANG):
            operand = self._parse_not()
            return UnaryExpr(op="!", operand=operand)
        return self._parse_bitwise_or()

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
            elif self.match(TOK_SLASHSLASH):
                right = self._parse_unary()
                left = BinaryExpr(op="/", left=left, right=right)
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
        if self.match(TOK_MINUS):
            operand = self._parse_unary()
            return UnaryExpr(op="-", operand=operand)
        if self.match(TOK_TILDE):
            operand = self._parse_unary()
            return UnaryExpr(op="~", operand=operand)
        if self.match(TOK_BANG):
            operand = self._parse_unary()
            return UnaryExpr(op="!", operand=operand)
        return self._parse_power()

    def _parse_power(self) -> Expression:
        base = self._parse_postfix()
        if self.match(TOK_STARSTAR):
            exp = self._parse_unary()
            return CallExpr(callee=Identifier(name="pow"), args=[base, exp])
        return base

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()
        while True:
            if self.match(TOK_DOT):
                prop_tok = self.expect(TOK_IDENT)
                prop_name = py_convert_name(prop_tok.value)

                if self.check(TOK_LPAREN):
                    args = self._parse_call_args()
                    if isinstance(expr, Identifier) and expr.name == "self":
                        expr = CallExpr(
                            callee=MemberExpr(object=Identifier(name="this"), property=prop_name),
                            args=args,
                        )
                    else:
                        expr = CallExpr(
                            callee=MemberExpr(object=expr, property=prop_name),
                            args=args,
                        )
                else:
                    if isinstance(expr, Identifier) and expr.name == "self":
                        expr = PropertyAccessExpr(property=prop_name)
                    else:
                        expr = MemberExpr(object=expr, property=prop_name)

            elif self.match(TOK_LBRACKET):
                index = self.parse_expression()
                self.expect(TOK_RBRACKET)
                expr = IndexAccessExpr(object=expr, index=index)

            elif self.match(TOK_LPAREN):
                args: list[Expression] = []
                while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
                    arg = self.parse_expression()
                    args.append(arg)
                    if not self.match(TOK_COMMA):
                        break
                self.expect(TOK_RPAREN)
                expr = CallExpr(callee=expr, args=args)
            else:
                break
        return expr

    def _parse_primary(self) -> Expression:
        tok = self.peek()

        if tok.kind == TOK_NUMBER:
            self.advance()
            return _parse_number(tok.value)

        if tok.kind == TOK_STRING:
            self.advance()
            return ByteStringLiteral(value=tok.value)

        if tok.kind == TOK_IDENT:
            self.advance()
            name = tok.value

            if name == "True" or name == "true":
                return BoolLiteral(value=True)
            if name == "False" or name == "false":
                return BoolLiteral(value=False)
            if name == "None":
                return BigIntLiteral(value=0)
            if name == "self":
                return Identifier(name="self")
            if name == "super":
                return Identifier(name="super")

            # bytes.fromhex("dead")
            if name == "bytes" and self.check(TOK_DOT):
                return self._parse_bytes_method()

            converted = py_convert_name(name)

            if self.check(TOK_LPAREN):
                args = self._parse_call_args()
                return CallExpr(callee=Identifier(name=converted), args=args)

            return Identifier(name=converted)

        if tok.kind == TOK_LPAREN:
            self.advance()
            expr = self.parse_expression()
            self.expect(TOK_RPAREN)
            return expr

        if tok.kind == TOK_LBRACKET:
            return self._parse_array_literal()

        self.add_error(f"line {tok.line}: unexpected token {tok.value!r}")
        self.advance()
        return BigIntLiteral(value=0)

    def _parse_bytes_method(self) -> Expression:
        self.expect(TOK_DOT)
        method_tok = self.expect(TOK_IDENT)
        if method_tok.value == "fromhex":
            self.expect(TOK_LPAREN)
            str_tok = self.expect(TOK_STRING)
            self.expect(TOK_RPAREN)
            return ByteStringLiteral(value=str_tok.value)
        if self.check(TOK_LPAREN):
            args = self._parse_call_args()
            return CallExpr(
                callee=MemberExpr(object=Identifier(name="bytes"), property=method_tok.value),
                args=args,
            )
        return MemberExpr(object=Identifier(name="bytes"), property=method_tok.value)

    def _parse_array_literal(self) -> Expression:
        self.expect(TOK_LBRACKET)
        elements: list[Expression] = []
        while not self.check(TOK_RBRACKET) and not self.check(TOK_EOF):
            elem = self.parse_expression()
            elements.append(elem)
            if not self.match(TOK_COMMA):
                break
        self.expect(TOK_RBRACKET)
        return ArrayLiteralExpr(elements=elements)

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


def _parse_number(s: str) -> Expression:
    try:
        val = int(s, 0)
    except ValueError:
        val = 0
    return BigIntLiteral(value=val)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_python(source: str, file_name: str) -> ParseResult:
    """Parse a Python-syntax Runar contract (.runar.py)."""
    p = _PyParser(file_name)

    raw = _tokenize_raw(source)
    p.tokens = _insert_indentation(raw)
    p.pos = 0

    try:
        contract = p.parse_contract()
    except ValueError as e:
        return ParseResult(errors=[Diagnostic(message=str(e), severity=Severity.ERROR)])

    if p.errors:
        return ParseResult(contract=contract, errors=p.errors)
    return ParseResult(contract=contract)
