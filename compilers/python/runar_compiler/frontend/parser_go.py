"""Go contract format parser (.runar.go) for the Runar compiler.

Ported from compilers/go/frontend/parser_gocontract.go.
Hand-written tokenizer + recursive descent parser for Go contract syntax.
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
TOK_TILDE = 27   # Go uses ^ for bitwise NOT on unary, but we tokenize ~ too
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
TOK_PLUSPLUS = 38
TOK_MINUSMINUS = 39
TOK_COLONEQ = 40
TOK_LSHIFT = 41
TOK_RSHIFT = 42
TOK_NEWLINE = 43
TOK_BACKTICK_STRING = 44


class Token:
    __slots__ = ("kind", "value", "line", "col")

    def __init__(self, kind: int, value: str, line: int, col: int):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# Go type mapping
# ---------------------------------------------------------------------------

_GO_TYPE_MAP: dict[str, str] = {
    "Int": "bigint",
    "Bigint": "bigint",
    "Bool": "boolean",
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

# Native Go types that map to Runar types
_GO_NATIVE_TYPE_MAP: dict[str, str] = {
    "int64": "bigint",
    "int": "bigint",
    "bool": "boolean",
}


def _map_go_type(name: str) -> TypeNode:
    """Map a Go type name to a Runar TypeNode."""
    if name in _GO_TYPE_MAP:
        return PrimitiveType(name=_GO_TYPE_MAP[name])
    if name in _GO_NATIVE_TYPE_MAP:
        return PrimitiveType(name=_GO_NATIVE_TYPE_MAP[name])
    if is_primitive_type(name):
        return PrimitiveType(name=name)
    return CustomType(name=name)


# ---------------------------------------------------------------------------
# Go builtin mapping (runar.FuncName -> Runar name)
# ---------------------------------------------------------------------------

_GO_BUILTIN_MAP: dict[str, str] = {
    "Assert": "assert",
    "Hash160": "hash160",
    "Hash256": "hash256",
    "Sha256": "sha256",
    "Ripemd160": "ripemd160",
    "CheckSig": "checkSig",
    "CheckMultiSig": "checkMultiSig",
    "CheckPreimage": "checkPreimage",
    "VerifyRabinSig": "verifyRabinSig",
    "VerifyWOTS": "verifyWOTS",
    "VerifySLHDSA_SHA2_128s": "verifySLHDSA_SHA2_128s",
    "VerifySLHDSA_SHA2_128f": "verifySLHDSA_SHA2_128f",
    "VerifySLHDSA_SHA2_192s": "verifySLHDSA_SHA2_192s",
    "VerifySLHDSA_SHA2_192f": "verifySLHDSA_SHA2_192f",
    "VerifySLHDSA_SHA2_256s": "verifySLHDSA_SHA2_256s",
    "VerifySLHDSA_SHA2_256f": "verifySLHDSA_SHA2_256f",
    "Num2Bin": "num2bin",
    "Bin2Num": "bin2num",
    "ExtractLocktime": "extractLocktime",
    "ExtractOutputHash": "extractOutputHash",
    "ExtractSequence": "extractSequence",
    "ExtractVersion": "extractVersion",
    "ExtractAmount": "extractAmount",
    "ExtractHashPrevouts": "extractHashPrevouts",
    "ExtractHashSequence": "extractHashSequence",
    "ExtractOutpoint": "extractOutpoint",
    "ExtractScriptCode": "extractScriptCode",
    "ExtractInputIndex": "extractInputIndex",
    "ExtractSigHashType": "extractSigHashType",
    "ExtractOutputs": "extractOutputs",
    "AddOutput": "addOutput",
    "GetStateScript": "getStateScript",
    "Safediv": "safediv",
    "Safemod": "safemod",
    "Clamp": "clamp",
    "Sign": "sign",
    "Pow": "pow",
    "MulDiv": "mulDiv",
    "PercentOf": "percentOf",
    "Sqrt": "sqrt",
    "Gcd": "gcd",
    "Divmod": "divmod",
    "Log2": "log2",
    "ToBool": "bool",
    "ReverseBytes": "reverseBytes",
    "EcAdd": "ecAdd",
    "EcMul": "ecMul",
    "EcMulGen": "ecMulGen",
    "EcNegate": "ecNegate",
    "EcOnCurve": "ecOnCurve",
    "EcModReduce": "ecModReduce",
    "EcEncodeCompressed": "ecEncodeCompressed",
    "EcMakePoint": "ecMakePoint",
    "EcPointX": "ecPointX",
    "EcPointY": "ecPointY",
    "EC_P": "EC_P",
    "EC_N": "EC_N",
    "EC_G": "EC_G",
}


def _map_go_builtin(name: str) -> str:
    """Map a Go exported builtin name to the Runar camelCase name."""
    if name in _GO_BUILTIN_MAP:
        return _GO_BUILTIN_MAP[name]
    return _go_field_to_camel(name)


def _go_field_to_camel(name: str) -> str:
    """Convert a Go exported name to camelCase (lowercase first letter).

    e.g. 'PubKeyHash' -> 'pubKeyHash', 'AddOutput' -> 'addOutput'
    If the name already starts with lowercase, return as-is.
    """
    if not name:
        return name
    if name[0].islower():
        return name
    return name[0].lower() + name[1:]


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _is_hex_digit(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _tokenize_go(source: str) -> list[Token]:
    """Tokenize Go source code.

    Go uses automatic semicolon insertion: a newline acts as a semicolon
    after certain tokens (identifiers, numbers, closing brackets, ++, --).
    We insert TOK_SEMICOLON in those cases and skip other newlines.
    """
    tokens: list[Token] = []
    line = 1
    col = 0
    i = 0
    n = len(source)

    def _last_significant_kind() -> int:
        """Return the kind of the last non-newline token, or TOK_EOF."""
        for j in range(len(tokens) - 1, -1, -1):
            if tokens[j].kind != TOK_NEWLINE:
                return tokens[j].kind
        return TOK_EOF

    while i < n:
        ch = source[i]

        # Newlines -- Go auto-semicolon insertion
        if ch == "\n" or ch == "\r":
            cur_line = line
            cur_col = col
            if ch == "\r":
                i += 1
                if i < n and source[i] == "\n":
                    i += 1
            else:
                i += 1
            line += 1
            col = 0

            # Insert semicolon after certain token types
            last = _last_significant_kind()
            if last in (
                TOK_IDENT, TOK_NUMBER, TOK_STRING, TOK_BACKTICK_STRING,
                TOK_RPAREN, TOK_RBRACKET, TOK_RBRACE,
                TOK_PLUSPLUS, TOK_MINUSMINUS,
            ):
                tokens.append(Token(TOK_SEMICOLON, ";", cur_line, cur_col))
            continue

        # Whitespace
        if ch == " " or ch == "\t":
            i += 1
            col += 1
            continue

        # Line comment
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n" and source[i] != "\r":
                i += 1
            continue

        # Block comment
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
            continue

        start_col = col

        # Backtick strings (raw string literals, used for struct tags)
        if ch == "`":
            i += 1
            col += 1
            start = i
            while i < n and source[i] != "`":
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
            tokens.append(Token(TOK_BACKTICK_STRING, val, line, start_col))
            continue

        # String literals
        if ch == '"':
            i += 1
            col += 1
            start = i
            while i < n and source[i] != '"':
                if source[i] == "\\":
                    i += 1
                    col += 1
                i += 1
                col += 1
            val = source[start:i]
            if i < n:
                i += 1
                col += 1
            # Process escape sequences to get the raw string value
            processed = _process_go_string_escapes(val)
            tokens.append(Token(TOK_STRING, processed, line, start_col))
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
            tokens.append(Token(TOK_IDENT, word, line, start_col))
            continue

        # Two-character operators
        if i + 1 < n:
            two = source[i:i + 2]
            two_map: dict[str, int] = {
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
                ":=": TOK_COLONEQ,
                "<<": TOK_LSHIFT,
                ">>": TOK_RSHIFT,
            }
            two_kind = two_map.get(two)
            if two_kind is not None:
                tokens.append(Token(two_kind, two, line, start_col))
                i += 2
                col += 2
                continue

        # Single-character operators
        one_map: dict[str, int] = {
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


def _process_go_string_escapes(s: str) -> str:
    """Process Go string escape sequences and return the literal value."""
    result: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            c = s[i + 1]
            if c == "n":
                result.append("\n")
                i += 2
            elif c == "t":
                result.append("\t")
                i += 2
            elif c == "r":
                result.append("\r")
                i += 2
            elif c == "\\":
                result.append("\\")
                i += 2
            elif c == '"':
                result.append('"')
                i += 2
            elif c == "x" and i + 3 < len(s):
                hex_val = s[i + 2:i + 4]
                try:
                    result.append(chr(int(hex_val, 16)))
                except ValueError:
                    result.append(s[i:i + 4])
                i += 4
            else:
                result.append(s[i])
                i += 1
        else:
            result.append(s[i])
            i += 1
    return "".join(result)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _GoParser:
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.tokens: list[Token] = []
        self.pos = 0
        self.errors: list[str] = []
        self.receiver_name: str = ""

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

    # -- Type parsing --------------------------------------------------------

    def parse_type(self) -> TypeNode:
        """Parse a Go type expression.

        Handles: runar.TypeName, TypeName, [N]Type, []Type
        """
        # Array type: [N]Type or []Type
        if self.check(TOK_LBRACKET):
            self.advance()
            if self.check(TOK_NUMBER):
                size_tok = self.advance()
                try:
                    size = int(size_tok.value)
                except ValueError:
                    size = 0
                    self.add_error(f"line {size_tok.line}: array size must be integer")
                self.expect(TOK_RBRACKET)
                elem_type = self.parse_type()
                return FixedArrayType(element=elem_type, length=size)
            else:
                # []Type -- slice, treat as the element type
                self.expect(TOK_RBRACKET)
                return self.parse_type()

        # Pointer type: *Type (skip the star)
        if self.check(TOK_STAR):
            self.advance()
            return self.parse_type()

        tok = self.peek()
        if tok.kind != TOK_IDENT:
            self.add_error(f"line {tok.line}: expected type name, got {tok.value!r}")
            self.advance()
            return CustomType(name="unknown")

        name = tok.value
        self.advance()

        # runar.TypeName
        if self.check(TOK_DOT):
            self.advance()
            sel_tok = self.expect(TOK_IDENT)
            if name == "runar":
                return _map_go_type(sel_tok.value)
            return CustomType(name=f"{name}.{sel_tok.value}")

        return _map_go_type(name)

    # -- Top-level parsing ---------------------------------------------------

    def parse_file(self) -> ContractNode | None:
        """Parse a complete Go source file and extract the contract."""
        self.skip_semicolons()

        # Skip 'package' declaration
        if self.match_ident("package"):
            self.expect(TOK_IDENT)  # package name
            self.skip_semicolons()

        # Skip import declarations
        while self.check_ident("import"):
            self._skip_import()
            self.skip_semicolons()

        # Collect top-level declarations
        contract_name = ""
        parent_class = ""
        properties: list[PropertyNode] = []
        methods: list[MethodNode] = []
        struct_found = False

        while not self.check(TOK_EOF):
            self.skip_semicolons()
            if self.check(TOK_EOF):
                break

            if self.check_ident("type"):
                result = self._parse_type_decl()
                if result is not None:
                    cname, pclass, props = result
                    contract_name = cname
                    parent_class = pclass
                    properties = props
                    struct_found = True
            elif self.check_ident("func"):
                method = self._parse_func_decl(contract_name)
                if method is not None:
                    methods.append(method)
            else:
                # Skip unknown top-level declarations
                self.advance()

        if not struct_found:
            return None

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
        constructor_params = [
            ParamNode(name=p.name, type=p.type) for p in uninit_props
        ]
        super_args: list[Expression] = [
            Identifier(name=p.name) for p in uninit_props
        ]
        constructor_body: list[Statement] = [
            ExpressionStmt(
                expr=CallExpr(
                    callee=Identifier(name="super"),
                    args=super_args,
                ),
                source_location=SourceLocation(file=self.file_name, line=1, column=1),
            ),
        ]
        for prop in uninit_props:
            constructor_body.append(
                AssignmentStmt(
                    target=PropertyAccessExpr(property=prop.name),
                    value=Identifier(name=prop.name),
                    source_location=SourceLocation(file=self.file_name, line=1, column=1),
                )
            )

        return ContractNode(
            name=contract_name,
            parent_class=parent_class,
            properties=properties,
            constructor=MethodNode(
                name="constructor",
                params=constructor_params,
                body=constructor_body,
                visibility="public",
                source_location=SourceLocation(file=self.file_name, line=1, column=1),
            ),
            methods=methods,
            source_file=self.file_name,
        )

    def _skip_import(self) -> None:
        """Skip an import declaration (single or grouped)."""
        self.expect_ident("import")

        if self.check(TOK_LPAREN):
            # Grouped import: import ( ... )
            self.advance()
            depth = 1
            while depth > 0 and not self.check(TOK_EOF):
                if self.check(TOK_LPAREN):
                    depth += 1
                elif self.check(TOK_RPAREN):
                    depth -= 1
                    if depth == 0:
                        self.advance()
                        break
                self.advance()
        else:
            # Single import: import "path" or import name "path"
            if self.check(TOK_IDENT):
                self.advance()  # alias
            if self.check(TOK_STRING):
                self.advance()  # path

    def _parse_type_decl(self) -> tuple[str, str, list[PropertyNode]] | None:
        """Parse a type declaration.

        Returns (contractName, parentClass, properties) if a contract struct
        is found, or None otherwise.
        """
        self.expect_ident("type")
        name_tok = self.expect(TOK_IDENT)
        type_name = name_tok.value

        if not self.match_ident("struct"):
            # Not a struct -- skip to end of declaration
            self._skip_to_semicolon_or_brace()
            return None

        self.expect(TOK_LBRACE)

        parent_class = ""
        properties: list[PropertyNode] = []

        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            self.skip_semicolons()
            if self.check(TOK_RBRACE):
                break

            field_loc = self.loc()

            # Check for embedded type: runar.SmartContract or runar.StatefulSmartContract
            if self.check(TOK_IDENT) and self._is_embed_field():
                embed_name = self._parse_embedded_type()
                if embed_name == "SmartContract":
                    parent_class = "SmartContract"
                elif embed_name == "StatefulSmartContract":
                    parent_class = "StatefulSmartContract"
                self.skip_semicolons()
                continue

            # Regular field: Name Type `tag`
            if self.check(TOK_IDENT):
                # Parse field names (Go allows: Name1, Name2 Type)
                field_names: list[str] = []
                first_name_tok = self.advance()
                field_names.append(first_name_tok.value)

                while self.match(TOK_COMMA):
                    nt = self.expect(TOK_IDENT)
                    field_names.append(nt.value)

                # Parse the type
                field_type = self.parse_type()

                # Check for struct tag
                readonly = False
                if self.check(TOK_BACKTICK_STRING):
                    tag_tok = self.advance()
                    if 'runar:"readonly"' in tag_tok.value:
                        readonly = True

                for fname in field_names:
                    prop_name = _go_field_to_camel(fname)
                    properties.append(PropertyNode(
                        name=prop_name,
                        type=field_type,
                        readonly=readonly,
                        source_location=field_loc,
                    ))

                self.skip_semicolons()
                continue

            # Unknown -- skip
            self.advance()
            self.skip_semicolons()

        self.expect(TOK_RBRACE)

        if not parent_class:
            return None

        return (type_name, parent_class, properties)

    def _is_embed_field(self) -> bool:
        """Look ahead to check if the current position is an embedded type field.

        Embedded fields have no field name -- they are just a type reference.
        For example: runar.SmartContract (selector with no name before it).
        We detect this by checking if the pattern is: IDENT DOT IDENT SEMICOLON/RBRACE
        with no further tokens that would indicate a field name followed by a type.
        """
        saved = self.pos
        tok1 = self.tokens[saved] if saved < len(self.tokens) else Token(TOK_EOF, "", 0, 0)
        tok2 = self.tokens[saved + 1] if saved + 1 < len(self.tokens) else Token(TOK_EOF, "", 0, 0)
        tok3 = self.tokens[saved + 2] if saved + 2 < len(self.tokens) else Token(TOK_EOF, "", 0, 0)
        tok4 = self.tokens[saved + 3] if saved + 3 < len(self.tokens) else Token(TOK_EOF, "", 0, 0)

        # Pattern: IDENT DOT IDENT (SEMICOLON | RBRACE | EOF)
        if (tok1.kind == TOK_IDENT and tok2.kind == TOK_DOT and
                tok3.kind == TOK_IDENT and
                tok4.kind in (TOK_SEMICOLON, TOK_RBRACE, TOK_EOF, TOK_BACKTICK_STRING)):
            # This could be an embed OR a field "Name pkg.Type"
            # If the first ident starts lowercase (like "runar"), it's likely a package name (embed)
            # Go embeds: the type name is the package-qualified type
            # Field names in Go structs are capitalized; package names are lowercase
            if tok1.value[0].islower():
                return True
        return False

    def _parse_embedded_type(self) -> str:
        """Parse an embedded type like runar.SmartContract and return the selector name."""
        pkg_tok = self.advance()  # package name (e.g. "runar")
        self.expect(TOK_DOT)
        sel_tok = self.expect(TOK_IDENT)

        # Skip optional struct tag on embed
        if self.check(TOK_BACKTICK_STRING):
            self.advance()

        if pkg_tok.value == "runar":
            return sel_tok.value
        return f"{pkg_tok.value}.{sel_tok.value}"

    def _parse_func_decl(self, contract_name: str) -> MethodNode | None:
        """Parse a func declaration (method or standalone function)."""
        location = self.loc()
        self.expect_ident("func")

        # Check for receiver: func (recv *Type) Name(params) retType { ... }
        has_receiver = False
        is_contract_method = False
        receiver_name = ""

        if self.check(TOK_LPAREN):
            # Could be receiver or function params -- look ahead
            saved = self.pos
            if self._looks_like_receiver():
                has_receiver = True
                self.pos = saved
                # Parse receiver
                self.expect(TOK_LPAREN)
                recv_tok = self.expect(TOK_IDENT)
                receiver_name = recv_tok.value
                # Skip the *TypeName
                self.match(TOK_STAR)
                type_tok = self.expect(TOK_IDENT)
                self.expect(TOK_RPAREN)

                if type_tok.value == contract_name:
                    is_contract_method = True
            else:
                self.pos = saved

        # Function/method name
        name_tok = self.expect(TOK_IDENT)
        func_name = name_tok.value

        # Set receiver name for property access resolution
        if has_receiver:
            self.receiver_name = receiver_name
        else:
            self.receiver_name = ""

        # Determine visibility
        if has_receiver and is_contract_method:
            visibility = "public" if func_name[0].isupper() else "private"
        elif not has_receiver:
            # Standalone functions: skip exported ones, init, main
            if func_name in ("init", "main"):
                self._skip_func_body()
                return None
            if func_name[0].isupper():
                # Exported standalone function -- skip (not a contract method)
                self._skip_func_body()
                return None
            visibility = "private"
        else:
            # Method on a different type -- skip
            self._skip_func_body()
            return None

        method_name = _go_field_to_camel(func_name)

        # Parse parameters
        params = self._parse_func_params()

        # Parse optional return type
        if not self.check(TOK_LBRACE):
            self._skip_return_type()

        # Parse body
        body = self._parse_block()

        return MethodNode(
            name=method_name,
            params=params,
            body=body,
            visibility=visibility,
            source_location=location,
        )

    def _looks_like_receiver(self) -> bool:
        """Look ahead from LPAREN to decide if this is a method receiver.

        A receiver looks like: (name *Type) or (name Type)
        A regular param list would have different structure.
        """
        saved = self.pos
        self.advance()  # skip LPAREN

        if not self.check(TOK_IDENT):
            self.pos = saved
            return False

        self.advance()  # skip receiver name

        # After receiver name, expect * or IDENT (the type), then RPAREN
        if self.check(TOK_STAR):
            self.advance()
            if self.check(TOK_IDENT):
                self.advance()
                if self.check(TOK_RPAREN):
                    self.advance()
                    # After RPAREN, there should be a method name (IDENT)
                    result = self.check(TOK_IDENT)
                    self.pos = saved
                    return result
        elif self.check(TOK_IDENT):
            self.advance()
            if self.check(TOK_RPAREN):
                self.advance()
                result = self.check(TOK_IDENT)
                self.pos = saved
                return result

        self.pos = saved
        return False

    def _parse_func_params(self) -> list[ParamNode]:
        """Parse a function parameter list: (name Type, name Type, ...)"""
        self.expect(TOK_LPAREN)
        params: list[ParamNode] = []

        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            # Collect parameter names (Go allows: a, b Type)
            param_names: list[str] = []
            name_tok = self.expect(TOK_IDENT)
            param_names.append(name_tok.value)

            while self.match(TOK_COMMA):
                # Check if next is IDENT followed by a type or another comma
                # This handles both "a, b Type" and "a Type, b Type"
                if self._is_param_name_before_type():
                    nt = self.expect(TOK_IDENT)
                    param_names.append(nt.value)
                else:
                    # This comma separates complete param declarations
                    # The next ident is a new param group
                    break

            # Parse the type
            param_type = self.parse_type()

            for pname in param_names:
                params.append(ParamNode(
                    name=_go_field_to_camel(pname),
                    type=param_type,
                ))

            if not self.match(TOK_COMMA):
                break

        self.expect(TOK_RPAREN)
        return params

    def _is_param_name_before_type(self) -> bool:
        """Look ahead to see if the next ident is a param name (followed by more names or a type).

        In Go, "a, b int64" means a and b are both int64.
        But "a int64, b int64" means each has its own type.
        We need to distinguish between the next token being a name (followed by
        comma or type) vs being the start of a type (like runar.Int).
        """
        saved = self.pos
        if not self.check(TOK_IDENT):
            return False

        tok = self.tokens[saved]
        tok2 = self.tokens[saved + 1] if saved + 1 < len(self.tokens) else Token(TOK_EOF, "", 0, 0)

        # If next is IDENT followed by COMMA, RPAREN, or DOT (package.Type),
        # it could be either a name or a type. Use a heuristic:
        # - If followed by DOT, it's likely a package-qualified type (not a name)
        # - If followed by COMMA, check further
        # - If it looks like a known type or package, it's a type

        # Simple heuristic: if the ident starts with a lowercase letter and
        # is not "runar" or a known type, it's likely a param name
        if tok.value == "runar" or tok.value in _GO_TYPE_MAP or tok.value in _GO_NATIVE_TYPE_MAP:
            return False
        if tok2.kind == TOK_DOT:
            return False
        if tok.value[0].isupper() and tok2.kind != TOK_COMMA:
            # Uppercase followed by non-comma -- likely a type name
            return False
        if tok2.kind == TOK_COMMA or tok2.kind == TOK_RPAREN:
            # name followed by comma or rparen -- could still be a name
            # but only if it's lowercase
            return tok.value[0].islower()

        return tok.value[0].islower()

    def _skip_return_type(self) -> None:
        """Skip a return type specification before the function body."""
        # Return type can be: Type, (Type), (Type, Type), or nothing
        if self.check(TOK_LPAREN):
            self.advance()
            depth = 1
            while depth > 0 and not self.check(TOK_EOF):
                if self.check(TOK_LPAREN):
                    depth += 1
                elif self.check(TOK_RPAREN):
                    depth -= 1
                self.advance()
        else:
            # Simple return type: skip until we see {
            while not self.check(TOK_LBRACE) and not self.check(TOK_EOF):
                self.advance()

    def _skip_func_body(self) -> None:
        """Skip parameter list, return type, and body of a function we don't care about."""
        # Skip params
        if self.check(TOK_LPAREN):
            self.advance()
            depth = 1
            while depth > 0 and not self.check(TOK_EOF):
                if self.check(TOK_LPAREN):
                    depth += 1
                elif self.check(TOK_RPAREN):
                    depth -= 1
                self.advance()

        # Skip return type
        if not self.check(TOK_LBRACE):
            self._skip_return_type()

        # Skip body
        if self.check(TOK_LBRACE):
            self.advance()
            depth = 1
            while depth > 0 and not self.check(TOK_EOF):
                if self.check(TOK_LBRACE):
                    depth += 1
                elif self.check(TOK_RBRACE):
                    depth -= 1
                self.advance()
        self.skip_semicolons()

    def _skip_to_semicolon_or_brace(self) -> None:
        """Skip tokens until a semicolon or opening brace."""
        while not self.check(TOK_SEMICOLON) and not self.check(TOK_LBRACE) and not self.check(TOK_EOF):
            self.advance()
        self.skip_semicolons()

    # -- Block and statement parsing -----------------------------------------

    def _parse_block(self) -> list[Statement]:
        """Parse a { ... } block returning a list of statements."""
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
        self.skip_semicolons()
        return stmts

    def _parse_statement(self) -> Statement | None:
        location = self.loc()

        # if statement
        if self.check_ident("if"):
            return self._parse_if(location)

        # for statement
        if self.check_ident("for"):
            return self._parse_for(location)

        # return statement
        if self.check_ident("return"):
            return self._parse_return(location)

        # var declaration: var name Type = expr
        if self.check_ident("var"):
            return self._parse_var_decl(location)

        # const declaration: const name = expr (or const name Type = expr)
        if self.check_ident("const"):
            return self._parse_const_decl(location)

        # Expression statement, assignment, short variable declaration, or inc/dec
        return self._parse_expr_statement(location)

    def _parse_if(self, loc: SourceLocation) -> Statement:
        self.expect_ident("if")
        condition = self._parse_expression()
        then_block = self._parse_block()

        else_block: list[Statement] = []
        if self.match_ident("else"):
            if self.check_ident("if"):
                # else if -> nested IfStmt in else
                elif_loc = self.loc()
                elif_stmt = self._parse_if(elif_loc)
                else_block = [elif_stmt]
            else:
                else_block = self._parse_block()

        return IfStmt(
            condition=condition,
            then=then_block,
            else_=else_block,
            source_location=loc,
        )

    def _parse_for(self, loc: SourceLocation) -> Statement:
        self.expect_ident("for")

        # Go for has several forms:
        #   for init; cond; post { body }
        #   for cond { body }
        #   for { body }  (infinite -- not supported in Runar)
        #
        # We detect the three-clause form by looking for a semicolon.

        if self.check(TOK_LBRACE):
            # for { body } -- infinite loop (not really supported but parse it)
            body = self._parse_block()
            return ForStmt(body=body, source_location=loc)

        # Try to detect if this is a three-clause for or condition-only for
        # by looking ahead for a semicolon before a brace
        if self._has_semicolon_before_brace():
            # Three-clause for: init; cond; post
            init_stmt = self._parse_simple_statement(loc)
            init_decl: VariableDeclStmt | None = None
            if isinstance(init_stmt, VariableDeclStmt):
                init_decl = init_stmt
            self.expect(TOK_SEMICOLON)

            cond = self._parse_expression()
            self.expect(TOK_SEMICOLON)

            update = self._parse_simple_statement(loc)

            body = self._parse_block()
            return ForStmt(
                init=init_decl,
                condition=cond,
                update=update,
                body=body,
                source_location=loc,
            )
        else:
            # Condition-only for
            cond = self._parse_expression()
            body = self._parse_block()
            return ForStmt(
                condition=cond,
                body=body,
                source_location=loc,
            )

    def _has_semicolon_before_brace(self) -> bool:
        """Look ahead to check if there's a semicolon before the next opening brace."""
        saved = self.pos
        depth = 0
        while saved < len(self.tokens):
            tok = self.tokens[saved]
            if tok.kind == TOK_LPAREN:
                depth += 1
            elif tok.kind == TOK_RPAREN:
                depth -= 1
            elif tok.kind == TOK_SEMICOLON and depth == 0:
                self.pos = self.pos  # don't change
                return True
            elif tok.kind == TOK_LBRACE and depth == 0:
                return False
            elif tok.kind == TOK_EOF:
                return False
            saved += 1
        return False

    def _parse_simple_statement(self, loc: SourceLocation) -> Statement | None:
        """Parse a simple statement (no blocks) -- used in for init/post.

        Unlike _parse_expr_statement, this does NOT consume trailing semicolons,
        because the for-loop parser uses semicolons as clause delimiters.
        """
        return self._parse_expr_statement(loc, consume_semicolons=False)

    def _parse_return(self, loc: SourceLocation) -> Statement:
        self.expect_ident("return")
        value: Expression | None = None
        if not self.check(TOK_SEMICOLON) and not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            value = self._parse_expression()
        self.skip_semicolons()
        return ReturnStmt(value=value, source_location=loc)

    def _parse_var_decl(self, loc: SourceLocation) -> Statement:
        self.expect_ident("var")
        name_tok = self.expect(TOK_IDENT)
        var_name = _go_field_to_camel(name_tok.value)

        type_node: TypeNode | None = None
        if not self.check(TOK_ASSIGN):
            type_node = self.parse_type()

        init: Expression | None = None
        if self.match(TOK_ASSIGN):
            init = self._parse_expression()

        if init is None:
            init = BigIntLiteral(value=0)

        self.skip_semicolons()
        return VariableDeclStmt(
            name=var_name,
            type=type_node,
            mutable=True,
            init=init,
            source_location=loc,
        )

    def _parse_const_decl(self, loc: SourceLocation) -> Statement:
        self.expect_ident("const")
        name_tok = self.expect(TOK_IDENT)
        var_name = _go_field_to_camel(name_tok.value)

        type_node: TypeNode | None = None
        if not self.check(TOK_ASSIGN):
            type_node = self.parse_type()

        self.expect(TOK_ASSIGN)
        init = self._parse_expression()

        self.skip_semicolons()
        return VariableDeclStmt(
            name=var_name,
            type=type_node,
            mutable=False,
            init=init,
            source_location=loc,
        )

    def _parse_expr_statement(
        self, loc: SourceLocation, consume_semicolons: bool = True,
    ) -> Statement | None:
        """Parse an expression statement, assignment, short var decl, or inc/dec."""
        expr = self._parse_expression()
        if expr is None:
            self.advance()
            if consume_semicolons:
                self.skip_semicolons()
            return None

        # Short variable declaration: name := expr
        if self.match(TOK_COLONEQ):
            init = self._parse_expression()
            name = ""
            if isinstance(expr, Identifier):
                name = expr.name
            if consume_semicolons:
                self.skip_semicolons()
            return VariableDeclStmt(
                name=name,
                mutable=True,
                init=init,
                source_location=loc,
            )

        # Assignment: target = value
        if self.match(TOK_ASSIGN):
            value = self._parse_expression()
            if consume_semicolons:
                self.skip_semicolons()
            return AssignmentStmt(target=expr, value=value, source_location=loc)

        # Compound assignments: +=, -=, *=, /=, %=
        compound_ops: dict[int, str] = {
            TOK_PLUSEQ: "+",
            TOK_MINUSEQ: "-",
            TOK_STAREQ: "*",
            TOK_SLASHEQ: "/",
            TOK_PERCENTEQ: "%",
        }
        for kind, bin_op in compound_ops.items():
            if self.match(kind):
                right = self._parse_expression()
                if consume_semicolons:
                    self.skip_semicolons()
                value = BinaryExpr(op=bin_op, left=expr, right=right)
                return AssignmentStmt(target=expr, value=value, source_location=loc)

        # Increment/decrement: expr++ or expr--
        if self.match(TOK_PLUSPLUS):
            if consume_semicolons:
                self.skip_semicolons()
            return ExpressionStmt(
                expr=IncrementExpr(operand=expr, prefix=False),
                source_location=loc,
            )
        if self.match(TOK_MINUSMINUS):
            if consume_semicolons:
                self.skip_semicolons()
            return ExpressionStmt(
                expr=DecrementExpr(operand=expr, prefix=False),
                source_location=loc,
            )

        if consume_semicolons:
            self.skip_semicolons()
        return ExpressionStmt(expr=expr, source_location=loc)

    # -- Expression parsing --------------------------------------------------

    def _parse_expression(self) -> Expression:
        return self._parse_or()

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
        if self.match(TOK_MINUS):
            operand = self._parse_unary()
            return UnaryExpr(op="-", operand=operand)
        if self.match(TOK_BANG):
            operand = self._parse_unary()
            return UnaryExpr(op="!", operand=operand)
        if self.match(TOK_CARET):
            # Go uses ^ as bitwise NOT (unary)
            operand = self._parse_unary()
            return UnaryExpr(op="~", operand=operand)
        return self._parse_postfix()

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()
        while True:
            if self.match(TOK_DOT):
                prop_tok = self.expect(TOK_IDENT)
                prop_name = _go_field_to_camel(prop_tok.value)

                if self.check(TOK_LPAREN):
                    # Method call: expr.Method(args)
                    args = self._parse_call_args()
                    if isinstance(expr, Identifier) and self._is_receiver(expr.name):
                        # receiver.Method(args) -> this.method(args)
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
                    if isinstance(expr, Identifier) and self._is_receiver(expr.name):
                        expr = PropertyAccessExpr(property=prop_name)
                    else:
                        expr = MemberExpr(object=expr, property=prop_name)

            elif self.check(TOK_LBRACKET):
                self.advance()
                index = self._parse_expression()
                self.expect(TOK_RBRACKET)
                expr = IndexAccessExpr(object=expr, index=index)

            elif self.check(TOK_LPAREN):
                # Direct function call: expr(args)
                args = self._parse_call_args()
                expr = CallExpr(callee=expr, args=args)
            else:
                break
        return expr

    def _is_receiver(self, name: str) -> bool:
        """Check if the given name is the method receiver (e.g. 'c', 'self')."""
        if self.receiver_name and name == self.receiver_name:
            return True
        if name in ("c", "self"):
            return True
        return False

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

        # Identifier
        if tok.kind == TOK_IDENT:
            self.advance()
            name = tok.value

            if name == "true":
                return BoolLiteral(value=True)
            if name == "false":
                return BoolLiteral(value=False)

            # Package-qualified access: runar.Something
            if name == "runar" and self.check(TOK_DOT):
                self.advance()  # skip dot
                sel_tok = self.expect(TOK_IDENT)
                sel_name = sel_tok.value

                # Type conversion: runar.Int(0), runar.Bigint(x), runar.Bool(x)
                if sel_name in ("Int", "Bigint", "Bool") and self.check(TOK_LPAREN):
                    args = self._parse_call_args()
                    if len(args) == 1:
                        return args[0]
                    return BigIntLiteral(value=0)

                builtin_name = _map_go_builtin(sel_name)

                # runar.EC_P, runar.EC_N, runar.EC_G -- constants, not calls
                if sel_name in ("EC_P", "EC_N", "EC_G") and not self.check(TOK_LPAREN):
                    return Identifier(name=builtin_name)

                # runar.TxPreimage -> this.txPreimage (property)
                if sel_name == "TxPreimage":
                    return PropertyAccessExpr(property="txPreimage")

                if self.check(TOK_LPAREN):
                    args = self._parse_call_args()
                    return CallExpr(
                        callee=Identifier(name=builtin_name),
                        args=args,
                    )
                return Identifier(name=builtin_name)

            # Receiver access: c.Field or self.Field
            if self._is_receiver(name):
                if self.check(TOK_DOT):
                    # Will be handled in _parse_postfix
                    return Identifier(name=name)
                return Identifier(name=name)

            converted = _go_field_to_camel(name)

            if self.check(TOK_LPAREN):
                args = self._parse_call_args()
                return CallExpr(callee=Identifier(name=converted), args=args)

            return Identifier(name=converted)

        # Parenthesized expression
        if tok.kind == TOK_LPAREN:
            self.advance()
            expr = self._parse_expression()
            self.expect(TOK_RPAREN)
            return expr

        self.add_error(f"line {tok.line}: unexpected token {tok.value!r}")
        self.advance()
        return BigIntLiteral(value=0)

    def _parse_call_args(self) -> list[Expression]:
        """Parse a function call argument list: (expr, expr, ...)"""
        self.expect(TOK_LPAREN)
        args: list[Expression] = []
        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            arg = self._parse_expression()
            args.append(arg)
            if not self.match(TOK_COMMA):
                break
        self.expect(TOK_RPAREN)
        return args


def _parse_number(s: str) -> Expression:
    """Parse a number string into a BigIntLiteral."""
    try:
        val = int(s, 0)
    except ValueError:
        val = 0
    return BigIntLiteral(value=val)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_go(source: str, file_name: str) -> ParseResult:
    """Parse a Go-syntax Runar contract (.runar.go)."""
    p = _GoParser(file_name)
    p.tokens = _tokenize_go(source)
    p.pos = 0

    try:
        contract = p.parse_file()
    except (ValueError, IndexError) as e:
        return ParseResult(errors=[f"Go parse error: {e}"])

    if contract is None and not p.errors:
        p.errors.append("no Runar contract struct found in Go source")

    if p.errors:
        return ParseResult(contract=contract, errors=p.errors)
    return ParseResult(contract=contract)
