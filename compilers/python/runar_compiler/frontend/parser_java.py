"""Java parser (.runar.java) for the Runar compiler.

Hand-written tokenizer + recursive-descent parser matching the surface
specification implemented by ``compilers/java/src/main/java/runar/compiler/
frontend/JavaParser.java``. The authoritative Java reference uses javac's
own tree API; this Python port works on the source directly since the
supported subset is small and well-bounded.

Supported Java subset:
 * package / import declarations (consumed and discarded)
 * package-private class extending SmartContract or StatefulSmartContract
 * @Readonly fields with optional literal initializer
 * Constructor, methods with optional @Public annotation
 * Statements: variable decl with initializer, assignment, if/else, for,
   return, expression statement
 * Expressions: identifiers, literals, binary/unary ops (including pre/post
   ++/--), method calls, member access, `this.x`, ternary, array access,
   `new T[]{...}` array literal
 * Types: boolean/Boolean, BigInteger/Bigint, Rúnar domain types,
   FixedArray<T, N>

Rejections mirror the Java implementation — loud failures over silent
divergence. The parser is only ever invoked for .runar.java inputs by
``parser_dispatch.parse_source``.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
    ContractNode, PropertyNode, MethodNode, ParamNode, SourceLocation,
    PrimitiveType, FixedArrayType, CustomType, TypeNode,
    BigIntLiteral, BoolLiteral, ByteStringLiteral, Identifier,
    PropertyAccessExpr, MemberExpr, BinaryExpr, UnaryExpr, CallExpr,
    TernaryExpr, IndexAccessExpr, IncrementExpr, DecrementExpr,
    ArrayLiteralExpr,
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
TOK_STRING = 3        # "..." string literal (only valid inside fromHex)
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
TOK_QUESTION = 14
TOK_AT = 15           # @ annotation prefix
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
TOK_STAREQ = 37
TOK_SLASHEQ = 38
TOK_PERCENTEQ = 39
TOK_PLUSPLUS = 40
TOK_MINUSMINUS = 41
TOK_LSHIFT = 42
TOK_RSHIFT = 43

# Keywords
TOK_PACKAGE = 60
TOK_IMPORT = 61
TOK_STATIC = 62
TOK_CLASS = 63
TOK_EXTENDS = 64
TOK_IMPLEMENTS = 65
TOK_PUBLIC = 66
TOK_PRIVATE = 67
TOK_PROTECTED = 68
TOK_FINAL = 69
TOK_VOID = 70
TOK_BOOLEAN_KW = 71
TOK_INT_KW = 72
TOK_LONG_KW = 73
TOK_RETURN_KW = 74
TOK_IF = 75
TOK_ELSE = 76
TOK_FOR = 77
TOK_WHILE = 78
TOK_DO = 79
TOK_TRUE = 80
TOK_FALSE = 81
TOK_THIS = 82
TOK_SUPER = 83
TOK_NEW = 84
TOK_NULL = 85


_KEYWORDS: dict[str, int] = {
    "package": TOK_PACKAGE,
    "import": TOK_IMPORT,
    "static": TOK_STATIC,
    "class": TOK_CLASS,
    "extends": TOK_EXTENDS,
    "implements": TOK_IMPLEMENTS,
    "public": TOK_PUBLIC,
    "private": TOK_PRIVATE,
    "protected": TOK_PROTECTED,
    "final": TOK_FINAL,
    "void": TOK_VOID,
    "boolean": TOK_BOOLEAN_KW,
    "int": TOK_INT_KW,
    "long": TOK_LONG_KW,
    "return": TOK_RETURN_KW,
    "if": TOK_IF,
    "else": TOK_ELSE,
    "for": TOK_FOR,
    "while": TOK_WHILE,
    "do": TOK_DO,
    "true": TOK_TRUE,
    "false": TOK_FALSE,
    "this": TOK_THIS,
    "super": TOK_SUPER,
    "new": TOK_NEW,
    "null": TOK_NULL,
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

# Bigint-wrapper method-name → canonical BinaryOp string. Mirrors
# JavaParser.BIGINT_BINARY_METHODS; unary `neg`/`abs` are handled separately
# at the call site. Receiver type is not consulted (parser has no type info
# at this stage); the typechecker rejects misuse.
#
# The map covers two spellings:
#   * Bigint wrapper (plus, minus, times, div, mod, shl, shr, ...)
#   * JDK BigInteger (add, subtract, multiply, divide, shiftLeft, shiftRight)
# Both lower to the same canonical BinaryExpr.
_BIGINT_BINARY_METHODS: dict[str, str] = {
    # Bigint wrapper spellings.
    "plus":  "+",
    "minus": "-",
    "times": "*",
    "div":   "/",
    "mod":   "%",
    "shl":   "<<",
    "shr":   ">>",
    "and":   "&",
    "or":    "|",
    "xor":   "^",
    "gt":    ">",
    "lt":    "<",
    "ge":    ">=",
    "le":    "<=",
    "eq":    "===",
    "neq":   "!==",
    # JDK BigInteger spellings.
    "add":        "+",
    "subtract":   "-",
    "multiply":   "*",
    "divide":     "/",
    "shiftLeft":  "<<",
    "shiftRight": ">>",
}


_TYPE_MAP: dict[str, str] = {
    # bigint aliases
    "BigInteger": "bigint",
    "Bigint": "bigint",
    "bigint": "bigint",
    "int": "bigint",
    "long": "bigint",
    "Integer": "bigint",
    "Long": "bigint",
    # booleans
    "boolean": "boolean",
    "Boolean": "boolean",
    # Rúnar domain types
    "ByteString": "ByteString",
    "PubKey": "PubKey",
    "Sig": "Sig",
    "Sha256": "Sha256",
    "Sha256Digest": "Sha256",
    "Ripemd160": "Ripemd160",
    "Hash160": "Ripemd160",
    "Addr": "Addr",
    "SigHashPreimage": "SigHashPreimage",
    "RabinSig": "RabinSig",
    "RabinPubKey": "RabinPubKey",
    "Point": "Point",
    "P256Point": "P256Point",
    "P384Point": "P384Point",
}


def _map_java_type(name: str) -> str:
    return _TYPE_MAP.get(name, name)


def _parse_type_name(name: str) -> TypeNode:
    mapped = _map_java_type(name)
    if is_primitive_type(mapped):
        return PrimitiveType(name=mapped)
    return CustomType(name=mapped)


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

def _tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    n = len(source)
    pos = 0
    line = 1
    col = 1

    while pos < n:
        ch = source[pos]

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

        # Line comments
        if ch == "/" and pos + 1 < n and source[pos + 1] == "/":
            while pos < n and source[pos] != "\n":
                pos += 1
            continue

        # Block comments (including /** ... */ javadoc)
        if ch == "/" and pos + 1 < n and source[pos + 1] == "*":
            pos += 2
            col += 2
            while pos + 1 < n and not (source[pos] == "*" and source[pos + 1] == "/"):
                if source[pos] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                pos += 1
            if pos + 1 < n:
                pos += 2  # consume */
                col += 2
            continue

        l = line
        c = col

        # Three-character operators: none that matter for our subset
        # (>>> right-shift-unsigned, <<= etc. not supported).

        # Two-character operators
        if pos + 1 < n:
            two = source[pos:pos + 2]
            two_kind = {
                "==": TOK_EQEQ,
                "!=": TOK_BANGEQ,
                "<=": TOK_LTEQ,
                ">=": TOK_GTEQ,
                "&&": TOK_AMPAMP,
                "||": TOK_PIPEPIPE,
                "+=": TOK_PLUSEQ,
                "-=": TOK_MINUSEQ,
                "*=": TOK_STAREQ,
                "/=": TOK_SLASHEQ,
                "%=": TOK_PERCENTEQ,
                "++": TOK_PLUSPLUS,
                "--": TOK_MINUSMINUS,
                "<<": TOK_LSHIFT,
                ">>": TOK_RSHIFT,
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
            "?": TOK_QUESTION,
            "@": TOK_AT,
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

        # String literals "..."
        if ch == '"':
            pos += 1
            col += 1
            start = pos
            while pos < n and source[pos] != '"':
                if source[pos] == "\\" and pos + 1 < n:
                    # Skip the escape sequence; we don't interpret escapes —
                    # Rúnar only uses these for ByteString.fromHex("...") hex
                    # payloads that are already plain ASCII.
                    pos += 2
                    col += 2
                    continue
                if source[pos] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                pos += 1
            val = source[start:pos]
            if pos < n:
                pos += 1  # closing quote
                col += 1
            tokens.append(Token(TOK_STRING, val, l, c))
            continue

        # Char literal — rejected later, but tokenize so we produce an error
        if ch == "'":
            pos += 1
            col += 1
            start = pos
            while pos < n and source[pos] != "'":
                if source[pos] == "\\" and pos + 1 < n:
                    pos += 2
                    col += 2
                    continue
                pos += 1
                col += 1
            val = source[start:pos]
            if pos < n:
                pos += 1
                col += 1
            # Tag as a string for downstream "unsupported" handling.
            tokens.append(Token(TOK_STRING, val, l, c))
            continue

        # Hex integer literal 0x...
        if ch == "0" and pos + 1 < n and source[pos + 1] in ("x", "X"):
            start = pos
            pos += 2
            col += 2
            while pos < n and (source[pos].isdigit() or source[pos] in "abcdefABCDEF_"):
                pos += 1
                col += 1
            val = source[start:pos].replace("_", "")
            tokens.append(Token(TOK_NUMBER, val, l, c))
            continue

        # Numeric literal (decimal). Trailing L/l suffix accepted.
        if ch.isdigit():
            start = pos
            while pos < n and (source[pos].isdigit() or source[pos] == "_"):
                pos += 1
                col += 1
            if pos < n and source[pos] in ("L", "l"):
                pos += 1
                col += 1
            val = source[start:pos].replace("_", "").rstrip("Ll")
            tokens.append(Token(TOK_NUMBER, val, l, c))
            continue

        # Identifier / keyword
        if ch.isalpha() or ch == "_" or ch == "$":
            start = pos
            while pos < n and (source[pos].isalnum() or source[pos] in ("_", "$")):
                pos += 1
                col += 1
            word = source[start:pos]
            kw_kind = _KEYWORDS.get(word)
            if kw_kind is not None:
                tokens.append(Token(kw_kind, word, l, c))
            else:
                tokens.append(Token(TOK_IDENT, word, l, c))
            continue

        # Unknown character — skip
        pos += 1
        col += 1

    tokens.append(Token(TOK_EOF, "", line, col))
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class _JavaParseError(Exception):
    """Raised on unrecoverable parse errors; bubbles up to parse_java."""


class _JavaParser:
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.tokens: list[Token] = []
        self.pos = 0
        self.errors: list[Diagnostic] = []

    # -- Token helpers -------------------------------------------------------

    def peek(self, offset: int = 0) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1] if self.tokens else Token(TOK_EOF, "", 0, 0)

    def advance(self) -> Token:
        tok = self.peek()
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return tok

    def check(self, kind: int) -> bool:
        return self.peek().kind == kind

    def match_tok(self, kind: int) -> bool:
        if self.check(kind):
            self.advance()
            return True
        return False

    def expect(self, kind: int, label: str = "") -> Token:
        tok = self.peek()
        if tok.kind != kind:
            lbl = label or f"token kind {kind}"
            raise _JavaParseError(
                f"line {tok.line}:{tok.col}: expected {lbl}, got {tok.value!r}"
            )
        return self.advance()

    def loc(self) -> SourceLocation:
        tok = self.peek()
        return SourceLocation(file=self.file_name, line=tok.line, column=tok.col)

    # -- Top-level -----------------------------------------------------------

    def parse(self) -> ContractNode:
        # package ...;
        if self.check(TOK_PACKAGE):
            while not self.check(TOK_SEMI) and not self.check(TOK_EOF):
                self.advance()
            self.match_tok(TOK_SEMI)

        # import [static] foo.bar.*;
        while self.check(TOK_IMPORT):
            while not self.check(TOK_SEMI) and not self.check(TOK_EOF):
                self.advance()
            self.match_tok(TOK_SEMI)

        # Skip any class-level annotations or modifiers (e.g. `public`) before
        # the `class` keyword. Java uses `public class ...`; Rúnar's Java
        # format is package-private but we tolerate both.
        self._skip_annotations()
        while self.check(TOK_PUBLIC) or self.check(TOK_PRIVATE) or \
                self.check(TOK_PROTECTED) or self.check(TOK_FINAL) or \
                self.check(TOK_STATIC):
            self.advance()
        self._skip_annotations()

        if not self.check(TOK_CLASS):
            tok = self.peek()
            raise _JavaParseError(
                f"line {tok.line}:{tok.col}: expected 'class' declaration, got {tok.value!r}"
            )
        return self._parse_class()

    # -- Class ---------------------------------------------------------------

    def _parse_class(self) -> ContractNode:
        class_loc = self.loc()
        self.expect(TOK_CLASS, "'class'")
        name_tok = self.expect(TOK_IDENT, "class name")
        class_name = name_tok.value

        if not self.check(TOK_EXTENDS):
            raise _JavaParseError(
                f"contract class in {self.file_name} must extend SmartContract or StatefulSmartContract"
            )
        self.advance()  # consume extends

        parent_tok = self.expect(TOK_IDENT, "parent class name")
        parent_name = parent_tok.value

        if parent_name == "SmartContract":
            parent_class = "SmartContract"
        elif parent_name == "StatefulSmartContract":
            parent_class = "StatefulSmartContract"
        else:
            raise _JavaParseError(
                f"contract class in {self.file_name} must extend SmartContract or "
                f"StatefulSmartContract, got {parent_name}"
            )

        # Ignore implements clause entirely.
        if self.check(TOK_IMPLEMENTS):
            self.advance()
            while not self.check(TOK_LBRACE) and not self.check(TOK_EOF):
                self.advance()

        self.expect(TOK_LBRACE, "'{'")

        properties: list[PropertyNode] = []
        constructor: MethodNode | None = None
        methods: list[MethodNode] = []

        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            member = self._parse_member(class_name)
            if member is None:
                continue
            if isinstance(member, PropertyNode):
                properties.append(member)
            elif isinstance(member, MethodNode):
                if member.name == "constructor":
                    if constructor is not None:
                        raise _JavaParseError(
                            f"{class_name} has more than one constructor"
                        )
                    constructor = member
                else:
                    methods.append(member)

        self.expect(TOK_RBRACE, "'}'")

        if constructor is None:
            constructor = self._synthetic_constructor(properties, class_loc)

        return ContractNode(
            name=class_name,
            parent_class=parent_class,
            properties=properties,
            constructor=constructor,
            methods=methods,
            source_file=self.file_name,
        )

    # -- Annotations ---------------------------------------------------------

    def _skip_annotations(self) -> list[str]:
        """Consume @Foo / @Foo(...) annotations, returning the bare names."""
        names: list[str] = []
        while self.check(TOK_AT):
            self.advance()  # @
            if self.peek().kind == TOK_IDENT or self.peek().kind in (
                TOK_PUBLIC, TOK_PRIVATE, TOK_PROTECTED, TOK_STATIC, TOK_FINAL
            ):
                names.append(self.peek().value)
                self.advance()
            # Optional (...) arguments. We tolerate arbitrary token sequences
            # inside — they're ignored for our subset.
            if self.check(TOK_LPAREN):
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
        return names

    # -- Class members -------------------------------------------------------

    def _parse_member(self, class_name: str) -> PropertyNode | MethodNode | None:
        loc = self.loc()

        anns = self._skip_annotations()
        readonly = any(a == "Readonly" for a in anns)
        is_public_ann = any(a == "Public" for a in anns)

        # Skip Java modifiers — they don't affect the AST.
        while self.check(TOK_PUBLIC) or self.check(TOK_PRIVATE) or \
                self.check(TOK_PROTECTED) or self.check(TOK_STATIC) or \
                self.check(TOK_FINAL):
            self.advance()
        # Annotations can also appear between modifiers.
        more_anns = self._skip_annotations()
        if any(a == "Readonly" for a in more_anns):
            readonly = True
        if any(a == "Public" for a in more_anns):
            is_public_ann = True

        if self.check(TOK_RBRACE) or self.check(TOK_EOF):
            return None

        # Constructor: Name(...) { ... }
        if self.peek().kind == TOK_IDENT and self.peek().value == class_name \
                and self.peek(1).kind == TOK_LPAREN:
            return self._parse_constructor(class_name, loc)

        # Otherwise it's a field or method. Both start with a type then a name.
        # If the token after the type+name is `(`, it's a method; else a field.
        start_pos = self.pos
        try:
            type_node = self._parse_type()
        except _JavaParseError:
            raise

        # Method with `void` return type: _parse_type returned a CustomType("void")
        # — actually we raise for void if used as a field, but for a method
        # return type we want to accept it. Handle that by checking the keyword
        # directly before parsing type.
        # (implementation detail: _parse_type treats `void` as an IDENT-like
        # keyword; we check the original token to disambiguate method vs field.)
        name_tok = self.peek()
        if name_tok.kind != TOK_IDENT:
            raise _JavaParseError(
                f"line {name_tok.line}:{name_tok.col}: expected field or method name after type"
            )
        member_name = name_tok.value
        self.advance()

        if self.check(TOK_LPAREN):
            return self._parse_method(
                member_name, type_node, is_public_ann, loc
            )

        # Field declaration: optional `= initializer`, then `;`.
        init_expr: Expression | None = None
        if self.match_tok(TOK_EQ):
            init_expr = self._parse_expression()
        self.expect(TOK_SEMI, "';' after field declaration")

        return PropertyNode(
            name=member_name,
            type=type_node,
            readonly=readonly,
            initializer=init_expr,
            source_location=loc,
        )

    def _parse_constructor(self, class_name: str, loc: SourceLocation) -> MethodNode:
        # Consume class name token.
        self.advance()
        params = self._parse_params()
        body = self._parse_block()
        return MethodNode(
            name="constructor",
            params=params,
            body=body,
            visibility="public",
            source_location=loc,
        )

    def _parse_method(
        self,
        name: str,
        return_type: TypeNode,
        is_public_ann: bool,
        loc: SourceLocation,
    ) -> MethodNode:
        params = self._parse_params()
        visibility = "public" if is_public_ann else "private"
        body = self._parse_block()
        # return_type is intentionally unused by the Python-side AST: methods
        # in Rúnar are declared by their body structure.
        _ = return_type
        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility=visibility,
            source_location=loc,
        )

    def _parse_params(self) -> list[ParamNode]:
        self.expect(TOK_LPAREN, "'('")
        params: list[ParamNode] = []
        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            # parameters may carry annotations (rare, but valid Java).
            self._skip_annotations()
            while self.check(TOK_FINAL):
                self.advance()
            param_type = self._parse_type()
            name_tok = self.expect(TOK_IDENT, "parameter name")
            params.append(ParamNode(name=name_tok.value, type=param_type))
            if not self.match_tok(TOK_COMMA):
                break
        self.expect(TOK_RPAREN, "')'")
        return params

    # -- Synthetic constructor (mirrors Java reference impl) -----------------

    def _synthetic_constructor(
        self, properties: list[PropertyNode], loc: SourceLocation
    ) -> MethodNode:
        params: list[ParamNode] = []
        body: list[Statement] = []
        super_args: list[Expression] = []

        for p in properties:
            if p.initializer is not None:
                continue
            params.append(ParamNode(name=p.name, type=p.type))
            super_args.append(Identifier(name=p.name))

        body.append(ExpressionStmt(
            expr=CallExpr(callee=Identifier(name="super"), args=super_args),
            source_location=loc,
        ))
        for p in properties:
            if p.initializer is not None:
                continue
            body.append(AssignmentStmt(
                target=PropertyAccessExpr(property=p.name),
                value=Identifier(name=p.name),
                source_location=loc,
            ))

        return MethodNode(
            name="constructor",
            params=params,
            body=body,
            visibility="public",
            source_location=loc,
        )

    # -- Types ---------------------------------------------------------------

    def _parse_type(self) -> TypeNode:
        tok = self.peek()

        if tok.kind == TOK_BOOLEAN_KW:
            self.advance()
            return PrimitiveType(name="boolean")
        if tok.kind == TOK_VOID:
            self.advance()
            return PrimitiveType(name="void")
        if tok.kind == TOK_INT_KW or tok.kind == TOK_LONG_KW:
            self.advance()
            # `int` / `long` → bigint for Rúnar purposes (promotion happens
            # naturally because integer literals already become BigIntLiteral).
            return PrimitiveType(name="bigint")

        if tok.kind != TOK_IDENT:
            raise _JavaParseError(
                f"line {tok.line}:{tok.col}: expected type, got {tok.value!r}"
            )

        name = tok.value
        self.advance()

        # Qualified type name: java.math.BigInteger — unwrap to the tail.
        while self.check(TOK_DOT):
            # Peek ahead: only treat as qualified type if next is IDENT and the
            # one after is not `(` (a method call) and not `.` continuation end
            # into a non-type context. Since we only call _parse_type in type
            # positions we can safely consume.
            self.advance()
            tail = self.expect(TOK_IDENT, "qualified type segment")
            name = tail.value

        # FixedArray<T, N>
        if name == "FixedArray" and self.check(TOK_LT):
            self.advance()  # <
            element = self._parse_type()
            self.expect(TOK_COMMA, "',' in FixedArray")
            len_tok = self.expect(TOK_NUMBER, "integer literal length")
            try:
                length = int(len_tok.value, 0)
            except ValueError:
                length = 0
            self.expect(TOK_GT, "'>'")
            return FixedArrayType(element=element, length=length)

        # Skip other generic parameters (like Optional<T>) defensively.
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

        # Trailing `[]` — not commonly used, but safely pass through as a
        # FixedArray-ish type. We reject here since FixedArray<T,N> is the
        # sanctioned form.
        if self.check(TOK_LBRACKET) and self.peek(1).kind == TOK_RBRACKET:
            raise _JavaParseError(
                f"raw array types 'T[]' are not supported; use FixedArray<T, N> in {self.file_name}"
            )

        return _parse_type_name(name)

    # -- Block / statements --------------------------------------------------

    def _parse_block(self) -> list[Statement]:
        self.expect(TOK_LBRACE, "'{'")
        stmts: list[Statement] = []
        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            stmts.append(self._parse_statement())
        self.expect(TOK_RBRACE, "'}'")
        return stmts

    def _parse_statement(self) -> Statement:
        loc = self.loc()
        tok = self.peek()

        # Block → flatten single block to its statements sequence. The Java
        # reference parser rejects nested blocks; we follow suit.
        if tok.kind == TOK_LBRACE:
            raise _JavaParseError(
                f"line {tok.line}:{tok.col}: nested blocks are unsupported in {self.file_name}"
            )

        if tok.kind == TOK_IF:
            return self._parse_if(loc)
        if tok.kind == TOK_FOR:
            return self._parse_for(loc)
        if tok.kind == TOK_WHILE or tok.kind == TOK_DO:
            raise _JavaParseError(
                f"line {tok.line}:{tok.col}: while/do-while loops are not supported "
                f"in {self.file_name}"
            )
        if tok.kind == TOK_RETURN_KW:
            self.advance()
            value: Expression | None = None
            if not self.check(TOK_SEMI):
                value = self._parse_expression()
            self.expect(TOK_SEMI, "';' after return")
            return ReturnStmt(value=value, source_location=loc)

        # Variable declaration: starts with a type. Detecting "starts with a
        # type" requires lookahead because a statement like `x = foo();` also
        # starts with an identifier. We use the heuristic: a type declaration
        # has `<type> IDENT` or `<type> IDENT =`. We disambiguate by peeking.
        if self._looks_like_var_decl():
            return self._parse_var_decl(loc)

        # Everything else is expression / assignment statement.
        return self._parse_expr_statement(loc)

    def _looks_like_var_decl(self) -> bool:
        """Heuristic: the upcoming tokens begin a local variable declaration."""
        tok = self.peek()

        # Primitive keyword → always a decl.
        if tok.kind in (TOK_BOOLEAN_KW, TOK_INT_KW, TOK_LONG_KW):
            return True

        if tok.kind != TOK_IDENT:
            return False

        # Scan forward: <Ident>(.<Ident>)*(<...>)?(<Ident> =|<Ident>;)
        save = self.pos
        try:
            # type name, optionally qualified
            if self.peek().kind != TOK_IDENT:
                return False
            self.advance()
            while self.check(TOK_DOT):
                self.advance()
                if self.peek().kind != TOK_IDENT:
                    return False
                self.advance()
            # optional generic args
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
                    # If we hit a token that clearly terminates a statement,
                    # bail out.
                    if self.check(TOK_SEMI) or self.check(TOK_LBRACE) or self.check(TOK_RBRACE):
                        return False
                    self.advance()
            # optional array brackets — not supported but detect the form
            if self.check(TOK_LBRACKET) and self.peek(1).kind == TOK_RBRACKET:
                # Still could be a decl; let _parse_type raise.
                pass
            # Now we must see IDENT followed by `=`, `;`, or `,`.
            if self.peek().kind != TOK_IDENT:
                return False
            next_kind = self.peek(1).kind
            return next_kind in (TOK_EQ, TOK_SEMI, TOK_COMMA)
        finally:
            self.pos = save

    def _parse_var_decl(self, loc: SourceLocation) -> Statement:
        type_node = self._parse_type()
        name_tok = self.expect(TOK_IDENT, "variable name")
        if not self.match_tok(TOK_EQ):
            raise _JavaParseError(
                f"line {name_tok.line}:{name_tok.col}: local variable {name_tok.value!r} "
                f"must have an initializer in {self.file_name}"
            )
        init = self._parse_expression()
        self.expect(TOK_SEMI, "';' after variable declaration")
        return VariableDeclStmt(
            name=name_tok.value,
            type=type_node,
            mutable=True,
            init=init,
            source_location=loc,
        )

    def _parse_if(self, loc: SourceLocation) -> Statement:
        self.expect(TOK_IF, "'if'")
        self.expect(TOK_LPAREN, "'('")
        condition = self._parse_expression()
        self.expect(TOK_RPAREN, "')'")
        then_body = self._parse_stmt_or_block()
        else_body: list[Statement] | None = None
        if self.match_tok(TOK_ELSE):
            if self.check(TOK_IF):
                # `else if` — wrap nested IfStmt as the else branch.
                else_body = [self._parse_statement()]
            else:
                else_body = self._parse_stmt_or_block()
        return IfStmt(
            condition=condition,
            then=then_body,
            else_=else_body or [],
            source_location=loc,
        )

    def _parse_stmt_or_block(self) -> list[Statement]:
        if self.check(TOK_LBRACE):
            return self._parse_block()
        return [self._parse_statement()]

    def _parse_for(self, loc: SourceLocation) -> Statement:
        self.expect(TOK_FOR, "'for'")
        self.expect(TOK_LPAREN, "'('")

        init_stmt: VariableDeclStmt | None = None
        if not self.check(TOK_SEMI):
            if not self._looks_like_var_decl():
                raise _JavaParseError(
                    f"line {self.peek().line}:{self.peek().col}: for-loop must declare "
                    f"a single loop variable in {self.file_name}"
                )
            decl = self._parse_var_decl(self.loc())
            if not isinstance(decl, VariableDeclStmt):
                raise _JavaParseError("for-loop init must be a single variable declaration")
            init_stmt = decl
            # _parse_var_decl already consumed the trailing ';'.
        else:
            self.advance()  # consume lone ';'

        condition: Expression | None = None
        if not self.check(TOK_SEMI):
            condition = self._parse_expression()
        self.expect(TOK_SEMI, "';' after for condition")

        update_stmt: Statement | None = None
        if not self.check(TOK_RPAREN):
            update_loc = self.loc()
            update_expr = self._parse_expression()
            # Accept `i = i + 1` or `i++` / `++i` style.
            if self.check(TOK_EQ):
                self.advance()
                rhs = self._parse_expression()
                target = self._to_assign_target(update_expr)
                update_stmt = AssignmentStmt(
                    target=target, value=rhs, source_location=update_loc
                )
            elif self.check(TOK_PLUSEQ):
                self.advance()
                rhs = self._parse_expression()
                target = self._to_assign_target(update_expr)
                update_stmt = AssignmentStmt(
                    target=target,
                    value=BinaryExpr(op="+", left=target, right=rhs),
                    source_location=update_loc,
                )
            elif self.check(TOK_MINUSEQ):
                self.advance()
                rhs = self._parse_expression()
                target = self._to_assign_target(update_expr)
                update_stmt = AssignmentStmt(
                    target=target,
                    value=BinaryExpr(op="-", left=target, right=rhs),
                    source_location=update_loc,
                )
            else:
                update_stmt = ExpressionStmt(expr=update_expr, source_location=update_loc)

        self.expect(TOK_RPAREN, "')'")
        body = self._parse_stmt_or_block()

        return ForStmt(
            init=init_stmt,
            condition=condition,
            update=update_stmt,
            body=body,
            source_location=loc,
        )

    def _to_assign_target(self, expr: Expression) -> Expression:
        """Normalize `this.x` references to PropertyAccessExpr when used as an
        assignment target. All other expression shapes pass through."""
        if isinstance(expr, MemberExpr) and isinstance(expr.object, Identifier) \
                and expr.object.name == "this":
            return PropertyAccessExpr(property=expr.property)
        return expr

    def _parse_expr_statement(self, loc: SourceLocation) -> Statement:
        expr = self._parse_expression()

        if self.check(TOK_EQ):
            self.advance()
            value = self._parse_expression()
            self.expect(TOK_SEMI, "';' after assignment")
            target = self._to_assign_target(expr)
            return AssignmentStmt(target=target, value=value, source_location=loc)

        # Compound assignments map to `target = target <op> rhs`.
        compound_map = {
            TOK_PLUSEQ: "+",
            TOK_MINUSEQ: "-",
            TOK_STAREQ: "*",
            TOK_SLASHEQ: "/",
            TOK_PERCENTEQ: "%",
        }
        for tok_kind, op in compound_map.items():
            if self.check(tok_kind):
                self.advance()
                rhs = self._parse_expression()
                self.expect(TOK_SEMI, "';' after compound assignment")
                target = self._to_assign_target(expr)
                return AssignmentStmt(
                    target=target,
                    value=BinaryExpr(op=op, left=target, right=rhs),
                    source_location=loc,
                )

        self.expect(TOK_SEMI, "';' after expression statement")
        return ExpressionStmt(expr=expr, source_location=loc)

    # -- Expressions (precedence climbing) -----------------------------------

    def _parse_expression(self) -> Expression:
        return self._parse_ternary()

    def _parse_ternary(self) -> Expression:
        cond = self._parse_or()
        if self.match_tok(TOK_QUESTION):
            then_expr = self._parse_expression()
            self.expect(TOK_COLON, "':' in ternary")
            else_expr = self._parse_expression()
            return TernaryExpr(
                condition=cond, consequent=then_expr, alternate=else_expr
            )
        return cond

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
                left = _fold_compare_to_zero("===", left, right)
            elif self.match_tok(TOK_BANGEQ):
                right = self._parse_comparison()
                left = _fold_compare_to_zero("!==", left, right)
            else:
                break
        return left

    def _parse_comparison(self) -> Expression:
        left = self._parse_shift()
        while True:
            if self.match_tok(TOK_LT):
                right = self._parse_shift()
                left = _fold_compare_to_zero("<", left, right)
            elif self.match_tok(TOK_LTEQ):
                right = self._parse_shift()
                left = _fold_compare_to_zero("<=", left, right)
            elif self.match_tok(TOK_GT):
                right = self._parse_shift()
                left = _fold_compare_to_zero(">", left, right)
            elif self.match_tok(TOK_GTEQ):
                right = self._parse_shift()
                left = _fold_compare_to_zero(">=", left, right)
            else:
                break
        return left

    def _parse_shift(self) -> Expression:
        left = self._parse_add()
        while True:
            if self.match_tok(TOK_LSHIFT):
                right = self._parse_add()
                left = BinaryExpr(op="<<", left=left, right=right)
            elif self.match_tok(TOK_RSHIFT):
                right = self._parse_add()
                left = BinaryExpr(op=">>", left=left, right=right)
            else:
                break
        return left

    def _parse_add(self) -> Expression:
        left = self._parse_mul()
        while True:
            if self.match_tok(TOK_PLUS):
                right = self._parse_mul()
                left = BinaryExpr(op="+", left=left, right=right)
            elif self.match_tok(TOK_MINUS):
                right = self._parse_mul()
                left = BinaryExpr(op="-", left=left, right=right)
            else:
                break
        return left

    def _parse_mul(self) -> Expression:
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
        if self.match_tok(TOK_TILDE):
            return UnaryExpr(op="~", operand=self._parse_unary())
        if self.match_tok(TOK_MINUS):
            return UnaryExpr(op="-", operand=self._parse_unary())
        if self.match_tok(TOK_PLUS):
            # Unary +x == x (matches Java parser reference).
            return self._parse_unary()
        if self.match_tok(TOK_PLUSPLUS):
            return IncrementExpr(operand=self._parse_unary(), prefix=True)
        if self.match_tok(TOK_MINUSMINUS):
            return DecrementExpr(operand=self._parse_unary(), prefix=True)
        return self._parse_postfix()

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()
        while True:
            if self.check(TOK_DOT):
                self.advance()
                name_tok = self.expect(TOK_IDENT, "member name")
                # `this.x` → PropertyAccessExpr("x").
                if isinstance(expr, Identifier) and expr.name == "this":
                    expr = PropertyAccessExpr(property=name_tok.value)
                else:
                    expr = MemberExpr(object=expr, property=name_tok.value)
            elif self.check(TOK_LPAREN):
                expr = self._parse_call(expr)
            elif self.check(TOK_LBRACKET):
                self.advance()
                index = self._parse_expression()
                self.expect(TOK_RBRACKET, "']'")
                expr = IndexAccessExpr(object=expr, index=index)
            elif self.check(TOK_PLUSPLUS):
                self.advance()
                expr = IncrementExpr(operand=expr, prefix=False)
            elif self.check(TOK_MINUSMINUS):
                self.advance()
                expr = DecrementExpr(operand=expr, prefix=False)
            else:
                break
        return expr

    def _parse_call(self, callee: Expression) -> Expression:
        # Special-case `<expr>.fromHex("...")` — the string literal is only
        # legal in this position, so we intercept it before the generic
        # expression parser rejects bare strings.
        if isinstance(callee, MemberExpr) and callee.property == "fromHex" \
                and self.peek().kind == TOK_LPAREN \
                and self.peek(1).kind == TOK_STRING \
                and self.peek(2).kind == TOK_RPAREN:
            self.advance()  # (
            hex_tok = self.advance()  # string
            self.advance()  # )
            return ByteStringLiteral(value=hex_tok.value)

        self.expect(TOK_LPAREN, "'('")
        args: list[Expression] = []
        while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
            args.append(self._parse_expression())
            if not self.match_tok(TOK_COMMA):
                break
        self.expect(TOK_RPAREN, "')'")

        # BigInteger.valueOf(<int literal>) / Bigint.of(<int literal>) → BigIntLiteral.
        # Both the bare `BigInteger.valueOf` and the fully-qualified
        # `java.math.BigInteger.valueOf` spellings are accepted.
        if isinstance(callee, MemberExpr) \
                and len(args) == 1 and isinstance(args[0], BigIntLiteral) \
                and (_is_biginteger_value_of_callee(callee) or _is_bigint_of_callee(callee)):
            return BigIntLiteral(value=args[0].value)

        # Bigint.of(<arbitrary expression>) / BigInteger.valueOf(<arbitrary expression>)
        # — identity at the Rúnar AST level. Bigint and BigInteger collapse to
        # the same BIGINT primitive, so the wrap is a no-op: lower to the inner
        # expression. Mirrors JavaParser.java's identity branch. Both bare and
        # `java.math.BigInteger.valueOf` are accepted.
        if isinstance(callee, MemberExpr) \
                and len(args) == 1 \
                and (_is_biginteger_value_of_callee(callee) or _is_bigint_of_callee(callee)):
            return args[0]

        # <expr>.value() — unwrapping a Bigint back to its underlying BigInteger.
        # Symmetric no-op to Bigint.of(...) above.
        if isinstance(callee, MemberExpr) \
                and callee.property == "value" \
                and len(args) == 0:
            return callee.object
        # <expr>.toByteString() — Java-side coercion of Point / Bigint / Sig /
        # PubKey wrappers to their raw byte form. Rúnar Point is structurally
        # a ByteString so the TS canonical sources pass Points directly to
        # builtins like `cat`. Lower to a no-op (drop the call, keep the
        # receiver) so the Java IR matches the canonical IR byte-for-byte.
        if isinstance(callee, MemberExpr) \
                and callee.property == "toByteString" \
                and len(args) == 0:
            return callee.object

        # Bigint-wrapper arithmetic methods: `a.plus(b)` → BinaryExpr(+, a, b),
        # `a.neg()` → UnaryExpr(-, a), `a.abs()` → CallExpr(abs, a). Matched by
        # method name + arity; receiver type is not consulted (parser has no
        # type info at this stage); the typechecker rejects misuse. Mirrors
        # JavaParser.tryLowerBigintMethod. The same table also accepts the JDK
        # `BigInteger` spellings (`add`, `subtract`, `multiply`, `divide`,
        # `shiftLeft`, `shiftRight`).
        if isinstance(callee, MemberExpr):
            if len(args) == 1 and callee.property in _BIGINT_BINARY_METHODS:
                op = _BIGINT_BINARY_METHODS[callee.property]
                return BinaryExpr(op=op, left=callee.object, right=args[0])
            if len(args) == 0 and callee.property in ("neg", "negate"):
                return UnaryExpr(op="-", operand=callee.object)
            # `a.not()` -> UnaryExpr(~, a). Mirrors java.math.BigInteger#not();
            # the Bigint wrapper exposes the same method so Rúnar Java sources
            # can use it natively.
            if len(args) == 0 and callee.property == "not":
                return UnaryExpr(op="~", operand=callee.object)
            if len(args) == 0 and callee.property == "abs":
                return CallExpr(callee=Identifier(name="abs"), args=[callee.object])
            # <expr>.equals(<expr>) — Java's value-equality method. Lower to
            # the canonical BinaryExpr(===, a, b). Receiver type is not
            # consulted; the typechecker rejects misuse.
            if len(args) == 1 and callee.property == "equals":
                return BinaryExpr(op="===", left=callee.object, right=args[0])

        # Static-imported `assertThat(cond)` is a builtin alias for `assert`
        # in the canonical Java BuiltinRegistry. Peer typecheckers only know
        # `assert`, so rewrite the callee here.
        if isinstance(callee, Identifier) and callee.name == "assertThat":
            return CallExpr(callee=Identifier(name="assert"), args=args)

        return CallExpr(callee=callee, args=args)

    def _parse_primary(self) -> Expression:
        tok = self.peek()

        if tok.kind == TOK_NUMBER:
            self.advance()
            try:
                val = int(tok.value, 0) if tok.value.startswith(("0x", "0X")) else int(tok.value)
            except ValueError:
                val = 0
            return BigIntLiteral(value=val)

        if tok.kind == TOK_TRUE:
            self.advance()
            return BoolLiteral(value=True)
        if tok.kind == TOK_FALSE:
            self.advance()
            return BoolLiteral(value=False)

        if tok.kind == TOK_THIS:
            self.advance()
            return Identifier(name="this")
        if tok.kind == TOK_SUPER:
            self.advance()
            return Identifier(name="super")

        if tok.kind == TOK_NULL:
            raise _JavaParseError(
                f"line {tok.line}:{tok.col}: null literals are unsupported in {self.file_name}"
            )

        if tok.kind == TOK_STRING:
            raise _JavaParseError(
                f"line {tok.line}:{tok.col}: bare String literals are not allowed in "
                f"contracts; use ByteString.fromHex(\"...\") in {self.file_name}"
            )

        if tok.kind == TOK_LPAREN:
            self.advance()
            # Cast expressions (T)x are not supported — but `(expr)` is fine.
            inner = self._parse_expression()
            self.expect(TOK_RPAREN, "')'")
            return inner

        if tok.kind == TOK_NEW:
            return self._parse_new()

        # Special-case BigInteger.ZERO/ONE/TWO/TEN or Bigint.ZERO/ONE/TWO/TEN
        # before we reach the member-access handler. The Bigint wrapper
        # re-exports BigInteger's constants so both spellings are accepted
        # (matches JavaParser.convertExpression).
        if tok.kind == TOK_IDENT and tok.value in ("BigInteger", "Bigint") \
                and self.peek(1).kind == TOK_DOT and self.peek(2).kind == TOK_IDENT:
            tail = self.peek(2).value
            const_map = {"ZERO": 0, "ONE": 1, "TWO": 2, "TEN": 10}
            if tail in const_map and self.peek(3).kind != TOK_LPAREN:
                self.advance()  # BigInteger / Bigint
                self.advance()  # .
                self.advance()  # ZERO/ONE/TWO/TEN
                return BigIntLiteral(value=const_map[tail])

        # Pseudo-keyword identifiers from ByteString's literal helper — handled
        # uniformly inside _parse_call via the MemberExpr/fromHex branch. We
        # only need to emit the leading identifier here and let postfix take
        # over.
        if tok.kind == TOK_IDENT:
            self.advance()
            return Identifier(name=tok.value)

        raise _JavaParseError(
            f"line {tok.line}:{tok.col}: unexpected token {tok.value!r}"
        )

    def _parse_new(self) -> Expression:
        self.expect(TOK_NEW, "'new'")
        # new T[]{ a, b, c }
        type_tok = self.peek()
        if type_tok.kind == TOK_IDENT or \
                type_tok.kind in (TOK_BOOLEAN_KW, TOK_INT_KW, TOK_LONG_KW):
            self.advance()
            # qualified type name
            while self.check(TOK_DOT):
                self.advance()
                self.expect(TOK_IDENT, "qualified type segment")
            # generic parameters
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
            if self.check(TOK_LBRACKET):
                self.advance()
                self.expect(TOK_RBRACKET, "']'")
                # Optional `{ elem, ... }` initializer.
                if self.check(TOK_LBRACE):
                    self.advance()
                    elements: list[Expression] = []
                    while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
                        elements.append(self._parse_expression())
                        if not self.match_tok(TOK_COMMA):
                            break
                    self.expect(TOK_RBRACE, "'}'")
                    return ArrayLiteralExpr(elements=elements)
                raise _JavaParseError(
                    f"line {type_tok.line}:{type_tok.col}: new-array expressions must "
                    f"have an initializer list in {self.file_name}"
                )
        raise _JavaParseError(
            f"line {type_tok.line}:{type_tok.col}: only `new T[]{{ ... }}` is supported in "
            f"{self.file_name}"
        )


# ---------------------------------------------------------------------------
# BigInteger / Bigint callee shape recognisers
# ---------------------------------------------------------------------------


def _is_biginteger_value_of_callee(callee: Expression) -> bool:
    """True if `callee` is `BigInteger.valueOf` or `java.math.BigInteger.valueOf`."""
    if not isinstance(callee, MemberExpr) or callee.property != "valueOf":
        return False
    obj = callee.object
    if isinstance(obj, Identifier) and obj.name == "BigInteger":
        return True
    # java.math.BigInteger
    if isinstance(obj, MemberExpr) and obj.property == "BigInteger" \
            and isinstance(obj.object, MemberExpr) and obj.object.property == "math" \
            and isinstance(obj.object.object, Identifier) \
            and obj.object.object.name == "java":
        return True
    return False


def _is_bigint_of_callee(callee: Expression) -> bool:
    """True if `callee` is `Bigint.of`."""
    return (
        isinstance(callee, MemberExpr)
        and callee.property == "of"
        and isinstance(callee.object, Identifier)
        and callee.object.name == "Bigint"
    )


# ---------------------------------------------------------------------------
# compareTo folding: `a.compareTo(b) <cmp> 0` → `a <cmp> b`.
# Java's BigInteger.compareTo returns -1/0/1, so the comparison-against-zero
# idiom is the standard JDK spelling for ordered comparison on BigInteger.
# We rewrite at parse time so the canonical Rúnar AST sees a single
# BinaryExpr — avoiding a redundant SUB and matching the IR produced by
# `a <cmp> b` in other formats. The fold only triggers when one side is the
# literal 0 and the operator is one of the six comparison ops; any other
# shape leaves compareTo as an unknown call (which the typechecker rejects
# loudly).
# ---------------------------------------------------------------------------


_COMPARISON_OPS = frozenset({"<", "<=", ">", ">=", "===", "!=="})


def _fold_compare_to_zero(op: str, left: Expression, right: Expression) -> Expression:
    if op not in _COMPARISON_OPS:
        return BinaryExpr(op=op, left=left, right=right)
    pair = _compare_to_receiver_arg(left)
    if pair is not None and isinstance(right, BigIntLiteral) and right.value == 0:
        a, b = pair
        return BinaryExpr(op=op, left=a, right=b)
    pair = _compare_to_receiver_arg(right)
    if pair is not None and isinstance(left, BigIntLiteral) and left.value == 0:
        a, b = pair
        return BinaryExpr(op=op, left=b, right=a)
    return BinaryExpr(op=op, left=left, right=right)


def _compare_to_receiver_arg(e: Expression):
    if not isinstance(e, CallExpr):
        return None
    if not isinstance(e.callee, MemberExpr):
        return None
    if e.callee.property != "compareTo" or len(e.args) != 1:
        return None
    return (e.callee.object, e.args[0])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_java(source: str, file_name: str) -> ParseResult:
    """Parse a Java-syntax Runar contract (.runar.java)."""
    parser = _JavaParser(file_name)
    parser.tokens = _tokenize(source)
    parser.pos = 0

    try:
        contract = parser.parse()
    except _JavaParseError as e:
        return ParseResult(errors=[Diagnostic(message=str(e), severity=Severity.ERROR)])
    except (ValueError, IndexError) as e:
        return ParseResult(errors=[Diagnostic(
            message=f"Java parse error: {e}", severity=Severity.ERROR
        )])

    if parser.errors:
        return ParseResult(contract=contract, errors=parser.errors)
    return ParseResult(contract=contract)
