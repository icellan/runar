"""TypeScript format parser (.runar.ts) for the Runar compiler.

Ported from compilers/go/frontend/parser.go.
Hand-written tokenizer + recursive descent parser for TypeScript-like syntax.
"""

from __future__ import annotations

import re

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
from runar_compiler.frontend.input_limits import NestingCounter, with_nesting_limit  # F-213
from runar_compiler.frontend.int_literal import invalid_integer_literal, lex_number, scan_number_end  # F-026
from runar_compiler.frontend.diagnostic import (  # F-011
    JAVA_CHAR_LITERAL,
    OPTIONAL_CHAINING,
    UNTERMINATED_STRING_LITERAL,
    lex_error,
    static_method_message,
    with_lex_errors,
)
from runar_compiler.frontend.diagnostic import Diagnostic, Severity
from runar_compiler.frontend.sighash_directive import extract_sighash_directive, lost_directive_message


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


# Issue #109: `@embedAlways` comment directive (word-boundary anchored so an
# identifier like ``embedAlwaysFlag`` does not trip it), mirroring the TS
# `/@embedAlways\b/` scan.
_EMBED_ALWAYS_RE = re.compile(r"@embedAlways\b")

# Issue #123: `@sighash` comment directive token, mirroring the TS
# `/@sighash/` scan. N-039 (R85): no word boundary, so `@sighashSINGLE|FORKID`
# / `@sighashType` reach the extractor and are refused as malformed.
_SIGHASH_TOKEN_RE = re.compile(r"@sighash")


class Token:
    __slots__ = ("kind", "value", "line", "col", "leading_comments", "offset", "leading_spans")

    def __init__(self, kind: int, value: str, line: int, col: int,
                 leading_comments: str = ""):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col
        # Issue #109/#123: the raw text of comment(s) immediately preceding this
        # token (the token's "leading trivia"). Populated by the tokenizer so the
        # parser can detect ``@embedAlways`` / ``@sighash`` comment directives.
        self.leading_comments = leading_comments
        # N-199: source offset of the token, and the [start, end) offsets of
        # the comments in ``leading_comments`` (lost-directive check).
        self.offset = -1
        self.leading_spans: tuple = ()


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
    "Sha256Digest": "Sha256",
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


def _tokenize(source: str, lex: list | None = None, file_name: str = "") -> list[Token]:
    tokens: list[Token] = []
    lex = lex if lex is not None else []
    line = 1
    col = 0
    i = 0
    n = len(source)

    # Issue #109/#123: accumulate comment text so the *next* real token carries
    # it as leading trivia. Comments are otherwise discarded; the parser needs
    # the trivia to detect ``@embedAlways`` / ``@sighash`` directives.
    pending_comments: list[str] = []
    pending_spans: list[tuple[int, int]] = []  # N-199: offsets of pending_comments
    tok_start = 0  # N-199: offset of the token being scanned
    # F-282: a comment only becomes eligible to attach as leading trivia once
    # a line break has been crossed since the last real token (or at the very
    # start of the file). Mirrors ts-morph/TypeScript's own leading-comment
    # scan, which never collects a comment sharing a line with the PRECEDING
    # token — that comment is the preceding token's trailing trivia, not the
    # next node's leading trivia. Without this, `pending_comments` picked up
    # ANY comment seen since the last token regardless of newlines, so a
    # same-line trailing `@sighash` comment after one member silently leaked
    # onto the NEXT member, and a directive sharing a line with the preceding
    # member's own last token was wrongly honoured (both diverge from the TS
    # reference, verified directly against ts-morph).
    collecting = True
    optional_chain_seen = False  # N-121

    def _add(tok: Token) -> None:
        nonlocal collecting
        if pending_comments:
            tok.leading_comments = "\n".join(pending_comments)
            tok.leading_spans = tuple(pending_spans)
            pending_comments.clear()
            pending_spans.clear()
        tok.offset = tok_start
        collecting = False
        tokens.append(tok)

    while i < n:
        ch = source[i]

        # Newlines
        if ch == "\n":
            i += 1
            line += 1
            col = 0
            collecting = True
            continue
        if ch == "\r":
            i += 1
            if i < n and source[i] == "\n":
                i += 1
            line += 1
            col = 0
            collecting = True
            continue

        # Whitespace
        if ch in (" ", "\t"):
            i += 1
            col += 1
            continue

        # Single-line comment //
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            _comment_start = i
            while i < n and source[i] != "\n" and source[i] != "\r":
                i += 1
            if collecting:
                pending_comments.append(source[_comment_start:i])
                pending_spans.append((_comment_start, i))
            continue

        # Multi-line comment /* ... */
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            _comment_start = i
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
            if collecting:
                pending_comments.append(source[_comment_start:i])
                pending_spans.append((_comment_start, i))
            continue

        start_col = col
        tok_start = i

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
            _add(Token(TOK_STRING, val, line, start_col))
            continue

        # String literals: single or double quotes
        if ch in ("'", '"'):
            quote = ch
            i += 1
            col += 1
            start = i
            # F-011: a TS string literal cannot span lines; one that reaches
            # an unescaped line break or end of file is unterminated. (A
            # backslash before the line break is a line continuation.)
            while i < n and source[i] != quote and source[i] not in "\r\n":
                if source[i] == "\\":
                    i += 1
                    col += 1
                if i < n:
                    i += 1
                    col += 1
            val = source[start:i]
            if i < n and source[i] == quote:
                i += 1
                col += 1
            else:
                lex.append(lex_error(UNTERMINATED_STRING_LITERAL, file_name, line, start_col))
            _add(Token(TOK_STRING, val, line, start_col))
            continue

        # Numbers (F-026): the whole glued [0-9A-Za-z_] run is one TypeScript
        # integer literal, BigInt suffix `n` included.
        if "0" <= ch <= "9":
            end, num_str, _, _ = lex_number("ts", source, i, lex, file_name, line, start_col)
            col += end - i
            i = end
            _add(Token(TOK_NUMBER, num_str, line, start_col))
            continue

        # Identifiers and keywords
        if _is_ident_start(ch):
            start = i
            while i < n and _is_ident_part(source[i]):
                i += 1
                col += 1
            word = source[start:i]
            _add(Token(TOK_IDENT, word, line, start_col))
            continue

        # Three-character operators
        if i + 2 < n:
            three = source[i:i + 3]
            three_kind = {
                "===": TOK_EQEQEQ,
                "!==": TOK_NOTEQEQ,
            }.get(three)
            if three_kind is not None:
                _add(Token(three_kind, three, line, start_col))
                i += 3
                col += 3
                continue

        # N-121: `?.` not followed by a decimal digit is optional chaining,
        # which is disallowed. Report the first one; `?` is still lexed below.
        if (ch == "?" and not optional_chain_seen and source[i + 1:i + 2] == "."
                and source[i + 2:i + 3] not in tuple("0123456789")):
            optional_chain_seen = True
            lex.append(lex_error(OPTIONAL_CHAINING, file_name, line, start_col))

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
                _add(Token(two_kind, two, line, start_col))
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
            _add(Token(one_kind, ch, line, start_col))
            i += 1
            col += 1
            continue

        # Skip unknown characters
        i += 1
        col += 1

    tok_start = n
    _add(Token(TOK_EOF, "", line, col))
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_VALID_BASE_CLASSES = frozenset((
    "SmartContract",
    "StatefulSmartContract",
    "UnsafeSmartContract",
))


# F-064: statement keywords the TS reference refuses, mapped to the
# ts.SyntaxKind name its "Unsupported statement kind" diagnostic reports.
_UNSUPPORTED_STATEMENT_KEYWORDS = {
    "while": "WhileStatement",
    "do": "DoStatement",
    "switch": "SwitchStatement",
    "try": "TryStatement",
    "throw": "ThrowStatement",
    "debugger": "DebuggerStatement",
    "with": "WithStatement",
    "class": "ClassDeclaration",
    "function": "FunctionDeclaration",
    "break": "BreakStatement",
    "continue": "ContinueStatement",
}


class _TsParser:
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.source = ""  # N-199: raw text, for the lost-directive scan
        self.tokens: list[Token] = []
        self.pos = 0
        self.errors: list[Diagnostic] = []
        # F-213 measure (A): parse nesting (see input_limits.NestingCounter).
        self._nest = NestingCounter()

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

    def skip_semicolons(self) -> None:
        while self.check(TOK_SEMICOLON):
            self.advance()

    # -- Top-level parsing ---------------------------------------------------

    def parse_contract(self) -> ContractNode | None:
        # F-016: mirror the TS reference (01-parse.ts). Scan EVERY top-level
        # class; only one whose ``extends`` names a valid base is the contract.
        # Other classes are ignored wherever they sit. Each valid class after
        # the first is an error, and the LAST valid class is the one parsed.
        valid: list[int] = []  # token index of each valid ``class`` keyword
        while not self.check(TOK_EOF):
            # Skip import statements
            if self.check_ident("import"):
                self._skip_import()
                continue

            decl_loc = self.loc()
            # export class ... / export default class ...
            if self.check_ident("export"):
                self.advance()
                if self.check_ident("default"):
                    self.advance()
                if not self.check_ident("class"):
                    # Other export statements — skip to next semicolon or brace
                    self._skip_statement()
                    continue

            if self.check_ident("class"):
                class_pos = self.pos
                self.advance()
                self.match(TOK_IDENT)  # class name
                base = None
                if self.match_ident("extends") and self.check(TOK_IDENT):
                    base = self.peek().value
                # Skip the rest of the header and the balanced class body.
                self._skip_statement()
                if base in _VALID_BASE_CLASSES:
                    # The TS reference locates a declaration at its first
                    # token (``export`` included).
                    if valid:
                        self.errors.append(Diagnostic(
                            message="Only one SmartContract subclass is allowed per file",
                            severity=Severity.ERROR,
                            loc=decl_loc,
                        ))
                    valid.append(class_pos)
                continue

            # Skip anything else at top level
            self._skip_statement()

        if not valid:
            self.errors.append(Diagnostic(
                message=(
                    "No class extending SmartContract, StatefulSmartContract, "
                    "or UnsafeSmartContract found"
                ),
                severity=Severity.ERROR,
                loc=SourceLocation(file=self.file_name, line=1, column=0),
            ))
            return None

        self.pos = valid[-1]
        return self._parse_class()

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

        if parent_class not in (
            "SmartContract",
            "StatefulSmartContract",
            "UnsafeSmartContract",
        ):
            raise ValueError(
                f"no class extending SmartContract, StatefulSmartContract, "
                f"or UnsafeSmartContract found"
            )

        lbrace = self.expect(TOK_LBRACE)

        properties: list[PropertyNode] = []
        constructor: MethodNode | None = None
        methods: list[MethodNode] = []
        # N-199: comment spans attached to methods / properties.
        method_spans: list[tuple[int, int]] = []
        prop_spans: list[tuple[int, int]] = []

        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            self.skip_semicolons()
            if self.check(TOK_RBRACE) or self.check(TOK_EOF):
                break

            # Same token _parse_class_member reads its directive trivia from.
            member_spans = self.peek().leading_spans
            member = self._parse_class_member(parent_class)
            if member is None:
                continue

            if isinstance(member, PropertyNode):
                properties.append(member)
                prop_spans.extend(member_spans)
            elif isinstance(member, MethodNode):
                if member.name == "constructor":
                    if constructor is not None:
                        self.add_error("duplicate constructor")
                    constructor = member
                else:
                    methods.append(member)
                    method_spans.extend(member_spans)

        rbrace = self.expect(TOK_RBRACE)

        # N-199 (R75): a directive in the class body that no member reads.
        self._report_lost_directives(lbrace, rbrace, method_spans, prop_spans)

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

    def _report_lost_directives(
        self, lbrace: Token, rbrace: Token,
        method_spans: list[tuple[int, int]], prop_spans: list[tuple[int, int]],
    ) -> None:
        """N-199 (user decision R75): refuse a ``@sighash`` / ``@embedAlways``
        marker inside the contract class body that is not in the leading
        comments of a member of the kind that reads it (``@sighash`` of a
        method, ``@embedAlways`` of a property). A comment sharing a line with
        the preceding token never attaches (F-282), so such a directive used to
        be dropped silently. Text outside the class braces is prose and is not
        scanned. Mirrors reportLostDirectives in the TS reference."""
        source = self.source
        if lbrace.kind != TOK_LBRACE or rbrace.kind != TOK_RBRACE or lbrace.offset < 0 or rbrace.offset < 0:
            return
        start, end = lbrace.offset + 1, rbrace.offset
        lost: list[tuple[int, str]] = []
        for regex, directive, spans in (
            (_SIGHASH_TOKEN_RE, "@sighash", method_spans),
            (_EMBED_ALWAYS_RE, "@embedAlways", prop_spans),
        ):
            for m in regex.finditer(source, start, end):
                pos = m.start()
                if not any(s <= pos < e for s, e in spans):
                    lost.append((pos, directive))
        lost.sort()
        for pos, directive in lost:
            line = source.count("\n", 0, pos) + 1
            col = pos - (source.rfind("\n", 0, pos) + 1)
            self.errors.append(Diagnostic(
                message=lost_directive_message(directive), severity=Severity.ERROR,
                loc=SourceLocation(file=self.file_name, line=line, column=col)))

    # -- Class members -------------------------------------------------------

    def _parse_class_member(self, parent_class: str) -> PropertyNode | MethodNode | None:
        """Parse a property or method from inside a class body."""
        location = self.loc()

        # Issue #109/#123: comment directives (``/** @embedAlways */`` /
        # ``/** @sighash <FLAGS> */``) sit in the leading trivia of the member's
        # first token, captured by the tokenizer. Grab it before consuming
        # modifiers (which is where the trivia attaches).
        leading = self.peek().leading_comments

        # Collect modifiers: public, private, readonly
        visibility = "private"
        is_readonly = False
        is_static = False

        while True:
            if self.check_ident("static") and not is_static \
                    and self.pos + 1 < len(self.tokens) \
                    and self.tokens[self.pos + 1].kind == TOK_IDENT:
                # N-050: `static` used to be read as the member NAME, which
                # skipped the member and refused the contract by accident.
                is_static = True
                self.advance()
            elif self.check_ident("public"):
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
            if is_static:
                # N-050: a static method is not a contract method.
                self.errors.append(Diagnostic(
                    message=static_method_message(member_name),
                    severity=Severity.ERROR, loc=location))
            return self._parse_method(member_name, visibility, location, leading)

        if is_static:
            # Not a method: keep the pre-N-050 handling of a static member.
            self._skip_to_next_member()
            return None

        # Issue #109: `/** @embedAlways */` (or `// @embedAlways`) directive
        # immediately preceding the field opts it out of DCE elimination.
        embed_always = _EMBED_ALWAYS_RE.search(leading) is not None

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
                embed_always=embed_always,
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
                embed_always=embed_always,
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
        self, name: str, visibility: str, location: SourceLocation,
        leading: str = "",
    ) -> MethodNode:
        params = self._parse_params()

        # Skip optional return type annotation
        if self.check(TOK_COLON):
            self.advance()
            self._parse_type()

        body = self._parse_block()

        # Issue #123: `/** @sighash <FLAGS> */` (or `// @sighash ...`) directive
        # in the method's leading trivia → per-method BIP-143 sighash type.
        sighash_type = self._parse_sighash_directive(leading, name, visibility, location)

        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility=visibility,
            sighash_type=sighash_type,
            source_location=location,
        )

    def _parse_sighash_directive(
        self, leading: str, name: str, visibility: str,
        location: SourceLocation,
    ) -> int | None:
        """Detect + parse a ``@sighash`` directive on a method (issue #123).

        Returns the numeric BIP-143 sighash type, or ``None`` when no directive
        is present. Pushes an error for a malformed flag list or a directive on
        a non-public method (only public methods are spending entry points, so a
        ``@sighash`` on a private helper is meaningless).
        """
        if not _SIGHASH_TOKEN_RE.search(leading):
            return None

        # N-039 (R88a): located at the method declaration, like the TS reference.
        if visibility != "public":
            self.errors.append(Diagnostic(
                message=f"@sighash directive on non-public method '{name}' has no effect "
                        f"— only public methods are spending entry points",
                severity=Severity.ERROR, loc=location))
            return None

        result = extract_sighash_directive(leading)
        if result is None:
            return None
        if result.error is not None:
            self.errors.append(Diagnostic(
                message=f"Method '{name}': {result.error}",
                severity=Severity.ERROR, loc=location))
            return None
        return result.value

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
                with self._nest.nested(self.loc):
                    elem_type = self._parse_type()
                self.expect(TOK_COMMA)
                size_tok = self.expect(TOK_NUMBER)
                # N-120: the TS reference reads the size with
                # parseInt(text, 10), which refuses a 0x/0o/0b spelling.
                raw = (
                    self.source[size_tok.offset:scan_number_end(self.source, size_tok.offset)]
                    if size_tok.kind == TOK_NUMBER and size_tok.offset >= 0
                    else ""
                )
                if raw[:2] in ("0x", "0X", "0o", "0O", "0b", "0B"):
                    self.add_error(f"line {size_tok.line}: FixedArray size must be a positive integer literal, got '{raw}'")
                    self.expect(TOK_GT)
                    return CustomType(name=name)
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

        # `number` is not a Runar type (R-301). _parse_ts_type_name maps it onto
        # bigint, which is the right lowering but the wrong silence: a contract
        # declaring `x: number` compiled to the same script as `x: bigint` with
        # nothing said. The go and rust tiers have always refused it here. The
        # mapping stays so the rest of the parse continues on a sane node.
        if name == "number":
            self.add_error(
                "'number' type is not allowed in Runar contracts; use 'bigint' instead"
            )

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
            # F-064: a stray `;` is an EmptyStatement, refused by
            # _parse_statement — no longer swallowed here.
            stmt = self._parse_statement()
            if stmt is not None:
                stmts.append(stmt)

        self.expect(TOK_RBRACE)
        return stmts

    # -- Statement parsing ---------------------------------------------------

    def _parse_statement(self) -> Statement | None:
        with self._nest.nested(self.loc):
            return self._parse_statement_inner()

    def _parse_statement_inner(self) -> Statement | None:
        location = self.loc()
        tok = self.peek()

        # F-064: refuse every statement kind outside spec/grammar.md §9 with
        # the TS reference's diagnostic instead of falling through to the
        # expression parser (or silently skipping a `;`).
        unsupported = self._unsupported_statement_kind()
        if unsupported is not None:
            self.errors.append(Diagnostic(
                message=f"Unsupported statement kind: {unsupported}",
                severity=Severity.ERROR,
                loc=location,
            ))
            self._skip_unsupported_statement()
            return None

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

    def _unsupported_statement_kind(self) -> str | None:
        """The ts.SyntaxKind name of an unsupported statement starting here."""
        tok = self.peek()
        if tok.kind == TOK_SEMICOLON:
            return "EmptyStatement"
        if tok.kind == TOK_LBRACE:
            return "Block"
        if tok.kind != TOK_IDENT:
            return None
        if tok.value in _UNSUPPORTED_STATEMENT_KEYWORDS:
            return _UNSUPPORTED_STATEMENT_KEYWORDS[tok.value]
        if self._peek_next_kind() == TOK_COLON:
            return "LabeledStatement"
        if tok.value == "for":
            # for (const|let <name> in|of ...)
            ahead = self.tokens[self.pos + 1:self.pos + 5]
            if (len(ahead) == 4 and ahead[0].kind == TOK_LPAREN
                    and ahead[1].kind == TOK_IDENT and ahead[1].value in ("const", "let", "var")
                    and ahead[2].kind == TOK_IDENT
                    and ahead[3].kind == TOK_IDENT and ahead[3].value in ("in", "of")):
                return "ForInStatement" if ahead[3].value == "in" else "ForOfStatement"
        return None

    def _skip_unsupported_statement(self) -> None:
        """Consume a refused statement: tokens up to a `;` or a closing brace at
        nesting depth 0, stopping before a `}` that closes the enclosing block."""
        depth = 0
        while not self.check(TOK_EOF):
            tok = self.peek()
            if tok.kind in (TOK_LBRACE, TOK_LPAREN, TOK_LBRACKET):
                depth += 1
            elif tok.kind in (TOK_RBRACE, TOK_RPAREN, TOK_RBRACKET):
                if depth == 0:
                    return
                depth -= 1
                self.advance()
                if depth == 0 and tok.kind == TOK_RBRACE:
                    return
                continue
            elif tok.kind == TOK_SEMICOLON and depth == 0:
                self.advance()
                return
            self.advance()

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

        self.match(TOK_SEMICOLON)  # F-064: one terminator; a second `;` is an EmptyStatement

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
                with self._nest.nested(self.loc):
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
            # N-135: only this branch stops ON the `;`; the variable_decl
            # above already consumed its own, so matching again there
            # swallowed an empty condition slot's `;`.
            self.match(TOK_SEMICOLON)

        # Condition
        condition: Expression
        if self.check(TOK_SEMICOLON):
            # N-135: the TS reference refuses an empty condition slot; the
            # placeholder below only keeps the AST well-formed.
            self.errors.append(Diagnostic(
                message="For loop must have a condition",
                severity=Severity.ERROR,
                loc=loc,
            ))
            condition = BoolLiteral(value=False)
        else:
            condition = self._parse_expression()
        self.expect(TOK_SEMICOLON)

        # Update
        update_loc = self.loc()
        update: Statement
        if self.check(TOK_RPAREN):
            # N-132: the TS reference refuses an empty update slot; the
            # placeholder below only keeps the AST well-formed.
            self.errors.append(Diagnostic(
                message="For loop must have an update expression",
                severity=Severity.ERROR,
                loc=loc,
            ))
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

        self.match(TOK_SEMICOLON)  # F-064: one terminator; a second `;` is an EmptyStatement
        return ReturnStmt(value=value, source_location=loc)

    def _parse_expression_statement(self, loc: SourceLocation) -> Statement | None:
        expr = self._parse_expression()

        # Check for assignment: expr = value
        if self.match(TOK_ASSIGN):
            value = self._parse_expression()
            self.match(TOK_SEMICOLON)  # F-064: one terminator; a second `;` is an EmptyStatement
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
                self.match(TOK_SEMICOLON)  # F-064: one terminator; a second `;` is an EmptyStatement
                value = BinaryExpr(op=bin_op, left=expr, right=right)
                return AssignmentStmt(target=expr, value=value, source_location=loc)

        self.match(TOK_SEMICOLON)  # F-064: one terminator; a second `;` is an EmptyStatement
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
        with self._nest.nested(self.loc):
            return self._parse_ternary()

    def _parse_ternary(self) -> Expression:
        expr = self._parse_or()
        if self.match(TOK_QUESTION):
            with self._nest.nested(self.loc):
                consequent = self._parse_ternary()
            self.expect(TOK_COLON)
            with self._nest.nested(self.loc):
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
            with self._nest.nested(self.loc):
                operand = self._parse_unary()
            return UnaryExpr(op="!", operand=operand)
        if self.match(TOK_MINUS):
            with self._nest.nested(self.loc):
                operand = self._parse_unary()
            return UnaryExpr(op="-", operand=operand)
        if self.match(TOK_TILDE):
            with self._nest.nested(self.loc):
                operand = self._parse_unary()
            return UnaryExpr(op="~", operand=operand)
        # Prefix ++ and --
        if self.match(TOK_PLUSPLUS):
            with self._nest.nested(self.loc):
                operand = self._parse_unary()
            return IncrementExpr(operand=operand, prefix=True)
        if self.match(TOK_MINUSMINUS):
            with self._nest.nested(self.loc):
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

            # asm({ body, in_arity?, out_arity? }) compiler intrinsic.
            # Normalise into a CallExpr with three positional args so
            # downstream passes only have to walk a CallExpr. Both the hex
            # body and array body forms are accepted; the optional generic
            # type argument asm<T>(...) flags the expression form.
            if name == "asm" and (
                self.check(TOK_LPAREN) or self.check(TOK_LT)
            ):
                return self._parse_asm_call()

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
        return ArrayLiteralExpr(elements=elements)

    # -- asm() compiler intrinsic -------------------------------------------

    def _parse_asm_call(self) -> Expression:
        """Decode an ``asm({ body, in_arity?, out_arity? })`` call into a
        CallExpr whose positional args are
        ``[ByteStringLiteral(body), BigIntLiteral(in_arity), BigIntLiteral(out_arity)]``.

        Two surface body shapes are accepted:
          - Hex string literal:  ``body: '76a90088ac'``
          - Array of opcode names / push() calls:
            ``body: [OP_DUP, OP_HASH160, push('1234abcd'), OP_EQUALVERIFY]``

        The optional generic type argument ``asm<T>({...})`` marks the
        expression form; the captured T is stashed on
        ``CallExpr.asm_return_type``. On malformed input we still return a
        syntactically valid CallExpr so later passes can produce additional
        diagnostics without crashing.
        """
        callee = Identifier(name="asm")

        # Capture the generic type argument asm<T>({...}) if present, BEFORE
        # arg-shape diagnostics so the expression form still records its
        # return type even when other args are malformed.
        asm_return_type = ""
        if self.match(TOK_LT):
            type_tok = self.expect(TOK_IDENT)
            text = type_tok.value
            if text in ("bigint", "boolean", "ByteString"):
                asm_return_type = text
            else:
                self.add_error(
                    f"asm<T>() return type must be 'bigint', 'boolean', or "
                    f"'ByteString'; got {text!r}"
                )
            self.expect(TOK_GT)

        self.expect(TOK_LPAREN)

        body_expr: Expression | None = None
        in_arity_expr: Expression | None = None
        out_arity_expr: Expression | None = None

        if not self.check(TOK_LBRACE):
            tok = self.peek()
            self.add_error(
                "asm() argument must be an object literal "
                "{ body: '<hex>', in_arity?: <int>, out_arity?: <int> }, "
                f"got {tok.value!r}"
            )
            # Best-effort: consume to the closing paren.
            while not self.check(TOK_RPAREN) and not self.check(TOK_EOF):
                self.advance()
            self.match(TOK_RPAREN)
            return CallExpr(callee=callee, args=[], asm_return_type=asm_return_type)

        self.expect(TOK_LBRACE)
        while not self.check(TOK_RBRACE) and not self.check(TOK_EOF):
            key_tok = self.expect(TOK_IDENT)
            key = key_tok.value
            self.expect(TOK_COLON)

            if key == "body":
                if self.check(TOK_STRING):
                    str_tok = self.advance()
                    body_expr = ByteStringLiteral(value=str_tok.value)
                elif self.check(TOK_LBRACKET):
                    body_expr = ByteStringLiteral(value=self._encode_asm_array_body())
                else:
                    tok = self.peek()
                    self.add_error(
                        "asm() body must be a hex string literal or an array "
                        "of opcode names / push() calls; got "
                        f"{tok.value!r}."
                    )
                    body_expr = ByteStringLiteral(value="")
                    # skip the offending value token
                    if not self.check(TOK_COMMA) and not self.check(TOK_RBRACE):
                        self.advance()
            elif key == "in_arity":
                in_arity_expr = self._parse_asm_arity_literal("in_arity")
            elif key == "out_arity":
                out_arity_expr = self._parse_asm_arity_literal("out_arity")
            else:
                self.add_error(
                    f"asm() does not accept the {key!r} field; valid fields "
                    "are 'body', 'in_arity', 'out_arity'."
                )
                if not self.check(TOK_COMMA) and not self.check(TOK_RBRACE):
                    self.advance()

            if not self.match(TOK_COMMA):
                break

        self.expect(TOK_RBRACE)
        self.expect(TOK_RPAREN)

        if body_expr is None:
            self.add_error(
                "asm() requires a 'body' field with a hex string literal value"
            )
            body_expr = ByteStringLiteral(value="")
        # Defaults: in_arity=0, out_arity=1. The out_arity=1 default reflects
        # the public-method-must-terminate-truthy invariant.
        if in_arity_expr is None:
            in_arity_expr = BigIntLiteral(value=0)
        if out_arity_expr is None:
            out_arity_expr = BigIntLiteral(value=1)

        return CallExpr(
            callee=callee,
            args=[body_expr, in_arity_expr, out_arity_expr],
            asm_return_type=asm_return_type,
        )

    def _parse_asm_arity_literal(self, field_name: str) -> Expression:
        """Parse a non-negative integer literal arity field for asm()."""
        if self.check(TOK_NUMBER):
            num_tok = self.advance()
            try:
                val = int(num_tok.value, 0)
            except ValueError:
                val = -1
            if val < 0:
                self.add_error(
                    f"asm() {field_name} must be a non-negative integer "
                    f"literal, got {num_tok.value!r}"
                )
                return BigIntLiteral(value=0)
            return BigIntLiteral(value=val)
        tok = self.peek()
        self.add_error(
            f"asm() {field_name} must be a non-negative integer literal, "
            f"got {tok.value!r}"
        )
        if not self.check(TOK_COMMA) and not self.check(TOK_RBRACE):
            self.advance()
        return BigIntLiteral(value=0)

    def _encode_asm_array_body(self) -> str:
        """Encode an ``asm({ body: [OP_DUP, push(0x42), ...] })`` array literal
        to its hex byte representation. Uses the same push-encoding helpers as
        the emit pass so the bytes are byte-identical to what the emitter
        would produce for the equivalent literal.
        """
        from runar_compiler.codegen.emit import (
            OPCODES,
            encode_push_big_int,
            encode_push_data,
        )

        hex_str = ""
        self.expect(TOK_LBRACKET)
        while not self.check(TOK_RBRACKET) and not self.check(TOK_EOF):
            if self.check(TOK_IDENT):
                name = self.advance().value
                # push(<literal>) call.
                if name == "push" and self.check(TOK_LPAREN):
                    self.expect(TOK_LPAREN)
                    pushed = self._encode_asm_push_literal(
                        OPCODES, encode_push_big_int, encode_push_data
                    )
                    self.expect(TOK_RPAREN)
                    hex_str += pushed
                else:
                    b = OPCODES.get(name)
                    if b is None:
                        self.add_error(
                            f"Unknown opcode {name!r} in asm() body array. "
                            "Expected an OP_* identifier (e.g. OP_DUP, "
                            "OP_HASH160) or a push(...) call."
                        )
                    else:
                        hex_str += f"{b:02x}"
            else:
                tok = self.peek()
                self.add_error(
                    "asm() body array element must be an opcode identifier "
                    "(e.g. OP_DUP) or a push(<literal>) call; got "
                    f"{tok.value!r}"
                )
                self.advance()

            if not self.match(TOK_COMMA):
                break
        self.expect(TOK_RBRACKET)
        return hex_str

    def _encode_asm_push_literal(
        self, opcodes, encode_push_big_int, encode_push_data
    ) -> str:
        """Encode a literal argument passed to ``push(...)`` inside an asm()
        body array. Returns the encoded hex string ('' on error).
        """
        tok = self.peek()
        # Negative number: -<number>
        if self.check(TOK_MINUS):
            self.advance()
            if self.check(TOK_NUMBER):
                num_tok = self.advance()
                try:
                    val = -int(num_tok.value, 0)
                except ValueError:
                    self.add_error(
                        "push() argument is not a valid integer literal: "
                        f"{num_tok.value!r}"
                    )
                    return ""
                h, _ = encode_push_big_int(val)
                return h
            self.add_error(
                "push() argument must be a literal value (bigint, number, "
                "boolean, or hex string), got prefix expression"
            )
            return ""
        if self.check(TOK_NUMBER):
            num_tok = self.advance()
            try:
                val = int(num_tok.value, 0)
            except ValueError:
                self.add_error(
                    "push() argument is not a valid integer literal: "
                    f"{num_tok.value!r}"
                )
                return ""
            h, _ = encode_push_big_int(val)
            return h
        if self.check(TOK_IDENT) and tok.value in ("true", "false"):
            self.advance()
            return "51" if tok.value == "true" else "00"
        if self.check(TOK_STRING):
            str_tok = self.advance()
            raw = str_tok.value
            import re as _re
            if len(raw) % 2 != 0 or not _re.fullmatch(r"[0-9a-fA-F]*", raw):
                self.add_error(
                    f"push() ByteString argument must be even-length hex "
                    f"(got {raw!r})"
                )
                return ""
            return encode_push_data(bytes.fromhex(raw)).hex()
        self.add_error(
            "push() argument must be a literal value (bigint, number, "
            f"boolean, or hex string), got {tok.value!r}"
        )
        self.advance()
        return ""


def _parse_number(s: str) -> Expression:
    try:
        val = int(s, 0)
    except ValueError:
        val = 0
    # Python ints are arbitrary-precision; Runar's BigIntLiteral carries the
    # full Python int so 256-bit constants (e.g. the secp256k1 group order
    # used in schnorr-zkp's s-bound assert) round-trip cleanly through
    # codegen. Downstream consumers (load_const serializer) handle the
    # arbitrary-precision case via decimal-string encoding.
    return BigIntLiteral(value=val)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_ts(source: str, file_name: str) -> ParseResult:
    """F-011: run the parser below and keep its tokenizer's diagnostics."""
    # DoS-bound size guard, enforced at every exported parser entry, not
    # just parse_source. N-136.
    from runar_compiler.frontend.input_limits import assert_source_bytes_under_limit
    assert_source_bytes_under_limit(source)
    lex: list = []
    return with_lex_errors(
        with_nesting_limit(file_name, lambda: _parse_ts_tokens(source, file_name, lex)), lex
    )


def _parse_ts_tokens(source: str, file_name: str, lex: list) -> ParseResult:
    """Parse a TypeScript-syntax Runar contract (.runar.ts)."""
    p = _TsParser(file_name)
    p.source = source
    p.tokens = _tokenize(source, lex, file_name)
    p.pos = 0

    try:
        contract = p.parse_contract()
    except ValueError as e:
        return ParseResult(errors=[Diagnostic(message=str(e), severity=Severity.ERROR)])

    if p.errors:
        return ParseResult(contract=contract, errors=p.errors)
    return ParseResult(contract=contract)
