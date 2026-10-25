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
from runar_compiler.frontend.input_limits import NestingCounter, with_nesting_limit  # F-213
from runar_compiler.frontend.int_literal import invalid_integer_literal, lex_number  # F-026
from runar_compiler.frontend.diagnostic import (  # F-011
    JAVA_CHAR_LITERAL,
    PY_BYTES_NON_ASCII,
    PY_STATEMENT_LINE_BREAK,
    UNTERMINATED_STRING_LITERAL,
    invalid_escape_sequence_message,
    lex_error,
    with_lex_errors,
)
from runar_compiler.frontend.diagnostic import Diagnostic, Severity, reject_unknown_return_type, static_method_message, unexpected_class_body_token_message, unexpected_token_after_class_message, unsupported_statement_message
from runar_compiler.frontend.identifier_collision import collision_diagnostics
from runar_compiler.frontend.sighash_directive import lost_directive_message, resolve_native_sighash


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

# N-053: the non-name tokens that can begin an expression (mirrors the TS
# reference's PY_EXPRESSION_START), and the keywords the TS reference lexes as
# their own tokens that begin neither a statement form nor an expression.
_PY_EXPR_START_KINDS = frozenset({
    TOK_NUMBER, TOK_STRING, TOK_LPAREN, TOK_LBRACKET, TOK_MINUS, TOK_TILDE, TOK_BANG,
})
_PY_NON_EXPR_KEYWORDS = frozenset({
    "class", "def", "elif", "else", "in", "range", "from", "import",
})


def _py_token_text(tok) -> str:
    """A token's source text, for a diagnostic (N-053)."""
    names = {TOK_INDENT: "INDENT", TOK_DEDENT: "DEDENT", TOK_NEWLINE: "NEWLINE",
             TOK_EOF: "eof", TOK_AMPAMP: "and", TOK_PIPEPIPE: "or"}
    return names.get(tok.kind, tok.value)


class Token:
    __slots__ = ("kind", "value", "line", "col", "is_bytes")

    def __init__(self, kind: int, value: str, line: int, col: int, is_bytes: bool = False):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col
        # N-093: a ``b"..."`` literal (TS lexes it as a distinct ``hexstring``
        # token), so ``@public(sighash=b"...")`` is refused as malformed.
        self.is_bytes = is_bytes


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
    "add_raw_output": "addRawOutput",
    "add_data_output": "addDataOutput",
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
    # Intent sub-covenant intrinsics (BSVM Phase 13).
    "extract_prev_output_script": "extractPrevOutputScript",
    "require_output_p2pkh":       "requireOutputP2PKH",
    "current_block_height":       "currentBlockHeight",
    "continuation_amount":        "continuationAmount",
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
    "int_to_str": "int2str",
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

# F-203: the single-character escapes CPython defines for bytes and str.
_PY_SIMPLE_ESCAPES = {
    "\\": 0x5C, "'": 0x27, '"': 0x22, "a": 0x07, "b": 0x08,
    "f": 0x0C, "n": 0x0A, "r": 0x0D, "t": 0x09, "v": 0x0B,
}
_OCTAL = "01234567"
_HEX = "0123456789abcdefABCDEF"


def _decode_py_literal(body: str, is_bytes: bool) -> tuple[str, str, str | None]:
    """F-203: decode the body of a .runar.py quoted literal the way CPython
    decodes a bytes (``is_bytes``) or str literal -- the TS reference's
    decodePyLiteral, implemented explicitly (no codecs).

    Returns ``(text, hex, error)``: the decoded text, its bytes as hex
    (meaningful for bytes only; ``\\xHH`` keeps its digits verbatim) and the
    first refusal or None. A trailing lone backslash only arises for an
    unterminated literal, which the tokenizer already refuses; it is dropped.
    """
    text: list[str] = []
    hexs: list[str] = []

    def push(v: int) -> None:
        text.append(chr(v))
        hexs.append(f"{v:02x}")

    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if is_bytes and ord(c) >= 0x80:
            return "".join(text), "".join(hexs), PY_BYTES_NON_ASCII
        if c != "\\":
            text.append(c)
            if is_bytes:
                hexs.append(f"{ord(c):02x}")
            i += 1
            continue
        if i + 1 >= n:
            break
        e = body[i + 1]
        if e in _PY_SIMPLE_ESCAPES:
            push(_PY_SIMPLE_ESCAPES[e])
            i += 2
            continue
        if e in _OCTAL:
            j = i + 1
            while j < n and j < i + 4 and body[j] in _OCTAL:
                j += 1
            v = int(body[i + 1 : j], 8)
            if v > 0xFF:
                return "".join(text), "".join(hexs), invalid_escape_sequence_message(body[i:j])
            push(v)
            i = j
            continue
        if e == "x":
            if not (i + 3 < n and body[i + 2] in _HEX and body[i + 3] in _HEX):
                return "".join(text), "".join(hexs), invalid_escape_sequence_message("\\x")
            text.append(chr(int(body[i + 2 : i + 4], 16)))
            hexs.append(body[i + 2 : i + 4])
            i += 4
            continue
        if is_bytes and ord(e) >= 0x80:
            return "".join(text), "".join(hexs), PY_BYTES_NON_ASCII
        # Anything else -- including str's \\N{..}, \\u and \\U, which the
        # surface does not support -- is refused.
        return "".join(text), "".join(hexs), invalid_escape_sequence_message("\\" + e)
    return "".join(text), "".join(hexs), None


def _scan_py_quoted(source: str, i: int, quote: str) -> int:
    """F-011/F-203: scan a single-line quoted literal from just after its
    opening quote. A backslash always takes the next character with it (so an
    escaped quote does not close the literal); a backslash at a line break or
    end of file is a continuation, which this surface does not support -- the
    literal is then unterminated. Returns the index of the closing quote, or
    of the line break / end of file where the literal stops."""
    n = len(source)
    while i < n and source[i] != quote and source[i] not in "\r\n":
        if source[i] == "\\":
            if i + 1 >= n or source[i + 1] in "\r\n":
                return i + 1
            i += 2
            continue
        i += 1
    return i


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
    "Sha256Digest": "Sha256",
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


def _tokenize_raw(source: str, lex: list | None = None, file_name: str = "") -> list[Token]:
    """Produce tokens including NEWLINE but without INDENT/DEDENT."""
    tokens: list[Token] = []
    lex = lex if lex is not None else []
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
            # F-011: a single-line literal that reaches a line break (escaped or
            # not) or end of file is unterminated; it must never run on into the
            # following lines.
            i = _scan_py_quoted(source, i, quote)
            col += i - start
            val = source[start:i]
            if i < n and source[i] == quote:
                i += 1
                col += 1
            else:
                lex.append(lex_error(UNTERMINATED_STRING_LITERAL, file_name, line, start_col))
            # F-203: escapes decode as in CPython bytes literals.
            _, hex_val, esc_err = _decode_py_literal(val, True)
            if esc_err is not None:
                lex.append(lex_error(esc_err, file_name, line, start_col))
            tokens.append(Token(TOK_STRING, hex_val, line, start_col, is_bytes=True))
            continue

        # String literals
        if ch in ("'", '"'):
            quote = ch
            # Triple-quote — always a docstring in Rúnar. Skip without emitting a token.
            if i + 2 < n and source[i + 1] == quote and source[i + 2] == quote:
                i += 3
                col += 3
                open_line = line
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
                else:
                    # F-011: still open at end of file.
                    lex.append(lex_error(UNTERMINATED_STRING_LITERAL, file_name, open_line, start_col))
                    i = n
                continue
            i += 1
            col += 1
            start = i
            # F-011: a single-line literal that reaches a line break (escaped or
            # not) or end of file is unterminated; it must never run on into the
            # following lines.
            i = _scan_py_quoted(source, i, quote)
            col += i - start
            val = source[start:i]
            if i < n and source[i] == quote:
                i += 1
                col += 1
            else:
                lex.append(lex_error(UNTERMINATED_STRING_LITERAL, file_name, line, start_col))
            # F-203: a str literal decodes the same escapes as CPython does.
            text_val, _, esc_err = _decode_py_literal(val, False)
            if esc_err is not None:
                lex.append(lex_error(esc_err, file_name, line, start_col))
            tokens.append(Token(TOK_STRING, text_val, line, start_col))
            continue

        # Numbers (F-026): the whole glued [0-9A-Za-z_] run is one literal.
        if "0" <= ch <= "9":
            end, num_str, _, _ = lex_number("py", source, i, lex, file_name, line, start_col)
            col += end - i
            i = end
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

        # N-033: a character the TS reference does not tokenize (`;`, `{`,
        # `}`, `$`, `?`, ...) is refused, never skipped.
        lex.append(lex_error("Unexpected character '%s'" % ch, file_name, line, start_col))
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
        # F-017: (source spelling, Rúnar name) of every declared identifier.
        self.declared: list[tuple[str, str]] = []
        # N-046: the locals already bound in the current method, so a later
        # ``name = expr`` of one of them is emitted as an AssignmentStmt, not a
        # fresh VariableDeclStmt. Python is function-scoped, so rebinding an
        # existing local inside a loop body or an if-arm IS an assignment; ANF
        # lowering alpha-renames a VariableDeclStmt that reuses an enclosing
        # binding's name. Snapshot/restored around if-branches and loop bodies
        # exactly as the Ruby parser's ``declared_locals``.
        self.declared_locals: set[str] = set()
        # F-213 measure (A): parse nesting (see input_limits.NestingCounter).
        self._nest = NestingCounter()

    def _bind_local(self, name: str, typ, init: Expression, loc: SourceLocation) -> Statement:
        """N-046: ``name = init`` is an assignment when the method already
        bound ``name``, otherwise a declaration."""
        if name in self.declared_locals:
            return AssignmentStmt(target=Identifier(name=name), value=init, source_location=loc)
        self.declared_locals.add(name)
        return VariableDeclStmt(name=name, type=typ, mutable=True, init=init, source_location=loc)

    def declare(self, raw: str) -> str:
        """Convert a DECLARED identifier and record it for the F-017
        collision rule (see identifier_collision.py)."""
        name = py_convert_name(raw)
        self.declared.append((raw, name))
        return name

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
                with self._nest.nested(self.loc):
                    inner = self.parse_type_annotation()
                self.expect(TOK_RBRACKET)
                return inner
            return CustomType(name=name)

        if name == "FixedArray":
            if self.match(TOK_LBRACKET):
                with self._nest.nested(self.loc):
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

        if parent_class not in (
            "SmartContract",
            "StatefulSmartContract",
            "UnsafeSmartContract",
        ):
            raise ValueError(
                f"unknown parent class: '{parent_class}', expected SmartContract, "
                "StatefulSmartContract, or UnsafeSmartContract"
            )

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

            # Decorators: @public (any others make a private method). N-050: a
            # method may carry several (`@public @staticmethod`), so read them all.
            if self.check(TOK_AT):
                decorators: list[str] = []
                sighash_specs: list[str | None] = []
                while self.check(TOK_AT):
                    self.advance()
                    dec_name = self.expect(TOK_IDENT).value
                    decorators.append(dec_name)
                    # N-093: ``@public(sighash="FLAGS")`` is the native
                    # spelling of the ``@sighash`` directive.
                    if dec_name == "public" and self.check(TOK_LPAREN):
                        sighash_specs.extend(self._parse_public_decorator_args())
                    self.skip_newlines()
                decorator = decorators[-1]

                if (
                    self.check_ident("def")
                    and sighash_specs
                    and self.pos + 1 < len(self.tokens)
                    and self.tokens[self.pos + 1].value == "__init__"
                ):
                    # N-093: the constructor is not a spending entry point.
                    self.errors.append(Diagnostic(
                        message=lost_directive_message("@sighash"),
                        severity=Severity.ERROR, loc=self.loc()))
                    sighash_specs = []

                if self.check_ident("def"):
                    if "staticmethod" in decorators or "classmethod" in decorators:
                        # N-050: a class-level function is not a contract method.
                        name = self.tokens[self.pos + 1].value if self.pos + 1 < len(self.tokens) else ""
                        self.errors.append(Diagnostic(
                            message=static_method_message(name),
                            severity=Severity.ERROR, loc=self.loc()))
                    method = self.parse_method(
                        "public" if "public" in decorators else "private", sighash_specs,
                    )
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

            # N-033: any other token is refused, never skipped.
            self._refuse_class_body_token()

        self.match(TOK_DEDENT)

        # N-410: nothing but blank lines may follow the class (N-004 did this
        # for .runar.rb); a method or class after it used to be dropped unread.
        self.skip_newlines()
        if not self.check(TOK_EOF):
            trailing = self.peek()
            self.errors.append(lex_error(unexpected_token_after_class_message(_py_token_text(trailing)), self.file_name, trailing.line, trailing.col))

        if constructor is None:
            # N-032: auto-generate from the uninitialized properties (declaration
            # order): super(...) first, then self.p = p.
            uninit = [p for p in properties if p.initializer is None]
            ctor_loc = SourceLocation(file=self.file_name, line=1, column=0)
            constructor = MethodNode(
                name="constructor",
                params=[ParamNode(name=p.name, type=p.type) for p in uninit],
                body=[
                    ExpressionStmt(
                        expr=CallExpr(
                            callee=Identifier(name="super"),
                            args=[Identifier(name=p.name) for p in uninit],
                        ),
                        source_location=ctor_loc,
                    ),
                    *[
                        AssignmentStmt(
                            target=PropertyAccessExpr(property=p.name),
                            value=Identifier(name=p.name),
                            source_location=ctor_loc,
                        )
                        for p in uninit
                    ],
                ],
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

    def _refuse_class_body_token(self) -> None:
        """N-033: a class-body token that begins no property, method,
        decorator or ``pass`` is refused at that token (N-004's diagnostic),
        and the rest of its line is skipped."""
        tok = self.advance()
        text = "INDENT" if tok.kind == TOK_INDENT else tok.value
        self.errors.append(lex_error(unexpected_class_body_token_message(text), self.file_name, tok.line, tok.col))
        while not (self.check(TOK_NEWLINE) or self.check(TOK_DEDENT) or self.check(TOK_EOF)):
            self.advance()

    def _is_property_decl(self) -> bool:
        if self.pos + 1 >= len(self.tokens):
            return False
        return self.tokens[self.pos + 1].kind == TOK_COLON

    # -- Property parsing ----------------------------------------------------

    def parse_property(self, parent_class: str) -> PropertyNode | None:
        location = self.loc()
        name_tok = self.expect(TOK_IDENT)
        prop_name = self.declare(name_tok.value)
        self.expect(TOK_COLON)

        # Parse type (possibly Readonly[T]). N-093: ``EmbedAlways[T]`` is the
        # native spelling of the ``@embedAlways`` directive; the two wrappers
        # compose in either order.
        is_readonly = False
        embed_always = False
        wrappers = 0
        while self.check_ident("Readonly") or self.check_ident("EmbedAlways"):
            if self.advance().value == "Readonly":
                is_readonly = True
            else:
                embed_always = True
            self.expect(TOK_LBRACKET)
            wrappers += 1
        # In SmartContract (and UnsafeSmartContract), all properties are
        # automatically readonly.
        if parent_class in ("SmartContract", "UnsafeSmartContract"):
            is_readonly = True

        typ_node = self.parse_type_annotation()
        for _ in range(wrappers):
            self.expect(TOK_RBRACKET)

        # Parse optional initializer: = value
        initializer = None
        if self.match(TOK_ASSIGN):
            initializer = self.parse_expression()

        # F-026: the field declaration ends at its line break.
        self._expect_statement_end()
        self.skip_newlines()

        return PropertyNode(
            name=prop_name,
            type=typ_node,
            readonly=is_readonly,
            initializer=initializer,
            embed_always=embed_always,
            source_location=location,
        )

    # -- Constructor parsing -------------------------------------------------

    def parse_constructor(self, properties: list[PropertyNode]) -> MethodNode:
        location = self.loc()
        self.expect_ident("def")
        self.expect_ident("__init__")

        # N-046: reset local tracking for this method's scope.
        self.declared_locals = set()

        params = self.parse_params()

        if self.match(TOK_ARROW):
            self.advance()  # skip return type

        self.expect(TOK_COLON)
        body = self.parse_block()

        # Transform super().__init__(...) -> super(...) form
        constructor_body: list[Statement] = []

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
                                continue
            constructor_body.append(stmt)

        return MethodNode(
            name="constructor",
            params=params,
            body=constructor_body,
            visibility="public",
            source_location=location,
        )

    # -- Method parsing ------------------------------------------------------

    def _parse_public_decorator_args(self) -> list[str | None]:
        """N-093: the argument list of ``@public(...)``. The only argument is
        the keyword ``sighash=<str>``; each one yields its string, and any other
        argument (positional, another keyword, a non-str value) yields ``None``,
        which is refused as a malformed spelling."""
        specs: list[str | None] = []
        self.expect(TOK_LPAREN)
        while not self.check(TOK_RPAREN) and not self.check(TOK_NEWLINE) and not self.check(TOK_EOF):
            is_sighash_kw = (
                self.check_ident("sighash")
                and self.pos + 1 < len(self.tokens)
                and self.tokens[self.pos + 1].kind == TOK_ASSIGN
            )
            if is_sighash_kw:
                self.advance()  # 'sighash'
                self.advance()  # '='
            # One argument value: up to the next top-level ',' or ')'.
            first = self.peek()
            count = 0
            depth = 0
            while not self.check(TOK_NEWLINE) and not self.check(TOK_EOF):
                k = self.peek().kind
                if k in (TOK_COMMA, TOK_RPAREN) and depth == 0:
                    break
                if k in (TOK_LPAREN, TOK_LBRACKET):
                    depth += 1
                if k in (TOK_RPAREN, TOK_RBRACKET):
                    depth -= 1
                self.advance()
                count += 1
            ok = is_sighash_kw and count == 1 and first.kind == TOK_STRING and not first.is_bytes
            specs.append(first.value if ok else None)
            if not self.match(TOK_COMMA):
                break
        self.expect(TOK_RPAREN)
        return specs

    def parse_method(self, visibility: str, sighash_specs: list[str | None] | None = None) -> MethodNode:
        location = self.loc()
        self.expect_ident("def")
        name_tok = self.expect(TOK_IDENT)
        name = self.declare(name_tok.value)

        # N-046: reset local tracking for this method's scope.
        self.declared_locals = set()

        params = self.parse_params()

        if self.match(TOK_ARROW):
            # The AST keeps no return type; N-331 refuses an unknown name.
            # `None` is Python's spelling of "returns nothing".
            ret_type = self.parse_type_annotation()
            if not (isinstance(ret_type, CustomType) and ret_type.name == "None"):
                reject_unknown_return_type(self.errors, ret_type, name_tok.value, location, visibility == "public")

        self.expect(TOK_COLON)
        body = self.parse_block()

        sighash = resolve_native_sighash(name, visibility == "public", sighash_specs or [])
        if sighash is not None and sighash.error is not None:
            self.errors.append(Diagnostic(message=sighash.error, severity=Severity.ERROR, loc=location))

        return MethodNode(
            name=name,
            params=params,
            body=body,
            visibility=visibility,
            sighash_type=sighash.value if sighash is not None else None,
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

            params.append(ParamNode(name=self.declare(param_name), type=typ))

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
            self._expect_statement_end()

        self.match(TOK_DEDENT)
        return stmts

    def _expect_statement_end(self) -> None:
        """F-026: a simple statement ends at its line break; compound
        statements end on a NEWLINE / DEDENT they consumed themselves.
        Pre-fix, ``lim = 0b1010`` parsed as ``lim = 0`` plus a second
        statement ``b1010``."""
        nxt = self.peek()
        if nxt.kind in (TOK_NEWLINE, TOK_DEDENT, TOK_EOF):
            return
        if self.pos > 0 and self.tokens[self.pos - 1].kind in (TOK_NEWLINE, TOK_DEDENT):
            return
        self.errors.append(lex_error(PY_STATEMENT_LINE_BREAK, self.file_name, nxt.line, nxt.col))
        while not (self.check(TOK_NEWLINE) or self.check(TOK_DEDENT) or self.check(TOK_EOF)):
            self.advance()

    # -- Statement parsing ---------------------------------------------------

    def parse_statement(self) -> Statement | None:
        with self._nest.nested(self.loc):
            return self._parse_statement_inner()

    def _parse_statement_inner(self) -> Statement | None:
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

        if self.check_ident("break") or self.check_ident("continue"):
            kw = self.peek().value
            self.advance()
            self.skip_newlines()
            self.errors.append(Diagnostic(
                message=f"Unsupported statement kind: {kw} — Rúnar does not support loop early-exit",
                severity=Severity.ERROR,
                loc=location,
            ))
            return None

        # N-053: a statement must start with a name or a token that can begin
        # an expression; anything else (a stray `elif`, `from`, `@`, an
        # unexpected indent, ...) is refused with the shared diagnostic.
        tok = self.peek()
        if ((tok.kind == TOK_IDENT and tok.value in _PY_NON_EXPR_KEYWORDS)
                or (tok.kind != TOK_IDENT and tok.kind not in _PY_EXPR_START_KINDS)):
            self.advance()
            self.errors.append(lex_error(
                unsupported_statement_message(_py_token_text(tok)), self.file_name, tok.line, tok.col))
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

        # N-046: a name first bound inside a branch stays branch-local.
        locals_before = set(self.declared_locals)
        then_block = self.parse_block()
        self.declared_locals = set(locals_before)

        else_block: list[Statement] = []
        self.skip_newlines()
        if self.check_ident("elif"):
            elif_loc = self.loc()
            self.advance()
            with self._nest.nested(self.loc):
                elif_stmt = self._parse_if_body(elif_loc)
            else_block = [elif_stmt]
            self.declared_locals = set(locals_before)
        elif self.match_ident("else"):
            self.expect(TOK_COLON)
            else_block = self.parse_block()
            self.declared_locals = set(locals_before)

        return IfStmt(
            condition=condition,
            then=then_block,
            else_=else_block,
            source_location=loc,
        )

    def _parse_for(self, loc: SourceLocation) -> Statement:
        self.expect_ident("for")
        var_tok = self.expect(TOK_IDENT)
        var_name = self.declare(var_tok.value)

        self.expect_ident("in")
        self.expect_ident("range")
        self.expect(TOK_LPAREN)

        first = self.parse_expression()

        is_countdown = False
        if self.match(TOK_COMMA):
            init_expr = first
            limit_expr = self.parse_expression()
            # Optional third range() argument: the step (issue #121). A
            # negative step is a countdown (range(5, 1, -1) -> 5, 4, 3, 2).
            #
            # Only +-1 is accepted: the ANF loop node synthesizes iteration k
            # as `start + k*step` with a unit step, so `range(0, 10, 2)` has no
            # representation. It used to be COERCED to +1 here -- the loop ran
            # 10 times over 0..9 instead of 5 times over 0,2,4,6,8, with no
            # diagnostic -- which is the same silent coercion N-061 found in
            # the for-header surfaces, in Python's spelling.
            if self.match(TOK_COMMA):
                step_expr = self.parse_expression()
                step = _literal_int_value(step_expr)
                if step == 1:
                    is_countdown = False
                elif step == -1:
                    is_countdown = True
                else:
                    self.add_error(RANGE_STEP_DIAGNOSTIC)
        else:
            init_expr = BigIntLiteral(value=0)
            limit_expr = first

        self.expect(TOK_RPAREN)
        self.expect(TOK_COLON)

        # N-046: the loop variable and the body's first bindings are body-local;
        # a rebinding of the loop variable inside the body is an assignment.
        locals_before_body = set(self.declared_locals)
        self.declared_locals.add(var_name)
        body = self.parse_block()
        self.declared_locals = locals_before_body

        init_stmt = VariableDeclStmt(
            name=var_name,
            type=PrimitiveType(name="bigint"),
            mutable=True,
            init=init_expr,
            source_location=loc,
        )

        # A step of -1 means a countdown loop: iterate while `var > stop` and
        # decrement (issue #121). An absent step counts up with `<` / `i++`,
        # preserving the historical zero-config `range(n)` / `range(a, b)`
        # behaviour byte-for-byte.
        condition = BinaryExpr(
            op=">" if is_countdown else "<",
            left=Identifier(name=var_name),
            right=limit_expr,
        )

        if is_countdown:
            update = ExpressionStmt(
                expr=DecrementExpr(operand=Identifier(name=var_name), prefix=False),
                source_location=loc,
            )
        else:
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
            var_name = self.declare(name_tok.value)
            self.expect(TOK_COLON)
            typ_node = self.parse_type_annotation()

            init: Expression
            if self.match(TOK_ASSIGN):
                init = self.parse_expression()
            else:
                init = BigIntLiteral(value=0)
            self.skip_newlines()
            # N-046: rebinding a local of this method is an assignment in Python.
            return self._bind_local(var_name, typ_node, init, loc)

        target_tok = self.peek()
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
                if target_tok.kind == TOK_IDENT:
                    self.declared.append((target_tok.value, expr.name))
                # N-046: rebinding a local of this method is an assignment in
                # Python (function-scoped).
                return self._bind_local(expr.name, None, value, loc)
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
        with self._nest.nested(self.loc):
            return self._parse_ternary()

    def _parse_ternary(self) -> Expression:
        expr = self._parse_or()
        if self.check_ident("if"):
            self.advance()
            condition = self._parse_or()
            self.expect_ident("else")
            with self._nest.nested(self.loc):
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
            with self._nest.nested(self.loc):
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
            with self._nest.nested(self.loc):
                operand = self._parse_unary()
            return UnaryExpr(op="-", operand=operand)
        if self.match(TOK_TILDE):
            with self._nest.nested(self.loc):
                operand = self._parse_unary()
            return UnaryExpr(op="~", operand=operand)
        if self.match(TOK_BANG):
            with self._nest.nested(self.loc):
                operand = self._parse_unary()
            return UnaryExpr(op="!", operand=operand)
        return self._parse_power()

    def _parse_power(self) -> Expression:
        base = self._parse_postfix()
        if self.match(TOK_STARSTAR):
            with self._nest.nested(self.loc):
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


#: Emitted for a ``range`` step the unrolled loop model cannot represent.
#: Shared verbatim with the other six tiers.
RANGE_STEP_DIAGNOSTIC = (
    "range() step must be 1 or -1. The unrolled loop carries only a start value "
    "and a unit step, so any other step -- range(0, 10, 2), say -- cannot be "
    "represented and would be discarded."
)


def _literal_int_value(expr: Expression | None) -> int | None:
    """The integer value of a literal expression, or None when it is not one.

    A negative literal arrives either as a unary minus over a positive one or
    as a directly-negative BigIntLiteral, so both shapes have to be walked --
    the same walk ANF lowering does, for the same reason (N-138).
    """
    if isinstance(expr, BigIntLiteral):
        return expr.value
    if isinstance(expr, UnaryExpr) and expr.op == "-":
        inner = _literal_int_value(expr.operand)
        return None if inner is None else -inner
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_python(source: str, file_name: str) -> ParseResult:
    """F-011: run the parser below and keep its tokenizer's diagnostics."""
    # DoS-bound size guard, enforced at every exported parser entry, not
    # just parse_source. N-136.
    from runar_compiler.frontend.input_limits import assert_source_bytes_under_limit
    assert_source_bytes_under_limit(source)
    lex: list = []
    return with_lex_errors(
        with_nesting_limit(file_name, lambda: _parse_python_tokens(source, file_name, lex)), lex
    )


def _parse_python_tokens(source: str, file_name: str, lex: list) -> ParseResult:
    """Parse a Python-syntax Runar contract (.runar.py)."""
    p = _PyParser(file_name)

    raw = _tokenize_raw(source, lex, file_name)
    p.tokens = _insert_indentation(raw)
    p.pos = 0

    try:
        contract = p.parse_contract()
    except ValueError as e:
        return ParseResult(errors=[Diagnostic(message=str(e), severity=Severity.ERROR)])

    p.errors.extend(collision_diagnostics(p.declared))
    if p.errors:
        return ParseResult(contract=contract, errors=p.errors)
    return ParseResult(contract=contract)
