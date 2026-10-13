//! F-011 — the tokenizer diagnostics every hand-written surface shares with
//! the TS reference (packages/runar-compiler/src/errors.ts).

const std = @import("std");

/// A quoted literal that reaches a line break or end of file before its
/// closing quote (only end of file on .runar.rs, for Python triple-quoted
/// strings, .runar.go backtick raw strings and .runar.ts template literals).
pub const UNTERMINATED_STRING_LITERAL = "unterminated string literal";

/// N-121 (user decision R85; the TS reference's OPTIONAL_CHAINING): a
/// .runar.ts `?.`, located at the `?`. Only the first `?.` in a file is
/// reported.
pub const OPTIONAL_CHAINING = "optional chaining '?.' is not supported";

/// F-203: a .runar.py string or bytes literal escape CPython does not define
/// for that literal kind, a `\x` without two hex digits, an octal escape above
/// 0o377, or a str `\N` / `\u` / `\U` (the TS reference's
/// invalidEscapeSequenceMessage). The argument is the backslash plus the
/// escape letter, or the whole octal escape.
pub const INVALID_ESCAPE_SEQUENCE_FMT = "invalid escape sequence '{s}'";

/// F-203: a non-ASCII character inside a .runar.py b'..' literal (CPython's
/// wording; the TS reference's PY_BYTES_NON_ASCII).
pub const PY_BYTES_NON_ASCII = "bytes can only contain ASCII literal characters";

/// F-026: a .runar.zig call argument list or array literal whose elements are
/// not separated by commas (the TS reference's ZIG_LIST_COMMA).
pub const ZIG_LIST_COMMA = "expected ',' between list elements";

/// F-026: a second .runar.py statement on the same line (the TS reference's
/// PY_STATEMENT_LINE_BREAK).
pub const PY_STATEMENT_LINE_BREAK = "expected a line break between statements";

/// A Java char literal, which Rúnar does not support.
pub const JAVA_CHAR_LITERAL = "char literals are unsupported in Rúnar Java contracts";

/// N-050: a static or class-level method (the TS reference's
/// staticMethodMessage): `static` on .runar.ts / .runar.java, `@staticmethod` /
/// `@classmethod` on .runar.py, `def self.m` on .runar.rb, and a `pub fn`
/// without a self receiver on .runar.rs / .runar.zig. The argument is the
/// method name as written in the source.
pub const STATIC_METHOD_FMT = "static methods are not allowed in Rúnar contracts; method '{s}' is declared static";

/// N-053: a .runar.rb / .runar.py statement whose first token can begin
/// neither a statement nor an expression (the TS reference's
/// unsupportedStatementMessage). The argument is the token's source text.
pub const UNSUPPORTED_STATEMENT_FMT = "Unsupported statement starting with '{s}'";

/// N-004: a .runar.rb class-body token that is not `prop`, `runar_public`,
/// `params`, `def` or a bare `private` / `public` marker (the TS reference's
/// unexpectedClassBodyTokenMessage). It used to be skipped, so an indented
/// `=begin` (lexed as `=`, `begin`) let a "commented-out" method become the
/// only spend path. The argument is the token's source text.
pub const UNEXPECTED_CLASS_BODY_TOKEN_FMT = "Unexpected token in class body: '{s}'";

/// N-004: the first token after a .runar.rb class's `end` (the TS reference's
/// unexpectedTokenAfterClassMessage). The argument is the token's source text.
pub const UNEXPECTED_TOKEN_AFTER_CLASS_FMT = "Unexpected token after class end: '{s}'";

/// 1-based line / 1-based column of an opening quote.
/// N-023's (R49) refusal, on the .runar.java surface, of an assignment (=,
/// op=, ++, --) to a bare property name that no local or parameter shadows
/// (the TS reference's bareJavaPropertyAssignmentMessage). In Java that bare
/// name IS the field. Format args: the property name, twice.
pub const BARE_JAVA_PROPERTY_ASSIGNMENT_FMT = "bare assignment to property '{s}' is not allowed; write `this.{s} = ...`";

/// F-205: a .runar.java member annotation whose simple name (last segment,
/// for a qualified name like `@runar.lang.annotations.Publlic`) Rúnar does
/// not recognize (the TS reference's "unsupported annotation @<name>",
/// 01-parse-java.ts parseMember). Before this diagnostic existed, an
/// unrecognized annotation was silently ignored and a misspelled `@Public`
/// left the method at its default `private` visibility with zero errors.
pub const UNSUPPORTED_ANNOTATION_FMT = "unsupported annotation @{s}";

/// 1-based line / 1-based column, the tokenizers' internal convention.
pub const Pos = struct { line: u32, col: u32 };

/// The printed column of a `file:line:col` diagnostic for a 1-based internal
/// column: diagnostics print 0-based columns (N-078, R88a), the source-map
/// convention, which codegen/emit.zig and compiler_api.zig convert to the
/// same way. Saturating, so an unknown column 0 stays 0.
pub fn diagCol(col: u32) u32 {
    return if (col > 0) col - 1 else 0;
}

var fallback = [_][]const u8{UNTERMINATED_STRING_LITERAL};

/// `errors` with `file:line:col: msg` in front, when `at` is set. An
/// allocation failure still refuses the source (it never drops the error).
pub fn prepend(allocator: std.mem.Allocator, errors: [][]const u8, file_name: []const u8, msg: []const u8, at: ?Pos) [][]const u8 {
    const p = at orelse return errors;
    const text = std.fmt.allocPrint(allocator, "{s}:{d}:{d}: {s}", .{ file_name, p.line, diagCol(p.col), msg }) catch return fallback[0..];
    const out = allocator.alloc([]const u8, errors.len + 1) catch return fallback[0..];
    out[0] = text;
    @memcpy(out[1..], errors);
    return out;
}
