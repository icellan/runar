//! Pass 1 (Ruby frontend): Hand-written tokenizer + recursive descent parser for .runar.rb files.
//!
//! Parses Ruby-style class syntax into the Runar IR ContractNode.
//!
//! Syntax conventions:
//!   - `require 'runar'` at top (skipped)
//!   - `class Name < Runar::SmartContract` / `class Name < Runar::StatefulSmartContract`
//!   - `prop :name, Type` for mutable properties
//!   - `prop :name, Type, readonly: true` for readonly properties
//!   - `prop :name, Type, default: 0` for properties with initializers
//!   - `def initialize(params)` is the constructor
//!   - `runar_public [key: Type, ...]` before `def` marks the next method as public
//!   - `def method_name(params) ... end` for private methods
//!   - `self.field` or `@field` for instance variable access
//!   - snake_case -> camelCase conversion for ALL identifiers
//!   - `assert(cond)` or `Runar.assert(cond)` for assertions
//!   - `and`/`or` for boolean operators (map to &&/||)
//!   - `!` or `not` for logical not
//!   - `if cond ... end` / `elsif ... end` / `else ... end` blocks
//!   - `unless cond ... end` maps to `if !cond ... end`
//!   - `for i in start...end` (exclusive) or `for i in start..end` (inclusive)
//!   - `==` maps to `===`, `!=` maps to `!==`
//!   - Comments: `#` line comments
//!   - `end` keyword terminates blocks (no braces)
//!   - `Runar.check_sig(sig, pk)` -> `checkSig(sig, pk)` (Runar. prefix builtins)

const std = @import("std");
const lex_diag = @import("lex_diag.zig");
const int_literal = @import("int_literal.zig");
const types = @import("../ir/types.zig");
const operand_loc = @import("operand_loc.zig");
const identifier_collision = @import("identifier_collision.zig");

const Allocator = std.mem.Allocator;
const input_limits = @import("../frontend/input_limits.zig");
const sighash_directive = @import("../frontend/sighash_directive.zig");
const Expression = types.Expression;
const Statement = types.Statement;
const ContractNode = types.ContractNode;
const ConstructorNode = types.ConstructorNode;
const PropertyNode = types.PropertyNode;
const MethodNode = types.MethodNode;
const ParamNode = types.ParamNode;
const TypeNode = types.TypeNode;
const RunarType = types.RunarType;
const PrimitiveTypeName = types.PrimitiveTypeName;
const ParentClass = types.ParentClass;
const BinaryOp = types.BinaryOp;
const UnaryOp = types.UnaryOp;
const BinOperator = types.BinOperator;
const UnaryOperator = types.UnaryOperator;
const CallExpr = types.CallExpr;
const MethodCall = types.MethodCall;
const PropertyAccess = types.PropertyAccess;
const IndexAccess = types.IndexAccess;
const ConstDecl = types.ConstDecl;
const LetDecl = types.LetDecl;
const Assign = types.Assign;
const IfStmt = types.IfStmt;
const ForStmt = types.ForStmt;
const AssertStmt = types.AssertStmt;
const AssignmentNode = types.AssignmentNode;
const Ternary = types.Ternary;
const IncrementExpr = types.IncrementExpr;
const DecrementExpr = types.DecrementExpr;

/// Delegates to the canonical implementation in types.zig.
const typeNodeToRunarType = types.typeNodeToRunarType;

// ============================================================================
// Public API
// ============================================================================

pub const ParseResult = struct {
    contract: ?ContractNode,
    errors: [][]const u8,
};

pub fn parseRuby(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
    // DoS-bound size guard, enforced at every exported parser entry,
    // not just runPipeline's Pass 0. N-136.
    if (input_limits.sourceSizeGuardErrors(allocator, source)) |errs| {
        return .{ .contract = null, .errors = errs };
    }
    var parser = Parser.init(allocator, source, file_name);
    const r = parser.parse();
    // F-213: an over-nested source is refused with the one shared diagnostic,
    // before anything here or downstream recurses over the tree.
    if (input_limits.nestingGuardErrors(allocator, parser.nest_error, r.contract, file_name)) |errs| {
        return .{ .contract = null, .errors = errs };
    }
    // F-011: report an unterminated literal (the tokenizer records it).
    var t = Tokenizer.init(allocator, source);
    _ = t.tokenize();
    const at_errs = lex_diag.prepend(allocator, r.errors, file_name, "Unexpected token in expression: '@'", t.bare_at);
    const errors = lex_diag.prepend(allocator, lex_diag.prependUnexpected(allocator, at_errs, file_name, t.unexpected), file_name, lex_diag.UNTERMINATED_STRING_LITERAL, t.unterminated);
    return .{ .contract = r.contract, .errors = prependUnterminatedBegin(allocator, errors, file_name, t.block_comment_start) };
}

var unterminated_begin_fallback = [_][]const u8{"unterminated '=begin' block comment: missing '=end'"};

/// N-021: `errors` with `file:N: unterminated '=begin' ...` in front when the
/// `=begin` on line N was never closed (`start` != 0). `file:N:` with no
/// column is how the Go tier prints this diagnostic's column-0 location. An
/// allocation failure still refuses the source (it never drops the error).
fn prependUnterminatedBegin(allocator: Allocator, errors: [][]const u8, file_name: []const u8, start: u32) [][]const u8 {
    if (start == 0) return errors;
    const text = std.fmt.allocPrint(
        allocator,
        "{s}:{d}: unterminated '=begin' block comment starting at line {d}: missing '=end'",
        .{ file_name, start, start },
    ) catch return unterminated_begin_fallback[0..];
    const out = allocator.alloc([]const u8, errors.len + 1) catch return unterminated_begin_fallback[0..];
    out[0] = text;
    @memcpy(out[1..], errors);
    return out;
}

/// Whether `line` starts at column 0 with `marker` (`=begin` or `=end`) as a
/// whole word: followed by ASCII whitespace (Ruby's `\s`) or end of line.
fn isEmbeddedDocMarker(line: []const u8, marker: []const u8) bool {
    if (!std.mem.startsWith(u8, line, marker)) return false;
    if (line.len == marker.len) return true;
    return switch (line[marker.len]) {
        ' ', '\t', '\n', 0x0b, 0x0c, '\r' => true,
        else => false,
    };
}


// ============================================================================
// Token Types
// ============================================================================

const TokenKind = enum {
    eof,
    newline, // logical line end
    ident,
    number,
    hex_string, // single-quoted string -> hex ByteString
    string_literal, // double-quoted string
    symbol, // :name
    ivar, // @name
    lparen,
    rparen,
    lbracket,
    rbracket,
    comma,
    dot,
    colon,
    colon_colon, // ::
    assign, // =
    eqeq, // ==
    not_eq, // !=
    lt, // <
    lt_eq, // <=
    gt, // >
    gt_eq, // >=
    plus, // +
    minus, // -
    star, // *
    slash, // /
    percent, // %
    bang, // !
    tilde, // ~
    ampersand, // &
    pipe, // |
    caret, // ^
    amp_amp, // &&
    pipe_pipe, // ||
    plus_eq, // +=
    minus_eq, // -=
    star_eq, // *=
    slash_eq, // /=
    percent_eq, // %=
    star_star, // **
    lshift, // <<
    rshift, // >>
    dot_dot, // ..
    dot_dot_dot, // ...
    question, // ?
    // Keywords
    kw_class,
    kw_def,
    kw_if,
    kw_elsif,
    kw_else,
    kw_unless,
    kw_for,
    kw_in,
    kw_end,
    kw_return,
    kw_true,
    kw_false,
    kw_nil,
    kw_and,
    kw_or,
    kw_not,
    kw_super,
    kw_require,
    kw_assert,
    kw_do,
    kw_self,
};

const Token = struct {
    kind: TokenKind,
    text: []const u8,
    line: u32,
    col: u32,
    /// F-026: a number token's literal as written (`text` holds its value).
    raw: []const u8 = "",
    /// F-026: valid only as the operand of a unary minus.
    neg_only: bool = false,
};

// ============================================================================
// Tokenizer
// ============================================================================

/// The tokenizer produces a flat array of tokens from the source.
/// Ruby uses newlines as statement terminators, so newline tokens are
/// significant, except when inside parentheses or brackets.
const Tokenizer = struct {
    allocator: Allocator,
    source: []const u8,
    tokens: std.ArrayListUnmanaged(Token),
    /// F-011: the first unterminated quoted literal, if any.
    unterminated: ?lex_diag.Pos = null,
    /// N-021: line number of an open `=begin` embedded document, or 0.
    block_comment_start: u32 = 0,
    /// N-214: the first unrecognised character, if any.
    unexpected: ?lex_diag.Unexpected = null,
    /// N-214: the first bare `@` (no instance-variable name), if any.
    bare_at: ?lex_diag.Pos = null,

    fn init(allocator: Allocator, source: []const u8) Tokenizer {
        return .{ .allocator = allocator, .source = source, .tokens = .empty };
    }

    fn tokenize(self: *Tokenizer) []Token {
        var paren_depth: i32 = 0;
        var line_num: u32 = 0;

        // Process line by line (Ruby is line-oriented)
        var line_start: usize = 0;
        while (line_start < self.source.len) {
            // Find end of line
            var line_end = line_start;
            while (line_end < self.source.len and self.source[line_end] != '\n') {
                line_end += 1;
            }
            line_num += 1;

            // Strip trailing \r
            var effective_end = line_end;
            if (effective_end > line_start and self.source[effective_end - 1] == '\r') {
                effective_end -= 1;
            }

            const raw_line = self.source[line_start..effective_end];

            // N-021: Ruby embedded documents, the Ruby tier's F-018 rule
            // (Ruby's own). `=begin` / `=end` open and close a block comment
            // only at column 0 and only as a whole word (followed by
            // whitespace or end of line). Every line from `=begin` through
            // `=end` is a comment. Before this, a method "commented out" this
            // way compiled as a live spend path and the `end` of `=end`
            // closed the class early.
            const in_block = self.block_comment_start != 0;
            if (in_block and isEmbeddedDocMarker(raw_line, "=end")) {
                self.block_comment_start = 0;
            } else if (!in_block and isEmbeddedDocMarker(raw_line, "=begin")) {
                self.block_comment_start = line_num;
            }
            if (in_block or self.block_comment_start != 0) {
                if (line_end < self.source.len) line_start = line_end + 1 else line_start = line_end;
                continue;
            }

            // Skip blank lines and comment-only lines
            const stripped = trimLeft(raw_line);
            if (stripped.len == 0 or stripped[0] == '#') {
                if (line_end < self.source.len) line_start = line_end + 1 else line_start = line_end;
                continue;
            }

            var pos: usize = @intCast(raw_line.len - stripped.len);
            const had_tokens_before = self.tokens.items.len;

            while (pos < raw_line.len) {
                const ch = raw_line[pos];
                const col: u32 = @intCast(pos + 1);

                // Whitespace within line
                if (ch == ' ' or ch == '\t') {
                    pos += 1;
                    continue;
                }

                // Comment
                if (ch == '#') {
                    break; // rest of line is comment
                }

                // Instance variable: @name
                if (ch == '@') {
                    pos += 1;
                    const name_start = pos;
                    while (pos < raw_line.len and isIdentPart(raw_line[pos])) pos += 1;
                    if (pos > name_start) {
                        self.tokens.append(self.allocator, .{
                            .kind = .ivar,
                            .text = raw_line[name_start..pos],
                            .line = line_num,
                            .col = col,
                        }) catch {};
                    } else if (self.bare_at == null) {
                        // N-214: a bare `@` was dropped, so `a + @ b` compiled
                        // as `a + b`. The TS reference lexes it as its own
                        // token and refuses it in the expression.
                        self.bare_at = .{ .line = line_num, .col = col };
                    }
                    continue;
                }

                // Three-dot range operator (check before two-dot)
                if (ch == '.' and pos + 2 < raw_line.len and raw_line[pos + 1] == '.' and raw_line[pos + 2] == '.') {
                    self.tokens.append(self.allocator, .{ .kind = .dot_dot_dot, .text = "...", .line = line_num, .col = col }) catch {};
                    pos += 3;
                    continue;
                }

                // Two-dot range operator (check before single dot)
                if (ch == '.' and pos + 1 < raw_line.len and raw_line[pos + 1] == '.') {
                    self.tokens.append(self.allocator, .{ .kind = .dot_dot, .text = "..", .line = line_num, .col = col }) catch {};
                    pos += 2;
                    continue;
                }

                // Two-character operators
                if (pos + 1 < raw_line.len) {
                    const two = raw_line[pos .. pos + 2];
                    const two_kind: ?TokenKind = twoCharOp(two);
                    if (two_kind) |tk| {
                        self.tokens.append(self.allocator, .{ .kind = tk, .text = two, .line = line_num, .col = col }) catch {};
                        pos += 2;
                        continue;
                    }
                }

                // Parentheses (track depth for multi-line expressions)
                if (ch == '(') {
                    paren_depth += 1;
                    self.tokens.append(self.allocator, .{ .kind = .lparen, .text = "(", .line = line_num, .col = col }) catch {};
                    pos += 1;
                    continue;
                }
                if (ch == ')') {
                    if (paren_depth > 0) paren_depth -= 1;
                    self.tokens.append(self.allocator, .{ .kind = .rparen, .text = ")", .line = line_num, .col = col }) catch {};
                    pos += 1;
                    continue;
                }
                if (ch == '[') {
                    paren_depth += 1;
                    self.tokens.append(self.allocator, .{ .kind = .lbracket, .text = "[", .line = line_num, .col = col }) catch {};
                    pos += 1;
                    continue;
                }
                if (ch == ']') {
                    if (paren_depth > 0) paren_depth -= 1;
                    self.tokens.append(self.allocator, .{ .kind = .rbracket, .text = "]", .line = line_num, .col = col }) catch {};
                    pos += 1;
                    continue;
                }

                // Symbol: :name (but not ::)
                if (ch == ':' and pos + 1 < raw_line.len and isIdentStart(raw_line[pos + 1])) {
                    pos += 1; // skip ':'
                    const sym_start = pos;
                    while (pos < raw_line.len and isIdentPart(raw_line[pos])) pos += 1;
                    self.tokens.append(self.allocator, .{
                        .kind = .symbol,
                        .text = raw_line[sym_start..pos],
                        .line = line_num,
                        .col = col,
                    }) catch {};
                    continue;
                }

                // Single-quoted string literals: hex ByteStrings
                if (ch == '\'') {
                    pos += 1;
                    const str_start = pos;
                    while (pos < raw_line.len and raw_line[pos] != '\'') {
                        if (raw_line[pos] == '\\' and pos + 1 < raw_line.len) {
                            pos += 2;
                        } else {
                            pos += 1;
                        }
                    }
                    const str_end = pos;
                    if (pos < raw_line.len) {
                        pos += 1; // skip closing quote
                    } else if (self.unterminated == null) {
                        // F-011: line-based, so reaching the line break means
                        // the literal is unterminated; refuse it.
                        self.unterminated = .{ .line = line_num, .col = col };
                    }
                    self.tokens.append(self.allocator, .{
                        .kind = .hex_string,
                        .text = raw_line[str_start..str_end],
                        .line = line_num,
                        .col = col,
                    }) catch {};
                    continue;
                }

                // Double-quoted string literals
                if (ch == '"') {
                    pos += 1;
                    const str_start = pos;
                    while (pos < raw_line.len and raw_line[pos] != '"') {
                        if (raw_line[pos] == '\\' and pos + 1 < raw_line.len) {
                            pos += 2;
                        } else {
                            pos += 1;
                        }
                    }
                    const str_end = pos;
                    if (pos < raw_line.len) {
                        pos += 1; // skip closing quote
                    } else if (self.unterminated == null) {
                        // F-011: line-based, so reaching the line break means
                        // the literal is unterminated; refuse it.
                        self.unterminated = .{ .line = line_num, .col = col };
                    }
                    self.tokens.append(self.allocator, .{
                        .kind = .string_literal,
                        .text = raw_line[str_start..str_end],
                        .line = line_num,
                        .col = col,
                    }) catch {};
                    continue;
                }

                // Numbers (decimal and hex)
                if (ch >= '0' and ch <= '9') {
                    // F-026: the whole glued [0-9A-Za-z_] run is one Ruby literal.
                    const num_start = pos;
                    pos = int_literal.scanNumberEnd(raw_line, pos);
                    self.tokens.append(self.allocator, .{
                        .kind = .number,
                        .text = raw_line[num_start..pos],
                        .raw = raw_line[num_start..pos],
                        .line = line_num,
                        .col = col,
                    }) catch {};
                    continue;
                }

                // Identifiers and keywords
                if (isIdentStart(ch)) {
                    const id_start = pos;
                    while (pos < raw_line.len and isIdentPart(raw_line[pos])) pos += 1;
                    // Ruby convention: trailing ? or ! on method names
                    if (pos < raw_line.len and (raw_line[pos] == '?' or raw_line[pos] == '!')) {
                        pos += 1;
                    }
                    const word = raw_line[id_start..pos];
                    const kind = keywordKind(word);
                    self.tokens.append(self.allocator, .{
                        .kind = kind,
                        .text = word,
                        .line = line_num,
                        .col = col,
                    }) catch {};
                    continue;
                }

                // Single-character operators and punctuation
                const one_kind: ?TokenKind = oneCharOp(ch);
                if (one_kind) |tk| {
                    self.tokens.append(self.allocator, .{ .kind = tk, .text = raw_line[pos .. pos + 1], .line = line_num, .col = col }) catch {};
                    pos += 1;
                    continue;
                }

                // N-214: an unrecognised character is refused, as the TS
                // reference does, rather than skipped: skipping compiled
                // `a + § b` as `a + b`.
                const n = lex_diag.charLen(raw_line, pos);
                if (self.unexpected == null) self.unexpected = .{ .at = .{ .line = line_num, .col = col }, .text = raw_line[pos .. pos + n] };
                pos += n;
            }

            // Emit NEWLINE at end of significant line (only if not inside parens and we added tokens)
            if (paren_depth == 0 and self.tokens.items.len > had_tokens_before) {
                self.tokens.append(self.allocator, .{ .kind = .newline, .text = "", .line = line_num, .col = @intCast(raw_line.len + 1) }) catch {};
            }

            if (line_end < self.source.len) line_start = line_end + 1 else line_start = line_end;
        }

        self.tokens.append(self.allocator, .{ .kind = .eof, .text = "", .line = line_num + 1, .col = 1 }) catch {};
        return self.tokens.items;
    }

    fn trimLeft(s: []const u8) []const u8 {
        var i: usize = 0;
        while (i < s.len and (s[i] == ' ' or s[i] == '\t')) i += 1;
        return s[i..];
    }

    fn isIdentStart(c: u8) bool {
        return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
    }

    fn isIdentPart(c: u8) bool {
        return isIdentStart(c) or (c >= '0' and c <= '9');
    }

    fn isHexDigit(c: u8) bool {
        return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
    }

    fn twoCharOp(two: []const u8) ?TokenKind {
        if (two.len < 2) return null;
        const a = two[0];
        const b = two[1];
        if (a == '*' and b == '*') return .star_star;
        if (a == ':' and b == ':') return .colon_colon;
        if (a == '=' and b == '=') return .eqeq;
        if (a == '!' and b == '=') return .not_eq;
        if (a == '<' and b == '=') return .lt_eq;
        if (a == '>' and b == '=') return .gt_eq;
        if (a == '<' and b == '<') return .lshift;
        if (a == '>' and b == '>') return .rshift;
        if (a == '&' and b == '&') return .amp_amp;
        if (a == '|' and b == '|') return .pipe_pipe;
        if (a == '+' and b == '=') return .plus_eq;
        if (a == '-' and b == '=') return .minus_eq;
        if (a == '*' and b == '=') return .star_eq;
        if (a == '/' and b == '=') return .slash_eq;
        if (a == '%' and b == '=') return .percent_eq;
        return null;
    }

    fn oneCharOp(ch: u8) ?TokenKind {
        return switch (ch) {
            ',' => .comma,
            '.' => .dot,
            ':' => .colon,
            '=' => .assign,
            '<' => .lt,
            '>' => .gt,
            '+' => .plus,
            '-' => .minus,
            '*' => .star,
            '/' => .slash,
            '%' => .percent,
            '!' => .bang,
            '~' => .tilde,
            '&' => .ampersand,
            '|' => .pipe,
            '^' => .caret,
            '?' => .question,
            else => null,
        };
    }

    fn keywordKind(word: []const u8) TokenKind {
        const map = std.StaticStringMap(TokenKind).initComptime(.{
            .{ "class", .kw_class },
            .{ "def", .kw_def },
            .{ "if", .kw_if },
            .{ "elsif", .kw_elsif },
            .{ "else", .kw_else },
            .{ "unless", .kw_unless },
            .{ "for", .kw_for },
            .{ "in", .kw_in },
            .{ "end", .kw_end },
            .{ "return", .kw_return },
            .{ "true", .kw_true },
            .{ "false", .kw_false },
            .{ "nil", .kw_nil },
            .{ "and", .kw_and },
            .{ "or", .kw_or },
            .{ "not", .kw_not },
            .{ "super", .kw_super },
            .{ "require", .kw_require },
            .{ "assert", .kw_assert },
            .{ "do", .kw_do },
            .{ "self", .kw_self },
        });
        return map.get(word) orelse .ident;
    }
};

// ============================================================================
// Snake_case to camelCase conversion
// ============================================================================

/// Special-case name mappings for Ruby snake_case -> Runar camelCase.
fn rbConvertName(allocator: Allocator, name: []const u8) []const u8 {
    // Check special names first
    const special = std.StaticStringMap([]const u8).initComptime(.{
        // Crypto builtins
        .{ "check_sig", "checkSig" },
        .{ "check_multi_sig", "checkMultiSig" },
        .{ "check_preimage", "checkPreimage" },
        // Post-quantum
        .{ "verify_wots", "verifyWOTS" },
        .{ "verify_slh_dsa_sha2_128s", "verifySLHDSA_SHA2_128s" },
        .{ "verify_slh_dsa_sha2_128f", "verifySLHDSA_SHA2_128f" },
        .{ "verify_slh_dsa_sha2_192s", "verifySLHDSA_SHA2_192s" },
        .{ "verify_slh_dsa_sha2_192f", "verifySLHDSA_SHA2_192f" },
        .{ "verify_slh_dsa_sha2_256s", "verifySLHDSA_SHA2_256s" },
        .{ "verify_slh_dsa_sha2_256f", "verifySLHDSA_SHA2_256f" },
        .{ "verify_rabin_sig", "verifyRabinSig" },
        // EC builtins
        .{ "ec_add", "ecAdd" },
        .{ "ec_mul", "ecMul" },
        .{ "ec_mul_gen", "ecMulGen" },
        .{ "ec_negate", "ecNegate" },
        .{ "ec_on_curve", "ecOnCurve" },
        .{ "ec_mod_reduce", "ecModReduce" },
        .{ "ec_encode_compressed", "ecEncodeCompressed" },
        .{ "ec_make_point", "ecMakePoint" },
        .{ "ec_point_x", "ecPointX" },
        .{ "ec_point_y", "ecPointY" },
        // NIST P-256 builtins
        .{ "verify_ecdsa_p256", "verifyECDSA_P256" },
        .{ "p256_add", "p256Add" },
        .{ "p256_mul", "p256Mul" },
        .{ "p256_mul_gen", "p256MulGen" },
        .{ "p256_negate", "p256Negate" },
        .{ "p256_on_curve", "p256OnCurve" },
        .{ "p256_encode_compressed", "p256EncodeCompressed" },
        // NIST P-384 builtins
        .{ "verify_ecdsa_p384", "verifyECDSA_P384" },
        .{ "p384_add", "p384Add" },
        .{ "p384_mul", "p384Mul" },
        .{ "p384_mul_gen", "p384MulGen" },
        .{ "p384_negate", "p384Negate" },
        .{ "p384_on_curve", "p384OnCurve" },
        .{ "p384_encode_compressed", "p384EncodeCompressed" },
        // Intrinsics
        .{ "add_output", "addOutput" },
        .{ "add_raw_output", "addRawOutput" },
        .{ "add_data_output", "addDataOutput" },
        .{ "get_state_script", "getStateScript" },
        // SHA-256 partial verification
        .{ "sha256_compress", "sha256Compress" },
        .{ "sha256_finalize", "sha256Finalize" },
        // Transaction intrinsics
        .{ "extract_locktime", "extractLocktime" },
        .{ "extract_output_hash", "extractOutputHash" },
        .{ "extract_sequence", "extractSequence" },
        .{ "extract_version", "extractVersion" },
        .{ "extract_amount", "extractAmount" },
        .{ "extract_nsequence", "extractNSequence" },
        .{ "extract_hash_prevouts", "extractHashPrevouts" },
        .{ "extract_hash_sequence", "extractHashSequence" },
        .{ "extract_outpoint", "extractOutpoint" },
        .{ "extract_script_code", "extractScriptCode" },
        .{ "extract_input_index", "extractInputIndex" },
        .{ "extract_sig_hash_type", "extractSigHashType" },
        .{ "extract_outputs", "extractOutputs" },
        // Math builtins
        .{ "mul_div", "mulDiv" },
        .{ "percent_of", "percentOf" },
        .{ "safe_div", "safediv" },
        .{ "safe_mod", "safemod" },
        .{ "div_mod", "divmod" },
        .{ "reverse_bytes", "reverseBytes" },
        // Hash builtins (pass through)
        .{ "sha256", "sha256" },
        .{ "ripemd160", "ripemd160" },
        .{ "hash160", "hash160" },
        .{ "hash256", "hash256" },
        // Misc
        .{ "num2bin", "num2bin" },
        .{ "bin2num", "bin2num" },
        .{ "log2", "log2" },
        .{ "divmod", "divmod" },
        .{ "tx_preimage", "txPreimage" },
        // EC constants
        .{ "EC_P", "EC_P" },
        .{ "EC_N", "EC_N" },
        .{ "EC_G", "EC_G" },
    });

    if (special.get(name)) |mapped| return mapped;

    // No underscores -> pass through unchanged
    if (std.mem.indexOfScalar(u8, name, '_') == null) return name;

    // Strip leading underscores
    var stripped = name;
    while (stripped.len > 0 and stripped[0] == '_') stripped = stripped[1..];
    if (stripped.len == 0) return name;

    // General snake_case to camelCase conversion
    var buf = allocator.alloc(u8, name.len) catch return name;
    var out_len: usize = 0;
    var capitalize_next = false;
    for (stripped) |ch| {
        if (ch == '_') {
            capitalize_next = true;
        } else {
            if (capitalize_next and ch >= 'a' and ch <= 'z') {
                buf[out_len] = ch - 32; // toUpper
            } else {
                buf[out_len] = ch;
            }
            out_len += 1;
            capitalize_next = false;
        }
    }
    return buf[0..out_len];
}

/// Map Ruby type names to Runar AST type names, then resolve to RunarType.
fn rbMapType(name: []const u8) RunarType {
    const map = std.StaticStringMap(RunarType).initComptime(.{
        .{ "Bigint", .bigint },
        .{ "Integer", .bigint },
        .{ "Int", .bigint },
        .{ "Boolean", .boolean },
        .{ "Bool", .boolean },
        .{ "ByteString", .byte_string },
        .{ "PubKey", .pub_key },
        .{ "Sig", .sig },
        .{ "Addr", .addr },
        .{ "Sha256", .sha256 },
        .{ "Sha256Digest", .sha256 },
        .{ "Ripemd160", .ripemd160 },
        .{ "SigHashPreimage", .sig_hash_preimage },
        .{ "RabinSig", .rabin_sig },
        .{ "RabinPubKey", .rabin_pub_key },
        .{ "Point", .point },
        .{ "P256Point", .p256_point },
        .{ "P384Point", .p384_point },
    });
    return map.get(name) orelse .unknown;
}

/// Map Ruby type name to Runar type string for ParamNode.type_name.
fn rbMapTypeName(name: []const u8) []const u8 {
    const map = std.StaticStringMap([]const u8).initComptime(.{
        .{ "Bigint", "bigint" },
        .{ "Integer", "bigint" },
        .{ "Int", "bigint" },
        .{ "Boolean", "boolean" },
        .{ "Bool", "boolean" },
        .{ "ByteString", "ByteString" },
        .{ "PubKey", "PubKey" },
        .{ "Sig", "Sig" },
        .{ "Addr", "Addr" },
        .{ "Sha256", "Sha256" },
        .{ "Ripemd160", "Ripemd160" },
        .{ "SigHashPreimage", "SigHashPreimage" },
        .{ "RabinSig", "RabinSig" },
        .{ "RabinPubKey", "RabinPubKey" },
        .{ "Point", "Point" },
        .{ "P256Point", "P256Point" },
        .{ "P384Point", "P384Point" },
    });
    return map.get(name) orelse types.runarTypeToString(.unknown);
}

// ============================================================================
// Parser
// ============================================================================

const Parser = struct {
    allocator: Allocator,
    tokens: []Token,
    pos: usize,
    file_name: []const u8,
    /// N-492: parenthesised-primary positions, for operand locations.
    operand_locs: operand_loc.OperandLocs(Token) = .{},
    /// N-464: the argument locations of the list `parseArgList` returned
    /// last; the caller copies them onto the call node it builds, as
    /// parse_ts.zig does (N-463).
    last_arg_locs: []const ?types.SourceLocation = &.{},
    errors: std.ArrayListUnmanaged([]const u8),
    nest: input_limits.NestingCounter = .{},
    nest_error: ?[]const u8 = null,
    declared_locals: std.StringHashMapUnmanaged(void),
    /// F-017: declared (spelling, Rúnar name) pairs.
    idents: identifier_collision.DeclaredIdents = .{},

    /// Convert a DECLARED identifier and record it for the F-017 collision
    /// rule (see identifier_collision.zig).
    fn declare(self: *Parser, raw: []const u8) []const u8 {
        return self.idents.declare(self.allocator, raw, rbConvertName(self.allocator, raw));
    }

    fn init(allocator: Allocator, source: []const u8, file_name: []const u8) Parser {
        var tokenizer = Tokenizer.init(allocator, source);
        const tokens = tokenizer.tokenize();
        var p: Parser = .{
            .allocator = allocator,
            .tokens = tokens,
            .pos = 0,
            .file_name = file_name,
            .errors = .empty,
            .declared_locals = .empty,
        };
        for (p.tokens) |*t| t.* = p.normalizeNumber(t.*);
        return p;
    }

    fn cloneDeclaredLocals(self: *Parser) std.StringHashMapUnmanaged(void) {
        var out: std.StringHashMapUnmanaged(void) = .empty;
        var it = self.declared_locals.iterator();
        while (it.next()) |entry| {
            out.put(self.allocator, entry.key_ptr.*, {}) catch {};
        }
        return out;
    }

    fn restoreDeclaredLocals(self: *Parser, snapshot: std.StringHashMapUnmanaged(void)) void {
        self.declared_locals = .empty;
        var it = snapshot.iterator();
        while (it.next()) |entry| {
            self.declared_locals.put(self.allocator, entry.key_ptr.*, {}) catch {};
        }
    }

    fn peek(self: *const Parser) Token {
        if (self.pos < self.tokens.len) return self.tokens[self.pos];
        return .{ .kind = .eof, .text = "", .line = 0, .col = 0 };
    }

    fn peekAhead(self: *const Parser, offset: usize) Token {
        const idx = self.pos + offset;
        if (idx < self.tokens.len) return self.tokens[idx];
        return .{ .kind = .eof, .text = "", .line = 0, .col = 0 };
    }

    fn bump(self: *Parser) Token {
        const tok = self.peek();
        self.operand_locs.consumed(tok);
        if (self.pos < self.tokens.len) self.pos += 1;
        return tok;
    }

    fn check(self: *const Parser, kind: TokenKind) bool {
        return self.peek().kind == kind;
    }

    fn checkIdent(self: *const Parser, text: []const u8) bool {
        const tok = self.peek();
        return tok.kind == .ident and std.mem.eql(u8, tok.text, text);
    }

    fn match(self: *Parser, kind: TokenKind) bool {
        if (self.check(kind)) {
            _ = self.bump();
            return true;
        }
        return false;
    }

    fn expect(self: *Parser, kind: TokenKind) ?Token {
        if (self.check(kind)) return self.bump();
        self.addErrorFmt("expected {s}, got '{s}'", .{ @tagName(kind), self.peek().text });
        return null;
    }

    /// F-213 measure (A): enter one counted nesting level — a statement, a
    /// full-expression parse, a prefix-unary operand, another self-recursion
    /// or a nested type (see frontend/input_limits.zig). False once the source
    /// is over-nested: the caller then returns without parsing, and must not
    /// call `self.nest.exit()`.
    fn enterNest(self: *Parser) bool {
        if (self.nest.enter()) return true;
        self.refuseNesting();
        return false;
    }

    /// Record the shared F-213 diagnostic (once) and jump to end of input, so
    /// every parse loop winds down; the parse entry then returns that
    /// diagnostic alone. Called again on every later refused `enterNest`, so a
    /// parse that rewinds the token stream after a refusal still ends.
    fn refuseNesting(self: *Parser) void {
        self.nest.exceeded = true;
        const tok = self.peek();
        if (self.nest_error == null) self.nest_error = input_limits.nestingErrorAt(self.allocator, self.file_name, tok.line, tok.col);
        self.pos = self.tokens.len;
    }

    /// F-213 measure (A): run `f` one counted nesting level deeper — the
    /// prefix-unary operand, ternary-arm, else-if and nested-type recursions.
    fn nestedParse(self: *Parser, comptime T: type, comptime f: fn (*Parser) ?T) ?T {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
        return f(self);
    }

    /// F-213 measure (A) for the nested-type recursions, whose parse functions
    /// return a value rather than an optional: `fallback` stands in for the
    /// refused parse (the whole source is refused anyway).
    fn nestedValue(self: *Parser, comptime T: type, fallback: T, comptime f: anytype, args: anytype) T {
        if (!self.enterNest()) return fallback;
        defer self.nest.exit();
        return @call(.auto, f, .{self} ++ args);
    }

    fn addError(self: *Parser, msg: []const u8) void {
        const tok = self.peek();
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, tok.line, lex_diag.diagCol(tok.col), msg }) catch return;
        self.errors.append(self.allocator, f) catch {};
    }

    fn addErrorAtLoc(self: *Parser, loc: types.SourceLocation, msg: []const u8) void {
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, loc.line, lex_diag.diagCol(loc.column), msg }) catch return;
        self.errors.append(self.allocator, f) catch {};
    }

    /// N-093: one `runar_sighash` line: its flag text (null when the argument
    /// is not exactly one string literal) and where it was written.
    const PendingSighash = struct { spec: ?[]const u8, loc: types.SourceLocation };

    fn addErrorFmt(self: *Parser, comptime fmt: []const u8, args: anytype) void {
        const msg = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        const tok = self.peek();
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, tok.line, lex_diag.diagCol(tok.col), msg }) catch return;
        self.allocator.free(msg);
        self.errors.append(self.allocator, f) catch {};
    }

    /// N-313: `readonly:` and `embed_always:` take a literal `true` or `false`.
    /// Any other value is refused, never silently dropped. Same text in all
    /// seven tiers.
    fn badBooleanPropOption(self: *Parser, option: []const u8) void {
        const got: []const u8 = if (self.check(.newline) or self.check(.eof)) "<end of line>" else self.peek().text;
        self.addErrorFmt("invalid value '{s}' for prop option '{s}' (expected true or false)", .{ got, option });
    }

    fn skipNewlines(self: *Parser) void {
        while (self.check(.newline)) _ = self.bump();
    }

    /// Source location of the current token, in the AST's **1-based line /
    /// 1-based column** convention (the same convention `file:line:col`
    /// diagnostics use). `codegen/emit.zig#recordSourceMapping` performs the
    /// single 1-based → 0-based column conversion when it materialises
    /// SourceMapping entries, so do NOT subtract here.
    ///
    /// This tokenizer is 1-based: `Tokenizer.tokenize` records `col = pos + 1`
    /// where `pos` is the 0-based byte offset within the current line.
    fn currentSourceLoc(self: *const Parser) types.SourceLocation {
        return self.tokenSourceLoc(self.peek());
    }

    fn tokenSourceLoc(self: *const Parser, tok: Token) types.SourceLocation {
        return .{ .file = self.file_name, .line = tok.line, .column = tok.col };
    }

    fn heapExpr(self: *Parser, expr: Expression) ?*Expression {
        const ptr = self.allocator.create(Expression) catch return null;
        ptr.* = expr;
        return ptr;
    }

    // ==== Top-level ====

    fn parse(self: *Parser) ParseResult {
        self.skipNewlines();

        // Skip `require 'runar'` lines
        while (self.check(.kw_require)) {
            // Consume everything until end of line
            while (!self.check(.newline) and !self.check(.eof)) _ = self.bump();
            self.skipNewlines();
        }

        const contract = self.parseContract();
        if (contract != null) {
            // N-004: nothing may follow the class's `end`.
            self.skipNewlines();
            if (!self.check(.eof)) {
                self.addErrorFmt(lex_diag.UNEXPECTED_TOKEN_AFTER_CLASS_FMT, .{self.peek().text});
            }
            if (self.idents.message(self.allocator)) |m| self.errors.append(self.allocator, m) catch {};
        }
        return .{ .contract = contract, .errors = self.errors.items };
    }

    // ==== Contract declaration ====

    fn parseContract(self: *Parser) ?ContractNode {
        if (!self.check(.kw_class)) {
            self.addError("expected 'class' keyword");
            return null;
        }
        _ = self.bump(); // 'class'

        // Contract name
        if (!self.check(.ident)) {
            self.addError("expected class name");
            return null;
        }
        const name_tok = self.bump();

        // Expect `<`
        if (self.expect(.lt) == null) return null;

        // Parse parent class: could be `Runar::SmartContract` or just `SmartContract`
        const first_part = self.bump(); // ident
        var parent_class_name: []const u8 = first_part.text;
        if (self.check(.colon_colon)) {
            _ = self.bump(); // '::'
            const class_part = self.bump();
            parent_class_name = class_part.text;
        }

        var parent_class: ParentClass = .smart_contract;
        if (std.mem.eql(u8, parent_class_name, "StatefulSmartContract")) {
            parent_class = .stateful_smart_contract;
        } else if (std.mem.eql(u8, parent_class_name, "UnsafeSmartContract")) {
            parent_class = .unsafe_smart_contract;
        } else if (!std.mem.eql(u8, parent_class_name, "SmartContract")) {
            self.addErrorFmt("unknown parent class: '{s}', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract", .{parent_class_name});
            return null;
        }

        self.skipNewlines();

        // Parse class body until `end`
        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;
        var constructor: ?ConstructorNode = null;
        var methods: std.ArrayListUnmanaged(MethodNode) = .empty;

        // Pending visibility and param types for the next method
        var pending_public = false;
        var pending_param_types: ?ParamTypeMap = null;
        // N-093: `runar_sighash 'FLAGS'` lines waiting for their `def`.
        var pending_sighash: std.ArrayListUnmanaged(PendingSighash) = .empty;

        while (!self.check(.kw_end) and !self.check(.eof)) {
            self.skipNewlines();
            if (self.check(.kw_end) or self.check(.eof)) break;

            // `prop :name, Type [, readonly: true]`
            if (self.checkIdent("prop")) {
                if (self.parseProp(parent_class)) |prop| {
                    properties.append(self.allocator, prop) catch {};
                }
                self.skipNewlines();
                continue;
            }

            // N-093: `runar_sighash 'FLAGS'` is the native spelling of the
            // `@sighash` directive; it applies to the next `def`.
            if (self.checkIdent("runar_sighash")) {
                const sighash_loc = self.currentSourceLoc();
                _ = self.bump(); // 'runar_sighash'
                const arg = self.peek();
                var count: usize = 0;
                while (!self.check(.newline) and !self.check(.eof)) {
                    _ = self.bump();
                    count += 1;
                }
                const is_str = arg.kind == .string_literal or arg.kind == .hex_string;
                pending_sighash.append(self.allocator, .{ .spec = if (count == 1 and is_str) arg.text else null, .loc = sighash_loc }) catch {};
                self.skipNewlines();
                continue;
            }

            // `runar_public [key: Type, ...]`
            if (self.checkIdent("runar_public")) {
                _ = self.bump(); // 'runar_public'
                pending_public = true;
                pending_param_types = self.parseOptionalParamTypes();
                self.skipNewlines();
                continue;
            }

            // `params key: Type, ...`
            if (self.checkIdent("params")) {
                _ = self.bump();
                pending_param_types = self.parseOptionalParamTypes();
                self.skipNewlines();
                continue;
            }

            // Method definition
            if (self.check(.kw_def)) {
                var method = self.parseMethod(pending_public, pending_param_types);
                if (std.mem.eql(u8, method.name, "constructor")) {
                    // N-093: the constructor is not a spending entry point.
                    for (pending_sighash.items) |p| self.addErrorAtLoc(p.loc, sighash_directive.LOST_SIGHASH_ERROR);
                    if (constructor != null) self.addError("duplicate constructor");
                    constructor = self.methodToConstructor(method);
                } else {
                    var specs: std.ArrayListUnmanaged(?[]const u8) = .empty;
                    for (pending_sighash.items) |p| specs.append(self.allocator, p.spec) catch {};
                    if (sighash_directive.resolveNativeSighash(self.allocator, method.name, method.is_public, specs.items)) |r| switch (r) {
                        .value => |v| method.sighash_type = v,
                        .err => |e| self.addErrorAtLoc(method.source_loc orelse self.currentSourceLoc(), e),
                    };
                    methods.append(self.allocator, method) catch {};
                }
                pending_public = false;
                pending_param_types = null;
                pending_sighash = .empty;
                self.skipNewlines();
                continue;
            }

            // Ruby's bare visibility markers are no-ops here (visibility
            // comes from `runar_public`); examples/ruby uses them.
            if (self.checkIdent("private") or self.checkIdent("public")) {
                _ = self.bump();
                continue;
            }

            // N-004: refuse anything else (an indented `=begin` lexes as `=`).
            self.addErrorFmt(lex_diag.UNEXPECTED_CLASS_BODY_TOKEN_FMT, .{self.peek().text});
            _ = self.bump();
        }

        // N-093: a `runar_sighash` with no `def` after it annotates nothing.
        for (pending_sighash.items) |p| self.addErrorAtLoc(p.loc, sighash_directive.LOST_SIGHASH_ERROR);

        // N-319: the class `end` is required; EOF here means it is missing.
        if (!self.match(.kw_end)) self.addError("unterminated class: missing closing 'end'");

        // Auto-generate constructor if not provided
        if (constructor == null) {
            constructor = self.autoGenerateConstructor(properties.items);
        }

        // Back-fill constructor param types from prop declarations.
        // In Ruby, `def initialize(pub_key_hash)` has no type annotations —
        // we infer them from the matching `prop :pub_key_hash, Addr` declarations.
        if (constructor) |*ctor| {
            self.backfillParamTypes(ctor, properties.items);
        }

        // F-213 measure (B), before the recursive pass below walks the bodies.
        if (self.nest_error == null and !self.nest.exceeded) self.nest_error = input_limits.membersNestingError(self.allocator, self.file_name, properties.items, methods.items);
        if (self.nest.exceeded or input_limits.membersTooDeep(properties.items, methods.items)) {
            self.refuseNesting();
            return null;
        }
        // Convert bare calls to declared methods and intrinsics into this.method() calls.
        var method_names: std.StringHashMapUnmanaged(void) = .empty;
        for (methods.items) |m| {
            method_names.put(self.allocator, m.name, {}) catch {};
        }
        // Intrinsic methods that must also be rewritten
        method_names.put(self.allocator, "addOutput", {}) catch {};
        method_names.put(self.allocator, "addRawOutput", {}) catch {};
        method_names.put(self.allocator, "addDataOutput", {}) catch {};
        method_names.put(self.allocator, "getStateScript", {}) catch {};

        for (methods.items) |*m| {
            self.rewriteBareMethodCalls(m.body, &method_names);
        }

        // Implicit return conversion for private methods:
        // Ruby methods implicitly return the value of their last expression.
        for (methods.items) |*m| {
            if (!m.is_public and m.body.len > 0) {
                const last = &m.body[m.body.len - 1];
                switch (last.*) {
                    .expr_stmt => |e| {
                        last.* = .{ .return_stmt = .{ .value = e.expr, .source_loc = e.source_loc } };
                    },
                    else => {},
                }
            }
        }

        return ContractNode{
            .name = name_tok.text,
            .parent_class = parent_class,
            .properties = properties.items,
            .constructor = constructor.?,
            .methods = methods.items,
        };
    }

    const ParamTypeEntry = struct { name: []const u8, type_info: RunarType, type_name: []const u8, spelled_type: []const u8 = "" };
    const ParamTypeMap = []ParamTypeEntry;

    /// Parse optional key: Type pairs after `runar_public` or `params`.
    /// Returns null if there are no pairs (just a bare keyword).
    fn parseOptionalParamTypes(self: *Parser) ?ParamTypeMap {
        // If the next token is NEWLINE or eof or def, there are no param types
        if (self.check(.newline) or self.check(.eof) or self.check(.kw_def)) return null;

        var entries: std.ArrayListUnmanaged(ParamTypeEntry) = .empty;

        // Parse key: Type pairs
        while (!self.check(.newline) and !self.check(.eof)) {
            if (!self.check(.ident)) break;
            const name_tok = self.bump();
            const raw_name = name_tok.text;

            // Expect ':'
            if (self.expect(.colon) == null) break;

            // Parse type
            if (!self.check(.ident)) break;
            const type_tok = self.bump();
            const type_info = rbMapType(type_tok.text);
            const type_name = rbMapTypeName(type_tok.text);

            entries.append(self.allocator, .{
                .name = raw_name,
                .type_info = type_info,
                .type_name = type_name,
                .spelled_type = types.spelledIfUnknown(type_info, type_tok.text),
            }) catch {};

            // Optional comma
            if (!self.match(.comma)) break;
        }

        if (entries.items.len == 0) return null;
        return entries.items;
    }

    // ==== Property parsing ====

    /// Type descriptor used during `prop` parsing. Captures either a scalar
    /// Rúnar type or a (possibly nested) FixedArray shape.
    const RbType = struct {
        info: RunarType,
        /// The type name as the author spelled it. Diagnostics only — N-109.
        name: []const u8 = "",
        /// Outer length when `info == .fixed_array`. Zero otherwise.
        length: u32 = 0,
        /// Element type when `info == .fixed_array`. `.unknown` otherwise.
        element: RunarType = .unknown,
        /// Inner length when the element is itself a FixedArray. Zero otherwise.
        nested_length: u32 = 0,
    };

    /// Parse a Ruby type, mirroring `parser_ruby.rb` / `parser_ruby.go` /
    /// `parser_ruby.py`. Recognises `FixedArray[T, N]` (and the nested
    /// `FixedArray[FixedArray[T, M], N]` form) so the rest of the pipeline
    /// sees the length + element type.
    fn parseRbType(self: *Parser) RbType {
        if (!self.check(.ident)) {
            self.addError("expected type name");
            return .{ .info = .unknown };
        }
        const tok = self.bump();
        const info = rbMapType(tok.text);

        // FixedArray[ElemType, N]
        if (std.mem.eql(u8, tok.text, "FixedArray") and self.check(.lbracket)) {
            _ = self.bump(); // '['
            const inner = self.nestedValue(RbType, .{ .info = .unknown }, Parser.parseRbType, .{});
            _ = self.expect(.comma);
            var size: u32 = 0;
            if (self.check(.number)) {
                const size_tok = self.bump();
                size = std.fmt.parseInt(u32, size_tok.text, 10) catch 0;
            } else {
                self.addError("FixedArray length must be a positive integer literal");
            }
            _ = self.expect(.rbracket);

            const element_info = if (inner.info == .fixed_array) RunarType.fixed_array else inner.info;
            return .{
                .info = .fixed_array,
                .name = "FixedArray",
                .length = size,
                .element = element_info,
                .nested_length = if (inner.info == .fixed_array) inner.length else 0,
            };
        }

        return .{ .info = info, .name = tok.text };
    }

    fn parseProp(self: *Parser, parent_class: ParentClass) ?PropertyNode {
        _ = self.bump(); // 'prop'

        // Expect symbol :name
        if (!self.check(.symbol)) {
            self.addError("expected symbol after 'prop'");
            while (!self.check(.newline) and !self.check(.eof)) _ = self.bump();
            return null;
        }

        const raw_name_tok = self.bump(); // symbol value (without colon)
        const raw_name = raw_name_tok.text;
        if (self.expect(.comma) == null) return null;

        // Parse type (supports FixedArray[T, N] and nested forms).
        const rb_type = self.parseRbType();

        // Check for optional trailing options: readonly: true/false, default: <literal>
        var is_readonly = false;
        var embed_always = false;
        var initializer: ?Expression = null;
        var option_error = false;

        while (self.check(.comma)) {
            _ = self.bump(); // ','
            if (self.checkIdent("embed_always")) {
                // N-093: the native spelling of the `@embedAlways` directive.
                _ = self.bump(); // 'embed_always'
                if (self.expect(.colon) == null) {
                    option_error = true;
                    break;
                }
                if (self.check(.kw_true)) {
                    _ = self.bump();
                    embed_always = true;
                } else if (self.check(.kw_false)) {
                    _ = self.bump();
                    embed_always = false;
                } else {
                    self.badBooleanPropOption("embed_always");
                    option_error = true;
                    break;
                }
            } else if (self.checkIdent("readonly")) {
                _ = self.bump(); // 'readonly'
                if (self.expect(.colon) == null) {
                    option_error = true;
                    break;
                }
                if (self.check(.kw_true)) {
                    _ = self.bump();
                    is_readonly = true;
                } else if (self.check(.kw_false)) {
                    _ = self.bump();
                    is_readonly = false;
                } else {
                    self.badBooleanPropOption("readonly");
                    option_error = true;
                    break;
                }
            } else if (self.checkIdent("default")) {
                _ = self.bump(); // 'default'
                if (self.expect(.colon) == null) {
                    option_error = true;
                    break;
                }
                if (self.check(.kw_nil)) {
                    // N-414: `nil` is not a Rúnar literal; refused, never read as 0.
                    self.addErrorFmt("prop default 'nil' is not a literal (expected a number, true, false or a hex string)", .{});
                    _ = self.bump(); // 'nil'
                } else {
                    initializer = self.parseUnary();
                }
            } else {
                // N-301: an unknown option (e.g. a typo of `embed_always`) is
                // refused, never silently dropped. Same text in all seven tiers.
                self.addErrorFmt("unknown prop option '{s}' (expected readonly, embed_always or default)", .{self.peek().text});
                option_error = true;
                break;
            }
        }

        // N-413: nothing may follow the type or an option value except `,`
        // (the next option) or end of line, so `default: 1 + 2` is refused
        // rather than silently truncated to its first operand. Same text in
        // all seven tiers.
        if (!option_error and !self.check(.newline) and !self.check(.eof)) {
            self.addErrorFmt("unexpected '{s}' in prop declaration (expected ',' or end of line)", .{self.peek().text});
        }

        // In stateless contracts (SmartContract and UnsafeSmartContract),
        // all properties are readonly.
        if (parent_class == .smart_contract or parent_class == .unsafe_smart_contract) {
            is_readonly = true;
        }

        // Skip rest of line
        while (!self.check(.newline) and !self.check(.eof)) _ = self.bump();

        return PropertyNode{
            .name = self.declare(raw_name),
            .type_info = rb_type.info,
            .readonly = is_readonly,
            .initializer = initializer,
            .embed_always = embed_always,
            // N-109: spelled type name + field-name token, for the validator's
            // unsupported-type diagnostic. Diagnostics only.
            .type_name = rb_type.name,
            .source_loc = self.tokenSourceLoc(raw_name_tok),
            .fixed_array_length = rb_type.length,
            .fixed_array_element = rb_type.element,
            .fixed_array_nested_length = rb_type.nested_length,
        };
    }

    // ==== Method parsing ====

    fn parseMethod(self: *Parser, is_public: bool, param_types: ?ParamTypeMap) MethodNode {
        _ = self.expect(.kw_def); // 'def'

        var name_tok = self.bump();
        // N-050: `def self.m` / `def Vault.m` declares a singleton (class-level)
        // method, not a contract method.
        if (self.check(.dot)) {
            _ = self.bump(); // '.'
            name_tok = self.bump();
            self.addErrorFmt(lex_diag.STATIC_METHOD_FMT, .{name_tok.text});
        }
        const raw_name = name_tok.text;
        const method_loc = self.tokenSourceLoc(name_tok);

        // Reset local variable tracking for this method scope
        self.declared_locals = .empty;

        // Parse parameters (optional parentheses for no-arg methods)
        var params: []ParamNode = &.{};
        if (self.check(.lparen)) {
            _ = self.bump(); // '('
            params = self.parseParams(param_types);
            _ = self.expect(.rparen);
        }

        self.skipNewlines();

        // Parse body until 'end'
        const body = self.parseStatements();

        _ = self.expect(.kw_end);

        // Determine if this is the constructor
        if (std.mem.eql(u8, raw_name, "initialize")) {
            return .{
                .name = "constructor",
                .params = params,
                .body = body,
                .is_public = true,
                .source_loc = method_loc,
            };
        }

        return .{
            .name = self.declare(raw_name),
            .is_public = is_public,
            .params = params,
            .body = body,
            .source_loc = method_loc,
        };
    }

    fn parseParams(self: *Parser, param_types: ?ParamTypeMap) []ParamNode {
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;

        while (!self.check(.rparen) and !self.check(.eof)) {
            if (!self.check(.ident)) break;
            const name_tok = self.bump();
            const raw_name = name_tok.text;
            const camel_name = self.declare(raw_name);

            // Look up the type from the preceding runar_public/params declaration
            var type_info: RunarType = .unknown;
            var type_name: []const u8 = "";
            var spelled_type: []const u8 = "";
            if (param_types) |pt| {
                for (pt) |entry| {
                    if (std.mem.eql(u8, entry.name, raw_name)) {
                        type_info = entry.type_info;
                        type_name = entry.type_name;
                        spelled_type = entry.spelled_type;
                        break;
                    }
                }
            }

            params.append(self.allocator, .{
                .name = camel_name,
                .type_info = type_info,
                .type_name = type_name,
                .spelled_type = spelled_type,
            }) catch {};

            if (!self.match(.comma)) break;
        }

        return params.items;
    }

    fn autoGenerateConstructor(self: *Parser, properties: []PropertyNode) ConstructorNode {
        // Properties with initializers do not need constructor parameters.
        var required_props: std.ArrayListUnmanaged(PropertyNode) = .empty;
        for (properties) |prop| {
            if (prop.initializer == null) {
                required_props.append(self.allocator, prop) catch {};
            }
        }

        var params = self.allocator.alloc(ParamNode, required_props.items.len) catch return .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
        var super_args = self.allocator.alloc(Expression, required_props.items.len) catch return .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
        var assignments = self.allocator.alloc(AssignmentNode, required_props.items.len) catch return .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };

        for (required_props.items, 0..) |prop, i| {
            params[i] = .{
                .name = prop.name,
                .type_info = prop.type_info,
                .type_name = types.runarTypeToString(prop.type_info),
            };
            super_args[i] = .{ .identifier = prop.name };
            assignments[i] = .{
                .target = prop.name,
                .value = .{ .identifier = prop.name },
            };
        }

        return .{
            .params = params,
            .super_args = super_args,
            .assignments = assignments,
        };
    }

    /// Convert a constructor MethodNode into a ConstructorNode.
    /// Extracts super(...) args and this.x = x assignments from body.
    fn methodToConstructor(self: *Parser, m: MethodNode) ConstructorNode {
        var super_args: std.ArrayListUnmanaged(Expression) = .empty;
        var assignments: std.ArrayListUnmanaged(AssignmentNode) = .empty;
        // R-040: see parse_ts.methodToConstructor — the full body minus the
        // `super(...)` call, so nothing is silently discarded.
        var body: std.ArrayListUnmanaged(Statement) = .empty;
        var super_loc: ?types.SourceLocation = null;

        for (m.body) |stmt| {
            switch (stmt) {
                .expr_stmt => |expr| {
                    // super(...) call
                    switch (expr.expr) {
                        .call => |call| {
                            if (std.mem.eql(u8, call.callee, "super")) {
                                super_loc = expr.source_loc;
                                for (call.args) |arg| super_args.append(self.allocator, arg) catch {};
                                continue;
                            }
                        },
                        else => {},
                    }
                    body.append(self.allocator, stmt) catch {};
                },
                .assign => |assign| {
                    // this.x = value
                    assignments.append(self.allocator, .{ .target = assign.target, .value = assign.value }) catch {};
                    body.append(self.allocator, stmt) catch {};
                },
                else => body.append(self.allocator, stmt) catch {},
            }
        }

        return .{
            .params = m.params,
            .super_args = super_args.items,
            .assignments = assignments.items,
            .super_loc = super_loc,
            .body = body.items,
        };
    }

    /// Back-fill constructor param types from property declarations.
    fn backfillParamTypes(self: *const Parser, ctor: *ConstructorNode, properties: []PropertyNode) void {
        _ = self;
        for (ctor.params) |*param| {
            if (param.type_info == .unknown) {
                for (properties) |prop| {
                    if (std.mem.eql(u8, param.name, prop.name)) {
                        param.type_info = prop.type_info;
                        param.type_name = types.runarTypeToString(prop.type_info);
                        break;
                    }
                }
            }
        }
    }

    /// Rewrite bare calls to declared methods and intrinsics into this.method() calls.
    fn rewriteBareMethodCalls(self: *Parser, body: []Statement, method_names: *std.StringHashMapUnmanaged(void)) void {
        for (body) |*stmt| {
            switch (stmt.*) {
                .expr_stmt => |*expr| {
                    self.rewriteExprMethodCalls(&expr.expr, method_names);
                },
                .assign => |*a| {
                    self.rewriteExprMethodCalls(&a.value, method_names);
                },
                .const_decl => |*cd| {
                    self.rewriteExprMethodCalls(&cd.value, method_names);
                },
                .let_decl => |*ld| {
                    if (ld.value) |*v| self.rewriteExprMethodCalls(v, method_names);
                },
                .if_stmt => |*ifs| {
                    self.rewriteExprMethodCalls(&ifs.condition, method_names);
                    self.rewriteBareMethodCalls(ifs.then_body, method_names);
                    if (ifs.else_body) |eb| self.rewriteBareMethodCalls(eb, method_names);
                },
                .assert_stmt => |*a| {
                    self.rewriteExprMethodCalls(&a.condition, method_names);
                },
                .return_stmt => |*rs| {
                    if (rs.value) |*v| self.rewriteExprMethodCalls(v, method_names);
                },
                .for_stmt => |*fs| {
                    self.rewriteBareMethodCalls(fs.body, method_names);
                },
            }
        }
    }

    fn rewriteExprMethodCalls(self: *Parser, expr: *Expression, method_names: *std.StringHashMapUnmanaged(void)) void {
        switch (expr.*) {
            .call => |call| {
                if (method_names.contains(call.callee)) {
                    // Rewrite to method call on 'this'
                    const mc = self.allocator.create(MethodCall) catch return;
                    mc.* = .{ .object = "this", .method = call.callee, .args = call.args };
                    expr.* = .{ .method_call = mc };
                }
            },
            .binary_op => |bop| {
                self.rewriteExprMethodCalls(@constCast(&bop.left), method_names);
                self.rewriteExprMethodCalls(@constCast(&bop.right), method_names);
            },
            .unary_op => |uop| {
                self.rewriteExprMethodCalls(@constCast(&uop.operand), method_names);
            },
            .method_call => |mc| {
                for (mc.args) |*arg| {
                    self.rewriteExprMethodCalls(@constCast(arg), method_names);
                }
            },
            else => {},
        }
    }

    // ==== Statements ====

    fn parseStatements(self: *Parser) []Statement {
        var stmts: std.ArrayListUnmanaged(Statement) = .empty;

        while (!self.check(.kw_end) and !self.check(.kw_elsif) and
            !self.check(.kw_else) and !self.check(.eof))
        {
            self.skipNewlines();
            if (self.check(.kw_end) or self.check(.kw_elsif) or
                self.check(.kw_else) or self.check(.eof)) break;

            if (self.parseStatement()) |s| stmts.append(self.allocator, s) catch {};
            self.skipNewlines();
        }

        return stmts.items;
    }

    fn parseStatement(self: *Parser) ?Statement {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
        return self.parseStatementInner();
    }

    fn parseStatementInner(self: *Parser) ?Statement {
        // assert statement
        if (self.check(.kw_assert)) return self.parseAssertStatement();

        // if statement
        if (self.check(.kw_if)) return self.parseIfStatement();

        // unless statement
        if (self.check(.kw_unless)) return self.parseUnlessStatement();

        // for statement
        if (self.check(.kw_for)) return self.parseForStatement();

        // return statement
        if (self.check(.kw_return)) return self.parseReturnStatement();

        // super(args...) — parse as part of constructor
        if (self.check(.kw_super)) return self.parseSuperCall();

        // Instance variable assignment: @var = expr, @var += expr
        if (self.check(.ivar)) return self.parseIvarStatement();

        // Variable declaration or expression statement starting with ident
        if (self.check(.ident) or self.check(.kw_self)) return self.parseIdentStatement();

        // N-053: a token that can begin an expression begins an expression
        // statement (a private helper's last one is its implicit return
        // value); any other token is refused. Skipping it dropped `!` / `(` /
        // literals.
        switch (self.peek().kind) {
            .number, .string_literal, .hex_string, .kw_true, .kw_false, .kw_nil,
            .lparen, .lbracket, .minus, .tilde, .bang, .kw_not,
            => {
                const loc = self.currentSourceLoc();
                const expr = self.parseExpression() orelse return null;
                return .{ .expr_stmt = .{ .expr = expr, .source_loc = loc } };
            },
            else => {},
        }
        self.addErrorFmt(lex_diag.UNSUPPORTED_STATEMENT_FMT, .{self.peek().text});
        _ = self.bump();
        return null;
    }

    fn parseAssertStatement(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // 'assert'

        // Support both `assert expr` and `assert(expr)`
        var cond: ?Expression = null;
        if (self.check(.lparen)) {
            _ = self.bump();
            cond = self.parseExpression();
            _ = self.expect(.rparen);
        } else {
            cond = self.parseExpression();
        }

        if (cond) |c| {
            return .{ .assert_stmt = .{ .condition = c, .source_loc = loc } };
        }
        return null;
    }

    fn parseIfStatement(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // 'if'
        const condition = self.parseExpression() orelse return null;
        self.skipNewlines();

        // Variables declared inside an if/elsif/else branch are scoped to
        // that branch. Snapshot+restore declared_locals so a sibling
        // branch (or sibling top-level if-without-else block) can
        // re-declare the same local without it being treated as an
        // assignment to an out-of-scope variable. Mirrors the canonical
        // TS / Python lexical-scope semantics.
        const locals_before_then = self.cloneDeclaredLocals();
        const then_body = self.parseStatements();
        self.restoreDeclaredLocals(locals_before_then);

        var else_body: ?[]Statement = null;

        if (self.check(.kw_elsif)) {
            const elif = self.nestedParse(Statement, Parser.parseElsifStatement) orelse return null;
            const a = self.allocator.alloc(Statement, 1) catch return null;
            a[0] = elif;
            else_body = a;
            self.restoreDeclaredLocals(locals_before_then);
        } else if (self.match(.kw_else)) {
            self.skipNewlines();
            else_body = self.parseStatements();
            self.restoreDeclaredLocals(locals_before_then);
        }

        _ = self.expect(.kw_end);

        return .{ .if_stmt = .{ .condition = condition, .then_body = then_body, .else_body = else_body, .source_loc = loc } };
    }

    fn parseElsifStatement(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // 'elsif'
        const condition = self.parseExpression() orelse return null;
        self.skipNewlines();

        // Same scope discipline as parseIfStatement.
        const locals_before_then = self.cloneDeclaredLocals();
        const then_body = self.parseStatements();
        self.restoreDeclaredLocals(locals_before_then);

        var else_body: ?[]Statement = null;

        if (self.check(.kw_elsif)) {
            const elif = self.nestedParse(Statement, Parser.parseElsifStatement) orelse return null;
            const a = self.allocator.alloc(Statement, 1) catch return null;
            a[0] = elif;
            else_body = a;
            self.restoreDeclaredLocals(locals_before_then);
        } else if (self.match(.kw_else)) {
            self.skipNewlines();
            else_body = self.parseStatements();
            self.restoreDeclaredLocals(locals_before_then);
        }

        // Note: the outer `end` is consumed by the parent parseIfStatement;
        // elsif branches do not consume their own `end`.

        return .{ .if_stmt = .{ .condition = condition, .then_body = then_body, .else_body = else_body, .source_loc = loc } };
    }

    fn parseUnlessStatement(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // 'unless'
        const raw_cond = self.parseExpression() orelse return null;
        self.skipNewlines();

        const body = self.parseStatements();
        _ = self.expect(.kw_end);

        // Unless is if with negated condition
        const uop = self.allocator.create(UnaryOp) catch return null;
        uop.* = .{ .op = .not, .operand = raw_cond };
        const negated: Expression = .{ .unary_op = uop };

        return .{ .if_stmt = .{ .condition = negated, .then_body = body, .source_loc = loc } };
    }

    fn parseForStatement(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // 'for'

        // Loop variable
        const iter_tok = self.bump();
        const var_name = self.declare(iter_tok.text);

        _ = self.expect(.kw_in);

        // Three loop headers, all of them real Ruby that iterates exactly these
        // values:
        //
        //   for i in 0...n       -> 0, 1, … n-1  (exclusive, ascending)
        //   for i in 0..n        -> 0, 1, … n    (inclusive, ascending)
        //   for i in n.downto(m) -> n, n-1, … m  (inclusive, DESCENDING)
        //
        // `downto` is what lets the Ruby surface spell a countdown. Ruby's
        // range operators only ever ascend — `(5..2)` is empty — so
        // `step = -1` was unreachable from this surface, and no fixture could
        // exercise it across all nine. `Integer#downto` is the language's own
        // countdown verb, it returns an Enumerator, and `for x in enum` is
        // valid Ruby over one.
        //
        // The `downto` receiver has to be recognised from the TOKENS, before
        // the expression parser runs: this tier's `MethodCall.object` is a
        // `[]const u8`, so a postfix parse of `5.downto(2)` throws the literal
        // receiver away ("unknown") and the start would be unrecoverable.
        var is_exclusive = false;
        var descending = false;
        var start_expr: Expression = undefined;
        var end_expr: Expression = undefined;

        if (self.peekAhead(1).kind == .dot and
            self.peekAhead(2).kind == .ident and
            std.mem.eql(u8, self.peekAhead(2).text, "downto") and
            self.peekAhead(3).kind == .lparen)
        {
            start_expr = self.parsePrimary() orelse return null;
            _ = self.expect(.dot);
            _ = self.bump(); // 'downto'
            _ = self.expect(.lparen);
            end_expr = self.parseExpression() orelse return null;
            _ = self.expect(.rparen);
            descending = true;
            is_exclusive = false; // downto's bound is inclusive
        } else {
            // Parse start value
            start_expr = self.parseExpression() orelse return null;

            // Expect range operator: .. (inclusive) or ... (exclusive)
            if (self.check(.dot_dot_dot)) {
                is_exclusive = true;
                _ = self.bump();
            } else if (self.check(.dot_dot)) {
                is_exclusive = false;
                _ = self.bump();
            } else {
                self.addError("expected range operator '..' or '...', or '.downto(n)', in for loop");
            }

            end_expr = self.parseExpression() orelse return null;
        }

        // Optional 'do' keyword
        _ = self.match(.kw_do);
        self.skipNewlines();

        const body = self.parseStatements();
        _ = self.expect(.kw_end);

        // Extract integer values for the ForStmt (which uses init_value and bound)
        var init_value: i64 = 0;
        // N-137: a start that is not a compile-time literal cannot be unrolled.
        var init_is_const: bool = true;
        // N-138: `.literal_int` alone missed a negated literal, so
        // `for i in -1...5` started at 0.
        if (loopStartLiteral(start_expr)) |v| init_value = v else {
            init_is_const = false;
        }

        var bound: i64 = 0;
        // F-025: see `ForStmt.bound_is_const`. Only a (possibly negated)
        // integer literal is unrollable; anything else used to leave `bound`
        // at 0 and compile a loop that runs zero times.
        var bound_is_const: bool = false;
        var bound_ident: ?[]const u8 = null;
        if (loopStartLiteral(end_expr)) |v| {
            bound_is_const = true;
            if (descending or is_exclusive) {
                // `downto`'s bound is inclusive and this tier records that
                // as `inclusive`, so the raw value goes through unchanged
                // — the +1 below is the ASCENDING inclusive range's
                // exclusive-bound conversion and must not be applied here.
                bound = v;
            } else {
                bound = v + 1; // inclusive range: bound becomes exclusive
            }
        } else if (end_expr == .identifier) {
            bound_ident = end_expr.identifier;
        }

        return .{ .for_stmt = .{
            .var_name = var_name,
            .init_value = init_value,
            .init_is_const = init_is_const,
            .bound = bound,
            .bound_is_const = bound_is_const,
            .bound_ident = bound_ident,
            .descending = descending,
            .inclusive = descending,
            .body = body,
            .source_loc = loc,
        } };
    }

    fn parseReturnStatement(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // 'return'
        if (self.check(.newline) or self.check(.kw_end) or self.check(.eof)) {
            return .{ .return_stmt = .{ .value = null, .source_loc = loc } };
        }
        const expr = self.parseExpression();
        return .{ .return_stmt = .{ .value = expr, .source_loc = loc } };
    }

    fn parseSuperCall(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // 'super'
        _ = self.expect(.lparen);
        var args: std.ArrayListUnmanaged(Expression) = .empty;
        while (!self.check(.rparen) and !self.check(.eof)) {
            const arg = self.parseExpression() orelse break;
            args.append(self.allocator, arg) catch {};
            if (!self.match(.comma)) break;
        }
        _ = self.expect(.rparen);

        const call = self.allocator.create(CallExpr) catch return null;
        call.* = .{ .callee = "super", .args = args.items };
        return .{ .expr_stmt = .{ .expr = .{ .call = call }, .source_loc = loc } };
    }

    fn parseIvarStatement(self: *Parser) ?Statement {
        const start = self.pos;
        const ivar_tok = self.bump(); // ivar token
        const loc = self.tokenSourceLoc(ivar_tok);
        const prop_name = rbConvertName(self.allocator, ivar_tok.text);

        // Build the LHS target, consuming `[index]` postfixes so that
        // `@var[i] = expr` lands on the assignment path rather than being
        // split into an orphan read and a rogue rhs.
        var target_expr: Expression = .{ .property_access = .{ .object = "this", .property = prop_name } };
        while (self.check(.lbracket)) {
            _ = self.bump();
            const index = self.parseExpression() orelse return null;
            if (!self.match(.rbracket)) {
                self.addError("expected ']'");
                return null;
            }
            const ia = self.allocator.create(IndexAccess) catch return null;
            ia.* = .{ .object = target_expr, .index = index };
            target_expr = .{ .index_access = ia };
        }

        // Simple assignment: @var = expr  |  @var[i] = expr
        if (self.match(.assign)) {
            const value = self.parseExpression() orelse return null;
            return self.buildAssignment(target_expr, value, loc);
        }

        // Compound assignments: @var += expr, etc.
        if (isCompoundAssignOp(self.peek().kind)) {
            const op_kind = self.peek().kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, target_expr, rhs) orelse return null;
            return self.buildAssignment(target_expr, compound_rhs, loc);
        }

        // Expression statement (@var on its own line, @var.method(...), or a
        // private helper's implicit return such as `@x + 1`). N-053: re-parse
        // from the ivar as a whole expression; continuing only the postfix
        // chain left `+ 1` behind, and the statement dispatcher skipped it.
        self.pos = start;
        const expr = self.parseExpression() orelse return null;
        return .{ .expr_stmt = .{ .expr = expr, .source_loc = loc } };
    }

    fn parseIdentStatement(self: *Parser) ?Statement {
        const tok = self.peek();
        const loc = self.tokenSourceLoc(tok);

        // Check for `self.` prefix -> property access/assignment
        if (tok.kind == .kw_self and self.peekAhead(1).kind == .dot) {
            _ = self.bump(); // 'self'
            _ = self.bump(); // '.'
            if (!self.check(.ident)) {
                self.addError("expected identifier after 'self.'");
                return null;
            }
            const member_tok = self.bump();
            const prop_name = rbConvertName(self.allocator, member_tok.text);

            // Method call: self.method(args)
            if (self.check(.lparen)) {
                _ = self.bump();
                const args = self.parseArgList();
                const arg_locs = self.last_arg_locs;
                const mc = self.allocator.create(MethodCall) catch return null;
                mc.* = .{ .object = "this", .method = prop_name, .args = args, .arg_locs = arg_locs };
                return .{ .expr_stmt = .{ .expr = .{ .method_call = mc }, .source_loc = loc } };
            }

            // Assignment: self.field = expr
            if (self.match(.assign)) {
                const value = self.parseExpression() orelse return null;
                return .{ .assign = .{ .target = prop_name, .value = value, .source_loc = loc, .target_is_property = true } };
            }

            // Compound assignment: self.field += expr
            if (isCompoundAssignOp(self.peek().kind)) {
                const op_kind = self.peek().kind;
                _ = self.bump();
                const rhs = self.parseExpression() orelse return null;
                const bin_op = binOpFromCompoundAssign(op_kind);
                const target_expr: Expression = .{ .property_access = .{ .object = "this", .property = prop_name } };
                const compound_rhs = self.makeBinaryExpr(bin_op, target_expr, rhs) orelse return null;
                return .{ .assign = .{ .target = prop_name, .value = compound_rhs, .source_loc = loc, .target_is_property = true } };
            }

            // Expression statement (property access)
            const expr: Expression = .{ .property_access = .{ .object = "this", .property = prop_name } };
            return .{ .expr_stmt = .{ .expr = expr, .source_loc = loc } };
        }

        // Check for simple name = expr pattern (variable declaration or assignment)
        if (tok.kind == .ident and self.peekAhead(1).kind == .assign) {
            _ = self.bump(); // consume ident
            _ = self.bump(); // consume '='
            const value = self.parseExpression() orelse return null;
            const camel_name = self.declare(tok.text);

            if (self.declared_locals.contains(camel_name)) {
                // Already declared: this is an assignment
                return .{ .assign = .{ .target = camel_name, .value = value, .source_loc = loc } };
            }
            // First assignment: variable declaration (let)
            self.declared_locals.put(self.allocator, camel_name, {}) catch {};
            return .{ .let_decl = .{ .name = camel_name, .value = value, .source_loc = loc } };
        }

        // Parse as expression first
        const expr = self.parseExpression() orelse {
            _ = self.bump();
            return null;
        };

        // Simple assignment (e.g. a.b = expr)
        if (self.match(.assign)) {
            const value = self.parseExpression() orelse return null;
            return self.buildAssignment(expr, value, loc);
        }

        // Compound assignment
        if (isCompoundAssignOp(self.peek().kind)) {
            const op_kind = self.peek().kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs, loc);
        }

        // Expression statement
        return .{ .expr_stmt = .{ .expr = expr, .source_loc = loc } };
    }

    fn buildAssignment(self: *Parser, target: Expression, value: Expression, loc: types.SourceLocation) ?Statement {
        _ = self;
        const is_prop = types.targetIsProperty(target);
        switch (target) {
            .property_access => |pa| {
                return .{ .assign = .{ .target = pa.property, .value = value, .source_loc = loc, .target_is_property = is_prop } };
            },
            .identifier => |id| {
                return .{ .assign = .{ .target = id, .value = value, .source_loc = loc, .target_is_property = is_prop } };
            },
            .index_access => |ia| {
                // @arr[idx] = value — carry the full index-access target on
                // the Assign so `expand_fixed_arrays` can rewrite it into
                // dispatch form. `target` stores the base property name (when
                // the object is `this.<name>`) so downstream pretty-printing
                // and debug output remain meaningful.
                const base_name: []const u8 = switch (ia.object) {
                    .property_access => |pa| pa.property,
                    .identifier => |id| id,
                    else => "unknown",
                };
                return .{ .assign = .{
                    .target = base_name,
                    .value = value,
                    .index_target = ia,
                    .source_loc = loc,
                    .target_is_property = is_prop,
                } };
            },
            else => {
                return .{ .assign = .{ .target = "unknown", .value = value, .source_loc = loc, .target_is_property = is_prop } };
            },
        }
    }

    fn makeBinaryExpr(self: *Parser, op: BinOperator, left: Expression, right: Expression) ?Expression {
        const bop = self.allocator.create(BinaryOp) catch return null;
        bop.* = .{ .op = op, .left = left, .right = right };
        return .{ .binary_op = bop };
    }

    fn makeLocatedBinaryExpr(self: *Parser, op: BinOperator, left: Expression, left_loc: ?types.SourceLocation, right: Expression, right_loc: ?types.SourceLocation) ?Expression {
        const bop = self.allocator.create(BinaryOp) catch return null;
        bop.* = .{ .op = op, .left = left, .right = right, .left_loc = left_loc, .right_loc = right_loc };
        return .{ .binary_op = bop };
    }

    /// N-492: where the TS reference locates the operand that began at token
    /// `start` and ends at the token just consumed. See `operand_loc.zig`.
    fn operandLocFrom(self: *const Parser, start: Token) ?types.SourceLocation {
        return self.tokenSourceLoc(self.operand_locs.startOf(start));
    }

    // ==== Expressions ====
    // Operator precedence (lowest to highest):
    //   ternary (? :)
    //   logical or (|| / or)
    //   logical and (&& / and)
    //   not (! / not) — Ruby 'not' is very low precedence, but we follow Go parser here
    //   bitwise or (|)
    //   bitwise xor (^)
    //   bitwise and (&)
    //   equality (== !=)
    //   comparison (< <= > >=)
    //   shift (<< >>)
    //   additive (+ -)
    //   multiplicative (* / %)
    //   unary (- ~ !)
    //   power (**)
    //   postfix (. [] ())
    //   primary

    fn parseExpression(self: *Parser) ?Expression {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
        return self.parseTernary();
    }

    fn parseTernary(self: *Parser) ?Expression {
        var expr = self.parseLogicalOr() orelse return null;
        if (self.match(.question)) {
            const consequent = self.parseExpression() orelse return null;
            if (self.expect(.colon) == null) return null;
            const alternate = self.parseExpression() orelse return null;
            const tern = self.allocator.create(Ternary) catch return null;
            tern.* = .{ .condition = expr, .then_expr = consequent, .else_expr = alternate };
            expr = .{ .ternary = tern };
        }
        return expr;
    }

    fn parseLogicalOr(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseLogicalAnd() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.pipe_pipe) or self.check(.kw_or)) {
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseLogicalAnd() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(.or_op, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseLogicalAnd(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseLogicalNot() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.amp_amp) or self.check(.kw_and)) {
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseLogicalNot() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(.and_op, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseLogicalNot(self: *Parser) ?Expression {
        if (self.check(.kw_not) or self.check(.bang)) {
            const op_loc = self.tokenSourceLoc(self.bump());
            const operand = self.nestedParse(Expression, Parser.parseLogicalNot) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .not, .operand = operand, .location = op_loc };
            return .{ .unary_op = uop };
        }
        return self.parseBitwiseOr();
    }

    fn parseBitwiseOr(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseBitwiseXor() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.pipe)) {
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseBitwiseXor() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(.bitor, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseBitwiseXor(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseBitwiseAnd() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.caret)) {
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseBitwiseAnd() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(.bitxor, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseBitwiseAnd(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseEquality() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.ampersand)) {
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseEquality() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(.bitand, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseEquality(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseComparison() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.eqeq) or self.check(.not_eq)) {
            const op: BinOperator = if (self.peek().kind == .eqeq) .eq else .neq;
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseComparison() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(op, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
            // N-505: the comparison node is located at its first token (a leading
            // `(` included), as the TS reference locates it; `===` / `!==` type
            // errors anchor here.
            left.binary_op.loc = left_loc;
        }
        return left;
    }

    fn parseComparison(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseShift() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.lt) or self.check(.lt_eq) or self.check(.gt) or self.check(.gt_eq)) {
            const op: BinOperator = switch (self.peek().kind) {
                .lt => .lt,
                .lt_eq => .lte,
                .gt => .gt,
                .gt_eq => .gte,
                else => unreachable,
            };
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseShift() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(op, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseShift(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseAdditive() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.lshift) or self.check(.rshift)) {
            const op: BinOperator = if (self.peek().kind == .lshift) .lshift else .rshift;
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseAdditive() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(op, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseAdditive(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseMultiplicative() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.plus) or self.check(.minus)) {
            const op: BinOperator = if (self.peek().kind == .plus) .add else .sub;
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseMultiplicative() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(op, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseMultiplicative(self: *Parser) ?Expression {
        const left_start = self.peek();
        var left = self.parseUnary() orelse return null;
        var left_loc = self.operandLocFrom(left_start);
        while (self.check(.star) or self.check(.slash) or self.check(.percent)) {
            const op: BinOperator = switch (self.peek().kind) {
                .star => .mul,
                .slash => .div,
                .percent => .mod,
                else => unreachable,
            };
            _ = self.bump();
            const right_start = self.peek();
            const right = self.parseUnary() orelse return null;
            const right_loc = self.operandLocFrom(right_start);
            left = self.makeLocatedBinaryExpr(op, left, left_loc, right, right_loc) orelse return null;
            left_loc = self.operandLocFrom(left_start);
        }
        return left;
    }

    fn parseUnary(self: *Parser) ?Expression {
        if (self.check(.minus)) {
            const op_loc = self.tokenSourceLoc(self.bump());
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .negate, .operand = o, .location = op_loc };
            return .{ .unary_op = uop };
        }
        if (self.check(.tilde)) {
            const op_loc = self.tokenSourceLoc(self.bump());
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .bitnot, .operand = o, .location = op_loc };
            return .{ .unary_op = uop };
        }
        if (self.check(.bang)) {
            const op_loc = self.tokenSourceLoc(self.bump());
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .not, .operand = o, .location = op_loc };
            return .{ .unary_op = uop };
        }
        return self.parsePower();
    }

    /// parsePower handles ** (right-associative, maps to pow() call)
    fn parsePower(self: *Parser) ?Expression {
        const base = self.parsePostfix() orelse return null;
        if (self.match(.star_star)) {
            const exp = self.nestedParse(Expression, Parser.parsePower) orelse return null; // right-recursive for right-associativity
            const call = self.allocator.create(CallExpr) catch return null;
            var args = self.allocator.alloc(Expression, 2) catch return null;
            args[0] = base;
            args[1] = exp;
            call.* = .{ .callee = "pow", .args = args };
            return .{ .call = call };
        }
        return base;
    }

    fn parsePostfix(self: *Parser) ?Expression {
        var expr = self.parsePrimary() orelse return null;
        expr = self.parsePostfixFrom(expr);
        return expr;
    }

    /// Parse postfix operations (method calls, property access, indexing) from a given expression.
    fn parsePostfixFrom(self: *Parser, start_expr: Expression) Expression {
        var expr = start_expr;
        while (true) {
            // Method call or property access: expr.name or expr.name(...)
            if (self.check(.dot)) {
                _ = self.bump();
                if (!self.check(.ident) and !self.check(.kw_assert)) {
                    self.addError("expected identifier after '.'");
                    return expr;
                }
                const member_tok = self.bump();
                const member = rbConvertName(self.allocator, member_tok.text);

                if (self.check(.lparen)) {
                    // Method call: expr.method(args)
                    _ = self.bump();
                    const args = self.parseArgList();
                    const arg_locs = self.last_arg_locs;
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "this") or std.mem.eql(u8, id, "Runar")) {
                                // this.method(args) or Runar.method(args) -> MethodCall or CallExpr
                                if (std.mem.eql(u8, id, "Runar")) {
                                    // Runar.method(args) -> CallExpr{callee=member}
                                    const call = self.allocator.create(CallExpr) catch return expr;
                                    call.* = .{ .callee = member, .args = args, .arg_locs = arg_locs };
                                    expr = .{ .call = call };
                                } else {
                                    const mc = self.allocator.create(MethodCall) catch return expr;
                                    mc.* = .{ .object = "this", .method = member, .args = args, .arg_locs = arg_locs };
                                    expr = .{ .method_call = mc };
                                }
                            } else {
                                const mc = self.allocator.create(MethodCall) catch return expr;
                                mc.* = .{ .object = id, .method = member, .args = args, .arg_locs = arg_locs };
                                expr = .{ .method_call = mc };
                            }
                        },
                        .property_access => |pa| {
                            // this.prop.method(args) -> complex, flatten to MethodCall
                            const mc = self.allocator.create(MethodCall) catch return expr;
                            mc.* = .{ .object = pa.property, .method = member, .args = args, .arg_locs = arg_locs };
                            expr = .{ .method_call = mc };
                        },
                        else => {
                            const mc = self.allocator.create(MethodCall) catch return expr;
                            mc.* = .{ .object = "unknown", .method = member, .args = args, .arg_locs = arg_locs };
                            expr = .{ .method_call = mc };
                        },
                    }
                } else {
                    // Property access: expr.property
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "this")) {
                                expr = .{ .property_access = .{ .object = "this", .property = member } };
                            } else {
                                expr = .{ .property_access = .{ .object = id, .property = member } };
                            }
                        },
                        else => {
                            expr = .{ .property_access = .{ .object = "unknown", .property = member } };
                        },
                    }
                }
                continue;
            }

            // Function call: expr(...)
            if (self.check(.lparen)) {
                switch (expr) {
                    .identifier => |id| {
                        _ = self.bump();
                        const args = self.parseArgList();
                        const arg_locs = self.last_arg_locs;
                        const call = self.allocator.create(CallExpr) catch return expr;
                        call.* = .{ .callee = id, .args = args, .arg_locs = arg_locs };
                        expr = .{ .call = call };
                    },
                    else => break,
                }
                continue;
            }

            // Index access: expr[index]
            if (self.check(.lbracket)) {
                _ = self.bump();
                const idx = self.parseExpression() orelse return expr;
                _ = self.expect(.rbracket);
                const ia = self.allocator.create(IndexAccess) catch return expr;
                ia.* = .{ .object = expr, .index = idx };
                expr = .{ .index_access = ia };
                continue;
            }

            break;
        }
        return expr;
    }

    fn parsePrimary(self: *Parser) ?Expression {
        const tok = self.peek();

        // Number literal
        if (tok.kind == .number) {
            _ = self.bump();
            return self.numberLiteral(tok);
        }

        // Boolean literals
        if (tok.kind == .kw_true) {
            _ = self.bump();
            return Expression{ .literal_bool = true };
        }
        if (tok.kind == .kw_false) {
            _ = self.bump();
            return Expression{ .literal_bool = false };
        }

        // Hex string literal (single-quoted)
        if (tok.kind == .hex_string) {
            _ = self.bump();
            return Expression{ .literal_bytes = .{ .value = tok.text, .location = self.tokenSourceLoc(tok) } };
        }

        // String literal (double-quoted)
        if (tok.kind == .string_literal) {
            _ = self.bump();
            return Expression{ .literal_bytes = .{ .value = tok.text, .location = self.tokenSourceLoc(tok) } };
        }

        // N-416: `nil` is not a Rúnar value; refused, never read as 0.
        if (tok.kind == .kw_nil) {
            self.addErrorFmt("'nil' is not a Rúnar value (use a number, true, false or a hex string)", .{});
            _ = self.bump();
            return Expression{ .literal_int = 0 };
        }

        // Instance variable: @var -> property access (this.camelCaseVar)
        if (tok.kind == .ivar) {
            _ = self.bump();
            const prop_name = rbConvertName(self.allocator, tok.text);
            return Expression{ .property_access = .{ .object = "this", .property = prop_name } };
        }

        // Parenthesised expression
        if (tok.kind == .lparen) {
            const open = self.bump();
            const inner_first = self.peek();
            const inner = self.parseExpression() orelse return null;
            if (self.expect(.rparen)) |close| self.operand_locs.recordParen(self.allocator, open, inner_first, close);
            return inner;
        }

        // Array literal: [elem, ...]
        if (tok.kind == .lbracket) {
            return self.parseArrayLiteral();
        }

        // super keyword
        if (tok.kind == .kw_super) {
            _ = self.bump();
            return Expression{ .identifier = "super" };
        }

        // assert as identifier (for assert in expressions)
        if (tok.kind == .kw_assert) {
            _ = self.bump();
            return Expression{ .identifier = "assert" };
        }

        // self keyword
        if (tok.kind == .kw_self) {
            _ = self.bump();
            return Expression{ .identifier = "this" };
        }

        // Identifier or function call
        if (tok.kind == .ident) {
            _ = self.bump();
            const name = rbConvertName(self.allocator, tok.text);

            // Check for "Runar" prefix: Runar.method(args) -> just pass through,
            // will be handled in postfix parsing
            if (std.mem.eql(u8, tok.text, "Runar")) {
                return Expression{ .identifier = "Runar" };
            }

            // Function call: name(...)
            if (self.check(.lparen)) {
                _ = self.bump();
                const args = self.parseArgList();
                const arg_locs = self.last_arg_locs;
                const call = self.allocator.create(CallExpr) catch return null;
                call.* = .{ .callee = name, .args = args, .arg_locs = arg_locs };
                return Expression{ .call = call };
            }

            return Expression{ .identifier = name };
        }

        self.addErrorFmt("unexpected token: '{s}'", .{tok.text});
        _ = self.bump();
        return null;
    }

    /// N-464: the first token of the argument about to be parsed, as
    /// parse_ts.zig's `operandLoc` (null on `(`, whose inner expression
    /// this one-token view cannot see).
    fn argLoc(self: *const Parser) ?types.SourceLocation {
        if (self.check(.lparen)) return null;
        return self.currentSourceLoc();
    }

    fn parseArgList(self: *Parser) []Expression {
        var args: std.ArrayListUnmanaged(Expression) = .empty;
        // N-464: published only once the whole list is parsed, so a call
        // nested inside an argument cannot clobber it.
        var locs: std.ArrayListUnmanaged(?types.SourceLocation) = .empty;
        defer self.last_arg_locs = if (locs.items.len == args.items.len) locs.items else &.{};
        while (!self.check(.rparen) and !self.check(.eof)) {
            const arg_loc = self.argLoc();
            const arg = self.parseExpression() orelse break;
            args.append(self.allocator, arg) catch {};
            locs.append(self.allocator, arg_loc) catch {};
            if (!self.match(.comma)) break;
        }
        _ = self.expect(.rparen);
        return args.items;
    }

    fn parseArrayLiteral(self: *Parser) ?Expression {
        _ = self.expect(.lbracket);
        var elements: std.ArrayListUnmanaged(Expression) = .empty;
        while (!self.check(.rbracket) and !self.check(.eof)) {
            const elem = self.parseExpression() orelse break;
            elements.append(self.allocator, elem) catch {};
            if (!self.match(.comma)) break;
        }
        _ = self.expect(.rbracket);
        return .{ .array_literal = elements.items };
    }

    fn parseRbNumber(self: *Parser, text: []const u8) ?Expression {
        // Strip underscores from number text. Buffer sized for 256-bit
        // decimal literals (78 digits) with headroom.
        var stripped_buf: [160]u8 = undefined;
        var stripped_len: usize = 0;
        var overflow = false;
        for (text) |ch| {
            if (ch == '_') continue;
            if (stripped_len >= stripped_buf.len) {
                overflow = true;
                break;
            }
            stripped_buf[stripped_len] = ch;
            stripped_len += 1;
        }
        if (overflow) {
            self.addErrorFmt("integer literal too long: '{s}'", .{text});
            return Expression{ .literal_int = 0 };
        }
        const stripped = stripped_buf[0..stripped_len];
        if (std.fmt.parseInt(i64, stripped, 0)) |val| {
            return Expression{ .literal_int = val };
        } else |_| {
            // Oversize decimal literal — carry as `literal_bigint`.
            // N-134: an oversize literal in ANY radix. `0xFFFF...41n` -- the
            // ordinary way to write secp256k1's group order, and accepted by the
            // other six tiers -- used to fall into the `invalid integer` arm
            // below, because this fallback only recognised decimal digits.
            if (int_literal.oversizeToDecimal(self.allocator, stripped)) |decimal| {
                return Expression{ .literal_bigint = decimal };
            }
            self.addErrorFmt("invalid integer: '{s}'", .{text});
            return Expression{ .literal_int = 0 };
        }
    }

    // ==== Helpers ====

    fn isCompoundAssignOp(k: TokenKind) bool {
        return k == .plus_eq or k == .minus_eq or k == .star_eq or k == .slash_eq or k == .percent_eq;
    }

    fn binOpFromCompoundAssign(k: TokenKind) BinOperator {
        return switch (k) {
            .plus_eq => .add,
            .minus_eq => .sub,
            .star_eq => .mul,
            .slash_eq => .div,
            .percent_eq => .mod,
            else => unreachable, // N-057: guarded by isCompoundAssignOp above; no fallback to add
        };
    }

    test "N-057: binOpFromCompoundAssign has no silent fallback to add (Ruby)" {
        // Proves: this file's source for binOpFromCompoundAssign's switch no longer
        // contains a default arm that maps every otherwise-unmapped compound
        // assignment token to the add operator. The needle is built by
        // concatenation so this assertion's own text cannot satisfy itself.
        // Does not prove runtime behavior of the removed default arm: every call
        // site already narrows to compound-assignment tokens via
        // isCompoundAssignOp (over the identical set the switch maps) before
        // calling binOpFromCompoundAssign, so that arm was unreachable before this
        // change and is `unreachable` now (a checked panic under Debug/ReleaseSafe,
        // undefined behavior under ReleaseFast/ReleaseSmall) — this test cannot and
        // does not exercise that code path directly.
        const bad_arm = "else " ++ "=> ." ++ "add";
        const src = @embedFile("parse_ruby.zig");
        try std.testing.expect(std.mem.indexOf(u8, src, bad_arm) == null);
    }

    /// F-026: a number token's `text` becomes the canonical decimal value of
    /// its literal (`raw` keeps the literal as written), validated against
    /// this surface's host-language rules
    /// (packages/runar-compiler/src/passes/int-literal.ts). A malformed
    /// literal is refused with the shared `invalid <Language> integer literal`.
    fn normalizeNumber(self: *Parser, tok: Token) Token {
        if (tok.kind != .number) return tok;
        var t = tok;
        const lit = int_literal.parse(self.allocator, "rb", tok.raw) orelse {
            const msg = int_literal.invalidIntegerLiteral(self.allocator, "rb", tok.raw);
            const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, tok.line, lex_diag.diagCol(tok.col), msg }) catch msg;
            self.errors.append(self.allocator, f) catch {};
            t.text = "0";
            return t;
        };
        t.text = if (lit.small) |v| (std.fmt.allocPrint(self.allocator, "{d}", .{v}) catch "0") else lit.big.?;
        t.neg_only = lit.neg_only;
        return t;
    }

    /// F-026: the AST value of a (normalized) number token.
    fn numberLiteral(self: *Parser, tok: Token) ?Expression {
        _ = self;
        if (std.fmt.parseInt(i64, tok.text, 10)) |v| return Expression{ .literal_int = v } else |_| {}
        return Expression{ .literal_bigint = tok.text };
    }

};

// ============================================================================
// Tests
// ============================================================================

test "rb tokenizer basics" {
    const allocator = std.testing.allocator;
    var tokenizer = Tokenizer.init(allocator, "class P2PKH < Runar::SmartContract");
    defer tokenizer.tokens.deinit(allocator);
    const tokens = tokenizer.tokenize();
    // class P2PKH < Runar :: SmartContract NEWLINE EOF
    try std.testing.expectEqual(TokenKind.kw_class, tokens[0].kind);
    try std.testing.expectEqualStrings("P2PKH", tokens[1].text);
    try std.testing.expectEqual(TokenKind.ident, tokens[1].kind);
    try std.testing.expectEqual(TokenKind.lt, tokens[2].kind);
    try std.testing.expectEqualStrings("Runar", tokens[3].text);
    try std.testing.expectEqual(TokenKind.colon_colon, tokens[4].kind);
    try std.testing.expectEqualStrings("SmartContract", tokens[5].text);
}

test "rb tokenizer symbols and ivars" {
    const allocator = std.testing.allocator;
    var tokenizer = Tokenizer.init(allocator, "prop :pub_key_hash, Addr\n@count += 1");
    defer tokenizer.tokens.deinit(allocator);
    const tokens = tokenizer.tokenize();
    // prop :pub_key_hash , Addr NEWLINE @count += 1 NEWLINE EOF
    try std.testing.expectEqual(TokenKind.ident, tokens[0].kind); // prop
    try std.testing.expectEqualStrings("prop", tokens[0].text);
    try std.testing.expectEqual(TokenKind.symbol, tokens[1].kind);
    try std.testing.expectEqualStrings("pub_key_hash", tokens[1].text);
    try std.testing.expectEqual(TokenKind.comma, tokens[2].kind);
    try std.testing.expectEqual(TokenKind.ident, tokens[3].kind); // Addr
    // NEWLINE
    try std.testing.expectEqual(TokenKind.newline, tokens[4].kind);
    try std.testing.expectEqual(TokenKind.ivar, tokens[5].kind);
    try std.testing.expectEqualStrings("count", tokens[5].text);
    try std.testing.expectEqual(TokenKind.plus_eq, tokens[6].kind);
}

test "rb tokenizer keywords" {
    const allocator = std.testing.allocator;
    var tokenizer = Tokenizer.init(allocator, "if true and false or not end elsif else unless for in def return do super require assert self nil");
    defer tokenizer.tokens.deinit(allocator);
    const tokens = tokenizer.tokenize();
    const expected_kinds = [_]TokenKind{
        .kw_if, .kw_true, .kw_and, .kw_false, .kw_or, .kw_not, .kw_end,
        .kw_elsif, .kw_else, .kw_unless, .kw_for, .kw_in, .kw_def, .kw_return,
        .kw_do, .kw_super, .kw_require, .kw_assert, .kw_self, .kw_nil,
    };
    for (expected_kinds, 0..) |ek, i| {
        try std.testing.expectEqual(ek, tokens[i].kind);
    }
}

test "rb tokenizer range operators" {
    const allocator = std.testing.allocator;
    var tokenizer = Tokenizer.init(allocator, "0...10 0..10");
    defer tokenizer.tokens.deinit(allocator);
    const tokens = tokenizer.tokenize();
    try std.testing.expectEqual(TokenKind.number, tokens[0].kind);
    try std.testing.expectEqual(TokenKind.dot_dot_dot, tokens[1].kind);
    try std.testing.expectEqual(TokenKind.number, tokens[2].kind);
    try std.testing.expectEqual(TokenKind.number, tokens[3].kind);
    try std.testing.expectEqual(TokenKind.dot_dot, tokens[4].kind);
    try std.testing.expectEqual(TokenKind.number, tokens[5].kind);
}

test "rb snake_case to camelCase" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectEqualStrings("checkSig", rbConvertName(allocator, "check_sig"));
    try std.testing.expectEqualStrings("pubKeyHash", rbConvertName(allocator, "pub_key_hash"));
    try std.testing.expectEqualStrings("hash160", rbConvertName(allocator, "hash160"));
    try std.testing.expectEqualStrings("addOutput", rbConvertName(allocator, "add_output"));
    try std.testing.expectEqualStrings("ecAdd", rbConvertName(allocator, "ec_add"));
    try std.testing.expectEqualStrings("extractLocktime", rbConvertName(allocator, "extract_locktime"));
    try std.testing.expectEqualStrings("hello", rbConvertName(allocator, "hello"));
}

test "rb type mapping" {
    try std.testing.expectEqual(RunarType.bigint, rbMapType("Bigint"));
    try std.testing.expectEqual(RunarType.bigint, rbMapType("Integer"));
    try std.testing.expectEqual(RunarType.bigint, rbMapType("Int"));
    try std.testing.expectEqual(RunarType.boolean, rbMapType("Boolean"));
    // F-206: 'Bool' must alias to boolean exactly like 'Boolean' does. The
    // native Ruby tier's own reference parser (parser_ruby.rb) already maps
    // both spellings; this tier's rbMapType only had 'Boolean'.
    try std.testing.expectEqual(RunarType.boolean, rbMapType("Bool"));
    try std.testing.expectEqual(RunarType.byte_string, rbMapType("ByteString"));
    try std.testing.expectEqual(RunarType.pub_key, rbMapType("PubKey"));
    try std.testing.expectEqual(RunarType.sig, rbMapType("Sig"));
    try std.testing.expectEqual(RunarType.addr, rbMapType("Addr"));
    try std.testing.expectEqual(RunarType.point, rbMapType("Point"));
    try std.testing.expectEqual(RunarType.unknown, rbMapType("UnknownType"));
}

// F-206: rbMapTypeName (used for ParamNode.type_name, a separate map from
// rbMapType) must also accept 'Bool'.
test "rb type name mapping accepts Bool alias" {
    try std.testing.expectEqualStrings("boolean", rbMapTypeName("Bool"));
    try std.testing.expectEqualStrings("boolean", rbMapTypeName("Boolean"));
}

test "rb parse basic P2PKH" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\require 'runar'
        \\
        \\class P2PKH < Runar::SmartContract
        \\  prop :pub_key_hash, Addr
        \\
        \\  def initialize(pub_key_hash)
        \\    super(pub_key_hash)
        \\    @pub_key_hash = pub_key_hash
        \\  end
        \\
        \\  runar_public sig: Sig, pub_key: PubKey
        \\  def unlock(sig, pub_key)
        \\    assert hash160(pub_key) == @pub_key_hash
        \\    assert check_sig(sig, pub_key)
        \\  end
        \\end
    ;
    const result = parseRuby(allocator, source, "P2PKH.runar.rb");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);

    const c = result.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("pubKeyHash", c.properties[0].name);
    try std.testing.expectEqual(RunarType.addr, c.properties[0].type_info);
    try std.testing.expect(c.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqualStrings("unlock", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].params.len);
}

test "rb parse stateful counter" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\require 'runar'
        \\
        \\class Counter < Runar::StatefulSmartContract
        \\  prop :count, Bigint
        \\
        \\  def initialize(count)
        \\    super(count)
        \\    @count = count
        \\  end
        \\
        \\  runar_public
        \\  def increment
        \\    @count += 1
        \\  end
        \\
        \\  runar_public
        \\  def decrement
        \\    assert @count > 0
        \\    @count -= 1
        \\  end
        \\end
    ;
    const result = parseRuby(allocator, source, "Counter.runar.rb");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);

    const c = result.contract.?;
    try std.testing.expectEqualStrings("Counter", c.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("count", c.properties[0].name);
    try std.testing.expect(!c.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expectEqualStrings("decrement", c.methods[1].name);
    try std.testing.expect(c.methods[1].is_public);
}

test "rb parse auction" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\require 'runar'
        \\
        \\class Auction < Runar::StatefulSmartContract
        \\  prop :auctioneer, PubKey, readonly: true
        \\  prop :highest_bidder, PubKey
        \\  prop :highest_bid, Bigint
        \\  prop :deadline, Bigint, readonly: true
        \\
        \\  def initialize(auctioneer, highest_bidder, highest_bid, deadline)
        \\    super(auctioneer, highest_bidder, highest_bid, deadline)
        \\    @auctioneer = auctioneer
        \\    @highest_bidder = highest_bidder
        \\    @highest_bid = highest_bid
        \\    @deadline = deadline
        \\  end
        \\
        \\  runar_public sig: Sig, bidder: PubKey, bid_amount: Bigint
        \\  def bid(sig, bidder, bid_amount)
        \\    assert check_sig(sig, bidder)
        \\    assert bid_amount > @highest_bid
        \\    assert extract_locktime(@tx_preimage) < @deadline
        \\    @highest_bidder = bidder
        \\    @highest_bid = bid_amount
        \\  end
        \\
        \\  runar_public sig: Sig
        \\  def close(sig)
        \\    assert check_sig(sig, @auctioneer)
        \\    assert extract_locktime(@tx_preimage) >= @deadline
        \\  end
        \\end
    ;
    const result = parseRuby(allocator, source, "Auction.runar.rb");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);

    const c = result.contract.?;
    try std.testing.expectEqualStrings("Auction", c.name);
    try std.testing.expectEqual(@as(usize, 4), c.properties.len);
    try std.testing.expect(c.properties[0].readonly); // auctioneer
    try std.testing.expect(!c.properties[1].readonly); // highest_bidder
    try std.testing.expect(!c.properties[2].readonly); // highest_bid
    try std.testing.expect(c.properties[3].readonly); // deadline
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqualStrings("bid", c.methods[0].name);
    try std.testing.expectEqualStrings("close", c.methods[1].name);
}

test "rb parse auto-generated constructor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\require 'runar'
        \\
        \\class Simple < Runar::SmartContract
        \\  prop :value, Bigint
        \\
        \\  runar_public
        \\  def check
        \\    assert @value > 0
        \\  end
        \\end
    ;
    const result = parseRuby(allocator, source, "Simple.runar.rb");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);

    const c = result.contract.?;
    // Constructor should be auto-generated
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqualStrings("value", c.constructor.params[0].name);
    try std.testing.expectEqual(@as(usize, 1), c.constructor.super_args.len);
    try std.testing.expectEqual(@as(usize, 1), c.constructor.assignments.len);
}

test "rb parse unless statement" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\require 'runar'
        \\
        \\class Guard < Runar::SmartContract
        \\  prop :limit, Bigint
        \\
        \\  runar_public amount: Bigint
        \\  def check(amount)
        \\    unless amount > @limit
        \\      assert false
        \\    end
        \\  end
        \\end
    ;
    const result = parseRuby(allocator, source, "Guard.runar.rb");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);

    const c = result.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    // Unless should produce an if with negated condition
    try std.testing.expect(c.methods[0].body.len > 0);
    switch (c.methods[0].body[0]) {
        .if_stmt => |ifs| {
            // Condition should be a unary NOT
            switch (ifs.condition) {
                .unary_op => |uop| try std.testing.expectEqual(UnaryOperator.not, uop.op),
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }
}

test "rb parse for loop" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\require 'runar'
        \\
        \\class Loop < Runar::SmartContract
        \\  prop :total, Bigint
        \\
        \\  runar_public n: Bigint
        \\  def sum(n)
        \\    for i in 0...10
        \\      assert i >= 0
        \\    end
        \\  end
        \\end
    ;
    const result = parseRuby(allocator, source, "Loop.runar.rb");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);

    const c = result.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    switch (c.methods[0].body[0]) {
        .for_stmt => |fs| {
            try std.testing.expectEqualStrings("i", fs.var_name);
            try std.testing.expectEqual(@as(i64, 0), fs.init_value);
            try std.testing.expectEqual(@as(i64, 10), fs.bound);
        },
        else => return error.TestExpectedEqual,
    }
}

test "rb parse property with default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\require 'runar'
        \\
        \\class Init < Runar::StatefulSmartContract
        \\  prop :counter, Bigint, default: 0
        \\
        \\  runar_public
        \\  def increment
        \\    @counter += 1
        \\  end
        \\end
    ;
    const result = parseRuby(allocator, source, "Init.runar.rb");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);

    const c = result.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expect(c.properties[0].initializer != null);
    switch (c.properties[0].initializer.?) {
        .literal_int => |v| try std.testing.expectEqual(@as(i64, 0), v),
        else => return error.TestExpectedEqual,
    }
    // Constructor params should not include properties with defaults
    try std.testing.expectEqual(@as(usize, 0), c.constructor.params.len);
}

/// N-138: the compile-time integer value of a loop-start expression, or null.
///
/// Accepts a literal and a NEGATED literal. The negated form is the gap this
/// helper exists for: every surface parser in this tier recognised a bare
/// `.number` (or a folded `.literal_int`) and let `-1` fall through to the
/// discard path, so a loop written with a negative start unrolled from 0 — a
/// different program from the one the source describes, and byte-divergent
/// from the other six tiers with no size difference to notice it by.
fn loopStartLiteral(expr: types.Expression) ?i64 {
    return switch (expr) {
        .literal_int => |v| v,
        .unary_op => |u| switch (u.op) {
            .negate => switch (u.operand) {
                .literal_int => |v| -v,
                else => null,
            },
            else => null,
        },
        else => null,
    };
}
