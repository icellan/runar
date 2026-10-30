//! Pass 1 (Move frontend): Hand-written tokenizer + recursive descent parser for .runar.move files.
//!
//! Parses Move-style module syntax into the Runar IR ContractNode.
//!
//! Syntax conventions:
//!   - `module Name { ... }` wraps the contract
//!   - `use runar::smart_contract::SmartContract;` import (skipped)
//!   - `resource struct Name { field: Type, ... }` for stateful, `struct Name { ... }` for stateless
//!   - Properties: `field_name: Type` (snake_case, converted to camelCase in AST)
//!   - Type mappings: `u64`/`u128`/`u256`/`Int` → bigint, `bool`/`Bool` → boolean, `vector<u8>` → ByteString
//!   - Constructor: auto-generated from struct fields (init function mapped to constructor)
//!   - Methods: `public fun name(contract: &Name, ...) { ... }` or `fun name(...)` for private
//!   - First param `contract: &ContractName` or `contract: &mut ContractName` is `self` — stripped
//!   - Property access: `contract.field` maps to `this.field`
//!   - `assert!(cond, code)` maps to `assert(cond)`
//!   - `assert_eq!(a, b, code)` maps to `assert(a === b)`
//!   - `==` maps to `===`, `!=` maps to `!==`
//!   - `let` / `let mut` for variable declarations
//!   - `if (cond) { ... } else { ... }` — conditions
//!   - snake_case to camelCase conversion for identifiers

const std = @import("std");
const lex_diag = @import("lex_diag.zig");
const int_literal = @import("int_literal.zig");
const types = @import("../ir/types.zig");
const loop_condition = @import("loop_condition.zig");
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

pub fn parseMove(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
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
    // F-011: tokenize the whole source once more so an unterminated literal
    // is reported even where the parser stopped before reaching it.
    var t = Tokenizer.init(source);
    var guard: usize = 0;
    while (guard <= source.len) : (guard += 1) {
        if (t.next().kind == .eof) break;
    }
    // N-019: a terminated quoted literal is refused as an unexpected character
    // (as the TS reference); the earlier of the two diagnostics comes first.
    const quoted_msg: []const u8 = if (t.quoted_char == '"') "Unexpected character '\"'" else "Unexpected character '''";
    const quoted_first = if (t.quoted) |q| (if (t.unterminated) |u| (q.line < u.line or (q.line == u.line and q.col < u.col)) else true) else false;
    const errs = if (quoted_first) blk: {
        const e1 = lex_diag.prepend(allocator, r.errors, file_name, lex_diag.UNTERMINATED_STRING_LITERAL, t.unterminated);
        break :blk lex_diag.prepend(allocator, e1, file_name, quoted_msg, t.quoted);
    } else blk: {
        const e1 = lex_diag.prepend(allocator, r.errors, file_name, quoted_msg, t.quoted);
        break :blk lex_diag.prepend(allocator, e1, file_name, lex_diag.UNTERMINATED_STRING_LITERAL, t.unterminated);
    };
    return .{ .contract = r.contract, .errors = lex_diag.prependUnexpected(allocator, errs, file_name, t.unexpected) };
}


// ============================================================================
// Token Types
// ============================================================================

/// N-093: one parsed `#[...]` attribute (see `Parser.parseAttributes`).
const MoveAttribute = struct {
    kind: enum { embed_always, sighash },
    flags: ?[]const u8,
    loc: types.SourceLocation,
};

const TokenKind = enum {
    eof,
    ident,
    number,
    string_literal,
    lparen,
    rparen,
    lbrace,
    rbrace,
    lbracket,
    rbracket,
    semicolon,
    comma,
    dot,
    colon,
    colon_colon,
    question,
    assign,
    eqeq,
    bang_eq,
    lt,
    lt_eq,
    gt,
    gt_eq,
    plus,
    minus,
    star,
    slash,
    percent,
    bang,
    tilde,
    ampersand,
    pipe,
    caret,
    amp_amp,
    pipe_pipe,
    lshift,
    rshift,
    plus_eq,
    minus_eq,
    star_eq,
    slash_eq,
    percent_eq,
    plus_plus,
    minus_minus,
    arrow,
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

const Tokenizer = struct {
    source: []const u8,
    /// F-011: the first unterminated quoted literal, if any.
    unterminated: ?lex_diag.Pos = null,
    /// N-214: the first unrecognised character, if any.
    unexpected: ?lex_diag.Unexpected = null,
    /// N-019: the first TERMINATED quoted literal (this surface has none) and
    /// the quote character that opened it.
    quoted: ?lex_diag.Pos = null,
    quoted_char: u8 = '"',
    pos: usize,
    line: u32,
    col: u32,

    fn init(source: []const u8) Tokenizer {
        return .{ .source = source, .pos = 0, .line = 1, .col = 1 };
    }

    fn peek(self: *const Tokenizer) u8 {
        if (self.pos >= self.source.len) return 0;
        return self.source[self.pos];
    }

    fn peekAt(self: *const Tokenizer, offset: usize) u8 {
        const i = self.pos + offset;
        if (i >= self.source.len) return 0;
        return self.source[i];
    }

    fn advance(self: *Tokenizer) u8 {
        if (self.pos >= self.source.len) return 0;
        const c = self.source[self.pos];
        self.pos += 1;
        if (c == '\n') {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        return c;
    }

    fn skipWhitespaceAndComments(self: *Tokenizer) void {
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                _ = self.advance();
            } else if (c == '/' and self.peekAt(1) == '/') {
                // Single-line comment
                while (self.pos < self.source.len and self.source[self.pos] != '\n') _ = self.advance();
            } else if (c == '/' and self.peekAt(1) == '*') {
                // Multi-line comment
                _ = self.advance();
                _ = self.advance();
                while (self.pos < self.source.len) {
                    if (self.source[self.pos] == '*' and self.peekAt(1) == '/') {
                        _ = self.advance();
                        _ = self.advance();
                        break;
                    }
                    _ = self.advance();
                }
            } else break;
        }
    }

    /// N-214: record the first character this surface does not recognise
    /// (its whole UTF-8 sequence, one column; `advance` took its first byte)
    /// and hand it on as a one-character token.
    fn unexpectedChar(self: *Tokenizer, start: usize, sl: u32, sc: u32) Token {
        self.pos = start + lex_diag.charLen(self.source, start);
        const text = self.source[start..self.pos];
        if (self.unexpected == null) self.unexpected = .{ .at = .{ .line = sl, .col = sc }, .text = text };
        return .{ .kind = .ident, .text = text, .line = sl, .col = sc };
    }

    fn next(self: *Tokenizer) Token {
        self.skipWhitespaceAndComments();
        if (self.pos >= self.source.len) return .{ .kind = .eof, .text = "", .line = self.line, .col = self.col };

        const sl = self.line;
        const sc = self.col;
        const start = self.pos;
        const c = self.source[self.pos];

        // String literals: single quotes, double quotes
        if (c == '"' or c == '\'') {
            const quote = c;
            _ = self.advance();
            // F-011: a literal that reaches a line break (escaped or not) or
            // end of file is unterminated; it must never run on into the
            // following lines.
            while (self.pos < self.source.len and self.source[self.pos] != quote and self.source[self.pos] != '\n' and self.source[self.pos] != '\r') {
                if (self.source[self.pos] == '\\') {
                    const nx = self.peekAt(1);
                    if (self.pos + 1 >= self.source.len or nx == '\n' or nx == '\r') break;
                    _ = self.advance();
                }
                _ = self.advance();
            }
            const content_end = self.pos;
            if (self.pos < self.source.len and self.source[self.pos] == quote) {
                _ = self.advance();
                if (self.quoted == null) {
                    self.quoted = .{ .line = sl, .col = sc };
                    self.quoted_char = quote;
                }
            } else if (self.unterminated == null) {
                self.unterminated = .{ .line = sl, .col = sc };
            }
            return .{ .kind = .string_literal, .text = self.source[start + 1 .. content_end], .line = sl, .col = sc };
        }

        // Numbers (decimal, hex; strip trailing type suffixes like u64, u128, u256)
        if (c >= '0' and c <= '9') {
            if (c == '0' and self.peekAt(1) == 'x') {
                // A lowercase `0x` spells a ByteString on this surface (F-026:
                // `0X` is not, and is refused as an integer literal).
                _ = self.advance(); // '0'
                _ = self.advance(); // 'x'
                while (self.pos < self.source.len and isHexDigit(self.source[self.pos])) _ = self.advance();
                return .{ .kind = .number, .text = self.source[start..self.pos], .raw = self.source[start..self.pos], .line = sl, .col = sc };
            }
            // F-026: the whole glued [0-9A-Za-z_] run is one integer literal.
            while (self.pos < self.source.len and int_literal.isNumberContinue(self.source[self.pos])) _ = self.advance();
            const lit_text = self.source[start..self.pos];
            return .{ .kind = .number, .text = int_literal.stripMoveSuffix(lit_text), .raw = lit_text, .line = sl, .col = sc };
        }

        // Identifiers and keywords; handle assert! and assert_eq! macros
        if (isIdentStart(c)) {
            while (self.pos < self.source.len and isIdentChar(self.source[self.pos])) _ = self.advance();
            // Check for trailing '!' (Move macro syntax: assert!, assert_eq!)
            if (self.pos < self.source.len and self.source[self.pos] == '!') {
                const id_with_bang_end = self.pos + 1;
                _ = self.advance(); // consume '!'
                return .{ .kind = .ident, .text = self.source[start..id_with_bang_end], .line = sl, .col = sc };
            }
            const text = self.source[start..self.pos];
            return .{ .kind = .ident, .text = text, .line = sl, .col = sc };
        }

        // Operators: advance one char, then check for multi-char operators
        _ = self.advance();
        const c2 = self.peek();

        // Two-character operators (check before single-char)
        const t = self.source[start..self.pos];
        return switch (c) {
            '(' => .{ .kind = .lparen, .text = t, .line = sl, .col = sc },
            ')' => .{ .kind = .rparen, .text = t, .line = sl, .col = sc },
            '{' => .{ .kind = .lbrace, .text = t, .line = sl, .col = sc },
            '}' => .{ .kind = .rbrace, .text = t, .line = sl, .col = sc },
            '[' => .{ .kind = .lbracket, .text = t, .line = sl, .col = sc },
            ']' => .{ .kind = .rbracket, .text = t, .line = sl, .col = sc },
            ';' => .{ .kind = .semicolon, .text = t, .line = sl, .col = sc },
            ',' => .{ .kind = .comma, .text = t, .line = sl, .col = sc },
            '.' => .{ .kind = .dot, .text = t, .line = sl, .col = sc },
            '?' => .{ .kind = .question, .text = t, .line = sl, .col = sc },
            '~' => .{ .kind = .tilde, .text = t, .line = sl, .col = sc },
            '^' => .{ .kind = .caret, .text = t, .line = sl, .col = sc },
            ':' => if (c2 == ':') blk: {
                _ = self.advance();
                break :blk .{ .kind = .colon_colon, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .colon, .text = t, .line = sl, .col = sc },
            '=' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .eqeq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .assign, .text = t, .line = sl, .col = sc },
            '!' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .bang_eq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .bang, .text = t, .line = sl, .col = sc },
            '<' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .lt_eq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else if (c2 == '<') blk2: {
                _ = self.advance();
                break :blk2 .{ .kind = .lshift, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .lt, .text = t, .line = sl, .col = sc },
            '>' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .gt_eq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else if (c2 == '>') blk2: {
                _ = self.advance();
                break :blk2 .{ .kind = .rshift, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .gt, .text = t, .line = sl, .col = sc },
            '+' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .plus_eq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else if (c2 == '+') blk2: {
                _ = self.advance();
                break :blk2 .{ .kind = .plus_plus, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .plus, .text = t, .line = sl, .col = sc },
            '-' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .minus_eq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else if (c2 == '-') blk2: {
                _ = self.advance();
                break :blk2 .{ .kind = .minus_minus, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else if (c2 == '>') blk3: {
                _ = self.advance();
                break :blk3 .{ .kind = .arrow, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .minus, .text = t, .line = sl, .col = sc },
            '*' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .star_eq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .star, .text = t, .line = sl, .col = sc },
            '/' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .slash_eq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .slash, .text = t, .line = sl, .col = sc },
            '%' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .percent_eq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .percent, .text = t, .line = sl, .col = sc },
            '&' => if (c2 == '&') blk: {
                _ = self.advance();
                break :blk .{ .kind = .amp_amp, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .ampersand, .text = t, .line = sl, .col = sc },
            '|' => if (c2 == '|') blk: {
                _ = self.advance();
                break :blk .{ .kind = .pipe_pipe, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .pipe, .text = t, .line = sl, .col = sc },
            // N-093: `#[` opens an attribute, which the parser reads from this
            // `#` token; a `#` not followed by `[` is refused like any other.
            '#' => if (c2 == '[') .{ .kind = .ident, .text = t, .line = sl, .col = sc } else self.unexpectedChar(start, sl, sc),
            else => self.unexpectedChar(start, sl, sc),
        };
    }

    fn isIdentStart(c: u8) bool {
        return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
    }

    fn isIdentChar(c: u8) bool {
        return isIdentStart(c) or (c >= '0' and c <= '9');
    }

    fn isHexDigit(c: u8) bool {
        return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
    }
};

// ============================================================================
// snake_case → camelCase conversion
// ============================================================================

/// Convert a snake_case identifier to camelCase.
/// E.g., "pub_key_hash" → "pubKeyHash", "check_sig" → "checkSig", "hash_160" → "hash160"
fn snakeToCamel(allocator: Allocator, s: []const u8) []const u8 {
    // Fast path: no underscores means no conversion needed
    var has_underscore = false;
    for (s) |c| {
        if (c == '_') {
            has_underscore = true;
            break;
        }
    }
    if (!has_underscore) return s;

    // First pass: compute output length
    var out_len: usize = 0;
    for (s) |c| {
        if (c != '_') out_len += 1;
    }

    var buf = allocator.alloc(u8, out_len) catch return s;
    var out: usize = 0;
    var capitalize_next = false;
    for (s) |c| {
        if (c == '_') {
            capitalize_next = true;
        } else {
            if (capitalize_next and c >= 'a' and c <= 'z') {
                buf[out] = c - 32; // toUpper
                out += 1;
            } else {
                buf[out] = c;
                out += 1;
            }
            capitalize_next = false;
        }
    }
    return buf[0..out];
}

/// Map Move-style builtins from snake_case to Runar camelCase.
/// Some names have non-standard mappings (e.g., hash_160 → hash160).
fn mapBuiltin(allocator: Allocator, name: []const u8) []const u8 {
    const map = std.StaticStringMap([]const u8).initComptime(.{
        .{ "check_sig", "checkSig" },
        .{ "check_multi_sig", "checkMultiSig" },
        .{ "check_preimage", "checkPreimage" },
        .{ "hash_160", "hash160" },
        .{ "hash_256", "hash256" },
        .{ "sha_256", "sha256" },
        .{ "ripemd_160", "ripemd160" },
        .{ "num_2_bin", "num2bin" },
        .{ "bin_2_num", "bin2num" },
        .{ "reverse_bytes", "reverseBytes" },
        .{ "extract_locktime", "extractLocktime" },
        .{ "hash160", "hash160" },
        .{ "hash256", "hash256" },
        .{ "sha256", "sha256" },
        .{ "ripemd160", "ripemd160" },
        .{ "num2bin", "num2bin" },
        .{ "bin2num", "bin2num" },
        .{ "abs", "abs" },
        .{ "min", "min" },
        .{ "max", "max" },
        .{ "within", "within" },
        .{ "len", "len" },
        .{ "pack", "pack" },
        .{ "unpack", "unpack" },
        .{ "assert", "assert" },
        .{ "safediv", "safediv" },
        .{ "safemod", "safemod" },
        .{ "clamp", "clamp" },
        .{ "sign", "sign" },
        .{ "pow", "pow" },
        .{ "sqrt", "sqrt" },
        .{ "gcd", "gcd" },
        .{ "divmod", "divmod" },
        .{ "log2", "log2" },
        .{ "percent_of", "percentOf" },
        .{ "mul_div", "mulDiv" },
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
        .{ "verify_ecdsa_p256", "verifyECDSA_P256" },
        .{ "p256_add", "p256Add" },
        .{ "p256_mul", "p256Mul" },
        .{ "p256_mul_gen", "p256MulGen" },
        .{ "p256_negate", "p256Negate" },
        .{ "p256_on_curve", "p256OnCurve" },
        .{ "p256_encode_compressed", "p256EncodeCompressed" },
        .{ "verify_ecdsa_p384", "verifyECDSA_P384" },
        .{ "p384_add", "p384Add" },
        .{ "p384_mul", "p384Mul" },
        .{ "p384_mul_gen", "p384MulGen" },
        .{ "p384_negate", "p384Negate" },
        .{ "p384_on_curve", "p384OnCurve" },
        .{ "p384_encode_compressed", "p384EncodeCompressed" },
        .{ "sha256_compress", "sha256Compress" },
        .{ "sha256_finalize", "sha256Finalize" },
        .{ "verify_wots", "verifyWOTS" },
        .{ "verify_rabin_sig", "verifyRabinSig" },
        .{ "verify_slh_dsa_sha2_128s", "verifySLHDSA_SHA2_128s" },
        .{ "verify_slh_dsa_sha2_128f", "verifySLHDSA_SHA2_128f" },
        .{ "verify_slh_dsa_sha2_192s", "verifySLHDSA_SHA2_192s" },
        .{ "verify_slh_dsa_sha2_192f", "verifySLHDSA_SHA2_192f" },
        .{ "verify_slh_dsa_sha2_256s", "verifySLHDSA_SHA2_256s" },
        .{ "verify_slh_dsa_sha2_256f", "verifySLHDSA_SHA2_256f" },
        .{ "verifySlhdsaSha2128s", "verifySLHDSA_SHA2_128s" },
        .{ "verifySlhdsaSha2128f", "verifySLHDSA_SHA2_128f" },
        .{ "verifySlhdsaSha2192s", "verifySLHDSA_SHA2_192s" },
        .{ "verifySlhdsaSha2192f", "verifySLHDSA_SHA2_192f" },
        .{ "verifySlhdsaSha2256s", "verifySLHDSA_SHA2_256s" },
        .{ "verifySlhdsaSha2256f", "verifySLHDSA_SHA2_256f" },
        .{ "blake3_compress", "blake3Compress" },
        .{ "blake3_hash", "blake3Hash" },
        .{ "cat", "cat" },
        .{ "substr", "substr" },
        .{ "left", "left" },
        .{ "right", "right" },
        .{ "split", "split" },
        .{ "int2str", "int2str" },
        .{ "to_byte_string", "toByteString" },
        .{ "build_change_output", "buildChangeOutput" },
        .{ "extract_version", "extractVersion" },
        .{ "extract_hash_prevouts", "extractHashPrevouts" },
        .{ "extract_hash_sequence", "extractHashSequence" },
        .{ "extract_outpoint", "extractOutpoint" },
        .{ "extract_input_index", "extractInputIndex" },
        .{ "extract_script_code", "extractScriptCode" },
        .{ "extract_amount", "extractAmount" },
        .{ "extract_sequence", "extractSequence" },
        .{ "extract_output_hash", "extractOutputHash" },
        .{ "extract_outputs", "extractOutputs" },
        .{ "extract_sig_hash_type", "extractSigHashType" },
        .{ "exit", "exit" },
        .{ "int2str", "int2str" },
        .{ "bool", "bool" },
        // Pre-camelCased forms also accepted (matches the canonical TS Move
        // parser, whose regex preserves the literal `_<uppercase>` boundary).
        .{ "verifyECDSA_P256", "verifyECDSA_P256" },
        .{ "verifyECDSA_P384", "verifyECDSA_P384" },
    });
    if (map.get(name)) |mapped| return mapped;
    return snakeToCamel(allocator, name);
}

/// Map Move-style type names to Runar types.
fn mapMoveType(name: []const u8) RunarType {
    const map = std.StaticStringMap(RunarType).initComptime(.{
        .{ "u64", .bigint },
        .{ "u128", .bigint },
        .{ "u256", .bigint },
        .{ "Int", .bigint },
        .{ "Bigint", .bigint },
        .{ "bigint", .bigint },
        .{ "bool", .boolean },
        .{ "Bool", .boolean },
        .{ "boolean", .boolean },
        .{ "vector", .byte_string },
        .{ "Bytes", .byte_string },
        .{ "ByteString", .byte_string },
        .{ "PubKey", .pub_key },
        .{ "Sig", .sig },
        .{ "address", .addr },
        .{ "Addr", .addr },
        .{ "Sha256", .sha256 },
        // N-108: no `Sha256Digest` arm. The alias is not part of the Move-style
        // surface vocabulary in the reference tier (`01-parse-move.ts` does not
        // apply `TYPE_ALIASES`), and six tiers refuse the name here. Zig was the
        // lone acceptor. Gate: conformance/negatives/N25-sha256digest-alias-move.
        .{ "Ripemd160", .ripemd160 },
        .{ "SigHashPreimage", .sig_hash_preimage },
        .{ "RabinSig", .rabin_sig },
        .{ "RabinPubKey", .rabin_pub_key },
        .{ "Point", .point },
        .{ "P256Point", .p256_point },
        .{ "P384Point", .p384_point },
        .{ "void", .void },
    });
    if (map.get(name)) |rt| return rt;
    // Try camelCase conversion for snake_case type names
    return .unknown;
}

/// Inverse of `typeNodeToRunarType` for the primitive subset. Lifts a
/// primitive `RunarType` back into a `TypeNode` so the FixedArray inner
/// element can carry a real recursive `TypeNode`.
fn runarTypeToTypeNodeMove(rt: RunarType) TypeNode {
    return switch (rt) {
        .bigint => .{ .primitive_type = .bigint },
        .boolean => .{ .primitive_type = .boolean },
        .byte_string => .{ .primitive_type = .byte_string },
        .pub_key => .{ .primitive_type = .pub_key },
        .sig => .{ .primitive_type = .sig },
        .sha256 => .{ .primitive_type = .sha256 },
        .ripemd160 => .{ .primitive_type = .ripemd160 },
        .addr => .{ .primitive_type = .addr },
        .sig_hash_preimage => .{ .primitive_type = .sig_hash_preimage },
        .rabin_sig => .{ .primitive_type = .rabin_sig },
        .rabin_pub_key => .{ .primitive_type = .rabin_pub_key },
        .point => .{ .primitive_type = .point },
        .p256_point => .{ .primitive_type = .p256_point },
        .p384_point => .{ .primitive_type = .p384_point },
        .void => .{ .primitive_type = .void },
        else => .{ .custom_type = "unknown" },
    };
}

fn runarTypeToTypeName(t: RunarType) []const u8 {
    return types.runarTypeToString(t);
}

// ============================================================================
// Parser
// ============================================================================

const Parser = struct {
    allocator: Allocator,
    tokenizer: Tokenizer,
    current: Token,
    file_name: []const u8,
    errors: std.ArrayListUnmanaged([]const u8),
    nest: input_limits.NestingCounter = .{},
    /// N-422: the name declared by the statement immediately before the one
    /// `parseMoveBlock` is about to parse, i.e. the only name a `while` there
    /// can be iterating over. Lets `parseMoveWhile` mirror `n > i` as the
    /// reference does.
    move_prev_decl: ?[]const u8 = null,
    nest_error: ?[]const u8 = null,
    /// F-017: declared (spelling, Rúnar name) pairs.
    idents: identifier_collision.DeclaredIdents = .{},

    /// Convert a DECLARED identifier and record it for the F-017 collision
    /// rule (see identifier_collision.zig).
    fn declare(self: *Parser, raw: []const u8) []const u8 {
        return self.idents.declare(self.allocator, raw, snakeToCamel(self.allocator, raw));
    }

    fn init(allocator: Allocator, source: []const u8, file_name: []const u8) Parser {
        var tokenizer = Tokenizer.init(source);
        const first = tokenizer.next();
        var p: Parser = .{ .allocator = allocator, .tokenizer = tokenizer, .current = first, .file_name = file_name, .errors = .empty };
        p.current = p.normalizeNumber(p.current);
        return p;
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
        if (self.nest_error == null) self.nest_error = input_limits.nestingErrorAt(self.allocator, self.file_name, self.current.line, self.current.col);
        self.tokenizer.pos = self.tokenizer.source.len;
        self.current = self.fetch();
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
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, self.current.line, lex_diag.diagCol(self.current.col), msg }) catch return;
        self.errors.append(self.allocator, f) catch {};
    }

    fn addErrorAtLoc(self: *Parser, loc: types.SourceLocation, msg: []const u8) void {
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, loc.line, lex_diag.diagCol(loc.column), msg }) catch return;
        self.errors.append(self.allocator, f) catch {};
    }

    /// N-093: `#[` opens an attribute. The tokenizer yields an unknown `#` as
    /// a one-byte ident; it starts an attribute only when `[` follows it
    /// directly (a lone `#` stays the unexpected token it was).
    fn atAttributeStart(self: *const Parser) bool {
        if (self.current.kind != .ident or !std.mem.eql(u8, self.current.text, "#")) return false;
        const t = &self.tokenizer;
        return t.pos < t.source.len and t.source[t.pos] == '[';
    }

    /// N-093: parse `#[...]` attributes. Only `#[embed_always]` and
    /// `#[sighash(FLAGS)]` exist; any other attribute is refused (it would
    /// otherwise be ignored). For `sighash`, `flags` is the `|`-joined
    /// identifier list, or null when the parentheses hold anything else or
    /// are missing.
    fn parseAttributes(self: *Parser) []MoveAttribute {
        var attrs: std.ArrayListUnmanaged(MoveAttribute) = .empty;
        while (self.atAttributeStart()) {
            const loc = self.currentSourceLoc();
            _ = self.bump(); // '#'
            _ = self.expect(.lbracket);
            const name: []const u8 = if (self.current.kind == .ident) self.bump().text else "";
            var flags: ?[]const u8 = null;
            var has_args = false;
            if (self.current.kind == .lparen) {
                has_args = true;
                _ = self.bump();
                var text: std.ArrayListUnmanaged(u8) = .empty;
                var ok = true;
                var depth: usize = 1;
                while (self.current.kind != .eof) {
                    const t = self.current;
                    if (t.kind == .lparen) depth += 1;
                    if (t.kind == .rparen) {
                        depth -= 1;
                        if (depth == 0) break;
                    }
                    if (t.kind == .ident or t.kind == .pipe) {
                        text.appendSlice(self.allocator, t.text) catch {};
                    } else ok = false;
                    _ = self.bump();
                }
                _ = self.expect(.rparen);
                flags = if (ok) text.items else null;
            }
            while (self.current.kind != .rbracket and self.current.kind != .eof) _ = self.bump();
            _ = self.expect(.rbracket);
            if (std.mem.eql(u8, name, "embed_always") and !has_args) {
                attrs.append(self.allocator, .{ .kind = .embed_always, .flags = null, .loc = loc }) catch {};
            } else if (std.mem.eql(u8, name, "sighash")) {
                attrs.append(self.allocator, .{ .kind = .sighash, .flags = flags, .loc = loc }) catch {};
            } else {
                const shown = if (has_args) std.fmt.allocPrint(self.allocator, "{s}(...)", .{name}) catch name else name;
                self.addErrorAtLoc(loc, sighash_directive.unknownMoveAttributeMessage(self.allocator, shown));
            }
        }
        return attrs.items;
    }

    fn reportLostAttributes(self: *Parser, attrs: []const MoveAttribute) void {
        for (attrs) |attr| {
            self.addErrorAtLoc(attr.loc, switch (attr.kind) {
                .sighash => sighash_directive.LOST_SIGHASH_ERROR,
                .embed_always => sighash_directive.LOST_EMBED_ALWAYS_ERROR,
            });
        }
    }

    fn addErrorFmt(self: *Parser, comptime fmt: []const u8, args: anytype) void {
        const msg = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, self.current.line, lex_diag.diagCol(self.current.col), msg }) catch return;
        self.allocator.free(msg);
        self.errors.append(self.allocator, f) catch {};
    }

    /// Source location of the current token, in the AST's **1-based line /
    /// 1-based column** convention (the same convention `file:line:col`
    /// diagnostics use). `codegen/emit.zig#recordSourceMapping` performs the
    /// single 1-based → 0-based column conversion when it materialises
    /// SourceMapping entries, so do NOT subtract here.
    ///
    /// This tokenizer is 1-based: `Tokenizer.init` starts at `col = 1` and
    /// resets to 1 after each newline.
    fn currentSourceLoc(self: *const Parser) types.SourceLocation {
        return self.tokenSourceLoc(self.current);
    }

    fn tokenSourceLoc(self: *const Parser, tok: Token) types.SourceLocation {
        return .{ .file = self.file_name, .line = tok.line, .column = tok.col };
    }

    fn bump(self: *Parser) Token {
        const prev = self.current;
        self.current = self.fetch();
        return prev;
    }

    fn expect(self: *Parser, kind: TokenKind) ?Token {
        if (self.current.kind == kind) return self.bump();
        self.addErrorFmt("expected {s}, got '{s}'", .{ @tagName(kind), self.current.text });
        return null;
    }

    fn checkIdent(self: *const Parser, text: []const u8) bool {
        return self.current.kind == .ident and std.mem.eql(u8, self.current.text, text);
    }

    fn matchIdent(self: *Parser, text: []const u8) bool {
        if (self.checkIdent(text)) {
            _ = self.bump();
            return true;
        }
        return false;
    }

    fn match(self: *Parser, kind: TokenKind) bool {
        if (self.current.kind == kind) {
            _ = self.bump();
            return true;
        }
        return false;
    }

    fn heapExpr(self: *Parser, expr: Expression) ?*Expression {
        const ptr = self.allocator.create(Expression) catch return null;
        ptr.* = expr;
        return ptr;
    }

    // ---- Top-level ----

    fn parse(self: *Parser) ParseResult {
        const contract = self.parseModule();
        if (contract != null) {
            if (self.idents.message(self.allocator)) |m| self.errors.append(self.allocator, m) catch {};
        }
        return .{ .contract = contract, .errors = self.errors.items };
    }

    // ---- Module parsing ----

    fn parseModule(self: *Parser) ?ContractNode {
        // Skip top-level use declarations before module
        while (self.checkIdent("use")) {
            self.skipUseDecl();
        }

        // `unsafe module Name { ... }` marks an UnsafeSmartContract — the
        // asm-escape-hatch base class. Plain `module Name { ... }` infers
        // SmartContract / StatefulSmartContract structurally as before.
        const is_unsafe = self.matchIdent("unsafe");

        // module Name { ... }
        if (!self.matchIdent("module")) {
            self.addError("expected 'module' keyword");
            return null;
        }

        // Module name
        if (self.current.kind != .ident) {
            self.addError("expected module name");
            return null;
        }
        const name_tok = self.bump();
        const module_name = name_tok.text;

        if (self.expect(.lbrace) == null) return null;

        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;
        var methods: std.ArrayListUnmanaged(MethodNode) = .empty;
        var parent_class: ParentClass = if (is_unsafe) .unsafe_smart_contract else .smart_contract;
        var has_init_fn = false;

        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            // N-093: attributes before a function (`#[sighash(...)]`).
            // Anything else they precede reads neither directive, so each one
            // is refused.
            const attrs = self.parseAttributes();
            if (attrs.len > 0 and !self.checkIdent("public") and !self.checkIdent("fun")) {
                self.reportLostAttributes(attrs);
            }

            // Skip use declarations inside the module
            if (self.checkIdent("use")) {
                self.skipUseDecl();
                continue;
            }

            // resource struct or struct
            if (self.checkIdent("resource") or self.checkIdent("struct")) {
                const is_resource = self.checkIdent("resource");
                if (is_resource) {
                    _ = self.bump(); // consume "resource"
                    if (!is_unsafe) {
                        parent_class = .stateful_smart_contract;
                    }
                }
                const props = self.parseMoveStruct(parent_class);
                for (props) |p| properties.append(self.allocator, p) catch {};
                continue;
            }

            // public fun or fun
            if (self.checkIdent("public") or self.checkIdent("fun")) {
                const method = self.parseMoveFunction(attrs);
                if (method) |m| {
                    if (std.mem.eql(u8, m.name, "init")) {
                        has_init_fn = true;
                        // init function is handled as constructor; skip adding as method
                    } else {
                        methods.append(self.allocator, m) catch {};
                    }
                }
                continue;
            }

            // Skip unknown tokens
            _ = self.bump();
        }

        _ = self.expect(.rbrace);

        // Finalize property readonly flags based on parent class
        if (parent_class == .stateful_smart_contract) {
            // Properties with explicit &mut type marker are already mutable.
            // Others remain as parsed (readonly by default in struct definitions).
            _ = &properties; // intentional no-op — properties are finalized above
        }

        // Build constructor from properties (auto-generate)
        const constructor = self.buildMoveConstructor(properties.items);

        return ContractNode{
            .name = module_name,
            .parent_class = parent_class,
            .properties = properties.items,
            .constructor = constructor,
            .methods = methods.items,
        };
    }

    fn skipUseDecl(self: *Parser) void {
        // use path::to::module::{Type1, Type2};
        while (self.current.kind != .semicolon and self.current.kind != .eof) {
            _ = self.bump();
        }
        _ = self.match(.semicolon);
    }

    // ---- Struct parsing ----

    fn parseMoveStruct(self: *Parser, parent_class: ParentClass) []PropertyNode {
        if (!self.matchIdent("struct")) {
            self.addError("expected 'struct' keyword");
            return &.{};
        }

        // Skip struct name (same as module name)
        if (self.current.kind == .ident) _ = self.bump();

        // Optional: has key, store, copy, drop abilities
        if (self.checkIdent("has")) {
            _ = self.bump();
            while (self.current.kind == .ident or self.current.kind == .comma) {
                _ = self.bump();
            }
        }

        if (self.expect(.lbrace) == null) return &.{};

        var props: std.ArrayListUnmanaged(PropertyNode) = .empty;

        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            // N-093: `#[embed_always]` before a field is the native spelling
            // of `@embedAlways`; `#[sighash(...)]` here annotates nothing.
            var embed_always = false;
            for (self.parseAttributes()) |attr| {
                if (attr.kind == .embed_always) embed_always = true else self.reportLostAttributes(&.{attr});
            }

            if (self.current.kind != .ident) {
                _ = self.bump();
                continue;
            }

            const field_name_tok = self.bump();
            const raw_field_name = field_name_tok.text;
            const field_name = self.declare(raw_field_name);

            if (self.expect(.colon) == null) continue;

            // Parse type, handling &mut prefix for mutable fields
            var is_mutable = false;
            if (self.current.kind == .ampersand) {
                _ = self.bump(); // consume '&'
                if (self.matchIdent("mut")) {
                    is_mutable = true;
                }
            }

            const type_node = self.parseMoveTypeNode();
            const type_info = types.typeNodeToRunarType(type_node);

            // Capture FixedArray shape (outer + nested).
            var fa_len: u32 = 0;
            var fa_elem: RunarType = .unknown;
            var fa_nested_len: u32 = 0;
            if (type_node == .fixed_array_type) {
                fa_len = type_node.fixed_array_type.length;
                const inner = type_node.fixed_array_type.element.*;
                fa_elem = types.typeNodeToRunarType(inner);
                if (inner == .fixed_array_type) {
                    fa_nested_len = inner.fixed_array_type.length;
                }
            }

            // Determine readonly based on parent class and mutability markers
            const readonly = if (parent_class == .smart_contract or parent_class == .unsafe_smart_contract)
                true
            else if (is_mutable)
                false
            else
                true;

            // Optional initializer: = value
            var initializer: ?Expression = null;
            if (self.current.kind == .assign) {
                _ = self.bump();
                initializer = self.parseExpression();
            }

            props.append(self.allocator, .{
                .name = field_name,
                .type_info = type_info,
                .readonly = readonly,
                .initializer = initializer,
                .embed_always = embed_always,
                // N-109: spelled type name + field-name token, for the
                // validator's unsupported-type diagnostic. Diagnostics only.
                .type_name = types.typeNodeName(type_node),
                .source_loc = self.tokenSourceLoc(field_name_tok),
                .fixed_array_length = fa_len,
                .fixed_array_element = fa_elem,
                .fixed_array_nested_length = fa_nested_len,
            }) catch {};

            _ = self.match(.comma);
        }

        _ = self.expect(.rbrace);
        return props.items;
    }

    fn parseMoveTypeName(self: *Parser) RunarType {
        var discard: []const u8 = "";
        return self.parseMoveTypeNameNamed(&discard);
    }

    /// `parseMoveTypeName`, additionally reporting the type name as the author
    /// spelled it (final path component), for diagnostics (N-323).
    fn parseMoveTypeNameNamed(self: *Parser, out_name: *[]const u8) RunarType {
        // Handle & references in type position (skip them)
        if (self.current.kind == .ampersand) {
            _ = self.bump();
            if (self.matchIdent("mut")) {
                // &mut Type — skip both
            }
        }

        if (self.current.kind != .ident) {
            self.addError("expected type name");
            if (self.current.kind != .eof) _ = self.bump();
            return .unknown;
        }

        const name_tok = self.bump();
        var name = name_tok.text;

        // Handle path types: module::Type — use the final component
        while (self.current.kind == .colon_colon) {
            _ = self.bump();
            if (self.current.kind == .ident) {
                name = self.bump().text;
            }
        }

        // Handle generic types: vector<u8> etc.
        if (self.current.kind == .lt) {
            // For "vector<u8>" → ByteString
            if (std.mem.eql(u8, name, "vector")) {
                self.skipTypeArgs();
                return .byte_string;
            }
            // For FixedArray<T, N>
            if (std.mem.eql(u8, name, "FixedArray")) {
                self.skipTypeArgs();
                return .fixed_array;
            }
            self.skipTypeArgs();
        }

        out_name.* = name;
        return mapMoveType(name);
    }

    fn skipTypeArgs(self: *Parser) void {
        if (self.current.kind != .lt) return;
        _ = self.bump();
        var depth_count: i32 = 1;
        while (depth_count > 0 and self.current.kind != .eof) {
            if (self.current.kind == .lt) {
                depth_count += 1;
                _ = self.bump();
                continue;
            }
            if (self.current.kind == .gt) {
                depth_count -= 1;
                _ = self.bump();
                continue;
            }
            if (self.current.kind == .rshift) {
                // `>>` closes two nested generic argument lists at once.
                depth_count -= 2;
                if (depth_count < 0) depth_count = 0;
                _ = self.bump();
                continue;
            }
            _ = self.bump();
        }
    }

    /// Move-style type parser that returns a `TypeNode`, with full
    /// nested `FixedArray<T, N>` support. The lexer eagerly forms `>>`
    /// as a shift token; `consumeMoveGenericClose` splits it back into
    /// two `>` when closing a nested generic argument list.
    fn parseMoveTypeNode(self: *Parser) TypeNode {
        // Handle & references — discard
        if (self.current.kind == .ampersand) {
            _ = self.bump();
            _ = self.matchIdent("mut");
        }

        if (self.current.kind != .ident) {
            self.addError("expected type name");
            if (self.current.kind != .eof) _ = self.bump();
            return .{ .custom_type = "unknown" };
        }

        const name_tok = self.bump();
        var name = name_tok.text;

        // Path types: module::Type — keep final component
        while (self.current.kind == .colon_colon) {
            _ = self.bump();
            if (self.current.kind == .ident) {
                name = self.bump().text;
            }
        }

        // FixedArray<T, N> — nestable
        if (std.mem.eql(u8, name, "FixedArray") and self.current.kind == .lt) {
            _ = self.bump(); // <
            const inner = self.nestedValue(TypeNode, .{ .primitive_type = .void }, Parser.parseMoveTypeNode, .{});
            _ = self.expect(.comma);
            if (self.current.kind != .number) {
                self.addError("FixedArray length must be a non-negative integer literal");
                while (self.current.kind != .gt and self.current.kind != .rshift and self.current.kind != .eof) _ = self.bump();
                self.consumeMoveGenericClose();
                return .{ .custom_type = "FixedArray" };
            }
            const size_tok = self.bump();
            const size = std.fmt.parseInt(u32, size_tok.text, 10) catch 0;
            self.consumeMoveGenericClose();
            const elem_ptr = self.allocator.create(TypeNode) catch return .{ .custom_type = "FixedArray" };
            elem_ptr.* = inner;
            return .{ .fixed_array_type = .{ .element = elem_ptr, .length = size } };
        }

        // vector<T> → ByteString (legacy)
        if (std.mem.eql(u8, name, "vector") and self.current.kind == .lt) {
            self.skipTypeArgs();
            return .{ .primitive_type = .byte_string };
        }

        // Other generics: skip args
        if (self.current.kind == .lt) {
            self.skipTypeArgs();
        }

        const rt = mapMoveType(name);
        if (rt == .unknown) return .{ .custom_type = name };
        return runarTypeToTypeNodeMove(rt);
    }

    /// Close a generic-argument list. Accepts either a plain `>` or splits
    /// a `>>` shift token in place into two `>`.
    fn consumeMoveGenericClose(self: *Parser) void {
        if (self.current.kind == .gt) {
            _ = self.bump();
            return;
        }
        if (self.current.kind == .rshift) {
            // Mutate the current `>>` into `>` in place so the outer
            // close consumes the remaining half.
            self.current = .{
                .kind = .gt,
                .text = ">",
                .line = self.current.line,
                .col = self.current.col + 1,
            };
            return;
        }
        _ = self.expect(.gt);
    }

    // ---- Function parsing ----

    fn parseMoveFunction(self: *Parser, attrs: []const MoveAttribute) ?MethodNode {
        var is_public = false;

        if (self.matchIdent("public")) {
            is_public = true;
            // Skip optional (friend) or (script) visibility
            if (self.current.kind == .lparen) {
                _ = self.bump();
                while (self.current.kind != .rparen and self.current.kind != .eof) {
                    _ = self.bump();
                }
                _ = self.match(.rparen);
            }
        }

        if (!self.matchIdent("fun")) {
            self.addError("expected 'fun' keyword");
            return null;
        }

        if (self.current.kind != .ident) {
            self.addError("expected function name");
            return null;
        }
        const name_tok = self.bump();
        const raw_name = name_tok.text;
        const method_loc = self.tokenSourceLoc(name_tok);
        const method_name = self.declare(raw_name);

        const params = self.parseMoveParams();

        // Optional return type: : Type or : &Type
        var has_return_type = false;
        if (self.current.kind == .colon) {
            _ = self.bump();
            // The AST keeps no return type; N-331 refuses an unknown name.
            var ret_spelled: []const u8 = "";
            const ret_ti = self.parseMoveTypeNameNamed(&ret_spelled);
            const ret_unknown = types.spelledIfUnknown(ret_ti, ret_spelled);
            if (ret_unknown.len > 0 and !std.mem.eql(u8, ret_unknown, "unknown")) {
                self.addErrorFmt(lex_diag.UNKNOWN_RETURN_TYPE_FMT, .{ ret_unknown, method_name });
            } else if (is_public and ret_ti != .void) {
                // N-332: public methods return nothing.
                self.addErrorFmt(lex_diag.PUBLIC_RETURN_TYPE_FMT, .{method_name});
            }
            has_return_type = true;
        }

        // Optional acquires clause
        if (self.checkIdent("acquires")) {
            _ = self.bump();
            // Skip comma-separated identifiers
            while (self.current.kind == .ident or self.current.kind == .comma or self.current.kind == .colon_colon) {
                _ = self.bump();
            }
        }

        var body = self.parseMoveBlock();

        // Move implicit return: if function has a return type and the last
        // statement is an expression statement, convert it to a return statement.
        if (has_return_type and body.len > 0) {
            const last = &body[body.len - 1];
            switch (last.*) {
                .expr_stmt => |e| {
                    last.* = .{ .return_stmt = e.expr };
                },
                else => {},
            }
        }

        // N-093: `#[sighash(FLAGS)]` on the function; `#[embed_always]` here
        // annotates nothing.
        var sighash_specs: std.ArrayListUnmanaged(?[]const u8) = .empty;
        for (attrs) |attr| {
            if (attr.kind == .sighash) sighash_specs.append(self.allocator, attr.flags) catch {} else self.reportLostAttributes(&.{attr});
        }
        var sighash_type: ?i32 = null;
        if (sighash_directive.resolveNativeSighash(self.allocator, method_name, is_public, sighash_specs.items)) |r| switch (r) {
            .value => |v| sighash_type = v,
            .err => |e| self.addErrorAtLoc(method_loc, e),
        };

        return MethodNode{
            .name = method_name,
            .is_public = is_public,
            .params = params,
            .body = body,
            .sighash_type = sighash_type,
            .source_loc = method_loc,
        };
    }

    fn parseMoveParams(self: *Parser) []ParamNode {
        if (self.expect(.lparen) == null) return &.{};
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;

        while (self.current.kind != .rparen and self.current.kind != .eof) {
            // Check for self
            if (self.checkIdent("self")) {
                _ = self.bump();
                if (self.current.kind == .comma) {
                    _ = self.bump();
                    continue;
                }
                break;
            }

            // Check for & prefix (reference params)
            if (self.current.kind == .ampersand) {
                _ = self.bump();
                if (self.matchIdent("mut")) {
                    // &mut — skip
                }
            }

            if (self.current.kind != .ident) break;
            const name_tok = self.bump();
            const param_name = name_tok.text;

            if (self.expect(.colon) == null) break;

            // Check for & in type position
            if (self.current.kind == .ampersand) {
                _ = self.bump();
                if (self.matchIdent("mut")) {
                    // &mut Type
                }
            }

            var spelled_type: []const u8 = "";
            const type_info = self.parseMoveTypeNameNamed(&spelled_type);

            // Skip self/contract parameters (first param that refers to the contract)
            if (std.mem.eql(u8, param_name, "self") or std.mem.eql(u8, param_name, "contract")) {
                if (self.current.kind == .comma) {
                    _ = self.bump();
                    continue;
                }
                break;
            }

            const camel_name = self.declare(param_name);

            params.append(self.allocator, .{
                .name = camel_name,
                .type_info = type_info,
                .type_name = runarTypeToTypeName(type_info),
                .spelled_type = types.spelledIfUnknown(type_info, spelled_type),
            }) catch {};

            if (self.current.kind == .comma) {
                _ = self.bump();
            } else break;
        }
        _ = self.expect(.rparen);
        return params.items;
    }

    // ---- Block parsing ----

    fn parseMoveBlock(self: *Parser) []Statement {
        if (self.expect(.lbrace) == null) return &.{};
        var stmts: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            self.skipSemicolons();
            if (self.current.kind == .rbrace or self.current.kind == .eof) break;
            const starts_while = self.checkIdent("while");
            self.move_prev_decl = null;
            if (stmts.items.len > 0) switch (stmts.items[stmts.items.len - 1]) {
                .let_decl => |ld| self.move_prev_decl = ld.name,
                .const_decl => |cd| self.move_prev_decl = cd.name,
                else => {},
            };
            if (self.parseStatement()) |s| {
                // N-421: a Move `while` must follow the declaration of its
                // loop variable immediately; the fold below is the only place
                // the start value is learned, so a `while` that does not fold
                // would silently start from the default 0. Refuse it with the
                // same sentence the other six tiers emit.
                var folded = false;
                // Fold `let i: Int = K; while (i < N) { ...; i = i + 1; }`
                // into a single for_stmt by patching init_value from a
                // preceding let/const decl whose name matches the loop variable.
                if (s == .for_stmt and stmts.items.len > 0) {
                    const last = &stmts.items[stmts.items.len - 1];
                    var decl_name: ?[]const u8 = null;
                    var decl_value: ?Expression = null;
                    switch (last.*) {
                        .let_decl => |ld| { decl_name = ld.name; decl_value = ld.value; },
                        .const_decl => |cd| { decl_name = cd.name; decl_value = cd.value; },
                        else => {},
                    }
                    if (decl_name) |dn| {
                        if (std.mem.eql(u8, dn, s.for_stmt.var_name)) {
                            // N-138: a negated literal is a literal.
                            // N-137: a declaration whose value is not a literal
                            // at all leaves the start unknown, which the
                            // unrolled loop model cannot represent.
                            var init_val: i64 = 0;
                            var init_const = true;
                            if (decl_value) |v| {
                                if (loopStartLiteral(v)) |n| init_val = n else {
                                    init_const = false;
                                }
                            }
                            stmts.items.len -= 1; // pop the decl
                            var merged = s.for_stmt;
                            merged.init_value = init_val;
                            merged.init_is_const = init_const;
                            stmts.append(self.allocator, .{ .for_stmt = merged }) catch {};
                            folded = true;
                        }
                    }
                }
                if (folded) continue;
                if (starts_while and s == .for_stmt) self.addError(move_while_shape_diagnostic);
                stmts.append(self.allocator, s) catch {};
            }
        }
        _ = self.expect(.rbrace);
        return stmts.items;
    }

    fn skipSemicolons(self: *Parser) void {
        while (self.current.kind == .semicolon) _ = self.bump();
    }

    // ---- Statements ----

    fn parseStatement(self: *Parser) ?Statement {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
        return self.parseStatementInner();
    }

    fn parseStatementInner(self: *Parser) ?Statement {
        // let [mut] name [: Type] = expr;
        if (self.checkIdent("let")) return self.parseMoveLetDecl();

        // assert!(expr, code) or assert_eq!(a, b, code)
        if (self.checkIdent("assert!") or self.checkIdent("assert_eq!")) return self.parseMoveAssert();

        // if condition { ... } [else { ... }]
        if (self.checkIdent("if")) return self.parseMoveIf();

        // while condition { ... }
        if (self.checkIdent("while")) return self.parseMoveWhile();

        // loop { ... }
        if (self.checkIdent("loop")) return self.parseMoveLoop();

        // return expr;
        if (self.checkIdent("return")) return self.parseMoveReturn();

        // N-153: `abort` is not part of the Move surface; it parses as a name
        // and is refused like any undefined one, as in the TS reference.

        // Expression statement or assignment
        return self.parseMoveExprStatement();
    }

    fn parseMoveLetDecl(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // consume 'let'

        const mutable = self.matchIdent("mut");

        if (self.current.kind != .ident) {
            self.addError("expected variable name after 'let'");
            return null;
        }
        const name_tok = self.bump();
        const var_name = self.declare(name_tok.text);

        // Optional type annotation
        var ti: ?RunarType = null;
        var spelled: []const u8 = "";
        if (self.current.kind == .colon) {
            _ = self.bump();
            ti = self.parseMoveTypeNameNamed(&spelled);
        }

        // Initializer
        var val: ?Expression = null;
        if (self.current.kind == .assign) {
            _ = self.bump();
            val = self.parseExpression();
        } else {
            // Default to 0 if no initializer
            val = Expression{ .literal_int = 0 };
        }

        self.skipSemicolons();

        if (mutable) {
            return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = val, .source_loc = loc, .type_name = spelled } };
        } else {
            return .{ .const_decl = .{ .name = var_name, .type_info = ti, .value = val orelse return null, .source_loc = loc, .type_name = spelled } };
        }
    }

    fn parseMoveAssert(self: *Parser) ?Statement {
        const tok = self.bump(); // consume 'assert!' or 'assert_eq!'
        const loc = self.tokenSourceLoc(tok);

        if (self.expect(.lparen) == null) return null;

        if (std.mem.eql(u8, tok.text, "assert_eq!")) {
            // assert_eq!(a, b, code) → assert(a === b)
            const left = self.parseExpression() orelse return null;
            if (self.expect(.comma) == null) return null;
            const right = self.parseExpression() orelse return null;
            // Skip optional error code
            if (self.current.kind == .comma) {
                _ = self.bump();
                _ = self.parseExpression();
            }
            if (self.expect(.rparen) == null) return null;
            self.skipSemicolons();

            // Build assert(left === right)
            const eq_expr = self.makeBinaryExpr(.eq, left, right) orelse return null;
            const call = self.allocator.create(CallExpr) catch return null;
            call.* = .{ .callee = "assert", .args = self.makeExprSlice(eq_expr) };
            return .{ .expr_stmt = .{ .expr = .{ .call = call }, .source_loc = loc } };
        }

        // assert!(expr, code)
        const expr = self.parseExpression() orelse return null;
        // Skip optional error code
        if (self.current.kind == .comma) {
            _ = self.bump();
            _ = self.parseExpression();
        }
        if (self.expect(.rparen) == null) return null;
        self.skipSemicolons();

        // Build assert(expr)
        const call = self.allocator.create(CallExpr) catch return null;
        call.* = .{ .callee = "assert", .args = self.makeExprSlice(expr) };
        return .{ .expr_stmt = .{ .expr = .{ .call = call }, .source_loc = loc } };
    }

    fn parseMoveIf(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // consume 'if'

        // Move uses parens around conditions optionally
        const has_paren = self.match(.lparen);
        const cond = self.parseExpression() orelse return null;
        if (has_paren) {
            _ = self.expect(.rparen);
        }

        const then_body = self.parseMoveBlock();

        // Skip optional trailing semicolon after block
        self.skipSemicolons();

        var else_body: ?[]Statement = null;
        if (self.checkIdent("else")) {
            _ = self.bump();
            if (self.checkIdent("if")) {
                // else if ...
                const nested = self.nestedParse(Statement, Parser.parseMoveIf) orelse return null;
                const a = self.allocator.alloc(Statement, 1) catch return null;
                a[0] = nested;
                else_body = a;
            } else {
                else_body = self.parseMoveBlock();
                self.skipSemicolons();
            }
        }

        return .{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body, .source_loc = loc } };
    }

    /// Emitted for a `while` that is not a representable bounded counting loop.
    ///
    /// Word for word the sentence the other six tiers emit, so a user
    /// switching tiers reads the same diagnostic.
    const move_while_shape_diagnostic =
        "Move `while` must be a bounded counting loop: " ++
        "`let i = K; while (i < N) { ...; i = i + 1; }`, or the counting-down form " ++
        "`let i = K; while (i > N) { ...; i = i - 1; }`. The iterator declaration, " ++
        "the comparison direction and a unit step must all agree.";

    /// Move has no C-style `for`, so a bounded loop is spelled as an induction
    /// variable declared just before a `while`:
    ///
    ///   let i: Int = K;          let i: Int = K;
    ///   while (i < N) {          while (i > N) {
    ///     ...                      ...
    ///     i = i + 1;               i = i - 1;
    ///   }                        }
    ///
    /// `parseMoveBlock` patches `init_value` from the preceding declaration;
    /// this function supplies everything else the unrolled loop model needs.
    ///
    /// The COUNTING-DOWN column used to be missing HERE TOO, and differently
    /// from the peer tiers: `descending` was never set from the comparison and
    /// the trailing update was trimmed only for `.add`, so `while (i > 1) {
    /// ...; i = i - 1; }` produced `start=5 step=+1 bound=1` — count
    /// `bound - start = -4`, clamped to 0 — against the peers' `start=0
    /// step=-1 iterVar=_w`. Both were wrong AND they disagreed: a six-vs-one
    /// hex split (`009c` vs `55007b7c9c77`) on byte-identical source. Deriving
    /// the direction from the comparison and requiring the step's sign to
    /// agree fixes the semantics, and the agreement follows from that.
    fn parseMoveWhile(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // consume 'while'

        // N-422: read before the condition is parsed (the body's own blocks
        // overwrite it).
        const prev_decl = self.move_prev_decl;
        const has_paren = self.match(.lparen);
        const _cond = self.parseExpression();
        // N-115: `while (5 > i)` folds exactly like `while (i < 5)`. N-422: so
        // does `while (n > i)`, whose left side is an identifier, once the
        // iterator is known to be the preceding declaration.
        if (_cond) |c| loop_condition.normalize(c, prev_decl);
        if (has_paren) {
            _ = self.expect(.rparen);
        }

        const body = self.parseMoveBlock();
        self.skipSemicolons();

        // Extract the iterator, the bound and the DIRECTION from the
        // condition. `<`/`<=` counts up, `>`/`>=` counts down; `<=`/`>=` are
        // inclusive. Anything else is not a bound the unrolled model can
        // represent, and leaves `representable` false.
        var var_name: []const u8 = "_w";
        var bound: i64 = 0;
        var bound_is_const = false;
        var bound_ident: ?[]const u8 = null;
        var descending = false;
        var inclusive = false;
        var representable = false;
        if (_cond) |cond| {
            switch (cond) {
                .binary_op => |bop| {
                    const dir_ok = switch (bop.op) {
                        .lt, .lte => blk: {
                            descending = false;
                            inclusive = bop.op == .lte;
                            break :blk true;
                        },
                        .gt, .gte => blk: {
                            descending = true;
                            inclusive = bop.op == .gte;
                            break :blk true;
                        },
                        else => false,
                    };
                    if (dir_ok and bop.left == .identifier) {
                        var_name = bop.left.identifier;
                        // N-137's counterpart for the BOUND: a non-literal
                        // bound is not unrollable, and leaving
                        // `bound_is_const` at its `true` default silently
                        // collapsed it to a 0-iteration loop here.
                        //
                        // F-025: the SHAPE is still a counting loop, though.
                        // The reference folds it (`foldCountingWhile` does not
                        // look at the bound) and refuses the bound afterwards
                        // with the for-loop sentence, so the shape diagnostic
                        // here is not the reference's. Fold it and let
                        // validate.zig refuse the bound the same way.
                        representable = true;
                        if (loopStartLiteral(bop.right)) |v| {
                            bound = v;
                            bound_is_const = true;
                        } else if (bop.right == .identifier) {
                            bound_ident = bop.right.identifier;
                        }
                    }
                },
                else => {},
            }
        }

        // Drop the trailing `var_name = var_name ± 1` and carry it as the
        // loop's update clause for validate.zig to check.
        //
        // N-061: the trimmed statement used to vanish here, so `i = i + 2`
        // produced bytes identical to `i = i + 1`.
        var trimmed_body = body;
        var update: ?*const Statement = null;
        var step_ok = false;
        if (representable and body.len > 0) {
            const last = body[body.len - 1];
            if (last == .assign) {
                const a = last.assign;
                if (std.mem.eql(u8, a.target, var_name) and a.value == .binary_op) {
                    const bop = a.value.binary_op;
                    const isIter = struct {
                        fn f(e: types.Expression, name: []const u8) bool {
                            return e == .identifier and std.mem.eql(u8, e.identifier, name);
                        }
                    }.f;
                    const isOne = struct {
                        fn f(e: types.Expression) bool {
                            return e == .literal_int and e.literal_int == 1;
                        }
                    }.f;
                    // Accept `i + 1`, `1 + i` (addition only) and `i - 1`,
                    // and only when the step's SIGN agrees with the
                    // comparison direction.
                    const unit_step = switch (bop.op) {
                        .add => !descending and
                            ((isIter(bop.left, var_name) and isOne(bop.right)) or
                                (isOne(bop.left) and isIter(bop.right, var_name))),
                        .sub => descending and
                            isIter(bop.left, var_name) and isOne(bop.right),
                        else => false,
                    };
                    if (unit_step) {
                        trimmed_body = body[0 .. body.len - 1];
                        update = &body[body.len - 1];
                        step_ok = true;
                    }
                }
            }
        }

        if (!representable or !step_ok) {
            self.addError(move_while_shape_diagnostic);
        }

        return .{ .for_stmt = .{
            .var_name = var_name,
            .init_value = 0,
            .init_is_const = true,
            .bound = bound,
            .bound_is_const = bound_is_const,
            .bound_ident = bound_ident,
            .descending = descending,
            .inclusive = inclusive,
            .update = update,
            .body = trimmed_body,
            .source_loc = loc,
        } };
    }

    fn parseMoveLoop(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // consume 'loop'
        const body = self.parseMoveBlock();
        self.skipSemicolons();

        // Infinite loop — use a large bound. N-026: the reference lowers
        // `loop { }` to a `for` whose condition is the literal `true`, which its
        // validator refuses because the condition does not test the iterator
        // (`cond_tests_iter`). Mark it the same way so this tier emits that
        // sentence rather than the bound one.
        return .{ .for_stmt = .{ .var_name = "_l", .init_value = 0, .init_is_const = true, .bound = 1000, .bound_is_const = true, .cond_tests_iter = false, .body = body, .source_loc = loc } };
    }

    fn parseMoveReturn(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'return'

        if (self.current.kind == .semicolon) {
            _ = self.bump();
            return .{ .return_stmt = null };
        }
        if (self.current.kind == .rbrace or self.current.kind == .eof) {
            return .{ .return_stmt = null };
        }

        const expr = self.parseExpression();
        self.skipSemicolons();
        return .{ .return_stmt = expr };
    }

    fn parseMoveExprStatement(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        const expr = self.parseExpression() orelse {
            _ = self.bump();
            return null;
        };

        // Check for assignment: expr = value
        if (self.current.kind == .assign) {
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            self.skipSemicolons();
            return self.buildAssignment(expr, rhs, loc);
        }

        // Compound assignments: +=, -=, *=, /=, %=
        if (isCompoundAssignOp(self.current.kind)) {
            const op_kind = self.current.kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            self.skipSemicolons();
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs, loc);
        }

        self.skipSemicolons();
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
                // `this.arr[idx] = value` — carry the full index-access target
                // on the Assign so `expand_fixed_arrays.zig` can rewrite it
                // into leaf or dispatch form. `target` keeps the base property
                // name so debug output stays meaningful. Without this arm the
                // statement fell through to `else`, became
                // `Assign{ target = "unknown", index_target = null }`, and the
                // element write was silently dropped (N-059). Every other
                // surface parser in this tier already carried it.
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

    // ---- Expressions ----
    // Operator precedence (lowest to highest):
    //   ternary (? :)
    //   logical or (||)
    //   logical and (&&)
    //   bitwise or (|)
    //   bitwise xor (^)
    //   bitwise and (&)
    //   equality (== !=) — mapped to === !==
    //   comparison (< <= > >=)
    //   shift (<< >>)
    //   additive (+ -)
    //   multiplicative (* / %)
    //   unary (! - ~ & *ref)
    //   postfix (. [] () ++ --)
    //   primary

    fn parseExpression(self: *Parser) ?Expression {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
        return self.parseTernary();
    }

    fn parseTernary(self: *Parser) ?Expression {
        var expr = self.parseLogicalOr() orelse return null;
        if (self.current.kind == .question) {
            _ = self.bump();
            const consequent = self.nestedParse(Expression, Parser.parseTernary) orelse return null;
            if (self.expect(.colon) == null) return null;
            const alternate = self.nestedParse(Expression, Parser.parseTernary) orelse return null;
            const tern = self.allocator.create(Ternary) catch return null;
            tern.* = .{ .condition = expr, .then_expr = consequent, .else_expr = alternate };
            expr = .{ .ternary = tern };
        }
        return expr;
    }

    fn parseLogicalOr(self: *Parser) ?Expression {
        var left = self.parseLogicalAnd() orelse return null;
        while (self.current.kind == .pipe_pipe) {
            _ = self.bump();
            const right = self.parseLogicalAnd() orelse return null;
            left = self.makeBinaryExpr(.or_op, left, right) orelse return null;
        }
        return left;
    }

    fn parseLogicalAnd(self: *Parser) ?Expression {
        var left = self.parseBitwiseOr() orelse return null;
        while (self.current.kind == .amp_amp) {
            _ = self.bump();
            const right = self.parseBitwiseOr() orelse return null;
            left = self.makeBinaryExpr(.and_op, left, right) orelse return null;
        }
        return left;
    }

    fn parseBitwiseOr(self: *Parser) ?Expression {
        var left = self.parseBitwiseXor() orelse return null;
        while (self.current.kind == .pipe) {
            _ = self.bump();
            const right = self.parseBitwiseXor() orelse return null;
            left = self.makeBinaryExpr(.bitor, left, right) orelse return null;
        }
        return left;
    }

    fn parseBitwiseXor(self: *Parser) ?Expression {
        var left = self.parseBitwiseAnd() orelse return null;
        while (self.current.kind == .caret) {
            _ = self.bump();
            const right = self.parseBitwiseAnd() orelse return null;
            left = self.makeBinaryExpr(.bitxor, left, right) orelse return null;
        }
        return left;
    }

    fn parseBitwiseAnd(self: *Parser) ?Expression {
        var left = self.parseEquality() orelse return null;
        while (self.current.kind == .ampersand) {
            _ = self.bump();
            const right = self.parseEquality() orelse return null;
            left = self.makeBinaryExpr(.bitand, left, right) orelse return null;
        }
        return left;
    }

    fn parseEquality(self: *Parser) ?Expression {
        var left = self.parseComparison() orelse return null;
        while (self.current.kind == .eqeq or self.current.kind == .bang_eq) {
            // Move == maps to === and != maps to !==
            const op: BinOperator = if (self.current.kind == .eqeq) .eq else .neq;
            _ = self.bump();
            const right = self.parseComparison() orelse return null;
            left = self.makeBinaryExpr(op, left, right) orelse return null;
        }
        return left;
    }

    fn parseComparison(self: *Parser) ?Expression {
        var left = self.parseShift() orelse return null;
        while (self.current.kind == .lt or self.current.kind == .lt_eq or
            self.current.kind == .gt or self.current.kind == .gt_eq)
        {
            const op: BinOperator = switch (self.current.kind) {
                .lt => .lt,
                .lt_eq => .lte,
                .gt => .gt,
                .gt_eq => .gte,
                else => unreachable,
            };
            _ = self.bump();
            const right = self.parseShift() orelse return null;
            left = self.makeBinaryExpr(op, left, right) orelse return null;
        }
        return left;
    }

    fn parseShift(self: *Parser) ?Expression {
        var left = self.parseAdditive() orelse return null;
        while (self.current.kind == .lshift or self.current.kind == .rshift) {
            const op: BinOperator = if (self.current.kind == .lshift) .lshift else .rshift;
            _ = self.bump();
            const right = self.parseAdditive() orelse return null;
            left = self.makeBinaryExpr(op, left, right) orelse return null;
        }
        return left;
    }

    fn parseAdditive(self: *Parser) ?Expression {
        var left = self.parseMultiplicative() orelse return null;
        while (self.current.kind == .plus or self.current.kind == .minus) {
            const op: BinOperator = if (self.current.kind == .plus) .add else .sub;
            _ = self.bump();
            const right = self.parseMultiplicative() orelse return null;
            left = self.makeBinaryExpr(op, left, right) orelse return null;
        }
        return left;
    }

    fn parseMultiplicative(self: *Parser) ?Expression {
        var left = self.parseUnary() orelse return null;
        while (self.current.kind == .star or self.current.kind == .slash or self.current.kind == .percent) {
            const op: BinOperator = switch (self.current.kind) {
                .star => .mul,
                .slash => .div,
                .percent => .mod,
                else => unreachable,
            };
            _ = self.bump();
            const right = self.parseUnary() orelse return null;
            left = self.makeBinaryExpr(op, left, right) orelse return null;
        }
        return left;
    }

    fn parseUnary(self: *Parser) ?Expression {
        if (self.current.kind == .minus) {
            _ = self.bump();
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .negate, .operand = o };
            return .{ .unary_op = uop };
        }
        if (self.current.kind == .bang) {
            _ = self.bump();
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .not, .operand = o };
            return .{ .unary_op = uop };
        }
        if (self.current.kind == .tilde) {
            _ = self.bump();
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .bitnot, .operand = o };
            return .{ .unary_op = uop };
        }
        // Skip & (reference) — no-op in Runar
        if (self.current.kind == .ampersand) {
            _ = self.bump();
            if (self.matchIdent("mut")) {
                // &mut expr — skip both
            }
            return self.nestedParse(Expression, Parser.parseUnary);
        }
        // Prefix ++
        if (self.current.kind == .plus_plus) {
            _ = self.bump();
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const inc = self.allocator.create(IncrementExpr) catch return null;
            inc.* = .{ .operand = o, .prefix = true };
            return .{ .increment = inc };
        }
        // Prefix --
        if (self.current.kind == .minus_minus) {
            _ = self.bump();
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const dec = self.allocator.create(DecrementExpr) catch return null;
            dec.* = .{ .operand = o, .prefix = true };
            return .{ .decrement = dec };
        }
        return self.parsePostfix();
    }

    fn parsePostfix(self: *Parser) ?Expression {
        var expr = self.parsePrimary() orelse return null;
        while (true) {
            if (self.current.kind == .dot) {
                _ = self.bump();
                if (self.current.kind != .ident) {
                    self.addError("expected identifier after '.'");
                    return null;
                }
                const raw_member = self.bump().text;
                const member = snakeToCamel(self.allocator, raw_member);

                if (self.current.kind == .lparen) {
                    // Method call: expr.method(args)
                    _ = self.bump();
                    const args = self.parseArgList();
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "contract") or std.mem.eql(u8, id, "self")) {
                                // contract.method(args) → this.method(args)
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = "this", .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            } else if (std.mem.eql(u8, id, "this")) {
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = "this", .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            } else {
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = id, .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            }
                        },
                        else => {
                            const mc = self.allocator.create(MethodCall) catch return null;
                            mc.* = .{ .object = "unknown", .method = member, .args = args };
                            expr = .{ .method_call = mc };
                        },
                    }
                } else {
                    // Property access: expr.property
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "contract") or std.mem.eql(u8, id, "self")) {
                                // contract.field → this.field
                                expr = .{ .property_access = .{ .object = "this", .property = member } };
                            } else if (std.mem.eql(u8, id, "this")) {
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
            } else if (self.current.kind == .lbracket) {
                // Index access: expr[index]
                _ = self.bump();
                const idx = self.parseExpression() orelse return null;
                _ = self.expect(.rbracket);
                const ia = self.allocator.create(IndexAccess) catch return null;
                ia.* = .{ .object = expr, .index = idx };
                expr = .{ .index_access = ia };
            } else if (self.current.kind == .lparen) {
                // Direct call: expr(...) — only for identifiers
                switch (expr) {
                    .identifier => |id| {
                        _ = self.bump();
                        const raw_args = self.parseArgList();
                        // Strip `contract`/`self` first arg (Move self-param convention)
                        var args = raw_args;
                        if (raw_args.len > 0) {
                            switch (raw_args[0]) {
                                .identifier => |first_id| {
                                    if (std.mem.eql(u8, first_id, "contract") or std.mem.eql(u8, first_id, "self")) {
                                        args = raw_args[1..];
                                    }
                                },
                                else => {},
                            }
                        }
                        const call = self.allocator.create(CallExpr) catch return null;
                        call.* = .{ .callee = id, .args = args };
                        expr = .{ .call = call };
                    },
                    else => break,
                }
            } else if (self.current.kind == .plus_plus) {
                // Postfix ++
                _ = self.bump();
                const inc = self.allocator.create(IncrementExpr) catch return null;
                inc.* = .{ .operand = expr, .prefix = false };
                expr = .{ .increment = inc };
            } else if (self.current.kind == .minus_minus) {
                // Postfix --
                _ = self.bump();
                const dec = self.allocator.create(DecrementExpr) catch return null;
                dec.* = .{ .operand = expr, .prefix = false };
                expr = .{ .decrement = dec };
            } else break;
        }
        return expr;
    }

    fn parsePrimary(self: *Parser) ?Expression {
        return switch (self.current.kind) {
            .number => blk: {
                const tok = self.bump();
                break :blk self.numberLiteral(tok);
            },
            .string_literal => blk: {
                const tok = self.bump();
                break :blk Expression{ .literal_bytes = tok.text };
            },
            .lparen => blk: {
                _ = self.bump();
                const inner = self.parseExpression() orelse break :blk null;
                _ = self.expect(.rparen);
                break :blk inner;
            },
            .lbracket => blk: {
                // Array literal: [a, b, c]
                break :blk self.parseArrayLiteral();
            },
            .ident => blk: {
                const tok = self.bump();
                const name = tok.text;

                if (std.mem.eql(u8, name, "true")) break :blk Expression{ .literal_bool = true };
                if (std.mem.eql(u8, name, "false")) break :blk Expression{ .literal_bool = false };
                if (std.mem.eql(u8, name, "self") or std.mem.eql(u8, name, "contract")) {
                    break :blk Expression{ .identifier = name };
                }

                // Handle path access: module::function(...)
                var final_name = name;
                if (self.current.kind == .colon_colon) {
                    while (self.current.kind == .colon_colon) {
                        _ = self.bump();
                        if (self.current.kind == .ident) {
                            final_name = self.bump().text;
                        }
                    }
                }

                // Map builtins (snake_case → camelCase)
                const mapped = mapBuiltin(self.allocator, final_name);

                // Function call: name(...)
                if (self.current.kind == .lparen) {
                    _ = self.bump();
                    const raw_args = self.parseArgList();
                    // Strip `contract`/`self` first arg (Move self-param convention)
                    var args = raw_args;
                    if (raw_args.len > 0) {
                        switch (raw_args[0]) {
                            .identifier => |first_id| {
                                if (std.mem.eql(u8, first_id, "contract") or std.mem.eql(u8, first_id, "self")) {
                                    args = raw_args[1..];
                                }
                            },
                            else => {},
                        }
                    }
                    const call = self.allocator.create(CallExpr) catch break :blk null;
                    call.* = .{ .callee = mapped, .args = args };
                    break :blk Expression{ .call = call };
                }

                break :blk Expression{ .identifier = mapped };
            },
            else => blk: {
                self.addErrorFmt("unexpected token: '{s}'", .{self.current.text});
                break :blk null;
            },
        };
    }

    fn parseArgList(self: *Parser) []Expression {
        var args: std.ArrayListUnmanaged(Expression) = .empty;
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            const arg = self.parseExpression() orelse break;
            args.append(self.allocator, arg) catch {};
            if (self.current.kind == .comma) {
                _ = self.bump();
            } else break;
        }
        _ = self.expect(.rparen);
        return args.items;
    }

    fn parseArrayLiteral(self: *Parser) ?Expression {
        _ = self.expect(.lbracket);
        var elements: std.ArrayListUnmanaged(Expression) = .empty;
        while (self.current.kind != .rbracket and self.current.kind != .eof) {
            const elem = self.parseExpression() orelse break;
            elements.append(self.allocator, elem) catch {};
            if (self.current.kind == .comma) {
                _ = self.bump();
            } else break;
        }
        _ = self.expect(.rbracket);
        return .{ .array_literal = elements.items };
    }

    // ---- Constructor builder ----

    /// Auto-generate a constructor from the struct properties.
    /// Non-initialized properties become constructor params.
    /// super() is called with all non-initialized property identifiers.
    fn buildMoveConstructor(self: *Parser, properties: []PropertyNode) ConstructorNode {
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;
        var super_args: std.ArrayListUnmanaged(Expression) = .empty;
        var assignments: std.ArrayListUnmanaged(AssignmentNode) = .empty;

        for (properties) |prop| {
            if (prop.initializer != null) continue; // initialized properties are excluded

            params.append(self.allocator, .{
                .name = prop.name,
                .type_info = prop.type_info,
                .type_name = runarTypeToTypeName(prop.type_info),
            }) catch {};

            super_args.append(self.allocator, Expression{ .identifier = prop.name }) catch {};

            assignments.append(self.allocator, .{
                .target = prop.name,
                .value = Expression{ .identifier = prop.name },
            }) catch {};
        }

        return .{
            .params = params.items,
            .super_args = super_args.items,
            .assignments = assignments.items,
        };
    }

    // ---- Helpers ----

    fn makeBinaryExpr(self: *Parser, op: BinOperator, left: Expression, right: Expression) ?Expression {
        const bop = self.allocator.create(BinaryOp) catch return null;
        bop.* = .{ .op = op, .left = left, .right = right };
        return .{ .binary_op = bop };
    }

    fn makeExprSlice(self: *Parser, expr: Expression) []Expression {
        const a = self.allocator.alloc(Expression, 1) catch return &.{};
        a[0] = expr;
        return a;
    }

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

    test "N-057: binOpFromCompoundAssign has no silent fallback to add (Move)" {
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
        const src = @embedFile("parse_move.zig");
        try std.testing.expect(std.mem.indexOf(u8, src, bad_arm) == null);
    }

    /// F-026: a number token's `text` becomes the canonical decimal value of
    /// its literal (`raw` keeps the literal as written), validated against
    /// this surface's host-language rules
    /// (packages/runar-compiler/src/passes/int-literal.ts). A malformed
    /// literal is refused with the shared `invalid <Language> integer literal`.
    fn normalizeNumber(self: *Parser, tok: Token) Token {
        if (tok.kind != .number) return tok;
        // A lowercase `0x` spells a ByteString on this surface.
        if (std.mem.startsWith(u8, tok.raw, "0x")) return tok;
        var t = tok;
        const lit = int_literal.parse(self.allocator, "move", tok.raw) orelse {
            const msg = int_literal.invalidIntegerLiteral(self.allocator, "move", tok.raw);
            const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, tok.line, lex_diag.diagCol(tok.col), msg }) catch msg;
            self.errors.append(self.allocator, f) catch {};
            t.text = "0";
            return t;
        };
        t.text = if (lit.small) |v| (std.fmt.allocPrint(self.allocator, "{d}", .{v}) catch "0") else lit.big.?;
        t.neg_only = lit.neg_only;
        return t;
    }

    fn fetch(self: *Parser) Token {
        return self.normalizeNumber(self.tokenizer.next());
    }

    /// F-026: the AST value of a (normalized) number token.
    fn numberLiteral(self: *Parser, tok: Token) ?Expression {
        // A lowercase `0x` spells a ByteString on this surface (any length;
        // an odd one is refused downstream, as in the TS reference).
        if (std.mem.startsWith(u8, tok.raw, "0x")) return Expression{ .literal_bytes = tok.raw[2..] };
        _ = self;
        if (std.fmt.parseInt(i64, tok.text, 10)) |v| return Expression{ .literal_int = v } else |_| {}
        return Expression{ .literal_bigint = tok.text };
    }

};

// ============================================================================
// Tests
// ============================================================================

test "move tokenizer basics" {
    var t = Tokenizer.init("module P2PKH { }");
    try std.testing.expectEqual(TokenKind.ident, t.next().kind);
    const id = t.next();
    try std.testing.expectEqualStrings("P2PKH", id.text);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "move tokenizer colon_colon" {
    var t = Tokenizer.init("runar::types::Addr");
    try std.testing.expectEqualStrings("runar", t.next().text);
    try std.testing.expectEqual(TokenKind.colon_colon, t.next().kind);
    try std.testing.expectEqualStrings("types", t.next().text);
    try std.testing.expectEqual(TokenKind.colon_colon, t.next().kind);
    try std.testing.expectEqualStrings("Addr", t.next().text);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "move tokenizer assert! macro" {
    var t = Tokenizer.init("assert!(x == 1, 0);");
    const a = t.next();
    try std.testing.expectEqual(TokenKind.ident, a.kind);
    try std.testing.expectEqualStrings("assert!", a.text);
    try std.testing.expectEqual(TokenKind.lparen, t.next().kind);
}

test "move tokenizer operators" {
    var t = Tokenizer.init("== != <= >= << >> && || += -= *= /= %= ++ -- ::");
    const expected = [_]TokenKind{
        .eqeq, .bang_eq, .lt_eq, .gt_eq,
        .lshift, .rshift, .amp_amp, .pipe_pipe, .plus_eq, .minus_eq,
        .star_eq, .slash_eq, .percent_eq, .plus_plus, .minus_minus, .colon_colon, .eof,
    };
    for (expected) |e| try std.testing.expectEqual(e, t.next().kind);
}

test "move tokenizer number with type suffix" {
    var t = Tokenizer.init("42u64 100u128 0u8");
    const n1 = t.next();
    try std.testing.expectEqual(TokenKind.number, n1.kind);
    try std.testing.expectEqualStrings("42", n1.text);
    const n2 = t.next();
    try std.testing.expectEqual(TokenKind.number, n2.kind);
    try std.testing.expectEqualStrings("100", n2.text);
    const n3 = t.next();
    try std.testing.expectEqual(TokenKind.number, n3.kind);
    try std.testing.expectEqualStrings("0", n3.text);
}

test "snake_case to camelCase" {
    const allocator = std.testing.allocator;
    {
        const result = snakeToCamel(allocator, "pub_key_hash");
        try std.testing.expectEqualStrings("pubKeyHash", result);
        allocator.free(result);
    }
    {
        const result = snakeToCamel(allocator, "check_sig");
        try std.testing.expectEqualStrings("checkSig", result);
        allocator.free(result);
    }
    {
        const result = snakeToCamel(allocator, "hash_160");
        try std.testing.expectEqualStrings("hash160", result);
        // hash_160 has underscore so it allocates
        allocator.free(result);
    }
    {
        // No underscore — returns the same slice (no allocation)
        const result = snakeToCamel(allocator, "hello");
        try std.testing.expectEqualStrings("hello", result);
    }
}

test "parse P2PKH contract (Move)" {
    const source =
        \\module P2PKH {
        \\    use runar::types::{Addr, Sig, PubKey};
        \\    use runar::crypto::{hash160, check_sig};
        \\
        \\    resource struct P2PKH {
        \\        pub_key_hash: Addr,
        \\    }
        \\
        \\    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        \\        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        \\        assert!(check_sig(sig, pub_key), 0);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseMove(arena.allocator(), source, "P2PKH.runar.move");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    // resource struct implies StatefulSmartContract
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("pubKeyHash", c.properties[0].name);
    try std.testing.expectEqual(RunarType.addr, c.properties[0].type_info);
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqualStrings("pubKeyHash", c.constructor.params[0].name);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqualStrings("unlock", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].params.len);
    try std.testing.expectEqualStrings("sig", c.methods[0].params[0].name);
    try std.testing.expectEqualStrings("pubKey", c.methods[0].params[1].name);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].body.len);
}

test "parse Counter contract (stateful, Move)" {
    const source =
        \\module Counter {
        \\    resource struct Counter {
        \\        count: bigint,
        \\    }
        \\
        \\    public fun increment(contract: &mut Counter) {
        \\        contract.count = contract.count + 1;
        \\    }
        \\
        \\    public fun decrement(contract: &mut Counter) {
        \\        assert!(contract.count > 0, 0);
        \\        contract.count = contract.count - 1;
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseMove(arena.allocator(), source, "Counter.runar.move");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Counter", c.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("count", c.properties[0].name);
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
    try std.testing.expectEqualStrings("decrement", c.methods[1].name);
    // increment body: contract.count = contract.count + 1
    try std.testing.expectEqual(@as(usize, 1), c.methods[0].body.len);
    // decrement body: assert!, contract.count = contract.count - 1
    try std.testing.expectEqual(@as(usize, 2), c.methods[1].body.len);
}

test "parse MultiMethod contract (Move)" {
    const source =
        \\module MultiMethod {
        \\    use runar::types::{PubKey, Sig, Int};
        \\    use runar::crypto::{check_sig};
        \\
        \\    resource struct MultiMethod {
        \\        owner: PubKey,
        \\        backup: PubKey,
        \\    }
        \\
        \\    fun compute_threshold(a: Int, b: Int): Int {
        \\        a * b + 1
        \\    }
        \\
        \\    public fun spend_with_owner(contract: &MultiMethod, sig: Sig, amount: Int) {
        \\        let threshold = compute_threshold(amount, 2);
        \\        assert!(threshold > 10, 0);
        \\        assert!(check_sig(sig, contract.owner), 0);
        \\    }
        \\
        \\    public fun spend_with_backup(contract: &MultiMethod, sig: Sig) {
        \\        assert!(check_sig(sig, contract.backup), 0);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseMove(arena.allocator(), source, "MultiMethod.runar.move");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("MultiMethod", c.name);
    try std.testing.expectEqual(@as(usize, 2), c.properties.len);
    try std.testing.expectEqual(@as(usize, 3), c.methods.len);
    // compute_threshold is private (no 'public')
    try std.testing.expect(!c.methods[0].is_public);
    try std.testing.expectEqualStrings("computeThreshold", c.methods[0].name);
    // spend_with_owner is public
    try std.testing.expect(c.methods[1].is_public);
    try std.testing.expectEqualStrings("spendWithOwner", c.methods[1].name);
    // spend_with_backup is public
    try std.testing.expect(c.methods[2].is_public);
    try std.testing.expectEqualStrings("spendWithBackup", c.methods[2].name);
}

test "parse IfElse contract (Move)" {
    const source =
        \\module IfElse {
        \\    use runar::types::{Int};
        \\
        \\    resource struct IfElse {
        \\        limit: Int,
        \\    }
        \\
        \\    public fun check(contract: &IfElse, value: Int, mode: bool) {
        \\        let result: Int = 0;
        \\        if (mode) {
        \\            result = value + contract.limit;
        \\        } else {
        \\            result = value - contract.limit;
        \\        };
        \\        assert!(result > 0, 0);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseMove(arena.allocator(), source, "IfElse.runar.move");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    // body: let result, if-else, assert
    try std.testing.expectEqual(@as(usize, 3), c.methods[0].body.len);
    // Second statement should be if
    try std.testing.expectEqual(std.meta.Tag(Statement).if_stmt, std.meta.activeTag(c.methods[0].body[1]));
}

test "parse BoundedLoop contract (Move)" {
    const source =
        \\module BoundedLoop {
        \\    use runar::types::{Int};
        \\
        \\    resource struct BoundedLoop {
        \\        expected_sum: Int,
        \\    }
        \\
        \\    public fun verify(contract: &BoundedLoop, start: Int) {
        \\        let sum: Int = 0;
        \\        let i: Int = 0;
        \\        while (i < 5) {
        \\            sum = sum + start + i;
        \\            i = i + 1;
        \\        };
        \\        assert_eq!(sum, contract.expected_sum);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseMove(arena.allocator(), source, "BoundedLoop.runar.move");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    // body: let sum, for_stmt (folded from `let i` + `while`), assert_eq.
    // The parser folds the canonical `let i = 0; while (i < N) { ...; i = i + 1; }`
    // pattern into a single for_stmt so ANF lowering matches TypeScript's native
    // `for (let i = 0n; i < N; i++)` bounded-loop IR.
    try std.testing.expectEqual(@as(usize, 3), c.methods[0].body.len);
    // Second statement is the folded for_stmt
    try std.testing.expectEqual(std.meta.Tag(Statement).for_stmt, std.meta.activeTag(c.methods[0].body[1]));
    // Iter var should be `i`, not `_w`
    try std.testing.expectEqualStrings("i", c.methods[0].body[1].for_stmt.var_name);
}

test "parse error: no module found" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseMove(arena.allocator(), "const x = 5;", "bad.runar.move");
    try std.testing.expect(r.errors.len > 0);
    try std.testing.expect(r.contract == null);
}

/// N-138: the compile-time integer value of a loop-start expression, or null.
///
/// Accepts a literal and a NEGATED literal. The negated form is the gap this
/// helper exists for: every surface parser in this tier recognised a bare
/// `.number` (or a folded `.literal_int`) and let `-1` fall through to the
/// zero default, so a loop written with a negative start unrolled from 0 — a
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
