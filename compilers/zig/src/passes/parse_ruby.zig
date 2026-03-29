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
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;
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
    var parser = Parser.init(allocator, source, file_name);
    return parser.parse();
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
                    if (pos < raw_line.len) pos += 1; // skip closing quote
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
                    if (pos < raw_line.len) pos += 1; // skip closing quote
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
                    const num_start = pos;
                    if (ch == '0' and pos + 1 < raw_line.len and (raw_line[pos + 1] == 'x' or raw_line[pos + 1] == 'X')) {
                        pos += 2;
                        while (pos < raw_line.len and (isHexDigit(raw_line[pos]) or raw_line[pos] == '_')) pos += 1;
                    } else {
                        while (pos < raw_line.len and ((raw_line[pos] >= '0' and raw_line[pos] <= '9') or raw_line[pos] == '_')) pos += 1;
                    }
                    self.tokens.append(self.allocator, .{
                        .kind = .number,
                        .text = raw_line[num_start..pos],
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

                // Skip unknown characters
                pos += 1;
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
        // Intrinsics
        .{ "add_output", "addOutput" },
        .{ "add_raw_output", "addRawOutput" },
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
        .{ "ByteString", .byte_string },
        .{ "PubKey", .pub_key },
        .{ "Sig", .sig },
        .{ "Addr", .addr },
        .{ "Sha256", .sha256 },
        .{ "Ripemd160", .ripemd160 },
        .{ "SigHashPreimage", .sig_hash_preimage },
        .{ "RabinSig", .rabin_sig },
        .{ "RabinPubKey", .rabin_pub_key },
        .{ "Point", .point },
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
    errors: std.ArrayListUnmanaged([]const u8),
    depth: u32,
    declared_locals: std.StringHashMapUnmanaged(void),

    const max_depth: u32 = 256;

    fn init(allocator: Allocator, source: []const u8, file_name: []const u8) Parser {
        var tokenizer = Tokenizer.init(allocator, source);
        const tokens = tokenizer.tokenize();
        return .{
            .allocator = allocator,
            .tokens = tokens,
            .pos = 0,
            .file_name = file_name,
            .errors = .empty,
            .depth = 0,
            .declared_locals = .empty,
        };
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

    fn addError(self: *Parser, msg: []const u8) void {
        const tok = self.peek();
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, tok.line, tok.col, msg }) catch return;
        self.errors.append(self.allocator, f) catch {};
    }

    fn addErrorFmt(self: *Parser, comptime fmt: []const u8, args: anytype) void {
        const msg = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        const tok = self.peek();
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, tok.line, tok.col, msg }) catch return;
        self.allocator.free(msg);
        self.errors.append(self.allocator, f) catch {};
    }

    fn skipNewlines(self: *Parser) void {
        while (self.check(.newline)) _ = self.bump();
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
        } else if (!std.mem.eql(u8, parent_class_name, "SmartContract")) {
            self.addErrorFmt("unknown parent class: '{s}', expected SmartContract or StatefulSmartContract", .{parent_class_name});
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
                const method = self.parseMethod(pending_public, pending_param_types);
                if (std.mem.eql(u8, method.name, "constructor")) {
                    if (constructor != null) self.addError("duplicate constructor");
                    constructor = self.methodToConstructor(method);
                } else {
                    methods.append(self.allocator, method) catch {};
                }
                pending_public = false;
                pending_param_types = null;
                self.skipNewlines();
                continue;
            }

            // Skip unknown tokens
            _ = self.bump();
        }

        _ = self.match(.kw_end); // end of class

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

        // Convert bare calls to declared methods and intrinsics into this.method() calls.
        var method_names: std.StringHashMapUnmanaged(void) = .empty;
        for (methods.items) |m| {
            method_names.put(self.allocator, m.name, {}) catch {};
        }
        // Intrinsic methods that must also be rewritten
        method_names.put(self.allocator, "addOutput", {}) catch {};
        method_names.put(self.allocator, "addRawOutput", {}) catch {};
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
                        last.* = .{ .return_stmt = e };
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

    const ParamTypeEntry = struct { name: []const u8, type_info: RunarType, type_name: []const u8 };
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
            }) catch {};

            // Optional comma
            if (!self.match(.comma)) break;
        }

        if (entries.items.len == 0) return null;
        return entries.items;
    }

    // ==== Property parsing ====

    fn parseProp(self: *Parser, parent_class: ParentClass) ?PropertyNode {
        _ = self.bump(); // 'prop'

        // Expect symbol :name
        if (!self.check(.symbol)) {
            self.addError("expected symbol after 'prop'");
            while (!self.check(.newline) and !self.check(.eof)) _ = self.bump();
            return null;
        }

        const raw_name = self.bump().text; // symbol value (without colon)
        if (self.expect(.comma) == null) return null;

        // Parse type
        if (!self.check(.ident)) {
            self.addError("expected type name after comma in prop");
            return null;
        }
        const type_tok = self.bump();
        var type_info = rbMapType(type_tok.text);

        // Check for FixedArray[T, N]
        if (std.mem.eql(u8, type_tok.text, "FixedArray") and self.check(.lbracket)) {
            _ = self.bump(); // '['
            // Element type
            if (self.check(.ident)) {
                const elem_tok = self.bump();
                _ = rbMapType(elem_tok.text);
            }
            _ = self.match(.comma);
            // Size
            if (self.check(.number)) _ = self.bump();
            _ = self.match(.rbracket);
            type_info = .fixed_array;
        }

        // Check for optional trailing options: readonly: true/false, default: <literal>
        var is_readonly = false;
        var initializer: ?Expression = null;

        while (self.check(.comma)) {
            _ = self.bump(); // ','
            if (self.checkIdent("readonly")) {
                _ = self.bump(); // 'readonly'
                if (self.expect(.colon) == null) break;
                if (self.check(.kw_true)) {
                    _ = self.bump();
                    is_readonly = true;
                } else if (self.check(.kw_false)) {
                    _ = self.bump();
                    is_readonly = false;
                }
            } else if (self.checkIdent("default")) {
                _ = self.bump(); // 'default'
                if (self.expect(.colon) == null) break;
                initializer = self.parseUnary();
            } else {
                // Unknown trailing option -- stop parsing options
                break;
            }
        }

        // In stateless contracts, all properties are readonly
        if (parent_class == .smart_contract) {
            is_readonly = true;
        }

        // Skip rest of line
        while (!self.check(.newline) and !self.check(.eof)) _ = self.bump();

        return PropertyNode{
            .name = rbConvertName(self.allocator, raw_name),
            .type_info = type_info,
            .readonly = is_readonly,
            .initializer = initializer,
        };
    }

    // ==== Method parsing ====

    fn parseMethod(self: *Parser, is_public: bool, param_types: ?ParamTypeMap) MethodNode {
        _ = self.expect(.kw_def); // 'def'

        const name_tok = self.bump();
        const raw_name = name_tok.text;

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
            };
        }

        return .{
            .name = rbConvertName(self.allocator, raw_name),
            .is_public = is_public,
            .params = params,
            .body = body,
        };
    }

    fn parseParams(self: *Parser, param_types: ?ParamTypeMap) []ParamNode {
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;

        while (!self.check(.rparen) and !self.check(.eof)) {
            if (!self.check(.ident)) break;
            const name_tok = self.bump();
            const raw_name = name_tok.text;
            const camel_name = rbConvertName(self.allocator, raw_name);

            // Look up the type from the preceding runar_public/params declaration
            var type_info: RunarType = .unknown;
            var type_name: []const u8 = "";
            if (param_types) |pt| {
                for (pt) |entry| {
                    if (std.mem.eql(u8, entry.name, raw_name)) {
                        type_info = entry.type_info;
                        type_name = entry.type_name;
                        break;
                    }
                }
            }

            params.append(self.allocator, .{
                .name = camel_name,
                .type_info = type_info,
                .type_name = type_name,
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

        for (m.body) |stmt| {
            switch (stmt) {
                .expr_stmt => |expr| {
                    // super(...) call
                    switch (expr) {
                        .call => |call| {
                            if (std.mem.eql(u8, call.callee, "super")) {
                                for (call.args) |arg| super_args.append(self.allocator, arg) catch {};
                            }
                        },
                        else => {},
                    }
                },
                .assign => |assign| {
                    // this.x = value
                    assignments.append(self.allocator, .{ .target = assign.target, .value = assign.value }) catch {};
                },
                else => {},
            }
        }

        return .{
            .params = m.params,
            .super_args = super_args.items,
            .assignments = assignments.items,
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
                    self.rewriteExprMethodCalls(expr, method_names);
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
                    if (rs.*) |*v| self.rewriteExprMethodCalls(v, method_names);
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

        // Skip unknown
        _ = self.bump();
        return null;
    }

    fn parseAssertStatement(self: *Parser) ?Statement {
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
            return .{ .assert_stmt = .{ .condition = c } };
        }
        return null;
    }

    fn parseIfStatement(self: *Parser) ?Statement {
        _ = self.bump(); // 'if'
        const condition = self.parseExpression() orelse return null;
        self.skipNewlines();

        const then_body = self.parseStatements();

        var else_body: ?[]Statement = null;

        if (self.check(.kw_elsif)) {
            const elif = self.parseElsifStatement() orelse return null;
            const a = self.allocator.alloc(Statement, 1) catch return null;
            a[0] = elif;
            else_body = a;
        } else if (self.match(.kw_else)) {
            self.skipNewlines();
            else_body = self.parseStatements();
        }

        _ = self.expect(.kw_end);

        return .{ .if_stmt = .{ .condition = condition, .then_body = then_body, .else_body = else_body } };
    }

    fn parseElsifStatement(self: *Parser) ?Statement {
        _ = self.bump(); // 'elsif'
        const condition = self.parseExpression() orelse return null;
        self.skipNewlines();

        const then_body = self.parseStatements();

        var else_body: ?[]Statement = null;

        if (self.check(.kw_elsif)) {
            const elif = self.parseElsifStatement() orelse return null;
            const a = self.allocator.alloc(Statement, 1) catch return null;
            a[0] = elif;
            else_body = a;
        } else if (self.match(.kw_else)) {
            self.skipNewlines();
            else_body = self.parseStatements();
        }

        // Note: the outer `end` is consumed by the parent parseIfStatement;
        // elsif branches do not consume their own `end`.

        return .{ .if_stmt = .{ .condition = condition, .then_body = then_body, .else_body = else_body } };
    }

    fn parseUnlessStatement(self: *Parser) ?Statement {
        _ = self.bump(); // 'unless'
        const raw_cond = self.parseExpression() orelse return null;
        self.skipNewlines();

        const body = self.parseStatements();
        _ = self.expect(.kw_end);

        // Unless is if with negated condition
        const uop = self.allocator.create(UnaryOp) catch return null;
        uop.* = .{ .op = .not, .operand = raw_cond };
        const negated: Expression = .{ .unary_op = uop };

        return .{ .if_stmt = .{ .condition = negated, .then_body = body } };
    }

    fn parseForStatement(self: *Parser) ?Statement {
        _ = self.bump(); // 'for'

        // Loop variable
        const iter_tok = self.bump();
        const var_name = rbConvertName(self.allocator, iter_tok.text);

        _ = self.expect(.kw_in);

        // Parse start value
        const start_expr = self.parseExpression() orelse return null;

        // Expect range operator: .. (inclusive) or ... (exclusive)
        var is_exclusive = false;
        if (self.check(.dot_dot_dot)) {
            is_exclusive = true;
            _ = self.bump();
        } else if (self.check(.dot_dot)) {
            is_exclusive = false;
            _ = self.bump();
        } else {
            self.addError("expected range operator '..' or '...' in for loop");
        }

        const end_expr = self.parseExpression() orelse return null;

        // Optional 'do' keyword
        _ = self.match(.kw_do);
        self.skipNewlines();

        const body = self.parseStatements();
        _ = self.expect(.kw_end);

        // Extract integer values for the ForStmt (which uses init_value and bound)
        var init_value: i64 = 0;
        switch (start_expr) {
            .literal_int => |v| init_value = v,
            else => {},
        }

        var bound: i64 = 0;
        switch (end_expr) {
            .literal_int => |v| {
                if (is_exclusive) {
                    bound = v;
                } else {
                    bound = v + 1; // inclusive range: bound becomes exclusive
                }
            },
            else => {},
        }

        return .{ .for_stmt = .{ .var_name = var_name, .init_value = init_value, .bound = bound, .body = body } };
    }

    fn parseReturnStatement(self: *Parser) ?Statement {
        _ = self.bump(); // 'return'
        if (self.check(.newline) or self.check(.kw_end) or self.check(.eof)) {
            return .{ .return_stmt = null };
        }
        const expr = self.parseExpression();
        return .{ .return_stmt = expr };
    }

    fn parseSuperCall(self: *Parser) ?Statement {
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
        return .{ .expr_stmt = .{ .call = call } };
    }

    fn parseIvarStatement(self: *Parser) ?Statement {
        const ivar_tok = self.bump(); // ivar token
        const prop_name = rbConvertName(self.allocator, ivar_tok.text);

        // Simple assignment: @var = expr
        if (self.match(.assign)) {
            const value = self.parseExpression() orelse return null;
            return .{ .assign = .{ .target = prop_name, .value = value } };
        }

        // Compound assignments: @var += expr, etc.
        if (isCompoundAssignOp(self.peek().kind)) {
            const op_kind = self.peek().kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            const bin_op = binOpFromCompoundAssign(op_kind);
            const target_expr: Expression = .{ .property_access = .{ .object = "this", .property = prop_name } };
            const compound_rhs = self.makeBinaryExpr(bin_op, target_expr, rhs) orelse return null;
            return .{ .assign = .{ .target = prop_name, .value = compound_rhs } };
        }

        // Expression statement (e.g. @var.method(...))
        var expr: Expression = .{ .property_access = .{ .object = "this", .property = prop_name } };
        expr = self.parsePostfixFrom(expr);
        return .{ .expr_stmt = expr };
    }

    fn parseIdentStatement(self: *Parser) ?Statement {
        const tok = self.peek();

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
                const mc = self.allocator.create(MethodCall) catch return null;
                mc.* = .{ .object = "this", .method = prop_name, .args = args };
                return .{ .expr_stmt = .{ .method_call = mc } };
            }

            // Assignment: self.field = expr
            if (self.match(.assign)) {
                const value = self.parseExpression() orelse return null;
                return .{ .assign = .{ .target = prop_name, .value = value } };
            }

            // Compound assignment: self.field += expr
            if (isCompoundAssignOp(self.peek().kind)) {
                const op_kind = self.peek().kind;
                _ = self.bump();
                const rhs = self.parseExpression() orelse return null;
                const bin_op = binOpFromCompoundAssign(op_kind);
                const target_expr: Expression = .{ .property_access = .{ .object = "this", .property = prop_name } };
                const compound_rhs = self.makeBinaryExpr(bin_op, target_expr, rhs) orelse return null;
                return .{ .assign = .{ .target = prop_name, .value = compound_rhs } };
            }

            // Expression statement (property access)
            const expr: Expression = .{ .property_access = .{ .object = "this", .property = prop_name } };
            return .{ .expr_stmt = expr };
        }

        // Check for simple name = expr pattern (variable declaration or assignment)
        if (tok.kind == .ident and self.peekAhead(1).kind == .assign) {
            _ = self.bump(); // consume ident
            _ = self.bump(); // consume '='
            const value = self.parseExpression() orelse return null;
            const camel_name = rbConvertName(self.allocator, tok.text);

            if (self.declared_locals.contains(camel_name)) {
                // Already declared: this is an assignment
                return .{ .assign = .{ .target = camel_name, .value = value } };
            }
            // First assignment: variable declaration (let)
            self.declared_locals.put(self.allocator, camel_name, {}) catch {};
            return .{ .let_decl = .{ .name = camel_name, .value = value } };
        }

        // Parse as expression first
        const expr = self.parseExpression() orelse {
            _ = self.bump();
            return null;
        };

        // Simple assignment (e.g. a.b = expr)
        if (self.match(.assign)) {
            const value = self.parseExpression() orelse return null;
            return self.buildAssignment(expr, value);
        }

        // Compound assignment
        if (isCompoundAssignOp(self.peek().kind)) {
            const op_kind = self.peek().kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs);
        }

        // Expression statement
        return .{ .expr_stmt = expr };
    }

    fn buildAssignment(self: *Parser, target: Expression, value: Expression) ?Statement {
        _ = self;
        switch (target) {
            .property_access => |pa| {
                return .{ .assign = .{ .target = pa.property, .value = value } };
            },
            .identifier => |id| {
                return .{ .assign = .{ .target = id, .value = value } };
            },
            else => {
                return .{ .assign = .{ .target = "unknown", .value = value } };
            },
        }
    }

    fn makeBinaryExpr(self: *Parser, op: BinOperator, left: Expression, right: Expression) ?Expression {
        const bop = self.allocator.create(BinaryOp) catch return null;
        bop.* = .{ .op = op, .left = left, .right = right };
        return .{ .binary_op = bop };
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
        self.depth += 1;
        defer self.depth -= 1;
        if (self.depth > max_depth) {
            self.addError("expression nesting depth exceeds maximum (256)");
            return null;
        }
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
        var left = self.parseLogicalAnd() orelse return null;
        while (self.check(.pipe_pipe) or self.check(.kw_or)) {
            _ = self.bump();
            const right = self.parseLogicalAnd() orelse return null;
            left = self.makeBinaryExpr(.or_op, left, right) orelse return null;
        }
        return left;
    }

    fn parseLogicalAnd(self: *Parser) ?Expression {
        var left = self.parseLogicalNot() orelse return null;
        while (self.check(.amp_amp) or self.check(.kw_and)) {
            _ = self.bump();
            const right = self.parseLogicalNot() orelse return null;
            left = self.makeBinaryExpr(.and_op, left, right) orelse return null;
        }
        return left;
    }

    fn parseLogicalNot(self: *Parser) ?Expression {
        if (self.check(.kw_not) or self.check(.bang)) {
            _ = self.bump();
            const operand = self.parseLogicalNot() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .not, .operand = operand };
            return .{ .unary_op = uop };
        }
        return self.parseBitwiseOr();
    }

    fn parseBitwiseOr(self: *Parser) ?Expression {
        var left = self.parseBitwiseXor() orelse return null;
        while (self.check(.pipe)) {
            _ = self.bump();
            const right = self.parseBitwiseXor() orelse return null;
            left = self.makeBinaryExpr(.bitor, left, right) orelse return null;
        }
        return left;
    }

    fn parseBitwiseXor(self: *Parser) ?Expression {
        var left = self.parseBitwiseAnd() orelse return null;
        while (self.check(.caret)) {
            _ = self.bump();
            const right = self.parseBitwiseAnd() orelse return null;
            left = self.makeBinaryExpr(.bitxor, left, right) orelse return null;
        }
        return left;
    }

    fn parseBitwiseAnd(self: *Parser) ?Expression {
        var left = self.parseEquality() orelse return null;
        while (self.check(.ampersand)) {
            _ = self.bump();
            const right = self.parseEquality() orelse return null;
            left = self.makeBinaryExpr(.bitand, left, right) orelse return null;
        }
        return left;
    }

    fn parseEquality(self: *Parser) ?Expression {
        var left = self.parseComparison() orelse return null;
        while (self.check(.eqeq) or self.check(.not_eq)) {
            const op: BinOperator = if (self.peek().kind == .eqeq) .eq else .neq;
            _ = self.bump();
            const right = self.parseComparison() orelse return null;
            left = self.makeBinaryExpr(op, left, right) orelse return null;
        }
        return left;
    }

    fn parseComparison(self: *Parser) ?Expression {
        var left = self.parseShift() orelse return null;
        while (self.check(.lt) or self.check(.lt_eq) or self.check(.gt) or self.check(.gt_eq)) {
            const op: BinOperator = switch (self.peek().kind) {
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
        while (self.check(.lshift) or self.check(.rshift)) {
            const op: BinOperator = if (self.peek().kind == .lshift) .lshift else .rshift;
            _ = self.bump();
            const right = self.parseAdditive() orelse return null;
            left = self.makeBinaryExpr(op, left, right) orelse return null;
        }
        return left;
    }

    fn parseAdditive(self: *Parser) ?Expression {
        var left = self.parseMultiplicative() orelse return null;
        while (self.check(.plus) or self.check(.minus)) {
            const op: BinOperator = if (self.peek().kind == .plus) .add else .sub;
            _ = self.bump();
            const right = self.parseMultiplicative() orelse return null;
            left = self.makeBinaryExpr(op, left, right) orelse return null;
        }
        return left;
    }

    fn parseMultiplicative(self: *Parser) ?Expression {
        var left = self.parseUnary() orelse return null;
        while (self.check(.star) or self.check(.slash) or self.check(.percent)) {
            const op: BinOperator = switch (self.peek().kind) {
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
        if (self.check(.minus)) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .negate, .operand = o };
            return .{ .unary_op = uop };
        }
        if (self.check(.tilde)) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .bitnot, .operand = o };
            return .{ .unary_op = uop };
        }
        if (self.check(.bang)) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .not, .operand = o };
            return .{ .unary_op = uop };
        }
        return self.parsePower();
    }

    /// parsePower handles ** (right-associative, maps to pow() call)
    fn parsePower(self: *Parser) ?Expression {
        const base = self.parsePostfix() orelse return null;
        if (self.match(.star_star)) {
            const exp = self.parsePower() orelse return null; // right-recursive for right-associativity
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
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "this") or std.mem.eql(u8, id, "Runar")) {
                                // this.method(args) or Runar.method(args) -> MethodCall or CallExpr
                                if (std.mem.eql(u8, id, "Runar")) {
                                    // Runar.method(args) -> CallExpr{callee=member}
                                    const call = self.allocator.create(CallExpr) catch return expr;
                                    call.* = .{ .callee = member, .args = args };
                                    expr = .{ .call = call };
                                } else {
                                    const mc = self.allocator.create(MethodCall) catch return expr;
                                    mc.* = .{ .object = "this", .method = member, .args = args };
                                    expr = .{ .method_call = mc };
                                }
                            } else {
                                const mc = self.allocator.create(MethodCall) catch return expr;
                                mc.* = .{ .object = id, .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            }
                        },
                        .property_access => |pa| {
                            // this.prop.method(args) -> complex, flatten to MethodCall
                            const mc = self.allocator.create(MethodCall) catch return expr;
                            mc.* = .{ .object = pa.property, .method = member, .args = args };
                            expr = .{ .method_call = mc };
                        },
                        else => {
                            const mc = self.allocator.create(MethodCall) catch return expr;
                            mc.* = .{ .object = "unknown", .method = member, .args = args };
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
                        const call = self.allocator.create(CallExpr) catch return expr;
                        call.* = .{ .callee = id, .args = args };
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
            return self.parseRbNumber(tok.text);
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
            return Expression{ .literal_bytes = tok.text };
        }

        // String literal (double-quoted)
        if (tok.kind == .string_literal) {
            _ = self.bump();
            return Expression{ .literal_bytes = tok.text };
        }

        // nil -> 0
        if (tok.kind == .kw_nil) {
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
            _ = self.bump();
            const inner = self.parseExpression() orelse return null;
            _ = self.expect(.rparen);
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
                const call = self.allocator.create(CallExpr) catch return null;
                call.* = .{ .callee = name, .args = args };
                return Expression{ .call = call };
            }

            return Expression{ .identifier = name };
        }

        self.addErrorFmt("unexpected token: '{s}'", .{tok.text});
        _ = self.bump();
        return null;
    }

    fn parseArgList(self: *Parser) []Expression {
        var args: std.ArrayListUnmanaged(Expression) = .empty;
        while (!self.check(.rparen) and !self.check(.eof)) {
            const arg = self.parseExpression() orelse break;
            args.append(self.allocator, arg) catch {};
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
        // Strip underscores from number text
        var stripped_buf: [64]u8 = undefined;
        var stripped_len: usize = 0;
        for (text) |ch| {
            if (ch != '_' and stripped_len < stripped_buf.len) {
                stripped_buf[stripped_len] = ch;
                stripped_len += 1;
            }
        }
        const stripped = stripped_buf[0..stripped_len];
        const val = std.fmt.parseInt(i64, stripped, 0) catch {
            self.addErrorFmt("invalid integer: '{s}'", .{text});
            return Expression{ .literal_int = 0 };
        };
        return Expression{ .literal_int = val };
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
            else => .add,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "rb tokenizer basics" {
    const allocator = std.testing.allocator;
    var tokenizer = Tokenizer.init(allocator, "class P2PKH < Runar::SmartContract");
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
    const tokens = tokenizer.tokenize();
    try std.testing.expectEqual(TokenKind.number, tokens[0].kind);
    try std.testing.expectEqual(TokenKind.dot_dot_dot, tokens[1].kind);
    try std.testing.expectEqual(TokenKind.number, tokens[2].kind);
    try std.testing.expectEqual(TokenKind.number, tokens[3].kind);
    try std.testing.expectEqual(TokenKind.dot_dot, tokens[4].kind);
    try std.testing.expectEqual(TokenKind.number, tokens[5].kind);
}

test "rb snake_case to camelCase" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqualStrings("checkSig", rbConvertName(allocator, "check_sig"));
    try std.testing.expectEqualStrings("pubKeyHash", rbConvertName(allocator, "pub_key_hash"));
    try std.testing.expectEqualStrings("hash160", rbConvertName(allocator, "hash160"));
    try std.testing.expectEqualStrings("addOutput", rbConvertName(allocator, "add_output"));
    try std.testing.expectEqualStrings("ecAdd", rbConvertName(allocator, "ec_add"));
    try std.testing.expectEqualStrings("extractLocktime", rbConvertName(allocator, "extract_locktime"));
    try std.testing.expectEqualStrings("hello", rbConvertName(allocator, "hello"));
    // Verify we can free allocations without issues (arena-like usage)
}

test "rb type mapping" {
    try std.testing.expectEqual(RunarType.bigint, rbMapType("Bigint"));
    try std.testing.expectEqual(RunarType.bigint, rbMapType("Integer"));
    try std.testing.expectEqual(RunarType.bigint, rbMapType("Int"));
    try std.testing.expectEqual(RunarType.boolean, rbMapType("Boolean"));
    try std.testing.expectEqual(RunarType.byte_string, rbMapType("ByteString"));
    try std.testing.expectEqual(RunarType.pub_key, rbMapType("PubKey"));
    try std.testing.expectEqual(RunarType.sig, rbMapType("Sig"));
    try std.testing.expectEqual(RunarType.addr, rbMapType("Addr"));
    try std.testing.expectEqual(RunarType.point, rbMapType("Point"));
    try std.testing.expectEqual(RunarType.unknown, rbMapType("UnknownType"));
}

test "rb parse basic P2PKH" {
    const allocator = std.testing.allocator;
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
    const allocator = std.testing.allocator;
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
    const allocator = std.testing.allocator;
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
    const allocator = std.testing.allocator;
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
    const allocator = std.testing.allocator;
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
    const allocator = std.testing.allocator;
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
    const allocator = std.testing.allocator;
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
