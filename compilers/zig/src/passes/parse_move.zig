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
//!   - `abort 0` maps to `assert(false)`
//!   - `==` maps to `===`, `!=` maps to `!==`
//!   - `let` / `let mut` for variable declarations
//!   - `if (cond) { ... } else { ... }` — conditions
//!   - snake_case to camelCase conversion for identifiers

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

pub fn parseMove(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
    var parser = Parser.init(allocator, source, file_name);
    return parser.parse();
}

// ============================================================================
// Token Types
// ============================================================================

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
};

// ============================================================================
// Tokenizer
// ============================================================================

const Tokenizer = struct {
    source: []const u8,
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
            while (self.pos < self.source.len and self.source[self.pos] != quote) {
                if (self.source[self.pos] == '\\') _ = self.advance();
                _ = self.advance();
            }
            if (self.pos < self.source.len) _ = self.advance();
            const end = self.pos;
            const content_start = start + 1;
            const content_end = if (end > 0) end - 1 else end;
            return .{ .kind = .string_literal, .text = self.source[content_start..content_end], .line = sl, .col = sc };
        }

        // Numbers (decimal, hex; strip trailing type suffixes like u64, u128, u256)
        if (c >= '0' and c <= '9') {
            if (c == '0' and (self.peekAt(1) == 'x' or self.peekAt(1) == 'X')) {
                _ = self.advance(); // '0'
                _ = self.advance(); // 'x'
                while (self.pos < self.source.len and isHexDigit(self.source[self.pos])) _ = self.advance();
            } else {
                while (self.pos < self.source.len and ((self.source[self.pos] >= '0' and self.source[self.pos] <= '9') or self.source[self.pos] == '_')) _ = self.advance();
            }
            const num_end = self.pos;
            // Strip trailing type suffix: u8, u16, u32, u64, u128, u256
            if (self.pos < self.source.len and self.source[self.pos] == 'u') {
                _ = self.advance(); // 'u'
                while (self.pos < self.source.len and self.source[self.pos] >= '0' and self.source[self.pos] <= '9') _ = self.advance();
            }
            // Also strip trailing BigInt suffix 'n' (for compatibility)
            if (self.pos < self.source.len and self.source[self.pos] == 'n') _ = self.advance();
            return .{ .kind = .number, .text = self.source[start..num_end], .line = sl, .col = sc };
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
            else => .{ .kind = .ident, .text = t, .line = sl, .col = sc },
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
        .{ "bigint", .bigint },
        .{ "bool", .boolean },
        .{ "Bool", .boolean },
        .{ "boolean", .boolean },
        .{ "vector", .byte_string },
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
        .{ "void", .void },
    });
    if (map.get(name)) |rt| return rt;
    // Try camelCase conversion for snake_case type names
    return .unknown;
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
    depth: u32,

    const max_depth: u32 = 256;

    fn init(allocator: Allocator, source: []const u8, file_name: []const u8) Parser {
        var tokenizer = Tokenizer.init(source);
        const first = tokenizer.next();
        return .{ .allocator = allocator, .tokenizer = tokenizer, .current = first, .file_name = file_name, .errors = .empty, .depth = 0 };
    }

    fn addError(self: *Parser, msg: []const u8) void {
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, self.current.line, self.current.col, msg }) catch return;
        self.errors.append(self.allocator, f) catch {};
    }

    fn addErrorFmt(self: *Parser, comptime fmt: []const u8, args: anytype) void {
        const msg = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, self.current.line, self.current.col, msg }) catch return;
        self.allocator.free(msg);
        self.errors.append(self.allocator, f) catch {};
    }

    fn bump(self: *Parser) Token {
        const prev = self.current;
        self.current = self.tokenizer.next();
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
        return .{ .contract = contract, .errors = self.errors.items };
    }

    // ---- Module parsing ----

    fn parseModule(self: *Parser) ?ContractNode {
        // Skip top-level use declarations before module
        while (self.checkIdent("use")) {
            self.skipUseDecl();
        }

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
        var parent_class: ParentClass = .smart_contract;
        var has_init_fn = false;

        while (self.current.kind != .rbrace and self.current.kind != .eof) {
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
                    parent_class = .stateful_smart_contract;
                }
                const props = self.parseMoveStruct(parent_class);
                for (props) |p| properties.append(self.allocator, p) catch {};
                continue;
            }

            // public fun or fun
            if (self.checkIdent("public") or self.checkIdent("fun")) {
                const method = self.parseMoveFunction();
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
            if (self.current.kind != .ident) {
                _ = self.bump();
                continue;
            }

            const field_name_tok = self.bump();
            const raw_field_name = field_name_tok.text;
            const field_name = snakeToCamel(self.allocator, raw_field_name);

            if (self.expect(.colon) == null) continue;

            // Parse type, handling &mut prefix for mutable fields
            var is_mutable = false;
            if (self.current.kind == .ampersand) {
                _ = self.bump(); // consume '&'
                if (self.matchIdent("mut")) {
                    is_mutable = true;
                }
            }

            const type_info = self.parseMoveTypeName();

            // Determine readonly based on parent class and mutability markers
            const readonly = if (parent_class == .smart_contract)
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
            }) catch {};

            _ = self.match(.comma);
        }

        _ = self.expect(.rbrace);
        return props.items;
    }

    fn parseMoveTypeName(self: *Parser) RunarType {
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

        return mapMoveType(name);
    }

    fn skipTypeArgs(self: *Parser) void {
        if (self.current.kind != .lt) return;
        _ = self.bump();
        var depth_count: i32 = 1;
        while (depth_count > 0 and self.current.kind != .eof) {
            if (self.current.kind == .lt) depth_count += 1;
            if (self.current.kind == .gt) depth_count -= 1;
            _ = self.bump();
        }
    }

    // ---- Function parsing ----

    fn parseMoveFunction(self: *Parser) ?MethodNode {
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
        const method_name = snakeToCamel(self.allocator, raw_name);

        const params = self.parseMoveParams();

        // Optional return type: : Type or : &Type
        var has_return_type = false;
        if (self.current.kind == .colon) {
            _ = self.bump();
            _ = self.parseMoveTypeName(); // skip return type
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
                    last.* = .{ .return_stmt = e };
                },
                else => {},
            }
        }

        return MethodNode{
            .name = method_name,
            .is_public = is_public,
            .params = params,
            .body = body,
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

            const type_info = self.parseMoveTypeName();

            // Skip self/contract parameters (first param that refers to the contract)
            if (std.mem.eql(u8, param_name, "self") or std.mem.eql(u8, param_name, "contract")) {
                if (self.current.kind == .comma) {
                    _ = self.bump();
                    continue;
                }
                break;
            }

            const camel_name = snakeToCamel(self.allocator, param_name);

            params.append(self.allocator, .{
                .name = camel_name,
                .type_info = type_info,
                .type_name = runarTypeToTypeName(type_info),
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
            if (self.parseStatement()) |s| {
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
                            const init_val: i64 = if (decl_value) |v| switch (v) {
                                .literal_int => |n| n,
                                else => 0,
                            } else 0;
                            stmts.items.len -= 1; // pop the decl
                            var merged = s.for_stmt;
                            merged.init_value = init_val;
                            stmts.append(self.allocator, .{ .for_stmt = merged }) catch {};
                            continue;
                        }
                    }
                }
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

        // abort code — maps to assert(false)
        if (self.checkIdent("abort")) return self.parseMoveAbort();

        // Expression statement or assignment
        return self.parseMoveExprStatement();
    }

    fn parseMoveLetDecl(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'let'

        const mutable = self.matchIdent("mut");

        if (self.current.kind != .ident) {
            self.addError("expected variable name after 'let'");
            return null;
        }
        const name_tok = self.bump();
        const var_name = snakeToCamel(self.allocator, name_tok.text);

        // Optional type annotation
        var ti: ?RunarType = null;
        if (self.current.kind == .colon) {
            _ = self.bump();
            ti = self.parseMoveTypeName();
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
            return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = val } };
        } else {
            return .{ .const_decl = .{ .name = var_name, .type_info = ti, .value = val orelse return null } };
        }
    }

    fn parseMoveAssert(self: *Parser) ?Statement {
        const tok = self.bump(); // consume 'assert!' or 'assert_eq!'

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
            return .{ .expr_stmt = .{ .call = call } };
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
        return .{ .expr_stmt = .{ .call = call } };
    }

    fn parseMoveIf(self: *Parser) ?Statement {
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
                const nested = self.parseMoveIf() orelse return null;
                const a = self.allocator.alloc(Statement, 1) catch return null;
                a[0] = nested;
                else_body = a;
            } else {
                else_body = self.parseMoveBlock();
                self.skipSemicolons();
            }
        }

        return .{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body } };
    }

    fn parseMoveWhile(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'while'

        const has_paren = self.match(.lparen);
        const _cond = self.parseExpression();
        if (has_paren) {
            _ = self.expect(.rparen);
        }

        const body = self.parseMoveBlock();
        self.skipSemicolons();

        // Extract var_name and bound from condition if it's a simple comparison: var < N
        var var_name: []const u8 = "_w";
        var bound: i64 = 0;
        if (_cond) |cond| {
            switch (cond) {
                .binary_op => |bop| {
                    if (bop.left == .identifier) var_name = bop.left.identifier;
                    switch (bop.right) {
                        .literal_int => |v| {
                            bound = v;
                        },
                        else => {},
                    }
                },
                else => {},
            }
        }

        // Drop a trailing `var_name = var_name + K` so the for_stmt's implicit
        // iteration matches TypeScript's native `for (let i = 0n; i < N; i++)`.
        var trimmed_body = body;
        if (body.len > 0) {
            const last = body[body.len - 1];
            if (last == .assign) {
                const a = last.assign;
                if (std.mem.eql(u8, a.target, var_name)) {
                    if (a.value == .binary_op) {
                        const bop = a.value.binary_op;
                        if (bop.op == .add and bop.left == .identifier and
                            std.mem.eql(u8, bop.left.identifier, var_name))
                        {
                            trimmed_body = body[0 .. body.len - 1];
                        }
                    }
                }
            }
        }

        return .{ .for_stmt = .{ .var_name = var_name, .init_value = 0, .bound = bound, .body = trimmed_body } };
    }

    fn parseMoveLoop(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'loop'
        const body = self.parseMoveBlock();
        self.skipSemicolons();

        // Infinite loop — use a large bound
        return .{ .for_stmt = .{ .var_name = "_l", .init_value = 0, .bound = 1000, .body = body } };
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

    fn parseMoveAbort(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'abort'
        // Skip the error code
        _ = self.parseExpression();
        self.skipSemicolons();

        // abort maps to assert(false)
        const call = self.allocator.create(CallExpr) catch return null;
        call.* = .{ .callee = "assert", .args = self.makeExprSlice(.{ .literal_bool = false }) };
        return .{ .expr_stmt = .{ .call = call } };
    }

    fn parseMoveExprStatement(self: *Parser) ?Statement {
        const expr = self.parseExpression() orelse {
            _ = self.bump();
            return null;
        };

        // Check for assignment: expr = value
        if (self.current.kind == .assign) {
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            self.skipSemicolons();
            return self.buildAssignment(expr, rhs);
        }

        // Compound assignments: +=, -=, *=, /=, %=
        if (isCompoundAssignOp(self.current.kind)) {
            const op_kind = self.current.kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            self.skipSemicolons();
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs);
        }

        self.skipSemicolons();
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
        if (self.current.kind == .question) {
            _ = self.bump();
            const consequent = self.parseTernary() orelse return null;
            if (self.expect(.colon) == null) return null;
            const alternate = self.parseTernary() orelse return null;
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
            const o = self.parseUnary() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .negate, .operand = o };
            return .{ .unary_op = uop };
        }
        if (self.current.kind == .bang) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .not, .operand = o };
            return .{ .unary_op = uop };
        }
        if (self.current.kind == .tilde) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
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
            return self.parseUnary();
        }
        // Prefix ++
        if (self.current.kind == .plus_plus) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const inc = self.allocator.create(IncrementExpr) catch return null;
            inc.* = .{ .operand = o, .prefix = true };
            return .{ .increment = inc };
        }
        // Prefix --
        if (self.current.kind == .minus_minus) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
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
                // Strip underscores from number text
                var stripped_buf: [64]u8 = undefined;
                var stripped_len: usize = 0;
                for (tok.text) |ch| {
                    if (ch != '_' and stripped_len < stripped_buf.len) {
                        stripped_buf[stripped_len] = ch;
                        stripped_len += 1;
                    }
                }
                const stripped = stripped_buf[0..stripped_len];
                // Hex literals with even digit count → ByteString
                if (stripped.len > 2 and stripped[0] == '0' and (stripped[1] == 'x' or stripped[1] == 'X')) {
                    const hex_digits = stripped[2..];
                    if (hex_digits.len > 0 and hex_digits.len % 2 == 0) {
                        const duped = self.allocator.dupe(u8, hex_digits) catch break :blk null;
                        break :blk Expression{ .literal_bytes = duped };
                    }
                }
                const val = std.fmt.parseInt(i64, stripped, 0) catch {
                    self.addErrorFmt("invalid integer: '{s}'", .{tok.text});
                    break :blk null;
                };
                break :blk Expression{ .literal_int = val };
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
            else => .add,
        };
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
