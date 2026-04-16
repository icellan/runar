//! Pass 1 (Rust DSL frontend): Hand-written tokenizer + recursive descent parser for .runar.rs files.
//!
//! Parses Rust macro-style contract syntax into the Runar IR ContractNode.
//!
//! Syntax conventions:
//!   - `use runar::prelude::*;` at top (skipped)
//!   - `#[runar::contract]` or `#[runar::stateful_contract]` attribute on struct
//!   - `struct Name { field: Type, ... }` declares properties
//!   - `#[readonly]` attribute makes fields readonly
//!   - `#[runar::methods(Name)]` attribute on impl block
//!   - `impl Name { ... }` contains methods
//!   - `#[public] fn method(&self, params) { ... }` for public methods
//!   - `fn method(&self, params) { ... }` for private methods
//!   - `self.field` maps to `this.camelCaseField` (snake_case → camelCase)
//!   - `assert!(expr)` maps to assert statement
//!   - `assert_eq!(a, b)` maps to `assert(a === b)`
//!   - `==` maps to `===`, `!=` maps to `!==`
//!   - `let [mut] name: Type = expr;` for variable declarations
//!   - `if cond { ... } else { ... }` (no parens)
//!   - `for i in 0..n { ... }` for range loops
//!   - `fn init(&mut self) { ... }` method is extracted as property initializers
//!   - `fn new(params) -> Self { Self { field: value, ... } }` for constructor
//!   - Type mappings: i128/Bigint/Int → bigint, bool/Bool → boolean, ByteString/Vec<u8> → ByteString

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

// ============================================================================
// Public API
// ============================================================================

pub const ParseResult = struct {
    contract: ?ContractNode,
    errors: [][]const u8,
};

pub fn parseRust(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
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
    hex_string, // 0x... hex literal or double-quoted string
    lparen,
    rparen,
    lbrace,
    rbrace,
    lbracket,
    rbracket,
    semicolon,
    comma,
    dot,
    dot_dot, // ..
    colon,
    colon_colon, // ::
    hash_bracket, // #[
    arrow, // ->
    assign, // =
    eqeq, // ==
    bang_eq, // !=
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
                // Line comment (including /// doc comments)
                while (self.pos < self.source.len and self.source[self.pos] != '\n') _ = self.advance();
            } else if (c == '/' and self.peekAt(1) == '*') {
                // Block comment
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

        // Double-quoted string — treated as ByteString literal
        if (c == '"') {
            _ = self.advance();
            while (self.pos < self.source.len and self.source[self.pos] != '"') {
                if (self.source[self.pos] == '\\') _ = self.advance();
                _ = self.advance();
            }
            if (self.pos < self.source.len) _ = self.advance();
            const content_start = start + 1;
            const content_end = self.pos - 1;
            return .{ .kind = .hex_string, .text = self.source[content_start..content_end], .line = sl, .col = sc };
        }

        // Numbers: decimal, hex (0x...)
        if (c >= '0' and c <= '9') {
            if (c == '0' and (self.peekAt(1) == 'x' or self.peekAt(1) == 'X')) {
                // Hex literal: 0x...
                _ = self.advance(); // '0'
                _ = self.advance(); // 'x'
                const hex_start = self.pos;
                while (self.pos < self.source.len and isHexDigit(self.source[self.pos])) _ = self.advance();
                // Return just the hex digits (without 0x prefix) as hex_string
                return .{ .kind = .hex_string, .text = self.source[hex_start..self.pos], .line = sl, .col = sc };
            }
            // Decimal number (skip underscores for Rust numeric literals)
            while (self.pos < self.source.len and ((self.source[self.pos] >= '0' and self.source[self.pos] <= '9') or self.source[self.pos] == '_')) _ = self.advance();
            // Skip type suffixes like i128, u64, etc.
            if (self.pos < self.source.len and (self.source[self.pos] == 'i' or self.source[self.pos] == 'u')) {
                while (self.pos < self.source.len and isIdentChar(self.source[self.pos])) _ = self.advance();
            }
            return .{ .kind = .number, .text = self.source[start..self.pos], .line = sl, .col = sc };
        }

        // Identifiers and keywords
        if (isIdentStart(c)) {
            while (self.pos < self.source.len and isIdentChar(self.source[self.pos])) _ = self.advance();
            const text = self.source[start..self.pos];
            // Check for assert! and assert_eq! macro syntax
            if (self.pos < self.source.len and self.source[self.pos] == '!') {
                if (std.mem.eql(u8, text, "assert") or std.mem.eql(u8, text, "assert_eq")) {
                    _ = self.advance(); // consume '!'
                    return .{ .kind = .ident, .text = self.source[start..self.pos], .line = sl, .col = sc };
                }
            }
            return .{ .kind = .ident, .text = text, .line = sl, .col = sc };
        }

        // Operators and punctuation
        _ = self.advance();
        const c2 = self.peek();

        // #[ attribute opener
        if (c == '#' and c2 == '[') {
            _ = self.advance();
            return .{ .kind = .hash_bracket, .text = self.source[start..self.pos], .line = sl, .col = sc };
        }

        // Two-character operators
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
            '~' => .{ .kind = .tilde, .text = t, .line = sl, .col = sc },
            '^' => .{ .kind = .caret, .text = t, .line = sl, .col = sc },
            '.' => if (c2 == '.') blk: {
                _ = self.advance();
                break :blk .{ .kind = .dot_dot, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .dot, .text = t, .line = sl, .col = sc },
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
// Snake-case to camelCase conversion
// ============================================================================

fn snakeToCamel(allocator: Allocator, name: []const u8) []const u8 {
    // If no underscore, return as-is
    if (std.mem.indexOfScalar(u8, name, '_') == null) return name;

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    var capitalize_next = false;
    var first_segment = true;
    for (name) |ch| {
        if (ch == '_') {
            if (!first_segment) {
                capitalize_next = true;
            } else {
                // Leading underscore or empty first segment
                capitalize_next = true;
                first_segment = false;
            }
        } else {
            if (capitalize_next and !first_segment) {
                buf.append(allocator, std.ascii.toUpper(ch)) catch {};
                capitalize_next = false;
            } else {
                buf.append(allocator, ch) catch {};
                capitalize_next = false;
                first_segment = false;
            }
        }
    }
    return buf.items;
}

/// Map Rust-style builtin names to canonical Runar names.
/// Handles special cases that snake_to_camel cannot produce correctly.
fn mapBuiltin(allocator: Allocator, name: []const u8) []const u8 {
    const map = std.StaticStringMap([]const u8).initComptime(.{
        .{ "bool_cast", "bool" },
        .{ "verify_wots", "verifyWOTS" },
        .{ "verify_slh_dsa_sha2_128s", "verifySLHDSA_SHA2_128s" },
        .{ "verify_slh_dsa_sha2_128f", "verifySLHDSA_SHA2_128f" },
        .{ "verify_slh_dsa_sha2_192s", "verifySLHDSA_SHA2_192s" },
        .{ "verify_slh_dsa_sha2_192f", "verifySLHDSA_SHA2_192f" },
        .{ "verify_slh_dsa_sha2_256s", "verifySLHDSA_SHA2_256s" },
        .{ "verify_slh_dsa_sha2_256f", "verifySLHDSA_SHA2_256f" },
        .{ "bin_2_num", "bin2num" },
        .{ "num_2_bin", "num2bin" },
        .{ "to_byte_string", "toByteString" },
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
    });
    if (map.get(name)) |mapped| return mapped;
    return snakeToCamel(allocator, name);
}

/// Map Rust type names to Runar type names.
fn mapRustType(name: []const u8) []const u8 {
    const tmap = std.StaticStringMap([]const u8).initComptime(.{
        .{ "Bigint", "bigint" },
        .{ "Int", "bigint" },
        .{ "i64", "bigint" },
        .{ "u64", "bigint" },
        .{ "i128", "bigint" },
        .{ "u128", "bigint" },
        .{ "Bool", "boolean" },
        .{ "bool", "boolean" },
        .{ "ByteString", "ByteString" },
        .{ "Vec", "ByteString" },
        .{ "String", "ByteString" },
    });
    if (tmap.get(name)) |mapped| return mapped;
    // Pass through Runar primitives: PubKey, Sig, Addr, Sha256, Ripemd160, etc.
    return name;
}

/// Resolve a mapped type name string to a TypeNode.
fn resolveRustTypeName(name: []const u8) TypeNode {
    const mapped = mapRustType(name);
    if (std.mem.eql(u8, mapped, "bigint") or std.mem.eql(u8, mapped, "number")) return .{ .primitive_type = .bigint };
    if (std.mem.eql(u8, mapped, "boolean")) return .{ .primitive_type = .boolean };
    if (std.mem.eql(u8, mapped, "void")) return .{ .primitive_type = .void };
    if (PrimitiveTypeName.fromTsString(mapped)) |ptn| return .{ .primitive_type = ptn };
    return .{ .custom_type = mapped };
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

    // ==================================================================
    // Top-level parse
    // ==================================================================

    fn parse(self: *Parser) ParseResult {
        // Skip `use` declarations
        self.skipUseDeclarations();

        var contract_name: []const u8 = "";
        var parent_class: ?ParentClass = null;
        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;
        var methods: std.ArrayListUnmanaged(MethodNode) = .empty;

        while (self.current.kind != .eof) {
            if (self.current.kind == .hash_bracket) {
                const attr = self.parseAttribute();

                if (std.mem.eql(u8, attr, "runar::contract") or std.mem.eql(u8, attr, "runar::stateful_contract")) {
                    if (std.mem.eql(u8, attr, "runar::stateful_contract")) {
                        parent_class = .stateful_smart_contract;
                    }
                    // Parse: [pub] struct Name { fields... }
                    _ = self.matchIdent("pub");
                    if (!self.checkIdent("struct")) {
                        self.addError("expected 'struct' after #[runar::contract]");
                        _ = self.bump();
                        continue;
                    }
                    _ = self.bump(); // consume 'struct'
                    if (self.current.kind == .ident) {
                        contract_name = self.bump().text;
                    } else {
                        self.addError("expected struct name");
                    }
                    if (self.expect(.lbrace) == null) continue;

                    while (self.current.kind != .rbrace and self.current.kind != .eof) {
                        // Field may have #[readonly] attribute
                        var readonly = false;
                        if (self.current.kind == .hash_bracket) {
                            const field_attr = self.parseAttribute();
                            if (std.mem.eql(u8, field_attr, "readonly")) {
                                readonly = true;
                            }
                        }

                        // Skip optional `pub` visibility on fields
                        _ = self.matchIdent("pub");

                        if (self.current.kind == .ident) {
                            const field_name_tok = self.bump();
                            if (self.expect(.colon) == null) continue;
                            const field_type = self.parseRustType();
                            _ = self.match(.comma);

                            // Skip txPreimage — implicit stateful param
                            const camel_name = snakeToCamel(self.allocator, field_name_tok.text);
                            if (!std.mem.eql(u8, camel_name, "txPreimage")) {
                                const type_info = types.typeNodeToRunarType(field_type);
                                properties.append(self.allocator, .{
                                    .name = camel_name,
                                    .type_info = type_info,
                                    .readonly = readonly,
                                }) catch {};
                            }
                        } else {
                            _ = self.bump(); // skip unexpected token
                        }
                    }
                    _ = self.expect(.rbrace);
                } else if (std.mem.startsWith(u8, attr, "runar::methods")) {
                    // Parse: impl Name { methods... }
                    _ = self.matchIdent("impl");
                    // Skip type name
                    if (self.current.kind == .ident) _ = self.bump();
                    if (self.expect(.lbrace) == null) continue;

                    while (self.current.kind != .rbrace and self.current.kind != .eof) {
                        var visibility_public = false;
                        if (self.current.kind == .hash_bracket) {
                            const method_attr = self.parseAttribute();
                            if (std.mem.eql(u8, method_attr, "public")) {
                                visibility_public = true;
                            }
                        }
                        // `pub fn` also makes it public
                        if (self.checkIdent("pub")) {
                            _ = self.bump();
                            visibility_public = true;
                        }
                        const m = self.parseFunction(visibility_public);
                        methods.append(self.allocator, m) catch {};
                    }
                    _ = self.expect(.rbrace);
                }
                // Unknown attribute — skip
            } else {
                _ = self.bump();
            }
        }

        if (contract_name.len == 0) {
            self.addError("no Runar contract struct found in Rust source");
            return .{ .contract = null, .errors = self.errors.items };
        }

        // Derive parent class from property mutability if not explicitly set
        if (parent_class == null) {
            var all_readonly = true;
            for (properties.items) |prop| {
                if (!prop.readonly) {
                    all_readonly = false;
                    break;
                }
            }
            parent_class = if (all_readonly) .smart_contract else .stateful_smart_contract;
        }

        // Extract init() method as property initializers
        var final_methods: std.ArrayListUnmanaged(MethodNode) = .empty;
        for (methods.items) |m| {
            if (std.mem.eql(u8, m.name, "init") and m.params.len == 0) {
                // Extract assignments as property initializers
                for (m.body) |stmt| {
                    switch (stmt) {
                        .assign => |assign| {
                            for (properties.items, 0..) |_, pi| {
                                if (std.mem.eql(u8, properties.items[pi].name, assign.target)) {
                                    properties.items[pi].initializer = assign.value;
                                    break;
                                }
                            }
                        },
                        else => {},
                    }
                }
            } else {
                final_methods.append(self.allocator, m) catch {};
            }
        }

        // Build constructor from non-initialized properties
        var uninit_props: std.ArrayListUnmanaged(PropertyNode) = .empty;
        for (properties.items) |prop| {
            if (prop.initializer == null) {
                uninit_props.append(self.allocator, prop) catch {};
            }
        }

        var ctor_params = self.allocator.alloc(ParamNode, uninit_props.items.len) catch return .{ .contract = null, .errors = self.errors.items };
        for (uninit_props.items, 0..) |prop, i| {
            ctor_params[i] = .{
                .name = prop.name,
                .type_info = prop.type_info,
                .type_name = runarTypeToTypeName(prop.type_info),
            };
        }

        var super_args = self.allocator.alloc(Expression, uninit_props.items.len) catch return .{ .contract = null, .errors = self.errors.items };
        for (uninit_props.items, 0..) |prop, i| {
            super_args[i] = .{ .identifier = prop.name };
        }

        var ctor_assignments = self.allocator.alloc(AssignmentNode, uninit_props.items.len) catch return .{ .contract = null, .errors = self.errors.items };
        for (uninit_props.items, 0..) |prop, i| {
            ctor_assignments[i] = .{
                .target = prop.name,
                .value = .{ .identifier = prop.name },
            };
        }

        const constructor = ConstructorNode{
            .params = ctor_params,
            .super_args = super_args,
            .assignments = ctor_assignments,
        };

        return .{
            .contract = ContractNode{
                .name = contract_name,
                .parent_class = parent_class.?,
                .properties = properties.items,
                .constructor = constructor,
                .methods = final_methods.items,
            },
            .errors = self.errors.items,
        };
    }

    fn skipUseDeclarations(self: *Parser) void {
        while (self.checkIdent("use")) {
            while (self.current.kind != .semicolon and self.current.kind != .eof) _ = self.bump();
            _ = self.match(.semicolon);
        }
    }

    // ==================================================================
    // Attribute parsing
    // ==================================================================

    /// Consume an already-peeked #[ and collect the attribute text up to the matching ].
    fn parseAttribute(self: *Parser) []const u8 {
        _ = self.bump(); // consume #[
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        var depth: i32 = 1;
        while (depth > 0 and self.current.kind != .eof) {
            switch (self.current.kind) {
                .lbracket => {
                    depth += 1;
                    _ = self.bump();
                },
                .rbracket => {
                    depth -= 1;
                    _ = self.bump();
                },
                .ident => {
                    buf.appendSlice(self.allocator, self.current.text) catch {};
                    _ = self.bump();
                },
                .colon_colon => {
                    buf.appendSlice(self.allocator, "::") catch {};
                    _ = self.bump();
                },
                .lparen => {
                    buf.append(self.allocator, '(') catch {};
                    _ = self.bump();
                },
                .rparen => {
                    buf.append(self.allocator, ')') catch {};
                    _ = self.bump();
                },
                else => {
                    _ = self.bump();
                },
            }
        }
        return buf.items;
    }

    // ==================================================================
    // Type parsing
    // ==================================================================

    fn parseRustType(self: *Parser) TypeNode {
        // Skip optional & and mut (reference types)
        _ = self.match(.ampersand);
        _ = self.matchIdent("mut");

        if (self.current.kind == .ident) {
            const name = self.bump().text;
            // Skip generic type args: Type<...>
            if (self.current.kind == .lt) {
                self.skipTypeArgs();
            }
            return resolveRustTypeName(name);
        }
        _ = self.bump();
        return .{ .custom_type = "unknown" };
    }

    fn skipTypeArgs(self: *Parser) void {
        if (self.current.kind != .lt) return;
        _ = self.bump();
        var depth_counter: i32 = 1;
        while (depth_counter > 0 and self.current.kind != .eof) {
            if (self.current.kind == .lt) depth_counter += 1;
            if (self.current.kind == .gt) depth_counter -= 1;
            _ = self.bump();
        }
    }

    /// Delegates to the canonical implementation in types.zig.
    const typeNodeToRunarType = types.typeNodeToRunarType;

    fn runarTypeToTypeName(t: RunarType) []const u8 {
        return types.runarTypeToString(t);
    }

    // ==================================================================
    // Function parsing
    // ==================================================================

    fn parseFunction(self: *Parser, is_public: bool) MethodNode {
        if (!self.checkIdent("fn")) {
            self.addError("expected 'fn' keyword");
            self.skipToNextMember();
            return .{ .name = "unknown", .is_public = is_public, .params = &.{}, .body = &.{} };
        }
        _ = self.bump(); // consume 'fn'

        var raw_name: []const u8 = "unknown";
        if (self.current.kind == .ident) {
            raw_name = self.bump().text;
        } else {
            self.addError("expected function name");
        }
        const name = snakeToCamel(self.allocator, raw_name);

        if (self.expect(.lparen) == null) {
            return .{ .name = name, .is_public = is_public, .params = &.{}, .body = &.{} };
        }

        var params: std.ArrayListUnmanaged(ParamNode) = .empty;

        while (self.current.kind != .rparen and self.current.kind != .eof) {
            // Skip &self, &mut self, self
            if (self.current.kind == .ampersand) {
                _ = self.bump();
                _ = self.matchIdent("mut");
                if (self.checkIdent("self")) {
                    _ = self.bump();
                    _ = self.match(.comma);
                    continue;
                }
            }
            if (self.checkIdent("self")) {
                _ = self.bump();
                _ = self.match(.comma);
                continue;
            }

            if (self.current.kind == .ident) {
                const param_name_tok = self.bump();
                if (self.expect(.colon) == null) break;
                const param_type = self.parseRustType();
                const param_type_info = types.typeNodeToRunarType(param_type);
                params.append(self.allocator, .{
                    .name = snakeToCamel(self.allocator, param_name_tok.text),
                    .type_info = param_type_info,
                    .type_name = runarTypeToTypeName(param_type_info),
                }) catch {};
            } else {
                _ = self.bump();
            }
            _ = self.match(.comma);
        }
        _ = self.expect(.rparen);

        // Optional return type: -> Type
        if (self.current.kind == .arrow) {
            _ = self.bump();
            _ = self.parseRustType(); // consume and discard
        }

        // Parse body
        if (self.expect(.lbrace) == null) {
            return .{ .name = name, .is_public = is_public, .params = params.items, .body = &.{} };
        }
        var body: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            if (self.parseStatement()) |s| body.append(self.allocator, s) catch {};
        }
        _ = self.expect(.rbrace);

        return .{ .name = name, .is_public = is_public, .params = params.items, .body = body.items };
    }

    fn skipToNextMember(self: *Parser) void {
        var depth_val: i32 = 0;
        while (self.current.kind != .eof) {
            if (self.current.kind == .lbrace) {
                depth_val += 1;
                _ = self.bump();
            } else if (self.current.kind == .rbrace) {
                if (depth_val <= 0) return;
                depth_val -= 1;
                _ = self.bump();
                if (depth_val == 0) return;
            } else if (self.current.kind == .semicolon and depth_val == 0) {
                _ = self.bump();
                return;
            } else {
                _ = self.bump();
            }
        }
    }

    // ==================================================================
    // Statement parsing
    // ==================================================================

    fn parseStatement(self: *Parser) ?Statement {
        self.skipSemicolons();
        if (self.current.kind == .rbrace or self.current.kind == .eof) return null;

        // assert!(expr)
        if (std.mem.eql(u8, self.current.text, "assert!") and self.current.kind == .ident) {
            return self.parseAssertMacro();
        }

        // assert_eq!(a, b)
        if (std.mem.eql(u8, self.current.text, "assert_eq!") and self.current.kind == .ident) {
            return self.parseAssertEqMacro();
        }

        // let [mut] name [: Type] = expr;
        if (self.checkIdent("let")) return self.parseLetDecl();

        // if expr { ... } [else { ... }]
        if (self.checkIdent("if")) return self.parseIfStmt();

        // for var in start..end { ... }
        if (self.checkIdent("for")) return self.parseForStmt();

        // return [expr];
        if (self.checkIdent("return")) return self.parseReturnStmt();

        // Expression statement (including assignments and compound assignments)
        return self.parseExpressionStatement();
    }

    fn skipSemicolons(self: *Parser) void {
        while (self.current.kind == .semicolon) _ = self.bump();
    }

    fn parseAssertMacro(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'assert!'
        if (self.expect(.lparen) == null) return null;
        const expr = self.parseExpression() orelse return null;
        _ = self.expect(.rparen);
        _ = self.match(.semicolon);
        return .{ .assert_stmt = .{ .condition = expr } };
    }

    fn parseAssertEqMacro(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'assert_eq!'
        if (self.expect(.lparen) == null) return null;
        const left = self.parseExpression() orelse return null;
        if (self.expect(.comma) == null) return null;
        const right = self.parseExpression() orelse return null;
        _ = self.expect(.rparen);
        _ = self.match(.semicolon);
        // assert_eq!(a, b) -> assert(a === b)
        const bop = self.allocator.create(BinaryOp) catch return null;
        bop.* = .{ .op = .eq, .left = left, .right = right };
        return .{ .assert_stmt = .{ .condition = .{ .binary_op = bop } } };
    }

    fn parseLetDecl(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'let'
        const mutable = self.matchIdent("mut");

        if (self.current.kind != .ident) {
            self.addError("expected variable name");
            return null;
        }
        const name_tok = self.bump();
        const var_name = snakeToCamel(self.allocator, name_tok.text);

        // Optional type annotation
        var ti: ?RunarType = null;
        if (self.current.kind == .colon) {
            _ = self.bump();
            const tn = self.parseRustType();
            ti = types.typeNodeToRunarType(tn);
        }

        // Initializer
        if (self.expect(.assign) == null) return null;
        const val = self.parseExpression() orelse return null;
        _ = self.match(.semicolon);

        if (mutable) {
            return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = val } };
        } else {
            return .{ .const_decl = .{ .name = var_name, .type_info = ti, .value = val } };
        }
    }

    fn parseIfStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'if'
        // Rust-style: no parens around condition
        const cond = self.parseExpression() orelse return null;

        // Then block: { ... }
        if (self.expect(.lbrace) == null) return null;
        var then_stmts: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            if (self.parseStatement()) |s| then_stmts.append(self.allocator, s) catch {};
        }
        _ = self.expect(.rbrace);

        // Optional else
        var else_body: ?[]Statement = null;
        if (self.checkIdent("else")) {
            _ = self.bump();
            if (self.checkIdent("if")) {
                // else if ...
                const nested = self.parseIfStmt() orelse return null;
                const a = self.allocator.alloc(Statement, 1) catch return null;
                a[0] = nested;
                else_body = a;
            } else {
                if (self.expect(.lbrace) == null) return null;
                var else_stmts: std.ArrayListUnmanaged(Statement) = .empty;
                while (self.current.kind != .rbrace and self.current.kind != .eof) {
                    if (self.parseStatement()) |s| else_stmts.append(self.allocator, s) catch {};
                }
                _ = self.expect(.rbrace);
                else_body = else_stmts.items;
            }
        }

        return .{ .if_stmt = .{ .condition = cond, .then_body = then_stmts.items, .else_body = else_body } };
    }

    fn parseForStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'for'

        var var_name: []const u8 = "_i";
        if (self.current.kind == .ident and !self.checkIdent("in")) {
            var_name = snakeToCamel(self.allocator, self.bump().text);
        }

        // Consume 'in'
        if (!self.matchIdent("in")) {
            self.addError("expected 'in' in for loop");
        }

        // Parse range: start..end
        var init_value: i64 = 0;
        var bound: i64 = 0;

        // Parse start value
        if (self.current.kind == .number) {
            const start_tok = self.bump();
            init_value = parseNumberLiteral(start_tok.text);
        } else {
            // Non-literal start — parse as expression and try to extract
            _ = self.parseExpression();
        }

        // Consume '..'
        if (self.current.kind == .dot_dot) {
            _ = self.bump();
        } else {
            self.addError("expected '..' in range expression");
        }

        // Parse end value
        if (self.current.kind == .number) {
            const end_tok = self.bump();
            bound = parseNumberLiteral(end_tok.text);
        } else {
            // Non-literal bound — parse as expression
            const bound_expr = self.parseExpression();
            if (bound_expr) |expr| {
                switch (expr) {
                    .literal_int => |v| {
                        bound = v;
                    },
                    else => {},
                }
            }
        }

        // Body
        if (self.expect(.lbrace) == null) {
            return .{ .for_stmt = .{ .var_name = var_name, .init_value = init_value, .bound = bound, .body = &.{} } };
        }
        var body: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            if (self.parseStatement()) |s| body.append(self.allocator, s) catch {};
        }
        _ = self.expect(.rbrace);

        return .{ .for_stmt = .{ .var_name = var_name, .init_value = init_value, .bound = bound, .body = body.items } };
    }

    fn parseReturnStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'return'

        if (self.current.kind == .semicolon) {
            _ = self.bump();
            return .{ .return_stmt = null };
        }
        if (self.current.kind == .rbrace or self.current.kind == .eof) {
            return .{ .return_stmt = null };
        }

        const expr = self.parseExpression();
        _ = self.match(.semicolon);
        return .{ .return_stmt = expr };
    }

    fn parseExpressionStatement(self: *Parser) ?Statement {
        const expr = self.parseExpression() orelse {
            _ = self.bump();
            return null;
        };

        // Simple assignment: lhs = rhs
        if (self.current.kind == .assign) {
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            _ = self.match(.semicolon);
            return self.buildAssignment(expr, rhs);
        }

        // Compound assignments: +=, -=, *=, /=, %=
        if (isCompoundAssignOp(self.current.kind)) {
            const op_kind = self.current.kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            _ = self.match(.semicolon);
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs);
        }

        const had_semi = self.match(.semicolon);
        // Implicit return: expression without semicolon right before }
        if (!had_semi and self.current.kind == .rbrace) {
            return .{ .return_stmt = expr };
        }

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

    // ==================================================================
    // Expression parsing — precedence climbing
    // ==================================================================
    // Operator precedence (lowest to highest):
    //   ternary (? :)            — not in Rust, but supported for compatibility
    //   logical or (||)
    //   logical and (&&)
    //   bitwise or (|)
    //   bitwise xor (^)
    //   bitwise and (&)
    //   equality (== !=)         — maps to === !==
    //   comparison (< <= > >=)
    //   shift (<< >>)
    //   additive (+ -)
    //   multiplicative (* / %)
    //   unary (! - ~ & &mut)
    //   postfix (. [] () ::)
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
        // Rust doesn't have ternary, but keep the level for consistency
        return self.parseLogicalOr();
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
            // Rust == maps to ===, != maps to !==
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
        // Skip & and &mut reference-taking operators
        if (self.current.kind == .ampersand) {
            _ = self.bump();
            _ = self.matchIdent("mut");
            return self.parsePostfix();
        }
        return self.parsePostfix();
    }

    fn parsePostfix(self: *Parser) ?Expression {
        var expr = self.parsePrimary() orelse return null;
        while (true) {
            if (self.current.kind == .dot) {
                // Member access or method call
                _ = self.bump();
                if (self.current.kind != .ident) {
                    self.addError("expected identifier after '.'");
                    return expr;
                }
                const member_raw = self.bump().text;
                const member = snakeToCamel(self.allocator, member_raw);

                if (self.current.kind == .lparen) {
                    // Method call: expr.method(args)
                    _ = self.bump();
                    const args = self.parseArgList();
                    // `.clone()` is a Rust borrow-checker artifact — in Runar
                    // values are copied by default, so strip it and keep the
                    // receiver expression unchanged.
                    if (args.len == 0 and std.mem.eql(u8, member, "clone")) {
                        continue;
                    }
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "self")) {
                                // self.method(args) -> MethodCall{object="this", method=member}
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
                            if (std.mem.eql(u8, id, "self")) {
                                // self.property -> PropertyAccess{object="this", property=member}
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
            } else if (self.current.kind == .colon_colon) {
                // Path separator: Type::method — take the last segment
                _ = self.bump();
                if (self.current.kind == .ident) {
                    const path_name = snakeToCamel(self.allocator, self.bump().text);
                    expr = .{ .identifier = path_name };
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
                // Direct call: expr(...)
                switch (expr) {
                    .identifier => |id| {
                        _ = self.bump();
                        const args = self.parseArgList();
                        const call = self.allocator.create(CallExpr) catch return null;
                        call.* = .{ .callee = id, .args = args };
                        expr = .{ .call = call };
                    },
                    else => break,
                }
            } else break;
        }
        return expr;
    }

    fn parsePrimary(self: *Parser) ?Expression {
        return switch (self.current.kind) {
            .number => blk: {
                const tok = self.bump();
                const val = parseNumberLiteral(tok.text);
                break :blk Expression{ .literal_int = val };
            },
            .hex_string => blk: {
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
                if (std.mem.eql(u8, name, "self")) break :blk Expression{ .identifier = "self" };
                if (std.mem.eql(u8, name, "Self")) break :blk Expression{ .identifier = "Self" };

                // Skip `as Type` cast expressions
                // (handled after parsing — caller sees the operand only)

                // Map builtin names
                const mapped = mapBuiltin(self.allocator, name);
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

    // ---- Helpers ----

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

/// Parse a number literal, stripping underscores and type suffixes.
fn parseNumberLiteral(text: []const u8) i64 {
    var stripped_buf: [64]u8 = undefined;
    var stripped_len: usize = 0;
    for (text) |ch| {
        // Stop at type suffix (i128, u64, etc.)
        if ((ch == 'i' or ch == 'u') and stripped_len > 0) break;
        if (ch != '_' and stripped_len < stripped_buf.len) {
            stripped_buf[stripped_len] = ch;
            stripped_len += 1;
        }
    }
    const stripped = stripped_buf[0..stripped_len];
    return std.fmt.parseInt(i64, stripped, 0) catch 0;
}

// ============================================================================
// Tests
// ============================================================================

test "rust tokenizer basics" {
    var t = Tokenizer.init("#[runar::contract] struct P2PKH { }");
    try std.testing.expectEqual(TokenKind.hash_bracket, t.next().kind);
    const id1 = t.next();
    try std.testing.expectEqualStrings("runar", id1.text);
    try std.testing.expectEqual(TokenKind.colon_colon, t.next().kind);
    const id2 = t.next();
    try std.testing.expectEqualStrings("contract", id2.text);
    try std.testing.expectEqual(TokenKind.rbracket, t.next().kind);
    const id3 = t.next();
    try std.testing.expectEqualStrings("struct", id3.text);
    const id4 = t.next();
    try std.testing.expectEqualStrings("P2PKH", id4.text);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "rust tokenizer operators" {
    var t = Tokenizer.init("== != <= >= << >> && || += -= -> :: ..");
    const expected = [_]TokenKind{
        .eqeq,     .bang_eq,    .lt_eq,     .gt_eq,
        .lshift,   .rshift,     .amp_amp,   .pipe_pipe,
        .plus_eq,  .minus_eq,   .arrow,     .colon_colon,
        .dot_dot,  .eof,
    };
    for (expected) |e| try std.testing.expectEqual(e, t.next().kind);
}

test "rust tokenizer assert macro" {
    var t = Tokenizer.init("assert!(x) assert_eq!(a, b)");
    const tok1 = t.next();
    try std.testing.expectEqual(TokenKind.ident, tok1.kind);
    try std.testing.expectEqualStrings("assert!", tok1.text);
    try std.testing.expectEqual(TokenKind.lparen, t.next().kind);
    try std.testing.expectEqual(TokenKind.ident, t.next().kind); // x
    try std.testing.expectEqual(TokenKind.rparen, t.next().kind);
    const tok2 = t.next();
    try std.testing.expectEqual(TokenKind.ident, tok2.kind);
    try std.testing.expectEqualStrings("assert_eq!", tok2.text);
}

test "rust tokenizer hex literal" {
    var t = Tokenizer.init("0xff 0xDEAD");
    const n1 = t.next();
    try std.testing.expectEqual(TokenKind.hex_string, n1.kind);
    try std.testing.expectEqualStrings("ff", n1.text);
    const n2 = t.next();
    try std.testing.expectEqual(TokenKind.hex_string, n2.kind);
    try std.testing.expectEqualStrings("DEAD", n2.text);
}

test "rust tokenizer double-quoted string" {
    var t = Tokenizer.init("\"hello\"");
    const tok = t.next();
    try std.testing.expectEqual(TokenKind.hex_string, tok.kind);
    try std.testing.expectEqualStrings("hello", tok.text);
}

test "rust tokenizer comments" {
    var t = Tokenizer.init("// line comment\nstruct /* block\n comment */ X { }");
    try std.testing.expectEqualStrings("struct", t.next().text);
    try std.testing.expectEqualStrings("X", t.next().text);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "snake_to_camel conversion" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("pubKeyHash", snakeToCamel(a, "pub_key_hash"));
    try std.testing.expectEqualStrings("checkSig", snakeToCamel(a, "check_sig"));
    try std.testing.expectEqualStrings("count", snakeToCamel(a, "count"));
    try std.testing.expectEqualStrings("txPreimage", snakeToCamel(a, "tx_preimage"));
}

test "parse P2PKH contract (Rust DSL)" {
    const source =
        \\use runar::prelude::*;
        \\
        \\#[runar::contract]
        \\struct P2PKH {
        \\    #[readonly]
        \\    pub_key_hash: Addr,
        \\}
        \\
        \\#[runar::methods(P2PKH)]
        \\impl P2PKH {
        \\    #[public]
        \\    fn unlock(&self, sig: Sig, pub_key: PubKey) {
        \\        assert!(hash160(pub_key) == self.pub_key_hash);
        \\        assert!(check_sig(sig, pub_key));
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseRust(arena.allocator(), source, "P2PKH.runar.rs");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
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
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].body.len);
}

test "parse Counter contract (stateful, Rust DSL)" {
    const source =
        \\use runar::prelude::*;
        \\
        \\#[runar::contract]
        \\pub struct Counter {
        \\    pub count: Bigint,
        \\}
        \\
        \\#[runar::methods(Counter)]
        \\impl Counter {
        \\    #[public]
        \\    pub fn increment(&mut self) {
        \\        self.count += 1;
        \\    }
        \\
        \\    #[public]
        \\    pub fn decrement(&mut self) {
        \\        assert!(self.count > 0);
        \\        self.count -= 1;
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseRust(arena.allocator(), source, "Counter.runar.rs");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Counter", c.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("count", c.properties[0].name);
    try std.testing.expect(!c.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expectEqualStrings("decrement", c.methods[1].name);
}

test "parse Auction contract (Rust DSL)" {
    const source =
        \\use runar::prelude::*;
        \\
        \\#[runar::contract]
        \\struct Auction {
        \\    #[readonly]
        \\    auctioneer: PubKey,
        \\    highest_bidder: PubKey,
        \\    highest_bid: Bigint,
        \\    #[readonly]
        \\    deadline: Bigint,
        \\}
        \\
        \\#[runar::methods(Auction)]
        \\impl Auction {
        \\    #[public]
        \\    fn bid(&mut self, sig: Sig, bidder: PubKey, bid_amount: Bigint) {
        \\        assert!(check_sig(sig, bidder));
        \\        assert!(bid_amount > self.highest_bid);
        \\        self.highest_bidder = bidder;
        \\        self.highest_bid = bid_amount;
        \\    }
        \\
        \\    #[public]
        \\    fn close(&mut self, sig: Sig) {
        \\        assert!(check_sig(sig, self.auctioneer));
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseRust(arena.allocator(), source, "Auction.runar.rs");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Auction", c.name);
    try std.testing.expectEqual(@as(usize, 4), c.properties.len);
    try std.testing.expect(c.properties[0].readonly); // auctioneer
    try std.testing.expect(!c.properties[1].readonly); // highest_bidder
    try std.testing.expect(!c.properties[2].readonly); // highest_bid
    try std.testing.expect(c.properties[3].readonly); // deadline
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
}

test "parse BoundedLoop contract with for..in range (Rust DSL)" {
    const source =
        \\use runar::prelude::*;
        \\
        \\#[runar::contract]
        \\struct BoundedLoop {
        \\    #[readonly]
        \\    expected_sum: Int,
        \\}
        \\
        \\#[runar::methods(BoundedLoop)]
        \\impl BoundedLoop {
        \\    #[public]
        \\    fn verify(&self, start: Int) {
        \\        let mut sum: Int = 0;
        \\        for i in 0..5 {
        \\            sum = sum + start + i;
        \\        }
        \\        assert!(sum == self.expected_sum);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseRust(arena.allocator(), source, "BoundedLoop.runar.rs");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("BoundedLoop", c.name);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    // Method body: let, for, assert
    try std.testing.expectEqual(@as(usize, 3), c.methods[0].body.len);
    // Check the for loop
    const for_stmt = c.methods[0].body[1].for_stmt;
    try std.testing.expectEqualStrings("i", for_stmt.var_name);
    try std.testing.expectEqual(@as(i64, 0), for_stmt.init_value);
    try std.testing.expectEqual(@as(i64, 5), for_stmt.bound);
}

test "parse PropertyInitializers with init method (Rust DSL)" {
    const source =
        \\use runar::prelude::*;
        \\
        \\#[runar::contract]
        \\struct PropertyInitializers {
        \\    count: Int,
        \\    #[readonly]
        \\    max_count: Int,
        \\    #[readonly]
        \\    active: Bool,
        \\}
        \\
        \\#[runar::methods(PropertyInitializers)]
        \\impl PropertyInitializers {
        \\    fn init(&mut self) {
        \\        self.count = 0;
        \\        self.active = true;
        \\    }
        \\
        \\    #[public]
        \\    fn increment(&mut self, amount: Int) {
        \\        assert!(self.active);
        \\        self.count = self.count + amount;
        \\        assert!(self.count <= self.max_count);
        \\    }
        \\
        \\    #[public]
        \\    fn reset(&mut self) {
        \\        self.count = 0;
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseRust(arena.allocator(), source, "PropertyInitializers.runar.rs");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("PropertyInitializers", c.name);

    // count should have initializer (0), active should have initializer (true)
    try std.testing.expect(c.properties[0].initializer != null); // count = 0
    try std.testing.expect(c.properties[2].initializer != null); // active = true

    // Only maxCount should be in the constructor params (uninitialised + readonly)
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqualStrings("maxCount", c.constructor.params[0].name);

    // init() should NOT appear in methods
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
    try std.testing.expectEqualStrings("reset", c.methods[1].name);
}

test "parse number literal with underscores and suffix" {
    try std.testing.expectEqual(@as(i64, 1000000), parseNumberLiteral("1_000_000"));
    try std.testing.expectEqual(@as(i64, 42), parseNumberLiteral("42i128"));
    try std.testing.expectEqual(@as(i64, 100), parseNumberLiteral("100u64"));
    try std.testing.expectEqual(@as(i64, 0), parseNumberLiteral("0"));
}
