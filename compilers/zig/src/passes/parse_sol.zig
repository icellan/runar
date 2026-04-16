//! Pass 1 (Solidity frontend): Hand-written tokenizer + recursive descent parser for .runar.sol files.
//!
//! Parses Solidity-like syntax into the Runar IR ContractNode.
//!
//! Syntax conventions:
//!   - `pragma runar ^0.1.0;` at top (skipped)
//!   - `contract Name is SmartContract { ... }` declares the contract
//!   - `Type immutable name;` for immutable (readonly) properties
//!   - `Type name;` for mutable properties
//!   - `Type name = value;` for properties with initializers
//!   - `constructor(Type _name, ...) { name = _name; }` is the constructor
//!   - `function name(Type name, ...) public { ... }` are public methods
//!   - `function name(Type name, ...) [private] { ... }` are private methods
//!   - `require(cond)` maps to `assert(cond)`
//!   - `==` maps to `===`, `!=` maps to `!==`
//!   - `keccak256(...)` is an alias for `sha256(...)`
//!   - Types before names: `int`/`uint`/`int256`/`uint256` -> bigint, `bool` -> boolean,
//!     `bytes`/`bytes32` -> ByteString, `address` -> Addr
//!   - `immutable` keyword instead of `readonly`
//!   - Integer division with `/` (no `//`)
//!   - `&&`, `||` for logical operators
//!   - Supports `if`, `else`, `for` loops, variable declarations with `Type name = expr;`

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

pub fn parseSol(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
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
            // Return text without quotes
            const end = self.pos;
            const content_start = start + 1;
            const content_end = if (end > 0) end - 1 else end;
            return .{ .kind = .string_literal, .text = self.source[content_start..content_end], .line = sl, .col = sc };
        }

        // Numbers (decimal, hex; strip trailing 'n' for BigInt)
        if (c >= '0' and c <= '9') {
            if (c == '0' and (self.peekAt(1) == 'x' or self.peekAt(1) == 'X')) {
                _ = self.advance(); // '0'
                _ = self.advance(); // 'x'
                while (self.pos < self.source.len and isHexDigit(self.source[self.pos])) _ = self.advance();
            } else {
                while (self.pos < self.source.len and ((self.source[self.pos] >= '0' and self.source[self.pos] <= '9') or self.source[self.pos] == '_')) _ = self.advance();
            }
            // Strip trailing BigInt suffix 'n'
            const num_end = self.pos;
            if (self.pos < self.source.len and self.source[self.pos] == 'n') _ = self.advance();
            return .{ .kind = .number, .text = self.source[start..num_end], .line = sl, .col = sc };
        }

        // Identifiers and keywords
        if (isIdentStart(c)) {
            while (self.pos < self.source.len and isIdentChar(self.source[self.pos])) _ = self.advance();
            const text = self.source[start..self.pos];
            return .{ .kind = .ident, .text = text, .line = sl, .col = sc };
        }

        // Operators: advance first char, then check multi-char
        _ = self.advance();
        const c2 = self.peek();

        // Two-character operators first
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
            ':' => .{ .kind = .colon, .text = t, .line = sl, .col = sc },
            '?' => .{ .kind = .question, .text = t, .line = sl, .col = sc },
            '~' => .{ .kind = .tilde, .text = t, .line = sl, .col = sc },
            '^' => .{ .kind = .caret, .text = t, .line = sl, .col = sc },
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
        return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_' or c == '$';
    }

    fn isIdentChar(c: u8) bool {
        return isIdentStart(c) or (c >= '0' and c <= '9');
    }

    fn isHexDigit(c: u8) bool {
        return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
    }
};

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
        self.skipPragmaAndImports();
        const contract = self.parseContractDecl();
        return .{ .contract = contract, .errors = self.errors.items };
    }

    /// Skip `pragma runar ^0.1.0;` and any `import` statements.
    fn skipPragmaAndImports(self: *Parser) void {
        // Skip pragma
        if (self.checkIdent("pragma")) {
            while (self.current.kind != .semicolon and self.current.kind != .eof) _ = self.bump();
            _ = self.match(.semicolon);
        }
        // Skip import statements
        while (self.checkIdent("import")) {
            while (self.current.kind != .semicolon and self.current.kind != .eof) _ = self.bump();
            _ = self.match(.semicolon);
        }
    }

    // ---- Contract declaration ----

    fn parseContractDecl(self: *Parser) ?ContractNode {
        if (!self.matchIdent("contract")) {
            self.addError("expected 'contract' keyword");
            return null;
        }

        // Contract name
        if (self.current.kind != .ident) {
            self.addError("expected contract name");
            return null;
        }
        const name_tok = self.bump();

        // is ParentClass
        var parent_class: ParentClass = .smart_contract;
        if (self.matchIdent("is")) {
            if (self.current.kind != .ident) {
                self.addError("expected parent class name after 'is'");
                return null;
            }
            const parent_tok = self.bump();
            if (ParentClass.fromTsString(parent_tok.text)) |pc| {
                parent_class = pc;
            } else {
                self.addErrorFmt("unknown parent class: '{s}', expected SmartContract or StatefulSmartContract", .{parent_tok.text});
                return null;
            }
        }

        if (self.expect(.lbrace) == null) return null;

        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;
        var constructor: ?ConstructorNode = null;
        var methods: std.ArrayListUnmanaged(MethodNode) = .empty;

        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            self.skipSemicolons();
            if (self.current.kind == .rbrace or self.current.kind == .eof) break;

            if (self.checkIdent("function")) {
                const m = self.parseFunction();
                methods.append(self.allocator, m) catch {};
            } else if (self.checkIdent("constructor")) {
                if (constructor != null) self.addError("duplicate constructor");
                constructor = self.parseSolConstructor(properties.items);
            } else {
                // Try to parse as property: Type [immutable] name [= value];
                if (self.parseSolProperty(parent_class)) |prop| {
                    properties.append(self.allocator, prop) catch {};
                }
            }
        }
        _ = self.expect(.rbrace);

        // Auto-generate constructor if none was provided
        if (constructor == null) {
            constructor = self.autoGenerateConstructor(properties.items);
        }

        return ContractNode{
            .name = name_tok.text,
            .parent_class = parent_class,
            .properties = properties.items,
            .constructor = constructor.?,
            .methods = methods.items,
        };
    }

    fn skipSemicolons(self: *Parser) void {
        while (self.current.kind == .semicolon) _ = self.bump();
    }

    // ---- Property parsing: Type [immutable] name [= value]; ----

    fn parseSolProperty(self: *Parser, parent_class: ParentClass) ?PropertyNode {
        // The current token should be a type identifier
        if (self.current.kind != .ident) {
            // Skip unknown token
            _ = self.bump();
            return null;
        }

        const type_tok = self.bump();
        const type_name = type_tok.text;

        // Check for immutable keyword
        var is_readonly = false;
        if (self.checkIdent("immutable")) {
            _ = self.bump();
            is_readonly = true;
        }

        // Property name
        if (self.current.kind != .ident) {
            self.addErrorFmt("expected property name after type '{s}'", .{type_name});
            self.skipToSemicolon();
            return null;
        }
        const name_tok = self.bump();

        // Optional initializer: = value
        var initializer: ?Expression = null;
        if (self.current.kind == .assign) {
            _ = self.bump();
            initializer = self.parseExpression();
        }

        _ = self.match(.semicolon);

        // For SmartContract, all fields are readonly
        const readonly = if (parent_class == .smart_contract) true else is_readonly;

        return .{
            .name = name_tok.text,
            .type_info = resolveSolType(type_name),
            .readonly = readonly,
            .initializer = initializer,
        };
    }

    fn skipToSemicolon(self: *Parser) void {
        while (self.current.kind != .semicolon and self.current.kind != .eof and self.current.kind != .rbrace) _ = self.bump();
        _ = self.match(.semicolon);
    }

    /// Map Solidity-style type names to RunarType.
    fn resolveSolType(name: []const u8) RunarType {
        // Solidity-specific type aliases
        if (std.mem.eql(u8, name, "int") or std.mem.eql(u8, name, "uint") or
            std.mem.eql(u8, name, "int256") or std.mem.eql(u8, name, "uint256"))
            return .bigint;
        if (std.mem.eql(u8, name, "bool")) return .boolean;
        if (std.mem.eql(u8, name, "bytes") or std.mem.eql(u8, name, "bytes32")) return .byte_string;
        if (std.mem.eql(u8, name, "address")) return .addr;
        if (std.mem.eql(u8, name, "string")) return .byte_string;

        // Standard Runar type names (PubKey, Sig, Addr, ByteString, bigint, etc.)
        if (std.mem.eql(u8, name, "bigint")) return .bigint;
        if (std.mem.eql(u8, name, "boolean")) return .boolean;
        if (std.mem.eql(u8, name, "PubKey")) return .pub_key;
        if (std.mem.eql(u8, name, "Sig")) return .sig;
        if (std.mem.eql(u8, name, "Addr")) return .addr;
        if (std.mem.eql(u8, name, "ByteString")) return .byte_string;
        if (std.mem.eql(u8, name, "Sha256")) return .sha256;
        if (std.mem.eql(u8, name, "Ripemd160")) return .ripemd160;
        if (std.mem.eql(u8, name, "SigHashPreimage")) return .sig_hash_preimage;
        if (std.mem.eql(u8, name, "RabinSig")) return .rabin_sig;
        if (std.mem.eql(u8, name, "RabinPubKey")) return .rabin_pub_key;
        if (std.mem.eql(u8, name, "Point")) return .point;
        if (std.mem.eql(u8, name, "P256Point")) return .byte_string;
        if (std.mem.eql(u8, name, "P384Point")) return .byte_string;
        if (std.mem.eql(u8, name, "void")) return .void;

        // Also check via PrimitiveTypeName for any we missed
        if (PrimitiveTypeName.fromTsString(name)) |ptn| {
            return types.typeNodeToRunarType(.{ .primitive_type = ptn });
        }

        return .unknown;
    }

    /// Map a RunarType back to its canonical string name.
    fn runarTypeToTypeName(t: RunarType) []const u8 {
        return types.runarTypeToString(t);
    }

    // ---- Constructor: constructor(Type _name, ...) { ... } ----

    fn parseSolConstructor(self: *Parser, properties: []const PropertyNode) ConstructorNode {
        _ = self.bump(); // consume 'constructor'
        const params = self.parseSolParams();
        const body = self.parseBlock();

        // Build super_args from params
        var super_args: std.ArrayListUnmanaged(Expression) = .empty;
        for (params) |param| {
            super_args.append(self.allocator, .{ .identifier = param.name }) catch {};
        }

        // Extract assignments from body (name = _name patterns).
        // Constructor params are stored without the leading underscore, but the
        // body may still reference `_name` — rewrite those references back to
        // the stripped param name so the ANF lowerer treats them consistently
        // with the other compilers (TS/Go/Rust/Python/Ruby).
        var assignments: std.ArrayListUnmanaged(AssignmentNode) = .empty;
        for (body) |stmt| {
            switch (stmt) {
                .assign => |assign| {
                    const renamed_value = self.solRenameUnderscoreIdents(assign.value, params);
                    assignments.append(self.allocator, .{ .target = assign.target, .value = renamed_value }) catch {};
                },
                .expr_stmt => |expr| {
                    // Check if it's a call to assert/require (skip)
                    switch (expr) {
                        .call => {},
                        else => {},
                    }
                },
                else => {},
            }
        }

        // If no explicit assignments but there are properties, auto-generate them
        // from matching constructor params
        if (assignments.items.len == 0 and properties.len > 0) {
            for (properties) |prop| {
                if (prop.initializer != null) continue; // skip initialized props
                for (params) |param| {
                    if (std.mem.eql(u8, param.name, prop.name)) {
                        assignments.append(self.allocator, .{
                            .target = prop.name,
                            .value = .{ .identifier = param.name },
                        }) catch {};
                        break;
                    }
                }
            }
        }

        return .{
            .params = params,
            .super_args = super_args.items,
            .assignments = assignments.items,
        };
    }

    /// Auto-generate a constructor for contracts without an explicit one.
    /// Only non-initialized properties become constructor params.
    fn autoGenerateConstructor(self: *Parser, properties: []const PropertyNode) ConstructorNode {
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;
        var super_args: std.ArrayListUnmanaged(Expression) = .empty;
        var assignments: std.ArrayListUnmanaged(AssignmentNode) = .empty;

        for (properties) |prop| {
            if (prop.initializer != null) continue;
            params.append(self.allocator, .{
                .name = prop.name,
                .type_info = prop.type_info,
                .type_name = runarTypeToTypeName(prop.type_info),
            }) catch {};
            super_args.append(self.allocator, .{ .identifier = prop.name }) catch {};
            assignments.append(self.allocator, .{
                .target = prop.name,
                .value = .{ .identifier = prop.name },
            }) catch {};
        }

        return .{
            .params = params.items,
            .super_args = super_args.items,
            .assignments = assignments.items,
        };
    }

    // ---- Function: function name(Type name, ...) [public|private|...] { ... } ----

    fn parseFunction(self: *Parser) MethodNode {
        _ = self.bump(); // consume 'function'

        var name: []const u8 = "anonymous";
        if (self.current.kind == .ident) {
            name = self.bump().text;
        } else {
            self.addError("expected function name");
        }

        const params = self.parseSolParams();

        // Parse visibility modifiers and skip 'returns (Type)' clauses
        var is_public = false;
        while (self.current.kind == .ident) {
            const mod = self.current.text;
            if (std.mem.eql(u8, mod, "public") or std.mem.eql(u8, mod, "external")) {
                is_public = true;
                _ = self.bump();
            } else if (std.mem.eql(u8, mod, "private") or std.mem.eql(u8, mod, "internal")) {
                _ = self.bump();
            } else if (std.mem.eql(u8, mod, "view") or std.mem.eql(u8, mod, "pure") or std.mem.eql(u8, mod, "payable")) {
                _ = self.bump();
            } else if (std.mem.eql(u8, mod, "returns")) {
                _ = self.bump();
                // Skip (Type) clause
                if (self.current.kind == .lparen) {
                    _ = self.bump();
                    var paren_depth: u32 = 1;
                    while (paren_depth > 0 and self.current.kind != .eof) {
                        if (self.current.kind == .lparen) paren_depth += 1;
                        if (self.current.kind == .rparen) paren_depth -= 1;
                        _ = self.bump();
                    }
                }
            } else break;
        }

        const body = self.parseBlock();
        return .{ .name = name, .is_public = is_public, .params = params, .body = body };
    }

    // ---- Parameters: (Type name, Type name, ...) ----
    // Solidity style: type comes before name, strip leading underscores

    fn parseSolParams(self: *Parser) []ParamNode {
        _ = self.expect(.lparen);
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;

        while (self.current.kind != .rparen and self.current.kind != .eof) {
            // Type name
            if (self.current.kind != .ident) break;
            const type_tok = self.bump();
            const type_name = type_tok.text;

            // Skip memory/storage/calldata qualifiers
            while (self.current.kind == .ident and
                (std.mem.eql(u8, self.current.text, "memory") or
                std.mem.eql(u8, self.current.text, "storage") or
                std.mem.eql(u8, self.current.text, "calldata")))
            {
                _ = self.bump();
            }

            // Parameter name
            if (self.current.kind != .ident) {
                self.addErrorFmt("expected parameter name after type '{s}'", .{type_name});
                break;
            }
            const name_tok = self.bump();
            const raw_name = name_tok.text;

            // Strip leading underscore (Solidity convention)
            const clean_name = if (raw_name.len > 1 and raw_name[0] == '_')
                raw_name[1..]
            else
                raw_name;

            const type_info = resolveSolType(type_name);

            params.append(self.allocator, .{
                .name = clean_name,
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

    // ---- Block parsing: { statements... } ----

    fn parseBlock(self: *Parser) []Statement {
        if (self.expect(.lbrace) == null) return &.{};
        var stmts: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            self.skipSemicolons();
            if (self.current.kind == .rbrace or self.current.kind == .eof) break;
            if (self.parseStatement()) |s| stmts.append(self.allocator, s) catch {};
        }
        _ = self.expect(.rbrace);
        return stmts.items;
    }

    // ---- Statements ----

    fn parseStatement(self: *Parser) ?Statement {
        // require(...) -> assert(...)
        if (self.checkIdent("require")) return self.parseRequire();

        // assert(...) -> assert(...)
        if (self.checkIdent("assert")) return self.parseAssert();

        // if (...) { ... } [else { ... }]
        if (self.checkIdent("if")) return self.parseIfStmt();

        // for (...) { ... }
        if (self.checkIdent("for")) return self.parseForStmt();

        // return ...;
        if (self.checkIdent("return")) return self.parseReturnStmt();

        // Variable declaration: Type name = expr;
        // We detect this by checking if current is a type identifier followed by another identifier
        if (self.current.kind == .ident and self.isTypeStart()) {
            return self.parseSolVarDecl();
        }

        // Expression statement (including assignments and calls)
        return self.parseExpressionStatement();
    }

    /// Check if the current token looks like a type name (for "Type name" pattern).
    /// Returns true if the current identifier is a known type and the next token is also an identifier.
    fn isTypeStart(self: *Parser) bool {
        if (self.current.kind != .ident) return false;

        // Peek at the next token to see if it's an identifier
        // We save tokenizer state for look-ahead
        const saved_pos = self.tokenizer.pos;
        const saved_line = self.tokenizer.line;
        const saved_col = self.tokenizer.col;
        const next_tok = self.tokenizer.next();
        self.tokenizer.pos = saved_pos;
        self.tokenizer.line = saved_line;
        self.tokenizer.col = saved_col;

        if (next_tok.kind != .ident) return false;

        // Check if current token looks like a type
        const name = self.current.text;
        // Also check for "immutable" as a keyword after the type (e.g. "int immutable x")
        if (std.mem.eql(u8, next_tok.text, "immutable")) return false; // that's a property, not a local var

        // Known Solidity and Runar types
        if (resolveSolType(name) != .unknown) return true;
        // Capitalized names are likely types
        if (name.len > 0 and name[0] >= 'A' and name[0] <= 'Z') return true;

        return false;
    }

    fn parseRequire(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'require'
        if (self.expect(.lparen) == null) return null;
        const cond = self.parseExpression() orelse return null;
        // Skip optional error message parameter
        if (self.current.kind == .comma) {
            _ = self.bump();
            _ = self.parseExpression(); // discard error message
        }
        _ = self.expect(.rparen);
        self.skipSemicolons();
        return .{ .assert_stmt = .{ .condition = cond } };
    }

    fn parseAssert(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'assert'
        if (self.expect(.lparen) == null) return null;
        const cond = self.parseExpression() orelse return null;
        _ = self.expect(.rparen);
        self.skipSemicolons();
        return .{ .assert_stmt = .{ .condition = cond } };
    }

    fn parseIfStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'if'
        if (self.expect(.lparen) == null) return null;
        const cond = self.parseExpression() orelse return null;
        if (self.expect(.rparen) == null) return null;

        const then_body = self.parseBlockOrStatement();

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
                else_body = self.parseBlockOrStatement();
            }
        }

        return .{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body } };
    }

    fn parseBlockOrStatement(self: *Parser) []Statement {
        if (self.current.kind == .lbrace) return self.parseBlock();
        if (self.parseStatement()) |s| {
            const a = self.allocator.alloc(Statement, 1) catch return &.{};
            a[0] = s;
            return a;
        }
        return &.{};
    }

    fn parseForStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'for'
        if (self.expect(.lparen) == null) return null;

        // For now, parse C-style for loops: for (Type i = 0; i < N; i++)
        // Extract: var_name, init_value, bound
        var var_name: []const u8 = "_i";
        var init_value: i64 = 0;
        var bound: i64 = 0;

        // Initializer: Type varname = expr OR let/const varname = expr
        if (self.current.kind == .ident and self.isTypeStart()) {
            // Solidity style: int i = 0
            _ = self.bump(); // skip type
            if (self.current.kind == .ident) {
                var_name = self.bump().text;
                if (self.current.kind == .assign) {
                    _ = self.bump();
                    if (self.current.kind == .number) {
                        init_value = std.fmt.parseInt(i64, self.bump().text, 0) catch 0;
                    } else {
                        _ = self.parseExpression();
                    }
                }
            }
        } else if (self.checkIdent("let") or self.checkIdent("const")) {
            _ = self.bump();
            if (self.current.kind == .ident) {
                var_name = self.bump().text;
                if (self.current.kind == .assign) {
                    _ = self.bump();
                    if (self.current.kind == .number) {
                        init_value = std.fmt.parseInt(i64, self.bump().text, 0) catch 0;
                    } else {
                        _ = self.parseExpression();
                    }
                }
            }
        } else {
            // Skip non-standard initializer
            while (self.current.kind != .semicolon and self.current.kind != .eof) _ = self.bump();
        }
        self.skipSemicolons();

        // Condition: i < N
        if (self.current.kind != .semicolon) {
            const cond_expr = self.parseExpression();
            if (cond_expr) |expr| {
                switch (expr) {
                    .binary_op => |bop| {
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
        }
        self.skipSemicolons();

        // Update: i++ / i += 1, etc. -- skip
        if (self.current.kind != .rparen) {
            _ = self.parseExpression();
        }
        if (self.expect(.rparen) == null) return null;

        const body = self.parseBlockOrStatement();

        return .{ .for_stmt = .{ .var_name = var_name, .init_value = init_value, .bound = bound, .body = body } };
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
        self.skipSemicolons();
        return .{ .return_stmt = expr };
    }

    fn parseSolVarDecl(self: *Parser) ?Statement {
        // Type name [= expr];
        const type_tok = self.bump(); // consume type
        const type_name = type_tok.text;

        if (self.current.kind != .ident) {
            self.addErrorFmt("expected variable name after type '{s}'", .{type_name});
            return null;
        }
        const name_tok = self.bump();

        var val: ?Expression = null;
        if (self.current.kind == .assign) {
            _ = self.bump();
            val = self.parseExpression();
        } else {
            // Default to 0 for uninitialized variables
            val = .{ .literal_int = 0 };
        }

        self.skipSemicolons();

        // Solidity variables are mutable (let_decl)
        const ti = resolveSolType(type_name);
        return .{ .let_decl = .{ .name = name_tok.text, .type_info = ti, .value = val } };
    }

    fn parseExpressionStatement(self: *Parser) ?Statement {
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

    fn makeBinaryExpr(self: *Parser, op: BinOperator, left: Expression, right: Expression) ?Expression {
        const bop = self.allocator.create(BinaryOp) catch return null;
        bop.* = .{ .op = op, .left = left, .right = right };
        return .{ .binary_op = bop };
    }

    /// Recursively rewrite identifiers `_name` -> `name` whenever `name` is the
    /// stripped form of a constructor parameter. Used to clean constructor body
    /// expressions so that the ANF lowerer doesn't see stale `_xxx` references.
    fn solRenameUnderscoreIdents(self: *Parser, expr: Expression, params: []const ParamNode) Expression {
        switch (expr) {
            .identifier => |name| {
                if (name.len > 1 and name[0] == '_') {
                    const stripped = name[1..];
                    for (params) |p| {
                        if (std.mem.eql(u8, p.name, stripped)) {
                            return .{ .identifier = stripped };
                        }
                    }
                }
                return expr;
            },
            .binary_op => |bop| {
                bop.left = self.solRenameUnderscoreIdents(bop.left, params);
                bop.right = self.solRenameUnderscoreIdents(bop.right, params);
                return expr;
            },
            .unary_op => |uop| {
                uop.operand = self.solRenameUnderscoreIdents(uop.operand, params);
                return expr;
            },
            .call => |c| {
                for (c.args, 0..) |arg, i| {
                    c.args[i] = self.solRenameUnderscoreIdents(arg, params);
                }
                return expr;
            },
            .method_call => |mc| {
                for (mc.args, 0..) |arg, i| {
                    mc.args[i] = self.solRenameUnderscoreIdents(arg, params);
                }
                return expr;
            },
            .ternary => |t| {
                t.condition = self.solRenameUnderscoreIdents(t.condition, params);
                t.then_expr = self.solRenameUnderscoreIdents(t.then_expr, params);
                t.else_expr = self.solRenameUnderscoreIdents(t.else_expr, params);
                return expr;
            },
            .index_access => |ia| {
                ia.object = self.solRenameUnderscoreIdents(ia.object, params);
                ia.index = self.solRenameUnderscoreIdents(ia.index, params);
                return expr;
            },
            else => return expr,
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
    //   equality (== !=)  -- mapped to === !==
    //   comparison (< <= > >=)
    //   shift (<< >>)
    //   additive (+ -)
    //   multiplicative (* / %)
    //   unary (! - ~ ++ --)
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
        // Solidity uses == and != which we map to === and !==
        while (self.current.kind == .eqeq or self.current.kind == .bang_eq) {
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
                const member = self.bump().text;

                if (self.current.kind == .lparen) {
                    // Method call: expr.method(args)
                    _ = self.bump();
                    const args = self.parseArgList();
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "this")) {
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
            } else if (self.current.kind == .lbracket) {
                // Index access: expr[index]
                _ = self.bump();
                const idx = self.parseExpression() orelse return null;
                _ = self.expect(.rbracket);
                const ia = self.allocator.create(IndexAccess) catch return null;
                ia.* = .{ .object = expr, .index = idx };
                expr = .{ .index_access = ia };
            } else if (self.current.kind == .lparen) {
                // Direct call: expr(...) -- only for identifiers
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
                // Hex literals with even digit count → ByteString (Solidity convention)
                if (stripped.len > 2 and stripped[0] == '0' and (stripped[1] == 'x' or stripped[1] == 'X')) {
                    const hex_digits = stripped[2..];
                    if (hex_digits.len > 0 and hex_digits.len % 2 == 0) {
                        // Even number of hex digits → byte string literal
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
                break :blk self.parseArrayLiteral();
            },
            .ident => blk: {
                const tok = self.bump();
                const name = tok.text;

                if (std.mem.eql(u8, name, "true")) break :blk Expression{ .literal_bool = true };
                if (std.mem.eql(u8, name, "false")) break :blk Expression{ .literal_bool = false };
                if (std.mem.eql(u8, name, "this")) break :blk Expression{ .identifier = "this" };

                // keccak256 is an alias for sha256
                const callee_name = if (std.mem.eql(u8, name, "keccak256")) "sha256" else name;

                // Function call: name(...)
                if (self.current.kind == .lparen) {
                    _ = self.bump();
                    const args = self.parseArgList();
                    const call = self.allocator.create(CallExpr) catch break :blk null;
                    call.* = .{ .callee = callee_name, .args = args };
                    break :blk Expression{ .call = call };
                }

                break :blk Expression{ .identifier = callee_name };
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

// ============================================================================
// Tests
// ============================================================================

test "sol tokenizer basics" {
    var t = Tokenizer.init("contract P2PKH is SmartContract { }");
    try std.testing.expectEqual(TokenKind.ident, t.next().kind); // contract
    const id = t.next();
    try std.testing.expectEqualStrings("P2PKH", id.text);
    try std.testing.expectEqual(TokenKind.ident, t.next().kind); // is
    try std.testing.expectEqual(TokenKind.ident, t.next().kind); // SmartContract
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "sol tokenizer operators" {
    var t = Tokenizer.init("== != <= >= << >> && || += -= *= /= %= ++ --");
    const expected = [_]TokenKind{
        .eqeq, .bang_eq, .lt_eq, .gt_eq,
        .lshift, .rshift, .amp_amp, .pipe_pipe, .plus_eq, .minus_eq,
        .star_eq, .slash_eq, .percent_eq, .plus_plus, .minus_minus, .eof,
    };
    for (expected) |e| try std.testing.expectEqual(e, t.next().kind);
}

test "sol tokenizer strings" {
    var t = Tokenizer.init("'hello' \"world\"");
    const s1 = t.next();
    try std.testing.expectEqual(TokenKind.string_literal, s1.kind);
    try std.testing.expectEqualStrings("hello", s1.text);
    const s2 = t.next();
    try std.testing.expectEqual(TokenKind.string_literal, s2.kind);
    try std.testing.expectEqualStrings("world", s2.text);
}

test "sol tokenizer numbers" {
    var t = Tokenizer.init("42 0xff 100n");
    const n1 = t.next();
    try std.testing.expectEqual(TokenKind.number, n1.kind);
    try std.testing.expectEqualStrings("42", n1.text);
    const n2 = t.next();
    try std.testing.expectEqual(TokenKind.number, n2.kind);
    try std.testing.expectEqualStrings("0xff", n2.text);
    const n3 = t.next();
    try std.testing.expectEqual(TokenKind.number, n3.kind);
    try std.testing.expectEqualStrings("100", n3.text); // 'n' suffix stripped
}

test "sol parse basic P2PKH" {
    const source =
        \\pragma runar ^0.1.0;
        \\
        \\contract P2PKH is SmartContract {
        \\    Addr immutable pubKeyHash;
        \\
        \\    constructor(Addr _pubKeyHash) {
        \\        pubKeyHash = _pubKeyHash;
        \\    }
        \\
        \\    function unlock(Sig _sig, PubKey _pubKey) public {
        \\        require(hash160(_pubKey) == pubKeyHash);
        \\        require(checkSig(_sig, _pubKey));
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = parseSol(arena.allocator(), source, "P2PKH.runar.sol");
    for (result.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expect(result.contract != null);
    const c = result.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("pubKeyHash", c.properties[0].name);
    try std.testing.expect(c.properties[0].readonly);
    try std.testing.expectEqual(RunarType.addr, c.properties[0].type_info);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqualStrings("unlock", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].params.len);
}

test "sol parse stateful counter" {
    const source =
        \\pragma runar ^0.1.0;
        \\
        \\contract Counter is StatefulSmartContract {
        \\    bigint count;
        \\
        \\    constructor(bigint _count) {
        \\        count = _count;
        \\    }
        \\
        \\    function increment() public {
        \\        this.count++;
        \\    }
        \\
        \\    function decrement() public {
        \\        require(this.count > 0);
        \\        this.count--;
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = parseSol(arena.allocator(), source, "Counter.runar.sol");
    for (result.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expect(result.contract != null);
    const c = result.contract.?;
    try std.testing.expectEqualStrings("Counter", c.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("count", c.properties[0].name);
    try std.testing.expect(!c.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
    try std.testing.expectEqualStrings("decrement", c.methods[1].name);
}

test "sol parse property initializers" {
    const source =
        \\pragma runar ^0.1.0;
        \\
        \\contract PropInit is StatefulSmartContract {
        \\    int count = 0;
        \\    int immutable maxCount;
        \\    bool immutable active = true;
        \\
        \\    constructor(int _maxCount) {
        \\        maxCount = _maxCount;
        \\    }
        \\
        \\    function increment(int _amount) public {
        \\        require(active);
        \\        count = count + _amount;
        \\        require(count <= maxCount);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = parseSol(arena.allocator(), source, "PropInit.runar.sol");
    for (result.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expect(result.contract != null);
    const c = result.contract.?;
    try std.testing.expectEqual(@as(usize, 3), c.properties.len);
    // count has initializer
    try std.testing.expectEqualStrings("count", c.properties[0].name);
    try std.testing.expect(c.properties[0].initializer != null);
    try std.testing.expect(!c.properties[0].readonly);
    // maxCount has no initializer
    try std.testing.expectEqualStrings("maxCount", c.properties[1].name);
    try std.testing.expect(c.properties[1].initializer == null);
    try std.testing.expect(c.properties[1].readonly);
    // active has initializer and is readonly
    try std.testing.expectEqualStrings("active", c.properties[2].name);
    try std.testing.expect(c.properties[2].initializer != null);
    try std.testing.expect(c.properties[2].readonly);
}

test "sol parse for loop" {
    const source =
        \\pragma runar ^0.1.0;
        \\
        \\contract LoopTest is SmartContract {
        \\    int immutable expectedSum;
        \\
        \\    constructor(int _expectedSum) {
        \\        expectedSum = _expectedSum;
        \\    }
        \\
        \\    function verify(int _start) public {
        \\        int sum = 0;
        \\        for (int i = 0; i < 5; i++) {
        \\            sum = sum + _start + i;
        \\        }
        \\        require(sum == expectedSum);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = parseSol(arena.allocator(), source, "LoopTest.runar.sol");
    for (result.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expect(result.contract != null);
    const c = result.contract.?;
    try std.testing.expectEqualStrings("LoopTest", c.name);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    // The method body should have a let_decl, for_stmt, and assert_stmt
    try std.testing.expectEqual(@as(usize, 3), c.methods[0].body.len);
}

test "sol parse function with returns clause" {
    const source =
        \\pragma runar ^0.1.0;
        \\
        \\contract FuncTest is StatefulSmartContract {
        \\    bigint immutable owner;
        \\    bigint balance;
        \\
        \\    constructor(bigint _owner, bigint _balance) {
        \\        owner = _owner;
        \\        balance = _balance;
        \\    }
        \\
        \\    function computeFee(bigint _amount, bigint _feeBps) private returns (bigint) {
        \\        return percentOf(_amount, _feeBps);
        \\    }
        \\
        \\    function deposit(bigint _amount) public {
        \\        require(_amount > 0);
        \\        balance = balance + _amount;
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = parseSol(arena.allocator(), source, "FuncTest.runar.sol");
    for (result.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expect(result.contract != null);
    const c = result.contract.?;
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    // computeFee is private
    try std.testing.expectEqualStrings("computeFee", c.methods[0].name);
    try std.testing.expect(!c.methods[0].is_public);
    // deposit is public
    try std.testing.expectEqualStrings("deposit", c.methods[1].name);
    try std.testing.expect(c.methods[1].is_public);
}

test "sol type resolution" {
    // Solidity aliases
    try std.testing.expectEqual(RunarType.bigint, Parser.resolveSolType("int"));
    try std.testing.expectEqual(RunarType.bigint, Parser.resolveSolType("uint"));
    try std.testing.expectEqual(RunarType.bigint, Parser.resolveSolType("int256"));
    try std.testing.expectEqual(RunarType.bigint, Parser.resolveSolType("uint256"));
    try std.testing.expectEqual(RunarType.boolean, Parser.resolveSolType("bool"));
    try std.testing.expectEqual(RunarType.byte_string, Parser.resolveSolType("bytes"));
    try std.testing.expectEqual(RunarType.byte_string, Parser.resolveSolType("bytes32"));
    try std.testing.expectEqual(RunarType.addr, Parser.resolveSolType("address"));
    // Standard Runar types
    try std.testing.expectEqual(RunarType.bigint, Parser.resolveSolType("bigint"));
    try std.testing.expectEqual(RunarType.pub_key, Parser.resolveSolType("PubKey"));
    try std.testing.expectEqual(RunarType.sig, Parser.resolveSolType("Sig"));
    try std.testing.expectEqual(RunarType.point, Parser.resolveSolType("Point"));
    // Unknown
    try std.testing.expectEqual(RunarType.unknown, Parser.resolveSolType("SomeRandomType"));
}
