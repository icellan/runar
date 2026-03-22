//! Pass 1 (TypeScript frontend): Hand-written tokenizer + recursive descent parser for .runar.ts files.
//!
//! Parses TypeScript-style class syntax into the Runar IR ContractNode.
//!
//! Syntax conventions:
//!   - `import { SmartContract, ... } from 'runar-lang';` at top (skipped)
//!   - `class Name extends SmartContract { ... }` declares the contract
//!   - `readonly prop: Type;` for immutable properties
//!   - `prop: Type;` for mutable properties (StatefulSmartContract only)
//!   - `constructor(params) { super(...); this.x = x; }` is the constructor
//!   - `public methodName(params) { ... }` are public methods
//!   - `methodName(params) { ... }` are private methods (no `public` keyword)
//!   - `this.property` for property access
//!   - `===` / `!==` for equality (also accepts `==` / `!=`)
//!   - BigInt literals with `n` suffix: `42n`, `0n` (suffix stripped)
//!   - Types after colon: `param: Type`
//!   - Builtins: `assert(...)`, `hash160(...)`, `checkSig(...)`, etc.
//!   - Types: `PubKey`, `Sig`, `Addr`, `ByteString`, `bigint`, `boolean`, `void`

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

pub fn parseTs(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
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
    eqeqeq,
    bang_eq,
    bang_eqeq,
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

        // String literals: single quotes, double quotes, backticks
        if (c == '"' or c == '\'' or c == '`') {
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

        // Numbers (decimal, hex, octal, binary; strip trailing 'n' for BigInt)
        if (c >= '0' and c <= '9') {
            if (c == '0' and (self.peekAt(1) == 'x' or self.peekAt(1) == 'X')) {
                _ = self.advance(); // '0'
                _ = self.advance(); // 'x'
                while (self.pos < self.source.len and isHexDigit(self.source[self.pos])) _ = self.advance();
            } else if (c == '0' and (self.peekAt(1) == 'o' or self.peekAt(1) == 'O')) {
                _ = self.advance();
                _ = self.advance();
                while (self.pos < self.source.len and self.source[self.pos] >= '0' and self.source[self.pos] <= '7') _ = self.advance();
            } else if (c == '0' and (self.peekAt(1) == 'b' or self.peekAt(1) == 'B')) {
                _ = self.advance();
                _ = self.advance();
                while (self.pos < self.source.len and (self.source[self.pos] == '0' or self.source[self.pos] == '1')) _ = self.advance();
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
            return .{ .kind = identToKind(text), .text = text, .line = sl, .col = sc };
        }

        // Operators: try 3-char, then 2-char, then 1-char
        _ = self.advance();
        const c2 = self.peek();
        const c3 = self.peekAt(1);

        // Three-character operators
        if (c == '=' and c2 == '=' and c3 == '=') {
            _ = self.advance();
            _ = self.advance();
            return .{ .kind = .eqeqeq, .text = self.source[start..self.pos], .line = sl, .col = sc };
        }
        if (c == '!' and c2 == '=' and c3 == '=') {
            _ = self.advance();
            _ = self.advance();
            return .{ .kind = .bang_eqeq, .text = self.source[start..self.pos], .line = sl, .col = sc };
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
            '.' => .{ .kind = .dot, .text = t, .line = sl, .col = sc },
            ':' => .{ .kind = .colon, .text = t, .line = sl, .col = sc },
            '?' => .{ .kind = .question, .text = t, .line = sl, .col = sc },
            '~' => .{ .kind = .tilde, .text = t, .line = sl, .col = sc },
            '^' => .{ .kind = .caret, .text = t, .line = sl, .col = sc },
            '=' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .eqeq, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else if (c2 == '>') blk2: {
                _ = self.advance();
                break :blk2 .{ .kind = .arrow, .text = self.source[start..self.pos], .line = sl, .col = sc };
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

    fn identToKind(text: []const u8) TokenKind {
        // TS keywords are identifiers in our tokenizer; we resolve them in the parser.
        // Only true/false need special handling at token level for literal parsing.
        // Everything else (class, extends, import, export, public, private, readonly,
        // constructor, if, else, for, while, return, const, let, this, super, new)
        // stays as .ident and is resolved by the parser via checkIdent().
        const map = std.StaticStringMap(TokenKind).initComptime(.{
            .{ "true", .ident },
            .{ "false", .ident },
        });
        return map.get(text) orelse .ident;
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
        self.skipImportsAndPreamble();
        const contract = self.parseClassDecl();
        return .{ .contract = contract, .errors = self.errors.items };
    }

    /// Skip import statements and any top-level noise until we find a class declaration.
    fn skipImportsAndPreamble(self: *Parser) void {
        while (self.current.kind != .eof) {
            // import ...
            if (self.checkIdent("import")) {
                self.skipImport();
                continue;
            }
            // export class ... or export default class ...
            if (self.checkIdent("export")) {
                _ = self.bump();
                if (self.checkIdent("default")) _ = self.bump();
                if (self.checkIdent("class")) return; // leave 'class' for parseClassDecl
                // Other export — skip to semicolon
                self.skipStatement();
                continue;
            }
            // class ...
            if (self.checkIdent("class")) return;
            // Unknown top-level statement
            self.skipStatement();
        }
    }

    fn skipImport(self: *Parser) void {
        // Consume 'import'
        _ = self.bump();
        while (self.current.kind != .eof) {
            if (self.current.kind == .semicolon) {
                _ = self.bump();
                return;
            }
            // End-of-import heuristic: next top-level keyword without semicolon
            if (self.current.kind == .ident) {
                const val = self.current.text;
                if (std.mem.eql(u8, val, "import") or std.mem.eql(u8, val, "export") or std.mem.eql(u8, val, "class")) return;
            }
            _ = self.bump();
        }
    }

    fn skipStatement(self: *Parser) void {
        var depth: i32 = 0;
        while (self.current.kind != .eof) {
            if (self.current.kind == .lbrace) {
                depth += 1;
                _ = self.bump();
            } else if (self.current.kind == .rbrace) {
                if (depth <= 0) return;
                depth -= 1;
                _ = self.bump();
                if (depth == 0) return;
            } else if (self.current.kind == .semicolon and depth == 0) {
                _ = self.bump();
                return;
            } else {
                _ = self.bump();
            }
        }
    }

    // ---- Class declaration ----

    fn parseClassDecl(self: *Parser) ?ContractNode {
        if (!self.checkIdent("class")) {
            self.addError("expected 'class' declaration");
            return null;
        }
        _ = self.bump(); // consume 'class'

        // Contract name
        if (self.current.kind != .ident) {
            self.addError("expected class name");
            return null;
        }
        const name_tok = self.bump();

        // extends clause
        var parent_class: ParentClass = .smart_contract;
        if (self.matchIdent("extends")) {
            if (self.current.kind != .ident) {
                self.addError("expected parent class name after 'extends'");
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

            const member = self.parseClassMember(parent_class);
            switch (member) {
                .property => |prop| properties.append(self.allocator, prop) catch {},
                .constructor_method => |m| {
                    if (constructor != null) self.addError("duplicate constructor");
                    constructor = self.methodToConstructor(m);
                },
                .method => |m| methods.append(self.allocator, m) catch {},
                .none => {},
            }
        }
        _ = self.expect(.rbrace);

        if (constructor == null) {
            self.addError("contract must have a constructor");
            constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
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

    // ---- Class members ----

    const ClassMember = union(enum) {
        property: PropertyNode,
        constructor_method: MethodNode,
        method: MethodNode,
        none,
    };

    fn parseClassMember(self: *Parser, parent_class: ParentClass) ClassMember {
        // Skip TypeScript decorators: @prop(), @method(), etc.
        while (self.current.kind == .ident and self.current.text.len == 1 and self.current.text[0] == '@') {
            _ = self.bump(); // consume '@'
            if (self.current.kind == .ident) _ = self.bump(); // consume decorator name
            // consume optional parenthesized arguments: (...)
            if (self.current.kind == .lparen) {
                _ = self.bump(); // consume '('
                var paren_depth: u32 = 1;
                while (paren_depth > 0 and self.current.kind != .eof) {
                    if (self.current.kind == .lparen) paren_depth += 1;
                    if (self.current.kind == .rparen) paren_depth -= 1;
                    _ = self.bump();
                }
            }
        }

        // Collect modifiers: public, private, protected, readonly
        var is_public = false;
        var is_readonly = false;

        while (true) {
            if (self.checkIdent("public")) {
                is_public = true;
                _ = self.bump();
            } else if (self.checkIdent("private") or self.checkIdent("protected")) {
                is_public = false;
                _ = self.bump();
            } else if (self.checkIdent("readonly")) {
                is_readonly = true;
                _ = self.bump();
            } else break;
        }

        // constructor(...)
        if (self.checkIdent("constructor")) {
            return .{ .constructor_method = self.parseConstructorMethod() };
        }

        // Must be an identifier at this point
        if (self.current.kind != .ident) {
            _ = self.bump();
            return .none;
        }

        const name_tok = self.bump();
        const member_name = name_tok.text;

        // Method: name(...)
        if (self.current.kind == .lparen) {
            const m = self.parseMethod(member_name, is_public);
            return .{ .method = m };
        }

        // Property: name: Type
        if (self.current.kind == .colon) {
            _ = self.bump(); // consume ':'
            const type_node = self.parseTypeAnnotation();
            const type_info = typeNodeToRunarType(type_node);

            // Optional initializer: = value
            var initializer: ?Expression = null;
            if (self.current.kind == .assign) {
                _ = self.bump();
                initializer = self.parseExpression();
            }
            self.skipSemicolons();

            // For SmartContract, all fields are readonly.
            // For StatefulSmartContract, readonly depends on the keyword.
            const readonly = if (parent_class == .smart_contract) true else is_readonly;

            return .{ .property = .{
                .name = member_name,
                .type_info = type_info,
                .readonly = readonly,
                .initializer = initializer,
            } };
        }

        // Property with no type annotation
        if (self.current.kind == .semicolon) {
            _ = self.bump();
            self.addErrorFmt("property '{s}' must have an explicit type annotation", .{member_name});
            return .{ .property = .{
                .name = member_name,
                .type_info = .unknown,
                .readonly = is_readonly,
            } };
        }

        // Unknown — skip to next member
        self.skipToNextMember();
        return .none;
    }

    fn skipToNextMember(self: *Parser) void {
        var depth: i32 = 0;
        while (self.current.kind != .eof) {
            if (self.current.kind == .lbrace) {
                depth += 1;
                _ = self.bump();
            } else if (self.current.kind == .rbrace) {
                if (depth <= 0) return;
                depth -= 1;
                _ = self.bump();
            } else if (self.current.kind == .semicolon and depth == 0) {
                _ = self.bump();
                return;
            } else {
                _ = self.bump();
            }
        }
    }

    // ---- Constructor ----

    fn parseConstructorMethod(self: *Parser) MethodNode {
        _ = self.bump(); // consume 'constructor'
        const params = self.parseParams();

        // Skip optional return type
        if (self.current.kind == .colon) {
            _ = self.bump();
            _ = self.parseTypeAnnotation();
        }

        const body = self.parseBlock();
        return .{ .name = "constructor", .is_public = true, .params = params, .body = body };
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
                    if (self.isSuperCall(expr)) {
                        if (self.extractSuperArgs(expr)) |args| {
                            for (args) |arg| super_args.append(self.allocator, arg) catch {};
                        }
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

    fn isSuperCall(self: *const Parser, expr: Expression) bool {
        _ = self;
        switch (expr) {
            .call => |call| {
                return std.mem.eql(u8, call.callee, "super");
            },
            .method_call => |mc| {
                return std.mem.eql(u8, mc.object, "super");
            },
            else => return false,
        }
    }

    fn extractSuperArgs(self: *const Parser, expr: Expression) ?[]const Expression {
        _ = self;
        switch (expr) {
            .call => |call| return call.args,
            .method_call => |mc| return mc.args,
            else => return null,
        }
    }

    // ---- Methods ----

    fn parseMethod(self: *Parser, name: []const u8, is_public: bool) MethodNode {
        const params = self.parseParams();

        // Skip optional return type
        if (self.current.kind == .colon) {
            _ = self.bump();
            _ = self.parseTypeAnnotation();
        }

        const body = self.parseBlock();
        return .{ .name = name, .is_public = is_public, .params = params, .body = body };
    }

    // ---- Parameters ----

    fn parseParams(self: *Parser) []ParamNode {
        _ = self.expect(.lparen);
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;

        while (self.current.kind != .rparen and self.current.kind != .eof) {
            // Skip modifiers in constructor params
            while (self.current.kind == .ident and
                (std.mem.eql(u8, self.current.text, "public") or
                std.mem.eql(u8, self.current.text, "private") or
                std.mem.eql(u8, self.current.text, "protected") or
                std.mem.eql(u8, self.current.text, "readonly")))
            {
                _ = self.bump();
            }

            if (self.current.kind != .ident) break;
            const name_tok = self.bump();
            const param_name = name_tok.text;

            // Optional '?' for optional params
            _ = self.match(.question);

            // Type annotation: : Type
            var type_name: []const u8 = "";
            var type_info: RunarType = .unknown;
            if (self.current.kind == .colon) {
                _ = self.bump();
                const tn = self.parseTypeAnnotation();
                type_info = typeNodeToRunarType(tn);
                type_name = runarTypeToTypeName(type_info);
            } else {
                self.addErrorFmt("parameter '{s}' must have an explicit type annotation", .{param_name});
            }

            params.append(self.allocator, .{
                .name = param_name,
                .type_info = type_info,
                .type_name = type_name,
            }) catch {};

            if (self.current.kind == .comma) {
                _ = self.bump();
            } else break;
        }
        _ = self.expect(.rparen);
        return params.items;
    }

    // ---- Type parsing ----

    fn parseTypeAnnotation(self: *Parser) TypeNode {
        if (self.current.kind != .ident) {
            self.addError("expected type name");
            _ = self.bump();
            return .{ .custom_type = "unknown" };
        }

        const name = self.current.text;
        _ = self.bump();

        // FixedArray<T, N>
        if (std.mem.eql(u8, name, "FixedArray")) {
            if (self.current.kind == .lt) {
                _ = self.bump(); // '<'
                const elem_type = self.parseTypeAnnotation();
                _ = self.expect(.comma);
                const size_tok = self.expect(.number) orelse return .{ .custom_type = "FixedArray" };
                const size = std.fmt.parseInt(u32, size_tok.text, 10) catch 0;
                _ = self.expect(.gt);
                const elem_ptr = self.allocator.create(TypeNode) catch return .{ .custom_type = "FixedArray" };
                elem_ptr.* = elem_type;
                return .{ .fixed_array_type = .{ .element = elem_ptr, .length = size } };
            }
            return .{ .custom_type = name };
        }

        // Skip generic type args: Type<...>
        if (self.current.kind == .lt) {
            self.skipTypeArgs();
        }

        // Array type: Type[] — not supported, use FixedArray
        if (self.current.kind == .lbracket and self.tokenizer.peek() == ']') {
            // Peek ahead is tricky with our tokenizer, just check next token
            const saved_pos = self.tokenizer.pos;
            const saved_line = self.tokenizer.line;
            const saved_col = self.tokenizer.col;
            const saved_current = self.current;
            _ = self.bump(); // consume '['
            if (self.current.kind == .rbracket) {
                _ = self.bump(); // consume ']'
                self.addErrorFmt("use FixedArray<T, N> instead of {s}[]", .{name});
            } else {
                // Not [] — restore
                self.tokenizer.pos = saved_pos;
                self.tokenizer.line = saved_line;
                self.tokenizer.col = saved_col;
                self.current = saved_current;
            }
        }

        return resolveTsTypeName(name);
    }

    fn skipTypeArgs(self: *Parser) void {
        if (self.current.kind != .lt) return;
        _ = self.bump();
        var depth: i32 = 1;
        while (depth > 0 and self.current.kind != .eof) {
            if (self.current.kind == .lt) depth += 1;
            if (self.current.kind == .gt) depth -= 1;
            _ = self.bump();
        }
    }

    pub fn resolveTsTypeName(name: []const u8) TypeNode {
        // Direct primitive type names from TypeScript
        if (std.mem.eql(u8, name, "bigint") or std.mem.eql(u8, name, "number")) return .{ .primitive_type = .bigint };
        if (std.mem.eql(u8, name, "boolean")) return .{ .primitive_type = .boolean };
        if (std.mem.eql(u8, name, "void")) return .{ .primitive_type = .void };
        // Runar-specific types
        if (std.mem.eql(u8, name, "PubKey")) return .{ .primitive_type = .pub_key };
        if (std.mem.eql(u8, name, "Sig")) return .{ .primitive_type = .sig };
        if (std.mem.eql(u8, name, "Addr")) return .{ .primitive_type = .addr };
        if (std.mem.eql(u8, name, "Ripemd160")) return .{ .primitive_type = .ripemd160 };
        if (std.mem.eql(u8, name, "ByteString")) return .{ .primitive_type = .byte_string };
        if (std.mem.eql(u8, name, "Sha256")) return .{ .primitive_type = .sha256 };
        if (std.mem.eql(u8, name, "SigHashPreimage")) return .{ .primitive_type = .sig_hash_preimage };
        if (std.mem.eql(u8, name, "RabinSig")) return .{ .primitive_type = .rabin_sig };
        if (std.mem.eql(u8, name, "RabinPubKey")) return .{ .primitive_type = .rabin_pub_key };
        if (std.mem.eql(u8, name, "Point")) return .{ .primitive_type = .point };
        // Also check via PrimitiveTypeName
        if (PrimitiveTypeName.fromTsString(name)) |ptn| return .{ .primitive_type = ptn };
        return .{ .custom_type = name };
    }

    /// Delegates to the canonical implementation in types.zig.
    const typeNodeToRunarType = types.typeNodeToRunarType;

    fn runarTypeToTypeName(t: RunarType) []const u8 {
        return types.runarTypeToString(t);
    }

    // ---- Block parsing ----

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
        // Variable declarations: const, let
        if (self.checkIdent("const")) return self.parseVarDecl(false);
        if (self.checkIdent("let")) return self.parseVarDecl(true);

        // If statement
        if (self.checkIdent("if")) return self.parseIfStmt();

        // For statement
        if (self.checkIdent("for")) return self.parseForStmt();

        // Return statement
        if (self.checkIdent("return")) return self.parseReturnStmt();

        // Expression statement (including assignments and calls)
        return self.parseExpressionStatement();
    }

    fn parseVarDecl(self: *Parser, mutable: bool) ?Statement {
        _ = self.bump(); // consume 'const' or 'let'

        if (self.current.kind != .ident) {
            self.addError("expected variable name");
            return null;
        }
        const name_tok = self.bump();

        // Optional type annotation
        var ti: ?RunarType = null;
        if (self.current.kind == .colon) {
            _ = self.bump();
            const tn = self.parseTypeAnnotation();
            ti = typeNodeToRunarType(tn);
        }

        // Initializer
        if (self.expect(.assign) == null) return null;
        const val = self.parseExpression() orelse return null;
        self.skipSemicolons();

        if (mutable) {
            return .{ .let_decl = .{ .name = name_tok.text, .type_info = ti, .value = val } };
        } else {
            return .{ .const_decl = .{ .name = name_tok.text, .type_info = ti, .value = val } };
        }
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

        // For now, parse C-style for loops: for (let i = 0; i < N; i++)
        // Extract: var_name, init_value, bound
        var var_name: []const u8 = "_i";
        var init_value: i64 = 0;
        var bound: i64 = 0;

        // Initializer: let/const varname = expr
        if (self.checkIdent("let") or self.checkIdent("const")) {
            _ = self.bump();
            if (self.current.kind == .ident) {
                var_name = self.bump().text;
                if (self.current.kind == .colon) {
                    _ = self.bump();
                    _ = self.parseTypeAnnotation();
                }
                if (self.current.kind == .assign) {
                    _ = self.bump();
                    if (self.current.kind == .number) {
                        init_value = std.fmt.parseInt(i64, self.bump().text, 10) catch 0;
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
            // Try to extract bound from simple comparison: var < N
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

        // Update: i++ / i += 1, etc. — skip
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
            // Extract assignment target name
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
                // For more complex targets, use identifier name if possible
                return .{ .assign = .{ .target = "unknown", .value = value } };
            },
        }
    }

    fn makeBinaryExpr(self: *Parser, op: BinOperator, left: Expression, right: Expression) ?Expression {
        const bop = self.allocator.create(BinaryOp) catch return null;
        bop.* = .{ .op = op, .left = left, .right = right };
        return .{ .binary_op = bop };
    }

    // ---- Expressions ----
    // Operator precedence (lowest to highest):
    //   ternary (? :)
    //   logical or (||)
    //   logical and (&&)
    //   bitwise or (|)
    //   bitwise xor (^)
    //   bitwise and (&)
    //   equality (=== !==)
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
        while (self.current.kind == .eqeqeq or self.current.kind == .bang_eqeq or
            self.current.kind == .eqeq or self.current.kind == .bang_eq)
        {
            const op: BinOperator = if (self.current.kind == .eqeqeq or self.current.kind == .eqeq) .eq else .neq;
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
                                // this.method(args) -> MethodCall{object="this", method=member}
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = "this", .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            } else {
                                // obj.method(args) -> MethodCall
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = id, .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            }
                        },
                        else => {
                            // Complex expr.method(args) -> CallExpr with callee=method_call-ish
                            // Flatten to MethodCall if we can extract the object name
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
                                // this.property -> PropertyAccess
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
                if (std.mem.eql(u8, name, "this")) break :blk Expression{ .identifier = "this" };
                if (std.mem.eql(u8, name, "super")) break :blk Expression{ .identifier = "super" };

                // Function call: name(...)
                if (self.current.kind == .lparen) {
                    _ = self.bump();
                    const args = self.parseArgList();
                    const call = self.allocator.create(CallExpr) catch break :blk null;
                    call.* = .{ .callee = name, .args = args };
                    break :blk Expression{ .call = call };
                }

                break :blk Expression{ .identifier = name };
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

test "ts tokenizer basics" {
    var t = Tokenizer.init("class P2PKH extends SmartContract { }");
    try std.testing.expectEqual(TokenKind.ident, t.next().kind);
    const id = t.next();
    try std.testing.expectEqualStrings("P2PKH", id.text);
    try std.testing.expectEqual(TokenKind.ident, t.next().kind); // extends
    try std.testing.expectEqual(TokenKind.ident, t.next().kind); // SmartContract
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "ts tokenizer operators" {
    var t = Tokenizer.init("=== !== == != <= >= << >> && || += -= *= /= %= ++ --");
    const expected = [_]TokenKind{
        .eqeqeq, .bang_eqeq, .eqeq, .bang_eq, .lt_eq, .gt_eq,
        .lshift,  .rshift,    .amp_amp, .pipe_pipe, .plus_eq, .minus_eq,
        .star_eq, .slash_eq,  .percent_eq, .plus_plus, .minus_minus, .eof,
    };
    for (expected) |e| try std.testing.expectEqual(e, t.next().kind);
}

test "ts tokenizer strings" {
    var t = Tokenizer.init("'hello' \"world\" `template`");
    const s1 = t.next();
    try std.testing.expectEqual(TokenKind.string_literal, s1.kind);
    try std.testing.expectEqualStrings("hello", s1.text);
    const s2 = t.next();
    try std.testing.expectEqual(TokenKind.string_literal, s2.kind);
    try std.testing.expectEqualStrings("world", s2.text);
    const s3 = t.next();
    try std.testing.expectEqual(TokenKind.string_literal, s3.kind);
    try std.testing.expectEqualStrings("template", s3.text);
}

test "ts tokenizer bigint suffix" {
    var t = Tokenizer.init("42n 0n 100n");
    const n1 = t.next();
    try std.testing.expectEqual(TokenKind.number, n1.kind);
    try std.testing.expectEqualStrings("42", n1.text);
    const n2 = t.next();
    try std.testing.expectEqual(TokenKind.number, n2.kind);
    try std.testing.expectEqualStrings("0", n2.text);
    const n3 = t.next();
    try std.testing.expectEqual(TokenKind.number, n3.kind);
    try std.testing.expectEqualStrings("100", n3.text);
}

test "ts tokenizer hex literal" {
    var t = Tokenizer.init("0xff 0xFF");
    const n1 = t.next();
    try std.testing.expectEqual(TokenKind.number, n1.kind);
    try std.testing.expectEqualStrings("0xff", n1.text);
    const n2 = t.next();
    try std.testing.expectEqual(TokenKind.number, n2.kind);
    try std.testing.expectEqualStrings("0xFF", n2.text);
}

test "ts tokenizer comments" {
    var t = Tokenizer.init("// line comment\nclass /* block\n comment */ X { }");
    try std.testing.expectEqualStrings("class", t.next().text);
    try std.testing.expectEqualStrings("X", t.next().text);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "parse P2PKH contract (TS)" {
    const source =
        \\import { SmartContract, assert, PubKey, Sig, hash160, checkSig } from 'runar-lang';
        \\class P2PKH extends SmartContract {
        \\  readonly pubKeyHash: Addr;
        \\  constructor(pubKeyHash: Addr) {
        \\    super(pubKeyHash);
        \\    this.pubKeyHash = pubKeyHash;
        \\  }
        \\  public unlock(sig: Sig, pubKey: PubKey) {
        \\    assert(hash160(pubKey) === this.pubKeyHash);
        \\    assert(checkSig(sig, pubKey));
        \\  }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseTs(arena.allocator(), source, "P2PKH.runar.ts");
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

test "parse Counter contract (stateful, TS)" {
    const source =
        \\import { StatefulSmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';
        \\class Counter extends StatefulSmartContract {
        \\  readonly owner: PubKey;
        \\  count: bigint;
        \\  constructor(owner: PubKey, count: bigint) {
        \\    super(owner, count);
        \\    this.owner = owner;
        \\    this.count = count;
        \\  }
        \\  public increment(sig: Sig) {
        \\    assert(checkSig(sig, this.owner));
        \\    this.count += 1n;
        \\    this.addOutput(1n, this.count);
        \\  }
        \\  public decrement(sig: Sig) {
        \\    assert(checkSig(sig, this.owner));
        \\    assert(this.count > 0n);
        \\    this.count -= 1n;
        \\    this.addOutput(1n, this.count);
        \\  }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseTs(arena.allocator(), source, "Counter.runar.ts");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Counter", c.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 2), c.properties.len);
    try std.testing.expect(c.properties[0].readonly); // owner: readonly keyword
    try std.testing.expect(!c.properties[1].readonly); // count: no readonly keyword
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
    try std.testing.expectEqualStrings("decrement", c.methods[1].name);
    // increment body: assert, this.count += 1n, this.addOutput(...)
    try std.testing.expectEqual(@as(usize, 3), c.methods[0].body.len);
}

test "parse Escrow contract (multi-method, TS)" {
    const source =
        \\import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';
        \\class Escrow extends SmartContract {
        \\  readonly buyer: PubKey;
        \\  readonly seller: PubKey;
        \\  readonly arbiter: PubKey;
        \\  constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey) {
        \\    super(buyer, seller, arbiter);
        \\    this.buyer = buyer;
        \\    this.seller = seller;
        \\    this.arbiter = arbiter;
        \\  }
        \\  public release(buyerSig: Sig, sellerSig: Sig) {
        \\    assert(checkSig(buyerSig, this.buyer));
        \\    assert(checkSig(sellerSig, this.seller));
        \\  }
        \\  public arbitrate(arbiterSig: Sig, winnerSig: Sig, winnerPubKey: PubKey) {
        \\    assert(checkSig(arbiterSig, this.arbiter));
        \\    assert(winnerPubKey === this.buyer || winnerPubKey === this.seller);
        \\    assert(checkSig(winnerSig, winnerPubKey));
        \\  }
        \\  verifyParticipant(pubKey: PubKey): boolean {
        \\    return pubKey === this.buyer || pubKey === this.seller || pubKey === this.arbiter;
        \\  }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseTs(arena.allocator(), source, "Escrow.runar.ts");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Escrow", c.name);
    try std.testing.expectEqual(@as(usize, 3), c.properties.len);
    try std.testing.expectEqual(@as(usize, 3), c.methods.len);
    try std.testing.expect(c.methods[0].is_public); // release
    try std.testing.expect(c.methods[1].is_public); // arbitrate
    try std.testing.expect(!c.methods[2].is_public); // verifyParticipant (no 'public')
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].body.len);
    try std.testing.expectEqual(@as(usize, 3), c.methods[1].body.len);
    // verifyParticipant has a return statement
    try std.testing.expectEqual(std.meta.Tag(Statement).return_stmt, std.meta.activeTag(c.methods[2].body[0]));
}

test "parse error: no class found" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseTs(arena.allocator(), "const x = 5;", "bad.runar.ts");
    try std.testing.expect(r.errors.len > 0);
    try std.testing.expect(r.contract == null);
}

test "parse error: wrong parent class" {
    const source =
        \\class Bad extends Object {
        \\  constructor() { super(); }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseTs(arena.allocator(), source, "bad.runar.ts");
    try std.testing.expect(r.errors.len > 0);
    try std.testing.expect(r.contract == null);
}

test "binary operators and precedence (TS)" {
    const source =
        \\class A extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  public check(x: bigint) {
        \\    const a = x + 1n;
        \\    const r = x + 2n * 3n;
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "A.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    // a = x + 1
    switch (body[0]) {
        .const_decl => |cd| {
            switch (cd.value) {
                .binary_op => |b| {
                    try std.testing.expectEqual(BinOperator.add, b.op);
                    try std.testing.expectEqual(@as(i64, 1), b.right.literal_int);
                },
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
    // r = x + (2 * 3)  -- mul binds tighter than add
    switch (body[1]) {
        .const_decl => |cd| {
            switch (cd.value) {
                .binary_op => |top| {
                    try std.testing.expectEqual(BinOperator.add, top.op);
                    switch (top.right) {
                        .binary_op => |r2| {
                            try std.testing.expectEqual(BinOperator.mul, r2.op);
                        },
                        else => return error.UnexpectedVariant,
                    }
                },
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
}

test "unary operators (TS)" {
    const source =
        \\class U extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  public check(x: bigint) {
        \\    const a = -x;
        \\    const b = !true;
        \\    const c = ~x;
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "U.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    switch (body[0].const_decl.value) {
        .unary_op => |u| try std.testing.expectEqual(UnaryOperator.negate, u.op),
        else => return error.UnexpectedVariant,
    }
    switch (body[1].const_decl.value) {
        .unary_op => |u| try std.testing.expectEqual(UnaryOperator.not, u.op),
        else => return error.UnexpectedVariant,
    }
    switch (body[2].const_decl.value) {
        .unary_op => |u| try std.testing.expectEqual(UnaryOperator.bitnot, u.op),
        else => return error.UnexpectedVariant,
    }
}

test "method calls and property access (TS)" {
    const source =
        \\import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';
        \\class MC extends SmartContract {
        \\  readonly owner: PubKey;
        \\  constructor(owner: PubKey) { super(owner); this.owner = owner; }
        \\  public check(sig: Sig) {
        \\    assert(checkSig(sig, this.owner));
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "MC.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const stmt = res.contract.?.methods[0].body[0];
    // assert(checkSig(sig, this.owner)) is an expression statement
    switch (stmt) {
        .expr_stmt => |expr| {
            switch (expr) {
                .call => |call| {
                    try std.testing.expectEqualStrings("assert", call.callee);
                    try std.testing.expectEqual(@as(usize, 1), call.args.len);
                    // Inner call: checkSig(sig, this.owner)
                    switch (call.args[0]) {
                        .call => |inner| {
                            try std.testing.expectEqualStrings("checkSig", inner.callee);
                            try std.testing.expectEqual(@as(usize, 2), inner.args.len);
                        },
                        else => return error.UnexpectedVariant,
                    }
                },
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
}

test "type resolution (TS)" {
    try std.testing.expectEqual(TypeNode{ .primitive_type = .pub_key }, Parser.resolveTsTypeName("PubKey"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .sig }, Parser.resolveTsTypeName("Sig"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .addr }, Parser.resolveTsTypeName("Addr"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .byte_string }, Parser.resolveTsTypeName("ByteString"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .sha256 }, Parser.resolveTsTypeName("Sha256"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .ripemd160 }, Parser.resolveTsTypeName("Ripemd160"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .rabin_sig }, Parser.resolveTsTypeName("RabinSig"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .rabin_pub_key }, Parser.resolveTsTypeName("RabinPubKey"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .point }, Parser.resolveTsTypeName("Point"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .bigint }, Parser.resolveTsTypeName("bigint"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .bigint }, Parser.resolveTsTypeName("number"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .boolean }, Parser.resolveTsTypeName("boolean"));
    try std.testing.expectEqual(TypeNode{ .primitive_type = .void }, Parser.resolveTsTypeName("void"));
}

test "if statement (TS)" {
    const source =
        \\class I extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  public check(x: bigint) {
        \\    if (x > 0n) { assert(this.val > 0n); } else { assert(this.val === 0n); }
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "I.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    try std.testing.expectEqual(std.meta.Tag(Statement).if_stmt, std.meta.activeTag(body[0]));
    try std.testing.expectEqual(@as(usize, 1), body[0].if_stmt.then_body.len);
    try std.testing.expect(body[0].if_stmt.else_body != null);
}

test "let decl and compound assignment (TS)" {
    const source =
        \\class V extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  public mutate(x: bigint) {
        \\    let y = x;
        \\    y += 10n;
        \\    assert(y > this.val);
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "V.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    try std.testing.expectEqual(std.meta.Tag(Statement).let_decl, std.meta.activeTag(body[0]));
    try std.testing.expectEqual(std.meta.Tag(Statement).assign, std.meta.activeTag(body[1]));
}

test "this field compound assignment (TS)" {
    const source =
        \\class S extends StatefulSmartContract {
        \\  readonly owner: PubKey;
        \\  count: bigint;
        \\  constructor(owner: PubKey, count: bigint) { super(owner, count); this.owner = owner; this.count = count; }
        \\  public inc(sig: Sig) {
        \\    this.count += 1n;
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "S.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    switch (body[0]) {
        .assign => |a| try std.testing.expectEqualStrings("count", a.target),
        else => return error.UnexpectedVariant,
    }
}

test "return statement with expression (TS)" {
    const source =
        \\class R extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  helper(x: bigint): boolean { return x > this.val; }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "R.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    try std.testing.expectEqual(std.meta.Tag(Statement).return_stmt, std.meta.activeTag(body[0]));
    try std.testing.expect(body[0].return_stmt != null);
    switch (body[0].return_stmt.?) {
        .binary_op => |b| try std.testing.expectEqual(BinOperator.gt, b.op),
        else => return error.UnexpectedVariant,
    }
}

test "logical or operator (TS)" {
    const source =
        \\class L extends SmartContract {
        \\  readonly a: PubKey;
        \\  readonly b: PubKey;
        \\  constructor(a: PubKey, b: PubKey) { super(a, b); this.a = a; this.b = b; }
        \\  public check(pk: PubKey) { assert(pk === this.a || pk === this.b); }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "L.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const stmt = res.contract.?.methods[0].body[0];
    switch (stmt) {
        .expr_stmt => |expr| {
            switch (expr) {
                .call => |call| {
                    switch (call.args[0]) {
                        .binary_op => |b| try std.testing.expectEqual(BinOperator.or_op, b.op),
                        else => return error.UnexpectedVariant,
                    }
                },
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
}

test "triple equals parsed as equality (TS)" {
    const source =
        \\class E extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  public check(x: bigint) { assert(x === this.val); assert(x !== 0n); }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "E.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    try std.testing.expectEqual(@as(usize, 2), body.len);
    // First assert: x === this.val -> eq
    switch (body[0].expr_stmt) {
        .call => |call| {
            switch (call.args[0]) {
                .binary_op => |b| try std.testing.expectEqual(BinOperator.eq, b.op),
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
    // Second assert: x !== 0n -> neq
    switch (body[1].expr_stmt) {
        .call => |call| {
            switch (call.args[0]) {
                .binary_op => |b| try std.testing.expectEqual(BinOperator.neq, b.op),
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
}

test "export class prefix (TS)" {
    const source =
        \\import { SmartContract, assert, PubKey } from 'runar-lang';
        \\export class Simple extends SmartContract {
        \\  readonly key: PubKey;
        \\  constructor(key: PubKey) { super(key); this.key = key; }
        \\  public check() { assert(true); }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "Simple.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    try std.testing.expect(res.contract != null);
    try std.testing.expectEqualStrings("Simple", res.contract.?.name);
}

test "constructor extracts super args" {
    const source =
        \\class C extends SmartContract {
        \\  readonly a: PubKey;
        \\  readonly b: Addr;
        \\  constructor(a: PubKey, b: Addr) {
        \\    super(a, b);
        \\    this.a = a;
        \\    this.b = b;
        \\  }
        \\  public check() { assert(true); }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "C.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const ctor = res.contract.?.constructor;
    try std.testing.expectEqual(@as(usize, 2), ctor.params.len);
    try std.testing.expectEqual(@as(usize, 2), ctor.super_args.len);
    try std.testing.expectEqual(@as(usize, 2), ctor.assignments.len);
    try std.testing.expectEqualStrings("a", ctor.assignments[0].target);
    try std.testing.expectEqualStrings("b", ctor.assignments[1].target);
}

test "ternary expression (TS)" {
    const source =
        \\class T extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  public check(x: bigint) {
        \\    const r = x > 0n ? x : 0n;
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "T.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    switch (body[0].const_decl.value) {
        .ternary => |t| {
            switch (t.condition) {
                .binary_op => |b| try std.testing.expectEqual(BinOperator.gt, b.op),
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
}

test "this.method() call (TS)" {
    const source =
        \\class M extends StatefulSmartContract {
        \\  count: bigint;
        \\  constructor(count: bigint) { super(count); this.count = count; }
        \\  public inc(sig: Sig) {
        \\    this.count += 1n;
        \\    this.addOutput(1n, this.count);
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "M.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    // Second statement: this.addOutput(1n, this.count)
    switch (body[1].expr_stmt) {
        .method_call => |mc| {
            try std.testing.expectEqualStrings("this", mc.object);
            try std.testing.expectEqualStrings("addOutput", mc.method);
            try std.testing.expectEqual(@as(usize, 2), mc.args.len);
        },
        else => return error.UnexpectedVariant,
    }
}

test "array literal (TS)" {
    const source =
        \\class AL extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  public check() {
        \\    const arr = [1n, 2n, 3n];
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "AL.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    switch (body[0].const_decl.value) {
        .array_literal => |elems| {
            try std.testing.expectEqual(@as(usize, 3), elems.len);
        },
        else => return error.UnexpectedVariant,
    }
}

test "parameter type resolution (TS)" {
    const source =
        \\class PT extends SmartContract {
        \\  readonly owner: PubKey;
        \\  constructor(owner: PubKey) { super(owner); this.owner = owner; }
        \\  public check(sig: Sig, pk: PubKey, addr: Addr, val: bigint, flag: boolean) {
        \\    assert(true);
        \\  }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "PT.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const params = res.contract.?.methods[0].params;
    try std.testing.expectEqual(@as(usize, 5), params.len);
    try std.testing.expectEqual(RunarType.sig, params[0].type_info);
    try std.testing.expectEqual(RunarType.pub_key, params[1].type_info);
    try std.testing.expectEqual(RunarType.addr, params[2].type_info);
    try std.testing.expectEqual(RunarType.bigint, params[3].type_info);
    try std.testing.expectEqual(RunarType.boolean, params[4].type_info);
}

test "multiple imports skipped (TS)" {
    const source =
        \\import { SmartContract } from 'runar-lang';
        \\import type { PubKey, Sig } from 'runar-lang';
        \\class MI extends SmartContract {
        \\  readonly val: bigint;
        \\  constructor(val: bigint) { super(val); this.val = val; }
        \\  public check() { assert(true); }
        \\}
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseTs(arena2.allocator(), source, "MI.runar.ts");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    try std.testing.expect(res.contract != null);
    try std.testing.expectEqualStrings("MI", res.contract.?.name);
}

const UnexpectedVariant = error{UnexpectedVariant};
