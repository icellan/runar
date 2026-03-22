//! Pass 1 (Zig frontend): Hand-written tokenizer + recursive descent parser for .runar.zig files.
//!
//! Parses idiomatic Zig struct syntax into the Runar IR ContractNode.
//!
//! Syntax conventions:
//!   - `const runar = @import("runar");` at top (skipped)
//!   - `pub const Name = struct { ... };` declares the contract
//!   - `pub const Contract = runar.SmartContract;` sets parent class
//!   - Fields without defaults are readonly; fields with `= expr` defaults are mutable
//!     (for StatefulSmartContract only -- all SmartContract fields are readonly)
//!   - `runar.Readonly(T)` marks a field readonly explicitly in StatefulSmartContract
//!   - `pub fn init(...)` is the constructor
//!   - `pub fn name(self, ...)` are public methods
//!   - `fn name(self, ...)` are private methods
//!   - Builtins: `runar.assert(...)`, `runar.hash160(...)`, `runar.checkSig(...)`, etc.
//!   - Types: `runar.Bigint`, `runar.PubKey`, `runar.Sig`, `runar.Addr`, `runar.ByteString`, `i64`, `bool`, `void`

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
const AssertStmt = types.AssertStmt;
const AssignmentNode = types.AssignmentNode;
const Ternary = types.Ternary;
const IncrementExpr = types.IncrementExpr;
const DecrementExpr = types.DecrementExpr;

/// Convert a TypeNode to a RunarType. Delegates to the canonical implementation in types.zig.
const typeNodeToRunarType = types.typeNodeToRunarType;

// ============================================================================
// Public API
// ============================================================================

pub const ParseResult = struct {
    contract: ?ContractNode,
    errors: [][]const u8,
};

pub fn parseZig(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
    var parser = Parser.init(allocator, source, file_name);
    return parser.parse();
}

// ============================================================================
// Token Types
// ============================================================================

const TokenKind = enum {
    eof, ident, number, string_literal,
    lparen, rparen, lbrace, rbrace, lbracket, rbracket,
    semicolon, comma, dot, colon, at_sign,
    assign, eqeq, bang_eq, lt, lt_eq, gt, gt_eq,
    plus, minus, star, slash, percent,
    bang, tilde, ampersand, pipe, caret,
    amp_amp, pipe_pipe, lshift, rshift,
    plus_eq, minus_eq, star_eq, slash_eq, percent_eq,
    kw_pub, kw_const, kw_var, kw_fn, kw_struct,
    kw_if, kw_else, kw_for, kw_while, kw_return,
    kw_true, kw_false, kw_void, kw_self, kw_or, kw_and,
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
        if (c == '\n') { self.line += 1; self.col = 1; } else { self.col += 1; }
        return c;
    }

    fn skipWhitespaceAndComments(self: *Tokenizer) void {
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                _ = self.advance();
            } else if (c == '/' and self.peekAt(1) == '/') {
                while (self.pos < self.source.len and self.source[self.pos] != '\n') _ = self.advance();
            } else if (c == '/' and self.peekAt(1) == '*') {
                _ = self.advance(); _ = self.advance();
                while (self.pos < self.source.len) {
                    if (self.source[self.pos] == '*' and self.peekAt(1) == '/') { _ = self.advance(); _ = self.advance(); break; }
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

        if (c == '"') {
            _ = self.advance();
            while (self.pos < self.source.len and self.source[self.pos] != '"') {
                if (self.source[self.pos] == '\\') _ = self.advance();
                _ = self.advance();
            }
            if (self.pos < self.source.len) _ = self.advance();
            return .{ .kind = .string_literal, .text = self.source[start + 1 .. self.pos - 1], .line = sl, .col = sc };
        }
        if (c >= '0' and c <= '9') {
            while (self.pos < self.source.len and self.source[self.pos] >= '0' and self.source[self.pos] <= '9') _ = self.advance();
            return .{ .kind = .number, .text = self.source[start..self.pos], .line = sl, .col = sc };
        }
        if (isIdentStart(c)) {
            while (self.pos < self.source.len and isIdentChar(self.source[self.pos])) _ = self.advance();
            const text = self.source[start..self.pos];
            return .{ .kind = identToKind(text), .text = text, .line = sl, .col = sc };
        }

        _ = self.advance();
        const c2 = self.peek();
        const t = self.source[start..self.pos];
        return switch (c) {
            '@' => .{ .kind = .at_sign, .text = t, .line = sl, .col = sc },
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
            '~' => .{ .kind = .tilde, .text = t, .line = sl, .col = sc },
            '^' => .{ .kind = .caret, .text = t, .line = sl, .col = sc },
            '=' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .eqeq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .assign, .text = t, .line = sl, .col = sc },
            '!' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .bang_eq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .bang, .text = t, .line = sl, .col = sc },
            '<' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .lt_eq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else if (c2 == '<') blk2: { _ = self.advance(); break :blk2 .{ .kind = .lshift, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .lt, .text = t, .line = sl, .col = sc },
            '>' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .gt_eq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else if (c2 == '>') blk2: { _ = self.advance(); break :blk2 .{ .kind = .rshift, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .gt, .text = t, .line = sl, .col = sc },
            '+' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .plus_eq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .plus, .text = t, .line = sl, .col = sc },
            '-' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .minus_eq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .minus, .text = t, .line = sl, .col = sc },
            '*' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .star_eq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .star, .text = t, .line = sl, .col = sc },
            '/' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .slash_eq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .slash, .text = t, .line = sl, .col = sc },
            '%' => if (c2 == '=') blk: { _ = self.advance(); break :blk .{ .kind = .percent_eq, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .percent, .text = t, .line = sl, .col = sc },
            '&' => if (c2 == '&') blk: { _ = self.advance(); break :blk .{ .kind = .amp_amp, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .ampersand, .text = t, .line = sl, .col = sc },
            '|' => if (c2 == '|') blk: { _ = self.advance(); break :blk .{ .kind = .pipe_pipe, .text = self.source[start..self.pos], .line = sl, .col = sc }; } else .{ .kind = .pipe, .text = t, .line = sl, .col = sc },
            else => .{ .kind = .ident, .text = t, .line = sl, .col = sc },
        };
    }

    fn isIdentStart(c: u8) bool { return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_'; }
    fn isIdentChar(c: u8) bool { return isIdentStart(c) or (c >= '0' and c <= '9'); }

    fn identToKind(text: []const u8) TokenKind {
        const map = std.StaticStringMap(TokenKind).initComptime(.{
            .{ "pub", .kw_pub }, .{ "const", .kw_const }, .{ "var", .kw_var },
            .{ "fn", .kw_fn }, .{ "struct", .kw_struct }, .{ "if", .kw_if },
            .{ "else", .kw_else }, .{ "for", .kw_for }, .{ "while", .kw_while },
            .{ "return", .kw_return }, .{ "true", .kw_true }, .{ "false", .kw_false },
            .{ "void", .kw_void }, .{ "self", .kw_self }, .{ "or", .kw_or }, .{ "and", .kw_and },
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

    const ParsedFieldType = struct {
        type_node: TypeNode,
        explicit_readonly: bool,
    };

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

    fn bump(self: *Parser) Token { const prev = self.current; self.current = self.tokenizer.next(); return prev; }

    fn expect(self: *Parser, kind: TokenKind) ?Token {
        if (self.current.kind == kind) return self.bump();
        self.addErrorFmt("expected {s}, got '{s}'", .{ @tagName(kind), self.current.text });
        return null;
    }

    fn checkIdent(self: *const Parser, text: []const u8) bool {
        return self.current.kind == .ident and std.mem.eql(u8, self.current.text, text);
    }

    fn heapExpr(self: *Parser, expr: Expression) ?*Expression {
        const ptr = self.allocator.create(Expression) catch return null;
        ptr.* = expr;
        return ptr;
    }

    fn makeBinOp(self: *Parser, op: BinOperator, left: Expression, right: Expression) ?Expression {
        const bin = self.allocator.create(BinaryOp) catch return null;
        bin.* = .{ .op = op, .left = left, .right = right };
        return Expression{ .binary_op = bin };
    }

    fn makeUnaryOp(self: *Parser, op: UnaryOperator, operand: Expression) ?Expression {
        const u = self.allocator.create(UnaryOp) catch return null;
        u.* = .{ .op = op, .operand = operand };
        return Expression{ .unary_op = u };
    }

    fn makeCall(self: *Parser, callee: []const u8, args: []Expression) ?Expression {
        const c = self.allocator.create(CallExpr) catch return null;
        c.* = .{ .callee = callee, .args = args };
        return Expression{ .call = c };
    }

    fn makeMethodCall(self: *Parser, object: []const u8, method: []const u8, args: []Expression) ?Expression {
        const mc = self.allocator.create(MethodCall) catch return null;
        mc.* = .{ .object = object, .method = method, .args = args };
        return Expression{ .method_call = mc };
    }

    fn makeRunarBuiltinExpr(self: *Parser, member: []const u8, args: []Expression) ?Expression {
        if (std.mem.eql(u8, member, "bytesEq")) {
            if (args.len != 2) {
                self.addError("runar.bytesEq expects exactly 2 arguments");
                return null;
            }
            return self.makeBinOp(.eq, args[0], args[1]);
        }
        return self.makeCall(member, args);
    }

    // ---- Top-level ----

    fn parse(self: *Parser) ParseResult {
        self.skipRunarImport();
        const contract = self.parseContractDecl();
        return .{ .contract = contract, .errors = self.errors.items };
    }

    fn skipRunarImport(self: *Parser) void {
        if (self.current.kind == .kw_const) {
            _ = self.bump();
            if (self.checkIdent("runar")) { _ = self.bump();
                if (self.current.kind == .assign) { _ = self.bump();
                    if (self.current.kind == .at_sign) { _ = self.bump();
                        if (self.checkIdent("import")) { _ = self.bump();
                            _ = self.expect(.lparen); _ = self.expect(.string_literal);
                            _ = self.expect(.rparen); _ = self.expect(.semicolon);
                            return;
                        }
                    }
                }
            }
        }
        self.addError("expected 'const runar = @import(\"runar\");' at top of file");
    }

    fn parseContractDecl(self: *Parser) ?ContractNode {
        if (self.expect(.kw_pub) == null) return null;
        if (self.expect(.kw_const) == null) return null;
        const name_tok = self.expect(.ident) orelse return null;
        if (self.expect(.assign) == null) return null;
        if (self.expect(.kw_struct) == null) return null;
        if (self.expect(.lbrace) == null) return null;

        var parent_class: ?ParentClass = null;
        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;
        var constructor: ?ConstructorNode = null;
        var methods: std.ArrayListUnmanaged(MethodNode) = .empty;
        var fields_with_defaults: std.ArrayListUnmanaged([]const u8) = .empty;
        var explicit_readonly_fields: std.ArrayListUnmanaged([]const u8) = .empty;

        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            if (self.current.kind == .kw_pub) {
                const sp = self.tokenizer.pos; const sline = self.tokenizer.line;
                const scol = self.tokenizer.col; const sc = self.current;
                _ = self.bump();

                if (self.current.kind == .kw_const) {
                    _ = self.bump();
                    if (self.checkIdent("Contract")) {
                        _ = self.bump();
                        if (self.expect(.assign) == null) continue;
                        parent_class = self.parseParentClass();
                        _ = self.expect(.semicolon);
                        continue;
                    }
                    self.skipToSemicolon();
                    continue;
                }
                if (self.current.kind == .kw_fn) {
                    _ = self.bump();
                    const fn_name = self.expect(.ident) orelse continue;
                    if (std.mem.eql(u8, fn_name.text, "init")) {
                        if (self.parseConstructor(properties.items)) |ctor| {
                            constructor = ctor;
                        }
                    } else {
                        if (self.parseMethod(fn_name.text, true)) |m| methods.append(self.allocator, m) catch {};
                    }
                    continue;
                }
                self.tokenizer.pos = sp; self.tokenizer.line = sline;
                self.tokenizer.col = scol; self.current = sc;
            }

            if (self.current.kind == .kw_fn) {
                _ = self.bump();
                const fn_name = self.expect(.ident) orelse continue;
                if (self.parseMethod(fn_name.text, false)) |m| methods.append(self.allocator, m) catch {};
                continue;
            }

            if (self.parseField(&fields_with_defaults, &explicit_readonly_fields)) |f| {
                properties.append(self.allocator, f) catch {};
            } else {
                _ = self.bump();
            }
        }

        _ = self.expect(.rbrace); _ = self.expect(.semicolon);

        if (parent_class == null) {
            self.addError("missing 'pub const Contract = runar.SmartContract;' or 'runar.StatefulSmartContract;'");
            return null;
        }

        const pc = parent_class.?;
        for (properties.items) |*prop| {
            if (pc == .smart_contract) { prop.readonly = true; } else {
                var is_explicit_readonly = false;
                for (explicit_readonly_fields.items) |fname| {
                    if (std.mem.eql(u8, fname, prop.name)) {
                        is_explicit_readonly = true;
                        break;
                    }
                }
                if (is_explicit_readonly) {
                    prop.readonly = true;
                    continue;
                }
                var has_default = false;
                for (fields_with_defaults.items) |fname| { if (std.mem.eql(u8, fname, prop.name)) { has_default = true; break; } }
                prop.readonly = !has_default;
            }
        }

        return ContractNode{
            .name = name_tok.text, .parent_class = pc, .properties = properties.items,
            .constructor = constructor orelse .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
            .methods = methods.items,
        };
    }

    fn parseParentClass(self: *Parser) ?ParentClass {
        if (!self.checkIdent("runar")) { self.addError("expected 'runar.SmartContract' or 'runar.StatefulSmartContract'"); return null; }
        _ = self.bump();
        if (self.expect(.dot) == null) return null;
        const ct = self.expect(.ident) orelse return null;
        if (std.mem.eql(u8, ct.text, "SmartContract")) return .smart_contract;
        if (std.mem.eql(u8, ct.text, "StatefulSmartContract")) return .stateful_smart_contract;
        self.addErrorFmt("unknown contract type: '{s}'", .{ct.text});
        return null;
    }

    // ---- Fields ----

    fn parseField(
        self: *Parser,
        fwd: *std.ArrayListUnmanaged([]const u8),
        explicit_readonly_fields: *std.ArrayListUnmanaged([]const u8),
    ) ?PropertyNode {
        if (self.current.kind == .kw_pub) _ = self.bump();
        if (self.current.kind != .ident) return null;
        const name_tok = self.bump();
        if (self.current.kind != .colon) return null;
        _ = self.bump();
        const parsed_type = self.parseFieldTypeNode();
        var has_default = false;
        var initializer: ?*const Expression = null;
        if (self.current.kind == .assign) {
            _ = self.bump(); has_default = true;
            if (self.parseExpression()) |e| { initializer = self.heapExpr(e); }
        }
        if (has_default) fwd.append(self.allocator, name_tok.text) catch {};
        if (parsed_type.explicit_readonly) explicit_readonly_fields.append(self.allocator, name_tok.text) catch {};
        if (self.current.kind == .comma) { _ = self.bump(); } else if (self.current.kind == .semicolon) { _ = self.bump(); }
        const expr_val: ?Expression = if (initializer) |init_ptr| init_ptr.* else null;
        return PropertyNode{ .name = name_tok.text, .type_info = typeNodeToRunarType(parsed_type.type_node), .readonly = false, .initializer = expr_val };
    }

    fn parseFieldTypeNode(self: *Parser) ParsedFieldType {
        if (self.current.kind == .ident and std.mem.eql(u8, self.current.text, "runar")) {
            _ = self.bump();
            if (self.expect(.dot) == null) {
                return .{ .type_node = .{ .custom_type = "unknown" }, .explicit_readonly = false };
            }
            if (self.current.kind != .ident) {
                self.addError("expected type name after 'runar.'");
                return .{ .type_node = .{ .custom_type = "unknown" }, .explicit_readonly = false };
            }

            const name = self.current.text;
            _ = self.bump();
            if (std.mem.eql(u8, name, "Readonly")) {
                if (self.expect(.lparen) == null) {
                    return .{ .type_node = .{ .custom_type = "unknown" }, .explicit_readonly = true };
                }
                const inner = self.parseFieldTypeNode();
                _ = self.expect(.rparen);
                return .{ .type_node = inner.type_node, .explicit_readonly = true };
            }

            return .{ .type_node = resolveRunarTypeNode(name), .explicit_readonly = false };
        }

        return .{ .type_node = self.parseTypeNode(), .explicit_readonly = false };
    }

    fn parseTypeNode(self: *Parser) TypeNode {
        if (self.current.kind == .ident) {
            if (std.mem.eql(u8, self.current.text, "i64")) { _ = self.bump(); return .{ .primitive_type = .bigint }; }
            if (std.mem.eql(u8, self.current.text, "bool")) { _ = self.bump(); return .{ .primitive_type = .boolean }; }
            if (std.mem.eql(u8, self.current.text, "runar")) {
                _ = self.bump();
                if (self.expect(.dot) == null) return .{ .custom_type = "unknown" };
                if (self.current.kind != .ident) { self.addError("expected type name after 'runar.'"); return .{ .custom_type = "unknown" }; }
                const name = self.current.text; _ = self.bump();
                return resolveRunarTypeNode(name);
            }
            const text = self.current.text; _ = self.bump();
            if (PrimitiveTypeName.fromTsString(text)) |ptn| return .{ .primitive_type = ptn };
            return .{ .custom_type = text };
        }
        if (self.current.kind == .kw_void) { _ = self.bump(); return .{ .primitive_type = .void }; }
        self.addError("expected type");
        return .{ .custom_type = "unknown" };
    }

    pub fn resolveRunarTypeNode(name: []const u8) TypeNode {
        if (std.mem.eql(u8, name, "Bigint")) return .{ .primitive_type = .bigint };
        if (std.mem.eql(u8, name, "PubKey")) return .{ .primitive_type = .pub_key };
        if (std.mem.eql(u8, name, "Sig")) return .{ .primitive_type = .sig };
        if (std.mem.eql(u8, name, "Addr")) return .{ .primitive_type = .addr };
        if (std.mem.eql(u8, name, "ByteString")) return .{ .primitive_type = .byte_string };
        if (std.mem.eql(u8, name, "Sha256")) return .{ .primitive_type = .sha256 };
        if (std.mem.eql(u8, name, "Ripemd160")) return .{ .primitive_type = .ripemd160 };
        if (std.mem.eql(u8, name, "SigHashPreimage")) return .{ .primitive_type = .sig_hash_preimage };
        if (std.mem.eql(u8, name, "RabinSig")) return .{ .primitive_type = .rabin_sig };
        if (std.mem.eql(u8, name, "RabinPubKey")) return .{ .primitive_type = .rabin_pub_key };
        if (std.mem.eql(u8, name, "Point")) return .{ .primitive_type = .point };
        return .{ .custom_type = name };
    }

    fn typeNodeName(type_node: TypeNode) []const u8 {
        return switch (type_node) {
            .primitive_type => |ptn| ptn.toTsString(),
            .fixed_array_type => "array",
            .custom_type => |name| name,
        };
    }

    // ---- Constructor ----

    fn parseConstructor(self: *Parser, properties: []const PropertyNode) ?ConstructorNode {
        if (self.expect(.lparen) == null) return null;
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            if (self.parseParam()) |p| params.append(self.allocator, p) catch {};
            if (self.current.kind == .comma) _ = self.bump();
        }
        _ = self.expect(.rparen);
        if (self.current.kind == .ident) _ = self.bump(); // return type
        if (self.expect(.lbrace) == null) return null;
        var assignments: std.ArrayListUnmanaged(AssignmentNode) = .empty;
        var found_struct_return = false;

        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            if (self.current.kind == .kw_return) {
                _ = self.bump();
                if (self.current.kind == .dot) {
                    _ = self.bump();
                    if (self.current.kind == .lbrace) {
                        self.parseStructReturnAssignments(&assignments);
                        found_struct_return = true;
                        _ = self.expect(.semicolon);
                        continue;
                    }
                }

                _ = self.parseExpression();
                _ = self.expect(.semicolon);
                continue;
            }

            _ = self.parseStatement();
        }

        _ = self.expect(.rbrace);

        if (!found_struct_return) {
            for (params.items) |param| {
                for (properties) |prop| {
                    if (std.mem.eql(u8, prop.name, param.name)) {
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
            .params = params.items,
            .super_args = &.{},
            .assignments = assignments.items,
        };
    }

    fn parseStructReturnAssignments(self: *Parser, assignments: *std.ArrayListUnmanaged(AssignmentNode)) void {
        _ = self.expect(.lbrace);
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            if (self.current.kind == .dot) _ = self.bump();
            const field = self.expect(.ident) orelse return;
            if (self.expect(.assign) == null) return;
            const value = self.parseExpression() orelse return;
            assignments.append(self.allocator, .{
                .target = field.text,
                .value = value,
            }) catch {};
            if (self.current.kind == .comma) _ = self.bump();
        }
        _ = self.expect(.rbrace);
    }

    // ---- Methods ----

    fn parseMethod(self: *Parser, name: []const u8, is_public: bool) ?MethodNode {
        if (self.expect(.lparen) == null) return null;
        if (self.current.kind == .kw_self) {
            _ = self.bump();
            if (self.current.kind == .colon) { _ = self.bump(); self.skipTypeAnnotation(); }
            if (self.current.kind == .comma) _ = self.bump();
        }
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            if (self.parseParam()) |p| params.append(self.allocator, p) catch {};
            if (self.current.kind == .comma) _ = self.bump();
        }
        _ = self.expect(.rparen);
        if (self.current.kind != .lbrace) _ = self.parseTypeNode();
        if (self.expect(.lbrace) == null) return null;
        const body = self.parseBlock();
        return MethodNode{ .name = name, .is_public = is_public, .params = params.items, .body = body };
    }

    fn parseParam(self: *Parser) ?ParamNode {
        if (self.current.kind != .ident) return null;
        const n = self.bump();
        if (self.expect(.colon) == null) return null;
        const type_node = self.parseTypeNode();
        return ParamNode{
            .name = n.text,
            .type_info = typeNodeToRunarType(type_node),
            .type_name = typeNodeName(type_node),
        };
    }

    fn skipTypeAnnotation(self: *Parser) void {
        if (self.current.kind == .star) _ = self.bump();
        if (self.current.kind == .kw_const) _ = self.bump();
        if (self.current.kind == .ident) _ = self.bump();
    }

    // ---- Statements ----

    fn parseBlock(self: *Parser) []Statement {
        var stmts: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            if (self.parseStatement()) |s| stmts.append(self.allocator, s) catch {};
        }
        _ = self.expect(.rbrace);
        return stmts.items;
    }

    fn parseStatement(self: *Parser) ?Statement {
        return switch (self.current.kind) {
            .kw_const => self.parseVarDeclStmt(false),
            .kw_var => self.parseVarDeclStmt(true),
            .kw_if => self.parseIfStmt(),
            .kw_for, .kw_while => { self.addError("loops not yet supported in .runar.zig"); _ = self.bump(); self.skipToClosingBrace(); return null; },
            .kw_return => self.parseReturnStmt(),
            else => self.parseExpressionStatement(),
        };
    }

    fn parseVarDeclStmt(self: *Parser, mutable: bool) ?Statement {
        _ = self.bump();
        const n = self.expect(.ident) orelse return null;
        var ti: ?RunarType = null;
        if (self.current.kind == .colon) { _ = self.bump(); ti = typeNodeToRunarType(self.parseTypeNode()); }
        if (self.expect(.assign) == null) return null;
        const v = self.parseExpression() orelse return null;
        _ = self.expect(.semicolon);
        if (mutable) {
            return Statement{ .let_decl = .{ .name = n.text, .type_info = ti, .value = v } };
        } else {
            return Statement{ .const_decl = .{ .name = n.text, .type_info = ti, .value = v } };
        }
    }

    fn parseIfStmt(self: *Parser) ?Statement {
        _ = self.bump();
        var hp = false;
        if (self.current.kind == .lparen) { hp = true; _ = self.bump(); }
        const cond = self.parseExpression() orelse return null;
        if (hp) _ = self.expect(.rparen);
        if (self.expect(.lbrace) == null) return null;
        const then_body = self.parseBlock();
        var else_body: ?[]Statement = null;
        if (self.current.kind == .kw_else) {
            _ = self.bump();
            if (self.current.kind == .kw_if) {
                const nested = self.parseIfStmt() orelse return null;
                const a = self.allocator.alloc(Statement, 1) catch return null;
                a[0] = nested;
                else_body = a;
            } else { if (self.expect(.lbrace) == null) return null; else_body = self.parseBlock(); }
        }
        return Statement{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body } };
    }

    fn parseReturnStmt(self: *Parser) ?Statement {
        _ = self.bump();
        if (self.current.kind == .semicolon) { _ = self.bump(); return Statement{ .return_stmt = null }; }
        if (self.current.kind == .dot) {
            _ = self.bump();
            if (self.current.kind == .lbrace) { self.skipStructLiteral(); _ = self.expect(.semicolon); return Statement{ .return_stmt = null }; }
        }
        const expr = self.parseExpression();
        _ = self.expect(.semicolon);
        if (expr) |e| return Statement{ .return_stmt = e };
        return Statement{ .return_stmt = null };
    }

    fn skipStructLiteral(self: *Parser) void {
        _ = self.expect(.lbrace);
        var d: i32 = 1;
        while (self.current.kind != .eof and d > 0) {
            if (self.current.kind == .lbrace) d += 1;
            if (self.current.kind == .rbrace) d -= 1;
            if (d > 0) _ = self.bump();
        }
        if (self.current.kind == .rbrace) _ = self.bump();
    }

    fn parseExpressionStatement(self: *Parser) ?Statement {
        const expr = self.parseExpression() orelse { _ = self.bump(); return null; };

        if (isCompoundAssignOp(self.current.kind)) {
            const ok = self.current.kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            _ = self.expect(.semicolon);
            const bo = binOpFromCompoundAssign(ok);
            const target_name = extractAssignTarget(expr);
            const bin = self.allocator.create(BinaryOp) catch return null;
            bin.* = .{ .op = bo, .left = expr, .right = rhs };
            return Statement{ .assign = .{ .target = target_name, .value = .{ .binary_op = bin } } };
        }
        if (self.current.kind == .assign) {
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            _ = self.expect(.semicolon);
            const target_name = extractAssignTarget(expr);
            return Statement{ .assign = .{ .target = target_name, .value = rhs } };
        }
        _ = self.expect(.semicolon);
        return Statement{ .expr_stmt = expr };
    }

    /// Extract a string target name from an expression for Assign.target.
    /// For identifiers: returns the name. For property_access: returns the property name.
    fn extractAssignTarget(expr: Expression) []const u8 {
        return switch (expr) {
            .identifier => |id| id,
            .property_access => |pa| pa.property,
            else => "unknown",
        };
    }

    // ---- Expressions ----

    fn parseExpression(self: *Parser) ?Expression {
        self.depth += 1;
        defer self.depth -= 1;
        if (self.depth > max_depth) {
            self.addError("expression nesting depth exceeds maximum (256)");
            return null;
        }
        return self.parseLogicalOr();
    }

    fn parseLogicalOr(self: *Parser) ?Expression {
        var left = self.parseLogicalAnd() orelse return null;
        while (self.current.kind == .pipe_pipe or self.current.kind == .kw_or) {
            _ = self.bump();
            const right = self.parseLogicalAnd() orelse return null;
            left = self.makeBinOp(.or_op, left, right) orelse return null;
        }
        return left;
    }

    fn parseLogicalAnd(self: *Parser) ?Expression {
        var left = self.parseBitwiseOr() orelse return null;
        while (self.current.kind == .amp_amp or self.current.kind == .kw_and) {
            _ = self.bump();
            const right = self.parseBitwiseOr() orelse return null;
            left = self.makeBinOp(.and_op, left, right) orelse return null;
        }
        return left;
    }

    fn parseBitwiseOr(self: *Parser) ?Expression {
        var left = self.parseBitwiseXor() orelse return null;
        while (self.current.kind == .pipe) { _ = self.bump(); const r = self.parseBitwiseXor() orelse return null;
            left = self.makeBinOp(.bitor, left, r) orelse return null; }
        return left;
    }

    fn parseBitwiseXor(self: *Parser) ?Expression {
        var left = self.parseBitwiseAnd() orelse return null;
        while (self.current.kind == .caret) { _ = self.bump(); const r = self.parseBitwiseAnd() orelse return null;
            left = self.makeBinOp(.bitxor, left, r) orelse return null; }
        return left;
    }

    fn parseBitwiseAnd(self: *Parser) ?Expression {
        var left = self.parseEquality() orelse return null;
        while (self.current.kind == .ampersand) { _ = self.bump(); const r = self.parseEquality() orelse return null;
            left = self.makeBinOp(.bitand, left, r) orelse return null; }
        return left;
    }

    fn parseEquality(self: *Parser) ?Expression {
        var left = self.parseComparison() orelse return null;
        while (self.current.kind == .eqeq or self.current.kind == .bang_eq) {
            const op: BinOperator = if (self.current.kind == .eqeq) .eq else .neq;
            _ = self.bump(); const r = self.parseComparison() orelse return null;
            left = self.makeBinOp(op, left, r) orelse return null;
        }
        return left;
    }

    fn parseComparison(self: *Parser) ?Expression {
        var left = self.parseShift() orelse return null;
        while (self.current.kind == .lt or self.current.kind == .lt_eq or self.current.kind == .gt or self.current.kind == .gt_eq) {
            const op: BinOperator = switch (self.current.kind) { .lt => .lt, .lt_eq => .lte, .gt => .gt, .gt_eq => .gte, else => unreachable };
            _ = self.bump(); const r = self.parseShift() orelse return null;
            left = self.makeBinOp(op, left, r) orelse return null;
        }
        return left;
    }

    fn parseShift(self: *Parser) ?Expression {
        var left = self.parseAdditive() orelse return null;
        while (self.current.kind == .lshift or self.current.kind == .rshift) {
            const op: BinOperator = if (self.current.kind == .lshift) .lshift else .rshift;
            _ = self.bump(); const r = self.parseAdditive() orelse return null;
            left = self.makeBinOp(op, left, r) orelse return null;
        }
        return left;
    }

    fn parseAdditive(self: *Parser) ?Expression {
        var left = self.parseMultiplicative() orelse return null;
        while (self.current.kind == .plus or self.current.kind == .minus) {
            const op: BinOperator = if (self.current.kind == .plus) .add else .sub;
            _ = self.bump(); const r = self.parseMultiplicative() orelse return null;
            left = self.makeBinOp(op, left, r) orelse return null;
        }
        return left;
    }

    fn parseMultiplicative(self: *Parser) ?Expression {
        var left = self.parseUnary() orelse return null;
        while (self.current.kind == .star or self.current.kind == .slash or self.current.kind == .percent) {
            const op: BinOperator = switch (self.current.kind) { .star => .mul, .slash => .div, .percent => .mod, else => unreachable };
            _ = self.bump(); const r = self.parseUnary() orelse return null;
            left = self.makeBinOp(op, left, r) orelse return null;
        }
        return left;
    }

    fn parseUnary(self: *Parser) ?Expression {
        if (self.current.kind == .minus) { _ = self.bump(); const o = self.parseUnary() orelse return null; return self.makeUnaryOp(.negate, o); }
        if (self.current.kind == .bang) { _ = self.bump(); const o = self.parseUnary() orelse return null; return self.makeUnaryOp(.not, o); }
        if (self.current.kind == .tilde) { _ = self.bump(); const o = self.parseUnary() orelse return null; return self.makeUnaryOp(.bitnot, o); }
        return self.parsePostfix();
    }

    fn parsePostfix(self: *Parser) ?Expression {
        var expr = self.parsePrimary() orelse return null;
        while (true) {
            if (self.current.kind == .dot) {
                _ = self.bump();
                if (self.current.kind != .ident) { self.addError("expected identifier after '.'"); return null; }
                const member = self.bump().text;
                if (self.current.kind == .lparen) {
                    // Method call: obj.method(args)
                    _ = self.bump();
                    const args = self.parseArgList();
                    const object_name = switch (expr) {
                        .identifier => |id| id,
                        .property_access => |pa| pa.property,
                        else => "unknown",
                    };
                    // Strip runar. namespace: runar.assert(x) → assert(x)
                    if (std.mem.eql(u8, object_name, "runar")) {
                        expr = self.makeRunarBuiltinExpr(member, args) orelse return null;
                    } else {
                        expr = self.makeMethodCall(object_name, member, args) orelse return null;
                    }
                } else {
                    // Property access: obj.prop
                    const object_name = switch (expr) {
                        .identifier => |id| id,
                        .property_access => |pa| pa.property,
                        else => "unknown",
                    };
                    expr = .{ .property_access = .{ .object = object_name, .property = member } };
                }
            } else if (self.current.kind == .lbracket) {
                _ = self.bump();
                const idx = self.parseExpression() orelse return null;
                const ia = self.allocator.create(IndexAccess) catch return null;
                ia.* = .{ .object = expr, .index = idx };
                expr = .{ .index_access = ia };
            } else break;
        }
        return expr;
    }

    fn parsePrimary(self: *Parser) ?Expression {
        return switch (self.current.kind) {
            .dot => blk: {
                _ = self.bump();
                if (self.current.kind != .lbrace) break :blk null;
                _ = self.bump();
                var elems: std.ArrayListUnmanaged(Expression) = .empty;
                while (self.current.kind != .rbrace and self.current.kind != .eof) {
                    const elem = self.parseExpression() orelse return null;
                    elems.append(self.allocator, elem) catch return null;
                    if (self.current.kind == .comma) _ = self.bump();
                }
                _ = self.expect(.rbrace);
                break :blk .{ .array_literal = elems.items };
            },
            .number => blk: { const tok = self.bump(); break :blk Expression{ .literal_int = std.fmt.parseInt(i64, tok.text, 10) catch { self.addErrorFmt("invalid integer: '{s}'", .{tok.text}); break :blk null; } }; },
            .kw_true => blk: { _ = self.bump(); break :blk Expression{ .literal_bool = true }; },
            .kw_false => blk: { _ = self.bump(); break :blk Expression{ .literal_bool = false }; },
            .string_literal => blk: { const tok = self.bump(); break :blk Expression{ .literal_bytes = tok.text }; },
            .kw_self => blk: { _ = self.bump(); break :blk Expression{ .identifier = "self" }; },
            .ident => blk: { const tok = self.bump();
                if (self.current.kind == .lparen) { _ = self.bump(); const args = self.parseArgList();
                    break :blk self.makeCall(tok.text, args);
                }
                break :blk Expression{ .identifier = tok.text };
            },
            .lparen => blk: { _ = self.bump(); const inner = self.parseExpression() orelse break :blk null; _ = self.expect(.rparen); break :blk inner; },
            else => blk: { self.addErrorFmt("unexpected token: '{s}'", .{self.current.text}); break :blk null; },
        };
    }

    fn parseArgList(self: *Parser) []Expression {
        var args: std.ArrayListUnmanaged(Expression) = .empty;
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            const arg = self.parseExpression() orelse break;
            args.append(self.allocator, arg) catch {};
            if (self.current.kind == .comma) _ = self.bump() else break;
        }
        _ = self.expect(.rparen);
        return args.items;
    }

    // ---- Helpers ----

    fn skipToSemicolon(self: *Parser) void {
        while (self.current.kind != .semicolon and self.current.kind != .eof) _ = self.bump();
        if (self.current.kind == .semicolon) _ = self.bump();
    }

    fn skipToClosingBrace(self: *Parser) void {
        var d: i32 = 0;
        while (self.current.kind != .eof) {
            if (self.current.kind == .lbrace) d += 1;
            if (self.current.kind == .rbrace) { if (d == 0) { _ = self.bump(); return; } d -= 1; }
            _ = self.bump();
        }
    }

    fn isCompoundAssignOp(k: TokenKind) bool {
        return k == .plus_eq or k == .minus_eq or k == .star_eq or k == .slash_eq or k == .percent_eq;
    }

    fn binOpFromCompoundAssign(k: TokenKind) BinOperator {
        return switch (k) { .plus_eq => .add, .minus_eq => .sub, .star_eq => .mul, .slash_eq => .div, .percent_eq => .mod, else => .add };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "tokenizer basics" {
    var t = Tokenizer.init("pub const P2PKH = struct { };");
    try std.testing.expectEqual(TokenKind.kw_pub, t.next().kind);
    try std.testing.expectEqual(TokenKind.kw_const, t.next().kind);
    const id = t.next(); try std.testing.expectEqualStrings("P2PKH", id.text);
    try std.testing.expectEqual(TokenKind.assign, t.next().kind);
    try std.testing.expectEqual(TokenKind.kw_struct, t.next().kind);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.semicolon, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "tokenizer operators" {
    var t = Tokenizer.init("== != <= >= << >> && || += -= *= /= %=");
    const expected = [_]TokenKind{ .eqeq, .bang_eq, .lt_eq, .gt_eq, .lshift, .rshift, .amp_amp, .pipe_pipe, .plus_eq, .minus_eq, .star_eq, .slash_eq, .percent_eq, .eof };
    for (expected) |e| try std.testing.expectEqual(e, t.next().kind);
}

test "tokenizer comments" {
    var t = Tokenizer.init("// line comment\npub const /* block\n comment */ X = 5;");
    const expected = [_]TokenKind{ .kw_pub, .kw_const, .ident, .assign, .number, .semicolon, .eof };
    for (expected) |e| try std.testing.expectEqual(e, t.next().kind);
}

test "parse P2PKH contract" {
    const source =
        \\const runar = @import("runar");
        \\pub const P2PKH = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    pub_key_hash: runar.Addr,
        \\    pub fn init(pub_key_hash: runar.Addr) P2PKH { return .{ .pub_key_hash = pub_key_hash }; }
        \\    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pub_key: runar.PubKey) void {
        \\        runar.assert(runar.hash160(pub_key) == self.pub_key_hash);
        \\        runar.assert(runar.checkSig(sig, pub_key));
        \\    }
        \\};
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseZig(arena.allocator(), source,"P2PKH.runar.zig");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqual(RunarType.addr, c.properties[0].type_info);
    try std.testing.expect(c.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqualStrings("unlock", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].params.len);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].body.len);
}

test "parse Counter contract (stateful)" {
    const source =
        \\const runar = @import("runar");
        \\pub const Counter = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\    owner: runar.PubKey,
        \\    count: i64 = 0,
        \\    pub fn init(owner: runar.PubKey, count: i64) Counter { return .{ .owner = owner, .count = count }; }
        \\    pub fn increment(self: *Counter, sig: runar.Sig) void {
        \\        runar.assert(runar.checkSig(sig, self.owner));
        \\        self.count += 1;
        \\        self.addOutput(1, self.count);
        \\    }
        \\    pub fn decrement(self: *Counter, sig: runar.Sig) void {
        \\        runar.assert(runar.checkSig(sig, self.owner));
        \\        runar.assert(self.count > 0);
        \\        self.count -= 1;
        \\        self.addOutput(1, self.count);
        \\    }
        \\};
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseZig(arena.allocator(), source,"Counter.runar.zig");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Counter", c.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 2), c.properties.len);
    try std.testing.expect(c.properties[0].readonly); // owner: no default
    try std.testing.expect(!c.properties[1].readonly); // count: has default
    try std.testing.expectEqual(@as(usize, 2), c.constructor.params.len);
    try std.testing.expectEqual(@as(usize, 2), c.constructor.assignments.len);
    try std.testing.expectEqualStrings("owner", c.constructor.assignments[0].target);
    try std.testing.expectEqualStrings("count", c.constructor.assignments[1].target);
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqual(@as(usize, 3), c.methods[0].body.len);
    try std.testing.expectEqual(std.meta.Tag(Statement).expr_stmt, std.meta.activeTag(c.methods[0].body[0]));
    try std.testing.expectEqual(std.meta.Tag(Statement).assign, std.meta.activeTag(c.methods[0].body[1]));
    try std.testing.expectEqual(std.meta.Tag(Statement).expr_stmt, std.meta.activeTag(c.methods[0].body[2]));
}

test "parse constructor struct return assignments" {
    const source =
        \\const runar = @import("runar");
        \\pub const Example = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\    count: i64 = 0,
        \\    active: bool,
        \\    pub fn init(count: i64) Example {
        \\        return .{
        \\            .count = count,
        \\            .active = true,
        \\        };
        \\    }
        \\};
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const res = parseZig(arena.allocator(), source, "Example.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const ctor = res.contract.?.constructor;
    try std.testing.expectEqual(@as(usize, 1), ctor.params.len);
    try std.testing.expectEqual(@as(usize, 2), ctor.assignments.len);
    try std.testing.expectEqualStrings("count", ctor.assignments[0].target);
    try std.testing.expectEqualStrings("active", ctor.assignments[1].target);
    switch (ctor.assignments[0].value) {
        .identifier => |name| try std.testing.expectEqualStrings("count", name),
        else => return error.UnexpectedVariant,
    }
    switch (ctor.assignments[1].value) {
        .literal_bool => |value| try std.testing.expect(value),
        else => return error.UnexpectedVariant,
    }
}

test "parse Escrow contract (multi-method)" {
    const source =
        \\const runar = @import("runar");
        \\pub const Escrow = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    buyer: runar.PubKey,
        \\    seller: runar.PubKey,
        \\    arbiter: runar.PubKey,
        \\    pub fn init(buyer: runar.PubKey, seller: runar.PubKey, arbiter: runar.PubKey) Escrow { return .{ .buyer = buyer, .seller = seller, .arbiter = arbiter }; }
        \\    pub fn release(self: *const Escrow, buyer_sig: runar.Sig, seller_sig: runar.Sig) void {
        \\        runar.assert(runar.checkSig(buyer_sig, self.buyer));
        \\        runar.assert(runar.checkSig(seller_sig, self.seller));
        \\    }
        \\    pub fn arbitrate(self: *const Escrow, arbiter_sig: runar.Sig, winner_sig: runar.Sig, winner_pub_key: runar.PubKey) void {
        \\        runar.assert(runar.checkSig(arbiter_sig, self.arbiter));
        \\        runar.assert(winner_pub_key == self.buyer or winner_pub_key == self.seller);
        \\        runar.assert(runar.checkSig(winner_sig, winner_pub_key));
        \\    }
        \\    fn verifyParticipant(self: *const Escrow, pub_key: runar.PubKey) bool {
        \\        return pub_key == self.buyer or pub_key == self.seller or pub_key == self.arbiter;
        \\    }
        \\};
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseZig(arena.allocator(), source,"Escrow.runar.zig");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Escrow", c.name);
    try std.testing.expectEqual(@as(usize, 3), c.properties.len);
    try std.testing.expectEqual(@as(usize, 3), c.methods.len);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expect(c.methods[1].is_public);
    try std.testing.expect(!c.methods[2].is_public);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].body.len);
    try std.testing.expectEqual(@as(usize, 3), c.methods[1].body.len);
    try std.testing.expectEqual(std.meta.Tag(Statement).return_stmt, std.meta.activeTag(c.methods[2].body[0]));
}

test "parse error: missing import" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseZig(arena.allocator(), "pub const P2PKH = struct { pub const Contract = runar.SmartContract; };", "bad.runar.zig");
    try std.testing.expect(r.errors.len > 0);
}

test "parse error: missing Contract decl" {
    const source = "const runar = @import(\"runar\");\npub const P2PKH = struct { name: runar.PubKey, };";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseZig(arena.allocator(), source,"bad.runar.zig");
    try std.testing.expect(r.errors.len > 0);
    try std.testing.expect(r.contract == null);
}

test "binary operators and precedence" {
    const source =
        \\const runar = @import("runar");
        \\pub const A = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    val: i64,
        \\    pub fn init(val: i64) A { return .{ .val = val }; }
        \\    pub fn check(self: *const A, x: i64) void {
        \\        const a = x + 1;
        \\        const r = x + 2 * 3;
        \\    }
        \\};
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseZig(arena2.allocator(), source, "A.runar.zig");
    for (res.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    // a = x + 1
    switch (body[0].const_decl.value) {
        .binary_op => |b| { try std.testing.expectEqual(BinOperator.add, b.op); try std.testing.expectEqual(@as(i64, 1), b.right.literal_int); },
        else => return error.UnexpectedVariant,
    }
    // r = x + (2 * 3)
    switch (body[1].const_decl.value) {
        .binary_op => |top| { try std.testing.expectEqual(BinOperator.add, top.op);
            switch (top.right) { .binary_op => |r2| { try std.testing.expectEqual(BinOperator.mul, r2.op); }, else => return error.UnexpectedVariant, }
        },
        else => return error.UnexpectedVariant,
    }
}

test "unary operators" {
    const source =
        \\const runar = @import("runar");
        \\pub const U = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    val: i64,
        \\    pub fn init(val: i64) U { return .{ .val = val }; }
        \\    pub fn check(self: *const U, x: i64) void { const a = -x; const b = !true; const c = ~x; }
        \\};
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseZig(arena2.allocator(), source, "U.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    switch (body[0].const_decl.value) { .unary_op => |u| try std.testing.expectEqual(UnaryOperator.negate, u.op), else => return error.UnexpectedVariant }
    switch (body[1].const_decl.value) { .unary_op => |u| try std.testing.expectEqual(UnaryOperator.not, u.op), else => return error.UnexpectedVariant }
    switch (body[2].const_decl.value) { .unary_op => |u| try std.testing.expectEqual(UnaryOperator.bitnot, u.op), else => return error.UnexpectedVariant }
}

test "method calls and property access" {
    const source =
        \\const runar = @import("runar");
        \\pub const MC = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    owner: runar.PubKey,
        \\    pub fn init(owner: runar.PubKey) MC { return .{ .owner = owner }; }
        \\    pub fn check(self: *const MC, sig: runar.Sig) void { runar.assert(runar.checkSig(sig, self.owner)); }
        \\};
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseZig(arena2.allocator(), source, "MC.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const outer = res.contract.?.methods[0].body[0].expr_stmt;
    switch (outer) {
        .call => |c| {
            try std.testing.expectEqualStrings("assert", c.callee);
            try std.testing.expectEqual(@as(usize, 1), c.args.len);
            switch (c.args[0]) {
                .call => |inner| { try std.testing.expectEqualStrings("checkSig", inner.callee); try std.testing.expectEqual(@as(usize, 2), inner.args.len); },
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
}

test "type resolution" {
    try std.testing.expectEqual(RunarType.bigint, typeNodeToRunarType(Parser.resolveRunarTypeNode("Bigint")));
    try std.testing.expectEqual(RunarType.pub_key, typeNodeToRunarType(Parser.resolveRunarTypeNode("PubKey")));
    try std.testing.expectEqual(RunarType.sig, typeNodeToRunarType(Parser.resolveRunarTypeNode("Sig")));
    try std.testing.expectEqual(RunarType.addr, typeNodeToRunarType(Parser.resolveRunarTypeNode("Addr")));
    try std.testing.expectEqual(RunarType.byte_string, typeNodeToRunarType(Parser.resolveRunarTypeNode("ByteString")));
    try std.testing.expectEqual(RunarType.sha256, typeNodeToRunarType(Parser.resolveRunarTypeNode("Sha256")));
    try std.testing.expectEqual(RunarType.ripemd160, typeNodeToRunarType(Parser.resolveRunarTypeNode("Ripemd160")));
    try std.testing.expectEqual(RunarType.rabin_sig, typeNodeToRunarType(Parser.resolveRunarTypeNode("RabinSig")));
    try std.testing.expectEqual(RunarType.point, typeNodeToRunarType(Parser.resolveRunarTypeNode("Point")));
}

test "parse explicit runar.Readonly fields in stateful contract" {
    const source =
        \\const runar = @import("runar");
        \\pub const ReadonlyState = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\    owner: runar.Readonly(runar.PubKey),
        \\    seed: runar.Readonly(i64) = 1,
        \\    count: i64 = 0,
        \\    pub fn init(owner: runar.PubKey) ReadonlyState {
        \\        return .{ .owner = owner, .seed = 1, .count = 0 };
        \\    }
        \\};
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const res = parseZig(arena.allocator(), source, "ReadonlyState.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const properties = res.contract.?.properties;
    try std.testing.expectEqual(@as(usize, 3), properties.len);
    try std.testing.expectEqual(RunarType.pub_key, properties[0].type_info);
    try std.testing.expect(properties[0].readonly);
    try std.testing.expectEqual(RunarType.bigint, properties[1].type_info);
    try std.testing.expect(properties[1].readonly);
    try std.testing.expectEqual(RunarType.bigint, properties[2].type_info);
    try std.testing.expect(!properties[2].readonly);
}

test "if statement" {
    const source =
        \\const runar = @import("runar");
        \\pub const I = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    val: i64,
        \\    pub fn init(val: i64) I { return .{ .val = val }; }
        \\    pub fn check(self: *const I, x: i64) void {
        \\        if (x > 0) { runar.assert(self.val > 0); } else { runar.assert(self.val == 0); }
        \\    }
        \\};
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseZig(arena2.allocator(), source, "I.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    try std.testing.expectEqual(std.meta.Tag(Statement).if_stmt, std.meta.activeTag(body[0]));
    try std.testing.expectEqual(@as(usize, 1), body[0].if_stmt.then_body.len);
    try std.testing.expect(body[0].if_stmt.else_body != null);
}

test "var decl and compound assignment" {
    const source =
        \\const runar = @import("runar");
        \\pub const V = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    val: i64,
        \\    pub fn init(val: i64) V { return .{ .val = val }; }
        \\    pub fn mutate(self: *const V, x: i64) void { var y = x; y += 10; runar.assert(y > self.val); }
        \\};
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseZig(arena2.allocator(), source, "V.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    try std.testing.expectEqual(std.meta.Tag(Statement).let_decl, std.meta.activeTag(body[0]));
    try std.testing.expectEqual(std.meta.Tag(Statement).assign, std.meta.activeTag(body[1]));
}

test "self field compound assignment" {
    const source =
        \\const runar = @import("runar");
        \\pub const S = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\    count: i64 = 0,
        \\    pub fn init(count: i64) S { return .{ .count = count }; }
        \\    pub fn inc(self: *S, sig: runar.Sig) void { self.count += 1; }
        \\};
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseZig(arena2.allocator(), source, "S.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    try std.testing.expectEqualStrings("count", res.contract.?.methods[0].body[0].assign.target);
}

test "return statement with expression" {
    const source =
        \\const runar = @import("runar");
        \\pub const R = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    val: i64,
        \\    pub fn init(val: i64) R { return .{ .val = val }; }
        \\    fn helper(self: *const R, x: i64) bool { return x > self.val; }
        \\};
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseZig(arena2.allocator(), source, "R.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const body = res.contract.?.methods[0].body;
    try std.testing.expect(body[0].return_stmt != null);
    switch (body[0].return_stmt.?) { .binary_op => |b| try std.testing.expectEqual(BinOperator.gt, b.op), else => return error.UnexpectedVariant }
}

test "logical or operator" {
    const source =
        \\const runar = @import("runar");
        \\pub const L = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    a: runar.PubKey,
        \\    b: runar.PubKey,
        \\    pub fn init(a: runar.PubKey, b: runar.PubKey) L { return .{ .a = a, .b = b }; }
        \\    pub fn check(self: *const L, pk: runar.PubKey) void { runar.assert(pk == self.a or pk == self.b); }
        \\};
    ;
    var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena2.deinit();
    const res = parseZig(arena2.allocator(), source, "L.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    switch (res.contract.?.methods[0].body[0].expr_stmt) {
        .call => |c| { try std.testing.expectEqualStrings("assert", c.callee); switch (c.args[0]) { .binary_op => |b| try std.testing.expectEqual(BinOperator.or_op, b.op), else => return error.UnexpectedVariant } },
        else => return error.UnexpectedVariant,
    }
}

test "parse runar.bytesEq as binary equality" {
    const source =
        \\const runar = @import("runar");
        \\pub const B = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    expected: runar.ByteString,
        \\    pub fn init(expected: runar.ByteString) B { return .{ .expected = expected }; }
        \\    pub fn check(self: *const B, actual: runar.ByteString) void {
        \\        runar.assert(runar.bytesEq(actual, self.expected));
        \\    }
        \\};
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const res = parseZig(arena.allocator(), source, "B.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    const stmt = res.contract.?.methods[0].body[0];
    switch (stmt.expr_stmt) {
        .call => |c| {
            try std.testing.expectEqualStrings("assert", c.callee);
            try std.testing.expectEqual(@as(usize, 1), c.args.len);
            switch (c.args[0]) {
                .binary_op => |b| try std.testing.expectEqual(BinOperator.eq, b.op),
                else => return error.UnexpectedVariant,
            }
        },
        else => return error.UnexpectedVariant,
    }
}

test "basic contract with file name" {
    const source =
        \\const runar = @import("runar");
        \\pub const T = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    v: i64,
        \\    pub fn init(v: i64) T { return .{ .v = v }; }
        \\    pub fn check(self: *const T, x: i64) void { runar.assert(x > 0); }
        \\};
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const res = parseZig(arena.allocator(), source, "test.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    try std.testing.expect(res.contract != null);
    try std.testing.expectEqualStrings("T", res.contract.?.name);
}

const UnexpectedVariant = error{UnexpectedVariant};
