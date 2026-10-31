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
const lex_diag = @import("lex_diag.zig");
const int_literal = @import("int_literal.zig");
const const_reassign = @import("const_reassign.zig");
const types = @import("../ir/types.zig");
const loop_condition = @import("loop_condition.zig");
const readonly_inference = @import("../frontend/readonly_inference.zig");

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
    const lex_errs = lex_diag.prepend(allocator, lex_diag.prependUnexpected(allocator, r.errors, file_name, t.unexpected), file_name, lex_diag.UNTERMINATED_STRING_LITERAL, t.unterminated);
    // N-344: a `const` local cannot be reassigned.
    const errs = if (r.contract) |c| const_reassign.check(allocator, file_name, c, lex_errs) else lex_errs;
    return .{ .contract = r.contract, .errors = errs };
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

        if (c == '"') {
            _ = self.advance();
            // F-011: a literal that reaches a line break (escaped or not) or
            // end of file is unterminated; it must never run on into the
            // following lines.
            while (self.pos < self.source.len and self.source[self.pos] != '"' and self.source[self.pos] != '\n' and self.source[self.pos] != '\r') {
                if (self.source[self.pos] == '\\') {
                    const nx = self.peekAt(1);
                    if (self.pos + 1 >= self.source.len or nx == '\n' or nx == '\r') break;
                    _ = self.advance();
                }
                _ = self.advance();
            }
            const content_end = self.pos;
            if (self.pos < self.source.len and self.source[self.pos] == '"') {
                _ = self.advance();
            } else if (self.unterminated == null) {
                self.unterminated = .{ .line = sl, .col = sc };
            }
            return .{ .kind = .string_literal, .text = self.source[start + 1 .. content_end], .line = sl, .col = sc };
        }
        if (c >= '0' and c <= '9') {
            // F-026: the whole glued [0-9A-Za-z_] run is one Zig integer literal;
            // stopping at the first non-digit read `0b1010` as `0` + `b1010`.
            while (self.pos < self.source.len and int_literal.isNumberContinue(self.source[self.pos])) _ = self.advance();
            const lit_text = self.source[start..self.pos];
            return .{ .kind = .number, .text = lit_text, .raw = lit_text, .line = sl, .col = sc };
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
            else => self.unexpectedChar(start, sl, sc),
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

const BarePending = struct { ptr: [*]const u8, len: usize, err_idx: usize };

const Parser = struct {
    allocator: Allocator,
    tokenizer: Tokenizer,
    current: Token,
    /// N-464: the argument locations of the list `parseArgList` returned
    /// last; `makeCall` / `makeMethodCall` copy them onto the node, as
    /// parse_ts.zig does (N-463). Both are only ever handed a list
    /// `parseArgList` just returned.
    last_arg_locs: []const ?types.SourceLocation = &.{},
    file_name: []const u8,
    errors: std.ArrayListUnmanaged([]const u8),
    nest: input_limits.NestingCounter = .{},
    nest_error: ?[]const u8 = null,
    /// N-448: bare string literals refused so far, withdrawable by
    /// `exemptBareLiteral` (matched by the literal's bytes pointer).
    bare_pending: std.ArrayListUnmanaged(BarePending) = .empty,

    const ParsedFieldType = struct {
        type_node: TypeNode,
        explicit_readonly: bool,
        /// N-093: `runar.EmbedAlways(T)`, the native spelling of `@embedAlways`.
        embed_always: bool = false,
    };

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

    /// N-093: `runar.Sighash("FLAGS")` in place of a return type is the native
    /// spelling of the `@sighash` directive (natively it is `void`). Returns
    /// null (consuming nothing) when the return type is not that spelling;
    /// otherwise consumes it and returns the flag text, or null-in-optional
    /// when the argument is not exactly one string literal.
    fn parseSighashReturnType(self: *Parser) ??[]const u8 {
        if (!self.checkIdent("runar")) return null;
        const sp = self.tokenizer.pos; const sline = self.tokenizer.line;
        const scol = self.tokenizer.col; const sc = self.current;
        _ = self.bump();
        if (self.current.kind != .dot) {
            self.tokenizer.pos = sp; self.tokenizer.line = sline; self.tokenizer.col = scol; self.current = sc;
            return null;
        }
        _ = self.bump();
        if (!self.checkIdent("Sighash")) {
            self.tokenizer.pos = sp; self.tokenizer.line = sline; self.tokenizer.col = scol; self.current = sc;
            return null;
        }
        _ = self.bump();
        _ = self.expect(.lparen);
        const arg = self.current;
        var count: usize = 0;
        var depth: usize = 0;
        while (self.current.kind != .eof) {
            const k = self.current.kind;
            if (k == .rparen and depth == 0) break;
            if (k == .lparen) depth += 1;
            if (k == .rparen) depth -= 1;
            _ = self.bump();
            count += 1;
        }
        _ = self.expect(.rparen);
        const spec: ?[]const u8 = if (count == 1 and arg.kind == .string_literal) arg.text else null;
        return spec;
    }

    /// N-448: a bare non-empty string literal used as a ByteString value is
    /// refused. Natively it is ASCII text; the compiler reads it as hex. The
    /// error is recorded now and withdrawn by `exemptBareLiteral` when the
    /// literal turns out to be the argument of the explicit hex helper or the
    /// body of an `asm` call (both parse their arguments as ordinary
    /// expressions first). Exempt outright: the empty string.
    fn refuseBareLiteral(self: *Parser, tok: Token, value: []const u8) void {
        if (value.len == 0) return;
        const msg = std.fmt.allocPrint(self.allocator, lex_diag.ZIG_BARE_STRING_LITERAL_FMT, .{ value, value }) catch return;
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, tok.line, lex_diag.diagCol(tok.col), msg }) catch return;
        // A speculative re-parse of the same tokens must not repeat the refusal.
        for (self.errors.items) |e| if (std.mem.eql(u8, e, f)) return;
        self.errors.append(self.allocator, f) catch return;
        self.bare_pending.append(self.allocator, .{ .ptr = value.ptr, .len = value.len, .err_idx = self.errors.items.len - 1 }) catch {};
    }

    fn exemptBareLiteral(self: *Parser, e: Expression) void {
        if (e != .literal_bytes) return;
        const v = e.literal_bytes.value;
        var i: usize = 0;
        while (i < self.bare_pending.items.len) : (i += 1) {
            const it = self.bare_pending.items[i];
            if (it.ptr == v.ptr and it.len == v.len) {
                _ = self.errors.orderedRemove(it.err_idx);
                _ = self.bare_pending.orderedRemove(i);
                for (self.bare_pending.items) |*o| {
                    if (o.err_idx > it.err_idx) o.err_idx -= 1;
                }
                return;
            }
        }
    }

    fn addErrorFmt(self: *Parser, comptime fmt: []const u8, args: anytype) void {
        const msg = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        const f = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, self.current.line, lex_diag.diagCol(self.current.col), msg }) catch return;
        self.allocator.free(msg);
        self.errors.append(self.allocator, f) catch {};
    }

    fn bump(self: *Parser) Token { const prev = self.current; self.current = self.fetch(); return prev; }

    fn currentSourceLoc(self: *const Parser) types.SourceLocation {
        return .{ .file = self.file_name, .line = self.current.line, .column = self.current.col };
    }

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
        const arg_locs: []const ?types.SourceLocation = if (self.last_arg_locs.len == args.len) self.last_arg_locs else &.{};
        c.* = .{ .callee = callee, .args = args, .arg_locs = arg_locs };
        return Expression{ .call = c };
    }

    fn makeMethodCall(self: *Parser, object: []const u8, method: []const u8, args: []Expression) ?Expression {
        const mc = self.allocator.create(MethodCall) catch return null;
        const arg_locs: []const ?types.SourceLocation = if (self.last_arg_locs.len == args.len) self.last_arg_locs else &.{};
        mc.* = .{ .object = object, .method = method, .args = args, .arg_locs = arg_locs };
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
        // runar.hexToBytes("deadbeef") -> literal_bytes "deadbeef" (compile-time hex decode).
        // Mirrors the Python parser's bytes.fromhex(...) handling — produces a
        // ByteString literal that downstream emit decodes as 4-byte hex, not
        // an 8-byte ASCII string. Allows the Zig DSL source to also compile
        // as a native Zig file, where runar.hexToBytes is a comptime helper
        // returning `*const [N]u8` (which coerces to ByteString).
        // N-448: the argument of the explicit hex spelling is a legal literal.
        if (std.mem.eql(u8, member, "asm") and args.len > 0) self.exemptBareLiteral(args[0]);
        if (std.mem.eql(u8, member, "hexToBytes")) {
            if (args.len == 1) self.exemptBareLiteral(args[0]);
            if (args.len != 1) {
                self.addError("runar.hexToBytes expects exactly 1 argument");
                return null;
            }
            switch (args[0]) {
                .literal_bytes => |s| return Expression{ .literal_bytes = s },
                else => {
                    self.addError("runar.hexToBytes expects a string literal argument");
                    return null;
                },
            }
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

            if (self.current.kind == .ident) {
                if (self.parseField(&fields_with_defaults, &explicit_readonly_fields)) |f| {
                    properties.append(self.allocator, f) catch {};
                }
                continue;
            }

            // N-410: any other token is refused, never skipped.
            self.addErrorFmt(lex_diag.UNEXPECTED_STRUCT_BODY_TOKEN_FMT, .{self.current.text});
            _ = self.bump();
        }

        _ = self.expect(.rbrace); _ = self.expect(.semicolon);

        if (parent_class == null) {
            self.addError("missing 'pub const Contract = runar.SmartContract;' or 'runar.StatefulSmartContract;'");
            return null;
        }

        const pc = parent_class.?;
        for (properties.items) |*prop| {
            if (pc == .smart_contract or pc == .unsafe_smart_contract) { prop.readonly = true; } else {
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

        // F-213 measure (B), before the recursive pass below walks the bodies.
        if (self.nest.exceeded or input_limits.membersTooDeep(properties.items, methods.items)) {
            self.refuseNesting();
            return null;
        }

        // Rule 3: a field with no default that a method body ASSIGNS is state,
        // not a constructor constant. Without this the no-default shape was
        // inferred fully-readonly and the stateful continuation was dropped.
        readonly_inference.applyMutationInference(self.allocator, pc, properties.items, methods.items, explicit_readonly_fields.items) catch {
            // N-219: swallowing this here would be the same bug one level up
            // -- a stateful contract compiled under memory pressure would
            // keep whatever readonly flags rules 1/2 left it with (silently
            // wrong, not refused) instead of failing closed.
            self.addError("out of memory while inferring mutable fields");
            return null;
        };

        return ContractNode{
            .name = name_tok.text, .parent_class = pc, .properties = properties.items,
            .constructor = constructor orelse .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
            .methods = methods.items,
        };
    }

    fn parseParentClass(self: *Parser) ?ParentClass {
        if (!self.checkIdent("runar")) { self.addError("expected 'runar.SmartContract', 'runar.StatefulSmartContract', or 'runar.UnsafeSmartContract'"); return null; }
        _ = self.bump();
        if (self.expect(.dot) == null) return null;
        const ct = self.expect(.ident) orelse return null;
        if (std.mem.eql(u8, ct.text, "SmartContract")) return .smart_contract;
        if (std.mem.eql(u8, ct.text, "StatefulSmartContract")) return .stateful_smart_contract;
        if (std.mem.eql(u8, ct.text, "UnsafeSmartContract")) return .unsafe_smart_contract;
        self.addErrorFmt("unknown parent class: '{s}', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract", .{ct.text});
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
        // N-410: an identifier that is no field (no `:`) is refused, as TS does.
        if (self.expect(.colon) == null) return null;
        const parsed_type = self.parseFieldTypeNode();
        var has_default = false;
        var initializer: ?*const Expression = null;
        if (self.current.kind == .assign) {
            _ = self.bump(); has_default = true;
            if (self.parseExpression()) |e| { initializer = self.heapExpr(e); }
        }
        if (has_default) fwd.append(self.allocator, name_tok.text) catch {};
        if (parsed_type.explicit_readonly) explicit_readonly_fields.append(self.allocator, name_tok.text) catch {};
        // N-033: fields are separated by `,`; only the last before `}` may omit it.
        _ = self.expectListSeparator(.rbrace);
        const expr_val: ?Expression = if (initializer) |init_ptr| init_ptr.* else null;

        // Capture FixedArray shape (outer + optional nested length) so
        // `expand_fixed_arrays.zig` can see the property after typecheck.
        var fa_len: u32 = 0;
        var fa_elem: RunarType = .unknown;
        var fa_nested_len: u32 = 0;
        if (parsed_type.type_node == .fixed_array_type) {
            fa_len = parsed_type.type_node.fixed_array_type.length;
            const inner = parsed_type.type_node.fixed_array_type.element.*;
            fa_elem = typeNodeToRunarType(inner);
            if (inner == .fixed_array_type) {
                fa_nested_len = inner.fixed_array_type.length;
            }
        }

        return PropertyNode{
            .name = name_tok.text,
            .type_info = typeNodeToRunarType(parsed_type.type_node),
            .readonly = false,
            .initializer = expr_val,
            .embed_always = parsed_type.embed_always,
            // N-109: spelled type name + field-name token, for the validator's
            // unsupported-type diagnostic. Diagnostics only.
            .type_name = types.typeNodeName(parsed_type.type_node),
            .source_loc = .{ .file = self.file_name, .line = name_tok.line, .column = name_tok.col },
            .fixed_array_length = fa_len,
            .fixed_array_element = fa_elem,
            .fixed_array_nested_length = fa_nested_len,
        };
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
                const inner = self.nestedValue(ParsedFieldType, .{ .type_node = .{ .primitive_type = .void }, .explicit_readonly = false }, Parser.parseFieldTypeNode, .{});
                _ = self.expect(.rparen);
                return .{ .type_node = inner.type_node, .explicit_readonly = true, .embed_always = inner.embed_always };
            }
            // N-093: `runar.EmbedAlways(T)`, the native spelling of
            // `@embedAlways`; composes with `runar.Readonly` in either order.
            if (std.mem.eql(u8, name, "EmbedAlways") and self.current.kind == .lparen) {
                _ = self.bump();
                const inner = self.nestedValue(ParsedFieldType, .{ .type_node = .{ .primitive_type = .void }, .explicit_readonly = false }, Parser.parseFieldTypeNode, .{});
                _ = self.expect(.rparen);
                return .{ .type_node = inner.type_node, .explicit_readonly = inner.explicit_readonly, .embed_always = true };
            }

            return .{ .type_node = resolveRunarTypeNode(name), .explicit_readonly = false };
        }

        return .{ .type_node = self.parseTypeNode(), .explicit_readonly = false };
    }

    fn parseTypeNode(self: *Parser) TypeNode {
        // Zig-style fixed array: `[N]T` (recursive for `[M][N]T`). The
        // `[_]T` unsized form is rejected — Rúnar requires a concrete
        // length.
        if (self.current.kind == .lbracket) {
            _ = self.bump(); // '['
            if (self.current.kind != .number) {
                self.addError("FixedArray length must be a positive integer literal");
                // Recover: eat until ']' to keep the parser afloat.
                while (self.current.kind != .rbracket and self.current.kind != .eof) _ = self.bump();
                if (self.current.kind == .rbracket) _ = self.bump();
                return .{ .custom_type = "unknown" };
            }
            const size_tok = self.bump();
            const size = std.fmt.parseInt(u32, size_tok.text, 10) catch 0;
            _ = self.expect(.rbracket);
            const inner = self.nestedValue(TypeNode, .{ .primitive_type = .void }, Parser.parseTypeNode, .{});
            const inner_ptr = self.allocator.create(TypeNode) catch return .{ .custom_type = "unknown" };
            inner_ptr.* = inner;
            return .{ .fixed_array_type = .{ .element = inner_ptr, .length = size } };
        }
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
        if (std.mem.eql(u8, name, "Bigint") or std.mem.eql(u8, name, "BigintBig")) return .{ .primitive_type = .bigint };
        if (std.mem.eql(u8, name, "PubKey")) return .{ .primitive_type = .pub_key };
        if (std.mem.eql(u8, name, "Sig")) return .{ .primitive_type = .sig };
        if (std.mem.eql(u8, name, "Addr")) return .{ .primitive_type = .addr };
        if (std.mem.eql(u8, name, "ByteString")) return .{ .primitive_type = .byte_string };
        if (std.mem.eql(u8, name, "Sha256") or std.mem.eql(u8, name, "Sha256Digest")) return .{ .primitive_type = .sha256 };
        if (std.mem.eql(u8, name, "Ripemd160")) return .{ .primitive_type = .ripemd160 };
        if (std.mem.eql(u8, name, "SigHashPreimage")) return .{ .primitive_type = .sig_hash_preimage };
        if (std.mem.eql(u8, name, "RabinSig")) return .{ .primitive_type = .rabin_sig };
        if (std.mem.eql(u8, name, "RabinPubKey")) return .{ .primitive_type = .rabin_pub_key };
        if (std.mem.eql(u8, name, "Point")) return .{ .primitive_type = .point };
        if (std.mem.eql(u8, name, "P256Point")) return .{ .primitive_type = .p256_point };
        if (std.mem.eql(u8, name, "P384Point")) return .{ .primitive_type = .p384_point };
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
        const ctor_loc = self.currentSourceLoc();
        if (self.expect(.lparen) == null) return null;
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            if (self.parseParam()) |p| params.append(self.allocator, p) catch {};
            // N-033: parameters are separated by `,` (a trailing one is allowed).
            if (!self.expectListSeparator(.rparen)) break;
        }
        _ = self.expect(.rparen);
        // N-093: the constructor is not a spending entry point, so a
        // `runar.Sighash(...)` return type on `init` would be dropped.
        if (self.parseSighashReturnType() != null) {
            self.addErrorAtLoc(ctor_loc, sighash_directive.LOST_SIGHASH_ERROR);
        } else if (self.current.kind == .ident) _ = self.bump(); // return type
        if (self.expect(.lbrace) == null) return null;
        var assignments: std.ArrayListUnmanaged(AssignmentNode) = .empty;
        var found_struct_return = false;
        // R-040: statements the `init` body carries beyond the `return .{...}`
        // struct literal — `runar.assert(...)` on a parameter, a local `const`.
        // These used to be parsed and thrown away (`_ = self.parseStatement()`),
        // so an argument check written in `init` existed in six tiers' ANF and
        // in none of Zig's. The field writes are appended after them, since the
        // struct-return literal is by construction the last statement.
        var ctor_body: std.ArrayListUnmanaged(Statement) = .empty;

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

            if (self.parseStatement()) |stmt| {
                ctor_body.append(self.allocator, stmt) catch {};
            }
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

        for (assignments.items) |assign| {
            ctor_body.append(self.allocator, .{ .assign = .{
                .target = assign.target,
                .value = assign.value,
                .target_is_property = true,
            } }) catch {};
        }

        // Auto-generate super() args from constructor params (matching TS/Go/Rust/Python
        // behavior — all format parsers auto-inject super() as the first statement).
        var super_args: std.ArrayListUnmanaged(Expression) = .empty;
        for (params.items) |param| {
            super_args.append(self.allocator, .{ .identifier = param.name }) catch {};
        }

        return .{
            .params = params.items,
            .super_args = super_args.items,
            .assignments = assignments.items,
            .body = ctor_body.items,
        };
    }

    fn parseStructReturnAssignments(self: *Parser, assignments: *std.ArrayListUnmanaged(AssignmentNode)) void {
        _ = self.expect(.lbrace);
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            // N-410: Zig requires the leading `.` of a struct-init field.
            if (self.current.kind == .dot) {
                _ = self.bump();
            } else {
                self.addError(lex_diag.ZIG_STRUCT_INIT_DOT);
            }
            const field = self.expect(.ident) orelse return;
            if (self.expect(.assign) == null) return;
            const value = self.parseExpression() orelse return;
            assignments.append(self.allocator, .{
                .target = field.text,
                .value = value,
            }) catch {};
            // N-033: struct-init fields are separated by `,` (a trailing one is allowed).
            if (!self.expectListSeparator(.rbrace)) break;
        }
        _ = self.expect(.rbrace);
    }

    // ---- Methods ----

    fn parseMethod(self: *Parser, name: []const u8, is_public: bool) ?MethodNode {
        const method_loc = self.currentSourceLoc();
        if (self.expect(.lparen) == null) return null;
        const has_receiver = self.current.kind == .kw_self;
        if (has_receiver) {
            _ = self.bump();
            if (self.current.kind == .colon) { _ = self.bump(); self.skipTypeAnnotation(); }
            // N-033: the receiver is separated from the next parameter by `,`.
            _ = self.expectListSeparator(.rparen);
        }
        // N-050: a `pub fn` without a receiver is a namespace (static)
        // function, not a contract method. A private one stays a helper (the
        // multi-method golden's computeThreshold), like R9. (`init` never
        // reaches here.)
        if (is_public and !has_receiver) self.addErrorFmt(lex_diag.STATIC_METHOD_FMT, .{name});
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            if (self.parseParam()) |p| params.append(self.allocator, p) catch {};
            // N-033: parameters are separated by `,` (a trailing one is allowed).
            if (!self.expectListSeparator(.rparen)) break;
        }
        _ = self.expect(.rparen);
        // Return type. N-093: `runar.Sighash("FLAGS")` in its place is the
        // native spelling of the `@sighash` directive.
        var sighash_specs: std.ArrayListUnmanaged(?[]const u8) = .empty;
        if (self.parseSighashReturnType()) |spec| {
            sighash_specs.append(self.allocator, spec) catch {};
        } else if (self.current.kind != .lbrace) {
            // The AST keeps no return type; N-331 refuses an unknown name.
            // `init` returns the contract struct itself, which is not a type
            // to check.
            const rt = self.parseTypeNode();
            if (!std.mem.eql(u8, name, "init")) {
                const rt_unknown = types.spelledIfUnknown(typeNodeToRunarType(rt), typeNodeName(rt));
                if (rt_unknown.len > 0) {
                    self.addErrorFmt(lex_diag.UNKNOWN_RETURN_TYPE_FMT, .{ rt_unknown, name });
                } else if (is_public and typeNodeToRunarType(rt) != .void) {
                    // N-332: public methods return nothing.
                    self.addErrorFmt(lex_diag.PUBLIC_RETURN_TYPE_FMT, .{name});
                }
            }
        }
        if (self.expect(.lbrace) == null) return null;
        const body = self.parseBlock();
        var sighash_type: ?i32 = null;
        if (std.mem.eql(u8, name, "init")) {
            // N-093: a (non-`pub`) `fn init` is still the constructor's name,
            // not a spending entry point (the TS reference checks the name
            // before visibility).
            if (sighash_specs.items.len > 0) self.addErrorAtLoc(method_loc, sighash_directive.LOST_SIGHASH_ERROR);
        } else if (sighash_directive.resolveNativeSighash(self.allocator, name, is_public, sighash_specs.items)) |r| switch (r) {
            .value => |v| sighash_type = v,
            .err => |e| self.addErrorAtLoc(method_loc, e),
        };
        return MethodNode{ .name = name, .is_public = is_public, .params = params.items, .body = body, .sighash_type = sighash_type, .source_loc = method_loc };
    }

    fn parseParam(self: *Parser) ?ParamNode {
        if (self.current.kind != .ident) return null;
        const n = self.bump();
        if (self.expect(.colon) == null) return null;
        const type_node = self.parseTypeNode();
        const param_ti = typeNodeToRunarType(type_node);
        return ParamNode{
            .name = n.text,
            .type_info = param_ti,
            .type_name = typeNodeName(type_node),
            .spelled_type = types.spelledIfUnknown(param_ti, typeNodeName(type_node)),
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
            if (self.parseStatement()) |s| {
                // Merge `var i: i64 = 0; while (i < N) : (i += 1) { ... }` into a single for_stmt
                // by patching the init_value from the preceding let_decl.
                //
                // N-008: fold exactly as the reference (01-parse-zig.ts) does —
                // only when the preceding statement declares the variable the
                // UPDATE advances — and otherwise keep its ` __while_no_init`
                // placeholder iterator, which the condition never tests, so
                // validate.zig refuses the loop with the reference's sentence.
                // This tier used to fold on the name the CONDITION tests and,
                // when nothing folded, keep that name with a start of 0: a
                // non-adjacent `var i = 3;` compiled from 0, a silent
                // miscompile every other tier refuses.
                if (s == .for_stmt) {
                    const upd_name = whileUpdateTargetName(s.for_stmt);
                    const last: ?*Statement = if (stmts.items.len > 0) &stmts.items[stmts.items.len - 1] else null;
                    if (last != null and last.?.* == .let_decl and upd_name != null and
                        std.mem.eql(u8, last.?.let_decl.name, upd_name.?))
                    {
                        const ld = last.?.let_decl;
                        // N-138: a negated literal is a literal.
                        // N-137: a declaration whose value is not a literal
                        // at all leaves the start unknown, which the
                        // unrolled loop model cannot represent.
                        var init_val: i64 = 0;
                        var init_const = true;
                        if (ld.value) |v| {
                            if (loopStartLiteral(v)) |n| init_val = n else {
                                init_const = false;
                            }
                        }
                        stmts.items.len -= 1; // pop the let_decl
                        var merged = s.for_stmt;
                        merged.init_value = init_val;
                        merged.init_is_const = init_const;
                        // The folded declaration is the iterator. A
                        // condition naming some other variable does not
                        // test it.
                        if (!std.mem.eql(u8, merged.var_name, ld.name)) merged.cond_tests_iter = false;
                        merged.var_name = ld.name;
                        stmts.append(self.allocator, .{ .for_stmt = merged }) catch {};
                        continue;
                    }
                    var unfolded = s.for_stmt;
                    // N-009: a LEADING SPACE makes this unspellable in
                    // `.runar.zig` source, so a developer local literally
                    // named "__while_no_init" can never alias this
                    // placeholder by string equality (this tier's own
                    // `cond_tests_iter` is already decided by this point and
                    // does not depend on the name, but the diagnostic text
                    // below interpolates `var_name` and must match the other
                    // six tiers' sentinel verbatim).
                    unfolded.var_name = " __while_no_init";
                    unfolded.cond_tests_iter = false;
                    stmts.append(self.allocator, .{ .for_stmt = unfolded }) catch {};
                    continue;
                }
                stmts.append(self.allocator, s) catch {};
            }
        }
        _ = self.expect(.rbrace);
        return stmts.items;
    }

    fn parseStatement(self: *Parser) ?Statement {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
        return self.parseStatementInner();
    }

    fn parseStatementInner(self: *Parser) ?Statement {
        return switch (self.current.kind) {
            .kw_const => self.parseVarDeclStmt(false),
            .kw_var => self.parseVarDeclStmt(true),
            .kw_if => self.parseIfStmt(),
            .kw_while => self.parseWhileStmt(),
            .kw_for => { self.addError("unsupported 'for' syntax in .runar.zig — use 'while' loops instead"); _ = self.bump(); self.skipToClosingBrace(); return null; },
            .kw_return => self.parseReturnStmt(),
            else => self.parseExpressionStatement(),
        };
    }

    fn parseVarDeclStmt(self: *Parser, mutable: bool) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump();
        const n = self.expect(.ident) orelse return null;
        var ti: ?RunarType = null;
        var spelled: []const u8 = "";
        if (self.current.kind == .colon) {
            _ = self.bump();
            const tn = self.parseTypeNode();
            ti = typeNodeToRunarType(tn);
            spelled = types.typeNodeName(tn);
        }
        if (self.expect(.assign) == null) return null;
        const v = self.parseExpression() orelse return null;
        _ = self.expect(.semicolon);
        if (mutable) {
            return Statement{ .let_decl = .{ .name = n.text, .type_info = ti, .value = v, .source_loc = loc, .type_name = spelled } };
        } else {
            return Statement{ .const_decl = .{ .name = n.text, .type_info = ti, .value = v, .source_loc = loc, .type_name = spelled } };
        }
    }

    fn parseIfStmt(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
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
                const nested = self.nestedParse(Statement, Parser.parseIfStmt) orelse return null;
                const a = self.allocator.alloc(Statement, 1) catch return null;
                a[0] = nested;
                else_body = a;
            } else { if (self.expect(.lbrace) == null) return null; else_body = self.parseBlock(); }
        }
        return Statement{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body, .source_loc = loc } };
    }

    /// Heap-copy a for-loop update statement so `ForStmt.update` can point at
    /// it (N-061). Returns null if the allocation fails — the update is then
    /// treated as absent, exactly as before this field existed.
    fn storeUpdateStmt(self: *Parser, stmt: Statement) ?*const Statement {
        const ptr = self.allocator.create(Statement) catch return null;
        ptr.* = stmt;
        return ptr;
    }

    /// Emitted for `while (i != N)`, which is not a representable loop bound.
    const loop_neq_condition_diagnostic =
        "while loop condition must compare the loop variable against a bound " ++
        "with '<', '<=', '>' or '>=' — '!=' carries no direction and is not a " ++
        "loop bound the unrolled loop model can represent.";

    /// Parse Zig while loop: `while (cond) : (continue_expr) { body }`
    ///
    /// Supports common Runar patterns:
    ///   var i: i64 = 0; while (i < 10) : (i += 1) { ... }   // count up
    ///   var i: i64 = 10; while (i > 0) : (i -= 1) { ... }   // count down
    ///   while (10 > i) : (i += 1) { ... }                    // reversed (N-115)
    ///
    /// `while (i != N)` is NOT one of them — see the `.neq` branch below.
    ///
    /// Produces a ForStmt. The init_value defaults to 0 and is patched by
    /// parseBlock when a preceding let_decl matches the loop variable.
    fn parseWhileStmt(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // consume 'while'

        // Condition: while (i < N)
        var has_paren = false;
        if (self.current.kind == .lparen) { has_paren = true; _ = self.bump(); }
        const cond = self.parseExpression() orelse {
            self.addError("expected condition expression in while loop");
            self.skipToClosingBrace();
            return null;
        };
        if (has_paren) _ = self.expect(.rparen);
        // N-115: `N > i` is `i < N` (and `N < i` is `i > N`, …), on this
        // surface exactly as in every other tier.
        loop_condition.normalize(cond, null);

        // Extract var_name and bound from condition.
        // Supported patterns:
        //   ident < literal   → var_name=ident, bound=literal
        //   ident <= literal  → var_name=ident, bound=literal+1
        //   ident > literal   → var_name=ident, bound=literal (countdown)
        //   ident >= literal  → var_name=ident, bound=literal (countdown)
        //   ident != literal  → var_name=ident, bound=literal (until value)
        // A reversed comparison (`literal > ident`, …) was mirrored above.
        var var_name: []const u8 = "_loop_var";
        var bound: i64 = 0;
        // R-102: `descending` was never set here, so `while (i > 1) : (i -= 1)`
        // — the shape the doc comment above has always claimed to support —
        // lowered as an ASCENDING loop from `start` to `bound`, i.e. a count of
        // `bound - start`, clamped to 0. The body, and every assertion in it,
        // was dropped from the locking script with no diagnostic. Every other
        // tier lowered the same `.runar.zig` source to a real countdown, so
        // this was a one-tier hex divergence as well as a dropped guard.
        //
        // The range-style spellings below keep folding their inclusive
        // endpoint into `bound` and stay ascending; only the raw comparison
        // directions set `descending` / `inclusive`, exactly as parse_ts does.
        var descending = false;
        var inclusive = false;
        // W4: whether the condition's left-hand side is the iterator itself.
        // `var_name` is TAKEN from the condition here, so a computed left-hand
        // side (`i + 1 < 2`) left it at its `_loop_var` default while `bound`
        // was still read from the right -- the phantom-lap shape, on the
        // `.runar.zig` surface. Rejected by passes/validate.zig.
        var cond_tests_iter: bool = true;
        // F-025: see `ForStmt.bound_is_const`. Only a (possibly negated)
        // integer literal is unrollable; a bound this function did not
        // recognise used to stay at 0 and compile a loop that runs zero times.
        var bound_is_const: bool = false;
        var bound_ident: ?[]const u8 = null;
        // N-008: see `ForStmt.cond_lhs_name`.
        var cond_lhs_name: ?[]const u8 = null;
        if (cond == .binary_op and cond.binary_op.left == .identifier) cond_lhs_name = cond.binary_op.left.identifier;
        switch (cond) {
            .binary_op => |bop| {
                if (bop.op == .lt or bop.op == .lte) {
                    // ident < N or ident <= N
                    if (bop.left == .identifier) {
                        var_name = bop.left.identifier;
                    } else {
                        cond_tests_iter = false;
                    }
                    if (loopStartLiteral(bop.right)) |v| {
                        bound = v;
                        if (bop.op == .lte) bound += 1;
                        bound_is_const = true;
                    } else if (bop.right == .identifier) {
                        bound_ident = bop.right.identifier;
                    }
                } else if (bop.op == .gt or bop.op == .gte) {
                    if (bop.left != .identifier and bop.right != .identifier) {
                        cond_tests_iter = false;
                    }
                    if (bop.left == .identifier and loopStartLiteral(bop.right) != null) {
                        // ident > N or ident >= N (countdown)
                        var_name = bop.left.identifier;
                        bound = loopStartLiteral(bop.right).?;
                        bound_is_const = true;
                        descending = true;
                        inclusive = bop.op == .gte;
                    } else if (bop.left == .identifier) {
                        // ident > <non-literal> (countdown) -- F-025: refused
                        // by validate.zig through `bound_is_const = false`.
                        var_name = bop.left.identifier;
                        if (bop.right == .identifier) bound_ident = bop.right.identifier;
                        descending = true;
                        inclusive = bop.op == .gte;
                    }
                } else if (bop.op == .neq) {
                    // `i != N` is NOT a loop bound. `spec/grammar.md`'s RelOp
                    // production is `< | <= | > | >=`, and all six peer tiers
                    // refuse the shape from ANF lowering ("For loop counting
                    // up (i++) must use '<' or '<='"). This tier accepted it
                    // alone, on the `.runar.zig` surface, which is a frontend
                    // parity break that no fixture covered — and it accepted
                    // it WRONGLY, unrolling `bound - start` times (zero for
                    // any real countdown) because `!=` carries no direction.
                    //
                    // Converging onto the spec rather than onto this tier's
                    // extension: gated by
                    // conformance/negatives/N39-zig-loop-neq-condition.runar.zig.
                    self.addError(loop_neq_condition_diagnostic);
                }
            },
            else => {
                self.addError("while loop condition must be a comparison (e.g. 'i < N', 'i > 0')");
            },
        }
        // Continue expression: : (i += 1)
        //
        // N-061: this used to be parsed and discarded — only `var_name` and
        // `bound` were kept, and the step came from the comparison direction —
        // so `i += 2` compiled to bytes identical to `i += 1`. Record it as
        // the equivalent `i = i + 1` assignment (the spelling the other six
        // tiers' Zig frontends produce) so validate.zig can reject a step the
        // unrolled loop model cannot represent.
        var update: ?*const Statement = null;
        if (self.current.kind == .colon) {
            _ = self.bump();
            if (self.current.kind == .lparen) _ = self.bump();
            const lhs = self.parseExpression();
            // Handle compound assignment operator if present
            if (isCompoundAssignOp(self.current.kind)) {
                const op: ?BinOperator = switch (self.current.kind) {
                    .plus_eq => .add,
                    .minus_eq => .sub,
                    .star_eq => .mul,
                    .slash_eq => .div,
                    .percent_eq => .mod,
                    else => null,
                };
                _ = self.bump(); // consume +=, -=, etc.
                const rhs = self.parseExpression(); // consume RHS
                if (lhs != null and rhs != null and op != null and lhs.? == .identifier) {
                    const bin = self.allocator.create(BinaryOp) catch null;
                    if (bin) |ptr| {
                        ptr.* = .{ .op = op.?, .left = lhs.?, .right = rhs.? };
                        update = self.storeUpdateStmt(.{ .assign = .{
                            .target = lhs.?.identifier,
                            .value = .{ .binary_op = ptr },
                        } });
                    }
                }
            } else if (lhs) |e| {
                // N-116: a bare continue expression (`: (i)`) is recorded as
                // the expression statement the reference builds, so the fold
                // and validate.zig see it. It used to be dropped, leaving
                // `update == null`, which nothing checks.
                update = self.storeUpdateStmt(.{ .expr_stmt = .{ .expr = e } });
            }
            if (self.current.kind == .rparen) _ = self.bump();
        }

        if (self.expect(.lbrace) == null) return null;
        const body = self.parseBlock();

        return Statement{ .for_stmt = .{
            .var_name = var_name,
            .init_value = 0, // will be patched by parseBlock if preceding let_decl matches
            .init_is_const = true, // N-026: no declaration folded in => the reference's literal 0
            .bound = bound,
            .bound_is_const = bound_is_const,
            .bound_ident = bound_ident,
            .descending = descending,
            .inclusive = inclusive,
            .cond_tests_iter = cond_tests_iter,
            .update = update,
            .cond_lhs_name = cond_lhs_name,
            .body = body,
            .source_loc = loc,
        } };
    }

    /// N-008: the variable a while loop's continue expression advances — the
    /// name the reference folds the preceding declaration on — or null when
    /// the loop has no continue expression this parser records.
    fn whileUpdateTargetName(f: types.ForStmt) ?[]const u8 {
        const u = f.update orelse return null;
        return switch (u.*) {
            .assign => |a| if (a.target_is_property) null else a.target,
            // N-116: the reference folds on a bare-identifier continue
            // expression too (`getLoopUpdateTargetName`).
            .expr_stmt => |es| switch (es.expr) {
                .identifier => |name| name,
                else => null,
            },
            else => null,
        };
    }

    fn parseReturnStmt(self: *Parser) ?Statement {
        _ = self.bump();
        if (self.current.kind == .semicolon) { _ = self.bump(); return Statement{ .return_stmt = .{ .value = null } }; }
        if (self.current.kind == .dot) {
            _ = self.bump();
            if (self.current.kind == .lbrace) { self.skipStructLiteral(); _ = self.expect(.semicolon); return Statement{ .return_stmt = .{ .value = null } }; }
        }
        const expr = self.parseExpression();
        _ = self.expect(.semicolon);
        if (expr) |e| return Statement{ .return_stmt = .{ .value = e } };
        return Statement{ .return_stmt = .{ .value = null } };
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
        const loc = self.currentSourceLoc();
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
            const index_tgt: ?*IndexAccess = if (expr == .index_access) expr.index_access else null;
            return Statement{ .assign = .{ .target = target_name, .value = .{ .binary_op = bin }, .source_loc = loc, .index_target = index_tgt, .target_is_property = types.targetIsProperty(expr) } };
        }
        if (self.current.kind == .assign) {
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            _ = self.expect(.semicolon);
            // N-053: Zig's discard `_ = expr;` drops the VALUE, not the
            // evaluation -- a helper called for its asserts must keep them, so
            // `expr` lowers as an expression statement. Only a bare name (the
            // unused-binding idiom `_ = self;` / `_ = param;`) is dropped:
            // reading a name has no effect.
            if (expr == .identifier and std.mem.eql(u8, expr.identifier, "_")) {
                if (rhs == .identifier) return null;
                return Statement{ .expr_stmt = .{ .expr = rhs, .source_loc = loc } };
            }
            const target_name = extractAssignTarget(expr);
            // `self.arr[idx] = value` — carry the index-access target on
            // the Assign so `expand_fixed_arrays.zig` can rewrite it into
            // dispatch form.
            const index_tgt: ?*IndexAccess = if (expr == .index_access) expr.index_access else null;
            return Statement{ .assign = .{ .target = target_name, .value = rhs, .source_loc = loc, .index_target = index_tgt, .target_is_property = types.targetIsProperty(expr) } };
        }
        _ = self.expect(.semicolon);
        // Expression statements (including assert calls) carry their own source
        // location so an `assert(...)` anchors to its own line rather than the
        // enclosing method.
        return Statement{ .expr_stmt = .{ .expr = expr, .source_loc = loc } };
    }

    /// Extract a string target name from an expression for Assign.target.
    /// For identifiers: returns the name. For property_access: returns the
    /// property name. For index_access, returns the base property name when
    /// the object is `self.<name>`.
    fn extractAssignTarget(expr: Expression) []const u8 {
        return switch (expr) {
            .identifier => |id| id,
            .property_access => |pa| pa.property,
            .index_access => |ia| switch (ia.object) {
                .property_access => |pa| pa.property,
                .identifier => |id| id,
                else => "unknown",
            },
            else => "unknown",
        };
    }

    // ---- Expressions ----

    fn parseExpression(self: *Parser) ?Expression {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
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
        if (self.current.kind == .minus) { _ = self.bump(); const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null; return self.makeUnaryOp(.negate, o); }
        if (self.current.kind == .bang) { _ = self.bump(); const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null; return self.makeUnaryOp(.not, o); }
        if (self.current.kind == .tilde) { _ = self.bump(); const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null; return self.makeUnaryOp(.bitnot, o); }
        // Zig's `&` is the address-of operator used for slice coercion at
        // call sites like `&.{sig1, sig2}` (an anonymous-struct literal
        // coerced to a slice). Slices have no Rúnar IR analogue — the inner
        // array literal IS the IR node — so we simply skip the `&` and parse
        // the operand as a primary expression.
        if (self.current.kind == .ampersand) { _ = self.bump(); return self.parsePrimary(); }
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
                    //
                    // The receiver is normalised `self` -> `this`, matching
                    // the eight peer surface parsers in this tier (see
                    // `parse_rust.zig`, which spells the same rewrite out).
                    // The canonical AST names the contract receiver `this`,
                    // and `expand_fixed_arrays.zig`'s
                    // `tryResolveLiteralIndexChain` only resolves a chain
                    // rooted at it. Leaving `self` here meant a nested
                    // element access `self.grid[0][0]` resolved only its
                    // innermost level, so reads lowered to
                    // `__array_access(load_prop grid__0, 0)` and stack
                    // lowering then refused the contract outright (N-059).
                    const object_name = switch (expr) {
                        .identifier => |id| if (std.mem.eql(u8, id, "self")) "this" else id,
                        .property_access => |pa| pa.property,
                        else => "unknown",
                    };
                    expr = .{ .property_access = .{ .object = object_name, .property = member } };
                }
            } else if (self.current.kind == .lbracket) {
                _ = self.bump();
                const idx = self.parseExpression() orelse return null;
                _ = self.expect(.rbracket);
                const ia = self.allocator.create(IndexAccess) catch return null;
                ia.* = .{ .object = expr, .index = idx };
                expr = .{ .index_access = ia };
            } else break;
        }
        return expr;
    }

    fn parsePrimary(self: *Parser) ?Expression {
        return switch (self.current.kind) {
            .ampersand => blk: {
                // `&.{ ... }` — Zig slice-literal syntax used to coerce an
                // anonymous tuple to a `[]const T` slice (e.g. `&.{ sig1, sig2 }`).
                // Treat as an array literal; the leading `&` carries no Rúnar
                // semantics. `&` is otherwise a binary operator handled in
                // parseBitwiseAnd, so it cannot appear at primary position.
                _ = self.bump();
                if (self.current.kind != .dot) { self.addError("expected '.' after '&'"); break :blk null; }
                _ = self.bump();
                if (self.current.kind != .lbrace) { self.addError("expected '{' after '&.'"); break :blk null; }
                _ = self.bump();
                const elems = self.parseListElements(.rbrace) orelse return null;
                _ = self.expect(.rbrace);
                break :blk .{ .array_literal = elems };
            },
            .dot => blk: {
                _ = self.bump();
                if (self.current.kind != .lbrace) break :blk null;
                _ = self.bump();
                const elems = self.parseListElements(.rbrace) orelse return null;
                _ = self.expect(.rbrace);
                break :blk .{ .array_literal = elems };
            },
            .number => blk: {
                const tok = self.bump();
                break :blk self.numberLiteral(tok);
            },
            .kw_true => blk: { _ = self.bump(); break :blk Expression{ .literal_bool = true }; },
            .kw_false => blk: { _ = self.bump(); break :blk Expression{ .literal_bool = false }; },
            .string_literal => blk: { const tok = self.bump(); self.refuseBareLiteral(tok, tok.text); break :blk Expression{ .literal_bytes = .{ .value = tok.text, .location = .{ .file = self.file_name, .line = tok.line, .column = tok.col } } }; },
            .kw_self => blk: { _ = self.bump(); break :blk Expression{ .identifier = "self" }; },
            .ident => blk: { const tok = self.bump();
                if (self.current.kind == .lparen) { _ = self.bump(); const args = self.parseArgList();
                    break :blk self.makeCall(tok.text, args);
                }
                break :blk Expression{ .identifier = tok.text };
            },
            .lparen => blk: { _ = self.bump(); const inner = self.parseExpression() orelse break :blk null; _ = self.expect(.rparen); break :blk inner; },
            .lbracket => blk: {
                // `[_]T{...}` — typed array literal with inferred length. The
                // element type is parsed and discarded; Rúnar infers element
                // types from the literal contents. The element list is the
                // same `{...}` form used by `.{...}` anon-struct literals.
                _ = self.bump(); // '['
                if (!(self.current.kind == .ident and std.mem.eql(u8, self.current.text, "_"))) {
                    self.addError("expected '_' inside '[_]T{...}' typed array literal");
                    break :blk null;
                }
                _ = self.bump(); // '_'
                _ = self.expect(.rbracket) orelse break :blk null;
                _ = self.parseTypeNode(); // discard element type
                _ = self.expect(.lbrace) orelse break :blk null;
                const elems = self.parseListElements(.rbrace) orelse return null;
                _ = self.expect(.rbrace);
                break :blk .{ .array_literal = elems };
            },
            .at_sign => blk: {
                // Zig builtins: @divTrunc(a,b) → a/b, @rem(a,b) → a%b, @mod(a,b) → a%b,
                // @intCast(expr) → expr, @as(T, expr) → expr
                _ = self.bump();
                if (self.current.kind != .ident) { self.addError("expected builtin name after '@'"); break :blk null; }
                const builtin_name = self.bump().text;
                _ = self.expect(.lparen) orelse break :blk null;
                const args = self.parseArgList();
                if (std.mem.eql(u8, builtin_name, "divTrunc") or std.mem.eql(u8, builtin_name, "divFloor")) {
                    if (args.len != 2) { self.addError("@divTrunc/@divFloor expects 2 arguments"); break :blk null; }
                    break :blk self.makeBinOp(.div, args[0], args[1]);
                } else if (std.mem.eql(u8, builtin_name, "rem") or std.mem.eql(u8, builtin_name, "mod")) {
                    if (args.len != 2) { self.addError("@rem/@mod expects 2 arguments"); break :blk null; }
                    break :blk self.makeBinOp(.mod, args[0], args[1]);
                } else if (std.mem.eql(u8, builtin_name, "intCast")) {
                    if (args.len != 1) { self.addError("@intCast expects 1 argument"); break :blk null; }
                    break :blk args[0];
                } else if (std.mem.eql(u8, builtin_name, "as")) {
                    // @as(T, expr) — type coercion, return the expression
                    if (args.len != 2) { self.addError("@as expects 2 arguments"); break :blk null; }
                    break :blk args[1];
                } else {
                    self.addErrorFmt("unsupported Zig builtin: @{s}", .{builtin_name});
                    break :blk null;
                }
            },
            else => blk: { self.addErrorFmt("unexpected token: '{s}'", .{self.current.text}); break :blk null; },
        };
    }

    /// N-033: after a field, parameter or struct-init entry, consume the `,`
    /// that separates it from the next one. Reports ZIG_LIST_COMMA at the
    /// current token and returns false when that token is neither `,` nor
    /// `close`; never consumes `close`.
    fn expectListSeparator(self: *Parser, close: TokenKind) bool {
        if (self.current.kind == .comma) {
            _ = self.bump();
            return true;
        }
        if (self.current.kind == close) return true;
        self.addError(lex_diag.ZIG_LIST_COMMA);
        return false;
    }

    /// N-464: the first token of the argument about to be parsed, as
    /// parse_ts.zig's `operandLoc` (null on `(`, whose inner expression
    /// this one-token view cannot see).
    fn argLoc(self: *const Parser) ?types.SourceLocation {
        if (self.current.kind == .lparen) return null;
        return self.currentSourceLoc();
    }

    fn parseArgList(self: *Parser) []Expression {
        var args: std.ArrayListUnmanaged(Expression) = .empty;
        // N-464: published only once the whole list is parsed, so a call
        // nested inside an argument cannot clobber it.
        var locs: std.ArrayListUnmanaged(?types.SourceLocation) = .empty;
        defer self.last_arg_locs = if (locs.items.len == args.items.len) locs.items else &.{};
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            const arg_loc = self.argLoc();
            const arg = self.parseExpression() orelse break;
            args.append(self.allocator, arg) catch {};
            locs.append(self.allocator, arg_loc) catch {};
            if (self.current.kind == .comma) {
                _ = self.bump();
                continue;
            }
            // F-026: Zig requires the comma between arguments.
            if (self.current.kind != .rparen) self.addError(lex_diag.ZIG_LIST_COMMA);
            break;
        }
        _ = self.expect(.rparen);
        return args.items;
    }

    /// F-026: the elements of an array literal up to (not including) `close`.
    /// Zig requires `,` between elements (a trailing one is allowed); without
    /// it a stray token after a literal used to become an extra element.
    fn parseListElements(self: *Parser, close: TokenKind) ?[]Expression {
        var elems: std.ArrayListUnmanaged(Expression) = .empty;
        while (self.current.kind != close and self.current.kind != .eof) {
            const elem = self.parseExpression() orelse return null;
            elems.append(self.allocator, elem) catch return null;
            if (self.current.kind == .comma) {
                _ = self.bump();
                continue;
            }
            if (self.current.kind != close) self.addError(lex_diag.ZIG_LIST_COMMA);
            break;
        }
        return elems.items;
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
        return switch (k) { .plus_eq => .add, .minus_eq => .sub, .star_eq => .mul, .slash_eq => .div, .percent_eq => .mod, else => unreachable }; // N-057: guarded by isCompoundAssignOp above; no fallback to add
    }

    test "N-057: binOpFromCompoundAssign has no silent fallback to add (Zig)" {
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
        const src = @embedFile("parse_zig.zig");
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
        const lit = int_literal.parse(self.allocator, "zig", tok.raw) orelse {
            const msg = int_literal.invalidIntegerLiteral(self.allocator, "zig", tok.raw);
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
        _ = self;
        if (std.fmt.parseInt(i64, tok.text, 10)) |v| return Expression{ .literal_int = v } else |_| {}
        return Expression{ .literal_bigint = tok.text };
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

// N-182 / R93: runar.BigintBig is the 256-bit native spelling (u256 in
// packages/runar-zig) for EC coordinates. Proves: it lowers to the same AST
// bigint as runar.Bigint, for a property and a parameter. Does NOT prove the
// native u256 runtime or any codegen.
test "parse runar.BigintBig as bigint (N-182)" {
    const source =
        \\const runar = @import("runar");
        \\pub const BigCoord = struct {
        \\    pub const Contract = runar.SmartContract;
        \\    x: runar.BigintBig,
        \\    pub fn init(x: runar.BigintBig) BigCoord { return .{ .x = x }; }
        \\    pub fn check(self: *const BigCoord, y: runar.BigintBig) void {
        \\        runar.assert(self.x == y);
        \\    }
        \\};
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseZig(arena.allocator(), source, "BigCoord.runar.zig");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqual(RunarType.bigint, c.properties[0].type_info);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqual(@as(usize, 1), c.methods[0].params.len);
    try std.testing.expectEqual(RunarType.bigint, c.methods[0].params[0].type_info);
    try std.testing.expectEqualStrings("bigint", c.methods[0].params[0].type_name);
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
    const outer = res.contract.?.methods[0].body[0].expr_stmt.expr;
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
    try std.testing.expect(body[0].return_stmt.value != null);
    switch (body[0].return_stmt.value.?) { .binary_op => |b| try std.testing.expectEqual(BinOperator.gt, b.op), else => return error.UnexpectedVariant }
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
    switch (res.contract.?.methods[0].body[0].expr_stmt.expr) {
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
    switch (stmt.expr_stmt.expr) {
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
