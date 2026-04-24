//! Pass 1 (Java frontend): Hand-written tokenizer + recursive descent parser for .runar.java files.
//!
//! Parses Java contract syntax into the Runar IR ContractNode. This mirrors the
//! authoritative surface spec in `compilers/java/src/main/java/runar/compiler/frontend/JavaParser.java`.
//!
//! Syntax conventions:
//!   - `package runar.examples.name;` at top (ignored)
//!   - `import ...;` declarations (ignored — no type resolution in this subset)
//!   - Package-private class extending `SmartContract` or `StatefulSmartContract`
//!   - `@Readonly` annotation on fields marks them readonly; otherwise mutable (stateful only)
//!   - `@Public` annotation on methods marks them as spending entry points
//!   - `@Stateful` annotation at class level (optional; derived from the base class)
//!   - Field initializers accept literal values only: `BigInteger.ZERO/ONE/TWO/TEN`,
//!     `BigInteger.valueOf(n)`, `true`/`false`, `ByteString.fromHex("...")`.
//!   - Constructor must call `super(...)` as first statement; `this.x = x` assignments follow.
//!   - Statements: variable decl (`Type name = expr;`), assignment, `if`/`else`, `for`, `return`, expression.
//!   - Expressions: identifier, int/bool literal, `X.fromHex("hex")` → ByteStringLiteral,
//!     `BigInteger.valueOf(N)` and `BigInteger.{ZERO,ONE,TWO,TEN}` → BigIntLiteral,
//!     binary ops, unary ops, method calls, member access, `this.foo`, ternary, array access,
//!     array literal (`new T[]{…}`).
//!   - Types: `boolean`/`Boolean`, `BigInteger`/`Bigint`, Rúnar domain types, `FixedArray<T, N>`.

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

pub fn parseJava(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
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
    at, // @ annotation marker
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
                // Line comment
                while (self.pos < self.source.len and self.source[self.pos] != '\n') _ = self.advance();
            } else if (c == '/' and self.peekAt(1) == '*') {
                // Block comment (includes /** ... */ Javadoc)
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

        // Double-quoted string literal
        if (c == '"') {
            _ = self.advance();
            while (self.pos < self.source.len and self.source[self.pos] != '"') {
                if (self.source[self.pos] == '\\') _ = self.advance();
                _ = self.advance();
            }
            if (self.pos < self.source.len) _ = self.advance();
            const content_start = start + 1;
            const content_end = self.pos - 1;
            return .{ .kind = .string_literal, .text = self.source[content_start..content_end], .line = sl, .col = sc };
        }

        // Numbers: decimal, hex (0x...), long suffix (L)
        if (c >= '0' and c <= '9') {
            if (c == '0' and (self.peekAt(1) == 'x' or self.peekAt(1) == 'X')) {
                _ = self.advance(); // '0'
                _ = self.advance(); // 'x'
                while (self.pos < self.source.len and isHexDigit(self.source[self.pos])) _ = self.advance();
            } else if (c == '0' and (self.peekAt(1) == 'b' or self.peekAt(1) == 'B')) {
                _ = self.advance();
                _ = self.advance();
                while (self.pos < self.source.len and (self.source[self.pos] == '0' or self.source[self.pos] == '1' or self.source[self.pos] == '_')) _ = self.advance();
            } else {
                while (self.pos < self.source.len and ((self.source[self.pos] >= '0' and self.source[self.pos] <= '9') or self.source[self.pos] == '_')) _ = self.advance();
            }
            // Optional trailing long suffix: 123L, 123l
            if (self.pos < self.source.len and (self.source[self.pos] == 'L' or self.source[self.pos] == 'l')) {
                _ = self.advance();
            }
            return .{ .kind = .number, .text = self.source[start..self.pos], .line = sl, .col = sc };
        }

        // Identifiers and keywords
        if (isIdentStart(c)) {
            while (self.pos < self.source.len and isIdentChar(self.source[self.pos])) _ = self.advance();
            const text = self.source[start..self.pos];
            return .{ .kind = .ident, .text = text, .line = sl, .col = sc };
        }

        // Operators / punctuation — advance one char, then peek
        _ = self.advance();
        const c2 = self.peek();

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
            '@' => .{ .kind = .at, .text = t, .line = sl, .col = sc },
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
// Type resolution
// ============================================================================

/// Map a Java type simple-name to a Runar TypeNode. Mirrors
/// JavaParser.resolveNamedType + the primitive-type switch.
fn resolveJavaType(name: []const u8) TypeNode {
    if (std.mem.eql(u8, name, "boolean") or std.mem.eql(u8, name, "Boolean")) {
        return .{ .primitive_type = .boolean };
    }
    if (std.mem.eql(u8, name, "Bigint") or std.mem.eql(u8, name, "BigInteger")) {
        return .{ .primitive_type = .bigint };
    }
    if (std.mem.eql(u8, name, "Ripemd160") or std.mem.eql(u8, name, "Hash160")) {
        return .{ .primitive_type = .ripemd160 };
    }
    if (PrimitiveTypeName.fromTsString(name)) |ptn| return .{ .primitive_type = ptn };
    return .{ .custom_type = name };
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
        return .{
            .allocator = allocator,
            .tokenizer = tokenizer,
            .current = first,
            .file_name = file_name,
            .errors = .empty,
            .depth = 0,
        };
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

    // ==================================================================
    // Top-level parse
    // ==================================================================

    fn parse(self: *Parser) ParseResult {
        self.skipPackageDecl();
        self.skipImportDecls();

        // Find the first class declaration (may be preceded by annotations / modifiers).
        var parent_class: ParentClass = .smart_contract;
        var contract_name: []const u8 = "";
        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;
        var constructor_method: ?MethodNode = null;
        var methods: std.ArrayListUnmanaged(MethodNode) = .empty;

        var found_class = false;
        while (self.current.kind != .eof) {
            // Skip annotations and modifiers before `class`
            self.skipClassHeaderCruft();
            if (self.checkIdent("class")) {
                _ = self.bump();
                if (self.current.kind != .ident) {
                    self.addError("expected class name");
                    return .{ .contract = null, .errors = self.errors.items };
                }
                contract_name = self.bump().text;

                // Require `extends SmartContract` or `extends StatefulSmartContract`
                if (!self.checkIdent("extends")) {
                    self.addErrorFmt("contract class '{s}' must extend SmartContract or StatefulSmartContract", .{contract_name});
                    return .{ .contract = null, .errors = self.errors.items };
                }
                _ = self.bump(); // consume 'extends'

                if (self.current.kind != .ident) {
                    self.addError("expected parent class name after 'extends'");
                    return .{ .contract = null, .errors = self.errors.items };
                }
                const parent_name_tok = self.bump();
                const parent_name = parent_name_tok.text;
                if (std.mem.eql(u8, parent_name, "SmartContract")) {
                    parent_class = .smart_contract;
                } else if (std.mem.eql(u8, parent_name, "StatefulSmartContract")) {
                    parent_class = .stateful_smart_contract;
                } else {
                    self.addErrorFmt(
                        "contract class '{s}' must extend SmartContract or StatefulSmartContract, got '{s}'",
                        .{ contract_name, parent_name },
                    );
                    return .{ .contract = null, .errors = self.errors.items };
                }

                // Optional `implements ...` — ignored
                if (self.checkIdent("implements")) {
                    _ = self.bump();
                    while (self.current.kind != .lbrace and self.current.kind != .eof) {
                        _ = self.bump();
                    }
                }

                if (self.expect(.lbrace) == null) return .{ .contract = null, .errors = self.errors.items };

                // Parse class members until matching `}`
                while (self.current.kind != .rbrace and self.current.kind != .eof) {
                    self.parseMember(contract_name, &properties, &constructor_method, &methods) catch break;
                }
                _ = self.expect(.rbrace);
                found_class = true;
                break;
            } else if (self.current.kind == .eof) {
                break;
            } else {
                _ = self.bump();
            }
        }

        if (!found_class) {
            self.addError("no class declaration found in Java source");
            return .{ .contract = null, .errors = self.errors.items };
        }

        // Build ConstructorNode from a user-supplied constructor if present,
        // otherwise auto-generate from non-initialized properties.
        const constructor: ConstructorNode = if (constructor_method) |cm|
            self.methodToConstructor(cm)
        else
            self.autoGenerateConstructor(properties.items);

        return .{
            .contract = ContractNode{
                .name = contract_name,
                .parent_class = parent_class,
                .properties = properties.items,
                .constructor = constructor,
                .methods = methods.items,
            },
            .errors = self.errors.items,
        };
    }

    fn skipPackageDecl(self: *Parser) void {
        if (!self.checkIdent("package")) return;
        _ = self.bump(); // consume 'package'
        // Consume until `;`
        while (self.current.kind != .semicolon and self.current.kind != .eof) _ = self.bump();
        _ = self.match(.semicolon);
    }

    fn skipImportDecls(self: *Parser) void {
        while (self.checkIdent("import")) {
            _ = self.bump(); // consume 'import'
            // Consume `static` if present
            _ = self.matchIdent("static");
            // Consume until `;`
            while (self.current.kind != .semicolon and self.current.kind != .eof) _ = self.bump();
            _ = self.match(.semicolon);
        }
    }

    /// Skip `@Annotation` (optionally with `(args)`) and class modifiers that
    /// may appear before the `class` keyword: `public`, `final`, `abstract`.
    fn skipClassHeaderCruft(self: *Parser) void {
        while (true) {
            if (self.current.kind == .at) {
                _ = self.bump();
                // Annotation name (may be qualified: A.B.C)
                while (self.current.kind == .ident) {
                    _ = self.bump();
                    if (self.current.kind == .dot) _ = self.bump() else break;
                }
                // Optional (args)
                if (self.current.kind == .lparen) self.skipBalancedParens();
                continue;
            }
            if (self.checkIdent("public") or self.checkIdent("final") or
                self.checkIdent("abstract") or self.checkIdent("static") or
                self.checkIdent("strictfp"))
            {
                _ = self.bump();
                continue;
            }
            break;
        }
    }

    fn skipBalancedParens(self: *Parser) void {
        if (self.current.kind != .lparen) return;
        var depth: i32 = 0;
        while (self.current.kind != .eof) {
            if (self.current.kind == .lparen) {
                depth += 1;
                _ = self.bump();
            } else if (self.current.kind == .rparen) {
                depth -= 1;
                _ = self.bump();
                if (depth <= 0) return;
            } else {
                _ = self.bump();
            }
        }
    }

    fn skipBalancedBraces(self: *Parser) void {
        if (self.current.kind != .lbrace) return;
        var depth: i32 = 0;
        while (self.current.kind != .eof) {
            if (self.current.kind == .lbrace) {
                depth += 1;
                _ = self.bump();
            } else if (self.current.kind == .rbrace) {
                depth -= 1;
                _ = self.bump();
                if (depth <= 0) return;
            } else {
                _ = self.bump();
            }
        }
    }

    // ==================================================================
    // Class member parsing
    // ==================================================================

    /// Parse a single class member: annotated field, constructor, or method.
    /// Dispatches by the shape of the head. Returns an error sentinel only on
    /// unrecoverable tokenizer exhaustion; soft errors are appended to
    /// `self.errors` so the parser keeps making progress.
    fn parseMember(
        self: *Parser,
        contract_name: []const u8,
        properties: *std.ArrayListUnmanaged(PropertyNode),
        constructor_method: *?MethodNode,
        methods: *std.ArrayListUnmanaged(MethodNode),
    ) !void {
        // Collect leading annotations and modifiers. Annotations relevant to
        // Runar are @Readonly (field) and @Public (method).
        var is_readonly = false;
        var is_public_annotation = false;

        while (true) {
            if (self.current.kind == .at) {
                _ = self.bump();
                if (self.current.kind != .ident) {
                    self.addError("expected annotation name after '@'");
                    _ = self.bump();
                    continue;
                }
                const annot_name = self.bump().text;
                // Qualified annotation: skip the trailing `.Name` parts but take
                // the last segment as the annotation's simple name.
                var simple_name = annot_name;
                while (self.current.kind == .dot) {
                    _ = self.bump();
                    if (self.current.kind == .ident) {
                        simple_name = self.bump().text;
                    }
                }
                if (std.mem.eql(u8, simple_name, "Readonly")) is_readonly = true;
                if (std.mem.eql(u8, simple_name, "Public")) is_public_annotation = true;
                // Optional annotation argument list: @Foo(x = 1)
                if (self.current.kind == .lparen) self.skipBalancedParens();
                continue;
            }
            if (self.checkIdent("public") or self.checkIdent("private") or
                self.checkIdent("protected") or self.checkIdent("final") or
                self.checkIdent("static") or self.checkIdent("abstract") or
                self.checkIdent("synchronized") or self.checkIdent("native") or
                self.checkIdent("strictfp") or self.checkIdent("transient") or
                self.checkIdent("volatile"))
            {
                _ = self.bump();
                continue;
            }
            break;
        }

        // Save position for potential rollback when distinguishing field vs. method.
        if (self.current.kind == .eof or self.current.kind == .rbrace) return;

        // Is this a constructor? A constructor begins with `<ClassName>(`.
        if (self.current.kind == .ident and std.mem.eql(u8, self.current.text, contract_name)) {
            const save_pos = self.tokenizer.pos;
            const save_line = self.tokenizer.line;
            const save_col = self.tokenizer.col;
            const save_current = self.current;
            _ = self.bump(); // consume class name
            if (self.current.kind == .lparen) {
                // Constructor
                const method = self.parseMethodAfterName("constructor", true);
                if (constructor_method.* != null) {
                    self.addErrorFmt("{s} has more than one constructor", .{contract_name});
                } else {
                    constructor_method.* = method;
                }
                return;
            }
            // Not a constructor: roll back and parse as a typed member
            self.tokenizer.pos = save_pos;
            self.tokenizer.line = save_line;
            self.tokenizer.col = save_col;
            self.current = save_current;
        }

        // Field or method: parse the type, then the name.
        const type_node = self.parseType();

        if (self.current.kind != .ident) {
            self.addErrorFmt("expected field/method name, got '{s}'", .{self.current.text});
            // Skip to next `;` or `}` to recover.
            self.recoverToMemberEnd();
            return;
        }
        const name_tok = self.bump();
        const member_name = name_tok.text;

        if (self.current.kind == .lparen) {
            // Method declaration
            const method = self.parseMethodAfterName(member_name, is_public_annotation);
            methods.append(self.allocator, method) catch {};
            return;
        }

        // Field: `Type name [= init] ;`  (support `=` initializer and comma-separated declarators, though the latter is rare)
        var initializer: ?Expression = null;
        if (self.current.kind == .assign) {
            _ = self.bump();
            initializer = self.parseExpression();
        }
        _ = self.match(.semicolon);

        const type_info = types.typeNodeToRunarType(type_node);
        var fixed_length: u32 = 0;
        var fixed_element: RunarType = .unknown;
        if (type_node == .fixed_array_type) {
            fixed_length = type_node.fixed_array_type.length;
            fixed_element = types.typeNodeToRunarType(type_node.fixed_array_type.element.*);
        }

        properties.append(self.allocator, .{
            .name = member_name,
            .type_info = type_info,
            .readonly = is_readonly,
            .initializer = initializer,
            .fixed_array_length = fixed_length,
            .fixed_array_element = fixed_element,
        }) catch {};
    }

    /// Recover from a malformed member by skipping to the next `;` or the
    /// matching `}`, whichever comes first.
    fn recoverToMemberEnd(self: *Parser) void {
        var depth: i32 = 0;
        while (self.current.kind != .eof) {
            if (self.current.kind == .lbrace) {
                depth += 1;
                _ = self.bump();
            } else if (self.current.kind == .rbrace) {
                if (depth == 0) return;
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

    /// Parse parameters + body for a method whose name has already been
    /// consumed. `name` is the method name ("constructor" for the ctor), and
    /// `is_public` reflects the presence of an `@Public` annotation (always
    /// true for constructors).
    fn parseMethodAfterName(self: *Parser, name: []const u8, is_public: bool) MethodNode {
        if (self.expect(.lparen) == null) {
            return .{ .name = name, .is_public = is_public, .params = &.{}, .body = &.{} };
        }

        var params: std.ArrayListUnmanaged(ParamNode) = .empty;
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            // Skip param annotations / `final`
            while (true) {
                if (self.current.kind == .at) {
                    _ = self.bump();
                    while (self.current.kind == .ident) {
                        _ = self.bump();
                        if (self.current.kind == .dot) _ = self.bump() else break;
                    }
                    if (self.current.kind == .lparen) self.skipBalancedParens();
                    continue;
                }
                if (self.checkIdent("final")) {
                    _ = self.bump();
                    continue;
                }
                break;
            }

            const param_type = self.parseType();
            if (self.current.kind != .ident) {
                self.addError("expected parameter name");
                break;
            }
            const pname = self.bump().text;
            const ti = types.typeNodeToRunarType(param_type);
            params.append(self.allocator, .{
                .name = pname,
                .type_info = ti,
                .type_name = types.runarTypeToString(ti),
            }) catch {};
            if (!self.match(.comma)) break;
        }
        _ = self.expect(.rparen);

        // Optional `throws ...` — not used in the Runar subset, but tolerated.
        if (self.checkIdent("throws")) {
            _ = self.bump();
            while (self.current.kind != .lbrace and self.current.kind != .semicolon and self.current.kind != .eof) {
                _ = self.bump();
            }
        }

        // Abstract / interface methods: `Type name(params);` with no body
        if (self.match(.semicolon)) {
            return .{ .name = name, .is_public = is_public, .params = params.items, .body = &.{} };
        }

        const body = self.parseBlock();
        return .{ .name = name, .is_public = is_public, .params = params.items, .body = body };
    }

    // ==================================================================
    // Type parsing
    // ==================================================================

    /// Parse a Java type declaration. Handles primitives, simple names,
    /// qualified names, and `FixedArray<T, N>` generics. Java arrays (`int[]`)
    /// are not part of the Rúnar subset (FixedArray is used instead), but
    /// bracket pairs are tolerated and folded into the base type as custom.
    fn parseType(self: *Parser) TypeNode {
        if (self.current.kind != .ident) {
            return .{ .custom_type = "unknown" };
        }
        const first = self.bump();
        var name_text = first.text;

        // Qualified: pkg.Name — take last segment.
        while (self.current.kind == .dot) {
            _ = self.bump();
            if (self.current.kind == .ident) {
                name_text = self.bump().text;
            } else break;
        }

        // Generic: Name<...>
        if (self.current.kind == .lt) {
            if (std.mem.eql(u8, name_text, "FixedArray")) {
                _ = self.bump(); // consume '<'
                // First type arg
                const elem_node = self.parseType();
                // Expect ','
                if (!self.match(.comma)) {
                    self.addError("FixedArray requires 2 type arguments (element, length)");
                    self.skipTypeArgs();
                    return .{ .custom_type = "FixedArray" };
                }
                // Second arg: integer literal
                var length: u32 = 0;
                if (self.current.kind == .number) {
                    const size_tok = self.bump();
                    length = parseFixedArrayLen(size_tok.text);
                } else {
                    self.addError("FixedArray length must be an integer literal");
                }
                _ = self.expect(.gt);
                const elem_ptr = self.allocator.create(TypeNode) catch return .{ .custom_type = "FixedArray" };
                elem_ptr.* = elem_node;
                return .{ .fixed_array_type = .{ .element = elem_ptr, .length = length } };
            }
            // Unsupported generic — skip args and treat as custom type.
            self.skipTypeArgs();
        }

        // Optional Java array brackets: `Type[]`, `Type[][]` — not in subset, skip.
        while (self.current.kind == .lbracket) {
            _ = self.bump();
            _ = self.expect(.rbracket);
        }

        return resolveJavaType(name_text);
    }

    fn skipTypeArgs(self: *Parser) void {
        if (self.current.kind != .lt) return;
        _ = self.bump();
        var depth: i32 = 1;
        while (depth > 0 and self.current.kind != .eof) {
            switch (self.current.kind) {
                .lt => depth += 1,
                .gt => depth -= 1,
                .rshift => depth -= 2, // `>>` closes two levels (raw Java generics)
                else => {},
            }
            _ = self.bump();
        }
    }

    // ==================================================================
    // Statement parsing
    // ==================================================================

    fn parseBlock(self: *Parser) []Statement {
        if (self.expect(.lbrace) == null) return &.{};
        var stmts: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            if (self.parseStatement()) |s| stmts.append(self.allocator, s) catch {};
        }
        _ = self.expect(.rbrace);
        return stmts.items;
    }

    fn parseStatement(self: *Parser) ?Statement {
        // if (cond) { ... } else { ... }
        if (self.checkIdent("if")) return self.parseIfStmt();
        // for (init; cond; update) { ... }
        if (self.checkIdent("for")) return self.parseForStmt();
        // return [expr];
        if (self.checkIdent("return")) return self.parseReturnStmt();
        // while / do / switch are not in the subset — reject loudly.
        if (self.checkIdent("while") or self.checkIdent("do") or self.checkIdent("switch") or
            self.checkIdent("try") or self.checkIdent("throw") or self.checkIdent("break") or
            self.checkIdent("continue"))
        {
            self.addErrorFmt("unsupported statement: '{s}'", .{self.current.text});
            // Skip the problematic statement
            while (self.current.kind != .semicolon and self.current.kind != .rbrace and self.current.kind != .eof) {
                if (self.current.kind == .lbrace) {
                    self.skipBalancedBraces();
                } else {
                    _ = self.bump();
                }
            }
            _ = self.match(.semicolon);
            return null;
        }

        // Block statement inside block is unsupported in the subset; but flatten
        // if seen by recursing.
        if (self.current.kind == .lbrace) {
            self.addError("nested blocks are unsupported");
            self.skipBalancedBraces();
            return null;
        }

        // Typed variable declaration vs. expression statement.
        // Heuristic: an identifier followed by another identifier signals a declaration.
        if (self.current.kind == .ident) {
            // Save state to decide which branch to take.
            const save_pos = self.tokenizer.pos;
            const save_line = self.tokenizer.line;
            const save_col = self.tokenizer.col;
            const save_current = self.current;

            if (self.looksLikeVariableDecl()) {
                // Restore and parse as decl
                self.tokenizer.pos = save_pos;
                self.tokenizer.line = save_line;
                self.tokenizer.col = save_col;
                self.current = save_current;
                return self.parseVariableDecl();
            }
            // Restore and fall through to expression
            self.tokenizer.pos = save_pos;
            self.tokenizer.line = save_line;
            self.tokenizer.col = save_col;
            self.current = save_current;
        }

        return self.parseExpressionStatement();
    }

    /// Peek ahead to decide if the upcoming tokens form a variable declaration
    /// (`Type name [= expr];`). Leaves `self.current` at the starting token if
    /// the caller saved state; otherwise the parser has consumed tokens.
    fn looksLikeVariableDecl(self: *Parser) bool {
        // Must start with an identifier (type name).
        if (self.current.kind != .ident) return false;
        // Reserved control-flow identifiers can never start a declaration.
        const kw_guard = [_][]const u8{ "if", "for", "while", "do", "return", "switch", "try", "throw", "break", "continue", "else", "super", "this", "new" };
        for (kw_guard) |kw| {
            if (std.mem.eql(u8, self.current.text, kw)) return false;
        }
        _ = self.bump(); // consume first ident (type)
        // Optional qualified type: `pkg.Name`
        while (self.current.kind == .dot) {
            _ = self.bump();
            if (self.current.kind == .ident) _ = self.bump() else return false;
        }
        // Optional generic args
        if (self.current.kind == .lt) {
            self.skipTypeArgs();
        }
        // Optional array brackets
        while (self.current.kind == .lbracket) {
            _ = self.bump();
            if (self.current.kind != .rbracket) return false;
            _ = self.bump();
        }
        // Now we need an identifier (variable name), then `=` or `;`.
        if (self.current.kind != .ident) return false;
        _ = self.bump();
        return self.current.kind == .assign or self.current.kind == .semicolon;
    }

    fn parseVariableDecl(self: *Parser) ?Statement {
        const type_node = self.parseType();
        const ti = types.typeNodeToRunarType(type_node);
        if (self.current.kind != .ident) {
            self.addError("expected variable name");
            return null;
        }
        const name_tok = self.bump();
        const var_name = name_tok.text;

        var value: ?Expression = null;
        if (self.match(.assign)) {
            value = self.parseExpression();
        }
        _ = self.match(.semicolon);

        if (value) |v| {
            return .{ .const_decl = .{ .name = var_name, .type_info = ti, .value = v } };
        }
        // Uninitialised declaration — Java allows it but the Rúnar subset
        // requires an initialiser. Emit a soft error and fall back to a
        // let_decl so we keep parsing.
        self.addErrorFmt("local variable '{s}' must have an initializer", .{var_name});
        return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = null } };
    }

    fn parseIfStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'if'
        if (self.expect(.lparen) == null) return null;
        const cond = self.parseExpression() orelse return null;
        _ = self.expect(.rparen);

        const then_body = self.parseStmtOrBlock();

        var else_body: ?[]Statement = null;
        if (self.checkIdent("else")) {
            _ = self.bump();
            if (self.checkIdent("if")) {
                const nested = self.parseIfStmt() orelse return null;
                const a = self.allocator.alloc(Statement, 1) catch return null;
                a[0] = nested;
                else_body = a;
            } else {
                else_body = self.parseStmtOrBlock();
            }
        }

        return .{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body } };
    }

    /// Parse either `{ stmts }` or a single statement (Java allows both).
    fn parseStmtOrBlock(self: *Parser) []Statement {
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

        var var_name: []const u8 = "_i";
        var init_value: i64 = 0;
        var bound: i64 = 0;

        // Init: `Type name = expr;` or plain expression
        if (self.current.kind == .ident) {
            const save_pos = self.tokenizer.pos;
            const save_line = self.tokenizer.line;
            const save_col = self.tokenizer.col;
            const save_current = self.current;

            if (self.looksLikeVariableDecl()) {
                // Restore and parse as variable decl
                self.tokenizer.pos = save_pos;
                self.tokenizer.line = save_line;
                self.tokenizer.col = save_col;
                self.current = save_current;
                _ = self.parseType(); // consume the type
                if (self.current.kind == .ident) {
                    var_name = self.bump().text;
                }
                if (self.match(.assign)) {
                    if (self.current.kind == .number) {
                        init_value = parseNumberLiteral(self.bump().text);
                    } else {
                        _ = self.parseExpression();
                    }
                }
            } else {
                self.tokenizer.pos = save_pos;
                self.tokenizer.line = save_line;
                self.tokenizer.col = save_col;
                self.current = save_current;
                _ = self.parseExpression();
            }
        }
        _ = self.expect(.semicolon);

        // Condition: extract right-hand constant if it's `name < N`
        if (self.current.kind != .semicolon) {
            const cond_expr = self.parseExpression();
            if (cond_expr) |expr| {
                switch (expr) {
                    .binary_op => |bop| switch (bop.right) {
                        .literal_int => |v| bound = v,
                        else => {},
                    },
                    else => {},
                }
            }
        }
        _ = self.expect(.semicolon);

        // Update: consume until `)`.
        while (self.current.kind != .rparen and self.current.kind != .eof) {
            _ = self.bump();
        }
        _ = self.expect(.rparen);

        const body = self.parseStmtOrBlock();
        return .{ .for_stmt = .{ .var_name = var_name, .init_value = init_value, .bound = bound, .body = body } };
    }

    fn parseReturnStmt(self: *Parser) ?Statement {
        _ = self.bump(); // 'return'
        if (self.current.kind == .semicolon) {
            _ = self.bump();
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

        // Assignment: lhs = rhs
        if (self.current.kind == .assign) {
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            _ = self.match(.semicolon);
            return self.buildAssignment(expr, rhs);
        }

        // Compound assignments
        if (isCompoundAssignOp(self.current.kind)) {
            const op_kind = self.current.kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            _ = self.match(.semicolon);
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs);
        }

        // Postfix ++/-- as a statement
        if (self.current.kind == .plus_plus) {
            _ = self.bump();
            _ = self.match(.semicolon);
            const inc = self.allocator.create(IncrementExpr) catch return null;
            inc.* = .{ .operand = expr, .prefix = false };
            return .{ .expr_stmt = .{ .increment = inc } };
        }
        if (self.current.kind == .minus_minus) {
            _ = self.bump();
            _ = self.match(.semicolon);
            const dec = self.allocator.create(DecrementExpr) catch return null;
            dec.* = .{ .operand = expr, .prefix = false };
            return .{ .expr_stmt = .{ .decrement = dec } };
        }

        _ = self.match(.semicolon);
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
            .index_access => |ia| {
                const base = switch (ia.object) {
                    .property_access => |pa| pa.property,
                    .identifier => |id| id,
                    else => "unknown",
                };
                return .{ .assign = .{ .target = base, .value = value, .index_target = ia } };
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
        const cond = self.parseLogicalOr() orelse return null;
        if (self.current.kind != .question) return cond;
        _ = self.bump(); // '?'
        const then_expr = self.parseExpression() orelse return null;
        if (self.expect(.colon) == null) return null;
        const else_expr = self.parseExpression() orelse return null;
        const tern = self.allocator.create(Ternary) catch return null;
        tern.* = .{ .condition = cond, .then_expr = then_expr, .else_expr = else_expr };
        return .{ .ternary = tern };
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
        if (self.current.kind == .plus) {
            // `+x` is the identity operator
            _ = self.bump();
            return self.parseUnary();
        }
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
        if (self.current.kind == .plus_plus) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const inc = self.allocator.create(IncrementExpr) catch return null;
            inc.* = .{ .operand = o, .prefix = true };
            return .{ .increment = inc };
        }
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
                    return expr;
                }
                const member_tok = self.bump();
                const member = member_tok.text;

                if (self.current.kind == .lparen) {
                    _ = self.bump();
                    const args = self.parseArgList();

                    // xxx.fromHex("hex") → ByteStringLiteral
                    if (std.mem.eql(u8, member, "fromHex") and args.len == 1) {
                        switch (args[0]) {
                            .literal_bytes => |raw| {
                                expr = .{ .literal_bytes = raw };
                                continue;
                            },
                            else => {},
                        }
                    }
                    // BigInteger.valueOf(<int literal>) → BigIntLiteral
                    if (std.mem.eql(u8, member, "valueOf") and args.len == 1) {
                        switch (expr) {
                            .identifier => |id| {
                                if (std.mem.eql(u8, id, "BigInteger")) {
                                    switch (args[0]) {
                                        .literal_int => |v| {
                                            expr = .{ .literal_int = v };
                                            continue;
                                        },
                                        else => {},
                                    }
                                }
                            },
                            else => {},
                        }
                    }

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
                    // Property access
                    // BigInteger.{ZERO,ONE,TWO,TEN} → literal
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "BigInteger")) {
                                if (std.mem.eql(u8, member, "ZERO")) {
                                    expr = .{ .literal_int = 0 };
                                    continue;
                                }
                                if (std.mem.eql(u8, member, "ONE")) {
                                    expr = .{ .literal_int = 1 };
                                    continue;
                                }
                                if (std.mem.eql(u8, member, "TWO")) {
                                    expr = .{ .literal_int = 2 };
                                    continue;
                                }
                                if (std.mem.eql(u8, member, "TEN")) {
                                    expr = .{ .literal_int = 10 };
                                    continue;
                                }
                            }
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
                _ = self.bump();
                const idx = self.parseExpression() orelse return null;
                _ = self.expect(.rbracket);
                const ia = self.allocator.create(IndexAccess) catch return null;
                ia.* = .{ .object = expr, .index = idx };
                expr = .{ .index_access = ia };
            } else if (self.current.kind == .lparen) {
                // Direct call: f(args)
                switch (expr) {
                    .identifier => |id| {
                        _ = self.bump();
                        const args = self.parseArgList();
                        // Java static-imported `assertThat(expr)` maps to assert.
                        if (std.mem.eql(u8, id, "assertThat") and args.len == 1) {
                            // Emit as a call so callers can consume it as an expression
                            // statement; the validator / typechecker treats this as an
                            // assertion, matching the Java parser's behaviour.
                            const call = self.allocator.create(CallExpr) catch return null;
                            call.* = .{ .callee = "assert", .args = args };
                            expr = .{ .call = call };
                            continue;
                        }
                        const call = self.allocator.create(CallExpr) catch return null;
                        call.* = .{ .callee = id, .args = args };
                        expr = .{ .call = call };
                    },
                    else => break,
                }
            } else if (self.current.kind == .plus_plus) {
                _ = self.bump();
                const inc = self.allocator.create(IncrementExpr) catch return null;
                inc.* = .{ .operand = expr, .prefix = false };
                expr = .{ .increment = inc };
            } else if (self.current.kind == .minus_minus) {
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
                const val = parseNumberLiteral(tok.text);
                break :blk Expression{ .literal_int = val };
            },
            .string_literal => blk: {
                const tok = self.bump();
                // Bare string literals are only meaningful in ByteString.fromHex("hex"),
                // which is rewritten in parsePostfix. Keep the raw payload here so
                // the postfix can reinterpret it as hex.
                break :blk Expression{ .literal_bytes = tok.text };
            },
            .lparen => blk: {
                _ = self.bump();
                // Cast expression: `(Type) expr` — tolerated by consuming and
                // returning the inner expression. We detect a cast by peeking
                // for an ident followed by `)` AND a non-operator token after.
                // For simplicity, we treat `(ident)` followed by a unary-start
                // token as a cast to that type.
                if (self.current.kind == .ident and self.looksLikeCast()) {
                    // Consume type, `)`, then parse the operand
                    _ = self.parseType();
                    _ = self.expect(.rparen);
                    break :blk self.parseUnary();
                }
                const inner = self.parseExpression() orelse break :blk null;
                _ = self.expect(.rparen);
                break :blk inner;
            },
            .ident => blk: {
                const tok = self.bump();
                const name = tok.text;
                if (std.mem.eql(u8, name, "true")) break :blk Expression{ .literal_bool = true };
                if (std.mem.eql(u8, name, "false")) break :blk Expression{ .literal_bool = false };
                if (std.mem.eql(u8, name, "null")) {
                    self.addError("null literals are unsupported");
                    break :blk Expression{ .literal_bool = false };
                }
                if (std.mem.eql(u8, name, "new")) {
                    break :blk self.parseNewExpr();
                }
                if (std.mem.eql(u8, name, "super")) {
                    break :blk Expression{ .identifier = "super" };
                }
                if (std.mem.eql(u8, name, "this")) {
                    break :blk Expression{ .identifier = "this" };
                }
                break :blk Expression{ .identifier = name };
            },
            else => blk: {
                self.addErrorFmt("unexpected token: '{s}'", .{self.current.text});
                break :blk null;
            },
        };
    }

    /// Look ahead to determine whether the current `(` begins a cast `(Type)`.
    /// Caller has already consumed `(` and the parser is pointing at an ident.
    /// Returns true only if the shape is `ident <typeargs?> <brackets?> )` and
    /// the next token after `)` begins a unary-expression start.
    fn looksLikeCast(self: *Parser) bool {
        const save_pos = self.tokenizer.pos;
        const save_line = self.tokenizer.line;
        const save_col = self.tokenizer.col;
        const save_current = self.current;

        // Consume type-like shape
        if (self.current.kind != .ident) {
            self.restoreState(save_pos, save_line, save_col, save_current);
            return false;
        }
        _ = self.bump();
        while (self.current.kind == .dot) {
            _ = self.bump();
            if (self.current.kind == .ident) _ = self.bump() else {
                self.restoreState(save_pos, save_line, save_col, save_current);
                return false;
            }
        }
        if (self.current.kind == .lt) self.skipTypeArgs();
        while (self.current.kind == .lbracket) {
            _ = self.bump();
            if (self.current.kind != .rbracket) {
                self.restoreState(save_pos, save_line, save_col, save_current);
                return false;
            }
            _ = self.bump();
        }

        const is_rparen = self.current.kind == .rparen;
        self.restoreState(save_pos, save_line, save_col, save_current);
        return is_rparen;
    }

    fn restoreState(self: *Parser, pos: usize, line: u32, col: u32, current: Token) void {
        self.tokenizer.pos = pos;
        self.tokenizer.line = line;
        self.tokenizer.col = col;
        self.current = current;
    }

    /// Parse `new T[]{a, b, c}` — the only `new` form in the Runar subset.
    /// Returns an `array_literal` expression.
    fn parseNewExpr(self: *Parser) ?Expression {
        // We've already consumed `new`.
        // Skip type tokens up to `[]` then `{`.
        if (self.current.kind != .ident) {
            self.addError("expected type after 'new'");
            return null;
        }
        _ = self.parseType(); // discard the element type (already encoded in the property type)
        if (self.current.kind != .lbracket) {
            self.addError("expected '[' after 'new Type'");
            return null;
        }
        _ = self.bump();
        _ = self.expect(.rbracket);
        if (self.expect(.lbrace) == null) return null;

        var elements: std.ArrayListUnmanaged(Expression) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            const elem = self.parseExpression() orelse break;
            elements.append(self.allocator, elem) catch {};
            if (!self.match(.comma)) break;
        }
        _ = self.expect(.rbrace);
        return .{ .array_literal = elements.items };
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

    // ==================================================================
    // Constructor lowering helpers
    // ==================================================================

    /// Convert a parsed constructor MethodNode into a ConstructorNode.
    /// Extracts `super(...)` args and `this.x = value` assignments from the
    /// body. Mirrors parse_ruby.methodToConstructor.
    fn methodToConstructor(self: *Parser, m: MethodNode) ConstructorNode {
        var super_args: std.ArrayListUnmanaged(Expression) = .empty;
        var assignments: std.ArrayListUnmanaged(AssignmentNode) = .empty;

        for (m.body) |stmt| {
            switch (stmt) {
                .expr_stmt => |expr| switch (expr) {
                    .call => |call| {
                        if (std.mem.eql(u8, call.callee, "super")) {
                            for (call.args) |arg| super_args.append(self.allocator, arg) catch {};
                        }
                    },
                    else => {},
                },
                .assign => |assign| {
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

    /// Auto-generate a constructor from non-initialised properties. Mirrors
    /// JavaParser.syntheticConstructor: every property without an initializer
    /// becomes a ctor param, a super-arg, and a `this.x = x` assignment.
    fn autoGenerateConstructor(self: *Parser, properties: []PropertyNode) ConstructorNode {
        var required: std.ArrayListUnmanaged(PropertyNode) = .empty;
        for (properties) |prop| {
            if (prop.initializer == null) required.append(self.allocator, prop) catch {};
        }

        const params = self.allocator.alloc(ParamNode, required.items.len) catch return .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
        const super_args = self.allocator.alloc(Expression, required.items.len) catch return .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };
        const assignments = self.allocator.alloc(AssignmentNode, required.items.len) catch return .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} };

        for (required.items, 0..) |prop, i| {
            params[i] = .{
                .name = prop.name,
                .type_info = prop.type_info,
                .type_name = types.runarTypeToString(prop.type_info),
            };
            super_args[i] = .{ .identifier = prop.name };
            assignments[i] = .{ .target = prop.name, .value = .{ .identifier = prop.name } };
        }

        return .{
            .params = params,
            .super_args = super_args,
            .assignments = assignments,
        };
    }
};

// ============================================================================
// Helpers
// ============================================================================

fn parseNumberLiteral(text: []const u8) i64 {
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    for (text) |ch| {
        // Drop Java long-suffix and digit separators
        if (ch == 'L' or ch == 'l') break;
        if (ch != '_' and len < buf.len) {
            buf[len] = ch;
            len += 1;
        }
    }
    return std.fmt.parseInt(i64, buf[0..len], 0) catch 0;
}

fn parseFixedArrayLen(text: []const u8) u32 {
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    for (text) |ch| {
        if (ch == 'L' or ch == 'l') break;
        if (ch != '_' and len < buf.len) {
            buf[len] = ch;
            len += 1;
        }
    }
    return std.fmt.parseInt(u32, buf[0..len], 0) catch 0;
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

// ============================================================================
// Tests
// ============================================================================

test "java tokenizer basics" {
    var t = Tokenizer.init("class P2PKH extends SmartContract { }");
    const c1 = t.next();
    try std.testing.expectEqual(TokenKind.ident, c1.kind);
    try std.testing.expectEqualStrings("class", c1.text);
    try std.testing.expectEqualStrings("P2PKH", t.next().text);
    try std.testing.expectEqualStrings("extends", t.next().text);
    try std.testing.expectEqualStrings("SmartContract", t.next().text);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "java tokenizer operators" {
    var t = Tokenizer.init("== != <= >= << >> && || += -= @");
    const expected = [_]TokenKind{
        .eqeq,    .bang_eq,    .lt_eq,    .gt_eq,
        .lshift,  .rshift,     .amp_amp,  .pipe_pipe,
        .plus_eq, .minus_eq,   .at,       .eof,
    };
    for (expected) |e| try std.testing.expectEqual(e, t.next().kind);
}

test "java tokenizer string literal" {
    var t = Tokenizer.init("\"deadbeef\"");
    const tok = t.next();
    try std.testing.expectEqual(TokenKind.string_literal, tok.kind);
    try std.testing.expectEqualStrings("deadbeef", tok.text);
}

test "java tokenizer number with long suffix" {
    var t = Tokenizer.init("42L 100 0xff");
    const a = t.next();
    try std.testing.expectEqual(TokenKind.number, a.kind);
    try std.testing.expectEqualStrings("42L", a.text);
    const b = t.next();
    try std.testing.expectEqual(TokenKind.number, b.kind);
    try std.testing.expectEqualStrings("100", b.text);
    const c = t.next();
    try std.testing.expectEqual(TokenKind.number, c.kind);
    try std.testing.expectEqualStrings("0xff", c.text);
}

test "java tokenizer comments" {
    var t = Tokenizer.init("// line comment\nclass /* block\n comment */ X { }");
    try std.testing.expectEqualStrings("class", t.next().text);
    try std.testing.expectEqualStrings("X", t.next().text);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "parse P2PKH contract (Java)" {
    const source =
        \\package runar.examples.p2pkh;
        \\
        \\import runar.lang.SmartContract;
        \\import runar.lang.annotations.Public;
        \\import runar.lang.annotations.Readonly;
        \\import runar.lang.types.Addr;
        \\import runar.lang.types.PubKey;
        \\import runar.lang.types.Sig;
        \\import static runar.lang.Builtins.assertThat;
        \\import static runar.lang.Builtins.checkSig;
        \\import static runar.lang.Builtins.hash160;
        \\
        \\class P2PKH extends SmartContract {
        \\    @Readonly Addr pubKeyHash;
        \\
        \\    P2PKH(Addr pubKeyHash) {
        \\        super(pubKeyHash);
        \\        this.pubKeyHash = pubKeyHash;
        \\    }
        \\
        \\    @Public
        \\    void unlock(Sig sig, PubKey pubKey) {
        \\        assertThat(hash160(pubKey).equals(pubKeyHash));
        \\        assertThat(checkSig(sig, pubKey));
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseJava(arena.allocator(), source, "P2PKH.runar.java");
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

test "parse stateful Counter (Java)" {
    const source =
        \\class Counter extends StatefulSmartContract {
        \\    Bigint count;
        \\    Counter(Bigint count) {
        \\        super(count);
        \\        this.count = count;
        \\    }
        \\
        \\    @Public
        \\    void increment() {
        \\        this.count = this.count + BigInteger.ONE;
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseJava(arena.allocator(), source, "Counter.runar.java");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Counter", c.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("count", c.properties[0].name);
    try std.testing.expectEqual(RunarType.bigint, c.properties[0].type_info);
    try std.testing.expect(!c.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
}

test "parse property initializer (Java)" {
    const source =
        \\class Box extends StatefulSmartContract {
        \\    Bigint count = BigInteger.ZERO;
        \\    @Readonly PubKey owner;
        \\    Box(PubKey owner) { super(owner); this.owner = owner; }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseJava(arena.allocator(), source, "Box.runar.java");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqual(@as(usize, 2), c.properties.len);
    // count carries the BigInteger.ZERO initializer → literal_int(0)
    const count_prop = c.properties[0];
    try std.testing.expectEqualStrings("count", count_prop.name);
    try std.testing.expect(count_prop.initializer != null);
    switch (count_prop.initializer.?) {
        .literal_int => |v| try std.testing.expectEqual(@as(i64, 0), v),
        else => return error.ExpectedLiteralInt,
    }
    // Synthetic ctor should only carry `owner` (count has an initializer).
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqualStrings("owner", c.constructor.params[0].name);
}

test "rejects class without extends (Java)" {
    const source = "class Bad { @Readonly Addr pkh; }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseJava(arena.allocator(), source, "Bad.runar.java");
    try std.testing.expect(r.errors.len > 0);
    try std.testing.expect(r.contract == null);
}

test "rejects unknown base class (Java)" {
    const source = "class Bad extends Frobulator { }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseJava(arena.allocator(), source, "Bad.runar.java");
    try std.testing.expect(r.errors.len > 0);
    try std.testing.expect(r.contract == null);
}

test "ByteString.fromHex literal (Java)" {
    const source =
        \\class C extends SmartContract {
        \\    @Readonly ByteString magic;
        \\    C(ByteString magic) { super(magic); this.magic = magic; }
        \\    @Public
        \\    void check() {
        \\        assertThat(magic.equals(ByteString.fromHex("deadbeef")));
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseJava(arena.allocator(), source, "C.runar.java");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    const body = c.methods[0].body;
    try std.testing.expectEqual(@as(usize, 1), body.len);
    // assertThat(magic.equals(ByteString.fromHex("deadbeef"))) — the
    // parser rewrites `fromHex(...)` with a single string argument into a
    // bytes literal. Walk down to find it.
    const outer = body[0].expr_stmt;
    const outer_call = outer.call.*; // assertThat(...) → call("assert", [arg])
    try std.testing.expectEqualStrings("assert", outer_call.callee);
    const equals_call = outer_call.args[0].method_call.*;
    try std.testing.expectEqualStrings("equals", equals_call.method);
    // The single arg must be a bytes literal with the hex payload.
    const lit = equals_call.args[0];
    switch (lit) {
        .literal_bytes => |raw| try std.testing.expectEqualStrings("deadbeef", raw),
        else => return error.ExpectedByteStringLiteral,
    }
}

test "BigInteger.valueOf literal (Java)" {
    const source =
        \\class C extends SmartContract {
        \\    @Readonly Bigint threshold;
        \\    C(Bigint threshold) { super(threshold); this.threshold = threshold; }
        \\    @Public
        \\    void check(Bigint x) {
        \\        assertThat(x == BigInteger.valueOf(7));
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseJava(arena.allocator(), source, "C.runar.java");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    const body = c.methods[0].body;
    const outer = body[0].expr_stmt;
    // assertThat(x == BigInteger.valueOf(7)) → call("assert", [x == 7])
    const outer_call = outer.call.*;
    try std.testing.expectEqualStrings("assert", outer_call.callee);
    const eq = outer_call.args[0].binary_op;
    try std.testing.expectEqual(BinOperator.eq, eq.op);
    switch (eq.left) {
        .identifier => |id| try std.testing.expectEqualStrings("x", id),
        else => return error.ExpectedIdent,
    }
    switch (eq.right) {
        .literal_int => |v| try std.testing.expectEqual(@as(i64, 7), v),
        else => return error.ExpectedInt,
    }
}

test "binary ops parse correctly (Java)" {
    const source =
        \\class C extends SmartContract {
        \\    @Readonly Bigint a;
        \\    C(Bigint a) { super(a); this.a = a; }
        \\    @Public
        \\    void m(Bigint x, Bigint y) {
        \\        Bigint r = x + y * BigInteger.TWO - (x / y) % a;
        \\        assertThat((x & y) == (x | y));
        \\        assertThat((x << BigInteger.ONE) >= y);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseJava(arena.allocator(), source, "C.runar.java");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    const body = c.methods[0].body;
    try std.testing.expectEqual(@as(usize, 3), body.len);
    // First statement is a variable declaration
    switch (body[0]) {
        .const_decl => |cd| try std.testing.expectEqualStrings("r", cd.name),
        else => return error.ExpectedVarDecl,
    }
}
