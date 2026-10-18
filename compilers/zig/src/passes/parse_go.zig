//! Pass 1 (Go frontend): Hand-written tokenizer + recursive descent parser for .runar.go files.
//!
//! Parses Go contract syntax into the Runar IR ContractNode.
//!
//! Syntax conventions:
//!   - `package contractname` at top (skipped)
//!   - `import "runar"` or `import "github.com/icellan/runar/packages/runar-go"` (skipped)
//!   - `type Name struct { ... }` declares the contract
//!   - First field in struct: `runar.SmartContract` or `runar.StatefulSmartContract` (embedded)
//!   - Properties: `FieldName Type` with optional `\`runar:"readonly"\`` tag
//!   - Types after name: `FieldName runar.PubKey`
//!   - Type mappings: `int64`/`runar.Int`/`runar.Bigint` -> bigint, `bool`/`runar.Bool` -> boolean, etc.
//!   - Constructor auto-generated from non-initialized properties
//!   - Methods: `func (c *Name) MethodName(params) { ... }` (receiver is self)
//!   - Public = uppercase first letter; private = lowercase first letter
//!   - `runar.Assert(cond)` -> assert, `runar.CheckSig(sig, pk)` -> checkSig, etc.
//!   - Property access: `c.FieldName` -> this.fieldName (PascalCase -> camelCase)
//!   - `:=` for short variable declarations, `=` for assignments
//!   - `if cond { ... } else { ... }` — no parens around condition
//!   - `for i := 0; i < n; i++ { ... }` — C-style for loops
//!   - `==` maps to `===`, `!=` maps to `!==`
//!   - `func (c *Name) init()` — private init method extracts property initializers
//!   - `c.AddOutput(...)` / `c.addOutput(...)` -> this.addOutput(...)
//!   - `var name Type = value` for variable declarations

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

// ============================================================================
// Public API
// ============================================================================

pub const ParseResult = struct {
    contract: ?ContractNode,
    errors: [][]const u8,
};

// F-010 diagnostics -- emitted verbatim by every tier's .runar.go parser (TS
// reference: goNoContractMessage / goMultipleContractsMessage /
// goForeignReceiverMessage in packages/runar-compiler/src/passes/01-parse-go.ts).
const go_no_contract_message = "no Rúnar contract struct found in Go source";
const go_multiple_contracts_fmt = "multiple Rúnar contract structs found in Go source: '{s}' and '{s}'; exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract or runar.UnsafeSmartContract";
const go_foreign_receiver_fmt = "method '{s}' has receiver type '{s}', not the contract type '{s}'; methods on other types are not allowed";

/// A parsed `func`: the method, the Go spelling of its name, and its receiver
/// type (`*` stripped), or null for a free function.
const FuncDecl = struct {
    method: MethodNode,
    go_name: []const u8,
    receiver_type: ?[]const u8,
};

pub fn parseGo(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
    // DoS-bound size guard, enforced at every exported parser entry,
    // not just runPipeline's Pass 0. N-136.
    if (input_limits.sourceSizeGuardErrors(allocator, source)) |errs| {
        return .{ .contract = null, .errors = errs };
    }
    var parser = Parser.init(allocator, source, file_name);
    parser.directives = collectGoDirectives(allocator, source);
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
    const errs = lex_diag.prepend(allocator, r.errors, file_name, lex_diag.UNTERMINATED_STRING_LITERAL, t.unterminated);
    return .{ .contract = r.contract, .errors = errs };
}


// ============================================================================
// N-093: Go DSL directive comments
// ============================================================================

/// A Go DSL directive comment `//runar:<name> <args>` (Go's own `//go:`
/// convention: no space after `//`). `attach_line`/`attach_col` locate the
/// first token after the comment, so a directive attaches to the declaration
/// that follows it, with only comments and blank lines in between.
const GoDirective = struct {
    name: []const u8,
    args: []const u8,
    line: u32,
    col: u32,
    attach_line: u32,
    attach_col: u32,
    consumed: bool = false,
};

/// Every `//runar:` directive comment in `source`, in source order. Walks the
/// real tokenizer so a `//runar:` inside a string literal is never read as a
/// directive; each whitespace/comment gap between two tokens is re-scanned
/// for line comments (the gap holds nothing else, so the re-scan is exact).
fn collectGoDirectives(allocator: Allocator, source: []const u8) []GoDirective {
    var out: std.ArrayListUnmanaged(GoDirective) = .empty;
    var t = Tokenizer.init(source);
    var guard: usize = 0;
    while (guard <= source.len) : (guard += 1) {
        const gap_start = t.pos;
        var line = t.line;
        var col = t.col;
        t.skipWhitespaceAndComments();
        const first = out.items.len;
        var i = gap_start;
        while (i < t.pos) {
            const c = source[i];
            if (c == '/' and i + 1 < t.pos and source[i + 1] == '/') {
                const start = i;
                const start_col = col;
                while (i < t.pos and source[i] != '\n') : (i += 1) col += 1;
                var text = source[start..i];
                if (text.len > 0 and text[text.len - 1] == '\r') text = text[0 .. text.len - 1];
                const prefix = "//runar:";
                if (std.mem.startsWith(u8, text, prefix)) {
                    const body = text[prefix.len..];
                    const name_end = std.mem.indexOfAny(u8, body, " \t") orelse body.len;
                    out.append(allocator, .{
                        .name = body[0..name_end],
                        .args = body[name_end..],
                        .line = line,
                        .col = start_col,
                        .attach_line = 0,
                        .attach_col = 0,
                    }) catch {};
                }
                continue;
            }
            if (c == '/' and i + 1 < t.pos and source[i + 1] == '*') {
                i += 2;
                col += 2;
                while (i < t.pos) {
                    if (source[i] == '*' and i + 1 < t.pos and source[i + 1] == '/') {
                        i += 2;
                        col += 2;
                        break;
                    }
                    if (source[i] == '\n') {
                        line += 1;
                        col = 1;
                    } else col += 1;
                    i += 1;
                }
                continue;
            }
            if (c == '\n') {
                line += 1;
                col = 1;
            } else col += 1;
            i += 1;
        }
        for (out.items[first..]) |*d| {
            d.attach_line = t.line;
            d.attach_col = t.col;
        }
        if (t.next().kind == .eof) break;
    }
    return out.items;
}

/// N-093: the value of the `runar:"..."` key of a Go struct tag (the key must
/// start the tag or follow whitespace), or null when the tag has no such key.
/// Mirrors the TS reference's `/(?:^|\s)runar:"([^"]*)"/`.
fn goRunarTagValue(tag: []const u8) ?[]const u8 {
    const key = "runar:\"";
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, tag, from, key)) |pos| {
        from = pos + 1;
        if (pos > 0 and !std.ascii.isWhitespace(tag[pos - 1])) continue;
        const start = pos + key.len;
        const end = std.mem.indexOfScalarPos(u8, tag, start, '"') orelse return null;
        return tag[start..end];
    }
    return null;
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
    colon_assign, // :=
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
    backtick_string, // backtick-delimited struct tags
    ellipsis, // ...
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

        // String literals: double quotes
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

        // Backtick-delimited struct tags: `runar:"readonly"`
        if (c == '`') {
            _ = self.advance();
            // F-011: this literal may span lines, so only end of file leaves
            // it unterminated.
            while (self.pos < self.source.len and self.source[self.pos] != '`') {
                _ = self.advance();
            }
            const content_end = self.pos;
            if (self.pos < self.source.len) {
                _ = self.advance();
            } else if (self.unterminated == null) {
                self.unterminated = .{ .line = sl, .col = sc };
            }
            return .{ .kind = .backtick_string, .text = self.source[start + 1 .. content_end], .line = sl, .col = sc };
        }

        // Numbers (decimal, hex, octal, binary)
        if (c >= '0' and c <= '9') {
            // F-026: the whole glued [0-9A-Za-z_] run is one integer literal
            // (prefix, digits, separators and any suffix), validated whole.
            while (self.pos < self.source.len and int_literal.isNumberContinue(self.source[self.pos])) _ = self.advance();
            const lit_text = self.source[start..self.pos];
            return .{ .kind = .number, .text = lit_text, .raw = lit_text, .line = sl, .col = sc };
        }

        // Identifiers and keywords
        if (isIdentStart(c)) {
            while (self.pos < self.source.len and isIdentChar(self.source[self.pos])) _ = self.advance();
            const text = self.source[start..self.pos];
            return .{ .kind = .ident, .text = text, .line = sl, .col = sc };
        }

        // Operators: try multi-char first
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
            '~' => .{ .kind = .tilde, .text = t, .line = sl, .col = sc },
            '^' => .{ .kind = .caret, .text = t, .line = sl, .col = sc },
            '?' => .{ .kind = .question, .text = t, .line = sl, .col = sc },
            '.' => if (c2 == '.' and self.peekAt(1) == '.') blk: {
                _ = self.advance();
                _ = self.advance();
                break :blk .{ .kind = .ellipsis, .text = self.source[start..self.pos], .line = sl, .col = sc };
            } else .{ .kind = .dot, .text = t, .line = sl, .col = sc },
            ':' => if (c2 == '=') blk: {
                _ = self.advance();
                break :blk .{ .kind = .colon_assign, .text = self.source[start..self.pos], .line = sl, .col = sc };
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
// Name conversion helpers
// ============================================================================

/// Convert a Go PascalCase name to camelCase.
/// "PubKeyHash" -> "pubKeyHash", "Count" -> "count", "X" -> "x"
/// Names that start with lowercase are returned unchanged.
fn goToCamelCase(allocator: Allocator, name: []const u8) []const u8 {
    if (name.len == 0) return name;
    if (name[0] >= 'a' and name[0] <= 'z') return name;
    // Already lowercase first letter
    if (!(name[0] >= 'A' and name[0] <= 'Z')) return name;
    // Allocate a copy with the first letter lowered
    const buf = allocator.alloc(u8, name.len) catch return name;
    buf[0] = name[0] + ('a' - 'A');
    if (name.len > 1) {
        @memcpy(buf[1..], name[1..]);
    }
    return buf;
}

/// Check if a Go name starts with uppercase (exported = public).
fn isExported(name: []const u8) bool {
    if (name.len == 0) return false;
    return name[0] >= 'A' and name[0] <= 'Z';
}

/// Map a Go type name to a Runar RunarType.
fn mapGoType(name: []const u8) RunarType {
    const map = std.StaticStringMap(RunarType).initComptime(.{
        .{ "Int", .bigint },
        .{ "Bigint", .bigint },
        .{ "BigintBig", .bigint },
        .{ "int64", .bigint },
        .{ "int", .bigint },
        .{ "Bool", .boolean },
        .{ "bool", .boolean },
        .{ "ByteString", .byte_string },
        .{ "PubKey", .pub_key },
        .{ "Sig", .sig },
        .{ "Sha256", .sha256 },
        .{ "Sha256Digest", .sha256 },
        .{ "Ripemd160", .ripemd160 },
        .{ "Ripemd160Hash", .ripemd160 },
        .{ "Addr", .addr },
        .{ "SigHashPreimage", .sig_hash_preimage },
        .{ "RabinSig", .rabin_sig },
        .{ "RabinPubKey", .rabin_pub_key },
        .{ "Point", .point },
        .{ "P256Point", .p256_point },
        .{ "P384Point", .p384_point },
        .{ "SigHashType", .unknown },
    });
    return map.get(name) orelse .unknown;
}

/// Map a Go builtin name (PascalCase from runar.FuncName) to the Runar camelCase equivalent.
fn mapGoBuiltin(name: []const u8) []const u8 {
    const map = std.StaticStringMap([]const u8).initComptime(.{
        // the *Big peers of num2bin / bin2num. They lower to the SAME builtins as
        // Num2Bin / Bin2Num, exactly as compilers/go has always done: the suffix
        // names a different Go RUNTIME type (*big.Int, so the Go-side mock does not
        // truncate), not a different Script operation. Six tiers fell through to the
        // default rule and produced `num2BinBig` / `bin2NumBig`, names no builtin
        // registry has (R-Bigint).
        .{ "Num2BinBig", "num2bin" },
        .{ "Bin2NumBig", "bin2num" },

        // the *Big peers of abs / gcd. Same rule as Num2BinBig / Bin2NumBig above: the
        // suffix names a different Go RUNTIME type (*big.Int, so the Go-side mock does
        // not narrow at MinInt64), not a different Script operation -- OP_ABS and the
        // gcd builtin are arbitrary-width after Genesis. These were mapped in ZERO
        // tiers while `Abs(math.MinInt64)` and `Gcd(math.MinInt64, 0)` in
        // packages/runar-go panic telling the author to use them, naming the .runar.go
        // parser as the thing that lowers them.
        .{ "AbsBig", "abs" },
        .{ "GcdBig", "gcd" },
        .{ "Assert", "assert" },
        .{ "Hash160", "hash160" },
        .{ "Hash256", "hash256" },
        .{ "Sha256", "sha256" },
        .{ "Sha256Hash", "sha256" },
        .{ "Ripemd160", "ripemd160" },
        .{ "CheckSig", "checkSig" },
        .{ "CheckMultiSig", "checkMultiSig" },
        .{ "CheckPreimage", "checkPreimage" },
        .{ "VerifyRabinSig", "verifyRabinSig" },
        .{ "VerifyWOTS", "verifyWOTS" },
        .{ "VerifySLHDSA_SHA2_128s", "verifySLHDSA_SHA2_128s" },
        .{ "VerifySLHDSA_SHA2_128f", "verifySLHDSA_SHA2_128f" },
        .{ "VerifySLHDSA_SHA2_192s", "verifySLHDSA_SHA2_192s" },
        .{ "VerifySLHDSA_SHA2_192f", "verifySLHDSA_SHA2_192f" },
        .{ "VerifySLHDSA_SHA2_256s", "verifySLHDSA_SHA2_256s" },
        .{ "VerifySLHDSA_SHA2_256f", "verifySLHDSA_SHA2_256f" },
        .{ "Num2Bin", "num2bin" },
        .{ "Bin2Num", "bin2num" },
        .{ "Cat", "cat" },
        .{ "Substr", "substr" },
        .{ "Len", "len" },
        .{ "ReverseBytes", "reverseBytes" },
        .{ "ExtractLocktime", "extractLocktime" },
        .{ "ExtractOutputHash", "extractOutputHash" },
        .{ "ExtractHashPrevouts", "extractHashPrevouts" },
        .{ "ExtractOutpoint", "extractOutpoint" },
        .{ "AddOutput", "addOutput" },
        .{ "AddRawOutput", "addRawOutput" },
        .{ "AddDataOutput", "addDataOutput" },
        .{ "GetStateScript", "getStateScript" },
        .{ "Safediv", "safediv" },
        .{ "Safemod", "safemod" },
        .{ "Clamp", "clamp" },
        .{ "Sign", "sign" },
        .{ "Pow", "pow" },
        .{ "MulDiv", "mulDiv" },
        .{ "PercentOf", "percentOf" },
        .{ "Sqrt", "sqrt" },
        .{ "Gcd", "gcd" },
        .{ "Divmod", "divmod" },
        .{ "Log2", "log2" },
        .{ "ToBool", "bool" },
        .{ "Abs", "abs" },
        .{ "Min", "min" },
        .{ "Max", "max" },
        .{ "Within", "within" },
        .{ "EcAdd", "ecAdd" },
        .{ "EcMul", "ecMul" },
        .{ "EcMulGen", "ecMulGen" },
        .{ "EcNegate", "ecNegate" },
        .{ "EcOnCurve", "ecOnCurve" },
        .{ "EcModReduce", "ecModReduce" },
        .{ "EcEncodeCompressed", "ecEncodeCompressed" },
        .{ "EcMakePoint", "ecMakePoint" },
        .{ "EcPointX", "ecPointX" },
        .{ "EcPointY", "ecPointY" },
        .{ "VerifyECDSAP256", "verifyECDSA_P256" },
        .{ "P256Add", "p256Add" },
        .{ "P256Mul", "p256Mul" },
        .{ "P256MulGen", "p256MulGen" },
        .{ "P256Negate", "p256Negate" },
        .{ "P256OnCurve", "p256OnCurve" },
        .{ "P256EncodeCompressed", "p256EncodeCompressed" },
        .{ "VerifyECDSAP384", "verifyECDSA_P384" },
        .{ "P384Add", "p384Add" },
        .{ "P384Mul", "p384Mul" },
        .{ "P384MulGen", "p384MulGen" },
        .{ "P384Negate", "p384Negate" },
        .{ "P384OnCurve", "p384OnCurve" },
        .{ "P384EncodeCompressed", "p384EncodeCompressed" },
        .{ "Sha256Compress", "sha256Compress" },
        .{ "Sha256Finalize", "sha256Finalize" },
        .{ "Blake3Compress", "blake3Compress" },
        .{ "Blake3Hash", "blake3Hash" },
        .{ "Left", "left" },
        .{ "Right", "right" },
        .{ "Split", "split" },
        .{ "Int2Str", "int2str" },
        .{ "ToByteString", "toByteString" },
        .{ "Pack", "pack" },
        .{ "Unpack", "unpack" },
        .{ "Bool", "bool" },
        .{ "Exit", "exit" },
        .{ "BuildChangeOutput", "buildChangeOutput" },
        .{ "ExtractVersion", "extractVersion" },
        .{ "ExtractHashSequence", "extractHashSequence" },
        .{ "ExtractInputIndex", "extractInputIndex" },
        .{ "ExtractScriptCode", "extractScriptCode" },
        .{ "ExtractAmount", "extractAmount" },
        .{ "ExtractSequence", "extractSequence" },
        .{ "ExtractOutputs", "extractOutputs" },
        .{ "ExtractSigHashType", "extractSigHashType" },
    });
    return map.get(name) orelse name;
}

/// Map a Go builtin name, falling back to camelCase conversion for names
/// without an explicit override. This mirrors the TS/Go/Rust/Python Go parsers
/// which all fall back to camelCase (e.g. `BbFieldAdd` -> `bbFieldAdd`,
/// `MerkleRootSha256` -> `merkleRootSha256`).
fn mapGoBuiltinCamel(allocator: Allocator, name: []const u8) []const u8 {
    const mapped = mapGoBuiltin(name);
    // If the static map had no override it returns the input unchanged. In
    // that case, apply the default camelCase conversion so unknown runar.*
    // builtins match the Runar naming convention used by other compilers.
    if (std.mem.eql(u8, mapped, name)) {
        return goToCamelCase(allocator, name);
    }
    return mapped;
}

/// Decode Go string escape sequences (\n, \t, \r, \0, \\, \", \xNN) from the
/// raw text of a Go string literal, then hex-encode the resulting bytes. Used
/// so that `runar.ByteString("\x00\x6a")` in source becomes a ByteString
/// literal with hex value `"006a"`.
fn decodeGoEscapesAndHex(allocator: Allocator, raw: []const u8) ![]const u8 {
    var decoded: std.ArrayListUnmanaged(u8) = .empty;
    defer decoded.deinit(allocator);
    var i: usize = 0;
    while (i < raw.len) {
        const c = raw[i];
        if (c == '\\' and i + 1 < raw.len) {
            const nx = raw[i + 1];
            switch (nx) {
                'n' => { try decoded.append(allocator, '\n'); i += 2; },
                't' => { try decoded.append(allocator, '\t'); i += 2; },
                'r' => { try decoded.append(allocator, '\r'); i += 2; },
                '0' => { try decoded.append(allocator, 0); i += 2; },
                '\\' => { try decoded.append(allocator, '\\'); i += 2; },
                '"' => { try decoded.append(allocator, '"'); i += 2; },
                'x' => {
                    if (i + 3 < raw.len) {
                        const h1 = raw[i + 2];
                        const h2 = raw[i + 3];
                        const isHex = std.ascii.isHex(h1) and std.ascii.isHex(h2);
                        if (isHex) {
                            const hex_pair = [_]u8{ h1, h2 };
                            const b = try std.fmt.parseInt(u8, &hex_pair, 16);
                            try decoded.append(allocator, b);
                            i += 4;
                        } else {
                            try decoded.append(allocator, c);
                            i += 1;
                        }
                    } else {
                        try decoded.append(allocator, c);
                        i += 1;
                    }
                },
                else => {
                    try decoded.append(allocator, nx);
                    i += 2;
                },
            }
        } else {
            try decoded.append(allocator, c);
            i += 1;
        }
    }
    // Hex-encode the decoded bytes.
    const hex = try allocator.alloc(u8, decoded.items.len * 2);
    const digits = "0123456789abcdef";
    for (decoded.items, 0..) |b, idx| {
        hex[idx * 2] = digits[(b >> 4) & 0xf];
        hex[idx * 2 + 1] = digits[b & 0xf];
    }
    return hex;
}

/// The Rúnar binary operator each `BigintBig` helper stands for.
///
/// `runar.BigintBig` is *big.Int in packages/runar-go and Go has no operator
/// overloading, so a .runar.go contract carrying arbitrary-precision values
/// spells `a === b` as `runar.BigintBigEqual(a, b)` -- and it has to emit the
/// script the operator emits. Mirrors bigintBigOpFor in
/// compilers/go/frontend/parser_gocontract.go, GO_BIGINTBIG_OPS in
/// packages/runar-compiler/src/passes/01-parse-go.ts, go_bigintbig_op in
/// compilers/rust/src/frontend/parser_gocontract.rs, _GO_BIGINTBIG_OPS in
/// compilers/python, and the eleven helpers in packages/runar-go/runar.go.
/// The rewrite lived only in compilers/go until R-Bigint, although all seven
/// tiers parse .runar.go.
fn bigintBigOp(name: []const u8) ?BinOperator {
    const map = std.StaticStringMap(BinOperator).initComptime(.{
        .{ "BigintBigLess", .lt },
        .{ "BigintBigLessEq", .lte },
        .{ "BigintBigGreater", .gt },
        .{ "BigintBigGreaterEq", .gte },
        .{ "BigintBigEqual", .eq },
        .{ "BigintBigNotEqual", .neq },
        .{ "BigintBigAdd", .add },
        .{ "BigintBigSub", .sub },
        .{ "BigintBigMul", .mul },
        .{ "BigintBigMod", .mod },
        .{ "BigintBigDiv", .div },
    });
    return map.get(name);
}

/// Check if a Go type name is a type conversion (not a function call).
/// e.g., runar.Int(0), runar.Bigint(x), runar.Bool(true) are type casts.
fn isTypeConversion(name: []const u8) bool {
    const convs = std.StaticStringMap(void).initComptime(.{
        .{ "Int", {} },
        .{ "Bigint", {} },
        .{ "BigintBig", {} },
        .{ "Bool", {} },
    });
    return convs.has(name);
}

// ============================================================================
// Parser
// ============================================================================

// ============================================================================
// N-056 — ambiguous operator precedence (mirrors 01-parse-go.ts)
// ============================================================================
//
// Go: `* / % << >> & &^` > `+ - | ^` > comparisons > `&&` > `||`. C ladder
// (this parser): MulDiv > AddSub > Shift > Comparison > Equality > BitAnd >
// BitXor > BitOr > And > Or. For `x OP1 y OP2 z` a scheme groups left iff
// prec(OP1) >= prec(OP2). The ordered (OP1 class, OP2 class) pairs on which
// the schemes disagree: 23 class pairs, 72 operator pairs. `&^` lexes as `&`
// over a prefix `^`, i.e. `&`.

const GoPrecClass = enum { mul, shift, @"and", add, @"or", xor, rel, eq, land, lor };

const go_ambiguous_precedence_pairs = [_][2]GoPrecClass{
    .{ .shift, .mul },  .{ .shift, .add },
    .{ .@"and", .mul }, .{ .@"and", .shift }, .{ .@"and", .add }, .{ .@"and", .rel }, .{ .@"and", .eq },
    .{ .add, .shift },  .{ .add, .@"and" },
    .{ .@"or", .add },  .{ .@"or", .xor },    .{ .@"or", .rel },  .{ .@"or", .eq },
    .{ .xor, .add },    .{ .xor, .rel },      .{ .xor, .eq },
    .{ .rel, .@"and" }, .{ .rel, .@"or" },    .{ .rel, .xor },
    .{ .eq, .@"and" },  .{ .eq, .@"or" },     .{ .eq, .xor },     .{ .eq, .rel },
};

fn goPrecClass(op: BinOperator) GoPrecClass {
    return switch (op) {
        .mul, .div, .mod => .mul,
        .lshift, .rshift => .shift,
        .bitand => .@"and",
        .add, .sub => .add,
        .bitor => .@"or",
        .bitxor => .xor,
        .lt, .lte, .gt, .gte => .rel,
        .eq, .neq => .eq,
        .and_op => .land,
        .or_op => .lor,
    };
}

fn isGoAmbiguousPrecedence(first: BinOperator, second: BinOperator) bool {
    const a = goPrecClass(first);
    const b = goPrecClass(second);
    for (go_ambiguous_precedence_pairs) |pair| {
        if (pair[0] == a and pair[1] == b) return true;
    }
    return false;
}

fn goSpelling(op: BinOperator) []const u8 {
    return switch (op) {
        .eq => "==",
        .neq => "!=",
        else => op.toTsString(),
    };
}

const go_ambiguous_precedence_fmt = "ambiguous operator precedence in .runar.go: `a {s} b {s} c` groups differently " ++
    "under Go precedence than in Rúnar's other surfaces; add parentheses";

const Parser = struct {
    allocator: Allocator,
    tokenizer: Tokenizer,
    current: Token,
    /// N-154: the token `bump` consumed last (null before the first), so a
    /// `;` can tell whether it ends a statement on the same line.
    prev: ?Token = null,
    file_name: []const u8,
    errors: std.ArrayListUnmanaged([]const u8),
    nest: input_limits.NestingCounter = .{},
    nest_error: ?[]const u8 = null,
    /// N-093: every `//runar:` directive in the file, in source order.
    directives: []GoDirective = &.{},
    receiver_name: []const u8, // current method's receiver variable name (e.g. "c", "m", "self")
    contract_name: []const u8, // the contract struct name
    /// F-017: declared (spelling, Rúnar name) pairs.
    idents: identifier_collision.DeclaredIdents = .{},
    /// N-056: binary nodes that are expression operands (parenthesised
    /// groups, BigintBig rewrites) and so are atoms to the precedence check.
    go_atoms: std.AutoHashMapUnmanaged(*BinaryOp, void) = .empty,

    /// N-093: the flag specs of the `//runar:sighash` directives attached to
    /// the declaration whose first token is at `line`/`col` (null for a
    /// malformed one).
    fn takeSighashDirectives(self: *Parser, line: u32, col: u32) []const ?[]const u8 {
        var specs: std.ArrayListUnmanaged(?[]const u8) = .empty;
        for (self.directives) |*d| {
            if (d.attach_line != line or d.attach_col != col or !std.mem.eql(u8, d.name, "sighash")) continue;
            d.consumed = true;
            var ok = d.args.len == 0 or d.args[0] == ' ' or d.args[0] == '\t';
            for (d.args) |ch| {
                if (!(std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '|' or ch == ' ' or ch == '\t')) ok = false;
            }
            specs.append(self.allocator, if (ok) d.args else null) catch {};
        }
        return specs.items;
    }

    /// N-093: refuse every directive that is unknown or attached to no func.
    fn reportStrayDirectives(self: *Parser) void {
        for (self.directives) |d| {
            if (d.consumed) continue;
            const msg = if (std.mem.eql(u8, d.name, "sighash"))
                sighash_directive.LOST_SIGHASH_ERROR
            else
                sighash_directive.unknownGoDirectiveMessage(self.allocator, std.mem.concat(self.allocator, u8, &.{ d.name, d.args }) catch d.name);
            const full = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, d.line, lex_diag.diagCol(d.col), msg }) catch continue;
            self.errors.append(self.allocator, full) catch {};
        }
    }

    /// Convert a DECLARED identifier and record it for the F-017 collision
    /// rule (see identifier_collision.zig).
    fn declare(self: *Parser, raw: []const u8) []const u8 {
        return self.idents.declare(self.allocator, raw, goToCamelCase(self.allocator, raw));
    }

    fn init(allocator: Allocator, source: []const u8, file_name: []const u8) Parser {
        var tokenizer = Tokenizer.init(source);
        const first = tokenizer.next();
        var p: Parser = .{
            .allocator = allocator,
            .tokenizer = tokenizer,
            .current = first,
            .file_name = file_name,
            .errors = .empty,
            .receiver_name = "c",
            .contract_name = "",
        };
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
        self.prev = prev;
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
        // Skip `package ...`
        self.skipPackageDecl();
        // Skip `import ...`
        self.skipImportDecl();

        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;
        var parent_class: ParentClass = .smart_contract;
        var methods: std.ArrayListUnmanaged(MethodNode) = .empty;
        var funcs: std.ArrayListUnmanaged(FuncDecl) = .empty;
        var found_struct = false;

        // Parse top-level declarations: type struct, func
        while (self.current.kind != .eof) {
            if (self.checkIdent("type")) {
                const result = self.parseTypeDecl();
                if (result.found) {
                    if (found_struct) {
                        // F-010: exactly one contract struct; never merged.
                        self.addErrorFmt(go_multiple_contracts_fmt, .{ self.contract_name, result.name });
                        continue;
                    }
                    found_struct = true;
                    self.contract_name = result.name;
                    parent_class = result.parent_class;
                    for (result.properties) |p| {
                        properties.append(self.allocator, p) catch {};
                    }
                }
            } else if (self.checkIdent("func")) {
                if (self.parseFuncDecl()) |f| {
                    funcs.append(self.allocator, f) catch {};
                }
            } else {
                // Skip unknown top-level tokens
                _ = self.bump();
            }
        }
        self.reportStrayDirectives();

        if (!found_struct) {
            self.addError(go_no_contract_message);
            return .{ .contract = null, .errors = self.errors.items };
        }

        // F-010: a method whose receiver (value or pointer) is not the
        // contract type is refused -- checked once the whole file is read, so
        // a method declared before the contract struct is judged the same way.
        for (funcs.items) |f| {
            if (f.receiver_type) |recv_type| {
                if (!std.mem.eql(u8, recv_type, self.contract_name)) {
                    const msg = std.fmt.allocPrint(self.allocator, go_foreign_receiver_fmt, .{ f.go_name, recv_type, self.contract_name }) catch continue;
                    const loc = f.method.source_loc orelse self.currentSourceLoc();
                    const full = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, loc.line, lex_diag.diagCol(loc.column), msg }) catch continue;
                    self.errors.append(self.allocator, full) catch {};
                    continue;
                }
            } else if (std.mem.eql(u8, f.go_name, "init") or std.mem.eql(u8, f.go_name, "main")) {
                // N-018: a free `init`/`main` is not an ordinary private
                // helper. Real Go reserves both names for the package
                // initializer / entry point, which can never be called as a
                // function.
                continue;
            }
            methods.append(self.allocator, f.method) catch {};
        }

        // Process init() method: extract property initializers
        var final_methods: std.ArrayListUnmanaged(MethodNode) = .empty;
        for (methods.items) |m| {
            if (std.mem.eql(u8, m.name, "init") and m.params.len == 0 and !m.is_public) {
                // Extract property assignments as initializers
                for (m.body) |stmt| {
                    switch (stmt) {
                        .assign => |assign| {
                            for (properties.items, 0..) |prop, i| {
                                if (std.mem.eql(u8, prop.name, assign.target)) {
                                    properties.items[i].initializer = assign.value;
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

        // Build auto-generated constructor from non-initialized properties
        var uninit_props: std.ArrayListUnmanaged(PropertyNode) = .empty;
        for (properties.items) |prop| {
            if (prop.initializer == null) {
                uninit_props.append(self.allocator, prop) catch {};
            }
        }

        var ctor_params = self.allocator.alloc(ParamNode, uninit_props.items.len) catch return .{ .contract = null, .errors = self.errors.items };
        var super_args = self.allocator.alloc(Expression, uninit_props.items.len) catch return .{ .contract = null, .errors = self.errors.items };
        var assignments = self.allocator.alloc(AssignmentNode, uninit_props.items.len) catch return .{ .contract = null, .errors = self.errors.items };

        for (uninit_props.items, 0..) |prop, i| {
            ctor_params[i] = .{
                .name = prop.name,
                .type_info = prop.type_info,
                .type_name = types.runarTypeToString(prop.type_info),
            };
            super_args[i] = .{ .identifier = prop.name };
            assignments[i] = .{ .target = prop.name, .value = .{ .identifier = prop.name } };
        }

        const constructor = ConstructorNode{
            .params = ctor_params,
            .super_args = super_args,
            .assignments = assignments,
        };

        if (self.idents.message(self.allocator)) |m| self.errors.append(self.allocator, m) catch {};
        return .{
            .contract = ContractNode{
                .name = self.contract_name,
                .parent_class = parent_class,
                .properties = properties.items,
                .constructor = constructor,
                .methods = final_methods.items,
            },
            .errors = self.errors.items,
        };
    }

    // ---- Package & Import ----

    fn skipPackageDecl(self: *Parser) void {
        if (!self.checkIdent("package")) return;
        _ = self.bump(); // consume 'package'
        // Consume package name
        if (self.current.kind == .ident) _ = self.bump();
    }

    fn skipImportDecl(self: *Parser) void {
        while (self.checkIdent("import")) {
            _ = self.bump(); // consume 'import'
            if (self.current.kind == .string_literal) {
                _ = self.bump(); // consume "runar" or path
            } else if (self.current.kind == .lparen) {
                // import ( "runar" )
                _ = self.bump(); // consume '('
                while (self.current.kind != .rparen and self.current.kind != .eof) {
                    _ = self.bump();
                }
                if (self.current.kind == .rparen) _ = self.bump();
            } else if (self.current.kind == .ident) {
                // import alias "path"
                _ = self.bump(); // alias
                if (self.current.kind == .string_literal) _ = self.bump();
            }
        }
    }

    // ---- Type declaration (struct) ----

    const TypeDeclResult = struct {
        found: bool,
        name: []const u8,
        parent_class: ParentClass,
        properties: []PropertyNode,
    };

    fn parseTypeDecl(self: *Parser) TypeDeclResult {
        const empty = TypeDeclResult{ .found = false, .name = "", .parent_class = .smart_contract, .properties = &.{} };

        _ = self.bump(); // consume 'type'

        if (self.current.kind != .ident) {
            self.addError("expected type name after 'type'");
            return empty;
        }
        const name_tok = self.bump();

        if (!self.checkIdent("struct")) {
            // Not a struct declaration; skip to end
            self.skipToEndOfDecl();
            return empty;
        }
        _ = self.bump(); // consume 'struct'

        if (self.expect(.lbrace) == null) return empty;

        var parent_class: ParentClass = .smart_contract;
        var found_parent = false;
        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;

        // Parse struct fields
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            // Check for embedded parent class: runar.SmartContract or runar.StatefulSmartContract
            if (self.checkIdent("runar") and self.tokenizer.peek() == '.') {
                _ = self.bump(); // consume 'runar'
                _ = self.expect(.dot); // consume '.'
                if (self.current.kind == .ident) {
                    const parent_name = self.bump().text;
                    if (std.mem.eql(u8, parent_name, "SmartContract")) {
                        parent_class = .smart_contract;
                        found_parent = true;
                    } else if (std.mem.eql(u8, parent_name, "StatefulSmartContract")) {
                        parent_class = .stateful_smart_contract;
                        found_parent = true;
                    } else if (std.mem.eql(u8, parent_name, "UnsafeSmartContract")) {
                        parent_class = .unsafe_smart_contract;
                        found_parent = true;
                    }
                }
                continue;
            }

            // Parse property: FieldName Type [`runar:"readonly"`]
            if (self.current.kind != .ident) {
                _ = self.bump();
                continue;
            }

            const field_name_tok = self.bump();
            const field_name = self.declare(field_name_tok.text);

            // Parse type — captures FixedArray shape so `expand_fixed_arrays.zig`
            // can see the property after typecheck. Mirrors parse_zig.zig and
            // parse_python.zig.
            const parsed_type = self.parseGoFieldType();

            // Check for struct tag. The `runar` key holds comma-separated
            // options (N-093): `readonly`, and `embedAlways` — the native
            // spelling of the `@embedAlways` directive — in any order.
            var is_readonly = false;
            var embed_always = false;
            if (self.current.kind == .backtick_string) {
                const tag = self.bump().text;
                if (goRunarTagValue(tag)) |value| {
                    var opts = std.mem.splitScalar(u8, value, ',');
                    while (opts.next()) |raw_opt| {
                        const opt = std.mem.trim(u8, raw_opt, " \t\r\n");
                        if (std.mem.eql(u8, opt, "readonly")) is_readonly = true;
                        if (std.mem.eql(u8, opt, "embedAlways")) embed_always = true;
                    }
                }
            }

            // For SmartContract (and UnsafeSmartContract), all properties are readonly
            const readonly = if (parent_class == .smart_contract or parent_class == .unsafe_smart_contract) true else is_readonly;

            properties.append(self.allocator, .{
                .name = field_name,
                .type_info = parsed_type.type_info,
                .readonly = readonly,
                .embed_always = embed_always,
                // N-109: spelled type name + field-name token, for the
                // validator's unsupported-type diagnostic. Diagnostics only.
                .type_name = parsed_type.type_name,
                .source_loc = self.tokenSourceLoc(field_name_tok),
                .fixed_array_length = parsed_type.fixed_array_length,
                .fixed_array_element = parsed_type.fixed_array_element,
                .fixed_array_nested_length = parsed_type.fixed_array_nested_length,
            }) catch {};
        }

        _ = self.expect(.rbrace);

        // F-010: a struct that embeds no runar base is not the contract and
        // is ignored (a method on it is what gets refused, in parse()).
        if (!found_parent) return empty;

        return .{
            .found = true,
            .name = name_tok.text,
            .parent_class = parent_class,
            .properties = properties.items,
        };
    }

    fn skipToEndOfDecl(self: *Parser) void {
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
            } else {
                _ = self.bump();
            }
        }
    }

    // ---- Go Type parsing ----

    const ParsedGoType = struct {
        type_info: RunarType,
        /// The type name as the author spelled it (`runar.PubKey` spells as
        /// `PubKey`, `[N]T` as `FixedArray`). Diagnostics only — N-109.
        type_name: []const u8 = "",
        fixed_array_length: u32 = 0,
        fixed_array_element: RunarType = .unknown,
        fixed_array_nested_length: u32 = 0,
    };

    /// Parse a Go field type, capturing FixedArray shape on outer + nested
    /// `[N]T` arrays. Mirrors `parseFieldTypeNode` in parse_zig.zig.
    fn parseGoFieldType(self: *Parser) ParsedGoType {
        // Fixed-length array: [N]T (recursive for [M][N]T)
        if (self.current.kind == .lbracket) {
            _ = self.bump(); // consume '['
            if (self.current.kind == .rbracket) {
                // []byte -> ByteString
                _ = self.bump(); // consume ']'
                if (self.checkIdent("byte")) {
                    _ = self.bump();
                    return .{ .type_info = .byte_string };
                }
                return .{ .type_info = .unknown };
            }
            if (self.current.kind != .number) {
                self.addError("FixedArray length must be a positive integer literal");
                while (self.current.kind != .rbracket and self.current.kind != .eof) _ = self.bump();
                if (self.current.kind == .rbracket) _ = self.bump();
                return .{ .type_info = .unknown };
            }
            const size_tok = self.bump();
            const size = std.fmt.parseInt(u32, size_tok.text, 10) catch 0;
            _ = self.expect(.rbracket);
            const inner = self.nestedValue(ParsedGoType, .{ .type_info = .unknown }, Parser.parseGoFieldType, .{});
            // Outer FixedArray: track its length and element type. If the
            // element is itself a FixedArray, fold its length into
            // fixed_array_nested_length so expand_fixed_arrays sees the full
            // shape (matches parse_zig / parse_python behaviour).
            //
            // Note: when the element is a nested FixedArray, fixed_array_element
            // stays as `.fixed_array` (NOT the inner element type), matching
            // parse_zig.zig's `typeNodeToRunarType` behaviour. expand_fixed_arrays
            // checks `element == .fixed_array && nested_length > 0` to know it
            // needs to recursively expand into a 2-D synthetic grid.
            var nested: u32 = 0;
            if (inner.type_info == .fixed_array) {
                nested = inner.fixed_array_length;
            }
            return .{
                .type_info = .fixed_array,
                .type_name = "FixedArray",
                .fixed_array_length = size,
                .fixed_array_element = inner.type_info,
                .fixed_array_nested_length = nested,
            };
        }

        var spelled: []const u8 = "";
        const info = self.parseGoTypeNamed(&spelled);
        return .{ .type_info = info, .type_name = spelled };
    }

    fn parseGoType(self: *Parser) RunarType {
        var discard: []const u8 = "";
        return self.parseGoTypeNamed(&discard);
    }

    /// `parseGoType`, additionally reporting the type name as the author
    /// spelled it. `parseGoType` collapses every unrecognised name to
    /// `.unknown`, so the name is the only thing a diagnostic can quote back
    /// (N-109). Left empty on the shapes that have no single spelled name.
    fn parseGoTypeNamed(self: *Parser, out_name: *[]const u8) RunarType {
        // runar.TypeName
        if (self.checkIdent("runar") and self.tokenizer.peek() == '.') {
            _ = self.bump(); // consume 'runar'
            _ = self.expect(.dot); // consume '.'
            if (self.current.kind == .ident) {
                const type_name = self.bump().text;
                out_name.* = type_name;
                return mapGoType(type_name);
            }
            return .unknown;
        }

        // []byte -> ByteString
        if (self.current.kind == .lbracket) {
            _ = self.bump(); // consume '['
            if (self.current.kind == .rbracket) {
                _ = self.bump(); // consume ']'
                if (self.checkIdent("byte")) {
                    _ = self.bump();
                    return .byte_string;
                }
            } else {
                // Fixed-length array nested via parseGoType (legacy path) -- skip
                while (self.current.kind != .rbracket and self.current.kind != .eof) _ = self.bump();
                if (self.current.kind == .rbracket) _ = self.bump();
                if (self.current.kind == .ident) _ = self.bump();
            }
            return .unknown;
        }

        // Plain type name: int64, bool, etc.
        if (self.current.kind == .ident) {
            const type_name = self.bump().text;
            out_name.* = type_name;
            if (std.mem.eql(u8, type_name, "int64") or std.mem.eql(u8, type_name, "int")) return .bigint;
            if (std.mem.eql(u8, type_name, "bool")) return .boolean;
            return mapGoType(type_name);
        }

        // Star pointer: *Type (skip the star, parse the type)
        if (self.current.kind == .star) {
            _ = self.bump();
            return self.nestedValue(RunarType, .unknown, Parser.parseGoTypeNamed, .{out_name});
        }

        return .unknown;
    }

    // ---- Function declarations ----

    /// Parse one `func` declaration. `receiver_type` is the receiver's type
    /// name (`*` stripped) or null for a free function; parse() checks it
    /// against the contract struct once the whole file is read (F-010).
    fn parseFuncDecl(self: *Parser) ?FuncDecl {
        // N-093: the `//runar:sighash` directives directly above this func.
        const func_line = self.current.line;
        const func_col = self.current.col;
        _ = self.bump(); // consume 'func'

        // Check for receiver: (c *Type)
        var has_receiver = false;
        var receiver_type: ?[]const u8 = null;
        if (self.current.kind == .lparen) {
            // This is a method with a receiver
            _ = self.bump(); // consume '('

            // Receiver variable name
            if (self.current.kind == .ident) {
                self.receiver_name = self.bump().text;
            }

            // *Type
            if (self.current.kind == .star) {
                _ = self.bump(); // consume '*'
            }
            receiver_type = "";
            if (self.current.kind == .ident) {
                receiver_type = self.bump().text;
            } else if (self.current.kind == .rparen) {
                // Unnamed receiver `(Type)`: the only identifier is the
                // type. N-018: real Go forbids referencing it in the method
                // body at all, so it must not default to "c" -- that wrongly
                // turned a same-spelled parameter into a self-reference.
                receiver_type = self.receiver_name;
                self.receiver_name = "";
            }
            _ = self.expect(.rparen);
            has_receiver = true;
        }

        // Method/function name
        if (self.current.kind != .ident) {
            self.addError("expected function name");
            self.skipToEndOfDecl();
            return null;
        }
        const name_tok = self.bump();
        const raw_name = name_tok.text;
        const method_loc = self.tokenSourceLoc(name_tok);
        const method_name = self.declare(raw_name);
        const is_public = isExported(raw_name);

        // Parse parameters
        const params = self.parseGoParams();

        // Skip optional return type (anything before '{'); N-331 refuses an
        // unknown name in it.
        self.checkReturnType(method_name, is_public and has_receiver);
        self.skipReturnType();

        // Parse body
        const body = self.parseBlock();

        // Standalone function: a private helper. F-010: exported ones too,
        // exactly as in the TS reference.
        const final_public = has_receiver and is_public;
        var sighash_type: ?i32 = null;
        if (sighash_directive.resolveNativeSighash(self.allocator, method_name, final_public, self.takeSighashDirectives(func_line, func_col))) |r| switch (r) {
            .value => |v| sighash_type = v,
            .err => |e| {
                const full = std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}: {s}", .{ self.file_name, method_loc.line, lex_diag.diagCol(method_loc.column), e }) catch e;
                self.errors.append(self.allocator, full) catch {};
            },
        };

        if (!has_receiver) {
            self.receiver_name = "";
            return .{ .method = .{ .name = method_name, .is_public = false, .params = params, .body = body, .sighash_type = sighash_type, .source_loc = method_loc }, .go_name = raw_name, .receiver_type = null };
        }

        return .{ .method = .{ .name = method_name, .is_public = is_public, .params = params, .body = body, .sighash_type = sighash_type, .source_loc = method_loc }, .go_name = raw_name, .receiver_type = receiver_type };
    }

    fn parseGoParams(self: *Parser) []ParamNode {
        if (self.expect(.lparen) == null) return &.{};
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;

        while (self.current.kind != .rparen and self.current.kind != .eof) {
            // Go parameter syntax: name Type  or  name1, name2 Type
            // Collect names first
            var names: std.ArrayListUnmanaged([]const u8) = .empty;

            while (self.current.kind == .ident) {
                const name_tok = self.bump();
                names.append(self.allocator, name_tok.text) catch {};

                if (self.current.kind == .comma) {
                    // Check if next is another name followed by a type, or if this comma
                    // separates parameters with different types
                    // In Go: `a, b Type` means both have Type
                    // Peek ahead to see if after the comma we have: ident (Type) or ident ident/runar (another name)
                    const saved_pos = self.tokenizer.pos;
                    const saved_line = self.tokenizer.line;
                    const saved_col = self.tokenizer.col;
                    const saved_current = self.current;

                    _ = self.bump(); // consume ','

                    // Check if next is name followed by type or just a type
                    if (self.current.kind == .ident) {
                        // Save state to look further ahead
                        const next_tok = self.current;
                        const next_pos = self.tokenizer.pos;
                        const next_line = self.tokenizer.line;
                        const next_col = self.tokenizer.col;

                        _ = self.bump(); // consume the next ident

                        // After consuming `, name`, decide whether `name` is a fresh
                        // parameter name (more names follow before the type) or actually
                        // the parameter type (e.g. `a, T` shorthand is invalid Go but the
                        // common shape is `name1, name2, ..., nameN Type`).
                        //
                        // Cases that mean `name` was another *parameter name*:
                        //   - next is `,`     → another `, name` group follows
                        //   - next is `ident` → a type token (runar/T/...) — name had
                        //     no inline type, and the type for this whole run is what we
                        //     are looking at right now. So `name` was a name.
                        //   - next is `[` `*` `.` → array/pointer/qualified type
                        //
                        // Case that means `name` was actually the type (we should stop):
                        //   - next is `)` → end of params, and the previous name's type
                        //     was inlined as `name1 Type`. Restore.
                        if (self.current.kind == .comma or
                            self.current.kind == .ident or
                            self.current.kind == .lbracket or
                            self.current.kind == .star or
                            self.current.kind == .dot)
                        {
                            // next_tok is another parameter name, restore to after comma
                            self.tokenizer.pos = next_pos;
                            self.tokenizer.line = next_line;
                            self.tokenizer.col = next_col;
                            self.current = next_tok;
                            continue; // collect more names
                        } else {
                            // next_tok was actually a type -- restore fully
                            self.tokenizer.pos = saved_pos;
                            self.tokenizer.line = saved_line;
                            self.tokenizer.col = saved_col;
                            self.current = saved_current;
                            break;
                        }
                    } else {
                        // Not an ident after comma -- restore
                        self.tokenizer.pos = saved_pos;
                        self.tokenizer.line = saved_line;
                        self.tokenizer.col = saved_col;
                        self.current = saved_current;
                        break;
                    }
                } else {
                    break;
                }
            }

            // Now parse the type
            var param_spelled: []const u8 = "";
            const param_type = self.parseGoTypeNamed(&param_spelled);

            // Create params for all collected names
            for (names.items) |name| {
                const camel = self.declare(name);
                params.append(self.allocator, .{
                    .name = camel,
                    .type_info = param_type,
                    .type_name = types.runarTypeToString(param_type),
                    .spelled_type = types.spelledIfUnknown(param_type, param_spelled),
                }) catch {};
            }

            // Consume comma between parameter groups
            if (self.current.kind == .comma) {
                _ = self.bump();
            } else {
                break;
            }
        }

        _ = self.expect(.rparen);
        return params.items;
    }

    /// N-331: the AST keeps no return type, so a single (unparenthesised)
    /// result type that is not a Rúnar type is refused where it is spelled.
    /// A parenthesised result list is left to `skipReturnType`.
    /// N-332: a PUBLIC method (`is_public`) may declare no result at all,
    /// parenthesised list and native `bool` included.
    fn checkReturnType(self: *Parser, method_name: []const u8, is_public: bool) void {
        if (self.current.kind == .lbrace or self.current.kind == .eof) return;
        if (self.current.kind == .lparen) {
            if (is_public) self.addErrorFmt(lex_diag.PUBLIC_RETURN_TYPE_FMT, .{method_name});
            return;
        }
        var spelled: []const u8 = "";
        const ti = self.parseGoTypeNamed(&spelled);
        const unknown = types.spelledIfUnknown(ti, spelled);
        if (unknown.len > 0) {
            self.addErrorFmt(lex_diag.UNKNOWN_RETURN_TYPE_FMT, .{ unknown, method_name });
        } else if (is_public and ti != .void) {
            self.addErrorFmt(lex_diag.PUBLIC_RETURN_TYPE_FMT, .{method_name});
        }
    }

    fn skipReturnType(self: *Parser) void {
        // Skip everything between ')' and '{' -- the return type
        while (self.current.kind != .lbrace and self.current.kind != .eof) {
            _ = self.bump();
        }
    }

    // ---- Block parsing ----

    fn parseBlock(self: *Parser) []Statement {
        if (self.expect(.lbrace) == null) return &.{};
        var stmts: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            self.skipStatementSeparators();
            if (self.current.kind == .rbrace or self.current.kind == .eof) break;
            if (self.parseStatement()) |s| stmts.append(self.allocator, s) catch {};
        }
        _ = self.expect(.rbrace);
        return stmts.items;
    }

    /// N-154: a `;` that ends a statement on the same line separates it from
    /// the next one (`a := 1; b := 2`, `runar.Assert(x);`), as go/parser
    /// accepts. Any other `;` -- right after `{`, after another `;`, or on a
    /// later line than the statement it would end (where Go has already
    /// inserted one) -- is an EMPTY statement, which stays refused (N-153)
    /// with the TS reference's diagnostic. Called before every statement of
    /// a block, never in a `for` header.
    fn skipStatementSeparators(self: *Parser) void {
        while (self.current.kind == .semicolon) {
            const separates = if (self.prev) |p|
                p.kind != .lbrace and p.kind != .semicolon and p.line == self.current.line
            else
                false;
            if (!separates) self.addError("Unexpected token in expression: ';'");
            _ = self.bump();
        }
    }

    // ---- Statements ----

    fn parseStatement(self: *Parser) ?Statement {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
        return self.parseStatementInner();
    }

    fn parseStatementInner(self: *Parser) ?Statement {
        // if statement (Go: no parens around condition)
        if (self.checkIdent("if")) return self.parseIfStmt();

        // for statement
        if (self.checkIdent("for")) return self.parseForStmt();

        // return statement
        if (self.checkIdent("return")) return self.parseReturnStmt();

        // var declaration: var name Type = value
        if (self.checkIdent("var")) return self.parseVarDecl();

        // Expression statement (including := short decl, assignments, calls)
        return self.parseExpressionStatement();
    }

    fn parseVarDecl(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // consume 'var'

        if (self.current.kind != .ident) {
            self.addError("expected variable name after 'var'");
            return null;
        }
        const name_tok = self.bump();
        const var_name = self.declare(name_tok.text);

        // Type annotation (optional if initializer present)
        var ti: ?RunarType = null;
        var spelled: []const u8 = "";
        if (self.current.kind != .assign and self.current.kind != .eof) {
            // There's a type before the =
            if (self.current.kind == .ident or self.current.kind == .lbracket or self.current.kind == .star) {
                ti = self.parseGoTypeNamed(&spelled);
            }
        }

        // Initializer
        if (self.current.kind == .assign) {
            _ = self.bump(); // consume '='
            const val = self.parseExpression() orelse return null;
            return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = val, .source_loc = loc, .type_name = spelled } };
        }

        // var with no initializer
        return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = null, .source_loc = loc, .type_name = spelled } };
    }

    fn parseIfStmt(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // consume 'if'

        // Go: condition without parens, body in braces
        const cond = self.parseExpression() orelse return null;

        const then_body = self.parseBlock();

        var else_body: ?[]Statement = null;
        if (self.checkIdent("else")) {
            _ = self.bump();
            if (self.checkIdent("if")) {
                // else if ...
                const nested = self.nestedParse(Statement, Parser.parseIfStmt) orelse return null;
                const a = self.allocator.alloc(Statement, 1) catch return null;
                a[0] = nested;
                else_body = a;
            } else {
                else_body = self.parseBlock();
            }
        }

        return .{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body, .source_loc = loc } };
    }

    /// Heap-copy a for-loop update statement so `ForStmt.update` can point at
    /// it (N-061). Returns null if the allocation fails — the update is then
    /// treated as absent, exactly as before this field existed.
    fn storeUpdateStmt(self: *Parser, stmt: Statement) ?*const Statement {
        const ptr = self.allocator.create(Statement) catch return null;
        ptr.* = stmt;
        return ptr;
    }

    fn parseForStmt(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        _ = self.bump(); // consume 'for'

        // Go for loop: for i := 0; i < n; i++ { ... }
        var var_name: []const u8 = "_i";
        var init_value: i64 = 0;
        // N-137: a start that is not a compile-time literal cannot be unrolled.
        var init_is_const: bool = true;
        var bound: i64 = 0;
        var descending: bool = false;
        var inclusive: bool = false;
        // W4: whether the condition's left-hand side is the iterator itself.
        // It used to be thrown away, so `i + 1n < 2n` unrolled twice for a loop
        // the source runs once. Rejected by passes/validate.zig.
        var cond_tests_iter: bool = true;
        // F-025: see `ForStmt.bound_is_const`.
        var bound_is_const: bool = false;
        var bound_ident: ?[]const u8 = null;
        var update: ?*const Statement = null;
        // R-065: did we actually parse a C-style three-part header? Everything
        // below depends on it — `bound` comes from the condition and `update`
        // from the post clause, and neither has a meaningful default. The flag
        // is what lets the refusal below distinguish "a header we read" from
        // "a header we gave up on", which is precisely the distinction the
        // pre-fix code erased.
        var three_part: bool = false;

        // Check if we have an initializer (look for :=)
        // Parse: varname := expr
        if (self.current.kind == .ident) {
            // Could be `i := 0` or just a condition
            // Peek to see if next is :=
            const saved_pos = self.tokenizer.pos;
            const saved_line = self.tokenizer.line;
            const saved_col = self.tokenizer.col;
            const saved_current = self.current;
            const name_tok = self.bump();

            if (self.current.kind == .colon_assign) {
                // for i := expr; ...
                three_part = true;
                var_name = self.declare(name_tok.text);
                _ = self.bump(); // consume ':='

                // Parse init expression -- try to extract int literal.
                //
                // N-129: the `runar.Int(N)` arm used to DISCARD the parsed
                // expression, leaving init_value at 0. `for i := runar.Int(3)`
                // — the idiomatic Go-DSL spelling, and the one every checked-in
                // example would use for a non-zero start — therefore became a
                // loop starting at 0, and since the count is derived from the
                // bound, `i := runar.Int(3); i < 7` unrolled as 0..6 instead of
                // 3..6. Seven iterations of the wrong values: the contract
                // compiled to a script computing a DIFFERENT NUMBER than the
                // source says, in this tier only.
                //
                // `parseExpression` already folds `runar.Int(<literal>)` to a
                // literal, so the fix is to look at what it returned instead of
                // throwing it away.
                if (self.current.kind == .number) {
                    init_value = std.fmt.parseInt(i64, self.bump().text, 0) catch 0;
                } else {
                    const init_expr = self.parseExpression();
                    if (init_expr) |e| {
                        // N-138: `.literal_int` alone missed a negated literal.
                        if (loopStartLiteral(e)) |v| init_value = v else {
                            init_is_const = false;
                        }
                    } else {
                        init_is_const = false;
                    }
                }

                _ = self.expect(.semicolon);

                // Parse condition: i < N
                if (self.current.kind != .semicolon) {
                    const cond_expr = self.parseExpression();
                    if (cond_expr) |expr| {
                        // N-115: `N > i` is `i < N`.
                        loop_condition.normalize(expr, var_name);
                        switch (expr) {
                            .binary_op => |bop| {
                                descending = bop.op == .gt or bop.op == .gte;
                                // Issue #121: record inclusivity (`<=`/`>=`).
                                inclusive = bop.op == .lte or bop.op == .gte;
                                cond_tests_iter = switch (bop.left) {
                                    .identifier => |n| std.mem.eql(u8, n, var_name),
                                    else => false,
                                };
                                // F-025: only a (possibly negated) integer
                                // literal is unrollable; anything else used
                                // to leave `bound` at 0 and compile a loop
                                // that runs zero times.
                                if (loopStartLiteral(bop.right)) |v| {
                                    bound = v;
                                    bound_is_const = true;
                                } else if (bop.right == .identifier) {
                                    bound_ident = bop.right.identifier;
                                }
                            },
                            else => cond_tests_iter = false,
                        }
                    }
                }
                _ = self.expect(.semicolon);

                // Parse update: i++, i += 1, etc. N-061: the clause used to
                // be parsed and discarded, so anything the unrolled loop model
                // cannot represent was silently coerced to a unit step. Record
                // it for validate.zig.
                if (self.current.kind != .lbrace) {
                    const operand = self.parseExpression();
                    // Consume postfix ++ / -- (Go: i++ is a statement, not part of expression)
                    if (self.current.kind == .plus_plus or self.current.kind == .minus_minus) {
                        const is_inc = self.current.kind == .plus_plus;
                        _ = self.bump();
                        if (operand) |o| {
                            if (is_inc) {
                                const inc = self.allocator.create(types.IncrementExpr) catch null;
                                if (inc) |ptr| {
                                    ptr.* = .{ .operand = o, .prefix = false };
                                    update = self.storeUpdateStmt(.{ .expr_stmt = .{ .expr = .{ .increment = ptr } } });
                                }
                            } else {
                                const dec = self.allocator.create(types.DecrementExpr) catch null;
                                if (dec) |ptr| {
                                    ptr.* = .{ .operand = o, .prefix = false };
                                    update = self.storeUpdateStmt(.{ .expr_stmt = .{ .expr = .{ .decrement = ptr } } });
                                }
                            }
                        }
                    } else if (operand) |o| {
                        update = self.storeUpdateStmt(.{ .expr_stmt = .{ .expr = o } });
                    }
                }
            } else {
                // Not a three-part for. Restore so the refusal below reports
                // the header's real first token rather than the one we peeked
                // past.
                self.tokenizer.pos = saved_pos;
                self.tokenizer.line = saved_line;
                self.tokenizer.col = saved_col;
                self.current = saved_current;
            }
        }

        // R-065 — refuse any `for` header this parser could not read as the
        // three-part form.
        //
        // This branch used to DISCARD the header outright:
        //
        //     while (self.current.kind != .lbrace and ...) { _ = self.bump(); }
        //
        // and then fall through to the shared `return .{ .for_stmt = ... }`
        // below with every field at its declaration default. `bound` stayed 0,
        // so `anf_lower.lowerForStatement` computed `base = bound - start = 0`
        // and unrolled the loop ZERO times; `update` was null only as a side
        // effect, which is why validate.zig's R-065 rule never had anything to
        // inspect. Measured on the three shapes a developer can actually write:
        //
        //     for i < 5 { sum = sum + start + i; i++ }
        //         16 hexchars, `0000007b7c9c7777` — body gone. `sum` never
        //         accumulates, so the guard degrades to `0 == expectedSum`:
        //         anyone-can-spend if that constant is 0, permanently
        //         unspendable if it is not. Fund loss either way.
        //     for { sum = sum + start }
        //         8 hexchars, `00009c77` — same shape from a bare Go infinite
        //         loop. Go's tier rejects it.
        //     for i := runar.Int(0); i < 5; { ... }
        //         reaches validate.zig instead; see the R-065 rule there.
        //
        // The unrolled loop model carries `{count, iterVar, start, step, body}`
        // and synthesises iteration k as `start + k*step`. A header with no
        // update clause puts the advance (if any) in the BODY, where nothing
        // proves it runs unconditionally, runs once per iteration, or advances
        // by one — so no count is derivable. spec/grammar.md:420 already says
        // so: "The loop variable MUST use simple increment (`++`) or decrement
        // (`--`)". Six peer tiers refuse these programs; the Rust tier used to
        // guess a count from the condition alone, which is unsound for a body
        // whose update is conditional, and has been fixed to refuse too.
        //
        // The statement is DROPPED rather than returned with a default bound:
        // a loop whose shape the parser could not derive has no honest AST,
        // and handing one downstream is the defect itself. The body is still
        // consumed so the rest of the file parses and the user sees every
        // diagnostic, not just this one.
        if (!three_part) {
            self.addError("For loop header must be the three-part form `for i := <literal>; i < <bound>; i++`. " ++
                "A `for <cond> { }` or bare `for { }` loop carries no update clause, so the unrolled " ++
                "loop model -- which synthesises iteration k as `start + k*step` -- has no iteration " ++
                "count to derive; an update written in the body is not guaranteed to run, to run once " ++
                "per iteration, or to advance by one");
            while (self.current.kind != .lbrace and self.current.kind != .eof) {
                _ = self.bump();
            }
            _ = self.parseBlock();
            return null;
        }

        const body = self.parseBlock();
        return .{ .for_stmt = .{ .var_name = var_name, .init_value = init_value, .init_is_const = init_is_const, .bound = bound, .bound_is_const = bound_is_const, .bound_ident = bound_ident, .descending = descending, .inclusive = inclusive, .cond_tests_iter = cond_tests_iter, .update = update, .body = body, .source_loc = loc, .header_requires_update = true } };
    }

    fn parseReturnStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'return'

        // If the next token is } or eof (or, N-154, a `;` separator), it's a
        // bare return
        if (self.current.kind == .rbrace or self.current.kind == .eof or self.current.kind == .semicolon) {
            return .{ .return_stmt = null };
        }

        const expr = self.parseExpression();
        return .{ .return_stmt = expr };
    }

    fn parseExpressionStatement(self: *Parser) ?Statement {
        const loc = self.currentSourceLoc();
        const target_tok = self.current;
        const expr = self.parseExpression() orelse {
            _ = self.bump();
            return null;
        };

        // Short variable declaration: name := value
        // We detect this post-hoc: if expr is an identifier and next is :=
        if (self.current.kind == .colon_assign) {
            _ = self.bump(); // consume ':='
            const rhs = self.parseExpression() orelse return null;
            // Extract the variable name from the LHS identifier
            switch (expr) {
                .identifier => |id| {
                    if (target_tok.kind == .ident) _ = self.idents.declare(self.allocator, target_tok.text, id);
                    return .{ .let_decl = .{ .name = id, .type_info = null, .value = rhs, .source_loc = loc } };
                },
                else => {
                    self.addError("left side of := must be an identifier");
                    return null;
                },
            }
        }

        // Assignment: expr = value
        if (self.current.kind == .assign) {
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            return self.buildAssignment(expr, rhs, loc);
        }

        // Compound assignments: +=, -=, *=, /=, %=
        if (isCompoundAssignOp(self.current.kind)) {
            const op_kind = self.current.kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs, loc);
        }

        // Postfix ++ / -- as statement (Go: i++ is a statement, not expression)
        if (self.current.kind == .plus_plus) {
            _ = self.bump();
            const inc = self.allocator.create(IncrementExpr) catch return null;
            inc.* = .{ .operand = expr, .prefix = false };
            return .{ .expr_stmt = .{ .expr = .{ .increment = inc }, .source_loc = loc } };
        }
        if (self.current.kind == .minus_minus) {
            _ = self.bump();
            const dec = self.allocator.create(DecrementExpr) catch return null;
            dec.* = .{ .operand = expr, .prefix = false };
            return .{ .expr_stmt = .{ .expr = .{ .decrement = dec }, .source_loc = loc } };
        }

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
                // `c.Board[i] = v` — extract the base property name and
                // attach the IndexAccess so `expand_fixed_arrays.zig` can
                // rewrite it into direct (literal index) or dispatch
                // (runtime index) form. Mirrors parse_zig.zig's
                // `extractAssignTarget` + `index_target` handling.
                const base = switch (ia.object) {
                    .property_access => |pa| pa.property,
                    .identifier => |id| id,
                    else => "unknown",
                };
                return .{ .assign = .{ .target = base, .value = value, .index_target = ia, .source_loc = loc, .target_is_property = is_prop } };
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

    // ---- Expressions ----
    // Operator precedence (lowest to highest):
    //   logical or (||)
    //   logical and (&&)
    //   bitwise or (|)
    //   bitwise xor (^)
    //   bitwise and (&)
    //   equality (== !=)
    //   comparison (< <= > >=)
    //   shift (<< >>)
    //   additive (+ -)
    //   multiplicative (* / %)
    //   unary (! - ~ )
    //   postfix (. [] ())
    //   primary

    fn parseExpression(self: *Parser) ?Expression {
        if (!self.enterNest()) return null;
        defer self.nest.exit();
        const expr = self.parseLogicalOr() orelse return null;
        self.checkGoPrecedence(expr);
        return expr;
    }

    /// N-056: refuse an unparenthesised operand edge that groups differently
    /// under Go precedence; nested ( ... ) groups were checked by their own
    /// parseExpression call and are atoms here.
    fn checkGoPrecedence(self: *Parser, expr: Expression) void {
        var work: std.ArrayListUnmanaged(*BinaryOp) = .empty;
        defer work.deinit(self.allocator);
        if (expr != .binary_op or self.go_atoms.contains(expr.binary_op)) return;
        work.append(self.allocator, expr.binary_op) catch return;
        while (work.pop()) |e| {
            const sides = [_]struct { child: Expression, left_side: bool }{
                .{ .child = e.left, .left_side = true },
                .{ .child = e.right, .left_side = false },
            };
            for (sides) |side| {
                if (side.child != .binary_op or self.go_atoms.contains(side.child.binary_op)) continue;
                const c = side.child.binary_op;
                const first = if (side.left_side) c.op else e.op;
                const second = if (side.left_side) e.op else c.op;
                if (isGoAmbiguousPrecedence(first, second)) {
                    self.addErrorFmt(go_ambiguous_precedence_fmt, .{ goSpelling(first), goSpelling(second) });
                    return;
                }
                work.append(self.allocator, c) catch return;
            }
        }
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
            // Go == maps to === , Go != maps to !==
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
            // Go uses ^ for bitwise NOT, but ~ might appear in some contexts
            _ = self.bump();
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .bitnot, .operand = o };
            return .{ .unary_op = uop };
        }
        if (self.current.kind == .caret) {
            // Go uses ^ as unary XOR (bitwise NOT)
            _ = self.bump();
            const o = self.nestedParse(Expression, Parser.parseUnary) orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .bitnot, .operand = o };
            return .{ .unary_op = uop };
        }
        const expr = self.parsePostfix() orelse return null;
        // N-056: an operand is an atom to the precedence check.
        if (expr == .binary_op) self.go_atoms.put(self.allocator, expr.binary_op, {}) catch {};
        return expr;
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
                const member_tok = self.bump();
                const member = member_tok.text;

                // Check if this is a call: expr.member(args)
                if (self.current.kind == .lparen) {
                    _ = self.bump(); // consume '('
                    const args = self.parseArgList();

                    switch (expr) {
                        .identifier => |id| {
                            // runar.FuncName(args) -> check for type conversion or builtin call
                            if (std.mem.eql(u8, id, "runar")) {
                                // Check for type conversions: runar.Int(0), runar.Bigint(x), runar.BigintBig(x), runar.Bool(true)
                                if (isTypeConversion(member) and args.len == 1) {
                                    expr = args[0];
                                } else if (args.len == 2 and bigintBigOp(member) != null) {
                                    // runar.BigintBigEqual(a, b) -> a === b.
                                    expr = self.makeBinaryExpr(bigintBigOp(member).?, args[0], args[1]) orelse return null;
                                } else if (std.mem.eql(u8, member, "ByteString") and args.len == 1) {
                                    // runar.ByteString("literal") -> literal_bytes (hex-encoded);
                                    // runar.ByteString(variable) -> unwrap.
                                    switch (args[0]) {
                                        .literal_bytes => |raw| {
                                            const hex = decodeGoEscapesAndHex(self.allocator, raw) catch raw;
                                            expr = .{ .literal_bytes = hex };
                                        },
                                        else => {
                                            expr = args[0];
                                        },
                                    }
                                } else {
                                    // Builtin call: runar.CheckSig(sig, pk) -> checkSig(sig, pk)
                                    const builtin_name = mapGoBuiltinCamel(self.allocator, member);
                                    const call = self.allocator.create(CallExpr) catch return null;
                                    call.* = .{ .callee = builtin_name, .args = args };
                                    expr = .{ .call = call };
                                }
                            } else if (self.isReceiver(id)) {
                                // c.MethodName(args) -> this.methodName(args)
                                const camel_member = goToCamelCase(self.allocator, member);
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = "this", .method = camel_member, .args = args };
                                expr = .{ .method_call = mc };
                            } else {
                                // Other: obj.method(args)
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = id, .method = goToCamelCase(self.allocator, member), .args = args };
                                expr = .{ .method_call = mc };
                            }
                        },
                        else => {
                            const mc = self.allocator.create(MethodCall) catch return null;
                            mc.* = .{ .object = "unknown", .method = goToCamelCase(self.allocator, member), .args = args };
                            expr = .{ .method_call = mc };
                        },
                    }
                } else {
                    // Property access: expr.property
                    switch (expr) {
                        .identifier => |id| {
                            if (self.isReceiver(id)) {
                                // c.FieldName -> this.fieldName
                                expr = .{ .property_access = .{ .object = "this", .property = goToCamelCase(self.allocator, member) } };
                            } else if (std.mem.eql(u8, id, "runar")) {
                                // runar.SomeConstant -> identifier
                                expr = .{ .identifier = mapGoBuiltinCamel(self.allocator, member) };
                            } else {
                                expr = .{ .property_access = .{ .object = id, .property = goToCamelCase(self.allocator, member) } };
                            }
                        },
                        else => {
                            expr = .{ .property_access = .{ .object = "unknown", .property = goToCamelCase(self.allocator, member) } };
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
                // Direct function call: expr(args) -- for identifiers
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
                break :blk self.parseArrayLiteral();
            },
            .ident => blk: {
                const tok = self.bump();
                const name = tok.text;

                // Go boolean literals
                if (std.mem.eql(u8, name, "true")) break :blk Expression{ .literal_bool = true };
                if (std.mem.eql(u8, name, "false")) break :blk Expression{ .literal_bool = false };

                // Go nil -> treat as false for now
                if (std.mem.eql(u8, name, "nil")) break :blk Expression{ .literal_bool = false };

                break :blk Expression{ .identifier = goToCamelCase(self.allocator, name) };
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
        // Go composite literal form: `[N]T{a, b, c}` or `[N][M]T{...}`.
        // The `[N]T` shape is parsed and discarded — the array literal AST node
        // tracks elements only; the field's type already records the FixedArray
        // shape, so expand_fixed_arrays has everything it needs.
        if (self.current.kind == .number) {
            _ = self.bump(); // consume N
            _ = self.expect(.rbracket);
            // Element type: `[M]T`, `runar.X`, or plain ident
            self.skipCompositeLiteralType();
            return self.parseCompositeLiteralBody();
        }
        // Fallback: legacy JS-style `[a, b, c]` literal.
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

    /// Parse the `{...}` body of a Go composite literal. Each element may be
    /// a regular expression OR a nested implicit composite literal `{ ... }`
    /// when the outer element type is itself a composite type (e.g. the inner
    /// `{0, 0}` of `[2][2]int{{0,0}, {0,0}}`).
    fn parseCompositeLiteralBody(self: *Parser) ?Expression {
        _ = self.expect(.lbrace);
        var elements: std.ArrayListUnmanaged(Expression) = .empty;
        while (self.current.kind != .rbrace and self.current.kind != .eof) {
            const elem: ?Expression = if (self.current.kind == .lbrace)
                self.nestedParse(Expression, Parser.parseCompositeLiteralBody)
            else
                self.parseExpression();
            if (elem) |e| {
                elements.append(self.allocator, e) catch {};
            } else break;
            if (self.current.kind == .comma) {
                _ = self.bump();
            } else break;
        }
        _ = self.expect(.rbrace);
        return .{ .array_literal = elements.items };
    }

    /// Skip the element type in a Go composite literal: `[M]T` (recursive),
    /// `runar.X`, or plain ident. Stops just before `{`.
    fn skipCompositeLiteralType(self: *Parser) void {
        while (true) {
            if (self.current.kind == .lbracket) {
                _ = self.bump();
                if (self.current.kind == .number) _ = self.bump();
                _ = self.expect(.rbracket);
                continue;
            }
            if (self.current.kind == .ident) {
                _ = self.bump();
                if (self.current.kind == .dot) {
                    _ = self.bump();
                    if (self.current.kind == .ident) _ = self.bump();
                }
                return;
            }
            return;
        }
    }

    // ---- Helpers ----

    fn isReceiver(self: *const Parser, name: []const u8) bool {
        // N-018: this must be an exact match on the actual declared
        // receiver name, never a hardcoded "c"/"self"/"m" -- that wrongly
        // turned ANY same-spelled parameter or local into a self-reference
        // even when the receiver was named something else, or unnamed
        // (self.receiver_name == "", which real Go forbids referencing at
        // all).
        return self.receiver_name.len > 0 and std.mem.eql(u8, name, self.receiver_name);
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

    test "N-057: binOpFromCompoundAssign has no silent fallback to add (Go)" {
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
        const src = @embedFile("parse_go.zig");
        try std.testing.expect(std.mem.indexOf(u8, src, bad_arm) == null);
    }

    /// Delegates to the canonical implementation in types.zig.
    const typeNodeToRunarType = types.typeNodeToRunarType;

    /// F-026: a number token's `text` becomes the canonical decimal value of
    /// its literal (`raw` keeps the literal as written), validated against
    /// this surface's host-language rules
    /// (packages/runar-compiler/src/passes/int-literal.ts). A malformed
    /// literal is refused with the shared `invalid <Language> integer literal`.
    fn normalizeNumber(self: *Parser, tok: Token) Token {
        if (tok.kind != .number) return tok;
        var t = tok;
        const lit = int_literal.parse(self.allocator, "go", tok.raw) orelse {
            const msg = int_literal.invalidIntegerLiteral(self.allocator, "go", tok.raw);
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

test "go tokenizer basics" {
    var t = Tokenizer.init("package contract\nimport \"runar\"\ntype P2PKH struct { }");
    // package
    const pkg = t.next();
    try std.testing.expectEqual(TokenKind.ident, pkg.kind);
    try std.testing.expectEqualStrings("package", pkg.text);
    // contract
    try std.testing.expectEqualStrings("contract", t.next().text);
    // import
    try std.testing.expectEqualStrings("import", t.next().text);
    // "runar"
    const s = t.next();
    try std.testing.expectEqual(TokenKind.string_literal, s.kind);
    try std.testing.expectEqualStrings("runar", s.text);
    // type
    try std.testing.expectEqualStrings("type", t.next().text);
    // P2PKH
    try std.testing.expectEqualStrings("P2PKH", t.next().text);
    // struct
    try std.testing.expectEqualStrings("struct", t.next().text);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "go tokenizer operators" {
    var t = Tokenizer.init(":= == != <= >= << >> && || += -= *= /= %= ++ --");
    const expected = [_]TokenKind{
        .colon_assign, .eqeq, .bang_eq, .lt_eq, .gt_eq,
        .lshift, .rshift, .amp_amp, .pipe_pipe, .plus_eq, .minus_eq,
        .star_eq, .slash_eq, .percent_eq, .plus_plus, .minus_minus, .eof,
    };
    for (expected) |e| try std.testing.expectEqual(e, t.next().kind);
}

test "go tokenizer backtick struct tag" {
    var t = Tokenizer.init("`runar:\"readonly\"`");
    const tag = t.next();
    try std.testing.expectEqual(TokenKind.backtick_string, tag.kind);
    try std.testing.expectEqualStrings("runar:\"readonly\"", tag.text);
}

test "go tokenizer comments" {
    var t = Tokenizer.init("// line comment\ntype /* block\n comment */ X struct { }");
    try std.testing.expectEqualStrings("type", t.next().text);
    try std.testing.expectEqualStrings("X", t.next().text);
    try std.testing.expectEqualStrings("struct", t.next().text);
    try std.testing.expectEqual(TokenKind.lbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.rbrace, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "goToCamelCase" {
    const allocator = std.testing.allocator;
    // PascalCase -> camelCase
    const r1 = goToCamelCase(allocator, "PubKeyHash");
    defer allocator.free(r1);
    try std.testing.expectEqualStrings("pubKeyHash", r1);

    // Single letter
    const r2 = goToCamelCase(allocator, "X");
    defer allocator.free(r2);
    try std.testing.expectEqualStrings("x", r2);

    // Already camelCase -- returned as-is (no alloc)
    const r3 = goToCamelCase(allocator, "count");
    try std.testing.expectEqualStrings("count", r3);

    // "Count" -> "count"
    const r4 = goToCamelCase(allocator, "Count");
    defer allocator.free(r4);
    try std.testing.expectEqualStrings("count", r4);
}

test "parse P2PKH contract (Go)" {
    const source =
        \\package contract
        \\
        \\import "runar"
        \\
        \\type P2PKH struct {
        \\  runar.SmartContract
        \\  PubKeyHash runar.Addr `runar:"readonly"`
        \\}
        \\
        \\func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
        \\  runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
        \\  runar.Assert(runar.CheckSig(sig, pubKey))
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "P2PKH.runar.go");
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
    // Auto-generated constructor should have 1 param
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqualStrings("unlock", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].params.len);
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].body.len);
}

test "parse Counter contract (stateful, Go)" {
    const source =
        \\package contract
        \\
        \\import "runar"
        \\
        \\type Counter struct {
        \\  runar.StatefulSmartContract
        \\  Count runar.Bigint
        \\}
        \\
        \\func (c *Counter) Increment() {
        \\  c.Count++
        \\}
        \\
        \\func (c *Counter) Decrement() {
        \\  runar.Assert(c.Count > 0)
        \\  c.Count--
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "Counter.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Counter", c.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, c.parent_class);
    try std.testing.expectEqual(@as(usize, 1), c.properties.len);
    try std.testing.expectEqualStrings("count", c.properties[0].name);
    try std.testing.expectEqual(RunarType.bigint, c.properties[0].type_info);
    try std.testing.expect(!c.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 2), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
    try std.testing.expect(c.methods[0].is_public);
    try std.testing.expectEqualStrings("decrement", c.methods[1].name);
    try std.testing.expect(c.methods[1].is_public);
}

test "parse Arithmetic contract (Go)" {
    const source =
        \\package contract
        \\
        \\import "runar"
        \\
        \\type Arithmetic struct {
        \\  runar.SmartContract
        \\  Target runar.Int `runar:"readonly"`
        \\}
        \\
        \\func (c *Arithmetic) Verify(a runar.Int, b runar.Int) {
        \\  sum := a + b
        \\  diff := a - b
        \\  prod := a * b
        \\  quot := a / b
        \\  result := sum + diff + prod + quot
        \\  runar.Assert(result == c.Target)
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "Arithmetic.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("Arithmetic", c.name);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    // Body should have 5 short var decls + 1 assert
    try std.testing.expectEqual(@as(usize, 6), c.methods[0].body.len);
}

test "parse PropertyInitializers contract (Go)" {
    const source =
        \\package contract
        \\
        \\import "runar"
        \\
        \\type PropertyInitializers struct {
        \\  runar.StatefulSmartContract
        \\  Count    runar.Int
        \\  MaxCount runar.Int `runar:"readonly"`
        \\  Active   runar.Bool `runar:"readonly"`
        \\}
        \\
        \\func (c *PropertyInitializers) init() {
        \\  c.Count = 0
        \\  c.Active = true
        \\}
        \\
        \\func (c *PropertyInitializers) Increment(amount runar.Int) {
        \\  runar.Assert(c.Active)
        \\  c.Count = c.Count + amount
        \\  runar.Assert(c.Count <= c.MaxCount)
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "PropertyInitializers.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("PropertyInitializers", c.name);
    // Count and Active should have initializers from init()
    // Only MaxCount should be in the constructor (Count has init, Active has init)
    try std.testing.expectEqual(@as(usize, 3), c.properties.len);
    // count has initializer
    try std.testing.expect(c.properties[0].initializer != null);
    // active has initializer
    try std.testing.expect(c.properties[2].initializer != null);
    // Constructor should have only maxCount (the only non-initialized prop)
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqualStrings("maxCount", c.constructor.params[0].name);
    // init() should be removed from methods, leaving only Increment
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqualStrings("increment", c.methods[0].name);
}

test "parse BoundedLoop contract (Go)" {
    const source =
        \\package contract
        \\
        \\import "runar"
        \\
        \\type BoundedLoop struct {
        \\  runar.SmartContract
        \\  ExpectedSum runar.Int `runar:"readonly"`
        \\}
        \\
        \\func (c *BoundedLoop) Verify(start runar.Int) {
        \\  sum := runar.Int(0)
        \\  for i := runar.Int(0); i < 5; i++ {
        \\    sum = sum + start + i
        \\  }
        \\  runar.Assert(sum == c.ExpectedSum)
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "BoundedLoop.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("BoundedLoop", c.name);
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    // Body: short var decl + for loop + assert = 3 statements
    try std.testing.expectEqual(@as(usize, 3), c.methods[0].body.len);
}

test "parse BigintBig property and param (Go)" {
    // runar.BigintBig is the big.Int-backed alias for the bigint primitive on
    // the Go mock side. The DSL parser must map it to the same bigint type so
    // arithmetic against runar.Bigint typechecks cleanly.
    const source =
        \\package contract
        \\
        \\import "runar"
        \\
        \\type BigMath struct {
        \\  runar.SmartContract
        \\  Target runar.BigintBig `runar:"readonly"`
        \\}
        \\
        \\func (c *BigMath) Check(a runar.Bigint, b runar.BigintBig) {
        \\  runar.Assert(a + b == c.Target)
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "BigMath.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    // Target property must map to bigint.
    try std.testing.expectEqual(RunarType.bigint, c.properties[0].type_info);
    // Method param b runar.BigintBig must also map to bigint.
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqual(RunarType.bigint, c.methods[0].params[1].type_info);
}

test "parse ByteString literal and variable (Go)" {
    // runar.ByteString("\x00\x6a") emits literal_bytes with hex "006a".
    // runar.ByteString(data) is a no-op type conversion.
    const source =
        \\package contract
        \\
        \\import "runar"
        \\
        \\type LitDemo struct {
        \\  runar.SmartContract
        \\  Expected runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *LitDemo) Check(data runar.ByteString) {
        \\  runar.Assert(runar.ByteString("\x00\x6a") == c.Expected)
        \\  runar.Assert(runar.ByteString(data) == c.Expected)
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "LitDemo.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);

    // Body: [assert_stmt(literal), assert_stmt(variable)].
    try std.testing.expectEqual(@as(usize, 2), c.methods[0].body.len);

    // Walk the first assert's expression and find a literal_bytes == "006a".
    const Finder = struct {
        fn find(expr: types.Expression) ?[]const u8 {
            return switch (expr) {
                .literal_bytes => |v| v,
                .binary_op => |bop| find(bop.left) orelse find(bop.right),
                .call => |call| blk: {
                    for (call.args) |a| if (find(a)) |v| break :blk v;
                    break :blk null;
                },
                else => null,
            };
        }
        fn findIdent(expr: types.Expression, name: []const u8) bool {
            return switch (expr) {
                .identifier => |s| std.mem.eql(u8, s, name),
                .binary_op => |bop| findIdent(bop.left, name) or findIdent(bop.right, name),
                .call => |call| blk: {
                    // Reject a wrapping `byteString(...)` call — that means
                    // the unwrap didn't happen.
                    if (std.mem.eql(u8, call.callee, "byteString")) break :blk false;
                    for (call.args) |a| if (findIdent(a, name)) break :blk true;
                    break :blk false;
                },
                else => false,
            };
        }
    };

    const stmt_0 = c.methods[0].body[0];
    try std.testing.expect(stmt_0 == .expr_stmt);
    const lit = Finder.find(stmt_0.expr_stmt.expr);
    try std.testing.expect(lit != null);
    try std.testing.expectEqualStrings("006a", lit.?);

    const stmt_1 = c.methods[0].body[1];
    try std.testing.expect(stmt_1 == .expr_stmt);
    try std.testing.expect(Finder.findIdent(stmt_1.expr_stmt.expr, "data"));
}

test "parse IfElse contract (Go)" {
    const source =
        \\package contract
        \\
        \\import "runar"
        \\
        \\type IfElse struct {
        \\  runar.SmartContract
        \\  Limit runar.Int `runar:"readonly"`
        \\}
        \\
        \\func (c *IfElse) Check(value runar.Int, mode runar.Bool) {
        \\  result := runar.Int(0)
        \\  if mode {
        \\    result = value + c.Limit
        \\  } else {
        \\    result = value - c.Limit
        \\  }
        \\  runar.Assert(result > 0)
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "IfElse.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expect(r.contract != null);
    const c = r.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    // Body: short var decl + if-else + assert = 3 statements
    try std.testing.expectEqual(@as(usize, 3), c.methods[0].body.len);
}

/// N-138: the compile-time integer value of a loop-start expression, or null.
///
/// Accepts a literal and a NEGATED literal. The negated form is the gap this
/// helper exists for: every surface parser recognised a bare `.number` (or a
/// folded `.literal_int`) and let `-1` fall through to the discard path, so a
/// loop written `for (… i = -1; …)` unrolled from 0 — a different program from
/// the one the source describes, and byte-divergent from the other six tiers
/// with no size difference to notice it by.
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

// ============================================================================
// F-010: a method is a contract method only if its receiver IS the contract.
// This tier refused shape A only by accident (it errored on ANY struct not
// embedding a runar base, so a helper struct was refused but a method on an
// undeclared type, or declared before the contract struct, got through the
// empty-contract-name gate). The rule (user decision R9), diagnostics
// verbatim in all seven tiers:
//   - the contract is THE struct embedding a runar base; others are ignored;
//   - zero or several such structs refuse the file;
//   - a method whose receiver (value or pointer) is another type refuses it;
//   - a free function, exported or not, is a private helper.
// Proves: this tier's .runar.go diagnostics and method set per shape.
// Does NOT prove: the other tiers, or anything on chain.
// ============================================================================

const f010_prelude = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n";
const f010_guarded = "\ntype Guarded struct {\n\trunar.SmartContract\n\tPubKey runar.PubKey `runar:\"readonly\"`\n}\n" ++
    "\nfunc (c *Guarded) Unlock(sig runar.Sig) {\n\trunar.Assert(runar.CheckSig(sig, c.PubKey))\n}\n";
const f010_receiver_error = "method 'Drain' has receiver type 'Unrelated', not the contract type 'Guarded'; methods on other types are not allowed";

fn f010Unrelated(comptime recv: []const u8) []const u8 {
    return "\ntype Unrelated struct{}\n\nfunc (" ++ recv ++ ") Drain(amount runar.Bigint) {\n\trunar.Assert(true)\n}\n";
}

/// Every error is `file:line:col: message`; compare the message part.
fn f010ExpectOnlyError(source: []const u8, want: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "Guarded.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 1), r.errors.len);
    try std.testing.expect(std.mem.endsWith(u8, r.errors[0], want));
    try std.testing.expect(std.mem.endsWith(u8, r.errors[0][0 .. r.errors[0].len - want.len], ": "));
}

fn f010ExpectMethods(source: []const u8, want: []const []const u8, want_public: []const bool) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parseGo(arena.allocator(), source, "Guarded.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqual(want.len, c.methods.len);
    for (c.methods, want, want_public) |m, name, public| {
        try std.testing.expectEqualStrings(name, m.name);
        try std.testing.expectEqual(public, m.is_public);
    }
}

test "F-010: a method on another type is refused (value/pointer, before/after, undeclared)" {
    try f010ExpectOnlyError(f010_prelude ++ f010_guarded ++ comptime f010Unrelated("u Unrelated"), f010_receiver_error);
    try f010ExpectOnlyError(f010_prelude ++ f010_guarded ++ comptime f010Unrelated("u *Unrelated"), f010_receiver_error);
    try f010ExpectOnlyError(f010_prelude ++ comptime f010Unrelated("u Unrelated") ++ f010_guarded, f010_receiver_error);
    try f010ExpectOnlyError(f010_prelude ++ comptime f010Unrelated("u *Unrelated") ++ f010_guarded, f010_receiver_error);
    try f010ExpectOnlyError(f010_prelude ++ f010_guarded ++ "\nfunc (u Unrelated) Drain(amount runar.Bigint) {\n\trunar.Assert(true)\n}\n", f010_receiver_error);
}

test "F-010: value- and pointer-receiver methods on the contract are kept" {
    try f010ExpectMethods(
        f010_prelude ++ f010_guarded ++ "\nfunc (c Guarded) Drain(amount runar.Bigint) {\n\trunar.Assert(amount > 0)\n}\n",
        &.{ "unlock", "drain" },
        &.{ true, true },
    );
}

test "F-010: an exported free function is a private helper" {
    try f010ExpectMethods(
        f010_prelude ++ f010_guarded ++ "\nfunc Drain(amount runar.Bigint) {\n\trunar.Assert(true)\n}\n",
        &.{ "unlock", "drain" },
        &.{ true, false },
    );
}

test "F-010: a helper struct never renames the contract or replaces its properties" {
    const helper = "\ntype Helper struct {\n\tAmount runar.Bigint\n}\n";
    inline for (.{ f010_prelude ++ f010_guarded ++ helper, f010_prelude ++ helper ++ f010_guarded }) |source| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const r = parseGo(arena.allocator(), source, "Guarded.runar.go");
        for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
        try std.testing.expectEqual(@as(usize, 0), r.errors.len);
        const c = r.contract.?;
        try std.testing.expectEqualStrings("Guarded", c.name);
        try std.testing.expectEqual(@as(usize, 1), c.properties.len);
        try std.testing.expectEqualStrings("pubKey", c.properties[0].name);
    }
}

test "F-010: a file with no contract struct is refused" {
    try f010ExpectOnlyError(f010_prelude ++ "\ntype Helper struct {\n\tAmount runar.Bigint\n}\n", "no Rúnar contract struct found in Go source");
}

test "F-010: a file with two contract structs is refused" {
    try f010ExpectOnlyError(
        f010_prelude ++ f010_guarded ++ "\ntype Other struct {\n\trunar.StatefulSmartContract\n\tCount runar.Bigint\n}\n",
        "multiple Rúnar contract structs found in Go source: 'Guarded' and 'Other'; exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract or runar.UnsafeSmartContract",
    );
}

// N-018: a free `init`/`main` is not an ordinary private helper. Real Go
// reserves both names for the package initializer / entry point, which can
// never be called as a function; the Go/Rust/Python/Java tiers already skip
// it (TS/Ruby carried the identical bug and are fixed alongside this one;
// see their own suites).
//
// A 0-param free `init()` is not a case this test reaches: the existing
// init-extraction pass below (`m.name == "init" and m.params.len == 0`)
// already absorbs it regardless of receiver. A free `init` WITH a parameter
// does reach the skip added by F-010's standalone-function loop.
test "N-018: a free init(param)/main() is dropped, not kept as a private helper" {
    try f010ExpectMethods(
        f010_prelude ++ f010_guarded ++
            "\nfunc main() {\n\trunar.Assert(true)\n}\n" ++
            "\nfunc init(amount runar.Bigint) {\n\trunar.Assert(amount > 0)\n}\n",
        &.{"unlock"},
        &.{true},
    );
}

// N-018: the unnamed receiver `(T)` must leave the receiver unreferenceable.
// Real Go forbids referencing an unnamed receiver in the method body at all
// -- there is no name bound to it. This tier instead defaulted the unnamed
// receiver's name to "c" AND (independently) hardcoded "c"/"self"/"m" as
// always meaning "the receiver" regardless of the actual declared name, so
// a parameter literally named `c` was silently read as the contract's own
// `PubKey` -- `this.pubKey`, not the parameter. The TS/Ruby reference
// already gets this right; Go, Rust, Python and Java carried the identical
// hardcoded-alias bug and are fixed alongside this one (see their own
// suites).
//
// Proves: this tier's .runar.go parser never treats a same-spelled
// non-receiver identifier as the contract's self, for an unnamed receiver;
// `c.PubKey` parses as a property_access on the parameter `c`, not on
// "this". Does NOT prove: the other six tiers.
test "N-018: unnamed receiver's parameter named c is not self" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = f010_prelude ++ f010_guarded ++
        "\nfunc (Guarded) CheckC(c runar.PubKey) {\n\trunar.Assert(c.PubKey)\n}\n";
    const r = parseGo(arena.allocator(), source, "Guarded.runar.go");
    for (r.errors) |err| std.debug.print("ERROR: {s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    var method: ?MethodNode = null;
    for (c.methods) |m| {
        if (std.mem.eql(u8, m.name, "checkC")) method = m;
    }
    try std.testing.expect(method != null);
    const stmt = method.?.body[0];
    const call = switch (stmt) {
        .expr_stmt => |es| switch (es.expr) {
            .call => |call| call,
            else => return error.TestExpectedCall,
        },
        else => return error.TestExpectedExprStmt,
    };
    const pa = switch (call.args[0]) {
        .property_access => |pa| pa,
        else => return error.TestExpectedPropertyAccess,
    };
    try std.testing.expectEqualStrings("c", pa.object);
    try std.testing.expectEqualStrings("pubKey", pa.property);
}
