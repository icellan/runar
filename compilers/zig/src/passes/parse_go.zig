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

pub fn parseGo(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
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

        // String literals: double quotes
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

        // Backtick-delimited struct tags: `runar:"readonly"`
        if (c == '`') {
            _ = self.advance();
            while (self.pos < self.source.len and self.source[self.pos] != '`') {
                _ = self.advance();
            }
            if (self.pos < self.source.len) _ = self.advance();
            const content_start = start + 1;
            const content_end = self.pos - 1;
            return .{ .kind = .backtick_string, .text = self.source[content_start..content_end], .line = sl, .col = sc };
        }

        // Numbers (decimal, hex, octal, binary)
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
            return .{ .kind = .number, .text = self.source[start..self.pos], .line = sl, .col = sc };
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
        .{ "int64", .bigint },
        .{ "int", .bigint },
        .{ "Bool", .boolean },
        .{ "bool", .boolean },
        .{ "ByteString", .byte_string },
        .{ "PubKey", .pub_key },
        .{ "Sig", .sig },
        .{ "Sha256", .sha256 },
        .{ "Ripemd160", .ripemd160 },
        .{ "Addr", .addr },
        .{ "SigHashPreimage", .sig_hash_preimage },
        .{ "RabinSig", .rabin_sig },
        .{ "RabinPubKey", .rabin_pub_key },
        .{ "Point", .point },
        .{ "SigHashType", .unknown },
    });
    return map.get(name) orelse .unknown;
}

/// Map a Go builtin name (PascalCase from runar.FuncName) to the Runar camelCase equivalent.
fn mapGoBuiltin(name: []const u8) []const u8 {
    const map = std.StaticStringMap([]const u8).initComptime(.{
        .{ "Assert", "assert" },
        .{ "Hash160", "hash160" },
        .{ "Hash256", "hash256" },
        .{ "Sha256", "sha256" },
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

/// Check if a Go type name is a type conversion (not a function call).
/// e.g., runar.Int(0), runar.Bigint(x), runar.Bool(true) are type casts.
fn isTypeConversion(name: []const u8) bool {
    const convs = std.StaticStringMap(void).initComptime(.{
        .{ "Int", {} },
        .{ "Bigint", {} },
        .{ "Bool", {} },
    });
    return convs.has(name);
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
    receiver_name: []const u8, // current method's receiver variable name (e.g. "c", "m", "self")
    contract_name: []const u8, // the contract struct name

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
            .receiver_name = "c",
            .contract_name = "",
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
        var found_struct = false;

        // Parse top-level declarations: type struct, func
        while (self.current.kind != .eof) {
            if (self.checkIdent("type")) {
                const result = self.parseTypeDecl();
                if (result.found) {
                    found_struct = true;
                    self.contract_name = result.name;
                    parent_class = result.parent_class;
                    for (result.properties) |p| {
                        properties.append(self.allocator, p) catch {};
                    }
                }
            } else if (self.checkIdent("func")) {
                if (self.parseFuncDecl()) |m| {
                    methods.append(self.allocator, m) catch {};
                }
            } else {
                // Skip unknown top-level tokens
                _ = self.bump();
            }
        }

        if (!found_struct) {
            self.addError("no Runar contract struct found in Go source");
            return .{ .contract = null, .errors = self.errors.items };
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
            const field_name = goToCamelCase(self.allocator, field_name_tok.text);

            // Parse type — captures FixedArray shape so `expand_fixed_arrays.zig`
            // can see the property after typecheck. Mirrors parse_zig.zig and
            // parse_python.zig.
            const parsed_type = self.parseGoFieldType();

            // Check for struct tag
            var is_readonly = false;
            if (self.current.kind == .backtick_string) {
                const tag = self.bump().text;
                if (std.mem.indexOf(u8, tag, "runar:\"readonly\"") != null) {
                    is_readonly = true;
                }
            }

            // For SmartContract, all properties are readonly
            const readonly = if (parent_class == .smart_contract) true else is_readonly;

            properties.append(self.allocator, .{
                .name = field_name,
                .type_info = parsed_type.type_info,
                .readonly = readonly,
                .fixed_array_length = parsed_type.fixed_array_length,
                .fixed_array_element = parsed_type.fixed_array_element,
                .fixed_array_nested_length = parsed_type.fixed_array_nested_length,
            }) catch {};
        }

        _ = self.expect(.rbrace);

        if (!found_parent) {
            self.addErrorFmt("struct '{s}' does not embed runar.SmartContract or runar.StatefulSmartContract", .{name_tok.text});
            return empty;
        }

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
            const inner = self.parseGoFieldType();
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
                .fixed_array_length = size,
                .fixed_array_element = inner.type_info,
                .fixed_array_nested_length = nested,
            };
        }

        return .{ .type_info = self.parseGoType() };
    }

    fn parseGoType(self: *Parser) RunarType {
        // runar.TypeName
        if (self.checkIdent("runar") and self.tokenizer.peek() == '.') {
            _ = self.bump(); // consume 'runar'
            _ = self.expect(.dot); // consume '.'
            if (self.current.kind == .ident) {
                const type_name = self.bump().text;
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
            if (std.mem.eql(u8, type_name, "int64") or std.mem.eql(u8, type_name, "int")) return .bigint;
            if (std.mem.eql(u8, type_name, "bool")) return .boolean;
            return mapGoType(type_name);
        }

        // Star pointer: *Type (skip the star, parse the type)
        if (self.current.kind == .star) {
            _ = self.bump();
            return self.parseGoType();
        }

        return .unknown;
    }

    // ---- Function declarations ----

    fn parseFuncDecl(self: *Parser) ?MethodNode {
        _ = self.bump(); // consume 'func'

        // Check for receiver: (c *ContractName)
        var has_receiver = false;
        if (self.current.kind == .lparen) {
            // This is a method with a receiver
            _ = self.bump(); // consume '('

            // Receiver variable name
            if (self.current.kind == .ident) {
                self.receiver_name = self.bump().text;
            }

            // *ContractName
            if (self.current.kind == .star) {
                _ = self.bump(); // consume '*'
            }
            if (self.current.kind == .ident) {
                const recv_type = self.bump().text;
                // Verify it matches our contract
                if (self.contract_name.len > 0 and !std.mem.eql(u8, recv_type, self.contract_name)) {
                    // Method on a different type -- skip
                    self.skipToEndOfDecl();
                    return null;
                }
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
        const raw_name = self.bump().text;
        const method_name = goToCamelCase(self.allocator, raw_name);
        const is_public = isExported(raw_name);

        // Parse parameters
        const params = self.parseGoParams();

        // Skip optional return type (anything before '{')
        self.skipReturnType();

        // Parse body
        const body = self.parseBlock();

        if (!has_receiver) {
            // Standalone function: only allow unexported (private helper) functions
            if (isExported(raw_name)) {
                // Skip exported standalone functions (e.g. NewContractName)
                // Check if this is a constructor function: NewContractName
                if (raw_name.len > 3 and std.mem.startsWith(u8, raw_name, "New")) {
                    // This is the constructor function -- we auto-generate constructor, skip it
                    return null;
                }
                return null;
            }
            // Private standalone helper function
            self.receiver_name = "";
            return .{ .name = method_name, .is_public = false, .params = params, .body = body };
        }

        return .{ .name = method_name, .is_public = is_public, .params = params, .body = body };
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
            const param_type = self.parseGoType();

            // Create params for all collected names
            for (names.items) |name| {
                const camel = goToCamelCase(self.allocator, name);
                params.append(self.allocator, .{
                    .name = camel,
                    .type_info = param_type,
                    .type_name = types.runarTypeToString(param_type),
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
            if (self.parseStatement()) |s| stmts.append(self.allocator, s) catch {};
        }
        _ = self.expect(.rbrace);
        return stmts.items;
    }

    // ---- Statements ----

    fn parseStatement(self: *Parser) ?Statement {
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
        _ = self.bump(); // consume 'var'

        if (self.current.kind != .ident) {
            self.addError("expected variable name after 'var'");
            return null;
        }
        const name_tok = self.bump();
        const var_name = goToCamelCase(self.allocator, name_tok.text);

        // Type annotation (optional if initializer present)
        var ti: ?RunarType = null;
        if (self.current.kind != .assign and self.current.kind != .eof) {
            // There's a type before the =
            if (self.current.kind == .ident or self.current.kind == .lbracket or self.current.kind == .star) {
                ti = self.parseGoType();
            }
        }

        // Initializer
        if (self.current.kind == .assign) {
            _ = self.bump(); // consume '='
            const val = self.parseExpression() orelse return null;
            return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = val } };
        }

        // var with no initializer
        return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = null } };
    }

    fn parseIfStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'if'

        // Go: condition without parens, body in braces
        const cond = self.parseExpression() orelse return null;

        const then_body = self.parseBlock();

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
                else_body = self.parseBlock();
            }
        }

        return .{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body } };
    }

    fn parseForStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'for'

        // Go for loop: for i := 0; i < n; i++ { ... }
        var var_name: []const u8 = "_i";
        var init_value: i64 = 0;
        var bound: i64 = 0;

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
                var_name = goToCamelCase(self.allocator, name_tok.text);
                _ = self.bump(); // consume ':='

                // Parse init expression -- try to extract int literal
                if (self.current.kind == .ident and std.mem.eql(u8, self.current.text, "runar")) {
                    // runar.Int(0) type conversion
                    _ = self.parseExpression();
                } else if (self.current.kind == .number) {
                    init_value = std.fmt.parseInt(i64, self.bump().text, 0) catch 0;
                } else {
                    _ = self.parseExpression();
                }

                _ = self.expect(.semicolon);

                // Parse condition: i < N
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
                _ = self.expect(.semicolon);

                // Parse update: i++, i += 1, etc.
                if (self.current.kind != .lbrace) {
                    _ = self.parseExpression();
                    // Consume postfix ++ / -- (Go: i++ is a statement, not part of expression)
                    if (self.current.kind == .plus_plus or self.current.kind == .minus_minus) {
                        _ = self.bump();
                    }
                }
            } else {
                // Not a three-part for; restore and try as condition-only
                self.tokenizer.pos = saved_pos;
                self.tokenizer.line = saved_line;
                self.tokenizer.col = saved_col;
                self.current = saved_current;

                // For condition-only or range loops, just parse condition before '{'
                while (self.current.kind != .lbrace and self.current.kind != .eof) {
                    _ = self.bump();
                }
            }
        }

        const body = self.parseBlock();
        return .{ .for_stmt = .{ .var_name = var_name, .init_value = init_value, .bound = bound, .body = body } };
    }

    fn parseReturnStmt(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'return'

        // If the next token is } or eof, it's a bare return
        if (self.current.kind == .rbrace or self.current.kind == .eof) {
            return .{ .return_stmt = null };
        }

        const expr = self.parseExpression();
        return .{ .return_stmt = expr };
    }

    fn parseExpressionStatement(self: *Parser) ?Statement {
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
                    return .{ .let_decl = .{ .name = id, .type_info = null, .value = rhs } };
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
            return self.buildAssignment(expr, rhs);
        }

        // Compound assignments: +=, -=, *=, /=, %=
        if (isCompoundAssignOp(self.current.kind)) {
            const op_kind = self.current.kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs);
        }

        // Postfix ++ / -- as statement (Go: i++ is a statement, not expression)
        if (self.current.kind == .plus_plus) {
            _ = self.bump();
            const inc = self.allocator.create(IncrementExpr) catch return null;
            inc.* = .{ .operand = expr, .prefix = false };
            return .{ .expr_stmt = .{ .increment = inc } };
        }
        if (self.current.kind == .minus_minus) {
            _ = self.bump();
            const dec = self.allocator.create(DecrementExpr) catch return null;
            dec.* = .{ .operand = expr, .prefix = false };
            return .{ .expr_stmt = .{ .decrement = dec } };
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
            // Go uses ^ for bitwise NOT, but ~ might appear in some contexts
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .bitnot, .operand = o };
            return .{ .unary_op = uop };
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
                                // Check for type conversions: runar.Int(0), runar.Bigint(x), runar.Bool(true)
                                if (isTypeConversion(member) and args.len == 1) {
                                    expr = args[0];
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
                self.parseCompositeLiteralBody()
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
        return std.mem.eql(u8, name, self.receiver_name) or
            std.mem.eql(u8, name, "c") or
            std.mem.eql(u8, name, "self") or
            std.mem.eql(u8, name, "m");
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

    /// Delegates to the canonical implementation in types.zig.
    const typeNodeToRunarType = types.typeNodeToRunarType;
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
