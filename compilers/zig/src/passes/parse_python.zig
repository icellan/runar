//! Pass 1 (Python frontend): Hand-written tokenizer + recursive descent parser for .runar.py files.
//!
//! Parses Python-syntax Rúnar contracts into the Runar IR ContractNode.
//!
//! Syntax conventions:
//!   - `from runar import *` or `from runar import SmartContract, ...` at top (skipped)
//!   - `class ContractName(SmartContract):` or `class ContractName(StatefulSmartContract):`
//!   - Properties: `pub_key_hash: Addr` (mutable), `field: Readonly[ByteString]` (readonly)
//!   - In SmartContract, all properties are implicitly readonly
//!   - Constructor: `def __init__(self, param: Type, ...):` with `super().__init__(...)`
//!   - Methods: `@public` decorator for public, no decorator for private
//!   - `self.field_name` → `this.camelCase`
//!   - snake_case → camelCase conversion for all identifiers
//!   - `assert_(expr)` or `assert expr` for assertions
//!   - `and`/`or`/`not` for boolean operators
//!   - `//` for integer division (maps to `/`)
//!   - `True`/`False` for boolean literals
//!   - `if cond:` / `elif cond:` / `else:` with INDENT/DEDENT significant whitespace
//!   - `for i in range(n):` for loops
//!   - `b'\xde\xad'` byte string literals
//!   - `bytes.fromhex("dead")` pattern
//!   - `**` for power (maps to `pow()` call)
//!   - Python ternary: `value_if_true if condition else value_if_false`
//!   - `#` line comments

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

/// Convert a TypeNode to a RunarType. Delegates to the canonical implementation in types.zig.
const typeNodeToRunarType = types.typeNodeToRunarType;

// ============================================================================
// Public API
// ============================================================================

pub const ParseResult = struct {
    contract: ?ContractNode,
    errors: [][]const u8,
};

pub fn parsePython(allocator: Allocator, source: []const u8, file_name: []const u8) ParseResult {
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
    lbracket,
    rbracket,
    comma,
    dot,
    colon,
    at_sign,
    assign,
    eq_eq,
    not_eq,
    lt,
    lt_eq,
    gt,
    gt_eq,
    plus,
    minus,
    star,
    slash,
    percent,
    tilde,
    ampersand,
    pipe,
    caret,
    amp_amp, // and
    pipe_pipe, // or
    bang, // not
    lshift,
    rshift,
    plus_eq,
    minus_eq,
    star_eq,
    slash_eq, // //=
    percent_eq,
    slash_slash, // //
    star_star, // **
    arrow, // ->
    indent,
    dedent,
    newline,
};

const Token = struct {
    kind: TokenKind,
    text: []const u8,
    line: u32,
    col: u32,
};

// ============================================================================
// Tokenizer — two-phase: raw tokens then INDENT/DEDENT insertion
// ============================================================================

const Tokenizer = struct {
    source: []const u8,
    /// Pre-tokenized list with INDENT/DEDENT.
    tokens: []Token,
    pos: usize,

    fn initFromTokens(tokens: []Token) Tokenizer {
        return .{ .source = "", .tokens = tokens, .pos = 0 };
    }

    fn next(self: *Tokenizer) Token {
        if (self.pos >= self.tokens.len) return .{ .kind = .eof, .text = "", .line = 0, .col = 0 };
        const tok = self.tokens[self.pos];
        self.pos += 1;
        return tok;
    }

    fn peek(self: *const Tokenizer) Token {
        if (self.pos >= self.tokens.len) return .{ .kind = .eof, .text = "", .line = 0, .col = 0 };
        return self.tokens[self.pos];
    }
};

/// Phase 1: produce raw tokens (including NEWLINE) without INDENT/DEDENT.
fn tokenizeRaw(allocator: Allocator, source: []const u8) []Token {
    var tokens = std.ArrayListUnmanaged(Token).empty;
    var i: usize = 0;
    var line: u32 = 1;
    var col: u32 = 0;
    var paren_depth: i32 = 0;

    while (i < source.len) {
        const ch = source[i];

        // Newlines
        if (ch == '\n' or ch == '\r') {
            if (ch == '\r') {
                i += 1;
                if (i < source.len and source[i] == '\n') i += 1;
            } else {
                i += 1;
            }
            if (paren_depth == 0) {
                tokens.append(allocator, .{ .kind = .newline, .text = "\n", .line = line, .col = col }) catch {};
            }
            line += 1;
            col = 0;
            continue;
        }

        // Non-newline whitespace
        if (ch == ' ' or ch == '\t') {
            i += 1;
            col += 1;
            continue;
        }

        // Comment: # ...
        if (ch == '#') {
            while (i < source.len and source[i] != '\n' and source[i] != '\r') {
                i += 1;
            }
            continue;
        }

        const start_col = col;

        // Byte string literals: b'...' or b"..."
        if (ch == 'b' and i + 1 < source.len and (source[i + 1] == '\'' or source[i + 1] == '"')) {
            const quote = source[i + 1];
            i += 2;
            col += 2;
            const start = i;
            while (i < source.len and source[i] != quote) {
                if (source[i] == '\\') {
                    i += 1;
                    col += 1;
                }
                i += 1;
                col += 1;
            }
            const val = source[start..i];
            if (i < source.len) {
                i += 1; // skip closing quote
                col += 1;
            }
            const hex_val = pyByteStringToHex(allocator, val);
            tokens.append(allocator, .{ .kind = .string_literal, .text = hex_val, .line = line, .col = start_col }) catch {};
            continue;
        }

        // String literals (single or double quoted, including triple-quoted)
        if (ch == '"' or ch == '\'') {
            const quote = ch;
            // Check for triple-quote
            if (i + 2 < source.len and source[i + 1] == quote and source[i + 2] == quote) {
                i += 3;
                col += 3;
                const start = i;
                while (i + 2 < source.len) {
                    if (source[i] == quote and source[i + 1] == quote and source[i + 2] == quote) break;
                    if (source[i] == '\n') {
                        line += 1;
                        col = 0;
                    } else {
                        col += 1;
                    }
                    i += 1;
                }
                const val = source[start..i];
                if (i + 2 < source.len) {
                    i += 3;
                    col += 3;
                }
                tokens.append(allocator, .{ .kind = .string_literal, .text = val, .line = line, .col = start_col }) catch {};
                continue;
            }

            i += 1;
            col += 1;
            const start = i;
            while (i < source.len and source[i] != quote) {
                if (source[i] == '\\') {
                    i += 1;
                    col += 1;
                }
                i += 1;
                col += 1;
            }
            const val = source[start..i];
            if (i < source.len) {
                i += 1;
                col += 1;
            }
            tokens.append(allocator, .{ .kind = .string_literal, .text = val, .line = line, .col = start_col }) catch {};
            continue;
        }

        // Numbers
        if (ch >= '0' and ch <= '9') {
            const start = i;
            if (ch == '0' and i + 1 < source.len and (source[i + 1] == 'x' or source[i + 1] == 'X')) {
                i += 2;
                col += 2;
                while (i < source.len and isHexDigit(source[i])) {
                    i += 1;
                    col += 1;
                }
            } else {
                while (i < source.len and ((source[i] >= '0' and source[i] <= '9') or source[i] == '_')) {
                    i += 1;
                    col += 1;
                }
            }
            tokens.append(allocator, .{ .kind = .number, .text = source[start..i], .line = line, .col = start_col }) catch {};
            continue;
        }

        // Identifiers and keywords (including Python boolean operators)
        if (isIdentStart(ch)) {
            const start = i;
            while (i < source.len and isIdentChar(source[i])) {
                i += 1;
                col += 1;
            }
            const word = source[start..i];

            // Map Python boolean keywords to operator tokens
            if (std.mem.eql(u8, word, "and")) {
                tokens.append(allocator, .{ .kind = .amp_amp, .text = "and", .line = line, .col = start_col }) catch {};
            } else if (std.mem.eql(u8, word, "or")) {
                tokens.append(allocator, .{ .kind = .pipe_pipe, .text = "or", .line = line, .col = start_col }) catch {};
            } else if (std.mem.eql(u8, word, "not")) {
                tokens.append(allocator, .{ .kind = .bang, .text = "not", .line = line, .col = start_col }) catch {};
            } else {
                tokens.append(allocator, .{ .kind = .ident, .text = word, .line = line, .col = start_col }) catch {};
            }
            continue;
        }

        // Three-character operators
        if (i + 2 < source.len) {
            const three = source[i .. i + 3];
            if (std.mem.eql(u8, three, "//=")) {
                tokens.append(allocator, .{ .kind = .slash_eq, .text = "//=", .line = line, .col = start_col }) catch {};
                i += 3;
                col += 3;
                continue;
            }
        }

        // Two-character operators
        if (i + 1 < source.len) {
            const two = source[i .. i + 2];
            const two_kind: ?TokenKind = if (std.mem.eql(u8, two, "=="))
                .eq_eq
            else if (std.mem.eql(u8, two, "!="))
                .not_eq
            else if (std.mem.eql(u8, two, "<="))
                .lt_eq
            else if (std.mem.eql(u8, two, ">="))
                .gt_eq
            else if (std.mem.eql(u8, two, "+="))
                .plus_eq
            else if (std.mem.eql(u8, two, "-="))
                .minus_eq
            else if (std.mem.eql(u8, two, "*="))
                .star_eq
            else if (std.mem.eql(u8, two, "%="))
                .percent_eq
            else if (std.mem.eql(u8, two, "//"))
                .slash_slash
            else if (std.mem.eql(u8, two, "**"))
                .star_star
            else if (std.mem.eql(u8, two, "->"))
                .arrow
            else if (std.mem.eql(u8, two, "<<"))
                .lshift
            else if (std.mem.eql(u8, two, ">>"))
                .rshift
            else
                null;

            if (two_kind) |k| {
                tokens.append(allocator, .{ .kind = k, .text = two, .line = line, .col = start_col }) catch {};
                i += 2;
                col += 2;
                continue;
            }
        }

        // Single-character operators and punctuation
        const one_kind: ?TokenKind = switch (ch) {
            '(' => blk: {
                paren_depth += 1;
                break :blk .lparen;
            },
            ')' => blk: {
                if (paren_depth > 0) paren_depth -= 1;
                break :blk .rparen;
            },
            '[' => blk: {
                paren_depth += 1;
                break :blk .lbracket;
            },
            ']' => blk: {
                if (paren_depth > 0) paren_depth -= 1;
                break :blk .rbracket;
            },
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
            '~' => .tilde,
            '&' => .ampersand,
            '|' => .pipe,
            '^' => .caret,
            '@' => .at_sign,
            else => null,
        };

        if (one_kind) |k| {
            tokens.append(allocator, .{ .kind = k, .text = source[i .. i + 1], .line = line, .col = start_col }) catch {};
            i += 1;
            col += 1;
            continue;
        }

        // Skip unknown characters
        i += 1;
        col += 1;
    }

    // Ensure final NEWLINE
    if (tokens.items.len == 0 or tokens.items[tokens.items.len - 1].kind != .newline) {
        tokens.append(allocator, .{ .kind = .newline, .text = "\n", .line = line, .col = col }) catch {};
    }
    tokens.append(allocator, .{ .kind = .eof, .text = "", .line = line, .col = col }) catch {};
    return tokens.items;
}

/// Phase 2: insert INDENT/DEDENT tokens based on leading whitespace.
fn insertIndentation(allocator: Allocator, raw: []const Token) []Token {
    var result = std.ArrayListUnmanaged(Token).empty;
    var indent_stack = std.ArrayListUnmanaged(u32).empty;
    indent_stack.append(allocator, 0) catch {};

    var at_line_start = true;
    var i: usize = 0;

    while (i < raw.len) {
        const tok = raw[i];

        if (tok.kind == .newline) {
            result.append(allocator, tok) catch {};
            at_line_start = true;
            i += 1;
            continue;
        }

        if (tok.kind == .eof) {
            // Emit DEDENT for each remaining indent level
            while (indent_stack.items.len > 1) {
                result.append(allocator, .{ .kind = .dedent, .text = "", .line = tok.line, .col = tok.col }) catch {};
                _ = indent_stack.pop();
            }
            result.append(allocator, tok) catch {};
            break;
        }

        if (at_line_start) {
            at_line_start = false;
            const indent_level: u32 = tok.col;
            const current_indent = indent_stack.items[indent_stack.items.len - 1];

            if (indent_level > current_indent) {
                indent_stack.append(allocator, indent_level) catch {};
                result.append(allocator, .{ .kind = .indent, .text = "", .line = tok.line, .col = tok.col }) catch {};
            } else if (indent_level < current_indent) {
                while (indent_stack.items.len > 1 and indent_stack.items[indent_stack.items.len - 1] > indent_level) {
                    _ = indent_stack.pop();
                    result.append(allocator, .{ .kind = .dedent, .text = "", .line = tok.line, .col = tok.col }) catch {};
                }
            }
        }

        result.append(allocator, tok) catch {};
        i += 1;
    }

    return result.items;
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

/// Convert Python byte string content like `\xde\xad` to hex string "dead".
fn pyByteStringToHex(allocator: Allocator, s: []const u8) []const u8 {
    var hex = std.ArrayListUnmanaged(u8).empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '\\' and i + 1 < s.len) {
            if (s[i + 1] == 'x' and i + 3 < s.len) {
                hex.append(allocator, s[i + 2]) catch {};
                hex.append(allocator, s[i + 3]) catch {};
                i += 4;
                continue;
            }
        }
        // Non-escape byte: encode as two hex chars
        const byte = s[i];
        const hex_chars = "0123456789abcdef";
        hex.append(allocator, hex_chars[byte >> 4]) catch {};
        hex.append(allocator, hex_chars[byte & 0x0f]) catch {};
        i += 1;
    }
    return hex.items;
}

// ============================================================================
// Snake-case to camelCase name conversion
// ============================================================================

/// Special name mappings from Python snake_case to Rúnar camelCase.
fn pyConvertName(allocator: Allocator, name: []const u8) []const u8 {
    // Check special names first
    const special_map = std.StaticStringMap([]const u8).initComptime(.{
        .{ "assert_", "assert" },
        .{ "__init__", "constructor" },
        .{ "check_sig", "checkSig" },
        .{ "check_multi_sig", "checkMultiSig" },
        .{ "check_preimage", "checkPreimage" },
        .{ "verify_wots", "verifyWOTS" },
        .{ "verify_slh_dsa_sha2_128s", "verifySLHDSA_SHA2_128s" },
        .{ "verify_slh_dsa_sha2_128f", "verifySLHDSA_SHA2_128f" },
        .{ "verify_slh_dsa_sha2_192s", "verifySLHDSA_SHA2_192s" },
        .{ "verify_slh_dsa_sha2_192f", "verifySLHDSA_SHA2_192f" },
        .{ "verify_slh_dsa_sha2_256s", "verifySLHDSA_SHA2_256s" },
        .{ "verify_slh_dsa_sha2_256f", "verifySLHDSA_SHA2_256f" },
        .{ "verify_rabin_sig", "verifyRabinSig" },
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
        .{ "add_output", "addOutput" },
        .{ "add_raw_output", "addRawOutput" },
        .{ "get_state_script", "getStateScript" },
        .{ "extract_locktime", "extractLocktime" },
        .{ "extract_output_hash", "extractOutputHash" },
        .{ "extract_sequence", "extractSequence" },
        .{ "extract_version", "extractVersion" },
        .{ "mul_div", "mulDiv" },
        .{ "percent_of", "percentOf" },
        .{ "reverse_bytes", "reverseBytes" },
        .{ "safe_div", "safediv" },
        .{ "safe_mod", "safemod" },
        .{ "sha256", "sha256" },
        .{ "ripemd160", "ripemd160" },
        .{ "hash160", "hash160" },
        .{ "hash256", "hash256" },
        .{ "num2bin", "num2bin" },
        .{ "bin2num", "bin2num" },
        .{ "log2", "log2" },
        .{ "div_mod", "divmod" },
        .{ "tx_preimage", "txPreimage" },
        .{ "sha256_compress", "sha256Compress" },
        .{ "sha256_finalize", "sha256Finalize" },
        .{ "EC_P", "EC_P" },
        .{ "EC_N", "EC_N" },
        .{ "EC_G", "EC_G" },
    });

    if (special_map.get(name)) |mapped| return mapped;

    // If no underscores, return as-is
    if (std.mem.indexOf(u8, name, "_") == null) return name;

    // Check for dunder names: __name__ -> strip and recurse
    if (name.len >= 4 and std.mem.startsWith(u8, name, "__") and std.mem.endsWith(u8, name, "__")) {
        return name;
    }

    // Strip trailing underscore (e.g., sum_ -> sum)
    var stripped = name;
    if (stripped.len > 1 and stripped[stripped.len - 1] == '_') {
        const candidate = stripped[0 .. stripped.len - 1];
        // Check if the stripped version matches a special name
        if (special_map.get(name)) |mapped| return mapped;
        // Otherwise just strip trailing underscore if it has no other underscores
        if (std.mem.indexOf(u8, candidate, "_") == null) return candidate;
        stripped = candidate;
    }

    // Strip leading single underscore for private methods
    if (stripped.len > 1 and stripped[0] == '_' and !(stripped.len > 2 and stripped[1] == '_')) {
        stripped = stripped[1..];
    }

    // General snake_case to camelCase conversion
    var result = std.ArrayListUnmanaged(u8).empty;
    var first_part = true;
    var iter_rest = stripped;

    while (iter_rest.len > 0) {
        const sep = std.mem.indexOf(u8, iter_rest, "_");
        const part = if (sep) |s| iter_rest[0..s] else iter_rest;
        iter_rest = if (sep) |s| (if (s + 1 < iter_rest.len) iter_rest[s + 1 ..] else "") else "";

        if (part.len == 0) continue;

        if (first_part) {
            for (part) |c| result.append(allocator, c) catch {};
            first_part = false;
        } else {
            // Capitalize first letter of subsequent parts
            if (part[0] >= 'a' and part[0] <= 'z') {
                result.append(allocator, part[0] - 32) catch {};
            } else {
                result.append(allocator, part[0]) catch {};
            }
            if (part.len > 1) {
                for (part[1..]) |c| result.append(allocator, c) catch {};
            }
        }
    }

    if (result.items.len == 0) return name;
    return result.items;
}

// ============================================================================
// Python type resolution
// ============================================================================

fn resolvePyTypeName(name: []const u8) TypeNode {
    // Python type aliases
    if (std.mem.eql(u8, name, "int") or std.mem.eql(u8, name, "Int") or std.mem.eql(u8, name, "Bigint")) return .{ .primitive_type = .bigint };
    if (std.mem.eql(u8, name, "bigint")) return .{ .primitive_type = .bigint };
    if (std.mem.eql(u8, name, "bool") or std.mem.eql(u8, name, "Bool") or std.mem.eql(u8, name, "boolean")) return .{ .primitive_type = .boolean };
    if (std.mem.eql(u8, name, "bytes") or std.mem.eql(u8, name, "ByteString")) return .{ .primitive_type = .byte_string };
    if (std.mem.eql(u8, name, "PubKey")) return .{ .primitive_type = .pub_key };
    if (std.mem.eql(u8, name, "Sig")) return .{ .primitive_type = .sig };
    if (std.mem.eql(u8, name, "Sha256")) return .{ .primitive_type = .sha256 };
    if (std.mem.eql(u8, name, "Ripemd160")) return .{ .primitive_type = .ripemd160 };
    if (std.mem.eql(u8, name, "Addr")) return .{ .primitive_type = .addr };
    if (std.mem.eql(u8, name, "SigHashPreimage")) return .{ .primitive_type = .sig_hash_preimage };
    if (std.mem.eql(u8, name, "RabinSig")) return .{ .primitive_type = .rabin_sig };
    if (std.mem.eql(u8, name, "RabinPubKey")) return .{ .primitive_type = .rabin_pub_key };
    if (std.mem.eql(u8, name, "Point")) return .{ .primitive_type = .point };
    if (std.mem.eql(u8, name, "void")) return .{ .primitive_type = .void };
    // Try the canonical lookup
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
        // Two-phase tokenization
        const raw = tokenizeRaw(allocator, source);
        const tokens = insertIndentation(allocator, raw);
        var tokenizer = Tokenizer.initFromTokens(tokens);
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

    fn skipNewlines(self: *Parser) void {
        while (self.current.kind == .newline) _ = self.bump();
    }

    // ---- Top-level ----

    fn parse(self: *Parser) ParseResult {
        self.skipNewlines();
        self.skipImports();
        self.skipNewlines();
        const contract = self.parseClassDecl();
        return .{ .contract = contract, .errors = self.errors.items };
    }

    /// Skip `from ... import ...` and `import ...` statements.
    fn skipImports(self: *Parser) void {
        while (self.checkIdent("from") or self.checkIdent("import")) {
            while (self.current.kind != .newline and self.current.kind != .eof) {
                _ = self.bump();
            }
            self.skipNewlines();
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

        // Parent class: (SmartContract) or (StatefulSmartContract)
        var parent_class: ParentClass = .smart_contract;
        if (self.match(.lparen)) {
            if (self.current.kind != .ident) {
                self.addError("expected parent class name");
                return null;
            }
            const parent_tok = self.bump();
            if (ParentClass.fromTsString(parent_tok.text)) |pc| {
                parent_class = pc;
            } else {
                self.addErrorFmt("unknown parent class: '{s}', expected SmartContract or StatefulSmartContract", .{parent_tok.text});
                return null;
            }
            _ = self.expect(.rparen);
        }

        _ = self.expect(.colon);
        self.skipNewlines();
        _ = self.expect(.indent);

        var properties: std.ArrayListUnmanaged(PropertyNode) = .empty;
        var constructor: ?ConstructorNode = null;
        var methods: std.ArrayListUnmanaged(MethodNode) = .empty;

        while (self.current.kind != .dedent and self.current.kind != .eof) {
            self.skipNewlines();
            if (self.current.kind == .dedent or self.current.kind == .eof) break;

            // Decorator: @public or @private
            if (self.current.kind == .at_sign) {
                _ = self.bump(); // consume '@'
                const decorator = if (self.current.kind == .ident) self.bump().text else "";
                self.skipNewlines();
                // The next thing should be a def
                if (self.checkIdent("def")) {
                    const method = self.parsePyMethod(decorator);
                    methods.append(self.allocator, method) catch {};
                } else {
                    self.addErrorFmt("expected 'def' after @{s} decorator", .{decorator});
                }
                continue;
            }

            // def __init__(self, ...): or def method(self, ...):
            if (self.checkIdent("def")) {
                // Peek ahead to see if it is __init__
                const next_tok = self.tokenizer.peek();
                if (std.mem.eql(u8, next_tok.text, "__init__")) {
                    const ctor_method = self.parsePyConstructorMethod(properties.items);
                    constructor = self.methodToConstructor(ctor_method);
                } else {
                    const method = self.parsePyMethod("private");
                    methods.append(self.allocator, method) catch {};
                }
                continue;
            }

            // pass
            if (self.matchIdent("pass")) {
                self.skipNewlines();
                continue;
            }

            // Property: name: Type or name: Readonly[Type]
            if (self.current.kind == .ident and self.isPyPropertyDecl()) {
                if (self.parsePyProperty(parent_class)) |prop| {
                    properties.append(self.allocator, prop) catch {};
                }
                continue;
            }

            // Skip unknown tokens
            _ = self.bump();
        }

        _ = self.match(.dedent);

        // Auto-generate constructor if not provided
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

    /// Check if current position is a property declaration: ident followed by ':'
    fn isPyPropertyDecl(self: *Parser) bool {
        const next_tok = self.tokenizer.peek();
        return next_tok.kind == .colon;
    }

    // ---- Property parsing ----

    fn parsePyProperty(self: *Parser, parent_class: ParentClass) ?PropertyNode {
        const name_tok = self.bump(); // consume property name
        const prop_name = pyConvertName(self.allocator, name_tok.text);

        _ = self.expect(.colon); // consume ':'

        // Check for Readonly[T]
        var is_readonly = false;
        if (self.checkIdent("Readonly")) {
            is_readonly = true;
        }
        // In SmartContract, all properties are automatically readonly
        if (parent_class == .smart_contract) {
            is_readonly = true;
        }

        const type_node = self.parsePyTypeAnnotation();
        const type_info = typeNodeToRunarType(type_node);

        // Optional initializer: = value
        var initializer: ?Expression = null;
        if (self.current.kind == .assign) {
            _ = self.bump();
            initializer = self.parseExpression();
        }

        self.skipNewlines();

        // Capture FixedArray shape so expand_fixed_arrays.zig can see the
        // length + element type after typecheck.
        var fa_len: u32 = 0;
        var fa_elem: types.RunarType = .unknown;
        var fa_nested_len: u32 = 0;
        if (type_node == .fixed_array_type) {
            fa_len = type_node.fixed_array_type.length;
            const inner = type_node.fixed_array_type.element.*;
            fa_elem = typeNodeToRunarType(inner);
            if (inner == .fixed_array_type) {
                fa_nested_len = inner.fixed_array_type.length;
            }
        }

        return .{
            .name = prop_name,
            .type_info = type_info,
            .readonly = is_readonly,
            .initializer = initializer,
            .fixed_array_length = fa_len,
            .fixed_array_element = fa_elem,
            .fixed_array_nested_length = fa_nested_len,
        };
    }

    // ---- Type annotation parsing ----

    fn parsePyTypeAnnotation(self: *Parser) TypeNode {
        if (self.current.kind != .ident) {
            self.addError("expected type name");
            if (self.current.kind != .eof) _ = self.bump();
            return .{ .custom_type = "unknown" };
        }

        const name = self.current.text;
        _ = self.bump();

        // Readonly[T] — return inner type, readonly-ness handled at property level
        if (std.mem.eql(u8, name, "Readonly")) {
            if (self.match(.lbracket)) {
                const inner = self.parsePyTypeAnnotation();
                _ = self.expect(.rbracket);
                return inner;
            }
            return .{ .custom_type = name };
        }

        // FixedArray[T, N]
        if (std.mem.eql(u8, name, "FixedArray")) {
            if (self.match(.lbracket)) {
                const elem_type = self.parsePyTypeAnnotation();
                _ = self.expect(.comma);
                const size_tok = self.expect(.number) orelse return .{ .custom_type = "FixedArray" };
                const size = std.fmt.parseInt(u32, size_tok.text, 10) catch 0;
                _ = self.expect(.rbracket);
                const elem_ptr = self.allocator.create(TypeNode) catch return .{ .custom_type = "FixedArray" };
                elem_ptr.* = elem_type;
                return .{ .fixed_array_type = .{ .element = elem_ptr, .length = size } };
            }
            return .{ .custom_type = name };
        }

        // Generic subscript: SomeType[...] — skip
        if (self.current.kind == .lbracket) {
            _ = self.bump();
            var bracket_depth: i32 = 1;
            while (bracket_depth > 0 and self.current.kind != .eof) {
                if (self.current.kind == .lbracket) bracket_depth += 1;
                if (self.current.kind == .rbracket) {
                    bracket_depth -= 1;
                    if (bracket_depth == 0) {
                        _ = self.bump();
                        break;
                    }
                }
                _ = self.bump();
            }
            return resolvePyTypeName(name);
        }

        return resolvePyTypeName(name);
    }

    fn runarTypeToTypeName(t: RunarType) []const u8 {
        return types.runarTypeToString(t);
    }

    // ---- Constructor parsing ----

    fn parsePyConstructorMethod(self: *Parser, _: []const PropertyNode) MethodNode {
        _ = self.bump(); // consume 'def'
        _ = self.bump(); // consume '__init__'

        const params = self.parsePyParams();

        // Optional return type: -> Type
        if (self.match(.arrow)) {
            _ = self.parsePyTypeAnnotation();
        }

        _ = self.expect(.colon);
        const body = self.parsePyBlock();

        return .{ .name = "constructor", .is_public = true, .params = params, .body = body };
    }

    /// Convert a constructor MethodNode into a ConstructorNode.
    /// Extracts super().__init__(...) args and self.field = field assignments from body.
    fn methodToConstructor(self: *Parser, m: MethodNode) ConstructorNode {
        var super_args: std.ArrayListUnmanaged(Expression) = .empty;
        var assignments: std.ArrayListUnmanaged(AssignmentNode) = .empty;

        for (m.body) |stmt| {
            switch (stmt) {
                .expr_stmt => |expr| {
                    // super().__init__(...) becomes a method_call with object="super" method="__init__"
                    // or after conversion: object="super" method="constructor"
                    if (self.isSuperInitCall(expr)) {
                        if (self.extractSuperInitArgs(expr)) |args| {
                            for (args) |arg| super_args.append(self.allocator, arg) catch {};
                        }
                        continue;
                    }
                    // Also handle super() call pattern (already converted)
                    if (self.isSuperCall(expr)) {
                        if (self.extractSuperArgs(expr)) |args| {
                            for (args) |arg| super_args.append(self.allocator, arg) catch {};
                        }
                        continue;
                    }
                },
                .assign => |assign| {
                    // self.x = value -> target = x, value = ...
                    assignments.append(self.allocator, .{ .target = assign.target, .value = assign.value }) catch {};
                    continue;
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
            .call => |call| return std.mem.eql(u8, call.callee, "super"),
            .method_call => |mc| return std.mem.eql(u8, mc.object, "super"),
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

    /// Detect super().__init__(...) pattern: a method call on super() result.
    /// In our AST this shows up as a method_call where the object was a call to super.
    /// After Python parsing it appears as: MethodCall{object="super", method="__init__" or "constructor", args=...}
    fn isSuperInitCall(self: *const Parser, expr: Expression) bool {
        _ = self;
        switch (expr) {
            .method_call => |mc| {
                if (std.mem.eql(u8, mc.object, "super") and
                    (std.mem.eql(u8, mc.method, "__init__") or std.mem.eql(u8, mc.method, "constructor") or
                    std.mem.eql(u8, mc.method, "")))
                {
                    return true;
                }
                return false;
            },
            else => return false,
        }
    }

    fn extractSuperInitArgs(self: *const Parser, expr: Expression) ?[]const Expression {
        _ = self;
        switch (expr) {
            .method_call => |mc| return mc.args,
            else => return null,
        }
    }

    fn autoGenerateConstructor(self: *Parser, properties: []const PropertyNode) ConstructorNode {
        // Only non-initialized properties become constructor params
        var params = std.ArrayListUnmanaged(ParamNode).empty;
        var super_args = std.ArrayListUnmanaged(Expression).empty;
        var assignments = std.ArrayListUnmanaged(AssignmentNode).empty;

        for (properties) |prop| {
            if (prop.initializer == null) {
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
        }

        return .{
            .params = params.items,
            .super_args = super_args.items,
            .assignments = assignments.items,
        };
    }

    // ---- Method parsing ----

    fn parsePyMethod(self: *Parser, visibility: []const u8) MethodNode {
        _ = self.bump(); // consume 'def'

        if (self.current.kind != .ident) {
            self.addError("expected method name after 'def'");
            return .{ .name = "unknown", .is_public = false, .params = &.{}, .body = &.{} };
        }
        const name_tok = self.bump();
        const name = pyConvertName(self.allocator, name_tok.text);

        const params = self.parsePyParams();

        // Optional return type: -> Type
        if (self.match(.arrow)) {
            _ = self.parsePyTypeAnnotation();
        }

        _ = self.expect(.colon);
        const body = self.parsePyBlock();

        const is_public = std.mem.eql(u8, visibility, "public");

        return .{ .name = name, .is_public = is_public, .params = params, .body = body };
    }

    // ---- Parameter parsing: (self, param: Type, ...) ----

    fn parsePyParams(self: *Parser) []ParamNode {
        _ = self.expect(.lparen);
        var params: std.ArrayListUnmanaged(ParamNode) = .empty;

        while (self.current.kind != .rparen and self.current.kind != .eof) {
            if (self.current.kind != .ident) break;
            const name_tok = self.bump();
            const param_name = name_tok.text;

            // Skip 'self' parameter
            if (std.mem.eql(u8, param_name, "self")) {
                if (!self.match(.comma)) break;
                continue;
            }

            var type_info: RunarType = .unknown;
            var type_name: []const u8 = "";
            if (self.match(.colon)) {
                const tn = self.parsePyTypeAnnotation();
                type_info = typeNodeToRunarType(tn);
                type_name = runarTypeToTypeName(type_info);
            }

            params.append(self.allocator, .{
                .name = pyConvertName(self.allocator, param_name),
                .type_info = type_info,
                .type_name = type_name,
            }) catch {};

            if (!self.match(.comma)) break;
        }

        _ = self.expect(.rparen);
        return params.items;
    }

    // ---- Block parsing (INDENT/DEDENT) ----

    fn parsePyBlock(self: *Parser) []Statement {
        self.skipNewlines();
        _ = self.expect(.indent);
        var stmts: std.ArrayListUnmanaged(Statement) = .empty;
        while (self.current.kind != .dedent and self.current.kind != .eof) {
            self.skipNewlines();
            if (self.current.kind == .dedent or self.current.kind == .eof) break;
            if (self.parseStatement()) |s| stmts.append(self.allocator, s) catch {};
        }
        _ = self.match(.dedent);
        return stmts.items;
    }

    // ---- Statements ----

    fn parseStatement(self: *Parser) ?Statement {
        // assert expr or assert_(expr)
        if (self.checkIdent("assert") or self.checkIdent("assert_")) {
            return self.parsePyAssert();
        }

        // if
        if (self.checkIdent("if")) return self.parsePyIf();

        // for
        if (self.checkIdent("for")) return self.parsePyFor();

        // return
        if (self.checkIdent("return")) return self.parsePyReturn();

        // pass
        if (self.matchIdent("pass")) {
            self.skipNewlines();
            return null;
        }

        // Variable declaration or expression statement
        return self.parsePyExprOrAssign();
    }

    fn parsePyAssert(self: *Parser) ?Statement {
        const tok = self.bump(); // consume 'assert' or 'assert_'

        if (std.mem.eql(u8, tok.text, "assert_")) {
            // assert_(expr) — function-call style
            _ = self.expect(.lparen);
            const expr = self.parseExpression() orelse return null;
            _ = self.expect(.rparen);
            self.skipNewlines();
            // Emit as call to assert
            const call = self.allocator.create(CallExpr) catch return null;
            call.* = .{
                .callee = "assert",
                .args = self.wrapSingleExpr(expr),
            };
            return .{ .expr_stmt = .{ .call = call } };
        }

        // assert expr or assert(expr) — keyword style
        if (self.current.kind == .lparen) {
            _ = self.bump();
            const expr = self.parseExpression() orelse return null;
            _ = self.expect(.rparen);
            self.skipNewlines();
            const call = self.allocator.create(CallExpr) catch return null;
            call.* = .{
                .callee = "assert",
                .args = self.wrapSingleExpr(expr),
            };
            return .{ .expr_stmt = .{ .call = call } };
        }

        const expr = self.parseExpression() orelse return null;
        self.skipNewlines();
        const call = self.allocator.create(CallExpr) catch return null;
        call.* = .{
            .callee = "assert",
            .args = self.wrapSingleExpr(expr),
        };
        return .{ .expr_stmt = .{ .call = call } };
    }

    fn wrapSingleExpr(self: *Parser, expr: Expression) []Expression {
        const a = self.allocator.alloc(Expression, 1) catch return &.{};
        a[0] = expr;
        return a;
    }

    fn parsePyIf(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'if'
        return self.parsePyIfBody();
    }

    fn parsePyIfBody(self: *Parser) ?Statement {
        const cond = self.parseExpression() orelse return null;
        _ = self.expect(.colon);
        const then_body = self.parsePyBlock();

        var else_body: ?[]Statement = null;
        self.skipNewlines();
        if (self.checkIdent("elif")) {
            _ = self.bump(); // consume 'elif'
            const nested = self.parsePyIfBody() orelse return null;
            const a = self.allocator.alloc(Statement, 1) catch return null;
            a[0] = nested;
            else_body = a;
        } else if (self.matchIdent("else")) {
            _ = self.expect(.colon);
            else_body = self.parsePyBlock();
        }

        return .{ .if_stmt = .{ .condition = cond, .then_body = then_body, .else_body = else_body } };
    }

    fn parsePyFor(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'for'

        if (self.current.kind != .ident) {
            self.addError("expected variable name in for loop");
            return null;
        }
        const var_name = pyConvertName(self.allocator, self.bump().text);

        // expect 'in'
        if (!self.matchIdent("in")) {
            self.addError("expected 'in' in for loop");
            return null;
        }

        // expect 'range'
        if (!self.matchIdent("range")) {
            self.addError("expected 'range' in for loop");
            return null;
        }

        _ = self.expect(.lparen);

        // range(n) or range(a, b)
        const first = self.parseExpression() orelse return null;
        var init_value: i64 = 0;
        var bound: i64 = 0;

        if (self.match(.comma)) {
            // range(a, b)
            const second = self.parseExpression() orelse return null;
            switch (first) {
                .literal_int => |v| {
                    init_value = v;
                },
                else => {},
            }
            switch (second) {
                .literal_int => |v| {
                    bound = v;
                },
                else => {},
            }
        } else {
            // range(n) — init = 0, limit = n
            init_value = 0;
            switch (first) {
                .literal_int => |v| {
                    bound = v;
                },
                else => {},
            }
        }

        _ = self.expect(.rparen);
        _ = self.expect(.colon);
        const body = self.parsePyBlock();

        return .{ .for_stmt = .{
            .var_name = var_name,
            .init_value = init_value,
            .bound = bound,
            .body = body,
        } };
    }

    fn parsePyReturn(self: *Parser) ?Statement {
        _ = self.bump(); // consume 'return'

        if (self.current.kind == .newline or self.current.kind == .dedent or self.current.kind == .eof) {
            self.skipNewlines();
            return .{ .return_stmt = null };
        }

        const expr = self.parseExpression();
        self.skipNewlines();
        return .{ .return_stmt = expr };
    }

    fn parsePyExprOrAssign(self: *Parser) ?Statement {
        // Check for typed variable declaration: name: Type = expr
        if (self.current.kind == .ident) {
            const next_tok = self.tokenizer.peek();
            if (next_tok.kind == .colon) {
                // This is name: Type [= expr]
                const name_tok = self.bump();
                const var_name = pyConvertName(self.allocator, name_tok.text);
                _ = self.bump(); // consume ':'

                const tn = self.parsePyTypeAnnotation();
                const ti = typeNodeToRunarType(tn);

                if (self.match(.assign)) {
                    const val = self.parseExpression() orelse return null;
                    self.skipNewlines();
                    return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = val } };
                } else {
                    self.skipNewlines();
                    return .{ .let_decl = .{ .name = var_name, .type_info = ti, .value = .{ .literal_int = 0 } } };
                }
            }
        }

        const expr = self.parseExpression() orelse {
            _ = self.bump();
            self.skipNewlines();
            return null;
        };

        // Check for assignment: expr = value
        if (self.match(.assign)) {
            const value = self.parseExpression() orelse return null;
            self.skipNewlines();
            return self.buildAssignment(expr, value);
        }

        // Compound assignments
        if (isCompoundAssignOp(self.current.kind)) {
            const op_kind = self.current.kind;
            _ = self.bump();
            const rhs = self.parseExpression() orelse return null;
            self.skipNewlines();
            const bin_op = binOpFromCompoundAssign(op_kind);
            const compound_rhs = self.makeBinaryExpr(bin_op, expr, rhs) orelse return null;
            return self.buildAssignment(expr, compound_rhs);
        }

        self.skipNewlines();
        return .{ .expr_stmt = expr };
    }

    fn buildAssignment(self: *Parser, target: Expression, value: Expression) ?Statement {
        _ = self;
        switch (target) {
            .property_access => |pa| {
                return .{ .assign = .{ .target = pa.property, .value = value } };
            },
            .identifier => |id| {
                // In Python, bare `name = expr` in method body is a variable declaration
                return .{ .let_decl = .{ .name = id, .value = value } };
            },
            .index_access => |ia| {
                // self.arr[idx] = value — carry the full target so
                // expand_fixed_arrays can rewrite it into dispatch form.
                const base_name: []const u8 = switch (ia.object) {
                    .property_access => |pa| pa.property,
                    .identifier => |id| id,
                    else => "unknown",
                };
                return .{ .assign = .{
                    .target = base_name,
                    .value = value,
                    .index_target = ia,
                } };
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
    //   Python ternary (value if condition else alternate)
    //   logical or
    //   logical and
    //   logical not
    //   bitwise or (|)
    //   bitwise xor (^)
    //   bitwise and (&)
    //   equality (== !=)
    //   comparison (< <= > >=)
    //   shift (<< >>)
    //   additive (+ -)
    //   multiplicative (* // / %)
    //   unary (- ~ not)
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

    /// Python ternary: value_if_true if condition else value_if_false
    fn parseTernary(self: *Parser) ?Expression {
        var expr = self.parseLogicalOr() orelse return null;

        // Check for postfix "if" (Python ternary)
        if (self.checkIdent("if")) {
            _ = self.bump(); // consume 'if'
            const condition = self.parseLogicalOr() orelse return null;
            if (!self.matchIdent("else")) {
                self.addError("expected 'else' in ternary expression");
                return null;
            }
            const alternate = self.parseTernary() orelse return null;
            const tern = self.allocator.create(Ternary) catch return null;
            tern.* = .{ .condition = condition, .then_expr = expr, .else_expr = alternate };
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
        var left = self.parseLogicalNot() orelse return null;
        while (self.current.kind == .amp_amp) {
            _ = self.bump();
            const right = self.parseLogicalNot() orelse return null;
            left = self.makeBinaryExpr(.and_op, left, right) orelse return null;
        }
        return left;
    }

    fn parseLogicalNot(self: *Parser) ?Expression {
        if (self.current.kind == .bang) {
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
        while (self.current.kind == .eq_eq or self.current.kind == .not_eq) {
            // Python == maps to === in Rúnar, != maps to !==
            const op: BinOperator = if (self.current.kind == .eq_eq) .eq else .neq;
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
        while (self.current.kind == .star or self.current.kind == .slash_slash or
            self.current.kind == .slash or self.current.kind == .percent)
        {
            const op: BinOperator = switch (self.current.kind) {
                .star => .mul,
                .slash_slash => .div, // Python // (integer division) maps to /
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
        if (self.current.kind == .tilde) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .bitnot, .operand = o };
            return .{ .unary_op = uop };
        }
        if (self.current.kind == .bang) {
            _ = self.bump();
            const o = self.parseUnary() orelse return null;
            const uop = self.allocator.create(UnaryOp) catch return null;
            uop.* = .{ .op = .not, .operand = o };
            return .{ .unary_op = uop };
        }
        return self.parsePower();
    }

    /// Handle ** (right-associative power) — maps to pow() call
    fn parsePower(self: *Parser) ?Expression {
        const base = self.parsePostfix() orelse return null;
        if (self.current.kind == .star_star) {
            _ = self.bump();
            const exp = self.parseUnary() orelse return null; // right-associative
            const call = self.allocator.create(CallExpr) catch return null;
            const args = self.allocator.alloc(Expression, 2) catch return null;
            args[0] = base;
            args[1] = exp;
            call.* = .{ .callee = "pow", .args = args };
            return .{ .call = call };
        }
        return base;
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
                const member_raw = self.bump().text;
                const member = pyConvertName(self.allocator, member_raw);

                if (self.current.kind == .lparen) {
                    // Method call: expr.method(args)
                    _ = self.bump();
                    const args = self.parseArgList();
                    switch (expr) {
                        .identifier => |id| {
                            if (std.mem.eql(u8, id, "self") or std.mem.eql(u8, id, "this")) {
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = "this", .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            } else if (std.mem.eql(u8, id, "super")) {
                                // super().__init__(args) — we already consumed super as identifier,
                                // then .method( pattern
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = "super", .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            } else {
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = id, .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            }
                        },
                        .call => |call_inner| {
                            // super().__init__(...) pattern: call_inner is super(), member is __init__
                            if (std.mem.eql(u8, call_inner.callee, "super")) {
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = "super", .method = member, .args = args };
                                expr = .{ .method_call = mc };
                            } else {
                                const mc = self.allocator.create(MethodCall) catch return null;
                                mc.* = .{ .object = "unknown", .method = member, .args = args };
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
                            if (std.mem.eql(u8, id, "self") or std.mem.eql(u8, id, "this")) {
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
                break :blk self.parseArrayLiteral();
            },
            .minus => blk: {
                // Unary minus at primary level (for negative literals)
                _ = self.bump();
                const o = self.parseUnary() orelse break :blk null;
                const uop = self.allocator.create(UnaryOp) catch break :blk null;
                uop.* = .{ .op = .negate, .operand = o };
                break :blk Expression{ .unary_op = uop };
            },
            .ident => blk: {
                const tok = self.bump();
                const name = tok.text;

                // Python boolean literals
                if (std.mem.eql(u8, name, "True") or std.mem.eql(u8, name, "true")) break :blk Expression{ .literal_bool = true };
                if (std.mem.eql(u8, name, "False") or std.mem.eql(u8, name, "false")) break :blk Expression{ .literal_bool = false };
                if (std.mem.eql(u8, name, "None")) break :blk Expression{ .literal_int = 0 };
                if (std.mem.eql(u8, name, "self")) break :blk Expression{ .identifier = "this" };
                if (std.mem.eql(u8, name, "super")) break :blk Expression{ .identifier = "super" };

                // bytes.fromhex("dead") pattern
                if (std.mem.eql(u8, name, "bytes") and self.current.kind == .dot) {
                    break :blk self.parseBytesMethod();
                }

                // Convert name
                const converted = pyConvertName(self.allocator, name);

                // Function call: name(...)
                if (self.current.kind == .lparen) {
                    _ = self.bump();
                    const args = self.parseArgList();
                    const call = self.allocator.create(CallExpr) catch break :blk null;
                    call.* = .{ .callee = converted, .args = args };
                    break :blk Expression{ .call = call };
                }

                break :blk Expression{ .identifier = converted };
            },
            else => blk: {
                self.addErrorFmt("unexpected token: '{s}'", .{self.current.text});
                break :blk null;
            },
        };
    }

    /// Handle bytes.fromhex("dead") -> literal_bytes
    fn parseBytesMethod(self: *Parser) ?Expression {
        _ = self.bump(); // consume '.'
        if (self.current.kind != .ident) {
            self.addError("expected method name after 'bytes.'");
            return null;
        }
        const method_name = self.bump().text;
        if (std.mem.eql(u8, method_name, "fromhex")) {
            _ = self.expect(.lparen);
            if (self.current.kind == .string_literal) {
                const str_tok = self.bump();
                _ = self.expect(.rparen);
                return Expression{ .literal_bytes = str_tok.text };
            }
            _ = self.expect(.rparen);
            return Expression{ .literal_bytes = "" };
        }
        // Unknown bytes method
        if (self.current.kind == .lparen) {
            _ = self.bump();
            const args = self.parseArgList();
            const mc = self.allocator.create(MethodCall) catch return null;
            mc.* = .{ .object = "bytes", .method = method_name, .args = args };
            return .{ .method_call = mc };
        }
        return .{ .property_access = .{ .object = "bytes", .property = method_name } };
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

test "python tokenizer basics" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source = "class P2PKH(SmartContract):";
    const raw = tokenizeRaw(allocator, source);
    // raw should have: ident(class), ident(P2PKH), lparen, ident(SmartContract), rparen, colon, newline, eof
    try std.testing.expectEqual(TokenKind.ident, raw[0].kind);
    try std.testing.expectEqualStrings("class", raw[0].text);
    try std.testing.expectEqual(TokenKind.ident, raw[1].kind);
    try std.testing.expectEqualStrings("P2PKH", raw[1].text);
    try std.testing.expectEqual(TokenKind.lparen, raw[2].kind);
    try std.testing.expectEqual(TokenKind.ident, raw[3].kind);
    try std.testing.expectEqualStrings("SmartContract", raw[3].text);
    try std.testing.expectEqual(TokenKind.rparen, raw[4].kind);
    try std.testing.expectEqual(TokenKind.colon, raw[5].kind);
}

test "python tokenizer operators" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source = "== != <= >= += -= *= //= %= // ** -> << >>";
    const raw = tokenizeRaw(allocator, source);
    const expected = [_]TokenKind{
        .eq_eq, .not_eq, .lt_eq, .gt_eq, .plus_eq, .minus_eq, .star_eq,
        .slash_eq, .percent_eq, .slash_slash, .star_star, .arrow, .lshift, .rshift,
        .newline, .eof,
    };
    for (expected, 0..) |e, idx| {
        try std.testing.expectEqual(e, raw[idx].kind);
    }
}

test "python boolean operator tokens" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source = "x and y or not z";
    const raw = tokenizeRaw(allocator, source);
    try std.testing.expectEqual(TokenKind.ident, raw[0].kind);
    try std.testing.expectEqual(TokenKind.amp_amp, raw[1].kind);
    try std.testing.expectEqual(TokenKind.ident, raw[2].kind);
    try std.testing.expectEqual(TokenKind.pipe_pipe, raw[3].kind);
    try std.testing.expectEqual(TokenKind.bang, raw[4].kind);
    try std.testing.expectEqual(TokenKind.ident, raw[5].kind);
}

test "python snake_case to camelCase" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectEqualStrings("checkSig", pyConvertName(allocator, "check_sig"));
    try std.testing.expectEqualStrings("pubKeyHash", pyConvertName(allocator, "pub_key_hash"));
    try std.testing.expectEqualStrings("hash160", pyConvertName(allocator, "hash160"));
    try std.testing.expectEqualStrings("assert", pyConvertName(allocator, "assert_"));
    try std.testing.expectEqualStrings("constructor", pyConvertName(allocator, "__init__"));
    try std.testing.expectEqualStrings("ecAdd", pyConvertName(allocator, "ec_add"));
    try std.testing.expectEqualStrings("addOutput", pyConvertName(allocator, "add_output"));
}

test "python indent/dedent insertion" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source = "if x:\n    y = 1\n    z = 2\nw = 3\n";
    const raw = tokenizeRaw(allocator, source);
    const tokens = insertIndentation(allocator, raw);
    // Find INDENT and DEDENT tokens
    var found_indent = false;
    var found_dedent = false;
    for (tokens) |tok| {
        if (tok.kind == .indent) found_indent = true;
        if (tok.kind == .dedent) found_dedent = true;
    }
    try std.testing.expect(found_indent);
    try std.testing.expect(found_dedent);
}

test "python parse basic P2PKH" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig
        \\
        \\class P2PKH(SmartContract):
        \\    pub_key_hash: Addr
        \\
        \\    def __init__(self, pub_key_hash: Addr):
        \\        super().__init__(pub_key_hash)
        \\        self.pub_key_hash = pub_key_hash
        \\
        \\    @public
        \\    def unlock(self, sig: Sig, pub_key: PubKey):
        \\        assert_(hash160(pub_key) == self.pub_key_hash)
        \\        assert_(check_sig(sig, pub_key))
        \\
    ;
    const result = parsePython(allocator, source, "P2PKH.runar.py");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);
    const contract = result.contract.?;
    try std.testing.expectEqualStrings("P2PKH", contract.name);
    try std.testing.expectEqual(ParentClass.smart_contract, contract.parent_class);
    try std.testing.expectEqual(@as(usize, 1), contract.properties.len);
    try std.testing.expectEqualStrings("pubKeyHash", contract.properties[0].name);
    try std.testing.expect(contract.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 1), contract.methods.len);
    try std.testing.expectEqualStrings("unlock", contract.methods[0].name);
    try std.testing.expect(contract.methods[0].is_public);
    try std.testing.expectEqual(@as(usize, 2), contract.methods[0].params.len);
}

test "python parse stateful counter" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\from runar import StatefulSmartContract, Bigint, public, assert_
        \\
        \\class Counter(StatefulSmartContract):
        \\    count: Bigint
        \\
        \\    def __init__(self, count: Bigint):
        \\        super().__init__(count)
        \\        self.count = count
        \\
        \\    @public
        \\    def increment(self):
        \\        self.count += 1
        \\
        \\    @public
        \\    def decrement(self):
        \\        assert_(self.count > 0)
        \\        self.count -= 1
        \\
    ;
    const result = parsePython(allocator, source, "Counter.runar.py");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);
    const contract = result.contract.?;
    try std.testing.expectEqualStrings("Counter", contract.name);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, contract.parent_class);
    try std.testing.expectEqual(@as(usize, 1), contract.properties.len);
    try std.testing.expectEqualStrings("count", contract.properties[0].name);
    try std.testing.expect(!contract.properties[0].readonly);
    try std.testing.expectEqual(@as(usize, 2), contract.methods.len);
    try std.testing.expectEqualStrings("increment", contract.methods[0].name);
    try std.testing.expectEqualStrings("decrement", contract.methods[1].name);
}

test "python parse if/else with elif" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\from runar import SmartContract, Bigint, public, assert_
        \\
        \\class IfElse(SmartContract):
        \\    limit: Bigint
        \\
        \\    def __init__(self, limit: Bigint):
        \\        super().__init__(limit)
        \\        self.limit = limit
        \\
        \\    @public
        \\    def check(self, value: Bigint, mode: bool):
        \\        result: Bigint = 0
        \\        if mode:
        \\            result = value + self.limit
        \\        else:
        \\            result = value - self.limit
        \\        assert_(result > 0)
        \\
    ;
    const result = parsePython(allocator, source, "IfElse.runar.py");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);
    const contract = result.contract.?;
    try std.testing.expectEqualStrings("IfElse", contract.name);
    try std.testing.expectEqual(@as(usize, 1), contract.methods.len);
    // Method should have statements including if_stmt
    const body = contract.methods[0].body;
    try std.testing.expect(body.len >= 2);
}

test "python parse for loop" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\from runar import SmartContract, Bigint, public, assert_
        \\
        \\class BoundedLoop(SmartContract):
        \\    expected_sum: Bigint
        \\
        \\    def __init__(self, expected_sum: Bigint):
        \\        super().__init__(expected_sum)
        \\        self.expected_sum = expected_sum
        \\
        \\    @public
        \\    def verify(self, start: Bigint):
        \\        sum_: Bigint = 0
        \\        for i in range(5):
        \\            sum_ = sum_ + start + i
        \\        assert_(sum_ == self.expected_sum)
        \\
    ;
    const result = parsePython(allocator, source, "BoundedLoop.runar.py");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);
    const contract = result.contract.?;
    try std.testing.expectEqualStrings("BoundedLoop", contract.name);
    try std.testing.expectEqual(@as(usize, 1), contract.methods.len);
    const body = contract.methods[0].body;
    // Should have let_decl (sum_), for_stmt, expr_stmt (assert)
    try std.testing.expect(body.len >= 3);
    try std.testing.expectEqual(Statement.for_stmt, std.meta.activeTag(body[1]));
}

test "python parse property initializers" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\from runar import StatefulSmartContract, Bigint, Bool, Readonly, public, assert_
        \\
        \\class PropertyInitializers(StatefulSmartContract):
        \\    count: Bigint = 0
        \\    max_count: Readonly[Bigint]
        \\    active: Readonly[Bool] = True
        \\
        \\    def __init__(self, max_count: Bigint):
        \\        super().__init__(max_count)
        \\        self.max_count = max_count
        \\
        \\    @public
        \\    def increment(self, amount: Bigint):
        \\        assert_(self.active)
        \\        self.count = self.count + amount
        \\        assert_(self.count <= self.max_count)
        \\
    ;
    const result = parsePython(allocator, source, "PropertyInitializers.runar.py");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);
    const contract = result.contract.?;
    try std.testing.expectEqual(@as(usize, 3), contract.properties.len);
    // count: Bigint = 0 (mutable, has initializer)
    try std.testing.expectEqualStrings("count", contract.properties[0].name);
    try std.testing.expect(!contract.properties[0].readonly);
    try std.testing.expect(contract.properties[0].initializer != null);
    // max_count: Readonly[Bigint] (readonly, no initializer)
    try std.testing.expectEqualStrings("maxCount", contract.properties[1].name);
    try std.testing.expect(contract.properties[1].readonly);
    try std.testing.expect(contract.properties[1].initializer == null);
    // active: Readonly[Bool] = True (readonly, has initializer)
    try std.testing.expectEqualStrings("active", contract.properties[2].name);
    try std.testing.expect(contract.properties[2].readonly);
    try std.testing.expect(contract.properties[2].initializer != null);
}

test "python parse integer division" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source =
        \\from runar import SmartContract, Bigint, public, assert_
        \\
        \\class Arithmetic(SmartContract):
        \\    target: Bigint
        \\
        \\    def __init__(self, target: Bigint):
        \\        super().__init__(target)
        \\        self.target = target
        \\
        \\    @public
        \\    def verify(self, a: Bigint, b: Bigint):
        \\        quot: Bigint = a // b
        \\        assert_(quot == self.target)
        \\
    ;
    const result = parsePython(allocator, source, "Arithmetic.runar.py");
    try std.testing.expect(result.errors.len == 0);
    try std.testing.expect(result.contract != null);
    const contract = result.contract.?;
    const body = contract.methods[0].body;
    // First statement should be a let_decl with a binary_op (div)
    try std.testing.expect(body.len >= 2);
    switch (body[0]) {
        .let_decl => |decl| {
            try std.testing.expectEqualStrings("quot", decl.name);
            if (decl.value) |val| {
                switch (val) {
                    .binary_op => |bop| {
                        try std.testing.expectEqual(BinOperator.div, bop.op);
                    },
                    else => return error.TestUnexpectedResult,
                }
            }
        },
        else => return error.TestUnexpectedResult,
    }
}

test "python byte string to hex" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const result = pyByteStringToHex(allocator, "\\xde\\xad");
    try std.testing.expectEqualStrings("dead", result);
}
