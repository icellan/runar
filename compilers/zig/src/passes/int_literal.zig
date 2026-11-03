//! Oversize integer literals, in any radix (N-134).
//!
//! Every surface parser in this tier reads an integer literal with
//! `parseInt(i64, text, 0)` and needs a fallback when the value does not fit —
//! a 256-bit curve order is ordinary Rúnar, not an edge case. The fallback
//! each parser grew independently was "keep the text if it is all ASCII
//! digits", which quietly excluded `0xFFFF…41n`: the usual way to write
//! secp256k1's `n`, accepted by the other six tiers, and rejected here with
//! `invalid integer` — no script at all, on a file every other tier compiles.
//!
//! One helper, nine callers. `literal_bigint` carries CANONICAL DECIMAL text
//! through ANF, IR JSON and codegen, so a literal in any radix is converted
//! here and nothing downstream needs to know which radix the author used.

const std = @import("std");

/// Digits and radix of `text`, with any radix prefix removed.
/// Returns null when `text` is not an integer literal.
fn split(text: []const u8) ?struct { radix: u8, digits: []const u8 } {
    if (text.len == 0) return null;
    if (text.len > 2 and text[0] == '0') {
        const radix: ?u8 = switch (text[1]) {
            'x', 'X' => 16,
            'b', 'B' => 2,
            'o', 'O' => 8,
            else => null,
        };
        if (radix) |r| return .{ .radix = r, .digits = text[2..] };
    }
    return .{ .radix = 10, .digits = text };
}

fn isDigitOfRadix(c: u8, radix: u8) bool {
    const v: u8 = switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => return false,
    };
    return v < radix;
}

/// The canonical DECIMAL text of an integer literal that does not fit in an
/// i64, or null when `text` is not an integer literal in a radix this language
/// spells (10, 0x, 0b, 0o). The caller owns the returned slice.
///
/// `text` must already have had any `_` separators and type suffix removed —
/// every caller strips those while lexing.
pub fn oversizeToDecimal(allocator: std.mem.Allocator, text: []const u8) ?[]const u8 {
    const parts = split(text) orelse return null;
    if (parts.digits.len == 0) return null;
    for (parts.digits) |c| {
        if (!isDigitOfRadix(c, parts.radix)) return null;
    }

    // Decimal text is already canonical; skip the bignum round-trip so the
    // common path allocates one copy and nothing else.
    if (parts.radix == 10) return allocator.dupe(u8, parts.digits) catch null;

    var big = std.math.big.int.Managed.init(allocator) catch return null;
    defer big.deinit();
    big.setString(parts.radix, parts.digits) catch return null;
    return big.toString(allocator, 10, .lower) catch null;
}

test "decimal passes through unchanged" {
    const a = std.testing.allocator;
    const out = oversizeToDecimal(a, "115792089237316195423570985008687907852837564279074904382605163141518161494337").?;
    defer a.free(out);
    try std.testing.expectEqualStrings(
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
        out,
    );
}

test "hex becomes the same decimal" {
    const a = std.testing.allocator;
    const out = oversizeToDecimal(a, "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").?;
    defer a.free(out);
    try std.testing.expectEqualStrings(
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
        out,
    );
}

test "lower-case hex, binary and octal" {
    const a = std.testing.allocator;
    const h = oversizeToDecimal(a, "0xff").?;
    defer a.free(h);
    try std.testing.expectEqualStrings("255", h);

    const b = oversizeToDecimal(a, "0b1011").?;
    defer a.free(b);
    try std.testing.expectEqualStrings("11", b);

    const o = oversizeToDecimal(a, "0o17").?;
    defer a.free(o);
    try std.testing.expectEqualStrings("15", o);
}

test "non-literals are refused" {
    const a = std.testing.allocator;
    try std.testing.expect(oversizeToDecimal(a, "") == null);
    try std.testing.expect(oversizeToDecimal(a, "0x") == null);
    try std.testing.expect(oversizeToDecimal(a, "0xzz") == null);
    try std.testing.expect(oversizeToDecimal(a, "12a4") == null);
    try std.testing.expect(oversizeToDecimal(a, "0b12") == null);
}

// ---------------------------------------------------------------------------
// F-026 — integer literals mean what their host language says they mean.
//
// A port of the TS reference (packages/runar-compiler/src/passes/int-literal.ts,
// user decision R15). Every hand-written tokenizer scans a number token over
// every [0-9A-Za-z_] character glued to its first digit and validates the whole
// token against the surface's host-language grammar. The table every tier must
// reproduce is conformance/negatives/int-literal-cases.json.
//
// A lowercase `0x` on .runar.sol / .runar.move / .runar.rs is a Rúnar ByteString
// literal, handled by those tokenizers before a number is scanned; on every
// other surface `0x` is a hexadecimal integer.
// ---------------------------------------------------------------------------

/// A validated literal. `neg_only` marks a literal valid only as the operand of
/// a unary minus (Java `2147483648`, Rust `128i8`); the value is then the
/// positive magnitude. `small` is set when the value fits an i64, otherwise
/// `big` holds its canonical decimal text (the AST's `literal_bigint`).
pub const Lit = struct {
    small: ?i64 = null,
    big: ?[]const u8 = null,
    neg_only: bool = false,
};

fn language(surface: []const u8) []const u8 {
    const table = [_][2][]const u8{
        .{ "ts", "TypeScript" }, .{ "sol", "Solidity" }, .{ "move", "Move" }, .{ "go", "Go" },
        .{ "rs", "Rust" },       .{ "py", "Python" },    .{ "zig", "Zig" },   .{ "rb", "Ruby" },
        .{ "java", "Java" },
    };
    for (table) |e| if (std.mem.eql(u8, e[0], surface)) return e[1];
    return "unknown";
}

/// The TS reference's `invalidIntegerLiteral()`. The caller owns the result.
pub fn invalidIntegerLiteral(allocator: std.mem.Allocator, surface: []const u8, text: []const u8) []const u8 {
    return std.fmt.allocPrint(allocator, "invalid {s} integer literal '{s}'", .{ language(surface), text }) catch "invalid integer literal";
}

pub fn isNumberContinue(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// End (exclusive) of the number token whose first digit is at `pos`.
pub fn scanNumberEnd(source: []const u8, pos: usize) usize {
    var i = pos + 1;
    while (i < source.len and isNumberContinue(source[i])) i += 1;
    return i;
}

/// Where `_` may appear in a digit run.
const Sep = enum {
    /// `d(_?d)*`: single separators, strictly between digits.
    single,
    /// `(_?d)+`: as `single`, plus one separator before the first digit.
    lead_single,
    /// `d([d_]*d)?`: repeatable separators between digits (Java).
    java,
    /// `[d_]*d`: any separators, a digit last (Java octal after its `0`).
    last_digit,
    /// `[d_]*` with at least one digit (Rust).
    loose,
};

fn digitsOk(s: []const u8, radix: u8, sep: Sep) bool {
    if (s.len == 0) return false;
    var any = false;
    for (s) |c| {
        if (c == '_') continue;
        if (!isDigitOfRadix(c, radix)) return false;
        any = true;
    }
    if (!any) return false;
    const first = s[0] != '_';
    const last = s[s.len - 1] != '_';
    const no_double = std.mem.indexOf(u8, s, "__") == null;
    return switch (sep) {
        .single => first and last and no_double,
        .lead_single => last and no_double,
        .java => first and last,
        .last_digit => last,
        .loose => true,
    };
}

const Big = std.math.big.int.Managed;

/// The value of a validated digit run (separators removed).
fn bigOf(allocator: std.mem.Allocator, digits: []const u8, radix: u8) ?Big {
    var buf = allocator.alloc(u8, digits.len) catch return null;
    defer allocator.free(buf);
    var n: usize = 0;
    for (digits) |c| {
        if (c == '_') continue;
        buf[n] = c;
        n += 1;
    }
    var v = Big.init(allocator) catch return null;
    v.setString(radix, buf[0..n]) catch {
        v.deinit();
        return null;
    };
    return v;
}

fn pow2(allocator: std.mem.Allocator, bits: usize) ?Big {
    var one = Big.initSet(allocator, 1) catch return null;
    defer one.deinit();
    var r = Big.init(allocator) catch return null;
    r.shiftLeft(&one, bits) catch {
        r.deinit();
        return null;
    };
    return r;
}

/// `v` as a Lit (consumes `v`).
fn finish(allocator: std.mem.Allocator, v: *Big, neg_only: bool) ?Lit {
    defer v.deinit();
    if (v.toConst().toInt(i64)) |small| {
        return .{ .small = small, .neg_only = neg_only };
    } else |_| {}
    const s = v.toString(allocator, 10, .lower) catch return null;
    return .{ .big = s, .neg_only = neg_only };
}

/// `0 | [1-9](_?d)*`
fn plainDecimal(text: []const u8) bool {
    if (std.mem.eql(u8, text, "0")) return true;
    return text.len > 0 and text[0] >= '1' and text[0] <= '9' and digitsOk(text, 10, .single);
}

fn decimalLit(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    var v = bigOf(allocator, text, 10) orelse return null;
    return finish(allocator, &v, false);
}

/// `0<p>digits` where `p` is one of `prefixes`; the digit run obeys `sep`.
fn prefixed(allocator: std.mem.Allocator, text: []const u8, prefixes: []const u8, radix: u8, sep: Sep) ?Lit {
    if (text.len < 2 or text[0] != '0' or std.mem.indexOfScalar(u8, prefixes, text[1]) == null) return null;
    if (!digitsOk(text[2..], radix, sep)) return null;
    var v = bigOf(allocator, text[2..], radix) orelse return null;
    return finish(allocator, &v, false);
}

fn parseTs(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    const body = if (text.len > 0 and text[text.len - 1] == 'n') text[0 .. text.len - 1] else text;
    if (plainDecimal(body)) return decimalLit(allocator, body);
    return prefixed(allocator, body, "xX", 16, .single) orelse
        prefixed(allocator, body, "oO", 8, .single) orelse
        prefixed(allocator, body, "bB", 2, .single);
}

fn parseMove(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    const suffixes = [_]struct { s: []const u8, bits: usize }{
        .{ .s = "u256", .bits = 256 }, .{ .s = "u128", .bits = 128 }, .{ .s = "u64", .bits = 64 },
        .{ .s = "u32", .bits = 32 },   .{ .s = "u16", .bits = 16 },   .{ .s = "u8", .bits = 8 },
    };
    var body = text;
    var bits: usize = 256;
    for (suffixes) |sf| {
        if (std.mem.endsWith(u8, text, sf.s)) {
            body = text[0 .. text.len - sf.s.len];
            bits = sf.bits;
            break;
        }
    }
    if (body.len == 0 or body[0] < '0' or body[0] > '9') return null;
    for (body) |c| if (!(std.ascii.isDigit(c) or c == '_')) return null;
    var v = bigOf(allocator, body, 10) orelse return null;
    if (v.toConst().bitCountAbs() > bits) {
        v.deinit();
        return null;
    }
    return finish(allocator, &v, false);
}

fn parseGo(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    if (plainDecimal(text)) return decimalLit(allocator, text);
    if (text.len > 1 and text[0] == '0' and digitsOk(text[1..], 8, .lead_single)) {
        var v = bigOf(allocator, text[1..], 8) orelse return null;
        return finish(allocator, &v, false);
    }
    return prefixed(allocator, text, "xX", 16, .lead_single) orelse
        prefixed(allocator, text, "oO", 8, .lead_single) orelse
        prefixed(allocator, text, "bB", 2, .lead_single);
}

fn rustBody(allocator: std.mem.Allocator, body: []const u8) ?Big {
    var digits = body;
    var radix: u8 = 10;
    if (std.mem.startsWith(u8, body, "0x")) {
        digits = body[2..];
        radix = 16;
    } else if (std.mem.startsWith(u8, body, "0o")) {
        digits = body[2..];
        radix = 8;
    } else if (std.mem.startsWith(u8, body, "0b")) {
        digits = body[2..];
        radix = 2;
    } else if (body.len == 0 or !std.ascii.isDigit(body[0])) {
        return null;
    }
    if (!digitsOk(digits, radix, .loose)) return null;
    return bigOf(allocator, digits, radix);
}

fn parseRust(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    // Unsuffixed values are unbounded: rustc stops at u128::MAX, but Rúnar's
    // Int is a bigint and the corpus spells 256-bit constants this way.
    if (rustBody(allocator, text)) |v0| {
        var v = v0;
        return finish(allocator, &v, false);
    }
    const suffixes = [_]struct { s: []const u8, bits: usize, signed: bool }{
        .{ .s = "i128", .bits = 128, .signed = true }, .{ .s = "isize", .bits = 64, .signed = true },
        .{ .s = "i16", .bits = 16, .signed = true },   .{ .s = "i32", .bits = 32, .signed = true },
        .{ .s = "i64", .bits = 64, .signed = true },   .{ .s = "i8", .bits = 8, .signed = true },
        .{ .s = "u128", .bits = 128, .signed = false }, .{ .s = "usize", .bits = 64, .signed = false },
        .{ .s = "u16", .bits = 16, .signed = false },  .{ .s = "u32", .bits = 32, .signed = false },
        .{ .s = "u64", .bits = 64, .signed = false },  .{ .s = "u8", .bits = 8, .signed = false },
    };
    for (suffixes) |sf| {
        if (!std.mem.endsWith(u8, text, sf.s)) continue;
        var v = rustBody(allocator, text[0 .. text.len - sf.s.len]) orelse return null;
        const n = v.toConst().bitCountAbs();
        if (!sf.signed) {
            if (n > sf.bits) {
                v.deinit();
                return null;
            }
            return finish(allocator, &v, false);
        }
        if (n < sf.bits) return finish(allocator, &v, false);
        if (n == sf.bits) {
            var min = pow2(allocator, sf.bits - 1) orelse return null;
            defer min.deinit();
            if (v.order(min) == .eq) return finish(allocator, &v, true);
        }
        v.deinit();
        return null;
    }
    return null;
}

fn parsePy(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    var zeros = text.len > 0 and text[0] == '0';
    for (text) |c| if (c != '0' and c != '_') {
        zeros = false;
    };
    if ((zeros and digitsOk(text, 10, .single)) or (text.len > 0 and text[0] >= '1' and text[0] <= '9' and digitsOk(text, 10, .single)))
        return decimalLit(allocator, text);
    return prefixed(allocator, text, "xX", 16, .lead_single) orelse
        prefixed(allocator, text, "oO", 8, .lead_single) orelse
        prefixed(allocator, text, "bB", 2, .lead_single);
}

fn parseZigSurface(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    if (plainDecimal(text)) return decimalLit(allocator, text);
    return prefixed(allocator, text, "x", 16, .single) orelse
        prefixed(allocator, text, "o", 8, .single) orelse
        prefixed(allocator, text, "b", 2, .single);
}

fn parseRb(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    if (plainDecimal(text)) return decimalLit(allocator, text);
    if (text.len > 1 and text[0] == '0' and digitsOk(text[1..], 8, .lead_single)) {
        var v = bigOf(allocator, text[1..], 8) orelse return null;
        return finish(allocator, &v, false);
    }
    return prefixed(allocator, text, "dD", 10, .single) orelse
        prefixed(allocator, text, "xX", 16, .single) orelse
        prefixed(allocator, text, "oO", 8, .single) orelse
        prefixed(allocator, text, "bB", 2, .single);
}

fn parseJava(allocator: std.mem.Allocator, text: []const u8) ?Lit {
    const is_long = text.len > 0 and (text[text.len - 1] == 'L' or text[text.len - 1] == 'l');
    const body = if (is_long) text[0 .. text.len - 1] else text;
    const bits: usize = if (is_long) 64 else 32;
    if (std.mem.eql(u8, body, "0") or (body.len > 0 and body[0] >= '1' and body[0] <= '9' and digitsOk(body, 10, .java))) {
        var v = bigOf(allocator, body, 10) orelse return null;
        const n = v.toConst().bitCountAbs();
        if (n < bits) return finish(allocator, &v, false);
        if (n == bits) {
            var min = pow2(allocator, bits - 1) orelse return null;
            defer min.deinit();
            if (v.order(min) == .eq) return finish(allocator, &v, true);
        }
        v.deinit();
        return null;
    }
    var v: Big = blk: {
        if (body.len >= 2 and body[0] == '0' and (body[1] == 'x' or body[1] == 'X') and digitsOk(body[2..], 16, .java))
            break :blk bigOf(allocator, body[2..], 16) orelse return null;
        if (body.len >= 2 and body[0] == '0' and (body[1] == 'b' or body[1] == 'B') and digitsOk(body[2..], 2, .java))
            break :blk bigOf(allocator, body[2..], 2) orelse return null;
        if (body.len >= 2 and body[0] == '0' and digitsOk(body[1..], 8, .last_digit))
            break :blk bigOf(allocator, body[1..], 8) orelse return null;
        return null;
    };
    const n = v.toConst().bitCountAbs();
    if (n > bits) {
        v.deinit();
        return null;
    }
    if (n == bits) {
        // Two's complement: an int / long literal with its top bit set is negative.
        var m = pow2(allocator, bits) orelse return null;
        defer m.deinit();
        var r = Big.init(allocator) catch return null;
        r.sub(&v, &m) catch return null;
        v.deinit();
        return finish(allocator, &r, false);
    }
    return finish(allocator, &v, false);
}

/// The value of the integer literal `text` (the whole number token) on
/// `surface`, or null when the host language rejects it.
pub fn parse(allocator: std.mem.Allocator, surface: []const u8, text: []const u8) ?Lit {
    if (std.mem.eql(u8, surface, "ts")) return parseTs(allocator, text);
    if (std.mem.eql(u8, surface, "sol")) return if (plainDecimal(text)) decimalLit(allocator, text) else null;
    if (std.mem.eql(u8, surface, "move")) return parseMove(allocator, text);
    if (std.mem.eql(u8, surface, "go")) return parseGo(allocator, text);
    if (std.mem.eql(u8, surface, "rs")) return parseRust(allocator, text);
    if (std.mem.eql(u8, surface, "py")) return parsePy(allocator, text);
    if (std.mem.eql(u8, surface, "zig")) return parseZigSurface(allocator, text);
    if (std.mem.eql(u8, surface, "rb")) return parseRb(allocator, text);
    if (std.mem.eql(u8, surface, "java")) return parseJava(allocator, text);
    return null;
}

/// The Move number token's text without its integer-type suffix (`42u64` ->
/// `42`). The suffix still reaches validation through the token's `raw`.
pub fn stripMoveSuffix(text: []const u8) []const u8 {
    for ([_][]const u8{ "u256", "u128", "u64", "u32", "u16", "u8" }) |sf| {
        if (text.len > sf.len and std.mem.endsWith(u8, text, sf)) return text[0 .. text.len - sf.len];
    }
    return text;
}
