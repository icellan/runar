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
