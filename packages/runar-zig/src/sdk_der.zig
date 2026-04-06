const std = @import("std");
const bsvz = @import("bsvz");

// secp256k1 half-order for low-S normalization (BIP 62)
const secp256k1_half_order: [32]u8 = .{
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
    0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
};
const secp256k1_order: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

/// Strip leading zeros from an integer byte slice, returning the minimal
/// start index. Always keeps at least 1 byte. If the first remaining byte
/// has bit 7 set, a 0x00 padding byte is needed for DER sign-bit.
fn minimalIntStart(buf: []const u8) struct { start: usize, needs_pad: bool } {
    var start: usize = 0;
    while (start < buf.len - 1 and buf[start] == 0) start += 1;
    return .{ .start = start, .needs_pad = (buf[start] & 0x80) != 0 };
}

/// Canonicalize a DER-encoded ECDSA signature:
///   1. Strip unnecessary leading zeros from R and S (Bitcoin strict DER)
///   2. If S > half_order, replace S with (order - S) (BIP 62 low-S)
///
/// The Zig standard library's toDer() always writes 32 bytes for R and S
/// without stripping leading zeros, which Bitcoin nodes reject as non-canonical.
pub fn canonicalizeDer(der: bsvz.crypto.DerSignature) bsvz.crypto.DerSignature {
    const raw = der.asSlice();
    if (raw.len < 8) return der;
    if (raw[0] != 0x30 or raw[2] != 0x02) return der;

    // Parse R
    const orig_r_len: usize = raw[3];
    const r_start: usize = 4;
    if (r_start + orig_r_len + 2 > raw.len) return der;
    const r_bytes = raw[r_start .. r_start + orig_r_len];

    // Parse S
    const s_tag_pos = r_start + orig_r_len;
    if (raw[s_tag_pos] != 0x02) return der;
    const orig_s_len: usize = raw[s_tag_pos + 1];
    const s_start = s_tag_pos + 2;
    if (s_start + orig_s_len > raw.len) return der;
    const s_bytes = raw[s_start .. s_start + orig_s_len];

    // Canonicalize R: strip leading zeros, add pad if high bit set
    const r_min = minimalIntStart(r_bytes);
    const canon_r = r_bytes[r_min.start..];
    const canon_r_len: u8 = @intCast(canon_r.len + @as(usize, if (r_min.needs_pad) 1 else 0));

    // Canonicalize S: strip leading zeros, pad to 32 bytes for comparison
    var s_padded: [32]u8 = .{0} ** 32;
    const s_min_raw = minimalIntStart(s_bytes);
    const s_trimmed = s_bytes[s_min_raw.start..];
    if (s_trimmed.len <= 32) {
        @memcpy(s_padded[32 - s_trimmed.len ..], s_trimmed);
    } else {
        return der; // S too large
    }

    // Enforce low-S (BIP 62): if S > half_order, S = order - S
    var final_s: [32]u8 = s_padded;
    if (std.mem.order(u8, &s_padded, &secp256k1_half_order) == .gt) {
        var borrow: u16 = 0;
        var i: usize = 31;
        while (true) : (i -= 1) {
            const diff: i16 = @as(i16, secp256k1_order[i]) - @as(i16, s_padded[i]) - @as(i16, @intCast(borrow));
            if (diff < 0) {
                final_s[i] = @intCast(@as(i16, 256) + diff);
                borrow = 1;
            } else {
                final_s[i] = @intCast(diff);
                borrow = 0;
            }
            if (i == 0) break;
        }
    }

    // Strip leading zeros from final S
    const fs = minimalIntStart(&final_s);
    const canon_s_start = fs.start;
    const canon_s_needs_pad = fs.needs_pad;
    const canon_s_len: u8 = @intCast(32 - canon_s_start + @as(usize, if (canon_s_needs_pad) 1 else 0));

    // Build canonical DER
    var result: bsvz.crypto.DerSignature = .{ .bytes = .{0} ** 72, .len = 0 };
    var pos: usize = 0;

    result.bytes[pos] = 0x30;
    pos += 1;
    result.bytes[pos] = @intCast(2 + @as(usize, canon_r_len) + 2 + @as(usize, canon_s_len));
    pos += 1;

    // R integer
    result.bytes[pos] = 0x02;
    pos += 1;
    result.bytes[pos] = canon_r_len;
    pos += 1;
    if (r_min.needs_pad) {
        result.bytes[pos] = 0x00;
        pos += 1;
    }
    @memcpy(result.bytes[pos .. pos + canon_r.len], canon_r);
    pos += canon_r.len;

    // S integer
    result.bytes[pos] = 0x02;
    pos += 1;
    result.bytes[pos] = canon_s_len;
    pos += 1;
    if (canon_s_needs_pad) {
        result.bytes[pos] = 0x00;
        pos += 1;
    }
    @memcpy(result.bytes[pos .. pos + 32 - canon_s_start], final_s[canon_s_start..32]);
    pos += 32 - canon_s_start;

    result.len = @intCast(pos);
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "canonicalizeDer strips leading zeros from R" {
    // Construct DER with a leading-zero R: 30 <len> 02 20 00 01 ... 02 20 ...
    var buf: [72]u8 = .{0} ** 72;
    // 30 <len> 02 20 <R=32 bytes with leading 00> 02 20 <S=32 bytes>
    buf[0] = 0x30;
    buf[1] = 68; // 2+32+2+32
    buf[2] = 0x02;
    buf[3] = 32; // R len
    buf[4] = 0x00; // leading zero in R
    buf[5] = 0x42; // R[1]
    // Fill rest of R with 0x01
    for (6..36) |i| buf[i] = 0x01;
    buf[36] = 0x02;
    buf[37] = 32; // S len
    buf[38] = 0x01; // S[0] — low S, no leading zero needed
    for (39..70) |i| buf[i] = 0x01;

    const der = bsvz.crypto.DerSignature{ .bytes = buf, .len = 70 };
    const canonical = canonicalizeDer(der);
    const c = canonical.asSlice();

    // R should be stripped: 31 bytes (no leading 0x00, but 0x42 < 0x80 so no pad needed)
    try std.testing.expectEqual(@as(u8, 0x02), c[2]);
    try std.testing.expectEqual(@as(u8, 31), c[3]); // R is 31 bytes (stripped 1 leading zero)
    try std.testing.expectEqual(@as(u8, 0x42), c[4]); // First R byte is 0x42
}

test "canonicalizeDer enforces low-S" {
    // Build a signature where S = order - 1 (which is > half_order)
    var buf: [72]u8 = .{0} ** 72;
    buf[0] = 0x30;
    buf[1] = 68;
    buf[2] = 0x02;
    buf[3] = 32;
    // R = some value (just 0x01 repeated)
    for (4..36) |i| buf[i] = 0x01;
    buf[36] = 0x02;
    buf[37] = 32;
    // S = order - 1 = FF...FE BA AE DC E6 AF 48 A0 3B BF D2 5E 8C D0 36 41 40
    @memcpy(buf[38..70], &secp256k1_order);
    buf[69] -= 1; // order - 1

    const der = bsvz.crypto.DerSignature{ .bytes = buf, .len = 70 };
    const canonical = canonicalizeDer(der);

    // S should now be low (= 1, since order - (order-1) = 1)
    const c = canonical.asSlice();
    // Find S: skip R header
    const r_len = c[3];
    const s_pos: usize = 4 + r_len;
    try std.testing.expectEqual(@as(u8, 0x02), c[s_pos]);
    const s_len = c[s_pos + 1];
    try std.testing.expectEqual(@as(u8, 1), s_len); // S = 1, encoded as single byte
    try std.testing.expectEqual(@as(u8, 0x01), c[s_pos + 2]); // S value = 1
}
