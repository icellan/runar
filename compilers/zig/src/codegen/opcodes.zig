//! Bitcoin Script opcode definitions, push data encoding, and hex utilities.
//! This is the canonical opcode table for the Runar compiler — all 96 opcodes
//! used in BSV Script with their correct hex values.

const std = @import("std");

// ============================================================================
// Opcode Enum — all 96 Bitcoin Script opcodes
// ============================================================================

pub const Opcode = enum(u8) {
    // Constants
    op_0 = 0x00, // OP_FALSE
    op_pushdata1 = 0x4c,
    op_pushdata2 = 0x4d,
    op_pushdata4 = 0x4e,
    op_1negate = 0x4f,
    op_1 = 0x51, // OP_TRUE
    op_2 = 0x52,
    op_3 = 0x53,
    op_4 = 0x54,
    op_5 = 0x55,
    op_6 = 0x56,
    op_7 = 0x57,
    op_8 = 0x58,
    op_9 = 0x59,
    op_10 = 0x5a,
    op_11 = 0x5b,
    op_12 = 0x5c,
    op_13 = 0x5d,
    op_14 = 0x5e,
    op_15 = 0x5f,
    op_16 = 0x60,

    // Flow control
    op_nop = 0x61,
    op_if = 0x63,
    op_notif = 0x64,
    op_else = 0x67,
    op_endif = 0x68,
    op_verify = 0x69,
    op_return = 0x6a,

    // Stack
    op_toaltstack = 0x6b,
    op_fromaltstack = 0x6c,
    op_2drop = 0x6d,
    op_2dup = 0x6e,
    op_3dup = 0x6f,
    op_2over = 0x70,
    op_2rot = 0x71,
    op_2swap = 0x72,
    op_ifdup = 0x73,
    op_depth = 0x74,
    op_drop = 0x75,
    op_dup = 0x76,
    op_nip = 0x77,
    op_over = 0x78,
    op_pick = 0x79,
    op_roll = 0x7a,
    op_rot = 0x7b,
    op_swap = 0x7c,
    op_tuck = 0x7d,

    // Splice
    op_cat = 0x7e,
    op_split = 0x7f,
    op_num2bin = 0x80,
    op_bin2num = 0x81,
    op_size = 0x82,

    // Bitwise
    op_invert = 0x83,
    op_and = 0x84,
    op_or = 0x85,
    op_xor = 0x86,

    // Comparison
    op_equal = 0x87,
    op_equalverify = 0x88,

    // Arithmetic
    op_1add = 0x8b,
    op_1sub = 0x8c,
    op_negate = 0x8f,
    op_abs = 0x90,
    op_not = 0x91,
    op_0notequal = 0x92,
    op_add = 0x93,
    op_sub = 0x94,
    op_mul = 0x95,
    op_div = 0x96,
    op_mod = 0x97,
    op_lshift = 0x98,
    op_rshift = 0x99,

    // Logic
    op_booland = 0x9a,
    op_boolor = 0x9b,

    // More comparison
    op_numequal = 0x9c,
    op_numequalverify = 0x9d,
    op_numnotequal = 0x9e,
    op_lessthan = 0x9f,
    op_greaterthan = 0xa0,
    op_lessthanorequal = 0xa1,
    op_greaterthanorequal = 0xa2,
    op_min = 0xa3,
    op_max = 0xa4,
    op_within = 0xa5,

    // Crypto
    op_ripemd160 = 0xa6,
    op_sha1 = 0xa7,
    op_sha256 = 0xa8,
    op_hash160 = 0xa9,
    op_hash256 = 0xaa,
    op_codeseparator = 0xab,
    op_checksig = 0xac,
    op_checksigverify = 0xad,
    op_checkmultisig = 0xae,
    op_checkmultisigverify = 0xaf,

    // Non-enum raw byte (for unknown opcodes in raw scripts)
    _,

    /// Convert to the single-byte encoding.
    pub fn toByte(self: Opcode) u8 {
        return @intFromEnum(self);
    }

    /// Convert from a raw byte.
    pub fn fromByte(b: u8) Opcode {
        return @enumFromInt(b);
    }
};

// ============================================================================
// Name Lookup — StaticStringMap for O(1) byName()
// ============================================================================

const name_map = std.StaticStringMap(Opcode).initComptime(.{
    // Constants
    .{ "OP_0", .op_0 },
    .{ "OP_FALSE", .op_0 },
    .{ "OP_PUSHDATA1", .op_pushdata1 },
    .{ "OP_PUSHDATA2", .op_pushdata2 },
    .{ "OP_PUSHDATA4", .op_pushdata4 },
    .{ "OP_1NEGATE", .op_1negate },
    .{ "OP_1", .op_1 },
    .{ "OP_TRUE", .op_1 },
    .{ "OP_2", .op_2 },
    .{ "OP_3", .op_3 },
    .{ "OP_4", .op_4 },
    .{ "OP_5", .op_5 },
    .{ "OP_6", .op_6 },
    .{ "OP_7", .op_7 },
    .{ "OP_8", .op_8 },
    .{ "OP_9", .op_9 },
    .{ "OP_10", .op_10 },
    .{ "OP_11", .op_11 },
    .{ "OP_12", .op_12 },
    .{ "OP_13", .op_13 },
    .{ "OP_14", .op_14 },
    .{ "OP_15", .op_15 },
    .{ "OP_16", .op_16 },
    // Flow control
    .{ "OP_NOP", .op_nop },
    .{ "OP_IF", .op_if },
    .{ "OP_NOTIF", .op_notif },
    .{ "OP_ELSE", .op_else },
    .{ "OP_ENDIF", .op_endif },
    .{ "OP_VERIFY", .op_verify },
    .{ "OP_RETURN", .op_return },
    // Stack
    .{ "OP_TOALTSTACK", .op_toaltstack },
    .{ "OP_FROMALTSTACK", .op_fromaltstack },
    .{ "OP_2DROP", .op_2drop },
    .{ "OP_2DUP", .op_2dup },
    .{ "OP_3DUP", .op_3dup },
    .{ "OP_2OVER", .op_2over },
    .{ "OP_2ROT", .op_2rot },
    .{ "OP_2SWAP", .op_2swap },
    .{ "OP_IFDUP", .op_ifdup },
    .{ "OP_DEPTH", .op_depth },
    .{ "OP_DROP", .op_drop },
    .{ "OP_DUP", .op_dup },
    .{ "OP_NIP", .op_nip },
    .{ "OP_OVER", .op_over },
    .{ "OP_PICK", .op_pick },
    .{ "OP_ROLL", .op_roll },
    .{ "OP_ROT", .op_rot },
    .{ "OP_SWAP", .op_swap },
    .{ "OP_TUCK", .op_tuck },
    // Splice
    .{ "OP_CAT", .op_cat },
    .{ "OP_SPLIT", .op_split },
    .{ "OP_NUM2BIN", .op_num2bin },
    .{ "OP_BIN2NUM", .op_bin2num },
    .{ "OP_SIZE", .op_size },
    // Bitwise
    .{ "OP_INVERT", .op_invert },
    .{ "OP_AND", .op_and },
    .{ "OP_OR", .op_or },
    .{ "OP_XOR", .op_xor },
    // Comparison
    .{ "OP_EQUAL", .op_equal },
    .{ "OP_EQUALVERIFY", .op_equalverify },
    // Arithmetic
    .{ "OP_1ADD", .op_1add },
    .{ "OP_1SUB", .op_1sub },
    .{ "OP_NEGATE", .op_negate },
    .{ "OP_ABS", .op_abs },
    .{ "OP_NOT", .op_not },
    .{ "OP_0NOTEQUAL", .op_0notequal },
    .{ "OP_ADD", .op_add },
    .{ "OP_SUB", .op_sub },
    .{ "OP_MUL", .op_mul },
    .{ "OP_DIV", .op_div },
    .{ "OP_MOD", .op_mod },
    .{ "OP_LSHIFT", .op_lshift },
    .{ "OP_RSHIFT", .op_rshift },
    // Logic
    .{ "OP_BOOLAND", .op_booland },
    .{ "OP_BOOLOR", .op_boolor },
    // More comparison
    .{ "OP_NUMEQUAL", .op_numequal },
    .{ "OP_NUMEQUALVERIFY", .op_numequalverify },
    .{ "OP_NUMNOTEQUAL", .op_numnotequal },
    .{ "OP_LESSTHAN", .op_lessthan },
    .{ "OP_GREATERTHAN", .op_greaterthan },
    .{ "OP_LESSTHANOREQUAL", .op_lessthanorequal },
    .{ "OP_GREATERTHANOREQUAL", .op_greaterthanorequal },
    .{ "OP_MIN", .op_min },
    .{ "OP_MAX", .op_max },
    .{ "OP_WITHIN", .op_within },
    // Crypto
    .{ "OP_RIPEMD160", .op_ripemd160 },
    .{ "OP_SHA1", .op_sha1 },
    .{ "OP_SHA256", .op_sha256 },
    .{ "OP_HASH160", .op_hash160 },
    .{ "OP_HASH256", .op_hash256 },
    .{ "OP_CODESEPARATOR", .op_codeseparator },
    .{ "OP_CHECKSIG", .op_checksig },
    .{ "OP_CHECKSIGVERIFY", .op_checksigverify },
    .{ "OP_CHECKMULTISIG", .op_checkmultisig },
    .{ "OP_CHECKMULTISIGVERIFY", .op_checkmultisigverify },
});

/// Look up an opcode by its standard name (e.g. "OP_DUP"). O(1) via StaticStringMap.
pub fn byName(name: []const u8) ?Opcode {
    return name_map.get(name);
}

// ============================================================================
// Reverse Lookup — opcode to canonical name
// ============================================================================

/// Return the canonical ASM name for an opcode (e.g. .op_dup -> "OP_DUP").
pub fn toName(opcode: Opcode) []const u8 {
    return switch (opcode) {
        .op_0 => "OP_0",
        .op_pushdata1 => "OP_PUSHDATA1",
        .op_pushdata2 => "OP_PUSHDATA2",
        .op_pushdata4 => "OP_PUSHDATA4",
        .op_1negate => "OP_1NEGATE",
        .op_1 => "OP_1",
        .op_2 => "OP_2",
        .op_3 => "OP_3",
        .op_4 => "OP_4",
        .op_5 => "OP_5",
        .op_6 => "OP_6",
        .op_7 => "OP_7",
        .op_8 => "OP_8",
        .op_9 => "OP_9",
        .op_10 => "OP_10",
        .op_11 => "OP_11",
        .op_12 => "OP_12",
        .op_13 => "OP_13",
        .op_14 => "OP_14",
        .op_15 => "OP_15",
        .op_16 => "OP_16",
        .op_nop => "OP_NOP",
        .op_if => "OP_IF",
        .op_notif => "OP_NOTIF",
        .op_else => "OP_ELSE",
        .op_endif => "OP_ENDIF",
        .op_verify => "OP_VERIFY",
        .op_return => "OP_RETURN",
        .op_toaltstack => "OP_TOALTSTACK",
        .op_fromaltstack => "OP_FROMALTSTACK",
        .op_2drop => "OP_2DROP",
        .op_2dup => "OP_2DUP",
        .op_3dup => "OP_3DUP",
        .op_2over => "OP_2OVER",
        .op_2rot => "OP_2ROT",
        .op_2swap => "OP_2SWAP",
        .op_ifdup => "OP_IFDUP",
        .op_depth => "OP_DEPTH",
        .op_drop => "OP_DROP",
        .op_dup => "OP_DUP",
        .op_nip => "OP_NIP",
        .op_over => "OP_OVER",
        .op_pick => "OP_PICK",
        .op_roll => "OP_ROLL",
        .op_rot => "OP_ROT",
        .op_swap => "OP_SWAP",
        .op_tuck => "OP_TUCK",
        .op_cat => "OP_CAT",
        .op_split => "OP_SPLIT",
        .op_num2bin => "OP_NUM2BIN",
        .op_bin2num => "OP_BIN2NUM",
        .op_size => "OP_SIZE",
        .op_invert => "OP_INVERT",
        .op_and => "OP_AND",
        .op_or => "OP_OR",
        .op_xor => "OP_XOR",
        .op_equal => "OP_EQUAL",
        .op_equalverify => "OP_EQUALVERIFY",
        .op_1add => "OP_1ADD",
        .op_1sub => "OP_1SUB",
        .op_negate => "OP_NEGATE",
        .op_abs => "OP_ABS",
        .op_not => "OP_NOT",
        .op_0notequal => "OP_0NOTEQUAL",
        .op_add => "OP_ADD",
        .op_sub => "OP_SUB",
        .op_mul => "OP_MUL",
        .op_div => "OP_DIV",
        .op_mod => "OP_MOD",
        .op_lshift => "OP_LSHIFT",
        .op_rshift => "OP_RSHIFT",
        .op_booland => "OP_BOOLAND",
        .op_boolor => "OP_BOOLOR",
        .op_numequal => "OP_NUMEQUAL",
        .op_numequalverify => "OP_NUMEQUALVERIFY",
        .op_numnotequal => "OP_NUMNOTEQUAL",
        .op_lessthan => "OP_LESSTHAN",
        .op_greaterthan => "OP_GREATERTHAN",
        .op_lessthanorequal => "OP_LESSTHANOREQUAL",
        .op_greaterthanorequal => "OP_GREATERTHANOREQUAL",
        .op_min => "OP_MIN",
        .op_max => "OP_MAX",
        .op_within => "OP_WITHIN",
        .op_ripemd160 => "OP_RIPEMD160",
        .op_sha1 => "OP_SHA1",
        .op_sha256 => "OP_SHA256",
        .op_hash160 => "OP_HASH160",
        .op_hash256 => "OP_HASH256",
        .op_codeseparator => "OP_CODESEPARATOR",
        .op_checksig => "OP_CHECKSIG",
        .op_checksigverify => "OP_CHECKSIGVERIFY",
        .op_checkmultisig => "OP_CHECKMULTISIG",
        .op_checkmultisigverify => "OP_CHECKMULTISIGVERIFY",
        _ => "OP_UNKNOWN",
    };
}

// ============================================================================
// Push Data Encoding
// ============================================================================

/// Encode a push data operation for the given bytes.
/// Empty data emits OP_0. Data <= 75 bytes uses direct push. Larger data
/// uses OP_PUSHDATA1/2/4 with appropriate length prefixes.
pub fn encodePushData(writer: anytype, data: []const u8) !void {
    if (data.len == 0) {
        try writer.writeByte(0x00);
    } else if (data.len <= 75) {
        try writer.writeByte(@intCast(data.len));
        try writer.writeAll(data);
    } else if (data.len <= 255) {
        try writer.writeByte(0x4c); // OP_PUSHDATA1
        try writer.writeByte(@intCast(data.len));
        try writer.writeAll(data);
    } else if (data.len <= 65535) {
        try writer.writeByte(0x4d); // OP_PUSHDATA2
        try writer.writeInt(u16, @intCast(data.len), .little);
        try writer.writeAll(data);
    } else {
        try writer.writeByte(0x4e); // OP_PUSHDATA4
        try writer.writeInt(u32, @intCast(data.len), .little);
        try writer.writeAll(data);
    }
}

// ============================================================================
// Script Number Encoding (LE sign-magnitude)
// ============================================================================

/// Encode a Bitcoin Script integer as minimal push data.
/// 0 -> OP_0, 1-16 -> OP_N, -1 -> OP_1NEGATE, else LE sign-magnitude bytes.
pub fn encodeScriptNumber(writer: anytype, n: i64) !void {
    if (n == 0) {
        try writer.writeByte(0x00); // OP_0
        return;
    }
    if (n >= 1 and n <= 16) {
        try writer.writeByte(@intCast(0x50 + @as(u8, @intCast(n)))); // OP_1..OP_16
        return;
    }
    if (n == -1) {
        try writer.writeByte(0x4f); // OP_1NEGATE
        return;
    }
    // Encode as LE sign-magnitude bytes
    var buf: [9]u8 = undefined;
    const len = encodeScriptInt(n, &buf);
    try encodePushData(writer, buf[0..len]);
}

/// Internal: encode an i64 as LE sign-magnitude bytes into buf, return length used.
fn encodeScriptInt(n: i64, buf: *[9]u8) usize {
    // Special case: i64 MIN cannot be negated without overflow.
    // |minInt(i64)| = 0x8000000000000000, LE sign-magnitude with sign byte = 9 bytes.
    if (n == std.math.minInt(i64)) {
        buf.* = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80 };
        return 9;
    }
    const neg = n < 0;
    var abs_val: u64 = if (neg) @intCast(-n) else @intCast(n);
    var i: usize = 0;
    while (abs_val > 0) : (i += 1) {
        buf[i] = @intCast(abs_val & 0xff);
        abs_val >>= 8;
    }
    if (i == 0) {
        buf[0] = 0;
        return 1;
    }
    // If MSB has the sign bit set, we need an extra byte for the sign
    if (buf[i - 1] & 0x80 != 0) {
        buf[i] = if (neg) 0x80 else 0x00;
        i += 1;
    } else if (neg) {
        buf[i - 1] |= 0x80;
    }
    return i;
}

// ============================================================================
// Hex Utilities
// ============================================================================

const hex_chars = "0123456789abcdef";

/// Convert a byte slice to a lowercase hex string. Caller owns returned memory.
pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

/// Convert a hex string to bytes. Caller owns returned memory.
/// Returns error.InvalidHexLength if odd length, error.InvalidHexCharacter on bad chars.
pub fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const result = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(result);
    for (0..result.len) |i| {
        const hi = hexDigit(hex[i * 2]) orelse return error.InvalidHexCharacter;
        const lo = hexDigit(hex[i * 2 + 1]) orelse return error.InvalidHexCharacter;
        result[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    return result;
}

fn hexDigit(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "opcode byte values" {
    try std.testing.expectEqual(@as(u8, 0x00), Opcode.op_0.toByte());
    try std.testing.expectEqual(@as(u8, 0x51), Opcode.op_1.toByte());
    try std.testing.expectEqual(@as(u8, 0x60), Opcode.op_16.toByte());
    try std.testing.expectEqual(@as(u8, 0x76), Opcode.op_dup.toByte());
    try std.testing.expectEqual(@as(u8, 0x75), Opcode.op_drop.toByte());
    try std.testing.expectEqual(@as(u8, 0x7c), Opcode.op_swap.toByte());
    try std.testing.expectEqual(@as(u8, 0x93), Opcode.op_add.toByte());
    try std.testing.expectEqual(@as(u8, 0xac), Opcode.op_checksig.toByte());
    try std.testing.expectEqual(@as(u8, 0xa9), Opcode.op_hash160.toByte());
    try std.testing.expectEqual(@as(u8, 0xaf), Opcode.op_checkmultisigverify.toByte());
    try std.testing.expectEqual(@as(u8, 0x83), Opcode.op_invert.toByte());
    try std.testing.expectEqual(@as(u8, 0x86), Opcode.op_xor.toByte());
    try std.testing.expectEqual(@as(u8, 0x98), Opcode.op_lshift.toByte());
    try std.testing.expectEqual(@as(u8, 0x99), Opcode.op_rshift.toByte());
    try std.testing.expectEqual(@as(u8, 0xa7), Opcode.op_sha1.toByte());
}

test "opcode from byte roundtrip" {
    inline for (@typeInfo(Opcode).@"enum".fields) |field| {
        const op: Opcode = @enumFromInt(field.value);
        try std.testing.expectEqual(op, Opcode.fromByte(field.value));
        try std.testing.expectEqual(@as(u8, field.value), op.toByte());
    }
}

test "byName lookup" {
    try std.testing.expectEqual(Opcode.op_dup, byName("OP_DUP").?);
    try std.testing.expectEqual(Opcode.op_checksig, byName("OP_CHECKSIG").?);
    try std.testing.expectEqual(Opcode.op_0, byName("OP_FALSE").?);
    try std.testing.expectEqual(Opcode.op_1, byName("OP_TRUE").?);
    try std.testing.expectEqual(Opcode.op_hash160, byName("OP_HASH160").?);
    try std.testing.expectEqual(Opcode.op_invert, byName("OP_INVERT").?);
    try std.testing.expectEqual(Opcode.op_booland, byName("OP_BOOLAND").?);
    try std.testing.expectEqual(Opcode.op_sha1, byName("OP_SHA1").?);
    try std.testing.expectEqual(Opcode.op_lshift, byName("OP_LSHIFT").?);
    try std.testing.expectEqual(Opcode.op_rshift, byName("OP_RSHIFT").?);
    try std.testing.expectEqual(Opcode.op_notif, byName("OP_NOTIF").?);
    try std.testing.expectEqual(@as(?Opcode, null), byName("OP_NONEXISTENT"));
}

test "toName reverse lookup" {
    try std.testing.expectEqualStrings("OP_DUP", toName(.op_dup));
    try std.testing.expectEqualStrings("OP_CHECKSIG", toName(.op_checksig));
    try std.testing.expectEqualStrings("OP_0", toName(.op_0));
    try std.testing.expectEqualStrings("OP_1", toName(.op_1));
    try std.testing.expectEqualStrings("OP_INVERT", toName(.op_invert));
    try std.testing.expectEqualStrings("OP_SHA1", toName(.op_sha1));
    try std.testing.expectEqualStrings("OP_LSHIFT", toName(.op_lshift));
    try std.testing.expectEqualStrings("OP_NOTIF", toName(.op_notif));
}

test "byName and toName roundtrip for all named opcodes" {
    // For every opcode that toName returns a real name, byName should recover it.
    inline for (@typeInfo(Opcode).@"enum".fields) |field| {
        const op: Opcode = @enumFromInt(field.value);
        const name = toName(op);
        if (!std.mem.eql(u8, name, "OP_UNKNOWN")) {
            const recovered = byName(name);
            try std.testing.expect(recovered != null);
            // Account for aliases (OP_FALSE -> op_0, OP_TRUE -> op_1): recovered byte must match
            try std.testing.expectEqual(@as(u8, field.value), recovered.?.toByte());
        }
    }
}

test "push data encoding — empty" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try encodePushData(buf.writer(std.testing.allocator), &.{});
    try std.testing.expectEqualSlices(u8, &.{0x00}, buf.items);
}

test "push data encoding — short (2 bytes)" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try encodePushData(buf.writer(std.testing.allocator), &.{ 0xab, 0xcd });
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0xab, 0xcd }, buf.items);
}

test "push data encoding — 75 bytes (max direct)" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    var data: [75]u8 = undefined;
    @memset(&data, 0xff);
    try encodePushData(buf.writer(std.testing.allocator), &data);
    try std.testing.expectEqual(@as(usize, 76), buf.items.len); // 1 len + 75 data
    try std.testing.expectEqual(@as(u8, 75), buf.items[0]);
}

test "push data encoding — 76 bytes (PUSHDATA1)" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    var data: [76]u8 = undefined;
    @memset(&data, 0xaa);
    try encodePushData(buf.writer(std.testing.allocator), &data);
    try std.testing.expectEqual(@as(usize, 78), buf.items.len); // 1 op + 1 len + 76 data
    try std.testing.expectEqual(@as(u8, 0x4c), buf.items[0]); // OP_PUSHDATA1
    try std.testing.expectEqual(@as(u8, 76), buf.items[1]);
}

test "push data encoding — 256 bytes (PUSHDATA2)" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    var data: [256]u8 = undefined;
    @memset(&data, 0xbb);
    try encodePushData(buf.writer(std.testing.allocator), &data);
    try std.testing.expectEqual(@as(usize, 259), buf.items.len); // 1 op + 2 len + 256 data
    try std.testing.expectEqual(@as(u8, 0x4d), buf.items[0]); // OP_PUSHDATA2
    try std.testing.expectEqual(@as(u8, 0x00), buf.items[1]); // 256 LE low
    try std.testing.expectEqual(@as(u8, 0x01), buf.items[2]); // 256 LE high
}

test "script number encoding — zero" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try encodeScriptNumber(buf.writer(std.testing.allocator), 0);
    try std.testing.expectEqualSlices(u8, &.{0x00}, buf.items);
}

test "script number encoding — small positives (1-16)" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try encodeScriptNumber(buf.writer(std.testing.allocator), 1);
    try std.testing.expectEqualSlices(u8, &.{0x51}, buf.items);

    buf.clearRetainingCapacity();
    try encodeScriptNumber(buf.writer(std.testing.allocator), 16);
    try std.testing.expectEqualSlices(u8, &.{0x60}, buf.items);

    buf.clearRetainingCapacity();
    try encodeScriptNumber(buf.writer(std.testing.allocator), 8);
    try std.testing.expectEqualSlices(u8, &.{0x58}, buf.items);
}

test "script number encoding — negative one" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try encodeScriptNumber(buf.writer(std.testing.allocator), -1);
    try std.testing.expectEqualSlices(u8, &.{0x4f}, buf.items);
}

test "script number encoding — 17 (beyond OP_16)" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    // 17 = 0x11, single byte, push as 01 11
    try encodeScriptNumber(buf.writer(std.testing.allocator), 17);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x11 }, buf.items);
}

test "script number encoding — 128 (needs sign byte)" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    // 128 = 0x80, MSB set so needs extra 0x00 byte: push 02 80 00
    try encodeScriptNumber(buf.writer(std.testing.allocator), 128);
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0x80, 0x00 }, buf.items);
}

test "script number encoding — -128 (negative, MSB conflict)" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    // -128: abs = 0x80, MSB set -> extra byte 0x80 for negative: push 02 80 80
    try encodeScriptNumber(buf.writer(std.testing.allocator), -128);
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0x80, 0x80 }, buf.items);
}

test "script number encoding — 255" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    // 255 = 0xff, MSB set -> needs extra byte: push 02 ff 00
    try encodeScriptNumber(buf.writer(std.testing.allocator), 255);
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0xff, 0x00 }, buf.items);
}

test "script number encoding — -5" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    // -5: abs = 0x05, MSB not set -> set sign bit: push 01 85
    try encodeScriptNumber(buf.writer(std.testing.allocator), -5);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x85 }, buf.items);
}

test "script number encoding — large positive 1000" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    // 1000 = 0x03E8 -> LE: E8 03, MSB of 03 not set -> push 02 e8 03
    try encodeScriptNumber(buf.writer(std.testing.allocator), 1000);
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0xe8, 0x03 }, buf.items);
}

test "script number encoding — i64 MIN does not panic" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    // minInt(i64) = -9223372036854775808
    // abs = 0x8000000000000000, LE sign-magnitude: 00 00 00 00 00 00 00 80 80 (9 bytes)
    // encodePushData wraps it as: 09 (length) + 9 data bytes
    try encodeScriptNumber(buf.writer(std.testing.allocator), std.math.minInt(i64));
    try std.testing.expectEqual(@as(usize, 10), buf.items.len); // 1 len + 9 data
    try std.testing.expectEqual(@as(u8, 9), buf.items[0]); // push 9 bytes
    // Last two bytes should be 0x80 0x80 (MSB of magnitude + sign byte)
    try std.testing.expectEqual(@as(u8, 0x80), buf.items[8]);
    try std.testing.expectEqual(@as(u8, 0x80), buf.items[9]);
}

test "bytesToHex" {
    const allocator = std.testing.allocator;
    const hex = try bytesToHex(allocator, &.{ 0x76, 0xa9, 0x14, 0xab, 0xcd });
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("76a914abcd", hex);
}

test "bytesToHex — empty" {
    const allocator = std.testing.allocator;
    const hex = try bytesToHex(allocator, &.{});
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("", hex);
}

test "hexToBytes" {
    const allocator = std.testing.allocator;
    const bytes = try hexToBytes(allocator, "76a914abcd");
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x76, 0xa9, 0x14, 0xab, 0xcd }, bytes);
}

test "hexToBytes — empty" {
    const allocator = std.testing.allocator;
    const bytes = try hexToBytes(allocator, "");
    defer allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), bytes.len);
}

test "hexToBytes — uppercase" {
    const allocator = std.testing.allocator;
    const bytes = try hexToBytes(allocator, "AABB");
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, bytes);
}

test "hexToBytes — odd length returns error" {
    const allocator = std.testing.allocator;
    const result = hexToBytes(allocator, "abc");
    try std.testing.expectError(error.InvalidHexLength, result);
}

test "hexToBytes — invalid char returns error" {
    const allocator = std.testing.allocator;
    const result = hexToBytes(allocator, "gg");
    try std.testing.expectError(error.InvalidHexCharacter, result);
}

test "hex roundtrip" {
    const allocator = std.testing.allocator;
    const original = [_]u8{ 0x00, 0x51, 0x76, 0xa9, 0xac, 0xff };
    const hex = try bytesToHex(allocator, &original);
    defer allocator.free(hex);
    const recovered = try hexToBytes(allocator, hex);
    defer allocator.free(recovered);
    try std.testing.expectEqualSlices(u8, &original, recovered);
}
