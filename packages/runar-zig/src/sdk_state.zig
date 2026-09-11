const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");

// ---------------------------------------------------------------------------
// State serialization — encode/decode state values as Bitcoin Script push data
// ---------------------------------------------------------------------------

/// SerializeState encodes a set of state values into a hex-encoded Bitcoin
/// Script data section (without the OP_RETURN prefix). Field order is
/// determined by the index property of each StateField.
pub fn serializeState(
    allocator: std.mem.Allocator,
    fields: []const types.StateField,
    values: []const types.StateValue,
) ![]u8 {
    // Build sorted index by StateField.index
    const sorted = try allocator.alloc(usize, fields.len);
    defer allocator.free(sorted);
    for (0..fields.len) |i| sorted[i] = i;
    std.mem.sort(usize, sorted, fields, struct {
        fn lessThan(ctx: []const types.StateField, a: usize, b: usize) bool {
            return ctx[a].index < ctx[b].index;
        }
    }.lessThan);

    var hex_out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer hex_out.deinit(allocator);

    for (sorted) |field_idx| {
        if (field_idx >= values.len) continue;
        const encoded = try encodeStateValue(allocator, values[field_idx], fields[field_idx].type_name);
        defer allocator.free(encoded);
        try hex_out.appendSlice(allocator, encoded);
    }

    return hex_out.toOwnedSlice(allocator);
}

/// DeserializeState decodes state values from a hex-encoded Bitcoin Script
/// data section. Caller must strip the code prefix and OP_RETURN byte first.
pub fn deserializeState(
    allocator: std.mem.Allocator,
    fields: []const types.StateField,
    script_hex: []const u8,
) ![]types.StateValue {
    const sorted = try allocator.alloc(usize, fields.len);
    defer allocator.free(sorted);
    for (0..fields.len) |i| sorted[i] = i;
    std.mem.sort(usize, sorted, fields, struct {
        fn lessThan(ctx: []const types.StateField, a: usize, b: usize) bool {
            return ctx[a].index < ctx[b].index;
        }
    }.lessThan);

    var result = try allocator.alloc(types.StateValue, fields.len);
    errdefer {
        for (result) |*v| v.deinit(allocator);
        allocator.free(result);
    }
    for (result) |*v| v.* = .{ .int = 0 };

    var offset: usize = 0;
    for (sorted) |field_idx| {
        const decoded = try decodeStateValue(allocator, script_hex, offset, fields[field_idx].type_name);
        result[field_idx] = decoded.value;
        offset += decoded.hex_chars_read;
    }

    return result;
}

/// ExtractStateFromScript extracts state values from a full locking script
/// hex, given the artifact. Returns null if the artifact has no state fields.
pub fn extractStateFromScript(
    allocator: std.mem.Allocator,
    artifact: *const types.RunarArtifact,
    script_hex: []const u8,
) !?[]types.StateValue {
    if (artifact.state_fields.len == 0) return null;

    const op_return_pos = findLastOpReturn(script_hex);
    if (op_return_pos == null) return null;

    // State data starts after the OP_RETURN byte (2 hex chars)
    const state_hex = script_hex[op_return_pos.? + 2 ..];
    return try deserializeState(allocator, artifact.state_fields, state_hex);
}

/// FindLastOpReturn walks the script hex as Bitcoin Script opcodes to find the
/// last OP_RETURN (0x6a) at a real opcode boundary.
pub fn findLastOpReturn(script_hex: []const u8) ?usize {
    var offset: usize = 0;
    const length = script_hex.len;

    while (offset + 2 <= length) {
        const opcode = hexByteAt(script_hex, offset) orelse break;

        if (opcode == 0x6a) {
            // OP_RETURN at a real opcode boundary — everything after is state data
            return offset;
        } else if (opcode >= 0x01 and opcode <= 0x4b) {
            offset += 2 + @as(usize, opcode) * 2;
        } else if (opcode == 0x4c) {
            // OP_PUSHDATA1
            if (offset + 4 > length) break;
            const push_len = hexByteAt(script_hex, offset + 2) orelse break;
            offset += 4 + @as(usize, push_len) * 2;
        } else if (opcode == 0x4d) {
            // OP_PUSHDATA2
            if (offset + 6 > length) break;
            const lo = hexByteAt(script_hex, offset + 2) orelse break;
            const hi = hexByteAt(script_hex, offset + 4) orelse break;
            const push_len = @as(usize, lo) | (@as(usize, hi) << 8);
            offset += 6 + push_len * 2;
        } else if (opcode == 0x4e) {
            // OP_PUSHDATA4
            if (offset + 10 > length) break;
            const b0 = hexByteAt(script_hex, offset + 2) orelse break;
            const b1 = hexByteAt(script_hex, offset + 4) orelse break;
            const b2 = hexByteAt(script_hex, offset + 6) orelse break;
            const b3 = hexByteAt(script_hex, offset + 8) orelse break;
            const push_len = @as(usize, b0) | (@as(usize, b1) << 8) | (@as(usize, b2) << 16) | (@as(usize, b3) << 24);
            offset += 10 + push_len * 2;
        } else {
            offset += 2;
        }
    }

    return null;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Encode a state value as hex. The result is raw hex bytes (no push opcode for
/// fixed-width types) matching the compiler's OP_NUM2BIN-based serialization.
fn encodeStateValue(
    allocator: std.mem.Allocator,
    value: types.StateValue,
    field_type: []const u8,
) ![]u8 {
    if (std.mem.eql(u8, field_type, "int") or std.mem.eql(u8, field_type, "bigint")) {
        switch (value) {
            .big_int => |decimal_str| return encodeBigNum2Bin(allocator, decimal_str, 8),
            else => {},
        }
        const n: i64 = switch (value) {
            .int => |i| i,
            .boolean => |b| if (b) @as(i64, 1) else @as(i64, 0),
            // .empty_sig (#106) is a call-arg-only marker, never a state field;
            // grouped with .bytes for exhaustiveness.
            .bytes, .empty_sig => 0,
            .big_int => unreachable, // handled above
            .array_value => return error.ArrayValueInScalarField,
        };
        return encodeNum2Bin(allocator, n, 8);
    } else if (std.mem.eql(u8, field_type, "bool")) {
        const b: bool = switch (value) {
            .boolean => |bv| bv,
            .int => |i| i != 0,
            .bytes, .big_int, .empty_sig => false,
            .array_value => return error.ArrayValueInScalarField,
        };
        return allocator.dupe(u8, if (b) "01" else "00");
    } else if (std.mem.eql(u8, field_type, "PubKey") or
        std.mem.eql(u8, field_type, "Addr") or
        std.mem.eql(u8, field_type, "Ripemd160") or
        std.mem.eql(u8, field_type, "Sha256") or
        std.mem.eql(u8, field_type, "Point") or
        std.mem.eql(u8, field_type, "P256Point") or
        std.mem.eql(u8, field_type, "P384Point"))
    {
        // Fixed-size byte types: raw hex, no framing.
        // P256Point (64) and P384Point (96) belong here because runar-lang's
        // cast constructors hard-assert those widths and all seven compilers
        // emit them as fixed raw slices; framing them instead deploys a state
        // section 1-2 bytes long and the first spend fails.
        return switch (value) {
            .bytes => |b| allocator.dupe(u8, b),
            else => allocator.dupe(u8, ""),
        };
    } else {
        // Variable-length types: use push-data encoding
        const hex = switch (value) {
            .bytes => |b| b,
            else => @as([]const u8, ""),
        };
        if (hex.len == 0) {
            return allocator.dupe(u8, "00");
        }
        return encodePushDataState(allocator, hex);
    }
}

/// encodePushDataState frames a hex-encoded byte string as a state-section
/// field: <len><data>.
///
/// Deliberately NOT the MINIMALDATA push encoding used by encodePushData. The
/// state section is raw data after OP_RETURN in the locking script; the
/// interpreter never executes it, so SCRIPT_VERIFY_MINIMALDATA — a rule
/// applied to push opcodes as they are executed — does not reach it. What does
/// read it is the compiler's on-chain state codec (emitPushDataEncode in
/// packages/runar-compiler/src/passes/05-stack-lower.ts), which writes and
/// parses <len><data>. Both sides must agree byte for byte or the continuation
/// hash check fails and the contract is unspendable.
///
/// #110 applied the MINIMALDATA short-circuit here, in all seven SDKs and none
/// of the seven compilers, so a 1-byte 0x05 state field serialised off-chain
/// as "55" while the script rebuilt it as "0105". Byte-identical with the
/// other six SDKs.
pub fn encodePushDataState(allocator: std.mem.Allocator, data_hex: []const u8) ![]u8 {
    const data_len = data_hex.len / 2;

    if (data_len <= 75) {
        var result = try allocator.alloc(u8, 2 + data_hex.len);
        _ = std.fmt.bufPrint(result[0..2], "{x:0>2}", .{data_len}) catch unreachable;
        @memcpy(result[2..], data_hex);
        return result;
    } else if (data_len <= 0xff) {
        var result = try allocator.alloc(u8, 4 + data_hex.len);
        @memcpy(result[0..2], "4c");
        _ = std.fmt.bufPrint(result[2..4], "{x:0>2}", .{data_len}) catch unreachable;
        @memcpy(result[4..], data_hex);
        return result;
    } else if (data_len <= 0xffff) {
        var result = try allocator.alloc(u8, 6 + data_hex.len);
        @memcpy(result[0..2], "4d");
        const lo = data_len & 0xff;
        const hi = (data_len >> 8) & 0xff;
        _ = std.fmt.bufPrint(result[2..4], "{x:0>2}", .{lo}) catch unreachable;
        _ = std.fmt.bufPrint(result[4..6], "{x:0>2}", .{hi}) catch unreachable;
        @memcpy(result[6..], data_hex);
        return result;
    } else {
        var result = try allocator.alloc(u8, 10 + data_hex.len);
        @memcpy(result[0..2], "4e");
        const b0 = data_len & 0xff;
        const b1 = (data_len >> 8) & 0xff;
        const b2 = (data_len >> 16) & 0xff;
        const b3 = (data_len >> 24) & 0xff;
        _ = std.fmt.bufPrint(result[2..4], "{x:0>2}", .{b0}) catch unreachable;
        _ = std.fmt.bufPrint(result[4..6], "{x:0>2}", .{b1}) catch unreachable;
        _ = std.fmt.bufPrint(result[6..8], "{x:0>2}", .{b2}) catch unreachable;
        _ = std.fmt.bufPrint(result[8..10], "{x:0>2}", .{b3}) catch unreachable;
        @memcpy(result[10..], data_hex);
        return result;
    }
}

/// encodeNum2Bin encodes an integer as a fixed-width LE sign-magnitude byte
/// string, matching OP_NUM2BIN behaviour.
///
/// FAILS CLOSED on an out-of-range magnitude with error.StateValueOutOfRange.
/// `width` bytes of sign-magnitude hold 8*width - 1 magnitude bits — the top
/// bit of the last byte is the sign — so -2^63 is a perfectly good i64 whose
/// MAGNITUDE (2^63) does not fit an 8-byte word. It used to serialise as
/// 0000000000000080, which reads back as 0 (negative zero), and the deploy then
/// succeeded with an unspendable UTXO: the covenant rebuilds the continuation
/// with the compiler's own OP_NUM2BIN `width`, which cannot produce those bytes
/// from that number, so hash256(outputs) never matches.
///
/// The magnitude is also computed WITHOUT negating `n`: `-n` is an illegal
/// negation for i64 minInt and panicked with "integer overflow" instead of
/// reporting an error. ±(2^(8*width-1) - 1) is unaffected.
pub fn encodeNum2Bin(allocator: std.mem.Allocator, n: i64, width: usize) ![]u8 {
    const negative = n < 0;
    // -(n + 1) + 1 keeps minInt in range; plain -n overflows.
    const magnitude: u64 = if (negative)
        @as(u64, @intCast(-(n + 1))) + 1
    else
        @intCast(n);

    const magnitude_bits = 8 * width - 1;
    if (magnitude_bits < 64) {
        const limit = @as(u64, 1) << @intCast(magnitude_bits);
        if (magnitude >= limit) return error.StateValueOutOfRange;
    }

    var buf = try allocator.alloc(u8, width);
    defer allocator.free(buf);
    @memset(buf, 0);

    var abs_val: u64 = magnitude;

    var i: usize = 0;
    while (i < width and abs_val > 0) : (i += 1) {
        buf[i] = @truncate(abs_val & 0xff);
        abs_val >>= 8;
    }
    if (negative) {
        buf[width - 1] |= 0x80;
    }

    return bytesToHex(allocator, buf);
}

/// encodeBigNum2Bin encodes an arbitrary-precision integer (given as a decimal
/// string) as a fixed-width LE sign-magnitude byte string, matching OP_NUM2BIN
/// behaviour. Used for state field serialization of values exceeding i64.
///
/// FAILS CLOSED on an out-of-range magnitude with error.StateValueOutOfRange.
/// The division loop below stops at `width` bytes and drops every higher digit,
/// then ORs the sign bit in on top of whatever landed there, so an oversized
/// value used to serialise to a plausible but WRONG word:
///
///     2^63      -> 0000000000000080   reads back as 0   (negative zero)
///     2^63 + 5  -> 0500000000000080   reads back as -5  (sign flip)
///     2^64      -> 0000000000000000   reads back as 0
///
/// The deploy then succeeded and the UTXO was unspendable: the covenant
/// rebuilds the continuation with the compiler's own OP_NUM2BIN `width`, which
/// cannot produce those bytes from that number, so hash256(outputs) never
/// matches. ±(2^(8*width-1) - 1) stays representable and is unaffected.
pub fn encodeBigNum2Bin(allocator: std.mem.Allocator, decimal_str: []const u8, width: usize) ![]u8 {
    // Check for negative sign
    const negative = decimal_str.len > 0 and decimal_str[0] == '-';
    const digits = if (negative) decimal_str[1..] else decimal_str;

    var buf = try allocator.alloc(u8, width);
    defer allocator.free(buf);
    @memset(buf, 0);

    // Convert decimal digits to LE bytes via repeated division by 256
    var work = try allocator.alloc(u8, digits.len);
    defer allocator.free(work);
    for (digits, 0..) |c, ci| {
        work[ci] = c - '0';
    }
    var work_len = digits.len;

    var byte_idx: usize = 0;
    while (work_len > 0 and byte_idx < width) {
        var remainder: u16 = 0;
        var new_len: usize = 0;
        for (0..work_len) |i| {
            const val = remainder * 10 + @as(u16, work[i]);
            const quotient_digit: u8 = @intCast(val / 256);
            remainder = val % 256;
            if (quotient_digit != 0 or new_len > 0) {
                work[new_len] = quotient_digit;
                new_len += 1;
            }
        }
        buf[byte_idx] = @intCast(remainder);
        byte_idx += 1;
        work_len = new_len;
    }

    // Digits left over means the magnitude needed more than `width` bytes; the
    // sign bit already set means it needed the 8*width-th bit, which the sign
    // occupies. Either way the word cannot hold it.
    if (work_len > 0 or (buf[width - 1] & 0x80) != 0) {
        return error.StateValueOutOfRange;
    }

    if (negative) {
        buf[width - 1] |= 0x80;
    }

    return bytesToHex(allocator, buf);
}

/// EncodePushData wraps a hex-encoded byte string in a Bitcoin Script push
/// data opcode.
///
/// Applies BSV consensus rule SCRIPT_VERIFY_MINIMALDATA for single-byte
/// pushes: a 1-byte payload whose value is in {0x01..=0x10, 0x81} MUST use the
/// corresponding minimal opcode (OP_1..OP_16 / OP_1NEGATE) rather than the
/// direct push "01 NN". Non-minimal direct pushes are relay-rejected as
/// "Data push larger than necessary".
///
/// NOTE: 0x00 is deliberately NOT in that set. OP_0 pushes the EMPTY byte
/// array, not a 1-byte 0x00 — so the minimal encoding of a 1-byte 0x00 payload
/// is the direct push "01 00" (matching the compiler's encodePushBytesHex in
/// push-encoding.ts), not OP_0 (C9 / S1).
pub fn encodePushData(allocator: std.mem.Allocator, data_hex: []const u8) ![]u8 {
    const data_len = data_hex.len / 2;

    // MINIMALDATA: single-byte payloads in the OP_N range must use the
    // corresponding minimal opcode. encodeScriptNumber already short-circuits
    // OP_N for Int fields; this brings the ByteString push path to the same
    // standard so a 1-byte ByteString value does not emit a relay-rejected
    // non-minimal direct push.
    if (data_len == 1) {
        const maybe_byte: ?u8 = std.fmt.parseInt(u8, data_hex, 16) catch null;
        if (maybe_byte) |b| {
            if (b >= 0x01 and b <= 0x10) {
                var buf: [2]u8 = undefined;
                _ = std.fmt.bufPrint(&buf, "{x:0>2}", .{@as(u8, @intCast(0x50 + @as(u16, b)))}) catch unreachable;
                return allocator.dupe(u8, &buf);
            }
            if (b == 0x81) return allocator.dupe(u8, "4f"); // OP_1NEGATE
        }
    }

    if (data_len <= 75) {
        var result = try allocator.alloc(u8, 2 + data_hex.len);
        _ = std.fmt.bufPrint(result[0..2], "{x:0>2}", .{data_len}) catch unreachable;
        @memcpy(result[2..], data_hex);
        return result;
    } else if (data_len <= 0xff) {
        var result = try allocator.alloc(u8, 4 + data_hex.len);
        @memcpy(result[0..2], "4c");
        _ = std.fmt.bufPrint(result[2..4], "{x:0>2}", .{data_len}) catch unreachable;
        @memcpy(result[4..], data_hex);
        return result;
    } else if (data_len <= 0xffff) {
        var result = try allocator.alloc(u8, 6 + data_hex.len);
        @memcpy(result[0..2], "4d");
        const lo = data_len & 0xff;
        const hi = (data_len >> 8) & 0xff;
        _ = std.fmt.bufPrint(result[2..4], "{x:0>2}", .{lo}) catch unreachable;
        _ = std.fmt.bufPrint(result[4..6], "{x:0>2}", .{hi}) catch unreachable;
        @memcpy(result[6..], data_hex);
        return result;
    } else {
        var result = try allocator.alloc(u8, 10 + data_hex.len);
        @memcpy(result[0..2], "4e");
        const b0 = data_len & 0xff;
        const b1 = (data_len >> 8) & 0xff;
        const b2 = (data_len >> 16) & 0xff;
        const b3 = (data_len >> 24) & 0xff;
        _ = std.fmt.bufPrint(result[2..4], "{x:0>2}", .{b0}) catch unreachable;
        _ = std.fmt.bufPrint(result[4..6], "{x:0>2}", .{b1}) catch unreachable;
        _ = std.fmt.bufPrint(result[6..8], "{x:0>2}", .{b2}) catch unreachable;
        _ = std.fmt.bufPrint(result[8..10], "{x:0>2}", .{b3}) catch unreachable;
        @memcpy(result[10..], data_hex);
        return result;
    }
}

/// EncodeScriptInt encodes an integer as a Bitcoin Script minimal-encoded
/// number push for state serialization.
pub fn encodeScriptInt(allocator: std.mem.Allocator, n: i64) ![]u8 {
    if (n == 0) {
        return allocator.dupe(u8, "00");
    }

    const negative = n < 0;
    var abs_val: u64 = if (negative) @intCast(-n) else @intCast(n);

    var byte_buf: [9]u8 = undefined;
    var byte_count: usize = 0;
    while (abs_val > 0) {
        byte_buf[byte_count] = @truncate(abs_val & 0xff);
        abs_val >>= 8;
        byte_count += 1;
    }

    if (byte_buf[byte_count - 1] & 0x80 != 0) {
        if (negative) {
            byte_buf[byte_count] = 0x80;
        } else {
            byte_buf[byte_count] = 0x00;
        }
        byte_count += 1;
    } else if (negative) {
        byte_buf[byte_count - 1] |= 0x80;
    }

    const hex = try bytesToHex(allocator, byte_buf[0..byte_count]);
    defer allocator.free(hex);
    return encodePushData(allocator, hex);
}

// ---------------------------------------------------------------------------
// Decoding helpers
// ---------------------------------------------------------------------------

const DecodedValue = struct {
    value: types.StateValue,
    hex_chars_read: usize,
};

fn decodeStateValue(
    allocator: std.mem.Allocator,
    hex: []const u8,
    offset: usize,
    field_type: []const u8,
) !DecodedValue {
    if (std.mem.eql(u8, field_type, "bool")) {
        if (offset + 2 > hex.len) {
            return .{ .value = .{ .boolean = false }, .hex_chars_read = 2 };
        }
        const is_true = !std.mem.eql(u8, hex[offset .. offset + 2], "00");
        return .{ .value = .{ .boolean = is_true }, .hex_chars_read = 2 };
    } else if (std.mem.eql(u8, field_type, "int") or std.mem.eql(u8, field_type, "bigint")) {
        const byte_width: usize = 8;
        const hex_width = byte_width * 2;
        if (offset + hex_width > hex.len) {
            return .{ .value = .{ .int = 0 }, .hex_chars_read = hex_width };
        }
        return .{ .value = .{ .int = decodeNum2Bin(hex[offset .. offset + hex_width]) }, .hex_chars_read = hex_width };
    } else if (std.mem.eql(u8, field_type, "PubKey")) {
        const w: usize = 66;
        if (offset + w > hex.len) return .{ .value = .{ .bytes = try allocator.dupe(u8, "") }, .hex_chars_read = w };
        return .{ .value = .{ .bytes = try allocator.dupe(u8, hex[offset .. offset + w]) }, .hex_chars_read = w };
    } else if (std.mem.eql(u8, field_type, "Addr") or std.mem.eql(u8, field_type, "Ripemd160")) {
        const w: usize = 40;
        if (offset + w > hex.len) return .{ .value = .{ .bytes = try allocator.dupe(u8, "") }, .hex_chars_read = w };
        return .{ .value = .{ .bytes = try allocator.dupe(u8, hex[offset .. offset + w]) }, .hex_chars_read = w };
    } else if (std.mem.eql(u8, field_type, "Sha256")) {
        const w: usize = 64;
        if (offset + w > hex.len) return .{ .value = .{ .bytes = try allocator.dupe(u8, "") }, .hex_chars_read = w };
        return .{ .value = .{ .bytes = try allocator.dupe(u8, hex[offset .. offset + w]) }, .hex_chars_read = w };
    } else if (std.mem.eql(u8, field_type, "Point") or std.mem.eql(u8, field_type, "P256Point")) {
        const w: usize = 128;
        if (offset + w > hex.len) return .{ .value = .{ .bytes = try allocator.dupe(u8, "") }, .hex_chars_read = w };
        return .{ .value = .{ .bytes = try allocator.dupe(u8, hex[offset .. offset + w]) }, .hex_chars_read = w };
    } else if (std.mem.eql(u8, field_type, "P384Point")) {
        const w: usize = 192;
        if (offset + w > hex.len) return .{ .value = .{ .bytes = try allocator.dupe(u8, "") }, .hex_chars_read = w };
        return .{ .value = .{ .bytes = try allocator.dupe(u8, hex[offset .. offset + w]) }, .hex_chars_read = w };
    } else {
        // Push-data decode
        const result = decodePushData(hex, offset);
        return .{
            .value = .{ .bytes = try allocator.dupe(u8, result.data) },
            .hex_chars_read = result.bytes_consumed,
        };
    }
}

/// decodeNum2Bin decodes a fixed-width LE sign-magnitude number.
pub fn decodeNum2Bin(hex: []const u8) i64 {
    if (hex.len == 0) return 0;
    const byte_len = hex.len / 2;
    var buf: [8]u8 = [_]u8{0} ** 8;
    for (0..byte_len) |i| {
        buf[i] = hexByteAt(hex, i * 2) orelse 0;
    }
    const negative = (buf[byte_len - 1] & 0x80) != 0;
    buf[byte_len - 1] &= 0x7f;

    var result: i64 = 0;
    var i: usize = byte_len;
    while (i > 0) {
        i -= 1;
        result = (result << 8) | @as(i64, buf[i]);
    }

    if (negative) return -result;
    return result;
}

/// DecodePushData decodes a Bitcoin Script push data at the given hex offset.
const PushDataResult = struct {
    data: []const u8,
    bytes_consumed: usize,
};

/// Exact inverse of `encodePushDataState`, and deliberately as strict as the
/// compiler's on-chain state reader: only <len><data> framing is understood.
/// OP_1..OP_16 (0x51..0x60) and OP_1NEGATE (0x4f) are NOT decoded as
/// single-byte values — accepting them would let the SDK read a state section
/// the contract's own script cannot parse. OP_0 (0x00) falls through to the
/// `opcode <= 75` branch and correctly decodes as the empty byte array.
pub fn decodePushData(hex: []const u8, offset: usize) PushDataResult {
    if (offset >= hex.len) {
        return .{ .data = "", .bytes_consumed = 0 };
    }

    const opcode = hexByteAt(hex, offset) orelse return .{ .data = "", .bytes_consumed = 2 };

    if (opcode <= 75) {
        const data_len = @as(usize, opcode) * 2;
        const start = offset + 2;
        if (start + data_len > hex.len) return .{ .data = "", .bytes_consumed = 2 };
        return .{ .data = hex[start .. start + data_len], .bytes_consumed = 2 + data_len };
    } else if (opcode == 0x4c) {
        // OP_PUSHDATA1
        const length = hexByteAt(hex, offset + 2) orelse return .{ .data = "", .bytes_consumed = 4 };
        const data_len = @as(usize, length) * 2;
        const start = offset + 4;
        if (start + data_len > hex.len) return .{ .data = "", .bytes_consumed = 4 };
        return .{ .data = hex[start .. start + data_len], .bytes_consumed = 4 + data_len };
    } else if (opcode == 0x4d) {
        // OP_PUSHDATA2
        const lo = hexByteAt(hex, offset + 2) orelse return .{ .data = "", .bytes_consumed = 6 };
        const hi = hexByteAt(hex, offset + 4) orelse return .{ .data = "", .bytes_consumed = 6 };
        const length = @as(usize, lo) | (@as(usize, hi) << 8);
        const data_len = length * 2;
        const start = offset + 6;
        if (start + data_len > hex.len) return .{ .data = "", .bytes_consumed = 6 };
        return .{ .data = hex[start .. start + data_len], .bytes_consumed = 6 + data_len };
    } else if (opcode == 0x4e) {
        // OP_PUSHDATA4
        const b0 = hexByteAt(hex, offset + 2) orelse return .{ .data = "", .bytes_consumed = 10 };
        const b1 = hexByteAt(hex, offset + 4) orelse return .{ .data = "", .bytes_consumed = 10 };
        const b2 = hexByteAt(hex, offset + 6) orelse return .{ .data = "", .bytes_consumed = 10 };
        const b3 = hexByteAt(hex, offset + 8) orelse return .{ .data = "", .bytes_consumed = 10 };
        const length = @as(usize, b0) | (@as(usize, b1) << 8) | (@as(usize, b2) << 16) | (@as(usize, b3) << 24);
        const data_len = length * 2;
        const start = offset + 10;
        if (start + data_len > hex.len) return .{ .data = "", .bytes_consumed = 10 };
        return .{ .data = hex[start .. start + data_len], .bytes_consumed = 10 + data_len };
    }

    return .{ .data = "", .bytes_consumed = 2 };
}

// ---------------------------------------------------------------------------
// Argument encoding for unlocking scripts
// ---------------------------------------------------------------------------

/// Encode a method argument as a Bitcoin Script push data element (hex).
pub fn encodeArg(allocator: std.mem.Allocator, value: types.StateValue) ![]u8 {
    return switch (value) {
        .int => |n| encodeScriptNumber(allocator, n),
        .big_int => |decimal_str| encodeBigScriptNumber(allocator, decimal_str),
        .boolean => |b| allocator.dupe(u8, if (b) "51" else "00"),
        .bytes => |hex| encodePushData(allocator, hex),
        // Issue #106: OP_0 — the empty-signature push for the deliberately-
        // failing branch of an OR-CHECKSIG method. See types.EMPTY_SIG.
        .empty_sig => allocator.dupe(u8, "00"),
        // Arrays are not valid standalone arguments — callers must flatten
        // them via flattenStateValues before passing them in.
        .array_value => error.ArrayValueInScalarField,
    };
}

// ---------------------------------------------------------------------------
// FixedArray flatten / regroup for state values
// ---------------------------------------------------------------------------

/// Recursively flatten a StateValue into the scalar leaves it represents. Used
/// to write a nested FixedArray value into N scalar state slots. Scalar values
/// are passed through unchanged; `.array_value` entries are walked depth-first.
pub fn flattenStateValue(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(types.StateValue),
    value: types.StateValue,
) !void {
    switch (value) {
        .array_value => |items| {
            for (items) |it| try flattenStateValue(allocator, out, it);
        },
        else => try out.append(allocator, try value.clone(allocator)),
    }
}

/// Regroup a flat list of scalar StateValues into a nested StateValue tree
/// matching the shape described by `shape` — a list of per-level fan-out
/// factors outermost-first. For a `FixedArray<FixedArray<bigint, 2>, 3>`
/// the shape is `&.{ 3, 2 }` and the input list has length 6.
///
/// Returns a newly-allocated `array_value` (or the single scalar when
/// `shape` is empty). The caller owns the returned value and must call
/// `deinit` on it.
pub fn regroupStateValues(
    allocator: std.mem.Allocator,
    flat: []const types.StateValue,
    shape: []const u32,
) !types.StateValue {
    if (shape.len == 0) {
        if (flat.len != 1) return error.ShapeMismatch;
        return try flat[0].clone(allocator);
    }

    const outer = shape[0];
    var total: usize = 1;
    for (shape) |d| total *= d;
    if (flat.len != total) return error.ShapeMismatch;

    var items = try allocator.alloc(types.StateValue, outer);
    errdefer {
        for (items) |it| it.deinit(allocator);
        allocator.free(items);
    }
    const sub_total = total / outer;
    var i: usize = 0;
    while (i < outer) : (i += 1) {
        const start = i * sub_total;
        const slice = flat[start .. start + sub_total];
        items[i] = try regroupStateValues(allocator, slice, shape[1..]);
    }
    return .{ .array_value = items };
}

/// encodeScriptNumber encodes an integer as a Bitcoin Script opcode or push data.
/// Uses OP_0, OP_1..16, OP_1NEGATE for small values.
pub fn encodeScriptNumber(allocator: std.mem.Allocator, n: i64) ![]u8 {
    if (n == 0) return allocator.dupe(u8, "00");
    if (n >= 1 and n <= 16) {
        var buf: [2]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{x:0>2}", .{@as(u8, @intCast(0x50 + @as(u64, @intCast(n))))}) catch unreachable;
        return allocator.dupe(u8, &buf);
    }
    if (n == -1) return allocator.dupe(u8, "4f");

    const negative = n < 0;
    var abs_val: u64 = if (negative) @intCast(-n) else @intCast(n);

    var byte_buf: [9]u8 = undefined;
    var byte_count: usize = 0;
    while (abs_val > 0) {
        byte_buf[byte_count] = @truncate(abs_val & 0xff);
        abs_val >>= 8;
        byte_count += 1;
    }

    if (byte_buf[byte_count - 1] & 0x80 != 0) {
        if (negative) {
            byte_buf[byte_count] = 0x80;
        } else {
            byte_buf[byte_count] = 0x00;
        }
        byte_count += 1;
    } else if (negative) {
        byte_buf[byte_count - 1] |= 0x80;
    }

    const hex = try bytesToHex(allocator, byte_buf[0..byte_count]);
    defer allocator.free(hex);
    return encodePushData(allocator, hex);
}

/// encodeBigScriptNumber encodes an arbitrary-precision integer (given as a
/// decimal string) into Bitcoin Script push data using LE sign-magnitude
/// encoding. Falls back to encodeScriptNumber for values that fit in i64.
pub fn encodeBigScriptNumber(allocator: std.mem.Allocator, decimal_str: []const u8) ![]u8 {
    if (decimal_str.len == 0) return allocator.dupe(u8, "00");

    // Check for negative sign
    const negative = decimal_str[0] == '-';
    const digits = if (negative) decimal_str[1..] else decimal_str;

    // Try i64 first for small-number opcodes (OP_0, OP_1..16, OP_1NEGATE)
    if (std.fmt.parseInt(i64, decimal_str, 10)) |n| {
        return encodeScriptNumber(allocator, n);
    } else |_| {}

    // Big number path: convert decimal digits to bytes via repeated division by 256.
    // We work with the absolute value digits, then apply the sign at the end.

    // Copy digits to a mutable working buffer (array of digit values 0-9)
    var work = try allocator.alloc(u8, digits.len);
    defer allocator.free(work);
    for (digits, 0..) |c, i| {
        work[i] = c - '0';
    }
    var work_len = digits.len;

    // Result bytes in little-endian order
    var le_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer le_bytes.deinit(allocator);

    while (work_len > 0) {
        // Divide the big number (in work[0..work_len]) by 256, collecting
        // the remainder as the next LE byte.
        var remainder: u16 = 0;
        var new_len: usize = 0;
        for (0..work_len) |i| {
            const val = remainder * 10 + @as(u16, work[i]);
            const quotient_digit: u8 = @intCast(val / 256);
            remainder = val % 256;
            if (quotient_digit != 0 or new_len > 0) {
                work[new_len] = quotient_digit;
                new_len += 1;
            }
        }
        try le_bytes.append(allocator, @intCast(remainder));
        work_len = new_len;
    }

    // Strip trailing zero bytes (they came from leading zeros in division)
    while (le_bytes.items.len > 1 and le_bytes.items[le_bytes.items.len - 1] == 0) {
        _ = le_bytes.pop();
    }

    // Apply sign bit (LE sign-magnitude encoding)
    if (le_bytes.items[le_bytes.items.len - 1] & 0x80 != 0) {
        // MSB is set; need an extra byte for the sign
        try le_bytes.append(allocator, if (negative) 0x80 else 0x00);
    } else if (negative) {
        le_bytes.items[le_bytes.items.len - 1] |= 0x80;
    }

    const hex = try bytesToHex(allocator, le_bytes.items);
    defer allocator.free(hex);
    return encodePushData(allocator, hex);
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    _ = bsvz.primitives.hex.encodeLower(bytes, out) catch unreachable;
    return out;
}

pub fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    return bsvz.primitives.hex.decode(allocator, hex);
}

fn hexByteAt(hex: []const u8, pos: usize) ?u8 {
    if (pos + 2 > hex.len) return null;
    const high = hexNibble(hex[pos]) orelse return null;
    const low = hexNibble(hex[pos + 1]) orelse return null;
    return (@as(u8, high) << 4) | @as(u8, low);
}

fn hexNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encodePushData small data" {
    const allocator = std.testing.allocator;
    const result = try encodePushData(allocator, "aabb");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("02aabb", result);
}

test "encodePushData empty returns OP_0" {
    const allocator = std.testing.allocator;
    const result = try encodeArg(allocator, .{ .bytes = "" });
    defer allocator.free(result);
    try std.testing.expectEqualStrings("00", result);
}

// MINIMALDATA (SCRIPT_VERIFY_MINIMALDATA): a 1-byte payload in
// {0x01..0x10, 0x81} must use the minimal opcode, not a direct push.
test "encodePushData MINIMALDATA single-byte opcodes" {
    const allocator = std.testing.allocator;
    {
        // C9/S1: 0x00 is NOT a MINIMALDATA opcode case. OP_0 pushes the EMPTY
        // byte array, not a 1-byte 0x00, so encoding a 1-byte 0x00 payload as
        // OP_0 changes the value (and it did not round-trip). The compiler's
        // canonical encoder encodePushBytesHex
        // (packages/runar-compiler/src/passes/push-encoding.ts) emits "0100"
        // for payload 00 and reserves "00"/OP_0 for a genuinely empty payload.
        const r = try encodePushData(allocator, "00");
        defer allocator.free(r);
        try std.testing.expectEqualStrings("0100", r); // direct push, NOT OP_0
    }
    {
        const r = try encodePushData(allocator, "05");
        defer allocator.free(r);
        try std.testing.expectEqualStrings("55", r); // OP_5
    }
    {
        const r = try encodePushData(allocator, "81");
        defer allocator.free(r);
        try std.testing.expectEqualStrings("4f", r); // OP_1NEGATE
    }
    var n: u8 = 1;
    while (n <= 16) : (n += 1) {
        var in_buf: [2]u8 = undefined;
        _ = std.fmt.bufPrint(&in_buf, "{x:0>2}", .{n}) catch unreachable;
        var want_buf: [2]u8 = undefined;
        _ = std.fmt.bufPrint(&want_buf, "{x:0>2}", .{@as(u8, @intCast(0x50 + @as(u16, n)))}) catch unreachable;
        const r = try encodePushData(allocator, &in_buf);
        defer allocator.free(r);
        try std.testing.expectEqualStrings(&want_buf, r);
    }
}

test "encodePushData MINIMALDATA out-of-range still direct-pushes" {
    const allocator = std.testing.allocator;
    for ([_]u8{ 0x11, 0x4f, 0x50, 0x60, 0x80, 0x82, 0xff }) |b| {
        var in_buf: [2]u8 = undefined;
        _ = std.fmt.bufPrint(&in_buf, "{x:0>2}", .{b}) catch unreachable;
        var want_buf: [4]u8 = undefined;
        _ = std.fmt.bufPrint(&want_buf, "01{x:0>2}", .{b}) catch unreachable;
        const r = try encodePushData(allocator, &in_buf);
        defer allocator.free(r);
        try std.testing.expectEqualStrings(&want_buf, r);
    }
    const r = try encodePushData(allocator, "0011");
    defer allocator.free(r);
    try std.testing.expectEqualStrings("020011", r);
}

test "encodeScriptNumber small values" {
    const allocator = std.testing.allocator;
    {
        const r = try encodeScriptNumber(allocator, 0);
        defer allocator.free(r);
        try std.testing.expectEqualStrings("00", r);
    }
    {
        const r = try encodeScriptNumber(allocator, 1);
        defer allocator.free(r);
        try std.testing.expectEqualStrings("51", r);
    }
    {
        const r = try encodeScriptNumber(allocator, 16);
        defer allocator.free(r);
        try std.testing.expectEqualStrings("60", r);
    }
    {
        const r = try encodeScriptNumber(allocator, -1);
        defer allocator.free(r);
        try std.testing.expectEqualStrings("4f", r);
    }
}

test "encodeNum2Bin roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try encodeNum2Bin(allocator, 42, 8);
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(i64, 42), decodeNum2Bin(encoded));
}

test "encodeNum2Bin negative roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try encodeNum2Bin(allocator, -100, 8);
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(i64, -100), decodeNum2Bin(encoded));
}

test "findLastOpReturn finds OP_RETURN at opcode boundary" {
    // OP_1 (0x51) then OP_RETURN (0x6a)
    try std.testing.expectEqual(@as(?usize, 2), findLastOpReturn("516a"));
    // OP_0 (0x00) then push 1 byte 0x6a then OP_RETURN (0x6a)
    // 00 01 6a 6a — the first 6a is data inside a push
    try std.testing.expectEqual(@as(?usize, 6), findLastOpReturn("00016a6a"));
    // No OP_RETURN
    try std.testing.expectEqual(@as(?usize, null), findLastOpReturn("5151"));
}

test "flattenStateValue walks nested arrays depth-first" {
    const allocator = std.testing.allocator;
    const inner0 = try allocator.alloc(types.StateValue, 2);
    inner0[0] = .{ .int = 1 };
    inner0[1] = .{ .int = 2 };
    const inner1 = try allocator.alloc(types.StateValue, 2);
    inner1[0] = .{ .int = 3 };
    inner1[1] = .{ .int = 4 };
    const outer = try allocator.alloc(types.StateValue, 2);
    outer[0] = .{ .array_value = inner0 };
    outer[1] = .{ .array_value = inner1 };
    const nested = types.StateValue{ .array_value = outer };
    defer nested.deinit(allocator);

    var out: std.ArrayListUnmanaged(types.StateValue) = .empty;
    defer {
        for (out.items) |v| v.deinit(allocator);
        out.deinit(allocator);
    }
    try flattenStateValue(allocator, &out, nested);
    try std.testing.expectEqual(@as(usize, 4), out.items.len);
    try std.testing.expectEqual(@as(i64, 1), out.items[0].int);
    try std.testing.expectEqual(@as(i64, 2), out.items[1].int);
    try std.testing.expectEqual(@as(i64, 3), out.items[2].int);
    try std.testing.expectEqual(@as(i64, 4), out.items[3].int);
}

test "regroupStateValues reconstructs nested shape" {
    const allocator = std.testing.allocator;
    const flat = &[_]types.StateValue{
        .{ .int = 1 }, .{ .int = 2 },
        .{ .int = 3 }, .{ .int = 4 },
        .{ .int = 5 }, .{ .int = 6 },
    };
    const shape = &[_]u32{ 3, 2 };
    const result = try regroupStateValues(allocator, flat, shape);
    defer result.deinit(allocator);
    try std.testing.expect(result == .array_value);
    const outer = result.array_value;
    try std.testing.expectEqual(@as(usize, 3), outer.len);
    const row0 = outer[0].array_value;
    try std.testing.expectEqual(@as(usize, 2), row0.len);
    try std.testing.expectEqual(@as(i64, 1), row0[0].int);
    try std.testing.expectEqual(@as(i64, 2), row0[1].int);
    const row2 = outer[2].array_value;
    try std.testing.expectEqual(@as(i64, 5), row2[0].int);
    try std.testing.expectEqual(@as(i64, 6), row2[1].int);
}

test "flatten and regroup round-trip for nested FixedArray" {
    const allocator = std.testing.allocator;

    // Build a nested value: [[10, 20], [30, 40]]
    const r0 = try allocator.alloc(types.StateValue, 2);
    r0[0] = .{ .int = 10 };
    r0[1] = .{ .int = 20 };
    const r1 = try allocator.alloc(types.StateValue, 2);
    r1[0] = .{ .int = 30 };
    r1[1] = .{ .int = 40 };
    const outer = try allocator.alloc(types.StateValue, 2);
    outer[0] = .{ .array_value = r0 };
    outer[1] = .{ .array_value = r1 };
    const original = types.StateValue{ .array_value = outer };
    defer original.deinit(allocator);

    var flat: std.ArrayListUnmanaged(types.StateValue) = .empty;
    defer {
        for (flat.items) |v| v.deinit(allocator);
        flat.deinit(allocator);
    }
    try flattenStateValue(allocator, &flat, original);

    const shape = &[_]u32{ 2, 2 };
    const regrouped = try regroupStateValues(allocator, flat.items, shape);
    defer regrouped.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 10), regrouped.array_value[0].array_value[0].int);
    try std.testing.expectEqual(@as(i64, 40), regrouped.array_value[1].array_value[1].int);
}

test "serializeState and deserializeState roundtrip" {
    const allocator = std.testing.allocator;
    const fields = &[_]types.StateField{
        .{ .name = "count", .type_name = "int", .index = 0 },
        .{ .name = "flag", .type_name = "bool", .index = 1 },
    };
    const values = &[_]types.StateValue{
        .{ .int = 42 },
        .{ .boolean = true },
    };

    const serialized = try serializeState(allocator, fields, values);
    defer allocator.free(serialized);

    const deserialized = try deserializeState(allocator, fields, serialized);
    defer {
        for (deserialized) |*v| v.deinit(allocator);
        allocator.free(deserialized);
    }

    try std.testing.expectEqual(@as(i64, 42), deserialized[0].int);
    try std.testing.expect(deserialized[1].boolean);
}

// ---------------------------------------------------------------------------
// The state section is framed <len><data>, never MINIMALDATA.
//
// SCRIPT_VERIFY_MINIMALDATA applies to pushes the interpreter EXECUTES —
// unlocking scripts and spliced constructor args, which encodePushData still
// handles (see the "encodePushData MINIMALDATA ..." tests above). The state
// section is raw data after OP_RETURN in the locking script: never executed,
// never MINIMALDATA-checked, and read back by the compiler's on-chain state
// codec (emitPushDataEncode in 05-stack-lower.ts), which understands only
// <len><data>.
//
// #110 applied the MINIMALDATA short-circuit to the state serializer in all
// seven SDKs and none of the seven compilers. A 1-byte 0x05 state field then
// serialised off-chain as "55" while the script rebuilt it as "0105", so the
// continuation hash never matched (unspendable), and a contract DEPLOYED with
// such a value could not be spent at all (the on-chain reader takes 0x55 as a
// length-85 push).
// ---------------------------------------------------------------------------

fn expectStateByteStringFraming(payload: []const u8, want: []const u8) !void {
    const allocator = std.testing.allocator;
    const fields = &[_]types.StateField{
        .{ .name = "b", .type_name = "ByteString", .index = 0 },
    };
    const values = &[_]types.StateValue{.{ .bytes = payload }};
    const serialized = try serializeState(allocator, fields, values);
    defer allocator.free(serialized);
    try std.testing.expectEqualStrings(want, serialized);
}

test "state ByteString: OP_N-range single bytes stay direct pushes" {
    var in_buf: [2]u8 = undefined;
    var want_buf: [4]u8 = undefined;
    var n: u8 = 1;
    while (n <= 0x10) : (n += 1) {
        _ = std.fmt.bufPrint(&in_buf, "{x:0>2}", .{n}) catch unreachable;
        _ = std.fmt.bufPrint(&want_buf, "01{x:0>2}", .{n}) catch unreachable;
        try expectStateByteStringFraming(&in_buf, &want_buf);
    }
}

test "state ByteString: 0x81 is not OP_1NEGATE" {
    try expectStateByteStringFraming("81", "0181");
}

test "state ByteString: single zero byte is a direct push" {
    try expectStateByteStringFraming("00", "0100");
}

test "state ByteString: empty is a zero-length push" {
    try expectStateByteStringFraming("", "00");
}

test "state ByteString: values outside the OP_N range are unchanged" {
    try expectStateByteStringFraming("11", "0111");
    try expectStateByteStringFraming("0011", "020011");
}

test "state ByteString: round-trips for every single-byte value" {
    const allocator = std.testing.allocator;
    const fields = &[_]types.StateField{
        .{ .name = "b", .type_name = "ByteString", .index = 0 },
    };
    var in_buf: [2]u8 = undefined;
    var b: u16 = 0;
    while (b <= 0xff) : (b += 1) {
        _ = std.fmt.bufPrint(&in_buf, "{x:0>2}", .{@as(u8, @intCast(b))}) catch unreachable;
        const values = &[_]types.StateValue{.{ .bytes = &in_buf }};
        const serialized = try serializeState(allocator, fields, values);
        defer allocator.free(serialized);
        const decoded = try deserializeState(allocator, fields, serialized);
        defer {
            for (decoded) |*v| v.deinit(allocator);
            allocator.free(decoded);
        }
        try std.testing.expectEqualStrings(&in_buf, decoded[0].bytes);
    }
}
