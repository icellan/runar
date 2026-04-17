const std = @import("std");
const state_mod = @import("sdk_state.zig");

// ---------------------------------------------------------------------------
// sdk_ordinals.zig -- Build and parse 1sat ordinal inscriptions
// ---------------------------------------------------------------------------
//
// Envelope layout:
//   OP_FALSE OP_IF PUSH("ord") OP_1 PUSH(<content-type>) OP_0 PUSH(<data>) OP_ENDIF
//
// Hex:
//   00 63 03 6f7264 51 <push content-type> 00 <push data> 68
//
// The envelope is a no-op (OP_FALSE causes the IF block to be skipped)
// and can be placed anywhere in a script without affecting execution.
// ---------------------------------------------------------------------------

/// Inscription data: content type and hex-encoded payload.
pub const Inscription = struct {
    content_type: []const u8,
    data: []const u8, // hex-encoded content

    pub fn deinit(self: *Inscription, allocator: std.mem.Allocator) void {
        if (self.content_type.len > 0) allocator.free(self.content_type);
        if (self.data.len > 0) allocator.free(self.data);
        self.* = .{ .content_type = &.{}, .data = &.{} };
    }

    pub fn clone(self: Inscription, allocator: std.mem.Allocator) !Inscription {
        return .{
            .content_type = try allocator.dupe(u8, self.content_type),
            .data = try allocator.dupe(u8, self.data),
        };
    }
};

/// Hex-char offsets bounding an inscription envelope within a script.
pub const EnvelopeBounds = struct {
    start_hex: usize,
    end_hex: usize,
};

// ---------------------------------------------------------------------------
// Hex utilities (local)
// ---------------------------------------------------------------------------

fn hexNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

fn hexByteAt(hex: []const u8, pos: usize) ?u8 {
    if (pos + 2 > hex.len) return null;
    const high = hexNibble(hex[pos]) orelse return null;
    const low = hexNibble(hex[pos + 1]) orelse return null;
    return (@as(u8, high) << 4) | @as(u8, low);
}

/// Convert a UTF-8 string to its hex representation.
fn utf8ToHex(allocator: std.mem.Allocator, str: []const u8) ![]u8 {
    var result = try allocator.alloc(u8, str.len * 2);
    for (str, 0..) |byte, i| {
        _ = std.fmt.bufPrint(result[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
    }
    return result;
}

/// Convert a hex string to UTF-8.
fn hexToUtf8(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len == 0) return allocator.dupe(u8, "");
    const byte_len = hex.len / 2;
    var result = try allocator.alloc(u8, byte_len);
    for (0..byte_len) |i| {
        result[i] = hexByteAt(hex, i * 2) orelse 0;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build a 1sat ordinals inscription envelope as hex.
///
/// @param content_type - MIME type (e.g. "image/png", "application/bsv-20")
/// @param data - Hex-encoded inscription content
/// @returns Hex string of the full envelope script fragment (caller owns).
pub fn buildInscriptionEnvelope(
    allocator: std.mem.Allocator,
    content_type: []const u8,
    data: []const u8,
) ![]u8 {
    const content_type_hex = try utf8ToHex(allocator, content_type);
    defer allocator.free(content_type_hex);

    const ct_push = try state_mod.encodePushData(allocator, content_type_hex);
    defer allocator.free(ct_push);

    // Data push: empty data => OP_0 (00)
    const data_push = if (data.len == 0)
        try allocator.dupe(u8, "00")
    else
        try state_mod.encodePushData(allocator, data);
    defer allocator.free(data_push);

    // OP_FALSE(00) OP_IF(63) PUSH3 "ord"(03 6f7264) OP_1(51)
    // + PUSH content-type
    // + OP_0(00) -- content delimiter
    // + PUSH data
    // + OP_ENDIF(68)
    const prefix = "006303" ++ "6f7264" ++ "51";
    const total_len = prefix.len + ct_push.len + 2 + data_push.len + 2;
    var result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    @memcpy(result[pos .. pos + prefix.len], prefix);
    pos += prefix.len;

    @memcpy(result[pos .. pos + ct_push.len], ct_push);
    pos += ct_push.len;

    @memcpy(result[pos .. pos + 2], "00");
    pos += 2;

    @memcpy(result[pos .. pos + data_push.len], data_push);
    pos += data_push.len;

    @memcpy(result[pos .. pos + 2], "68");

    return result;
}

// ---------------------------------------------------------------------------
// Parse / Find
// ---------------------------------------------------------------------------

/// Read a push-data value at the given hex offset. Returns the pushed data
/// (hex slice) and the total number of hex chars consumed.
const ReadPushDataResult = struct {
    data: []const u8,
    bytes_read: usize,
};

fn readPushData(script_hex: []const u8, offset: usize) ?ReadPushDataResult {
    if (offset + 2 > script_hex.len) return null;
    const opcode = hexByteAt(script_hex, offset) orelse return null;

    if (opcode >= 0x01 and opcode <= 0x4b) {
        const data_len = @as(usize, opcode) * 2;
        if (offset + 2 + data_len > script_hex.len) return null;
        return .{ .data = script_hex[offset + 2 .. offset + 2 + data_len], .bytes_read = 2 + data_len };
    } else if (opcode == 0x4c) {
        // OP_PUSHDATA1
        if (offset + 4 > script_hex.len) return null;
        const len = @as(usize, hexByteAt(script_hex, offset + 2) orelse return null);
        const data_len = len * 2;
        if (offset + 4 + data_len > script_hex.len) return null;
        return .{ .data = script_hex[offset + 4 .. offset + 4 + data_len], .bytes_read = 4 + data_len };
    } else if (opcode == 0x4d) {
        // OP_PUSHDATA2
        if (offset + 6 > script_hex.len) return null;
        const lo = @as(usize, hexByteAt(script_hex, offset + 2) orelse return null);
        const hi = @as(usize, hexByteAt(script_hex, offset + 4) orelse return null);
        const len = lo | (hi << 8);
        const data_len = len * 2;
        if (offset + 6 + data_len > script_hex.len) return null;
        return .{ .data = script_hex[offset + 6 .. offset + 6 + data_len], .bytes_read = 6 + data_len };
    } else if (opcode == 0x4e) {
        // OP_PUSHDATA4
        if (offset + 10 > script_hex.len) return null;
        const b0 = @as(usize, hexByteAt(script_hex, offset + 2) orelse return null);
        const b1 = @as(usize, hexByteAt(script_hex, offset + 4) orelse return null);
        const b2 = @as(usize, hexByteAt(script_hex, offset + 6) orelse return null);
        const b3 = @as(usize, hexByteAt(script_hex, offset + 8) orelse return null);
        const len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        const data_len = len * 2;
        if (offset + 10 + data_len > script_hex.len) return null;
        return .{ .data = script_hex[offset + 10 .. offset + 10 + data_len], .bytes_read = 10 + data_len };
    }

    return null;
}

/// Compute the number of hex chars an opcode occupies (including its push
/// data) so we can advance past it while walking a script.
fn opcodeSize(script_hex: []const u8, offset: usize) usize {
    if (offset + 2 > script_hex.len) return 2;
    const opcode = hexByteAt(script_hex, offset) orelse return 2;

    if (opcode >= 0x01 and opcode <= 0x4b) {
        return 2 + @as(usize, opcode) * 2;
    } else if (opcode == 0x4c) {
        if (offset + 4 > script_hex.len) return 2;
        const len = @as(usize, hexByteAt(script_hex, offset + 2) orelse return 2);
        return 4 + len * 2;
    } else if (opcode == 0x4d) {
        if (offset + 6 > script_hex.len) return 2;
        const lo = @as(usize, hexByteAt(script_hex, offset + 2) orelse return 2);
        const hi = @as(usize, hexByteAt(script_hex, offset + 4) orelse return 2);
        return 6 + (lo | (hi << 8)) * 2;
    } else if (opcode == 0x4e) {
        if (offset + 10 > script_hex.len) return 2;
        const b0 = @as(usize, hexByteAt(script_hex, offset + 2) orelse return 2);
        const b1 = @as(usize, hexByteAt(script_hex, offset + 4) orelse return 2);
        const b2 = @as(usize, hexByteAt(script_hex, offset + 6) orelse return 2);
        const b3 = @as(usize, hexByteAt(script_hex, offset + 8) orelse return 2);
        return 10 + (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) * 2;
    }

    return 2; // all other opcodes are 1 byte
}

/// Find the inscription envelope within a script hex string.
///
/// Walks the script as Bitcoin Script opcodes looking for the pattern:
///   OP_FALSE(00) OP_IF(63) PUSH3 "ord"(03 6f7264) ...
///
/// Returns hex-char offsets of the envelope, or null if not found.
pub fn findInscriptionEnvelope(script_hex: []const u8) ?EnvelopeBounds {
    var offset: usize = 0;
    const len = script_hex.len;

    while (offset + 2 <= len) {
        const opcode = hexByteAt(script_hex, offset) orelse break;

        // Look for OP_FALSE (0x00)
        if (opcode == 0x00) {
            // Check: OP_IF (63) PUSH3 (03) "ord" (6f7264)
            if (offset + 12 <= len and
                std.mem.eql(u8, script_hex[offset + 2 .. offset + 4], "63") and
                std.mem.eql(u8, script_hex[offset + 4 .. offset + 12], "036f7264"))
            {
                const envelope_start = offset;
                // Skip: OP_FALSE(2) + OP_IF(2) + PUSH3 "ord"(8) = 12 hex chars
                var pos = offset + 12;

                // Expect OP_1 (0x51)
                if (pos + 2 > len or !std.mem.eql(u8, script_hex[pos .. pos + 2], "51")) {
                    offset += 2;
                    continue;
                }
                pos += 2; // skip OP_1

                // Read content-type push
                const ct_push = readPushData(script_hex, pos) orelse {
                    offset += 2;
                    continue;
                };
                pos += ct_push.bytes_read;

                // Expect OP_0 (0x00) -- content delimiter
                if (pos + 2 > len or !std.mem.eql(u8, script_hex[pos .. pos + 2], "00")) {
                    offset += 2;
                    continue;
                }
                pos += 2; // skip OP_0

                // Read data push
                const data_push = readPushData(script_hex, pos) orelse {
                    offset += 2;
                    continue;
                };
                pos += data_push.bytes_read;

                // Expect OP_ENDIF (0x68)
                if (pos + 2 > len or !std.mem.eql(u8, script_hex[pos .. pos + 2], "68")) {
                    offset += 2;
                    continue;
                }
                pos += 2; // skip OP_ENDIF

                return .{ .start_hex = envelope_start, .end_hex = pos };
            }
        }

        // Advance past this opcode
        offset += opcodeSize(script_hex, offset);
    }

    return null;
}

/// Parse an inscription envelope from a script hex string.
///
/// Returns the inscription data, or null if no envelope is found.
pub fn parseInscriptionEnvelope(allocator: std.mem.Allocator, script_hex: []const u8) !?Inscription {
    const bounds = findInscriptionEnvelope(script_hex) orelse return null;
    const envelope_hex = script_hex[bounds.start_hex..bounds.end_hex];

    // Parse the envelope contents:
    // 00 63 03 6f7264 51 <ct-push> 00 <data-push> 68
    var pos: usize = 12; // skip OP_FALSE + OP_IF + PUSH3 "ord"
    pos += 2; // skip OP_1

    const ct_push = readPushData(envelope_hex, pos) orelse return null;
    pos += ct_push.bytes_read;

    pos += 2; // skip OP_0

    const data_push = readPushData(envelope_hex, pos) orelse return null;

    const content_type = try hexToUtf8(allocator, ct_push.data);
    const data = try allocator.dupe(u8, data_push.data);

    return .{
        .content_type = content_type,
        .data = data,
    };
}

/// Remove the inscription envelope from a script, returning the bare script.
///
/// Returns script hex with the envelope removed, or a copy of the original if
/// none found. Caller owns the returned slice.
pub fn stripInscriptionEnvelope(allocator: std.mem.Allocator, script_hex: []const u8) ![]u8 {
    const bounds = findInscriptionEnvelope(script_hex) orelse
        return allocator.dupe(u8, script_hex);

    const before = script_hex[0..bounds.start_hex];
    const after = script_hex[bounds.end_hex..];
    return std.mem.concat(allocator, u8, &[_][]const u8{ before, after });
}

// ---------------------------------------------------------------------------
// BSV-20 / BSV-21 helpers
// ---------------------------------------------------------------------------

/// Build a BSV-20 deploy inscription.
pub fn bsv20Deploy(
    allocator: std.mem.Allocator,
    tick: []const u8,
    max: []const u8,
    lim: ?[]const u8,
    dec: ?[]const u8,
) !Inscription {
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(allocator);

    try json_buf.appendSlice(allocator, "{\"p\":\"bsv-20\",\"op\":\"deploy\",\"tick\":\"");
    try appendJsonEscaped(&json_buf, allocator, tick);
    try json_buf.appendSlice(allocator, "\",\"max\":\"");
    try appendJsonEscaped(&json_buf, allocator, max);
    try json_buf.append(allocator, '"');
    if (lim) |l| {
        try json_buf.appendSlice(allocator, ",\"lim\":\"");
        try appendJsonEscaped(&json_buf, allocator, l);
        try json_buf.append(allocator, '"');
    }
    if (dec) |d| {
        try json_buf.appendSlice(allocator, ",\"dec\":\"");
        try appendJsonEscaped(&json_buf, allocator, d);
        try json_buf.append(allocator, '"');
    }
    try json_buf.append(allocator, '}');

    const data_hex = try utf8ToHex(allocator, json_buf.items);

    return .{
        .content_type = try allocator.dupe(u8, "application/bsv-20"),
        .data = data_hex,
    };
}

/// Build a BSV-20 mint inscription.
pub fn bsv20Mint(
    allocator: std.mem.Allocator,
    tick: []const u8,
    amt: []const u8,
) !Inscription {
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(allocator);

    try json_buf.appendSlice(allocator, "{\"p\":\"bsv-20\",\"op\":\"mint\",\"tick\":\"");
    try appendJsonEscaped(&json_buf, allocator, tick);
    try json_buf.appendSlice(allocator, "\",\"amt\":\"");
    try appendJsonEscaped(&json_buf, allocator, amt);
    try json_buf.appendSlice(allocator, "\"}");

    const data_hex = try utf8ToHex(allocator, json_buf.items);

    return .{
        .content_type = try allocator.dupe(u8, "application/bsv-20"),
        .data = data_hex,
    };
}

/// Build a BSV-20 transfer inscription.
pub fn bsv20Transfer(
    allocator: std.mem.Allocator,
    tick: []const u8,
    amt: []const u8,
) !Inscription {
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(allocator);

    try json_buf.appendSlice(allocator, "{\"p\":\"bsv-20\",\"op\":\"transfer\",\"tick\":\"");
    try appendJsonEscaped(&json_buf, allocator, tick);
    try json_buf.appendSlice(allocator, "\",\"amt\":\"");
    try appendJsonEscaped(&json_buf, allocator, amt);
    try json_buf.appendSlice(allocator, "\"}");

    const data_hex = try utf8ToHex(allocator, json_buf.items);

    return .{
        .content_type = try allocator.dupe(u8, "application/bsv-20"),
        .data = data_hex,
    };
}

/// Build a BSV-21 deploy+mint inscription.
pub fn bsv21DeployMint(
    allocator: std.mem.Allocator,
    amt: []const u8,
    dec: ?[]const u8,
    sym: ?[]const u8,
    icon: ?[]const u8,
) !Inscription {
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(allocator);

    try json_buf.appendSlice(allocator, "{\"p\":\"bsv-20\",\"op\":\"deploy+mint\",\"amt\":\"");
    try appendJsonEscaped(&json_buf, allocator, amt);
    try json_buf.append(allocator, '"');
    if (dec) |d| {
        try json_buf.appendSlice(allocator, ",\"dec\":\"");
        try appendJsonEscaped(&json_buf, allocator, d);
        try json_buf.append(allocator, '"');
    }
    if (sym) |s| {
        try json_buf.appendSlice(allocator, ",\"sym\":\"");
        try appendJsonEscaped(&json_buf, allocator, s);
        try json_buf.append(allocator, '"');
    }
    if (icon) |ic| {
        try json_buf.appendSlice(allocator, ",\"icon\":\"");
        try appendJsonEscaped(&json_buf, allocator, ic);
        try json_buf.append(allocator, '"');
    }
    try json_buf.append(allocator, '}');

    const data_hex = try utf8ToHex(allocator, json_buf.items);

    return .{
        .content_type = try allocator.dupe(u8, "application/bsv-20"),
        .data = data_hex,
    };
}

/// Build a BSV-21 transfer inscription.
pub fn bsv21Transfer(
    allocator: std.mem.Allocator,
    id: []const u8,
    amt: []const u8,
) !Inscription {
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(allocator);

    try json_buf.appendSlice(allocator, "{\"p\":\"bsv-20\",\"op\":\"transfer\",\"id\":\"");
    try appendJsonEscaped(&json_buf, allocator, id);
    try json_buf.appendSlice(allocator, "\",\"amt\":\"");
    try appendJsonEscaped(&json_buf, allocator, amt);
    try json_buf.appendSlice(allocator, "\"}");

    const data_hex = try utf8ToHex(allocator, json_buf.items);

    return .{
        .content_type = try allocator.dupe(u8, "application/bsv-20"),
        .data = data_hex,
    };
}

/// Append a string to a JSON buffer, escaping special characters.
fn appendJsonEscaped(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, str: []const u8) !void {
    for (str) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => try buf.append(allocator, c),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "buildInscriptionEnvelope builds text inscription" {
    const allocator = std.testing.allocator;
    const data = try utf8ToHex(allocator, "Hello, ordinals!");
    defer allocator.free(data);

    const envelope = try buildInscriptionEnvelope(allocator, "text/plain", data);
    defer allocator.free(envelope);

    // Starts with OP_FALSE OP_IF PUSH3 "ord" OP_1
    try std.testing.expect(std.mem.startsWith(u8, envelope, "006303" ++ "6f7264" ++ "51"));
    // Ends with OP_ENDIF
    try std.testing.expect(std.mem.endsWith(u8, envelope, "68"));
    // Contains content type hex
    const ct_hex = try utf8ToHex(allocator, "text/plain");
    defer allocator.free(ct_hex);
    try std.testing.expect(std.mem.indexOf(u8, envelope, ct_hex) != null);
    // Contains data
    try std.testing.expect(std.mem.indexOf(u8, envelope, data) != null);
}

test "buildInscriptionEnvelope with large data (OP_PUSHDATA2)" {
    const allocator = std.testing.allocator;
    // 300 bytes of data
    const data = "ff" ** 300;

    const envelope = try buildInscriptionEnvelope(allocator, "image/png", data);
    defer allocator.free(envelope);

    // Should contain OP_PUSHDATA2 (4d) for the data push: 300 = 0x012c LE = 2c01
    try std.testing.expect(std.mem.indexOf(u8, envelope, "4d" ++ "2c01" ++ data) != null);
    try std.testing.expect(std.mem.startsWith(u8, envelope, "006303" ++ "6f7264" ++ "51"));
    try std.testing.expect(std.mem.endsWith(u8, envelope, "68"));
}

test "buildInscriptionEnvelope with medium data (OP_PUSHDATA1)" {
    const allocator = std.testing.allocator;
    // 100 bytes
    const data = "ab" ** 100;

    const envelope = try buildInscriptionEnvelope(allocator, "application/octet-stream", data);
    defer allocator.free(envelope);

    // Should contain OP_PUSHDATA1 (4c) for the data push: 100 = 0x64
    try std.testing.expect(std.mem.indexOf(u8, envelope, "4c" ++ "64" ++ data) != null);
}

test "buildInscriptionEnvelope handles empty data" {
    const allocator = std.testing.allocator;
    const envelope = try buildInscriptionEnvelope(allocator, "text/plain", "");
    defer allocator.free(envelope);

    // Data push is OP_0 (00), pattern: 00 00 68
    try std.testing.expect(std.mem.endsWith(u8, envelope, "000068"));
}

test "parseInscriptionEnvelope round-trips text inscription" {
    const allocator = std.testing.allocator;
    const orig_data = try utf8ToHex(allocator, "Hello!");
    defer allocator.free(orig_data);

    const envelope = try buildInscriptionEnvelope(allocator, "text/plain", orig_data);
    defer allocator.free(envelope);

    var parsed = (try parseInscriptionEnvelope(allocator, envelope)).?;
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("text/plain", parsed.content_type);
    try std.testing.expectEqualStrings(orig_data, parsed.data);
}

test "parseInscriptionEnvelope round-trips large data" {
    const allocator = std.testing.allocator;
    const data = "ff" ** 300;

    const envelope = try buildInscriptionEnvelope(allocator, "image/png", data);
    defer allocator.free(envelope);

    var parsed = (try parseInscriptionEnvelope(allocator, envelope)).?;
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("image/png", parsed.content_type);
    try std.testing.expectEqualStrings(data, parsed.data);
}

test "parseInscriptionEnvelope returns null for script without envelope" {
    const allocator = std.testing.allocator;
    const script = "a914" ++ "00" ** 20 ++ "87";
    const result = try parseInscriptionEnvelope(allocator, script);
    try std.testing.expect(result == null);
}

test "parseInscriptionEnvelope finds envelope in larger script" {
    const allocator = std.testing.allocator;
    const prefix = "a914" ++ "00" ** 20 ++ "8788ac";
    const data = try utf8ToHex(allocator, "test");
    defer allocator.free(data);

    const envelope = try buildInscriptionEnvelope(allocator, "text/plain", data);
    defer allocator.free(envelope);

    const suffix = "6a" ++ "08" ++ "00" ** 8;

    const full_script = try std.mem.concat(allocator, u8, &[_][]const u8{ prefix, envelope, suffix });
    defer allocator.free(full_script);

    var parsed = (try parseInscriptionEnvelope(allocator, full_script)).?;
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("text/plain", parsed.content_type);
    try std.testing.expectEqualStrings(data, parsed.data);
}

test "findInscriptionEnvelope finds envelope bounds" {
    const allocator = std.testing.allocator;
    const prefix = "aabb";
    const hi_hex = try utf8ToHex(allocator, "hi");
    defer allocator.free(hi_hex);
    const envelope = try buildInscriptionEnvelope(allocator, "text/plain", hi_hex);
    defer allocator.free(envelope);
    const suffix = "ccdd";

    const script = try std.mem.concat(allocator, u8, &[_][]const u8{ prefix, envelope, suffix });
    defer allocator.free(script);

    const bounds = findInscriptionEnvelope(script).?;
    try std.testing.expectEqual(prefix.len, bounds.start_hex);
    try std.testing.expectEqual(prefix.len + envelope.len, bounds.end_hex);
}

test "findInscriptionEnvelope returns null when no envelope" {
    const result = findInscriptionEnvelope("76a914" ++ "00" ** 20 ++ "88ac");
    try std.testing.expect(result == null);
}

test "stripInscriptionEnvelope removes envelope" {
    const allocator = std.testing.allocator;
    const prefix = "aabb";
    const hi_hex = try utf8ToHex(allocator, "hi");
    defer allocator.free(hi_hex);
    const envelope = try buildInscriptionEnvelope(allocator, "text/plain", hi_hex);
    defer allocator.free(envelope);
    const suffix = "ccdd";

    const script = try std.mem.concat(allocator, u8, &[_][]const u8{ prefix, envelope, suffix });
    defer allocator.free(script);

    const stripped = try stripInscriptionEnvelope(allocator, script);
    defer allocator.free(stripped);

    const expected = try std.mem.concat(allocator, u8, &[_][]const u8{ prefix, suffix });
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, stripped);
}

test "stripInscriptionEnvelope returns copy when no envelope" {
    const allocator = std.testing.allocator;
    const script = "76a914" ++ "00" ** 20 ++ "88ac";
    const result = try stripInscriptionEnvelope(allocator, script);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(script, result);
}

test "bsv20Deploy builds correct JSON inscription" {
    const allocator = std.testing.allocator;
    var insc = try bsv20Deploy(allocator, "RUNAR", "21000000", "1000", null);
    defer insc.deinit(allocator);

    try std.testing.expectEqualStrings("application/bsv-20", insc.content_type);

    // Decode data hex to UTF-8 and verify JSON content
    const json_str = try hexToUtf8(allocator, insc.data);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"p\":\"bsv-20\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"deploy\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"tick\":\"RUNAR\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"max\":\"21000000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"lim\":\"1000\"") != null);
}

test "bsv20Deploy without optional fields" {
    const allocator = std.testing.allocator;
    var insc = try bsv20Deploy(allocator, "TEST", "1000", null, null);
    defer insc.deinit(allocator);

    const json_str = try hexToUtf8(allocator, insc.data);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"lim\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"dec\"") == null);
}

test "bsv20Mint builds correct JSON inscription" {
    const allocator = std.testing.allocator;
    var insc = try bsv20Mint(allocator, "RUNAR", "1000");
    defer insc.deinit(allocator);

    try std.testing.expectEqualStrings("application/bsv-20", insc.content_type);

    const json_str = try hexToUtf8(allocator, insc.data);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"mint\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"tick\":\"RUNAR\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"amt\":\"1000\"") != null);
}

test "bsv20Transfer builds correct JSON inscription" {
    const allocator = std.testing.allocator;
    var insc = try bsv20Transfer(allocator, "RUNAR", "50");
    defer insc.deinit(allocator);

    try std.testing.expectEqualStrings("application/bsv-20", insc.content_type);

    const json_str = try hexToUtf8(allocator, insc.data);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"transfer\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"tick\":\"RUNAR\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"amt\":\"50\"") != null);
}

test "bsv21DeployMint builds correct JSON inscription" {
    const allocator = std.testing.allocator;
    var insc = try bsv21DeployMint(allocator, "1000000", "18", "RNR", null);
    defer insc.deinit(allocator);

    try std.testing.expectEqualStrings("application/bsv-20", insc.content_type);

    const json_str = try hexToUtf8(allocator, insc.data);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"deploy+mint\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"amt\":\"1000000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"dec\":\"18\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"sym\":\"RNR\"") != null);
}

test "bsv21DeployMint without optional fields" {
    const allocator = std.testing.allocator;
    var insc = try bsv21DeployMint(allocator, "500", null, null, null);
    defer insc.deinit(allocator);

    const json_str = try hexToUtf8(allocator, insc.data);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"dec\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"sym\"") == null);
}

test "bsv21Transfer builds correct JSON inscription" {
    const allocator = std.testing.allocator;
    var insc = try bsv21Transfer(allocator, "3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1", "100");
    defer insc.deinit(allocator);

    try std.testing.expectEqualStrings("application/bsv-20", insc.content_type);

    const json_str = try hexToUtf8(allocator, insc.data);
    defer allocator.free(json_str);

    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"op\":\"transfer\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"id\":\"3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_str, "\"amt\":\"100\"") != null);
}

test "BSV-20 round-trip through envelope" {
    const allocator = std.testing.allocator;
    var insc = try bsv20Deploy(allocator, "RUNAR", "21000000", "1000", null);
    defer insc.deinit(allocator);

    // Build envelope and parse back
    const envelope = try buildInscriptionEnvelope(allocator, insc.content_type, insc.data);
    defer allocator.free(envelope);

    var parsed = (try parseInscriptionEnvelope(allocator, envelope)).?;
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings(insc.content_type, parsed.content_type);
    try std.testing.expectEqualStrings(insc.data, parsed.data);
}
