const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

// ---------------------------------------------------------------------------
// Script utilities — constructor arg extraction and artifact matching
// ---------------------------------------------------------------------------

/// Result of reading a script element at a given hex offset.
const ScriptElement = struct {
    data_hex: []const u8, // slice into the input hex (not owned)
    total_hex_chars: usize,
    opcode: u8,
};

/// Read a single Bitcoin Script element (opcode + data) at the given hex offset.
fn readScriptElement(hex: []const u8, offset: usize) ScriptElement {
    if (offset + 2 > hex.len) return .{ .data_hex = "", .total_hex_chars = 0, .opcode = 0 };

    const opcode = hexByteAt(hex, offset) orelse return .{ .data_hex = "", .total_hex_chars = 2, .opcode = 0 };

    if (opcode == 0x00) return .{ .data_hex = "", .total_hex_chars = 2, .opcode = opcode };

    if (opcode >= 0x01 and opcode <= 0x4b) {
        const data_len = @as(usize, opcode) * 2;
        const start = offset + 2;
        if (start + data_len > hex.len) return .{ .data_hex = "", .total_hex_chars = 2, .opcode = opcode };
        return .{ .data_hex = hex[start .. start + data_len], .total_hex_chars = 2 + data_len, .opcode = opcode };
    }

    if (opcode == 0x4c) {
        // OP_PUSHDATA1
        if (offset + 4 > hex.len) return .{ .data_hex = "", .total_hex_chars = 4, .opcode = opcode };
        const len = hexByteAt(hex, offset + 2) orelse return .{ .data_hex = "", .total_hex_chars = 4, .opcode = opcode };
        const data_len = @as(usize, len) * 2;
        const start = offset + 4;
        if (start + data_len > hex.len) return .{ .data_hex = "", .total_hex_chars = 4, .opcode = opcode };
        return .{ .data_hex = hex[start .. start + data_len], .total_hex_chars = 4 + data_len, .opcode = opcode };
    }

    if (opcode == 0x4d) {
        // OP_PUSHDATA2
        if (offset + 6 > hex.len) return .{ .data_hex = "", .total_hex_chars = 6, .opcode = opcode };
        const lo = hexByteAt(hex, offset + 2) orelse return .{ .data_hex = "", .total_hex_chars = 6, .opcode = opcode };
        const hi = hexByteAt(hex, offset + 4) orelse return .{ .data_hex = "", .total_hex_chars = 6, .opcode = opcode };
        const len = @as(usize, lo) | (@as(usize, hi) << 8);
        const data_len = len * 2;
        const start = offset + 6;
        if (start + data_len > hex.len) return .{ .data_hex = "", .total_hex_chars = 6, .opcode = opcode };
        return .{ .data_hex = hex[start .. start + data_len], .total_hex_chars = 6 + data_len, .opcode = opcode };
    }

    if (opcode == 0x4e) {
        // OP_PUSHDATA4
        if (offset + 10 > hex.len) return .{ .data_hex = "", .total_hex_chars = 10, .opcode = opcode };
        const b0 = hexByteAt(hex, offset + 2) orelse return .{ .data_hex = "", .total_hex_chars = 10, .opcode = opcode };
        const b1 = hexByteAt(hex, offset + 4) orelse return .{ .data_hex = "", .total_hex_chars = 10, .opcode = opcode };
        const b2 = hexByteAt(hex, offset + 6) orelse return .{ .data_hex = "", .total_hex_chars = 10, .opcode = opcode };
        const b3 = hexByteAt(hex, offset + 8) orelse return .{ .data_hex = "", .total_hex_chars = 10, .opcode = opcode };
        const len = @as(usize, b0) | (@as(usize, b1) << 8) | (@as(usize, b2) << 16) | (@as(usize, b3) << 24);
        const data_len = len * 2;
        const start = offset + 10;
        if (start + data_len > hex.len) return .{ .data_hex = "", .total_hex_chars = 10, .opcode = opcode };
        return .{ .data_hex = hex[start .. start + data_len], .total_hex_chars = 10 + data_len, .opcode = opcode };
    }

    return .{ .data_hex = "", .total_hex_chars = 2, .opcode = opcode };
}

/// Decode a Script number from hex data (sign-magnitude LE).
fn decodeScriptNumber(data_hex: []const u8) i64 {
    if (data_hex.len == 0) return 0;
    const byte_count = data_hex.len / 2;
    var buf: [8]u8 = [_]u8{0} ** 8;
    for (0..byte_count) |i| {
        buf[i] = hexByteAt(data_hex, i * 2) orelse 0;
    }
    const negative = (buf[byte_count - 1] & 0x80) != 0;
    buf[byte_count - 1] &= 0x7f;

    var result: i64 = 0;
    var i: usize = byte_count;
    while (i > 0) {
        i -= 1;
        result = (result << 8) | @as(i64, buf[i]);
    }

    if (negative) return -result;
    return result;
}

/// Interpret a script element as a typed value.
fn interpretScriptElement(allocator: std.mem.Allocator, opcode: u8, data_hex: []const u8, type_name: []const u8) !types.StateValue {
    if (std.mem.eql(u8, type_name, "int") or std.mem.eql(u8, type_name, "bigint")) {
        if (opcode == 0x00) return .{ .int = 0 };
        if (opcode >= 0x51 and opcode <= 0x60) return .{ .int = @as(i64, opcode) - 0x50 };
        if (opcode == 0x4f) return .{ .int = -1 };
        return .{ .int = decodeScriptNumber(data_hex) };
    }

    if (std.mem.eql(u8, type_name, "bool")) {
        if (opcode == 0x00) return .{ .boolean = false };
        if (opcode == 0x51) return .{ .boolean = true };
        return .{ .boolean = !std.mem.eql(u8, data_hex, "00") };
    }

    // Default: bytes
    return .{ .bytes = try allocator.dupe(u8, data_hex) };
}

/// Extract constructor argument values from a compiled on-chain script.
///
/// Uses `artifact.constructorSlots` to locate each constructor arg at its
/// byte offset, reads the push data, and deserializes according to the
/// ABI param type.
///
/// Returns a map from parameter name to StateValue. Caller owns the map and
/// all values within.
pub fn extractConstructorArgs(
    artifact: *const types.RunarArtifact,
    script_hex: []const u8,
    allocator: std.mem.Allocator,
) !std.StringHashMap(types.StateValue) {
    var result = std.StringHashMap(types.StateValue).init(allocator);
    errdefer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        result.deinit();
    }

    if (artifact.constructor_slots.len == 0) return result;

    // Strip state suffix for stateful contracts
    var code_hex = script_hex;
    if (artifact.state_fields.len > 0) {
        const op_return_pos = state_mod.findLastOpReturn(script_hex);
        if (op_return_pos) |pos| {
            code_hex = script_hex[0..pos];
        }
    }

    // Sort slots by byte offset, deduplicate by param index
    const Slot = struct { param_index: i32, byte_offset: i32 };
    var slots: std.ArrayListUnmanaged(Slot) = .empty;
    defer slots.deinit(allocator);

    // First, collect all unique slots sorted by byte offset
    var seen_params = std.AutoHashMap(i32, void).init(allocator);
    defer seen_params.deinit();

    // Build sorted index
    var indices = try allocator.alloc(usize, artifact.constructor_slots.len);
    defer allocator.free(indices);
    for (0..artifact.constructor_slots.len) |i| indices[i] = i;

    const cs = artifact.constructor_slots;
    std.mem.sort(usize, indices, cs, struct {
        fn lessThan(ctx: []const types.ConstructorSlot, a: usize, b: usize) bool {
            return ctx[a].byte_offset < ctx[b].byte_offset;
        }
    }.lessThan);

    for (indices) |idx| {
        const slot = cs[idx];
        if (!seen_params.contains(slot.param_index)) {
            try seen_params.put(slot.param_index, {});
            try slots.append(allocator, .{
                .param_index = slot.param_index,
                .byte_offset = slot.byte_offset,
            });
        }
    }

    // Walk through the slots, reading script elements
    var cumulative_shift: i64 = 0;

    for (slots.items) |slot| {
        const adjusted_hex_offset: usize = @intCast((@as(i64, slot.byte_offset) + cumulative_shift) * 2);
        if (adjusted_hex_offset >= code_hex.len) continue;

        const elem = readScriptElement(code_hex, adjusted_hex_offset);
        cumulative_shift += @as(i64, @intCast(elem.total_hex_chars)) / 2 - 1;

        const param_idx: usize = @intCast(slot.param_index);
        if (param_idx >= artifact.abi.constructor.params.len) continue;

        const param = artifact.abi.constructor.params[param_idx];
        const value = try interpretScriptElement(allocator, elem.opcode, elem.data_hex, param.type_name);
        const key = try allocator.dupe(u8, param.name);
        try result.put(key, value);
    }

    return result;
}

/// Determine whether a given on-chain script was produced from the given
/// contract artifact (regardless of what constructor args were used).
pub fn matchesArtifact(
    artifact: *const types.RunarArtifact,
    script_hex: []const u8,
) bool {
    // Strip state suffix for stateful contracts
    var code_hex = script_hex;
    if (artifact.state_fields.len > 0) {
        const op_return_pos = state_mod.findLastOpReturn(script_hex);
        if (op_return_pos) |pos| {
            code_hex = script_hex[0..pos];
        }
    }

    const template = artifact.script;

    if (artifact.constructor_slots.len == 0) {
        return std.mem.eql(u8, code_hex, template);
    }

    // Build sorted, deduplicated slots by byte offset
    // Use a simple inline sort since we can't allocate in a bool-returning fn
    var sorted_offsets: [64]struct { byte_offset: i32 } = undefined;
    var sorted_count: usize = 0;

    // Collect unique byte offsets
    for (artifact.constructor_slots) |slot| {
        var found = false;
        for (0..sorted_count) |k| {
            if (sorted_offsets[k].byte_offset == slot.byte_offset) {
                found = true;
                break;
            }
        }
        if (!found and sorted_count < 64) {
            sorted_offsets[sorted_count] = .{ .byte_offset = slot.byte_offset };
            sorted_count += 1;
        }
    }

    // Insertion sort
    for (1..sorted_count) |i| {
        const key = sorted_offsets[i];
        var j: usize = i;
        while (j > 0 and sorted_offsets[j - 1].byte_offset > key.byte_offset) {
            sorted_offsets[j] = sorted_offsets[j - 1];
            j -= 1;
        }
        sorted_offsets[j] = key;
    }

    var template_pos: usize = 0;
    var code_pos: usize = 0;

    for (0..sorted_count) |i| {
        const slot_hex_offset: usize = @intCast(sorted_offsets[i].byte_offset * 2);

        // Compare template segment before this slot
        const template_segment_len = slot_hex_offset - template_pos;
        if (code_pos + template_segment_len > code_hex.len) return false;
        if (template_pos + template_segment_len > template.len) return false;

        const template_segment = template[template_pos .. template_pos + template_segment_len];
        const code_segment = code_hex[code_pos .. code_pos + template_segment_len];
        if (!std.mem.eql(u8, template_segment, code_segment)) return false;

        // Skip the placeholder in template (1 byte = 2 hex chars: OP_0)
        template_pos = slot_hex_offset + 2;

        // Read the actual element in the code script
        const elem_offset = code_pos + template_segment_len;
        const elem = readScriptElement(code_hex, elem_offset);
        code_pos = elem_offset + elem.total_hex_chars;
    }

    // Compare the remaining suffix
    const template_rest = template[template_pos..];
    const code_rest = code_hex[code_pos..];
    return std.mem.eql(u8, template_rest, code_rest);
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

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

test "extractConstructorArgs returns empty for no slots" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"5100","asm":"OP_1 OP_0",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var result = try extractConstructorArgs(&artifact, "5100", allocator);
    defer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        result.deinit();
    }

    try std.testing.expectEqual(@as(usize, 0), result.count());
}

test "matchesArtifact matches identical script" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"5100","asm":"OP_1 OP_0",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    try std.testing.expect(matchesArtifact(&artifact, "5100"));
    try std.testing.expect(!matchesArtifact(&artifact, "5200"));
}

test "matchesArtifact with constructor slots" {
    const allocator = std.testing.allocator;
    // Template has OP_0 (00) at byte 0 as a placeholder
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"0088ac","asm":"OP_0 OP_EQUALVERIFY OP_CHECKSIG",
        \\"abi":{"constructor":{"params":[{"name":"pkh","type":"Addr"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[{"paramIndex":0,"byteOffset":0}],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    // On-chain script with a 20-byte push at offset 0: 14 + 20 bytes + "88ac"
    // OP_PUSH20 (0x14) + 20 zero bytes + OP_EQUALVERIFY + OP_CHECKSIG
    const on_chain = "14" ++ "00" ** 20 ++ "88ac";
    try std.testing.expect(matchesArtifact(&artifact, on_chain));

    // Different suffix should not match
    const bad = "14" ++ "00" ** 20 ++ "88ad";
    try std.testing.expect(!matchesArtifact(&artifact, bad));
}

test "extractConstructorArgs extracts int param" {
    const allocator = std.testing.allocator;
    // Script template: OP_0 (placeholder at byte 0) then "87" (OP_EQUAL)
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"0087","asm":"OP_0 OP_EQUAL",
        \\"abi":{"constructor":{"params":[{"name":"x","type":"int"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[{"paramIndex":0,"byteOffset":0}],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    // On-chain script: OP_5 (55) + OP_EQUAL (87)
    var result = try extractConstructorArgs(&artifact, "5587", allocator);
    defer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        result.deinit();
    }

    try std.testing.expectEqual(@as(usize, 1), result.count());
    const val = result.get("x").?;
    try std.testing.expectEqual(@as(i64, 5), val.int);
}
