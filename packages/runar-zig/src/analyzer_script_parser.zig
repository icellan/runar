// Script parser — decodes hex-encoded Bitcoin Script into Opcode records.
//
// Spec: spec/script-analyzer-format.md §4, §6, §12

const std = @import("std");
const types = @import("analyzer_types.zig");

const Opcode = types.Opcode;
const PushEncoding = types.PushEncoding;
const RawScriptSpan = types.RawScriptSpan;

/// Returns the canonical BSV opcode name for `byte`. Caller owns the
/// returned slice and must free with `allocator.free`.
pub fn canonicalOpcodeName(allocator: std.mem.Allocator, byte: u8) ![]u8 {
    const fixed: ?[]const u8 = switch (byte) {
        0x00 => "OP_0",
        0x4c => "OP_PUSHDATA1",
        0x4d => "OP_PUSHDATA2",
        0x4e => "OP_PUSHDATA4",
        0x4f => "OP_1NEGATE",
        0x51 => "OP_1",
        0x52 => "OP_2",
        0x53 => "OP_3",
        0x54 => "OP_4",
        0x55 => "OP_5",
        0x56 => "OP_6",
        0x57 => "OP_7",
        0x58 => "OP_8",
        0x59 => "OP_9",
        0x5a => "OP_10",
        0x5b => "OP_11",
        0x5c => "OP_12",
        0x5d => "OP_13",
        0x5e => "OP_14",
        0x5f => "OP_15",
        0x60 => "OP_16",
        0x61 => "OP_NOP",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_RETURN",
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x6f => "OP_3DUP",
        0x70 => "OP_2OVER",
        0x71 => "OP_2ROT",
        0x72 => "OP_2SWAP",
        0x73 => "OP_IFDUP",
        0x74 => "OP_DEPTH",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x79 => "OP_PICK",
        0x7a => "OP_ROLL",
        0x7b => "OP_ROT",
        0x7c => "OP_SWAP",
        0x7d => "OP_TUCK",
        0x7e => "OP_CAT",
        0x7f => "OP_SPLIT",
        0x80 => "OP_NUM2BIN",
        0x81 => "OP_BIN2NUM",
        0x82 => "OP_SIZE",
        0x83 => "OP_INVERT",
        0x84 => "OP_AND",
        0x85 => "OP_OR",
        0x86 => "OP_XOR",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0x8b => "OP_1ADD",
        0x8c => "OP_1SUB",
        0x8f => "OP_NEGATE",
        0x90 => "OP_ABS",
        0x91 => "OP_NOT",
        0x92 => "OP_0NOTEQUAL",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0x95 => "OP_MUL",
        0x96 => "OP_DIV",
        0x97 => "OP_MOD",
        0x98 => "OP_LSHIFT",
        0x99 => "OP_RSHIFT",
        0x9a => "OP_BOOLAND",
        0x9b => "OP_BOOLOR",
        0x9c => "OP_NUMEQUAL",
        0x9d => "OP_NUMEQUALVERIFY",
        0x9e => "OP_NUMNOTEQUAL",
        0x9f => "OP_LESSTHAN",
        0xa0 => "OP_GREATERTHAN",
        0xa1 => "OP_LESSTHANOREQUAL",
        0xa2 => "OP_GREATERTHANOREQUAL",
        0xa3 => "OP_MIN",
        0xa4 => "OP_MAX",
        0xa5 => "OP_WITHIN",
        0xa6 => "OP_RIPEMD160",
        0xa7 => "OP_SHA1",
        0xa8 => "OP_SHA256",
        0xa9 => "OP_HASH160",
        0xaa => "OP_HASH256",
        0xab => "OP_CODESEPARATOR",
        0xac => "OP_CHECKSIG",
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG",
        0xaf => "OP_CHECKMULTISIGVERIFY",
        else => null,
    };
    if (fixed) |s| return try allocator.dupe(u8, s);

    // Direct push (0x01..0x4b) — name is "PUSH_<n>".
    if (byte >= 0x01 and byte <= 0x4b) {
        return try std.fmt.allocPrint(allocator, "PUSH_{d}", .{byte});
    }

    // OP_UNKNOWN(0xNN) — lowercase 2-digit hex.
    return try std.fmt.allocPrint(allocator, "OP_UNKNOWN(0x{x:0>2})", .{byte});
}

/// Normalize a hex script: strip ASCII whitespace, lowercase. Caller
/// owns the result.
pub fn normalizeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, hex.len);
    for (hex) |c| {
        switch (c) {
            ' ', '\t', '\n', '\r' => {},
            'A'...'Z' => try out.append(allocator, c + ('a' - 'A')),
            else => try out.append(allocator, c),
        }
    }
    return try out.toOwnedSlice(allocator);
}

/// Decode `hex` (already normalized) into an opcode list. Caller owns
/// each Opcode (via `deinit`) and the returned slice.
pub fn parseScript(allocator: std.mem.Allocator, hex: []const u8) ![]Opcode {
    // Convert hex to bytes.
    if (hex.len % 2 != 0) return error.OddHexLen;
    const byte_count = hex.len / 2;
    const bytes = try allocator.alloc(u8, byte_count);
    defer allocator.free(bytes);
    var i: usize = 0;
    while (i < byte_count) : (i += 1) {
        const hi = hexDigit(hex[i * 2]) catch return error.InvalidHex;
        const lo = hexDigit(hex[i * 2 + 1]) catch return error.InvalidHex;
        bytes[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }

    var ops = std.ArrayList(Opcode).empty;
    errdefer {
        for (ops.items) |op| op.deinit(allocator);
        ops.deinit(allocator);
    }

    var pos: usize = 0;
    while (pos < bytes.len) {
        const byte = bytes[pos];
        const start = pos;

        if (byte >= 0x01 and byte <= 0x4b) {
            // Direct push.
            const data_len: usize = byte;
            const data_start = pos + 1;
            const data_end_unclamped = data_start + data_len;
            const data_end = @min(data_end_unclamped, bytes.len);
            const actual_data_len: i64 = @intCast(data_end - data_start);
            const declared: i64 = @intCast(data_len);
            const size: i64 = @intCast(1 + (data_end - data_start));
            const name = try canonicalOpcodeName(allocator, byte);
            errdefer allocator.free(name);
            try ops.append(allocator, Opcode{
                .opcode = byte,
                .name = name,
                .offset = @intCast(start),
                .size = size,
                .data_length = if (data_end_unclamped <= bytes.len) declared else actual_data_len,
                .push_encoding = .direct,
            });
            pos = data_end;
            if (data_end_unclamped > bytes.len) break; // Truncated push — stop parsing.
        } else if (byte == 0x4c) {
            // OP_PUSHDATA1
            if (pos + 1 >= bytes.len) {
                // No length byte — emit with available 0-length data and stop.
                const name = try canonicalOpcodeName(allocator, byte);
                try ops.append(allocator, Opcode{
                    .opcode = byte,
                    .name = name,
                    .offset = @intCast(start),
                    .size = @intCast(bytes.len - start),
                    .data_length = 0,
                    .push_encoding = .pushdata1,
                });
                break;
            }
            const data_len: usize = bytes[pos + 1];
            const data_start = pos + 2;
            const data_end_unclamped = data_start + data_len;
            const data_end = @min(data_end_unclamped, bytes.len);
            const declared: i64 = @intCast(data_len);
            const size: i64 = @intCast(2 + (data_end - data_start));
            const name = try canonicalOpcodeName(allocator, byte);
            try ops.append(allocator, Opcode{
                .opcode = byte,
                .name = name,
                .offset = @intCast(start),
                .size = size,
                .data_length = declared,
                .push_encoding = .pushdata1,
            });
            pos = data_end;
            if (data_end_unclamped > bytes.len) break;
        } else if (byte == 0x4d) {
            // OP_PUSHDATA2 — LE 2-byte length.
            if (pos + 2 >= bytes.len) {
                const name = try canonicalOpcodeName(allocator, byte);
                try ops.append(allocator, Opcode{
                    .opcode = byte,
                    .name = name,
                    .offset = @intCast(start),
                    .size = @intCast(bytes.len - start),
                    .data_length = 0,
                    .push_encoding = .pushdata2,
                });
                break;
            }
            const lo: u16 = bytes[pos + 1];
            const hi: u16 = bytes[pos + 2];
            const data_len: usize = lo | (hi << 8);
            const data_start = pos + 3;
            const data_end_unclamped = data_start + data_len;
            const data_end = @min(data_end_unclamped, bytes.len);
            const declared: i64 = @intCast(data_len);
            const size: i64 = @intCast(3 + (data_end - data_start));
            const name = try canonicalOpcodeName(allocator, byte);
            try ops.append(allocator, Opcode{
                .opcode = byte,
                .name = name,
                .offset = @intCast(start),
                .size = size,
                .data_length = declared,
                .push_encoding = .pushdata2,
            });
            pos = data_end;
            if (data_end_unclamped > bytes.len) break;
        } else if (byte == 0x4e) {
            // OP_PUSHDATA4 — LE 4-byte length.
            if (pos + 4 >= bytes.len) {
                const name = try canonicalOpcodeName(allocator, byte);
                try ops.append(allocator, Opcode{
                    .opcode = byte,
                    .name = name,
                    .offset = @intCast(start),
                    .size = @intCast(bytes.len - start),
                    .data_length = 0,
                    .push_encoding = .pushdata4,
                });
                break;
            }
            const b0: u32 = bytes[pos + 1];
            const b1: u32 = bytes[pos + 2];
            const b2: u32 = bytes[pos + 3];
            const b3: u32 = bytes[pos + 4];
            const data_len: usize = @intCast(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24));
            const data_start = pos + 5;
            const data_end_unclamped = data_start + data_len;
            const data_end = @min(data_end_unclamped, bytes.len);
            const declared: i64 = @intCast(data_len);
            const size: i64 = @intCast(5 + (data_end - data_start));
            const name = try canonicalOpcodeName(allocator, byte);
            try ops.append(allocator, Opcode{
                .opcode = byte,
                .name = name,
                .offset = @intCast(start),
                .size = size,
                .data_length = declared,
                .push_encoding = .pushdata4,
            });
            pos = data_end;
            if (data_end_unclamped > bytes.len) break;
        } else {
            // Single-byte opcode (incl. opN, control flow, arithmetic, etc.)
            const name = try canonicalOpcodeName(allocator, byte);
            const enc: PushEncoding = if (byte == 0x00 or byte == 0x4f or (byte >= 0x51 and byte <= 0x60)) .op_n else .none;
            try ops.append(allocator, Opcode{
                .opcode = byte,
                .name = name,
                .offset = @intCast(start),
                .size = 1,
                .data_length = null,
                .push_encoding = enc,
            });
            pos += 1;
        }
    }

    return try ops.toOwnedSlice(allocator);
}

fn hexDigit(c: u8) !u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => error.InvalidHex,
    };
}

/// Collapse rawScriptSpan ranges into synthetic RAW_SPAN steps (spec §12).
/// Caller owns returned slice; input `ops` ownership is transferred — any
/// opcodes not emitted into the output are freed inline.
pub fn collapseRawScriptSpans(
    allocator: std.mem.Allocator,
    ops: []Opcode,
    spans_in: []const RawScriptSpan,
) ![]Opcode {
    if (spans_in.len == 0) return ops;

    // Sort spans by offset ascending — copy to mutable local.
    const spans = try allocator.dupe(RawScriptSpan, spans_in);
    defer allocator.free(spans);
    std.mem.sort(RawScriptSpan, spans, {}, struct {
        fn lt(_: void, a: RawScriptSpan, b: RawScriptSpan) bool {
            return a.offset < b.offset;
        }
    }.lt);

    var out = std.ArrayList(Opcode).empty;
    errdefer {
        for (out.items) |op| op.deinit(allocator);
        out.deinit(allocator);
    }

    var span_idx: usize = 0;
    var last_emitted_span_offset: ?i64 = null;

    for (ops) |op| {
        // Advance past spans whose end <= op.offset.
        while (span_idx < spans.len and spans[span_idx].offset + spans[span_idx].length <= op.offset) {
            span_idx += 1;
        }
        if (span_idx >= spans.len) {
            try out.append(allocator, op);
            continue;
        }
        const span = spans[span_idx];
        const span_end = span.offset + span.length;

        if (op.offset + op.size <= span.offset) {
            try out.append(allocator, op);
            continue;
        }

        if (op.offset >= span.offset and op.offset + op.size <= span_end) {
            // Entirely inside — drop. Emit synthetic step once per span.
            op.deinit(allocator);
            if (last_emitted_span_offset == null or last_emitted_span_offset.? != span.offset) {
                const name = try allocator.dupe(u8, "RAW_SPAN");
                try out.append(allocator, Opcode{
                    .opcode = -1,
                    .name = name,
                    .offset = span.offset,
                    .size = span.length,
                    .data_length = null,
                    .push_encoding = .none,
                    .raw_span_arity = .{ span.in_arity, span.out_arity },
                });
                last_emitted_span_offset = span.offset;
            }
        } else {
            // Partial overlap — drop; emit synthetic step once.
            op.deinit(allocator);
            if (last_emitted_span_offset == null or last_emitted_span_offset.? != span.offset) {
                const name = try allocator.dupe(u8, "RAW_SPAN");
                try out.append(allocator, Opcode{
                    .opcode = -1,
                    .name = name,
                    .offset = span.offset,
                    .size = span.length,
                    .data_length = null,
                    .push_encoding = .none,
                    .raw_span_arity = .{ span.in_arity, span.out_arity },
                });
                last_emitted_span_offset = span.offset;
            }
        }
    }

    // Free outer slice (Opcode items have been transferred to `out` or deinit'd).
    allocator.free(ops);
    return try out.toOwnedSlice(allocator);
}

test "canonical opcode names" {
    const a = std.testing.allocator;
    const n1 = try canonicalOpcodeName(a, 0x00);
    defer a.free(n1);
    try std.testing.expectEqualStrings("OP_0", n1);
    const n2 = try canonicalOpcodeName(a, 0x51);
    defer a.free(n2);
    try std.testing.expectEqualStrings("OP_1", n2);
    const n3 = try canonicalOpcodeName(a, 0x14);
    defer a.free(n3);
    try std.testing.expectEqualStrings("PUSH_20", n3);
    const n4 = try canonicalOpcodeName(a, 0x62);
    defer a.free(n4);
    try std.testing.expectEqualStrings("OP_UNKNOWN(0x62)", n4);
    const n5 = try canonicalOpcodeName(a, 0xab);
    defer a.free(n5);
    try std.testing.expectEqualStrings("OP_CODESEPARATOR", n5);
}

test "normalize hex strips whitespace + lowercases" {
    const a = std.testing.allocator;
    const out = try normalizeHex(a, "  76A9 88AC\n");
    defer a.free(out);
    try std.testing.expectEqualStrings("76a988ac", out);
}

test "parseScript basic p2pkh" {
    const a = std.testing.allocator;
    const ops = try parseScript(a, "76a90088ac");
    defer {
        for (ops) |op| op.deinit(a);
        a.free(ops);
    }
    try std.testing.expectEqual(@as(usize, 5), ops.len);
    try std.testing.expectEqual(@as(i32, 0x76), ops[0].opcode);
    try std.testing.expectEqualStrings("OP_DUP", ops[0].name);
    try std.testing.expectEqualStrings("OP_HASH160", ops[1].name);
    try std.testing.expectEqualStrings("OP_0", ops[2].name);
    try std.testing.expectEqualStrings("OP_EQUALVERIFY", ops[3].name);
    try std.testing.expectEqualStrings("OP_CHECKSIG", ops[4].name);
    try std.testing.expectEqual(@as(i64, 0), ops[0].offset);
    try std.testing.expectEqual(@as(i64, 4), ops[4].offset);
}

test "parseScript direct push with data" {
    const a = std.testing.allocator;
    // PUSH_2 0xab 0xcd
    const ops = try parseScript(a, "02abcd");
    defer {
        for (ops) |op| op.deinit(a);
        a.free(ops);
    }
    try std.testing.expectEqual(@as(usize, 1), ops.len);
    try std.testing.expectEqualStrings("PUSH_2", ops[0].name);
    try std.testing.expectEqual(@as(i64, 3), ops[0].size);
    try std.testing.expectEqual(@as(i64, 2), ops[0].data_length.?);
}

test "parseScript truncated push" {
    const a = std.testing.allocator;
    // PUSH_10 with only 2 bytes of data — declared 10, actual 2.
    const ops = try parseScript(a, "0aabcd");
    defer {
        for (ops) |op| op.deinit(a);
        a.free(ops);
    }
    try std.testing.expectEqual(@as(usize, 1), ops.len);
    try std.testing.expectEqualStrings("PUSH_10", ops[0].name);
    // data_length reflects actual bytes available.
    try std.testing.expectEqual(@as(i64, 2), ops[0].data_length.?);
}

test "parseScript pushdata1" {
    const a = std.testing.allocator;
    // OP_PUSHDATA1 0x05 <5 bytes>
    const ops = try parseScript(a, "4c050102030405");
    defer {
        for (ops) |op| op.deinit(a);
        a.free(ops);
    }
    try std.testing.expectEqual(@as(usize, 1), ops.len);
    try std.testing.expectEqualStrings("OP_PUSHDATA1", ops[0].name);
    try std.testing.expectEqual(@as(i64, 5), ops[0].data_length.?);
    try std.testing.expectEqual(@as(i64, 7), ops[0].size);
}
