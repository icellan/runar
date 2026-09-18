const std = @import("std");
const registry = @import("crypto_builtins.zig");
const rabin_emitter = @import("rabin_emitter.zig");

const Allocator = std.mem.Allocator;

const secp256k1_field_p_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
};

pub const CryptoInstruction = union(enum) {
    op_name: []const u8,
    push_int: i64,
    push_data: []const u8,
};

pub const CryptoEmitterError = error{
    OutOfMemory,
    NotImplemented,
};

const Builder = struct {
    allocator: Allocator,
    instructions: std.ArrayListUnmanaged(CryptoInstruction) = .empty,

    fn deinit(self: *Builder) void {
        self.instructions.deinit(self.allocator);
    }

    fn emitOp(self: *Builder, op_name: []const u8) !void {
        try self.instructions.append(self.allocator, .{ .op_name = op_name });
    }

    fn emitPushInt(self: *Builder, value: i64) !void {
        try self.instructions.append(self.allocator, .{ .push_int = value });
    }

    fn emitPushData(self: *Builder, value: []const u8) !void {
        try self.instructions.append(self.allocator, .{ .push_data = value });
    }
};

pub fn appendBuiltinInstructions(
    list: *std.ArrayListUnmanaged(CryptoInstruction),
    allocator: Allocator,
    builtin: registry.CryptoBuiltin,
) CryptoEmitterError!void {
    var builder = Builder{ .allocator = allocator };
    defer builder.deinit();

    switch (builtin) {
        .verify_rabin_sig => try appendVerifyRabinSig(&builder),
        .ec_mod_reduce => try appendEcModReduce(&builder),
        .ec_encode_compressed => try appendEcEncodeCompressed(&builder),
        .ec_make_point => try appendEcMakePoint(&builder),
        .ec_point_x => try appendEcPointX(&builder),
        .ec_point_y => try appendEcPointY(&builder),
        else => return error.NotImplemented,
    }

    try list.appendSlice(allocator, builder.instructions.items);
}

/// Rabin signature verification — delegates to the standalone
/// `rabin_emitter.zig` module so the 18-opcode sequence is owned in one place
/// (mirrors the standalone Rabin modules in the other compiler tiers).
pub fn appendVerifyRabinSig(builder: *Builder) !void {
    try rabin_emitter.append(&builder.instructions, builder.allocator);
}

pub fn appendEcModReduce(builder: *Builder) !void {
    try builder.emitOp("OP_2DUP");
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_ROT");
    try builder.emitOp("OP_DROP");
    try builder.emitOp("OP_OVER");
    try builder.emitOp("OP_ADD");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_MOD");
}

/// CL-BUG-095 — a `Point` is DEFINED as exactly `want` bytes (x ‖ y,
/// big-endian, no prefix) and nothing checked it. Surplus bytes were silently
/// DISCARDED, because the split at 32 keeps only what it asked for. Aborting is
/// right for these three consumers: they produce a VALUE and have no error
/// channel, and there is no correct value to return for a blob that is not a
/// point. See `emitPointLenVerify` in ec_emitters.zig for the full argument —
/// and note an UNDER-length point already aborted by accident (`OP_SPLIT` runs
/// off the end), so this adds no new failure channel.
fn appendPointLenVerify(builder: *Builder, want: i64) !void {
    try builder.emitOp("OP_SIZE");
    try builder.emitPushInt(want);
    try builder.emitOp("OP_NUMEQUALVERIFY");
}

pub fn appendEcEncodeCompressed(builder: *Builder) !void {
    // CL-BUG-095, and the reason this one is the sharpest edge of it: the parity
    // byte used to be taken from the blob's LAST byte (OP_SIZE 1 OP_SUB
    // OP_SPLIT), not from a fixed offset. So appending one byte FLIPPED THE SIGN
    // of the compressed encoding — the same 64-byte point compressed to 02‖x or
    // 03‖x at the caller's choice, and anything that hashes a compressed pubkey
    // (a P2PKH address, a commitment) became forgeable between the two
    // spellings. Two independent fixes, both kept: the width is verified, and
    // the parity byte is read from offset 31 of y whatever the caller sent.
    try appendPointLenVerify(builder, 64);
    // Split at 32: [x_bytes, y_bytes]
    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    // Take y[31] at a FIXED offset: [x_bytes, y_head, y_last]
    try builder.emitPushInt(31);
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_NIP"); // drop y_head
    // Stack: [x_bytes, last_byte]
    try builder.emitOp("OP_BIN2NUM");
    try builder.emitPushInt(2);
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_IF");
    try builder.emitPushInt(3);
    try builder.emitOp("OP_ELSE");
    try builder.emitPushInt(2);
    try builder.emitOp("OP_ENDIF");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_CAT");
}

/// p as a little-endian sign-magnitude script number: the 32 big-endian bytes
/// reversed, plus a 0x00 sign byte because the top byte is 0xff.
const secp256k1_field_p_script_num = blk: {
    var out: [33]u8 = undefined;
    for (secp256k1_field_p_be, 0..) |b, i| out[31 - i] = b;
    out[32] = 0x00;
    break :blk out;
};

/// R-156 -- verify that the script number on TOS is a FIELD ELEMENT, 0 <= v < p.
/// Leaves the value in place (OP_DUP feeds the check, OP_VERIFY consumes the
/// flag), so the caller's stack shape is unchanged.
///
/// ecMakePoint converts each coordinate with `push 33, OP_NUM2BIN, push 32,
/// OP_SPLIT, OP_DROP`. NUM2BIN(33) writes a 33-byte little-endian SIGN-MAGNITUDE
/// script number, so byte 32 is exactly where the sign bit lives AND where any
/// bits >= 2^256 land -- and the split drops precisely that byte. The result was
/// an ecMakePoint that is NOT INJECTIVE:
///
///     ecMakePoint( 1n, y) == ecMakePoint(-1n, y)            sign discarded
///     ecMakePoint( 1n, y) == ecMakePoint(1n + 2^256, y)     magnitude truncated
///     ecMakePoint( x,  y) == ecMakePoint(x, -y)             and on the y half
///
/// all three measured on @bsv/sdk's Spend. The y-half collision is the sharpest:
/// `ecMakePoint(x, 0n - y)` is how an author spells negation by hand, and it
/// silently produced (x, +y) -- the point being negated -- rather than (x, p-y).
///
/// R-117's coordinate-canonicity gate does not cover this and cannot: the bytes
/// emitted for -1n are the perfectly canonical encoding of 1, so no downstream
/// consumer can tell. The aliasing happens before any Point exists.
///
/// REJECT rather than reduce, for the reason R-117 gives: ecOnCurve answers "no"
/// to a coordinate outside [0, p), so reducing here would leave the constructor
/// and the predicate disagreeing about what a point is. Rejecting also restores
/// injectivity, which is the property the defect broke.
///
/// OP_WITHIN(v, 0, p) is `0 <= v < p` in one opcode -- the same half-open bound
/// the `within` builtin exposes to contract authors.
fn appendFieldElementVerify(builder: *Builder) !void {
    try builder.emitOp("OP_DUP");
    try builder.emitPushInt(0);
    try builder.emitPushData(secp256k1_field_p_script_num[0..]);
    try builder.emitOp("OP_WITHIN");
    try builder.emitOp("OP_VERIFY");
}

pub fn appendEcMakePoint(builder: *Builder) !void {
    // R-156: y must be a field element before its sign byte is dropped.
    try appendFieldElementVerify(builder);
    try appendUnsignedNumToBigEndianBytes32(builder);
    try builder.emitOp("OP_SWAP");
    // R-156: and so must x.
    try appendFieldElementVerify(builder);
    try appendUnsignedNumToBigEndianBytes32(builder);
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_CAT");
}

pub fn appendEcPointX(builder: *Builder) !void {
    // CL-BUG-095: a 32-byte blob used to SUCCEED here and return itself as x —
    // the split at 32 left an empty tail that OP_DROP happily removed. ecPointY
    // on the identical input already aborted, which is how the hole survived: a
    // short point looked "already rejected".
    try appendPointLenVerify(builder, 64);
    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_DROP");
    try appendBigEndianBytes32AsUnsignedNum(builder);
}

fn appendReverse32(builder: *Builder) !void {
    try builder.emitOp("OP_0");
    try builder.emitOp("OP_SWAP");
    for (0..32) |_| {
        try builder.emitPushInt(1);
        try builder.emitOp("OP_SPLIT");
        try builder.emitOp("OP_ROT");
        try builder.emitOp("OP_ROT");
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_SWAP");
    }
    try builder.emitOp("OP_DROP");
}

fn appendBigEndianBytes32AsUnsignedNum(builder: *Builder) !void {
    try appendReverse32(builder);
    try builder.emitPushData(&.{0x00});
    try builder.emitOp("OP_CAT");
    try builder.emitOp("OP_BIN2NUM");
}

fn appendUnsignedNumToBigEndianBytes32(builder: *Builder) !void {
    try builder.emitPushInt(33);
    try builder.emitOp("OP_NUM2BIN");
    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_DROP");
    try appendReverse32(builder);
}

pub fn appendEcPointY(builder: *Builder) !void {
    try appendPointLenVerify(builder, 64);
    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DROP");
    try appendBigEndianBytes32AsUnsignedNum(builder);
}

// R-265 / R-284: `appendEcNegate` used to live here — a SECOND ecNegate
// emitter, with a different op sequence from the live one, unreachable from
// compilation, and carrying two tests. `stack_lower.zig` routes `.ecNegate` to
// `lowerEcBuiltin`, i.e. to `ec_emitters.buildBuiltinOps`, the same way it
// routes `verify_wots` to `pq_emitters` — so this module refuses `.ec_negate`
// for exactly the reason it already refused `verify_wots`, and the tests below
// assert that rather than exercising an emitter nothing compiles with.
//
// ecNegate is the ONLY EC builtin routed away from this module: ec_mod_reduce,
// ec_encode_compressed, ec_make_point, ec_point_x and ec_point_y all still come
// through `lowerCryptoBuiltin` and are emitted here.


pub fn builtinTodoNote(builtin: registry.CryptoBuiltin) ?[]const u8 {
    // All crypto builtins are fully implemented. Operations not handled by
    // this module (crypto_emitters) are dispatched to dedicated emitters:
    //   - ec_add, ec_mul, ec_mul_gen, ec_on_curve → ec_emitters
    //   - blake3, blake3_compress, blake3_hash → blake3_emitters
    //   - verify_wots, verify_slhdsa_* → pq_emitters
    _ = builtin;
    return null;
}

test "implemented crypto emitters append instructions" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer list.deinit(allocator);

    try appendBuiltinInstructions(&list, allocator, .verify_rabin_sig);
    try std.testing.expect(list.items.len > 0);
    try std.testing.expectEqualStrings("OP_SWAP", list.items[0].op_name);
    // BUG-011: the sequence now ends with the NUMERIC compare, not the byte
    // compare it used to — see rabin_emitter.zig.
    try std.testing.expectEqualStrings("OP_NUMEQUAL", list.items[list.items.len - 1].op_name);

}

test "non-local crypto emitters return NotImplemented from this module" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer list.deinit(allocator);

    // verify_wots is implemented via pq_emitters, not crypto_emitters,
    // so appendBuiltinInstructions correctly returns NotImplemented here.
    // The actual dispatch in stack_lower.zig routes it to lowerPqBuiltin.
    try std.testing.expectError(error.NotImplemented, appendBuiltinInstructions(&list, allocator, .verify_wots));
    // R-265 / R-284: ec_negate is emitted by ec_emitters (stack_lower routes it
    // to lowerEcBuiltin), so this module refuses it for the same reason. It used
    // to answer with a second, different, uncompiled op sequence.
    try std.testing.expectError(error.NotImplemented, appendBuiltinInstructions(&list, allocator, .ec_negate));
    // All builtins are fully implemented (via their respective emitter modules)
    try std.testing.expectEqual(@as(?[]const u8, null), builtinTodoNote(.verify_wots));
    try std.testing.expectEqual(@as(?[]const u8, null), builtinTodoNote(.ec_negate));
    try std.testing.expectEqual(@as(?[]const u8, null), builtinTodoNote(.ec_add));
    try std.testing.expectEqual(@as(?[]const u8, null), builtinTodoNote(.blake3));
}

test "ec point helpers include numeric conversion steps" {
    const allocator = std.testing.allocator;

    var point_x_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer point_x_list.deinit(allocator);
    try appendBuiltinInstructions(&point_x_list, allocator, .ec_point_x);
    // CL-BUG-095: the width gate is the first thing emitted, before the split.
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_SIZE" }, point_x_list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 64 }, point_x_list.items[1]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_NUMEQUALVERIFY" }, point_x_list.items[2]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 32 }, point_x_list.items[3]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_BIN2NUM" }, point_x_list.items[point_x_list.items.len - 1]);

    var point_y_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer point_y_list.deinit(allocator);
    try appendBuiltinInstructions(&point_y_list, allocator, .ec_point_y);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_SIZE" }, point_y_list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 64 }, point_y_list.items[1]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_NUMEQUALVERIFY" }, point_y_list.items[2]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 32 }, point_y_list.items[3]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_BIN2NUM" }, point_y_list.items[point_y_list.items.len - 1]);

    var make_point_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer make_point_list.deinit(allocator);
    try appendBuiltinInstructions(&make_point_list, allocator, .ec_make_point);
    // R-156: the field-element gate is the first thing emitted, before the
    // NUM2BIN whose dropped sign byte was the defect. Five ops per coordinate,
    // and the y half is gated first because y is on top.
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_DUP" }, make_point_list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 0 }, make_point_list.items[1]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_data = secp256k1_field_p_script_num[0..] }, make_point_list.items[2]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_WITHIN" }, make_point_list.items[3]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_VERIFY" }, make_point_list.items[4]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 33 }, make_point_list.items[5]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_CAT" }, make_point_list.items[make_point_list.items.len - 1]);

    var encode_compressed_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer encode_compressed_list.deinit(allocator);
    try appendBuiltinInstructions(&encode_compressed_list, allocator, .ec_encode_compressed);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_IF" }, encode_compressed_list.items[11]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 3 }, encode_compressed_list.items[12]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_ELSE" }, encode_compressed_list.items[13]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 2 }, encode_compressed_list.items[14]);
}

// R-265 / R-284: a test named "ec negate helper emits field subtraction and
// reduction" used to live here. It was the second of the two tests that
// exercised the unreachable `appendEcNegate` — and it is the reason the finding
// could say this tier had more coverage of the emitter it does NOT use than of
// the one it does. The live emitter is `ec_emitters`; its ecNegate is covered by
// the cross-tier conformance corpus, which compares the bytes seven tiers
// actually produce.

