const std = @import("std");
const registry = @import("crypto_builtins.zig");

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
        .ec_negate => try appendEcNegate(&builder),
        .ec_mod_reduce => try appendEcModReduce(&builder),
        .ec_encode_compressed => try appendEcEncodeCompressed(&builder),
        .ec_make_point => try appendEcMakePoint(&builder),
        .ec_point_x => try appendEcPointX(&builder),
        .ec_point_y => try appendEcPointY(&builder),
        else => return error.NotImplemented,
    }

    try list.appendSlice(allocator, builder.instructions.items);
}

pub fn appendVerifyRabinSig(builder: *Builder) !void {
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_ROT");
    try builder.emitOp("OP_DUP");
    try builder.emitOp("OP_MUL");
    try builder.emitOp("OP_ADD");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_SHA256");
    try builder.emitOp("OP_EQUAL");
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

pub fn appendEcEncodeCompressed(builder: *Builder) !void {
    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_SIZE");
    try builder.emitPushInt(1);
    try builder.emitOp("OP_SUB");
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_BIN2NUM");
    try builder.emitPushInt(2);
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DROP");
    try builder.emitOp("OP_IF");
    try builder.emitPushInt(3);
    try builder.emitOp("OP_ELSE");
    try builder.emitPushInt(2);
    try builder.emitOp("OP_ENDIF");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_CAT");
}

pub fn appendEcMakePoint(builder: *Builder) !void {
    try appendUnsignedNumToBigEndianBytes32(builder);
    try builder.emitOp("OP_SWAP");
    try appendUnsignedNumToBigEndianBytes32(builder);
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_CAT");
}

pub fn appendEcPointX(builder: *Builder) !void {
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
    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DROP");
    try appendBigEndianBytes32AsUnsignedNum(builder);
}

pub fn appendEcNegate(builder: *Builder) !void {
    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    try appendBigEndianBytes32AsUnsignedNum(builder);
    try builder.emitPushData(secp256k1_field_p_be[0..]);
    try appendBigEndianBytes32AsUnsignedNum(builder);
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_SUB");
    try builder.emitPushData(secp256k1_field_p_be[0..]);
    try appendBigEndianBytes32AsUnsignedNum(builder);
    try appendEcModReduce(builder);
    try appendUnsignedNumToBigEndianBytes32(builder);
    try builder.emitOp("OP_CAT");
}

pub fn builtinTodoNote(builtin: registry.CryptoBuiltin) ?[]const u8 {
    return switch (builtin) {
        .verify_wots => "verifyWOTS emitter is not implemented",
        .verify_slhdsa_sha2_128s,
        .verify_slhdsa_sha2_128f,
        .verify_slhdsa_sha2_192s,
        .verify_slhdsa_sha2_192f,
        .verify_slhdsa_sha2_256s,
        .verify_slhdsa_sha2_256f,
        => "SLH-DSA emitter is not implemented",
        .blake3_compress,
        .blake3_hash,
        .blake3,
        => "BLAKE3 emitter is not implemented",
        .ec_add,
        .ec_mul,
        .ec_mul_gen,
        .ec_on_curve,
        => "EC emitter is not implemented",
        else => null,
    };
}

test "implemented crypto emitters append instructions" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer list.deinit(allocator);

    try appendBuiltinInstructions(&list, allocator, .verify_rabin_sig);
    try std.testing.expect(list.items.len > 0);
    try std.testing.expectEqualStrings("OP_SWAP", list.items[0].op_name);
    try std.testing.expectEqualStrings("OP_EQUAL", list.items[list.items.len - 1].op_name);

    var negate_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer negate_list.deinit(allocator);
    try appendBuiltinInstructions(&negate_list, allocator, .ec_negate);
    try std.testing.expect(negate_list.items.len > 0);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 32 }, negate_list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_CAT" }, negate_list.items[negate_list.items.len - 1]);
}

test "scaffolded crypto emitters are explicit" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer list.deinit(allocator);

    try std.testing.expectError(error.NotImplemented, appendBuiltinInstructions(&list, allocator, .verify_wots));
    try std.testing.expectEqualStrings(
        "verifyWOTS emitter is not implemented",
        builtinTodoNote(.verify_wots).?,
    );
    try std.testing.expectEqual(@as(?[]const u8, null), builtinTodoNote(.ec_negate));
}

test "ec point helpers include numeric conversion steps" {
    const allocator = std.testing.allocator;

    var point_x_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer point_x_list.deinit(allocator);
    try appendBuiltinInstructions(&point_x_list, allocator, .ec_point_x);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 32 }, point_x_list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_BIN2NUM" }, point_x_list.items[point_x_list.items.len - 1]);

    var point_y_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer point_y_list.deinit(allocator);
    try appendBuiltinInstructions(&point_y_list, allocator, .ec_point_y);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 32 }, point_y_list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_BIN2NUM" }, point_y_list.items[point_y_list.items.len - 1]);

    var make_point_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer make_point_list.deinit(allocator);
    try appendBuiltinInstructions(&make_point_list, allocator, .ec_make_point);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 33 }, make_point_list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_CAT" }, make_point_list.items[make_point_list.items.len - 1]);

    var encode_compressed_list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer encode_compressed_list.deinit(allocator);
    try appendBuiltinInstructions(&encode_compressed_list, allocator, .ec_encode_compressed);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_IF" }, encode_compressed_list.items[11]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 3 }, encode_compressed_list.items[12]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_ELSE" }, encode_compressed_list.items[13]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 2 }, encode_compressed_list.items[14]);
}

test "ec negate helper emits field subtraction and reduction" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer list.deinit(allocator);

    try appendBuiltinInstructions(&list, allocator, .ec_negate);

    var saw_sub = false;
    var saw_mod = false;
    var prime_pushes: usize = 0;
    for (list.items) |inst| switch (inst) {
        .op_name => |name| {
            saw_sub = saw_sub or std.mem.eql(u8, name, "OP_SUB");
            saw_mod = saw_mod or std.mem.eql(u8, name, "OP_MOD");
        },
        .push_data => |data| {
            if (std.mem.eql(u8, data, secp256k1_field_p_be[0..])) {
                prime_pushes += 1;
            }
        },
        else => {},
    };

    try std.testing.expect(saw_sub);
    try std.testing.expect(saw_mod);
    try std.testing.expectEqual(@as(usize, 2), prime_pushes);
}
