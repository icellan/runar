const std = @import("std");
const registry = @import("crypto_builtins.zig");

const Allocator = std.mem.Allocator;

pub const PushValue = union(enum) {
    bytes: []const u8,
    integer: i64,
    boolean: bool,
};

pub const StackIf = struct {
    then: []StackOp,
    @"else": ?[]StackOp = null,
};

pub const StackOp = union(enum) {
    push: PushValue,
    dup: void,
    swap: void,
    drop: void,
    nip: void,
    over: void,
    rot: void,
    tuck: void,
    roll: u32,
    pick: u32,
    opcode: []const u8,
    @"if": StackIf,
};

const FIELD_P_MINUS_2_LOW_BITS: u32 = 0xfffffc2d;

const field_p_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
};

const curve_n_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

const curve_3n_script_num_le = [_]u8{
    0xc3, 0xc3, 0xa2, 0x70, 0xa6, 0x1b, 0x77, 0x3f,
    0xb3, 0xe0, 0xd9, 0x0d, 0xb4, 0x96, 0x0c, 0x30,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x02,
};

const gen_x_be = [_]u8{
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
};

const gen_y_be = [_]u8{
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
};

pub const EcEmitterError = anyerror;

pub const EcOpBundle = struct {
    allocator: Allocator,
    ops: []StackOp,
    owned_bytes: [][]u8,

    pub fn deinit(self: *EcOpBundle) void {
        deinitOpsRecursive(self.allocator, self.ops);
        self.allocator.free(self.ops);
        for (self.owned_bytes) |bytes| self.allocator.free(bytes);
        self.allocator.free(self.owned_bytes);
        self.* = undefined;
    }
};

pub fn buildBuiltinOps(allocator: Allocator, builtin: registry.CryptoBuiltin) EcEmitterError!EcOpBundle {
    var tracker = try ECTracker.init(allocator, initialNames(builtin));
    errdefer tracker.deinit();

    switch (builtin) {
        .ec_add => try emitEcAdd(&tracker),
        .ec_mul => try emitEcMul(&tracker, "_pt", "_k"),
        .ec_mul_gen => try emitEcMulGen(&tracker),
        .ec_negate => try emitEcNegate(&tracker),
        .ec_on_curve => try emitEcOnCurve(&tracker),
        else => return error.UnsupportedBuiltin,
    }

    return tracker.takeBundle();
}

pub fn appendBuiltinOps(
    list: *std.ArrayListUnmanaged(StackOp),
    allocator: Allocator,
    builtin: registry.CryptoBuiltin,
) EcEmitterError!EcOpBundle {
    var bundle = try buildBuiltinOps(allocator, builtin);
    errdefer bundle.deinit();
    try list.appendSlice(allocator, bundle.ops);
    return bundle;
}

pub fn deinitOpsRecursive(allocator: Allocator, ops: []StackOp) void {
    for (ops) |*op| {
        switch (op.*) {
            .@"if" => |stack_if| {
                deinitOpsRecursive(allocator, stack_if.then);
                allocator.free(stack_if.then);
                if (stack_if.@"else") |else_ops| {
                    deinitOpsRecursive(allocator, else_ops);
                    allocator.free(else_ops);
                }
            },
            else => {},
        }
    }
}

const ECTracker = struct {
    allocator: Allocator,
    names: std.ArrayListUnmanaged(?[]const u8),
    ops: std.ArrayListUnmanaged(StackOp),
    owned_bytes: std.ArrayListUnmanaged([]u8),

    fn init(allocator: Allocator, initial_names: []const ?[]const u8) !ECTracker {
        var names: std.ArrayListUnmanaged(?[]const u8) = .empty;
        errdefer names.deinit(allocator);
        try names.appendSlice(allocator, initial_names);
        return .{
            .allocator = allocator,
            .names = names,
            .ops = .empty,
            .owned_bytes = .empty,
        };
    }

    fn deinit(self: *ECTracker) void {
        deinitOpsRecursive(self.allocator, self.ops.items);
        self.ops.deinit(self.allocator);
        self.names.deinit(self.allocator);
        for (self.owned_bytes.items) |bytes| self.allocator.free(bytes);
        self.owned_bytes.deinit(self.allocator);
    }

    fn takeBundle(self: *ECTracker) !EcOpBundle {
        const ops = try self.ops.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(ops);
        const owned_bytes = try self.owned_bytes.toOwnedSlice(self.allocator);
        self.names.deinit(self.allocator);
        self.names = .empty;
        self.ops = .empty;
        self.owned_bytes = .empty;
        return .{
            .allocator = self.allocator,
            .ops = ops,
            .owned_bytes = owned_bytes,
        };
    }

    fn depth(self: *const ECTracker) usize {
        return self.names.items.len;
    }

    fn findDepth(self: *const ECTracker, name: []const u8) !usize {
        var i = self.names.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.names.items[i] orelse continue;
            if (std.mem.eql(u8, slot, name)) {
                return self.names.items.len - 1 - i;
            }
        }
        return error.UnsupportedBuiltin;
    }

    fn emitRaw(self: *ECTracker, op: StackOp) !void {
        try self.ops.append(self.allocator, op);
    }

    fn emitOpcode(self: *ECTracker, code: []const u8) !void {
        try self.emitRaw(.{ .opcode = code });
    }

    fn emitPushIntRaw(self: *ECTracker, value: i64) !void {
        try self.emitRaw(.{ .push = .{ .integer = value } });
    }

    fn emitPushBytesRaw(self: *ECTracker, value: []const u8) !void {
        try self.emitRaw(.{ .push = .{ .bytes = value } });
    }

    fn pushInt(self: *ECTracker, name: ?[]const u8, value: i64) !void {
        try self.emitPushIntRaw(value);
        try self.names.append(self.allocator, name);
    }

    fn pushOwnedBytes(self: *ECTracker, name: ?[]const u8, value: []u8) !void {
        try self.owned_bytes.append(self.allocator, value);
        try self.emitPushBytesRaw(value);
        try self.names.append(self.allocator, name);
    }

    fn pushStaticBytes(self: *ECTracker, name: ?[]const u8, value: []const u8) !void {
        try self.emitPushBytesRaw(value);
        try self.names.append(self.allocator, name);
    }

    fn dup(self: *ECTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .dup = {} });
        try self.names.append(self.allocator, name);
    }

    fn drop(self: *ECTracker) !void {
        try self.emitRaw(.{ .drop = {} });
        _ = self.names.pop();
    }

    fn swap(self: *ECTracker) !void {
        try self.emitRaw(.{ .swap = {} });
        const len = self.names.items.len;
        if (len >= 2) {
            const tmp = self.names.items[len - 1];
            self.names.items[len - 1] = self.names.items[len - 2];
            self.names.items[len - 2] = tmp;
        }
    }

    fn rot(self: *ECTracker) !void {
        try self.emitRaw(.{ .rot = {} });
        const len = self.names.items.len;
        if (len >= 3) {
            const rolled = self.names.orderedRemove(len - 3);
            try self.names.append(self.allocator, rolled);
        }
    }

    fn over(self: *ECTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .over = {} });
        try self.names.append(self.allocator, name);
    }

    fn roll(self: *ECTracker, depth_from_top: usize) !void {
        if (depth_from_top == 0) return;
        if (depth_from_top == 1) return self.swap();
        if (depth_from_top == 2) return self.rot();
        try self.emitRaw(.{ .roll = @intCast(depth_from_top) });
        const idx = self.names.items.len - 1 - depth_from_top;
        const rolled = self.names.orderedRemove(idx);
        try self.names.append(self.allocator, rolled);
    }

    fn pick(self: *ECTracker, depth_from_top: usize, name: ?[]const u8) !void {
        if (depth_from_top == 0) return self.dup(name);
        if (depth_from_top == 1) return self.over(name);
        try self.emitRaw(.{ .pick = @intCast(depth_from_top) });
        try self.names.append(self.allocator, name);
    }

    fn toTop(self: *ECTracker, name: []const u8) !void {
        try self.roll(try self.findDepth(name));
    }

    fn copyToTop(self: *ECTracker, name: []const u8, copy_name: ?[]const u8) !void {
        try self.pick(try self.findDepth(name), copy_name);
    }

    fn renameTop(self: *ECTracker, name: ?[]const u8) void {
        if (self.names.items.len > 0) {
            self.names.items[self.names.items.len - 1] = name;
        }
    }

    fn popNames(self: *ECTracker, count: usize) void {
        var i: usize = 0;
        while (i < count and self.names.items.len > 0) : (i += 1) {
            _ = self.names.pop();
        }
    }

    fn rawBlock(
        self: *ECTracker,
        consume_count: usize,
        produce_name: ?[]const u8,
        body: *const fn (*ECTracker) anyerror!void,
    ) !void {
        self.popNames(consume_count);
        try body(self);
        if (produce_name) |name| {
            try self.names.append(self.allocator, name);
        }
    }
};

fn initialNames(builtin: registry.CryptoBuiltin) []const ?[]const u8 {
    return switch (builtin) {
        .ec_add => &.{ "_pa", "_pb" },
        .ec_mul => &.{ "_pt", "_k" },
        .ec_mul_gen => &.{ "_k" },
        .ec_negate => &.{ "_pt" },
        .ec_on_curve => &.{ "_pt" },
        else => &.{},
    };
}

fn emitAddOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_ADD");
}

fn emitSubOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_SUB");
}

fn emitMulOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_MUL");
}

fn emitCatOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_CAT");
}

fn emitEqualOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_EQUAL");
}

fn emitDivOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_DIV");
}

fn emitModOpcode(t: *ECTracker) !void {
    try t.emitOpcode("OP_MOD");
}

fn emitFieldModSequence(t: *ECTracker) !void {
    try t.emitOpcode("OP_2DUP");
    try t.emitOpcode("OP_MOD");
    try t.emitRaw(.{ .rot = {} });
    try t.emitRaw(.{ .drop = {} });
    try t.emitRaw(.{ .over = {} });
    try t.emitOpcode("OP_ADD");
    try t.emitRaw(.{ .swap = {} });
    try t.emitOpcode("OP_MOD");
}

fn emitSplit32Sequence(t: *ECTracker) !void {
    try t.emitPushIntRaw(32);
    try t.emitOpcode("OP_SPLIT");
}

fn emitBytesToUnsignedNumSequence(t: *ECTracker) !void {
    try emitReverse32Raw(t);
    try t.emitPushBytesRaw(&.{0x00});
    try t.emitOpcode("OP_CAT");
    try t.emitOpcode("OP_BIN2NUM");
}

fn emitUnsignedNumToBigEndianBytes32Sequence(t: *ECTracker) !void {
    try t.emitPushIntRaw(33);
    try t.emitOpcode("OP_NUM2BIN");
    try t.emitPushIntRaw(32);
    try t.emitOpcode("OP_SPLIT");
    try t.emitRaw(.{ .drop = {} });
    try emitReverse32Raw(t);
}

fn emitReverse32Raw(t: *ECTracker) !void {
    try t.emitOpcode("OP_0");
    try t.emitRaw(.{ .swap = {} });
    for (0..32) |_| {
        try t.emitPushIntRaw(1);
        try t.emitOpcode("OP_SPLIT");
        try t.emitRaw(.{ .rot = {} });
        try t.emitRaw(.{ .rot = {} });
        try t.emitRaw(.{ .swap = {} });
        try t.emitOpcode("OP_CAT");
        try t.emitRaw(.{ .swap = {} });
    }
    try t.emitRaw(.{ .drop = {} });
}

fn beToUnsignedScriptNumAlloc(allocator: Allocator, be: []const u8) ![]u8 {
    var first: usize = 0;
    while (first < be.len and be[first] == 0) : (first += 1) {}
    if (first == be.len) {
        return allocator.dupe(u8, &.{});
    }

    const trimmed = be[first..];
    const needs_sign_byte = (trimmed[0] & 0x80) != 0;
    const out_len = trimmed.len + @as(usize, if (needs_sign_byte) 1 else 0);
    const out = try allocator.alloc(u8, out_len);
    for (trimmed, 0..) |_, idx| {
        out[idx] = trimmed[trimmed.len - 1 - idx];
    }
    if (needs_sign_byte) out[out_len - 1] = 0;
    return out;
}

fn pow2ScriptNumAlloc(allocator: Allocator, bit: usize) ![]u8 {
    const byte_index = bit / 8;
    const byte_mask: u8 = @as(u8, 1) << @intCast(bit % 8);
    const needs_sign_byte = byte_mask == 0x80;
    const out_len = byte_index + 1 + @as(usize, if (needs_sign_byte) 1 else 0);
    const out = try allocator.alloc(u8, out_len);
    @memset(out, 0);
    out[byte_index] = byte_mask;
    return out;
}

fn pushFieldPNum(t: *ECTracker, name: []const u8) !void {
    const encoded = try beToUnsignedScriptNumAlloc(t.allocator, field_p_be[0..]);
    try t.pushOwnedBytes(name, encoded);
}

fn pushCurveNNum(t: *ECTracker, name: []const u8) !void {
    const encoded = try beToUnsignedScriptNumAlloc(t.allocator, curve_n_be[0..]);
    try t.pushOwnedBytes(name, encoded);
}

fn pushPow2Divisor(t: *ECTracker, name: []const u8, bit: usize) !void {
    if (bit <= 4) {
        const value: i64 = @as(i64, 1) << @intCast(bit);
        try t.pushInt(name, value);
        return;
    }
    const encoded = try pow2ScriptNumAlloc(t.allocator, bit);
    try t.pushOwnedBytes(name, encoded);
}

fn generatorPointAlloc(allocator: Allocator) ![]u8 {
    const point = try allocator.alloc(u8, 64);
    @memcpy(point[0..32], gen_x_be[0..]);
    @memcpy(point[32..64], gen_y_be[0..]);
    return point;
}

fn fieldMod(t: *ECTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try pushFieldPNum(t, "_fmod_p");
    try t.rawBlock(2, result_name, emitFieldModSequence);
}

fn fieldAdd(t: *ECTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    try t.rawBlock(2, "_fadd_sum", emitAddOpcode);
    try fieldMod(t, "_fadd_sum", result_name);
}

fn fieldSub(t: *ECTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    try t.rawBlock(2, "_fsub_diff", emitSubOpcode);
    try fieldMod(t, "_fsub_diff", result_name);
}

fn fieldMul(t: *ECTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    try t.rawBlock(2, "_fmul_prod", emitMulOpcode);
    try fieldMod(t, "_fmul_prod", result_name);
}

fn fieldSqr(t: *ECTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_fsqr_copy");
    try fieldMul(t, a_name, "_fsqr_copy", result_name);
}

fn fieldInv(t: *ECTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_inv_r");

    var i: usize = 0;
    while (i < 222) : (i += 1) {
        try fieldSqr(t, "_inv_r", "_inv_r2");
        t.renameTop("_inv_r");
        try t.copyToTop(a_name, "_inv_a");
        try fieldMul(t, "_inv_r", "_inv_a", "_inv_m");
        t.renameTop("_inv_r");
    }

    try fieldSqr(t, "_inv_r", "_inv_r2");
    t.renameTop("_inv_r");

    var bit: i32 = 31;
    while (bit >= 0) : (bit -= 1) {
        try fieldSqr(t, "_inv_r", "_inv_r2");
        t.renameTop("_inv_r");
        if (((FIELD_P_MINUS_2_LOW_BITS >> @intCast(bit)) & 1) != 0) {
            try t.copyToTop(a_name, "_inv_a");
            try fieldMul(t, "_inv_r", "_inv_a", "_inv_m");
            t.renameTop("_inv_r");
        }
    }

    try t.toTop(a_name);
    try t.drop();
    try t.toTop("_inv_r");
    t.renameTop(result_name);
}

fn decomposePoint(t: *ECTracker, point_name: []const u8, x_name: []const u8, y_name: []const u8) !void {
    try t.toTop(point_name);
    t.popNames(1);
    try emitSplit32Sequence(t);
    try t.names.append(t.allocator, "_dp_xb");
    try t.names.append(t.allocator, "_dp_yb");

    try t.toTop("_dp_yb");
    try t.rawBlock(1, y_name, emitBytesToUnsignedNumSequence);

    try t.toTop("_dp_xb");
    try t.rawBlock(1, x_name, emitBytesToUnsignedNumSequence);
    try t.swap();
}

fn composePoint(t: *ECTracker, x_name: []const u8, y_name: []const u8, result_name: []const u8) !void {
    try t.toTop(x_name);
    try t.rawBlock(1, "_cp_xb", emitUnsignedNumToBigEndianBytes32Sequence);

    try t.toTop(y_name);
    try t.rawBlock(1, "_cp_yb", emitUnsignedNumToBigEndianBytes32Sequence);

    try t.toTop("_cp_xb");
    try t.toTop("_cp_yb");
    try t.rawBlock(2, result_name, emitCatOpcode);
}

fn affineAdd(t: *ECTracker) !void {
    try t.copyToTop("qy", "_qy1");
    try t.copyToTop("py", "_py1");
    try fieldSub(t, "_qy1", "_py1", "_s_num");

    try t.copyToTop("qx", "_qx1");
    try t.copyToTop("px", "_px1");
    try fieldSub(t, "_qx1", "_px1", "_s_den");

    try fieldInv(t, "_s_den", "_s_den_inv");
    try fieldMul(t, "_s_num", "_s_den_inv", "_s");

    try t.copyToTop("_s", "_s_keep");
    try fieldSqr(t, "_s", "_s2");
    try t.copyToTop("px", "_px2");
    try fieldSub(t, "_s2", "_px2", "_rx1");
    try t.copyToTop("qx", "_qx2");
    try fieldSub(t, "_rx1", "_qx2", "rx");

    try t.copyToTop("px", "_px3");
    try t.copyToTop("rx", "_rx2");
    try fieldSub(t, "_px3", "_rx2", "_px_rx");
    try fieldMul(t, "_s_keep", "_px_rx", "_s_px_rx");
    try t.copyToTop("py", "_py2");
    try fieldSub(t, "_s_px_rx", "_py2", "ry");

    try t.toTop("px");
    try t.drop();
    try t.toTop("py");
    try t.drop();
    try t.toTop("qx");
    try t.drop();
    try t.toTop("qy");
    try t.drop();
}

fn jacobianDouble(t: *ECTracker) !void {
    try t.copyToTop("jy", "_jy_save");
    try t.copyToTop("jx", "_jx_save");
    try t.copyToTop("jz", "_jz_save");

    try fieldSqr(t, "jy", "_A");

    try t.copyToTop("_A", "_A_save");
    try fieldMul(t, "jx", "_A", "_xA");
    try t.pushInt("_four", 4);
    try fieldMul(t, "_xA", "_four", "_B");

    try fieldSqr(t, "_A_save", "_A2");
    try t.pushInt("_eight", 8);
    try fieldMul(t, "_A2", "_eight", "_C");

    try fieldSqr(t, "_jx_save", "_x2");
    try t.pushInt("_three", 3);
    try fieldMul(t, "_x2", "_three", "_D");

    try t.copyToTop("_D", "_D_save");
    try t.copyToTop("_B", "_B_save");
    try fieldSqr(t, "_D", "_D2");
    try t.copyToTop("_B", "_B1");
    try t.pushInt("_two1", 2);
    try fieldMul(t, "_B1", "_two1", "_2B");
    try fieldSub(t, "_D2", "_2B", "_nx");

    try t.copyToTop("_nx", "_nx_copy");
    try fieldSub(t, "_B_save", "_nx_copy", "_B_nx");
    try fieldMul(t, "_D_save", "_B_nx", "_D_B_nx");
    try fieldSub(t, "_D_B_nx", "_C", "_ny");

    try fieldMul(t, "_jy_save", "_jz_save", "_yz");
    try t.pushInt("_two2", 2);
    try fieldMul(t, "_yz", "_two2", "_nz");

    try t.toTop("_B");
    try t.drop();
    try t.toTop("jz");
    try t.drop();
    try t.toTop("_nx");
    t.renameTop("jx");
    try t.toTop("_ny");
    t.renameTop("jy");
    try t.toTop("_nz");
    t.renameTop("jz");
}

fn jacobianToAffine(t: *ECTracker, rx_name: []const u8, ry_name: []const u8) !void {
    try fieldInv(t, "jz", "_zinv");
    try t.copyToTop("_zinv", "_zinv_keep");
    try fieldSqr(t, "_zinv", "_zinv2");
    try t.copyToTop("_zinv2", "_zinv2_keep");
    try fieldMul(t, "_zinv_keep", "_zinv2", "_zinv3");
    try fieldMul(t, "jx", "_zinv2_keep", rx_name);
    try fieldMul(t, "jy", "_zinv3", ry_name);
}

fn buildJacobianAddAffineInline(allocator: Allocator, base_names: []const ?[]const u8) !EcOpBundle {
    var inner = try ECTracker.init(allocator, base_names);
    errdefer inner.deinit();

    try inner.copyToTop("jz", "_jz_for_z1cu");
    try inner.copyToTop("jz", "_jz_for_z3");
    try inner.copyToTop("jy", "_jy_for_y3");
    try inner.copyToTop("jx", "_jx_for_u1h2");

    try fieldSqr(&inner, "jz", "_Z1sq");
    try inner.copyToTop("_Z1sq", "_Z1sq_for_u2");
    try fieldMul(&inner, "_jz_for_z1cu", "_Z1sq", "_Z1cu");

    try inner.copyToTop("ax", "_ax_c");
    try fieldMul(&inner, "_ax_c", "_Z1sq_for_u2", "_U2");

    try inner.copyToTop("ay", "_ay_c");
    try fieldMul(&inner, "_ay_c", "_Z1cu", "_S2");

    try fieldSub(&inner, "_U2", "jx", "_H");
    try fieldSub(&inner, "_S2", "jy", "_R");

    try inner.copyToTop("_H", "_H_for_h3");
    try inner.copyToTop("_H", "_H_for_z3");

    try fieldSqr(&inner, "_H", "_H2");
    try inner.copyToTop("_H2", "_H2_for_u1h2");

    try fieldMul(&inner, "_H_for_h3", "_H2", "_H3");
    try fieldMul(&inner, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2");

    try inner.copyToTop("_R", "_R_for_y3");
    try inner.copyToTop("_U1H2", "_U1H2_for_y3");
    try inner.copyToTop("_H3", "_H3_for_y3");

    try fieldSqr(&inner, "_R", "_R2");
    try fieldSub(&inner, "_R2", "_H3", "_x3_tmp");
    try inner.pushInt("_two", 2);
    try fieldMul(&inner, "_U1H2", "_two", "_2U1H2");
    try fieldSub(&inner, "_x3_tmp", "_2U1H2", "_X3");

    try inner.copyToTop("_X3", "_X3_c");
    try fieldSub(&inner, "_U1H2_for_y3", "_X3_c", "_u_minus_x");
    try fieldMul(&inner, "_R_for_y3", "_u_minus_x", "_r_tmp");
    try fieldMul(&inner, "_jy_for_y3", "_H3_for_y3", "_jy_h3");
    try fieldSub(&inner, "_r_tmp", "_jy_h3", "_Y3");

    try fieldMul(&inner, "_jz_for_z3", "_H_for_z3", "_Z3");

    try inner.toTop("_X3");
    inner.renameTop("jx");
    try inner.toTop("_Y3");
    inner.renameTop("jy");
    try inner.toTop("_Z3");
    inner.renameTop("jz");

    return inner.takeBundle();
}

fn emitEcAdd(t: *ECTracker) !void {
    try decomposePoint(t, "_pa", "px", "py");
    try decomposePoint(t, "_pb", "qx", "qy");
    try affineAdd(t);
    try composePoint(t, "rx", "ry", "_result");
}

fn emitEcMul(t: *ECTracker, point_name: []const u8, scalar_name: []const u8) !void {
    try decomposePoint(t, point_name, "ax", "ay");

    try t.toTop(scalar_name);
    try t.pushStaticBytes("_3n", curve_3n_script_num_le[0..]);
    try t.rawBlock(2, "_kn3", emitAddOpcode);
    t.renameTop("_k");

    try t.copyToTop("ax", "jx");
    try t.copyToTop("ay", "jy");
    try t.pushInt("jz", 1);

    var bit: i32 = 256;
    while (bit >= 0) : (bit -= 1) {
        try jacobianDouble(t);

        try t.copyToTop("_k", "_k_copy");
        if (bit > 0) {
            try pushPow2Divisor(t, "_div", @intCast(bit));
            try t.rawBlock(2, "_shifted", emitDivOpcode);
        } else {
            t.renameTop("_shifted");
        }
        try t.pushInt("_two", 2);
        try t.rawBlock(2, "_bit", emitModOpcode);

        try t.toTop("_bit");
        t.popNames(1);

        var add_bundle = try buildJacobianAddAffineInline(t.allocator, t.names.items);
        errdefer add_bundle.deinit();

        try t.owned_bytes.appendSlice(t.allocator, add_bundle.owned_bytes);
        t.allocator.free(add_bundle.owned_bytes);
        add_bundle.owned_bytes = &.{};

        try t.emitRaw(.{ .@"if" = .{ .then = add_bundle.ops, .@"else" = null } });
        add_bundle.ops = &.{};
    }

    try jacobianToAffine(t, "_rx", "_ry");

    try t.toTop("ax");
    try t.drop();
    try t.toTop("ay");
    try t.drop();
    try t.toTop("_k");
    try t.drop();

    try composePoint(t, "_rx", "_ry", "_result");
}

fn emitEcMulGen(t: *ECTracker) !void {
    const point = try generatorPointAlloc(t.allocator);
    try t.pushOwnedBytes("_pt", point);
    try t.swap();
    try emitEcMul(t, "_pt", "_k");
}

fn emitEcNegate(t: *ECTracker) !void {
    try decomposePoint(t, "_pt", "_nx", "_ny");
    try pushFieldPNum(t, "_fp");
    try fieldSub(t, "_fp", "_ny", "_neg_y");
    try composePoint(t, "_nx", "_neg_y", "_result");
}

fn emitEcOnCurve(t: *ECTracker) !void {
    try decomposePoint(t, "_pt", "_x", "_y");
    try fieldSqr(t, "_y", "_y2");

    try t.copyToTop("_x", "_x_copy");
    try fieldSqr(t, "_x", "_x2");
    try fieldMul(t, "_x2", "_x_copy", "_x3");
    try t.pushInt("_seven", 7);
    try fieldAdd(t, "_x3", "_seven", "_rhs");

    try t.toTop("_y2");
    try t.toTop("_rhs");
    try t.rawBlock(2, "_result", emitEqualOpcode);
}

fn containsOpcode(ops: []const StackOp, opcode: []const u8) bool {
    for (ops) |op| {
        switch (op) {
            .opcode => |value| if (std.mem.eql(u8, value, opcode)) return true,
            .@"if" => |stack_if| {
                if (containsOpcode(stack_if.then, opcode)) return true;
                if (stack_if.@"else") |else_ops| {
                    if (containsOpcode(else_ops, opcode)) return true;
                }
            },
            else => {},
        }
    }
    return false;
}

fn firstPushBytesLen(ops: []const StackOp) ?usize {
    for (ops) |op| {
        switch (op) {
            .push => |value| switch (value) {
                .bytes => |bytes| return bytes.len,
                else => {},
            },
            else => {},
        }
    }
    return null;
}

test "ec add helper emits affine split and compose flow" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_add);
    defer bundle.deinit();

    try std.testing.expect(bundle.ops.len > 0);
    try std.testing.expect(containsOpcode(bundle.ops, "OP_SPLIT"));
    try std.testing.expect(containsOpcode(bundle.ops, "OP_CAT"));
    try std.testing.expectEqualStrings("OP_CAT", bundle.ops[bundle.ops.len - 1].opcode);
}

test "ec mul helper emits 257 conditional additions" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_mul);
    defer bundle.deinit();

    var if_count: usize = 0;
    for (bundle.ops) |op| switch (op) {
        .@"if" => if_count += 1,
        else => {},
    };

    try std.testing.expectEqual(@as(usize, 257), if_count);
}

test "ec mul gen helper seeds the generator point" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_mul_gen);
    defer bundle.deinit();

    try std.testing.expect(bundle.ops.len > 2);
    try std.testing.expectEqual(@as(?usize, 64), firstPushBytesLen(bundle.ops));
    try std.testing.expect(containsOpcode(bundle.ops, "OP_SPLIT"));
}

test "ec on curve helper ends in equality" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_on_curve);
    defer bundle.deinit();

    try std.testing.expect(bundle.ops.len > 0);
    try std.testing.expectEqualStrings("OP_EQUAL", bundle.ops[bundle.ops.len - 1].opcode);
}

test "ec negate helper uses field-prime script number bytes" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_negate);
    defer bundle.deinit();

    var found = false;
    for (bundle.ops) |op| {
        switch (op) {
            .push => |value| switch (value) {
                .bytes => |bytes| {
                    if (bytes.len != 33) continue;
                    if (bytes[0] != 0x2f or bytes[1] != 0xfc or bytes[2] != 0xff or bytes[3] != 0xff or bytes[4] != 0xfe) continue;
                    if (bytes[32] != 0x00) continue;
                    found = true;
                    break;
                },
                else => {},
            },
            else => {},
        }
    }

    try std.testing.expect(found);
}

test "ec mul helper uses combined 3n scalar offset" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .ec_mul);
    defer bundle.deinit();

    var found = false;
    for (bundle.ops) |op| {
        switch (op) {
            .push => |value| switch (value) {
                .bytes => |bytes| {
                    if (std.mem.eql(u8, bytes, curve_3n_script_num_le[0..])) {
                        found = true;
                        break;
                    }
                },
                else => {},
            },
            else => {},
        }
    }

    try std.testing.expect(found);
}

test "field prime encoding uses initialized script number bytes" {
    const encoded = try beToUnsignedScriptNumAlloc(std.testing.allocator, field_p_be[0..]);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 33), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x2f), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0xfc), encoded[1]);
    try std.testing.expectEqual(@as(u8, 0xff), encoded[2]);
    try std.testing.expectEqual(@as(u8, 0xff), encoded[3]);
    try std.testing.expectEqual(@as(u8, 0xfe), encoded[4]);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[32]);
}

test "small power-of-two divisors use small-int pushes" {
    var tracker = try ECTracker.init(std.testing.allocator, &.{});
    defer tracker.deinit();

    try pushPow2Divisor(&tracker, "_pow2", 4);

    try std.testing.expectEqual(@as(usize, 1), tracker.ops.items.len);
    try std.testing.expectEqualDeep(StackOp{ .push = .{ .integer = 16 } }, tracker.ops.items[0]);
}
