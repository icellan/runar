const std = @import("std");
const registry = @import("crypto_builtins.zig");
const crypto_emitters = @import("crypto_emitters.zig");

const Allocator = std.mem.Allocator;

pub const CryptoInstruction = crypto_emitters.CryptoInstruction;

pub const PqEmitterError = error{
    OutOfMemory,
    NotImplemented,
    UnknownParamKey,
};

pub const SLHCodegenParams = struct {
    n: usize,
    h: usize,
    d: usize,
    hp: usize,
    a: usize,
    k: usize,
    w: usize,
    len: usize,
    len1: usize,
    len2: usize,
};

const SLH_WOTS_HASH: usize = 0;
const SLH_WOTS_PK: usize = 1;
const SLH_TREE: usize = 2;
const SLH_FORS_TREE: usize = 3;
const SLH_FORS_ROOTS: usize = 4;

const wots_chain_step_bytes = buildWotsChainStepBytes();
const single_byte_values = buildSingleByteValues();
const be_u32_values = buildBeU32Values();
const zero_bytes_32 = [_]u8{0} ** 32;
const zero_bytes_40 = [_]u8{0} ** 40;
const zero_bytes_48 = [_]u8{0} ** 48;
const two_pow_63_script_num = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00 };

const Builder = struct {
    allocator: Allocator,
    instructions: std.ArrayListUnmanaged(CryptoInstruction) = .empty,

    fn deinit(self: *Builder) void {
        self.instructions.deinit(self.allocator);
    }

    fn emitOp(self: *Builder, op_name: []const u8) PqEmitterError!void {
        try self.instructions.append(self.allocator, .{ .op_name = op_name });
    }

    fn emitPushInt(self: *Builder, value: i64) PqEmitterError!void {
        try self.instructions.append(self.allocator, .{ .push_int = value });
    }

    fn emitPushData(self: *Builder, value: []const u8) PqEmitterError!void {
        try self.instructions.append(self.allocator, .{ .push_data = value });
    }
};

const SLHTracker = struct {
    allocator: Allocator,
    builder: *Builder,
    names: std.ArrayListUnmanaged(?[]const u8) = .empty,

    fn init(allocator: Allocator, builder: *Builder, initial: []const ?[]const u8) PqEmitterError!SLHTracker {
        var tracker = SLHTracker{
            .allocator = allocator,
            .builder = builder,
        };
        try tracker.names.appendSlice(allocator, initial);
        return tracker;
    }

    fn deinit(self: *SLHTracker) void {
        self.names.deinit(self.allocator);
    }

    fn depth(self: *const SLHTracker) usize {
        return self.names.items.len;
    }

    fn has(self: *const SLHTracker, name: []const u8) bool {
        return self.findDepth(name) != null;
    }

    fn findDepth(self: *const SLHTracker, name: []const u8) ?usize {
        var i = self.names.items.len;
        while (i > 0) {
            i -= 1;
            const entry = self.names.items[i] orelse continue;
            if (std.mem.eql(u8, entry, name)) {
                return self.names.items.len - 1 - i;
            }
        }
        return null;
    }

    fn pushName(self: *SLHTracker, name: ?[]const u8) PqEmitterError!void {
        try self.names.append(self.allocator, name);
    }

    fn popName(self: *SLHTracker) void {
        if (self.names.items.len == 0) return;
        _ = self.names.pop();
    }

    fn pushInt(self: *SLHTracker, name: ?[]const u8, value: i64) PqEmitterError!void {
        try self.builder.emitPushInt(value);
        try self.pushName(name);
    }

    fn pushZeroBytes(self: *SLHTracker, name: ?[]const u8, count: usize) PqEmitterError!void {
        switch (count) {
            32 => try self.builder.emitPushData(zero_bytes_32[0..]),
            40 => try self.builder.emitPushData(zero_bytes_40[0..]),
            48 => try self.builder.emitPushData(zero_bytes_48[0..]),
            else => {
                try self.builder.emitPushInt(0);
                try self.builder.emitPushInt(@intCast(count));
                try self.builder.emitOp("OP_NUM2BIN");
            },
        }
        try self.pushName(name);
    }

    fn op(self: *SLHTracker, code: []const u8) PqEmitterError!void {
        try self.builder.emitOp(code);
    }

    fn dup(self: *SLHTracker, name: ?[]const u8) PqEmitterError!void {
        try self.builder.emitOp("OP_DUP");
        try self.pushName(name);
    }

    fn drop(self: *SLHTracker) PqEmitterError!void {
        try self.builder.emitOp("OP_DROP");
        self.popName();
    }

    fn swap(self: *SLHTracker) PqEmitterError!void {
        try self.builder.emitOp("OP_SWAP");
        const len = self.names.items.len;
        if (len >= 2) {
            const tmp = self.names.items[len - 1];
            self.names.items[len - 1] = self.names.items[len - 2];
            self.names.items[len - 2] = tmp;
        }
    }

    fn rot(self: *SLHTracker) PqEmitterError!void {
        try self.builder.emitOp("OP_ROT");
        const len = self.names.items.len;
        if (len >= 3) {
            const idx = len - 3;
            const moved = self.names.orderedRemove(idx);
            try self.names.append(self.allocator, moved);
        }
    }

    fn nip(self: *SLHTracker) PqEmitterError!void {
        try self.builder.emitOp("OP_NIP");
        const len = self.names.items.len;
        if (len >= 2) {
            _ = self.names.orderedRemove(len - 2);
        }
    }

    fn over(self: *SLHTracker, name: ?[]const u8) PqEmitterError!void {
        try self.builder.emitOp("OP_OVER");
        try self.pushName(name);
    }

    fn roll(self: *SLHTracker, depth_from_top: usize) PqEmitterError!void {
        if (depth_from_top == 0) return;
        if (depth_from_top == 1) return self.swap();
        if (depth_from_top == 2) return self.rot();

        try self.builder.emitPushInt(@intCast(depth_from_top));
        try self.pushName(null);
        try self.builder.emitOp("OP_ROLL");
        self.popName();

        const len = self.names.items.len;
        const idx = len - 1 - depth_from_top;
        const moved = self.names.orderedRemove(idx);
        try self.names.append(self.allocator, moved);
    }

    fn pick(self: *SLHTracker, depth_from_top: usize, name: ?[]const u8) PqEmitterError!void {
        if (depth_from_top == 0) return self.dup(name);
        if (depth_from_top == 1) return self.over(name);

        try self.builder.emitPushInt(@intCast(depth_from_top));
        try self.pushName(null);
        try self.builder.emitOp("OP_PICK");
        self.popName();
        try self.pushName(name);
    }

    fn toTop(self: *SLHTracker, name: []const u8) PqEmitterError!void {
        const depth_from_top = self.findDepth(name) orelse return error.NotImplemented;
        try self.roll(depth_from_top);
    }

    fn copyToTop(self: *SLHTracker, name: []const u8, new_name: ?[]const u8) PqEmitterError!void {
        const depth_from_top = self.findDepth(name) orelse return error.NotImplemented;
        try self.pick(depth_from_top, new_name);
    }

    fn toAlt(self: *SLHTracker) PqEmitterError!void {
        try self.builder.emitOp("OP_TOALTSTACK");
        self.popName();
    }

    fn fromAlt(self: *SLHTracker, name: ?[]const u8) PqEmitterError!void {
        try self.builder.emitOp("OP_FROMALTSTACK");
        try self.pushName(name);
    }

    fn split(self: *SLHTracker, left: ?[]const u8, right: ?[]const u8) PqEmitterError!void {
        try self.builder.emitOp("OP_SPLIT");
        self.popName();
        self.popName();
        try self.pushName(left);
        try self.pushName(right);
    }

    fn cat(self: *SLHTracker, name: ?[]const u8) PqEmitterError!void {
        try self.builder.emitOp("OP_CAT");
        self.popName();
        self.popName();
        try self.pushName(name);
    }

    fn sha256(self: *SLHTracker, name: ?[]const u8) PqEmitterError!void {
        try self.builder.emitOp("OP_SHA256");
        self.popName();
        try self.pushName(name);
    }

    fn equal(self: *SLHTracker, name: ?[]const u8) PqEmitterError!void {
        try self.builder.emitOp("OP_EQUAL");
        self.popName();
        self.popName();
        try self.pushName(name);
    }

    fn rename(self: *SLHTracker, name: ?[]const u8) void {
        if (self.names.items.len == 0) return;
        self.names.items[self.names.items.len - 1] = name;
    }

    fn consumeProduce(self: *SLHTracker, consume_count: usize, produce: ?[]const u8) PqEmitterError!void {
        var i: usize = 0;
        while (i < consume_count) : (i += 1) self.popName();
        if (produce != null) {
            try self.pushName(produce);
        }
    }
};

fn slhMk(n: usize, h: usize, d: usize, a: usize, k: usize, len2: usize) SLHCodegenParams {
    const len1 = 2 * n;
    return .{
        .n = n,
        .h = h,
        .d = d,
        .hp = h / d,
        .a = a,
        .k = k,
        .w = 16,
        .len = len1 + len2,
        .len1 = len1,
        .len2 = len2,
    };
}

fn buildWotsChainStepBytes() [67][15][2]u8 {
    @setEvalBranchQuota(3000);
    var table: [67][15][2]u8 = undefined;
    for (0..67) |chain_index| {
        for (0..15) |step| {
            table[chain_index][step] = .{ @intCast(chain_index), @intCast(step) };
        }
    }
    return table;
}

fn buildSingleByteValues() [256][1]u8 {
    @setEvalBranchQuota(2000);
    var table: [256][1]u8 = undefined;
    for (0..256) |value| {
        table[value] = .{@intCast(value)};
    }
    return table;
}

fn buildBeU32Values() [256][4]u8 {
    @setEvalBranchQuota(2000);
    var table: [256][4]u8 = undefined;
    for (0..256) |value| {
        table[value] = .{ 0x00, 0x00, 0x00, @intCast(value) };
    }
    return table;
}

fn wotsChainStepBytes(chain_index: usize, step: usize) []const u8 {
    return (&wots_chain_step_bytes[chain_index][step])[0..];
}

pub fn lookupSLHParams(param_key: []const u8) ?SLHCodegenParams {
    if (std.mem.eql(u8, param_key, "SHA2_128s")) return slhMk(16, 63, 7, 12, 14, 3);
    if (std.mem.eql(u8, param_key, "SHA2_128f")) return slhMk(16, 66, 22, 6, 33, 3);
    if (std.mem.eql(u8, param_key, "SHA2_192s")) return slhMk(24, 63, 7, 14, 17, 3);
    if (std.mem.eql(u8, param_key, "SHA2_192f")) return slhMk(24, 66, 22, 8, 33, 3);
    if (std.mem.eql(u8, param_key, "SHA2_256s")) return slhMk(32, 64, 8, 14, 22, 3);
    if (std.mem.eql(u8, param_key, "SHA2_256f")) return slhMk(32, 68, 17, 8, 35, 3);
    return null;
}

pub fn appendReverseN(
    list: *std.ArrayListUnmanaged(CryptoInstruction),
    allocator: Allocator,
    n: usize,
) PqEmitterError!void {
    var builder = Builder{ .allocator = allocator };
    defer builder.deinit();

    try appendReverseNToBuilder(&builder, n);
    try list.appendSlice(allocator, builder.instructions.items);
}

fn appendReverseNToBuilder(builder: *Builder, n: usize) PqEmitterError!void {
    if (n <= 1) return;
    var i: usize = 0;
    while (i < n - 1) : (i += 1) {
        try builder.emitPushInt(1);
        try builder.emitOp("OP_SPLIT");
    }
    i = 0;
    while (i < n - 1) : (i += 1) {
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_CAT");
    }
}

pub fn appendBuildADRS18(
    list: *std.ArrayListUnmanaged(CryptoInstruction),
    allocator: Allocator,
    layer: usize,
    type_: usize,
    chain: usize,
    ta8_depth: usize,
    kp4_depth: ?usize,
) PqEmitterError!void {
    var builder = Builder{ .allocator = allocator };
    defer builder.deinit();

    try appendBuildADRS18ToBuilder(&builder, layer, type_, chain, ta8_depth, kp4_depth);

    try list.appendSlice(allocator, builder.instructions.items);
}

fn appendBuildADRS18ToBuilder(
    builder: *Builder,
    layer: usize,
    type_: usize,
    chain: usize,
    ta8_depth: usize,
    kp4_depth: ?usize,
) PqEmitterError!void {
    try appendAdrsByteToBuilder(builder, layer);
    try builder.emitPushInt(@intCast(ta8_depth + 1));
    try builder.emitOp("OP_PICK");
    try builder.emitOp("OP_CAT");

    try appendAdrsByteToBuilder(builder, type_);
    try builder.emitOp("OP_CAT");

    if (kp4_depth) |depth| {
        try builder.emitPushInt(@intCast(depth + 1));
        try builder.emitOp("OP_PICK");
    } else {
        try builder.emitPushData(&[_]u8{ 0, 0, 0, 0 });
    }
    try builder.emitOp("OP_CAT");

    try builder.emitPushData(beU32Bytes(chain));
    try builder.emitOp("OP_CAT");
}

fn appendAdrsByteToBuilder(builder: *Builder, value: usize) PqEmitterError!void {
    try builder.emitPushData(singleByteValue(value));
}

pub fn appendBuildADRS(
    list: *std.ArrayListUnmanaged(CryptoInstruction),
    allocator: Allocator,
    layer: usize,
    type_: usize,
    chain: usize,
    ta8_depth: usize,
    kp4_depth: ?usize,
    use_stack_hash: bool,
) PqEmitterError!void {
    var builder = Builder{ .allocator = allocator };
    defer builder.deinit();

    try appendBuildADRSToBuilder(&builder, layer, type_, chain, ta8_depth, kp4_depth, use_stack_hash);

    try list.appendSlice(allocator, builder.instructions.items);
}

fn appendBuildADRSToBuilder(
    builder: *Builder,
    layer: usize,
    type_: usize,
    chain: usize,
    ta8_depth: usize,
    kp4_depth: ?usize,
    use_stack_hash: bool,
) PqEmitterError!void {
    if (use_stack_hash) {
        try builder.emitOp("OP_TOALTSTACK");
        try appendBuildADRS18ToBuilder(builder, layer, type_, chain, ta8_depth - 1, if (kp4_depth) |depth| depth - 1 else null);
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_CAT");
    } else {
        try appendBuildADRS18ToBuilder(builder, layer, type_, chain, ta8_depth, kp4_depth);
        try builder.emitPushData(&[_]u8{ 0, 0, 0, 0 });
        try builder.emitOp("OP_CAT");
    }
}

fn appendBytesToUnsignedNumToBuilder(
    builder: *Builder,
    byte_len: usize,
    bit_count: usize,
) PqEmitterError!void {
    if (byte_len > 1) try appendReverseNToBuilder(builder, byte_len);
    try builder.emitPushInt(0);
    try builder.emitPushInt(1);
    try builder.emitOp("OP_NUM2BIN");
    try builder.emitOp("OP_CAT");
    try builder.emitOp("OP_BIN2NUM");
    if (bit_count < byte_len * 8) {
        try appendPowerOfTwoModulusToBuilder(builder, bit_count);
        try builder.emitOp("OP_MOD");
    }
}

fn appendPowerOfTwoModulusToBuilder(builder: *Builder, exponent: usize) PqEmitterError!void {
    if (exponent < 63) {
        try builder.emitPushInt(@intCast(@as(u64, 1) << @intCast(exponent)));
        return;
    }

    try builder.emitPushData(two_pow_63_script_num[0..]);
}

fn appendNumToBigEndianToBuilder(builder: *Builder, width: usize) PqEmitterError!void {
    try builder.emitPushInt(@intCast(width));
    try builder.emitOp("OP_NUM2BIN");
    try appendReverseNToBuilder(builder, width);
}

fn appendPreserveTopAndDropBelow(builder: *Builder, drop_count: usize) PqEmitterError!void {
    try builder.emitOp("OP_TOALTSTACK");
    var i: usize = 0;
    while (i + 1 < drop_count) : (i += 2) {
        try builder.emitOp("OP_2DROP");
    }
    if (i < drop_count) {
        try builder.emitOp("OP_DROP");
    }
    try builder.emitOp("OP_FROMALTSTACK");
}

fn emitSLHTRaw(builder: *Builder, n: usize, pk_seed_pad_depth: usize) PqEmitterError!void {
    try builder.emitOp("OP_CAT");
    const pick_depth = pk_seed_pad_depth - 1;
    try builder.emitPushInt(@intCast(pick_depth));
    try builder.emitOp("OP_PICK");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_CAT");
    try builder.emitOp("OP_SHA256");
    if (n < 32) {
        try builder.emitPushInt(@intCast(n));
        try builder.emitOp("OP_SPLIT");
        try builder.emitOp("OP_DROP");
    }
}

fn emitSLHTTracked(
    tracker: *SLHTracker,
    n: usize,
    adrs: []const u8,
    msg: []const u8,
    result: []const u8,
) PqEmitterError!void {
    try tracker.toTop(adrs);
    try tracker.toTop(msg);
    try tracker.cat("_am");
    try tracker.copyToTop("_pkSeedPad", "_psp");
    try tracker.swap();
    try tracker.cat("_pre");
    try tracker.sha256("_h32");
    if (n < 32) {
        try tracker.pushInt(null, @intCast(n));
        try tracker.split(result, "_tr");
        try tracker.drop();
    } else {
        tracker.rename(result);
    }
}

fn emitSLHOneChainClean(
    builder: *Builder,
    n: usize,
    layer: usize,
    chain_index: usize,
    pk_seed_pad_depth: usize,
    ta8_depth: usize,
    kp4_depth: usize,
) PqEmitterError!void {
    try builder.emitPushInt(15);
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_SUB");
    try builder.emitOp("OP_DUP");
    try builder.emitOp("OP_TOALTSTACK");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_TOALTSTACK");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_TOALTSTACK");

    try builder.emitOp("OP_SWAP");
    try builder.emitPushInt(@intCast(n));
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_TOALTSTACK");
    try builder.emitOp("OP_SWAP");

    try builder.emitOp("OP_DUP");
    try builder.emitPushInt(15);
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_SUB");

    const psp_chain_depth = pk_seed_pad_depth - 1;
    const ta8_chain_depth = ta8_depth - 1;
    const kp4_chain_depth = kp4_depth - 1;

    try appendBuildADRS18ToBuilder(builder, layer, SLH_WOTS_HASH, chain_index, ta8_chain_depth, kp4_chain_depth);
    try builder.emitOp("OP_TOALTSTACK");

    var then_ops: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer then_ops.deinit(builder.allocator);
    {
        var then_builder = Builder{ .allocator = builder.allocator };
        defer then_builder.deinit();
        try then_builder.emitOp("OP_DUP");
        try then_builder.emitPushInt(4);
        try then_builder.emitOp("OP_NUM2BIN");
        try appendReverseNToBuilder(&then_builder, 4);
        try then_builder.emitOp("OP_FROMALTSTACK");
        try then_builder.emitOp("OP_DUP");
        try then_builder.emitOp("OP_TOALTSTACK");
        try then_builder.emitOp("OP_SWAP");
        try then_builder.emitOp("OP_CAT");
        try then_builder.emitPushInt(3);
        try then_builder.emitOp("OP_ROLL");
        try then_builder.emitOp("OP_CAT");
        try then_builder.emitPushInt(@intCast(psp_chain_depth));
        try then_builder.emitOp("OP_PICK");
        try then_builder.emitOp("OP_SWAP");
        try then_builder.emitOp("OP_CAT");
        try then_builder.emitOp("OP_SHA256");
        if (n < 32) {
            try then_builder.emitPushInt(@intCast(n));
            try then_builder.emitOp("OP_SPLIT");
            try then_builder.emitOp("OP_DROP");
        }
        try then_builder.emitOp("OP_ROT");
        try then_builder.emitOp("OP_1SUB");
        try then_builder.emitOp("OP_ROT");
        try then_builder.emitOp("OP_1ADD");
        try then_ops.appendSlice(builder.allocator, then_builder.instructions.items);
    }

    var j: usize = 0;
    while (j < 15) : (j += 1) {
        try builder.emitOp("OP_OVER");
        try builder.emitOp("OP_0NOTEQUAL");
        try builder.emitOp("OP_IF");
        try builder.instructions.appendSlice(builder.allocator, then_ops.items);
        try builder.emitOp("OP_ENDIF");
    }

    try builder.emitOp("OP_DROP");
    try builder.emitOp("OP_DROP");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_DROP");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_ROT");
    try builder.emitOp("OP_ADD");
    try builder.emitOp("OP_SWAP");
    try builder.emitPushInt(3);
    try builder.emitOp("OP_ROLL");
    try builder.emitOp("OP_CAT");
}

fn emitSLHWotsAll(
    builder: *Builder,
    p: SLHCodegenParams,
    layer: usize,
) PqEmitterError!void {
    const n = p.n;
    const len1 = p.len1;
    const len2 = p.len2;

    try builder.emitOp("OP_SWAP");
    try builder.emitPushInt(0);
    try builder.emitOp("OP_0");
    try builder.emitPushInt(3);
    try builder.emitOp("OP_ROLL");

    var byte_idx: usize = 0;
    while (byte_idx < n) : (byte_idx += 1) {
        if (byte_idx < n - 1) {
            try builder.emitPushInt(1);
            try builder.emitOp("OP_SPLIT");
            try builder.emitOp("OP_SWAP");
        }
        try builder.emitPushInt(0);
        try builder.emitPushInt(1);
        try builder.emitOp("OP_NUM2BIN");
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_BIN2NUM");
        try builder.emitOp("OP_DUP");
        try builder.emitPushInt(16);
        try builder.emitOp("OP_DIV");
        try builder.emitOp("OP_SWAP");
        try builder.emitPushInt(16);
        try builder.emitOp("OP_MOD");

        if (byte_idx < n - 1) {
            try builder.emitOp("OP_TOALTSTACK");
            try builder.emitOp("OP_SWAP");
            try builder.emitOp("OP_TOALTSTACK");
        } else {
            try builder.emitOp("OP_TOALTSTACK");
        }

        try emitSLHOneChainClean(builder, n, layer, byte_idx * 2, 6, 5, 4);

        if (byte_idx < n - 1) {
            try builder.emitOp("OP_FROMALTSTACK");
            try builder.emitOp("OP_FROMALTSTACK");
            try builder.emitOp("OP_SWAP");
            try builder.emitOp("OP_TOALTSTACK");
        } else {
            try builder.emitOp("OP_FROMALTSTACK");
        }

        try emitSLHOneChainClean(builder, n, layer, byte_idx * 2 + 1, 6, 5, 4);

        if (byte_idx < n - 1) {
            try builder.emitOp("OP_FROMALTSTACK");
        }
    }

    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DUP");
    try builder.emitPushInt(16);
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_TOALTSTACK");
    try builder.emitOp("OP_DUP");
    try builder.emitPushInt(16);
    try builder.emitOp("OP_DIV");
    try builder.emitPushInt(16);
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_TOALTSTACK");
    try builder.emitPushInt(256);
    try builder.emitOp("OP_DIV");
    try builder.emitPushInt(16);
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_TOALTSTACK");

    var ci: usize = 0;
    while (ci < len2) : (ci += 1) {
        try builder.emitOp("OP_TOALTSTACK");
        try builder.emitPushInt(0);
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_FROMALTSTACK");
        try emitSLHOneChainClean(builder, n, layer, len1 + ci, 6, 5, 4);
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_DROP");
    }

    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DROP");
    try appendBuildADRSToBuilder(builder, layer, SLH_WOTS_PK, 0, 2, null, false);
    try builder.emitOp("OP_SWAP");
    try emitSLHTRaw(builder, n, 4);
}

fn emitSLHMerkle(
    builder: *Builder,
    p: SLHCodegenParams,
    layer: usize,
) PqEmitterError!void {
    const n = p.n;
    const hp = p.hp;

    try builder.emitOp("OP_ROT");
    try builder.emitOp("OP_TOALTSTACK");

    var j: usize = 0;
    while (j < hp) : (j += 1) {
        try builder.emitOp("OP_TOALTSTACK");
        try builder.emitPushInt(@intCast(n));
        try builder.emitOp("OP_SPLIT");
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_DUP");
        try builder.emitOp("OP_TOALTSTACK");
        if (j > 0) {
            try builder.emitPushInt(@intCast(@as(usize, 1) << @intCast(j)));
            try builder.emitOp("OP_DIV");
        }
        try builder.emitPushInt(2);
        try builder.emitOp("OP_MOD");

        var mk_tweak_hash: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
        defer mk_tweak_hash.deinit(builder.allocator);
        {
            var inner = Builder{ .allocator = builder.allocator };
            defer inner.deinit();
            try inner.emitOp("OP_FROMALTSTACK");
            try inner.emitOp("OP_DUP");
            try inner.emitOp("OP_TOALTSTACK");
            if (j + 1 > 0) {
                try inner.emitPushInt(@intCast(@as(usize, 1) << @intCast(j + 1)));
                try inner.emitOp("OP_DIV");
            }
            try inner.emitPushInt(4);
            try inner.emitOp("OP_NUM2BIN");
            try appendReverseNToBuilder(&inner, 4);
            try appendBuildADRSToBuilder(&inner, layer, SLH_TREE, j + 1, 4, null, true);
            try inner.emitOp("OP_SWAP");
            try emitSLHTRaw(&inner, n, 5);
            try mk_tweak_hash.appendSlice(builder.allocator, inner.instructions.items);
        }

        try builder.emitOp("OP_IF");
        try builder.emitOp("OP_CAT");
        try builder.instructions.appendSlice(builder.allocator, mk_tweak_hash.items);
        try builder.emitOp("OP_ELSE");
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_CAT");
        try builder.instructions.appendSlice(builder.allocator, mk_tweak_hash.items);
        try builder.emitOp("OP_ENDIF");
    }

    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_DROP");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DROP");
}

fn emitSLHFors(builder: *Builder, p: SLHCodegenParams) PqEmitterError!void {
    const n = p.n;
    const a = p.a;
    const k = p.k;

    try builder.emitOp("OP_TOALTSTACK");
    try builder.emitOp("OP_0");
    try builder.emitOp("OP_TOALTSTACK");

    var i: usize = 0;
    while (i < k) : (i += 1) {
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_DUP");
        try builder.emitOp("OP_TOALTSTACK");
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_TOALTSTACK");

        const bit_start = i * a;
        const byte_start = bit_start / 8;
        const bit_offset = bit_start % 8;
        const bits_in_first = @min(8 - bit_offset, a);
        const take = if (a > bits_in_first) @divFloor(bit_offset + a + 7, 8) else @as(usize, 1);

        if (byte_start > 0) {
            try builder.emitPushInt(@intCast(byte_start));
            try builder.emitOp("OP_SPLIT");
            try builder.emitOp("OP_NIP");
        }
        try builder.emitPushInt(@intCast(take));
        try builder.emitOp("OP_SPLIT");
        try builder.emitOp("OP_DROP");
        if (take > 1) try appendReverseNToBuilder(builder, take);
        try builder.emitPushInt(0);
        try builder.emitPushInt(1);
        try builder.emitOp("OP_NUM2BIN");
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_BIN2NUM");
        const total_bits = take * 8;
        const right_shift = total_bits - bit_offset - a;
        if (right_shift > 0) {
            try builder.emitPushInt(@intCast(@as(usize, 1) << @intCast(right_shift)));
            try builder.emitOp("OP_DIV");
        }
        try builder.emitPushInt(@intCast(@as(usize, 1) << @intCast(a)));
        try builder.emitOp("OP_MOD");
        try builder.emitOp("OP_TOALTSTACK");

        try builder.emitPushInt(@intCast(n));
        try builder.emitOp("OP_SPLIT");
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_DUP");
        try builder.emitOp("OP_TOALTSTACK");
        if (i > 0) {
            try builder.emitPushInt(@intCast(i * (@as(usize, 1) << @intCast(a))));
            try builder.emitOp("OP_ADD");
        }
        try builder.emitPushInt(4);
        try builder.emitOp("OP_NUM2BIN");
        try appendReverseNToBuilder(builder, 4);
        try appendBuildADRSToBuilder(builder, 0, SLH_FORS_TREE, 0, 4, 3, true);
        try builder.emitOp("OP_SWAP");
        try emitSLHTRaw(builder, n, 5);

        var j: usize = 0;
        while (j < a) : (j += 1) {
            try builder.emitOp("OP_TOALTSTACK");
            try builder.emitPushInt(@intCast(n));
            try builder.emitOp("OP_SPLIT");
            try builder.emitOp("OP_SWAP");
            try builder.emitOp("OP_FROMALTSTACK");
            try builder.emitOp("OP_FROMALTSTACK");
            try builder.emitOp("OP_DUP");
            try builder.emitOp("OP_TOALTSTACK");
            if (j > 0) {
                try builder.emitPushInt(@intCast(@as(usize, 1) << @intCast(j)));
                try builder.emitOp("OP_DIV");
            }
            try builder.emitPushInt(2);
            try builder.emitOp("OP_MOD");

            var auth_hash: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
            defer auth_hash.deinit(builder.allocator);
            {
                var inner = Builder{ .allocator = builder.allocator };
                defer inner.deinit();
                try inner.emitOp("OP_FROMALTSTACK");
                try inner.emitOp("OP_DUP");
                try inner.emitOp("OP_TOALTSTACK");
                if (j + 1 > 0) {
                    try inner.emitPushInt(@intCast(@as(usize, 1) << @intCast(j + 1)));
                    try inner.emitOp("OP_DIV");
                }
                const base = i * (@as(usize, 1) << @intCast(a - j - 1));
                if (base > 0) {
                    try inner.emitPushInt(@intCast(base));
                    try inner.emitOp("OP_ADD");
                }
                try inner.emitPushInt(4);
                try inner.emitOp("OP_NUM2BIN");
                try appendReverseNToBuilder(&inner, 4);
                try appendBuildADRSToBuilder(&inner, 0, SLH_FORS_TREE, j + 1, 4, 3, true);
                try inner.emitOp("OP_SWAP");
                try emitSLHTRaw(&inner, n, 5);
                try auth_hash.appendSlice(builder.allocator, inner.instructions.items);
            }

            try builder.emitOp("OP_IF");
            try builder.emitOp("OP_CAT");
            try builder.instructions.appendSlice(builder.allocator, auth_hash.items);
            try builder.emitOp("OP_ELSE");
            try builder.emitOp("OP_SWAP");
            try builder.emitOp("OP_CAT");
            try builder.instructions.appendSlice(builder.allocator, auth_hash.items);
            try builder.emitOp("OP_ENDIF");
        }

        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_DROP");
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_TOALTSTACK");
    }

    try builder.emitOp("OP_DROP");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_DROP");
    try appendBuildADRSToBuilder(builder, 0, SLH_FORS_ROOTS, 0, 2, 1, false);
    try builder.emitOp("OP_SWAP");
    try emitSLHTRaw(builder, n, 4);
}

fn emitSLHHmsg(builder: *Builder, out_len: usize) PqEmitterError!void {
    try builder.emitOp("OP_CAT");
    try builder.emitOp("OP_CAT");
    try builder.emitOp("OP_CAT");
    try builder.emitOp("OP_SHA256");

    const blocks = (out_len + 31) / 32;
    if (blocks == 1) {
        try builder.emitPushData(&[_]u8{ 0, 0, 0, 0 });
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_SHA256");
        if (out_len < 32) {
            try builder.emitPushInt(@intCast(out_len));
            try builder.emitOp("OP_SPLIT");
            try builder.emitOp("OP_DROP");
        }
        return;
    }

    try builder.emitOp("OP_0");
    try builder.emitOp("OP_SWAP");

    var ctr: usize = 0;
    while (ctr < blocks) : (ctr += 1) {
        if (ctr < blocks - 1) try builder.emitOp("OP_DUP");
        try builder.emitPushData(beU32Bytes(ctr));
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_SHA256");

        if (ctr == blocks - 1) {
            const rem = out_len - ctr * 32;
            if (rem < 32) {
                try builder.emitPushInt(@intCast(rem));
                try builder.emitOp("OP_SPLIT");
                try builder.emitOp("OP_DROP");
            }
        }

        if (ctr < blocks - 1) {
            try builder.emitOp("OP_ROT");
            try builder.emitOp("OP_SWAP");
            try builder.emitOp("OP_CAT");
            try builder.emitOp("OP_SWAP");
        } else {
            try builder.emitOp("OP_SWAP");
            try builder.emitOp("OP_CAT");
        }
    }
}

fn singleByteValue(value: usize) []const u8 {
    return (&single_byte_values[value & 0xff])[0..];
}

fn beU32Bytes(value: usize) []const u8 {
    return (&be_u32_values[value & 0xff])[0..];
}

fn appendWOTSOneChain(builder: *Builder, chain_index: usize) PqEmitterError!void {
    try builder.emitOp("OP_DUP");
    try builder.emitPushInt(15);
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_SUB");
    try builder.emitOp("OP_TOALTSTACK");

    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_TOALTSTACK");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_TOALTSTACK");

    try builder.emitOp("OP_SWAP");
    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_TOALTSTACK");
    try builder.emitOp("OP_SWAP");

    var j: usize = 0;
    while (j < 15) : (j += 1) {
        try builder.emitOp("OP_DUP");
        try builder.emitOp("OP_0NOTEQUAL");
        try builder.emitOp("OP_IF");
        try builder.emitOp("OP_1SUB");
        try builder.emitOp("OP_ELSE");
        try builder.emitOp("OP_SWAP");
        try builder.emitPushInt(2);
        try builder.emitOp("OP_PICK");
        try builder.emitPushData(wotsChainStepBytes(chain_index, j));
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_SHA256");
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_ENDIF");
    }
    try builder.emitOp("OP_DROP");

    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_FROMALTSTACK");

    try builder.emitOp("OP_ROT");
    try builder.emitOp("OP_ADD");

    try builder.emitOp("OP_SWAP");
    try builder.emitPushInt(3);
    try builder.emitOp("OP_ROLL");
    try builder.emitOp("OP_CAT");
}

pub fn appendVerifyWOTS(
    list: *std.ArrayListUnmanaged(CryptoInstruction),
    allocator: Allocator,
) PqEmitterError!void {
    var builder = Builder{ .allocator = allocator };
    defer builder.deinit();

    try builder.emitPushInt(32);
    try builder.emitOp("OP_SPLIT");
    try builder.emitOp("OP_TOALTSTACK");

    try builder.emitOp("OP_ROT");
    try builder.emitOp("OP_ROT");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_SHA256");

    try builder.emitOp("OP_SWAP");
    try builder.emitPushInt(0);
    try builder.emitOp("OP_0");
    try builder.emitPushInt(3);
    try builder.emitOp("OP_ROLL");

    var byte_idx: usize = 0;
    while (byte_idx < 32) : (byte_idx += 1) {
        if (byte_idx < 31) {
            try builder.emitPushInt(1);
            try builder.emitOp("OP_SPLIT");
            try builder.emitOp("OP_SWAP");
        }

        try builder.emitPushInt(0);
        try builder.emitPushInt(1);
        try builder.emitOp("OP_NUM2BIN");
        try builder.emitOp("OP_CAT");
        try builder.emitOp("OP_BIN2NUM");
        try builder.emitOp("OP_DUP");
        try builder.emitPushInt(16);
        try builder.emitOp("OP_DIV");
        try builder.emitOp("OP_SWAP");
        try builder.emitPushInt(16);
        try builder.emitOp("OP_MOD");

        if (byte_idx < 31) {
            try builder.emitOp("OP_TOALTSTACK");
            try builder.emitOp("OP_SWAP");
            try builder.emitOp("OP_TOALTSTACK");
        } else {
            try builder.emitOp("OP_TOALTSTACK");
        }

        try appendWOTSOneChain(&builder, byte_idx * 2);

        if (byte_idx < 31) {
            try builder.emitOp("OP_FROMALTSTACK");
            try builder.emitOp("OP_FROMALTSTACK");
            try builder.emitOp("OP_SWAP");
            try builder.emitOp("OP_TOALTSTACK");
        } else {
            try builder.emitOp("OP_FROMALTSTACK");
        }

        try appendWOTSOneChain(&builder, byte_idx * 2 + 1);

        if (byte_idx < 31) {
            try builder.emitOp("OP_FROMALTSTACK");
        }
    }

    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DUP");
    try builder.emitPushInt(16);
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_TOALTSTACK");

    try builder.emitOp("OP_DUP");
    try builder.emitPushInt(16);
    try builder.emitOp("OP_DIV");
    try builder.emitPushInt(16);
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_TOALTSTACK");

    try builder.emitPushInt(256);
    try builder.emitOp("OP_DIV");
    try builder.emitPushInt(16);
    try builder.emitOp("OP_MOD");
    try builder.emitOp("OP_TOALTSTACK");

    var ci: usize = 0;
    while (ci < 3) : (ci += 1) {
        try builder.emitOp("OP_TOALTSTACK");
        try builder.emitPushInt(0);
        try builder.emitOp("OP_FROMALTSTACK");
        try builder.emitOp("OP_FROMALTSTACK");
        try appendWOTSOneChain(&builder, 64 + ci);
        try builder.emitOp("OP_SWAP");
        try builder.emitOp("OP_DROP");
    }

    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DROP");
    try builder.emitOp("OP_SHA256");
    try builder.emitOp("OP_FROMALTSTACK");
    try builder.emitOp("OP_EQUAL");
    try builder.emitOp("OP_SWAP");
    try builder.emitOp("OP_DROP");

    try list.appendSlice(allocator, builder.instructions.items);
}

pub fn appendVerifySLHDSA(
    list: *std.ArrayListUnmanaged(CryptoInstruction),
    allocator: Allocator,
    param_key: []const u8,
) PqEmitterError!void {
    const p = lookupSLHParams(param_key) orelse return error.UnknownParamKey;

    const n = p.n;
    const d = p.d;
    const hp = p.hp;
    const k = p.k;
    const a = p.a;
    const len = p.len;
    const fors_sig_len = k * (1 + a) * n;
    const xmss_sig_len = (len + hp) * n;
    const md_len = (k * a + 7) / 8;
    const tree_idx_len = (p.h - hp + 7) / 8;
    const leaf_idx_len = (hp + 7) / 8;
    const digest_len = md_len + tree_idx_len + leaf_idx_len;

    var builder = Builder{ .allocator = allocator };
    defer builder.deinit();

    var tracker = try SLHTracker.init(allocator, &builder, &[_]?[]const u8{ "msg", "sig", "pubkey" });
    defer tracker.deinit();

    var owned_names: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (owned_names.items) |name| allocator.free(name);
        owned_names.deinit(allocator);
    }

    const NameFactory = struct {
        fn make(alloc: Allocator, owned: *std.ArrayListUnmanaged([]u8), comptime fmt: []const u8, args: anytype) PqEmitterError![]const u8 {
            const name = try std.fmt.allocPrint(alloc, fmt, args);
            errdefer alloc.free(name);
            try owned.append(alloc, name);
            return name;
        }
    };

    try tracker.toTop("pubkey");
    try tracker.pushInt(null, @intCast(n));
    try tracker.split("pkSeed", "pkRoot");

    try tracker.copyToTop("pkSeed", "_psp");
    if (64 > n) {
        try tracker.pushZeroBytes(null, 64 - n);
        try tracker.cat("_pkSeedPad");
    } else {
        tracker.rename("_pkSeedPad");
    }

    try tracker.toTop("sig");
    try tracker.pushInt(null, @intCast(n));
    try tracker.split("R", "sigRest");

    try tracker.copyToTop("R", "_R");
    try tracker.copyToTop("pkSeed", "_pks");
    try tracker.copyToTop("pkRoot", "_pkr");
    try tracker.copyToTop("msg", "_msg");
    try emitSLHHmsg(&builder, digest_len);
    try tracker.consumeProduce(4, "digest");

    try tracker.toTop("digest");
    try tracker.pushInt(null, @intCast(md_len));
    try tracker.split("md", "_drest");

    try tracker.toTop("_drest");
    try tracker.pushInt(null, @intCast(tree_idx_len));
    try tracker.split("_treeBytes", "_leafBytes");

    try tracker.toTop("_treeBytes");
    try appendBytesToUnsignedNumToBuilder(&builder, tree_idx_len, p.h - hp);
    try tracker.consumeProduce(1, "treeIdx");

    try tracker.toTop("_leafBytes");
    try appendBytesToUnsignedNumToBuilder(&builder, leaf_idx_len, hp);
    try tracker.consumeProduce(1, "leafIdx");

    try tracker.copyToTop("treeIdx", "_ti8");
    try appendNumToBigEndianToBuilder(&builder, 8);
    try tracker.consumeProduce(1, "treeAddr8");

    try tracker.copyToTop("leafIdx", "_li4");
    try appendNumToBigEndianToBuilder(&builder, 4);
    try tracker.consumeProduce(1, "keypair4");

    try tracker.toTop("sigRest");
    try tracker.pushInt(null, @intCast(fors_sig_len));
    try tracker.split("forsSig", "htSigRest");

    try tracker.copyToTop("_pkSeedPad", "_psp");
    try tracker.copyToTop("treeAddr8", "_ta");
    try tracker.copyToTop("keypair4", "_kp");
    try tracker.toTop("forsSig");
    try tracker.toTop("md");
    try emitSLHFors(&builder, p);
    try appendPreserveTopAndDropBelow(&builder, 3);
    try tracker.consumeProduce(5, "forsPk");

    var last_root_name: []const u8 = "forsPk";

    var layer: usize = 0;
    while (layer < d) : (layer += 1) {
        const xsig_name = try NameFactory.make(allocator, &owned_names, "xsig{d}", .{layer});
        const wsig_name = try NameFactory.make(allocator, &owned_names, "wsig{d}", .{layer});
        const auth_name = try NameFactory.make(allocator, &owned_names, "auth{d}", .{layer});
        const wpk_name = try NameFactory.make(allocator, &owned_names, "wpk{d}", .{layer});
        const root_name = try NameFactory.make(allocator, &owned_names, "root{d}", .{layer});

        try tracker.toTop("htSigRest");
        try tracker.pushInt(null, @intCast(xmss_sig_len));
        try tracker.split(xsig_name, "htSigRest");

        try tracker.toTop(xsig_name);
        try tracker.pushInt(null, @intCast(len * n));
        try tracker.split(wsig_name, auth_name);

        try tracker.copyToTop("_pkSeedPad", "_psp");
        try tracker.copyToTop("treeAddr8", "_ta");
        try tracker.copyToTop("keypair4", "_kp");
        try tracker.toTop(wsig_name);
        try tracker.toTop(last_root_name);
        try emitSLHWotsAll(&builder, p, layer);
        try appendPreserveTopAndDropBelow(&builder, 3);
        try tracker.consumeProduce(5, wpk_name);

        try tracker.copyToTop("_pkSeedPad", "_psp");
        try tracker.copyToTop("treeAddr8", "_ta");
        try tracker.copyToTop("keypair4", "_kp");
        try tracker.toTop("leafIdx");
        try tracker.toTop(auth_name);
        try tracker.toTop(wpk_name);
        try emitSLHMerkle(&builder, p, layer);
        try appendPreserveTopAndDropBelow(&builder, 3);
        try tracker.consumeProduce(6, root_name);
        last_root_name = root_name;

        if (layer < d - 1) {
            try tracker.toTop("treeIdx");
            try tracker.dup("_tic");

            try builder.emitPushInt(@intCast(@as(usize, 1) << @intCast(hp)));
            try builder.emitOp("OP_MOD");
            try tracker.consumeProduce(1, "leafIdx");

            try tracker.swap();
            try builder.emitPushInt(@intCast(@as(usize, 1) << @intCast(hp)));
            try builder.emitOp("OP_DIV");
            try tracker.consumeProduce(1, "treeIdx");

            if (tracker.has("treeAddr8")) {
                try tracker.toTop("treeAddr8");
                try tracker.drop();
            }
            try tracker.copyToTop("treeIdx", "_ti8");
            try appendNumToBigEndianToBuilder(&builder, 8);
            try tracker.consumeProduce(1, "treeAddr8");

            if (tracker.has("keypair4")) {
                try tracker.toTop("keypair4");
                try tracker.drop();
            }
            try tracker.copyToTop("leafIdx", "_li4");
            try appendNumToBigEndianToBuilder(&builder, 4);
            try tracker.consumeProduce(1, "keypair4");
        }
    }

    try tracker.toTop(last_root_name);
    try tracker.toTop("pkRoot");
    try tracker.equal("_result");

    try tracker.toTop("_result");
    try tracker.toAlt();

    const leftovers = [_][]const u8{
        "msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx",
        "_pkSeedPad", "treeAddr8", "keypair4",
    };
    for (leftovers) |name| {
        if (tracker.has(name)) {
            try tracker.toTop(name);
            try tracker.drop();
        }
    }
    while (tracker.depth() > 0) {
        try tracker.drop();
    }
    try tracker.fromAlt("_result");

    try list.appendSlice(allocator, builder.instructions.items);
}

pub fn appendBuiltinInstructions(
    list: *std.ArrayListUnmanaged(CryptoInstruction),
    allocator: Allocator,
    builtin: registry.CryptoBuiltin,
) PqEmitterError!void {
    return switch (builtin) {
        .verify_wots => appendVerifyWOTS(list, allocator),
        .verify_slhdsa_sha2_128s,
        .verify_slhdsa_sha2_128f,
        .verify_slhdsa_sha2_192s,
        .verify_slhdsa_sha2_192f,
        .verify_slhdsa_sha2_256s,
        .verify_slhdsa_sha2_256f,
        => appendVerifySLHDSA(list, allocator, registry.slhDsaParamKey(builtin).?),
        else => error.NotImplemented,
    };
}

test "verifyWOTS emits a real instruction sequence" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer list.deinit(allocator);

    try appendVerifyWOTS(&list, allocator);

    try std.testing.expect(list.items.len > 100);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = 32 }, list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_SPLIT" }, list.items[1]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_DROP" }, list.items[list.items.len - 1]);
}

test "SLH params lookup covers all SHA2 families" {
    const p128s = lookupSLHParams("SHA2_128s").?;
    try std.testing.expectEqual(@as(usize, 16), p128s.n);
    try std.testing.expectEqual(@as(usize, 35), p128s.len);

    const p256f = lookupSLHParams("SHA2_256f").?;
    try std.testing.expectEqual(@as(usize, 32), p256f.n);
    try std.testing.expectEqual(@as(usize, 17), p256f.d);

    try std.testing.expectEqual(@as(?SLHCodegenParams, null), lookupSLHParams("SHA2_999x"));
}

test "runtime ADRS helpers emit concatenation pipeline" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer list.deinit(allocator);

    try appendBuildADRS18(&list, allocator, 3, 4, 5, 2, null);
    try std.testing.expect(list.items.len >= 8);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_data = &.{0x03} }, list.items[0]);
    try std.testing.expectEqualDeep(CryptoInstruction{ .op_name = "OP_CAT" }, list.items[list.items.len - 1]);
}

test "zero padding uses direct byte pushes for SLH widths" {
    const allocator = std.testing.allocator;
    var builder = Builder{ .allocator = allocator };
    defer builder.deinit();

    var tracker = try SLHTracker.init(allocator, &builder, &.{});
    defer tracker.deinit();

    try tracker.pushZeroBytes("_zeros", 48);

    try std.testing.expectEqual(@as(usize, 1), builder.instructions.items.len);
    try std.testing.expectEqualDeep(CryptoInstruction{ .push_data = zero_bytes_48[0..] }, builder.instructions.items[0]);
}

test "verifySLHDSA emits a real instruction sequence for SHA2_128s" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
    defer list.deinit(allocator);

    try appendVerifySLHDSA(&list, allocator, "SHA2_128s");

    try std.testing.expect(list.items.len > 500);

    var saw_roll = false;
    var saw_equal = false;
    for (list.items) |inst| {
        switch (inst) {
            .op_name => |name| {
                if (std.mem.eql(u8, name, "OP_ROLL")) saw_roll = true;
                if (std.mem.eql(u8, name, "OP_EQUAL")) saw_equal = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_roll);
    try std.testing.expect(saw_equal);
}

test "verifySLHDSA emits sequences for every SHA2 parameter family" {
    const allocator = std.testing.allocator;
    const param_keys = [_][]const u8{
        "SHA2_128s",
        "SHA2_128f",
        "SHA2_192s",
        "SHA2_192f",
        "SHA2_256s",
        "SHA2_256f",
    };

    for (param_keys) |param_key| {
        var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
        defer list.deinit(allocator);

        try appendVerifySLHDSA(&list, allocator, param_key);

        try std.testing.expect(list.items.len > 500);
        try std.testing.expectEqualDeep(CryptoInstruction{ .push_int = @intCast(lookupSLHParams(param_key).?.n) }, list.items[0]);

        var saw_equal = false;
        for (list.items) |inst| {
            switch (inst) {
                .op_name => |name| {
                    if (std.mem.eql(u8, name, "OP_EQUAL")) saw_equal = true;
                },
                else => {},
            }
        }
        try std.testing.expect(saw_equal);
    }
}

test "builtin dispatch covers all SLH-DSA variants" {
    const allocator = std.testing.allocator;
    const builtins = [_]registry.CryptoBuiltin{
        .verify_slhdsa_sha2_128s,
        .verify_slhdsa_sha2_128f,
        .verify_slhdsa_sha2_192s,
        .verify_slhdsa_sha2_192f,
        .verify_slhdsa_sha2_256s,
        .verify_slhdsa_sha2_256f,
    };

    for (builtins) |builtin| {
        var list: std.ArrayListUnmanaged(CryptoInstruction) = .empty;
        defer list.deinit(allocator);

        try appendBuiltinInstructions(&list, allocator, builtin);
        try std.testing.expect(list.items.len > 500);
    }
}
