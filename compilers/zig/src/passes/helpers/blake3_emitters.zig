const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Blake3Instruction = union(enum) {
    op_name: []const u8,
    push_int: i64,
    push_data: []const u8,
};

pub const Blake3Builtin = enum {
    compress,
    hash,
    blake3,
};

pub const Blake3EmitterError = error{
    OutOfMemory,
    UnexpectedDepth,
};

const blake3_iv_words = [_]u32{
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
};

const msg_permutation = [_]u8{
    2, 6, 3, 10, 7, 0, 4, 13,
    1, 11, 12, 5, 9, 14, 15, 8,
};

const chunk_start: u32 = 1;
const chunk_end: u32 = 2;
const root_flag: u32 = 8;

const blake3_iv_le = [_][4]u8{
    u32ToLE(0x6a09e667),
    u32ToLE(0xbb67ae85),
    u32ToLE(0x3c6ef372),
    u32ToLE(0xa54ff53a),
    u32ToLE(0x510e527f),
    u32ToLE(0x9b05688c),
    u32ToLE(0x1f83d9ab),
    u32ToLE(0x5be0cd19),
};

const blake3_iv_be = buildIvBE();
const blake3_iv_le_slices = [_][]const u8{
    (&blake3_iv_le[0])[0..],
    (&blake3_iv_le[1])[0..],
    (&blake3_iv_le[2])[0..],
    (&blake3_iv_le[3])[0..],
    (&blake3_iv_le[4])[0..],
    (&blake3_iv_le[5])[0..],
    (&blake3_iv_le[6])[0..],
    (&blake3_iv_le[7])[0..],
};
const zero_word_le = u32ToLE(0);
const block_len_le = u32ToLE(64);
const flags_le = u32ToLE(chunk_start | chunk_end | root_flag);
const msg_schedule = computeMsgSchedule();

const StateTracker = struct {
    positions: [16]i32,

    fn init() StateTracker {
        var positions: [16]i32 = undefined;
        for (0..16) |i| {
            positions[i] = @intCast(15 - i);
        }
        return .{ .positions = positions };
    }

    fn depth(self: *const StateTracker, word_idx: usize) usize {
        return @intCast(self.positions[word_idx]);
    }

    fn onRollToTop(self: *StateTracker, word_idx: usize) void {
        const tracked_depth = self.positions[word_idx];
        for (0..16) |j| {
            if (j != word_idx and self.positions[j] >= 0 and self.positions[j] < tracked_depth) {
                self.positions[j] += 1;
            }
        }
        self.positions[word_idx] = 0;
    }
};

const Emitter = struct {
    allocator: Allocator,
    instructions: std.ArrayListUnmanaged(Blake3Instruction) = .empty,
    depth: usize,
    alt_depth: usize = 0,

    fn init(allocator: Allocator, initial_depth: usize) Emitter {
        return .{
            .allocator = allocator,
            .depth = initial_depth,
        };
    }

    fn deinit(self: *Emitter) void {
        self.instructions.deinit(self.allocator);
    }

    fn emitOp(self: *Emitter, op_name: []const u8) Blake3EmitterError!void {
        try self.instructions.append(self.allocator, .{ .op_name = op_name });
    }

    fn emitPushInt(self: *Emitter, value: i64) Blake3EmitterError!void {
        try self.instructions.append(self.allocator, .{ .push_int = value });
        self.depth += 1;
    }

    fn emitPushData(self: *Emitter, value: []const u8) Blake3EmitterError!void {
        try self.instructions.append(self.allocator, .{ .push_data = value });
        self.depth += 1;
    }

    fn dup(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_DUP");
        self.depth += 1;
    }

    fn drop(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_DROP");
        self.depth -= 1;
    }

    fn swap(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_SWAP");
    }

    fn over(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_OVER");
        self.depth += 1;
    }

    fn nip(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_NIP");
        self.depth -= 1;
    }

    fn rot(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_ROT");
    }

    fn pick(self: *Emitter, d: usize) Blake3EmitterError!void {
        switch (d) {
            0 => try self.dup(),
            1 => try self.over(),
            else => {
                try self.emitPushInt(@intCast(d));
                try self.emitOp("OP_PICK");
            },
        }
    }

    fn roll(self: *Emitter, d: usize) Blake3EmitterError!void {
        switch (d) {
            0 => {},
            1 => try self.swap(),
            2 => try self.rot(),
            else => {
                try self.emitPushInt(@intCast(d));
                try self.emitOp("OP_ROLL");
                self.depth -= 1;
            },
        }
    }

    fn toAlt(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_TOALTSTACK");
        self.depth -= 1;
        self.alt_depth += 1;
    }

    fn fromAlt(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_FROMALTSTACK");
        self.depth += 1;
        self.alt_depth -= 1;
    }

    fn binOp(self: *Emitter, op_name: []const u8) Blake3EmitterError!void {
        try self.emitOp(op_name);
        self.depth -= 1;
    }

    fn uniOp(self: *Emitter, op_name: []const u8) Blake3EmitterError!void {
        try self.emitOp(op_name);
    }

    fn split(self: *Emitter) Blake3EmitterError!void {
        try self.emitOp("OP_SPLIT");
    }

    fn split4(self: *Emitter) Blake3EmitterError!void {
        try self.emitPushInt(4);
        try self.split();
    }

    fn assertDepth(self: *const Emitter, expected: usize) Blake3EmitterError!void {
        _ = self;
        _ = expected;
    }

    fn reverseBytes4(self: *Emitter) Blake3EmitterError!void {
        try self.emitPushInt(1);
        try self.split();
        try self.emitPushInt(1);
        try self.split();
        try self.emitPushInt(1);
        try self.split();
        try self.swap();
        try self.binOp("OP_CAT");
        try self.swap();
        try self.binOp("OP_CAT");
        try self.swap();
        try self.binOp("OP_CAT");
    }

    fn le2num(self: *Emitter) Blake3EmitterError!void {
        try self.emitPushData(&.{0x00});
        try self.binOp("OP_CAT");
        try self.uniOp("OP_BIN2NUM");
    }

    fn num2le(self: *Emitter) Blake3EmitterError!void {
        try self.emitPushInt(5);
        try self.binOp("OP_NUM2BIN");
        try self.emitPushInt(4);
        try self.split();
        try self.drop();
    }

    fn add32(self: *Emitter) Blake3EmitterError!void {
        try self.le2num();
        try self.swap();
        try self.le2num();
        try self.binOp("OP_ADD");
        try self.num2le();
    }

    fn addN(self: *Emitter, n: usize) Blake3EmitterError!void {
        if (n < 2) return;
        try self.le2num();
        var i: usize = 1;
        while (i < n) : (i += 1) {
            try self.swap();
            try self.le2num();
            try self.binOp("OP_ADD");
        }
        try self.num2le();
    }

    fn rotrBE(self: *Emitter, n: usize) Blake3EmitterError!void {
        try self.dup();
        try self.emitPushInt(@intCast(n));
        try self.binOp("OP_RSHIFT");
        try self.swap();
        try self.emitPushInt(@intCast(32 - n));
        try self.binOp("OP_LSHIFT");
        try self.binOp("OP_OR");
    }

    fn rotr16LE(self: *Emitter) Blake3EmitterError!void {
        try self.emitPushInt(2);
        try self.split();
        try self.swap();
        try self.binOp("OP_CAT");
    }

    fn rotr8LE(self: *Emitter) Blake3EmitterError!void {
        try self.emitPushInt(1);
        try self.split();
        try self.swap();
        try self.binOp("OP_CAT");
    }

    fn rotrLEGeneral(self: *Emitter, n: usize) Blake3EmitterError!void {
        try self.reverseBytes4();
        try self.rotrBE(n);
        try self.reverseBytes4();
    }

    fn beWordsToLE(self: *Emitter, n: usize) Blake3EmitterError!void {
        for (0..n) |_| {
            try self.reverseBytes4();
            try self.toAlt();
        }
        for (0..n) |_| {
            try self.fromAlt();
        }
    }
};

pub fn appendBuiltinInstructions(
    list: *std.ArrayListUnmanaged(Blake3Instruction),
    allocator: Allocator,
    builtin: Blake3Builtin,
) Blake3EmitterError!void {
    var emitter = Emitter.init(allocator, switch (builtin) {
        .compress => 2,
        .hash, .blake3 => 1,
    });
    defer emitter.deinit();

    switch (builtin) {
        .compress => try generateCompressOps(&emitter, 7),
        .hash, .blake3 => try generateHashOps(&emitter),
    }

    try list.appendSlice(allocator, emitter.instructions.items);
}

pub fn appendBlake3CompressInstructions(
    list: *std.ArrayListUnmanaged(Blake3Instruction),
    allocator: Allocator,
) Blake3EmitterError!void {
    try appendBuiltinInstructions(list, allocator, .compress);
}

pub fn appendBlake3HashInstructions(
    list: *std.ArrayListUnmanaged(Blake3Instruction),
    allocator: Allocator,
) Blake3EmitterError!void {
    try appendBuiltinInstructions(list, allocator, .hash);
}

pub fn appendBlake3Instructions(
    list: *std.ArrayListUnmanaged(Blake3Instruction),
    allocator: Allocator,
) Blake3EmitterError!void {
    try appendBuiltinInstructions(list, allocator, .blake3);
}

fn generateHashOps(emitter: *Emitter) Blake3EmitterError!void {
    try emitter.emitOp("OP_SIZE");
    emitter.depth += 1;
    try emitter.emitPushInt(64);
    try emitter.swap();
    try emitter.binOp("OP_SUB");
    try emitter.emitPushInt(0);
    try emitter.swap();
    try emitter.binOp("OP_NUM2BIN");
    try emitter.binOp("OP_CAT");

    try emitter.emitPushData(blake3_iv_be[0..]);
    try emitter.swap();

    try generateCompressOps(emitter, 7);
    emitter.depth = 1;
    try emitter.assertDepth(1);
}

fn generateCompressOps(emitter: *Emitter, num_rounds: usize) Blake3EmitterError!void {
    for (0..15) |_| {
        try emitter.split4();
    }
    try emitter.assertDepth(17);
    try emitter.beWordsToLE(16);
    try emitter.assertDepth(17);

    try emitter.roll(16);
    try emitter.toAlt();
    try emitter.assertDepth(16);

    try emitter.fromAlt();
    try emitter.assertDepth(17);
    for (0..7) |_| {
        try emitter.split4();
    }
    try emitter.assertDepth(24);
    try emitter.beWordsToLE(8);
    try emitter.assertDepth(24);

    for (0..4) |i| {
        try emitter.emitPushData(blake3_iv_le_slices[i]);
    }
    try emitter.assertDepth(28);

    try emitter.emitPushData(zero_word_le[0..]);
    try emitter.emitPushData(zero_word_le[0..]);
    try emitter.emitPushData(block_len_le[0..]);
    try emitter.emitPushData(flags_le[0..]);
    try emitter.assertDepth(32);

    var tracker = StateTracker.init();
    for (0..num_rounds) |round| {
        const schedule = msg_schedule[round];
        try emitGCall(emitter, &tracker, 0, 4, 8, 12, schedule[0], schedule[1]);
        try emitGCall(emitter, &tracker, 1, 5, 9, 13, schedule[2], schedule[3]);
        try emitGCall(emitter, &tracker, 2, 6, 10, 14, schedule[4], schedule[5]);
        try emitGCall(emitter, &tracker, 3, 7, 11, 15, schedule[6], schedule[7]);

        try emitGCall(emitter, &tracker, 0, 5, 10, 15, schedule[8], schedule[9]);
        try emitGCall(emitter, &tracker, 1, 6, 11, 12, schedule[10], schedule[11]);
        try emitGCall(emitter, &tracker, 2, 7, 8, 13, schedule[12], schedule[13]);
        try emitGCall(emitter, &tracker, 3, 4, 9, 14, schedule[14], schedule[15]);
    }
    try emitter.assertDepth(32);

    var i: usize = 16;
    while (i > 0) {
        i -= 1;
        const depth = tracker.depth(i);
        try emitter.roll(depth);
        tracker.onRollToTop(i);
        try emitter.toAlt();
        for (0..16) |j| {
            if (j != i and tracker.positions[j] >= 0) {
                tracker.positions[j] -= 1;
            }
        }
        tracker.positions[i] = -1;
    }

    for (0..16) |_| {
        try emitter.fromAlt();
    }
    try emitter.assertDepth(32);

    for (0..8) |k| {
        try emitter.roll(8 - k);
        try emitter.binOp("OP_XOR");
        try emitter.toAlt();
    }
    try emitter.assertDepth(16);

    for (0..8) |_| {
        try emitter.fromAlt();
    }
    try emitter.assertDepth(24);

    try emitter.reverseBytes4();
    for (1..8) |_| {
        try emitter.swap();
        try emitter.reverseBytes4();
        try emitter.swap();
        try emitter.binOp("OP_CAT");
    }
    try emitter.assertDepth(17);

    for (0..16) |_| {
        try emitter.swap();
        try emitter.drop();
    }
    try emitter.assertDepth(1);
}

fn emitHalfG(emitter: *Emitter, rot_d: usize, rot_b: usize) Blake3EmitterError!void {
    const start_depth = emitter.depth;

    try emitter.pick(3);
    try emitter.toAlt();

    try emitter.roll(3);
    try emitter.roll(4);
    try emitter.addN(3);
    try emitter.assertDepth(start_depth - 2);

    try emitter.dup();
    try emitter.rot();
    try emitter.binOp("OP_XOR");
    switch (rot_d) {
        16 => try emitter.rotr16LE(),
        8 => try emitter.rotr8LE(),
        else => try emitter.rotrLEGeneral(rot_d),
    }
    try emitter.assertDepth(start_depth - 2);

    try emitter.dup();
    try emitter.roll(3);
    try emitter.add32();
    try emitter.assertDepth(start_depth - 2);

    try emitter.fromAlt();
    try emitter.over();
    try emitter.binOp("OP_XOR");
    try emitter.rotrLEGeneral(rot_b);
    try emitter.assertDepth(start_depth - 1);

    try emitter.swap();
    try emitter.rot();
    try emitter.assertDepth(start_depth - 1);
}

fn emitG(emitter: *Emitter) Blake3EmitterError!void {
    const start_depth = emitter.depth;

    try emitter.toAlt();
    try emitHalfG(emitter, 16, 12);
    try emitter.assertDepth(start_depth - 2);

    try emitter.fromAlt();
    try emitter.assertDepth(start_depth - 1);

    try emitHalfG(emitter, 8, 7);
    try emitter.assertDepth(start_depth - 2);
}

fn emitGCall(
    emitter: *Emitter,
    tracker: *StateTracker,
    ai: usize,
    bi: usize,
    ci: usize,
    di: usize,
    mx_orig_idx: usize,
    my_orig_idx: usize,
) Blake3EmitterError!void {
    const start_depth = emitter.depth;

    for ([_]usize{ ai, bi, ci, di }) |idx| {
        try emitter.roll(tracker.depth(idx));
        tracker.onRollToTop(idx);
    }

    try emitter.pick(16 + (15 - mx_orig_idx));
    try emitter.pick(16 + (15 - my_orig_idx) + 1);
    try emitter.assertDepth(start_depth + 2);

    try emitG(emitter);
    try emitter.assertDepth(start_depth);

    tracker.positions[ai] = 3;
    tracker.positions[bi] = 2;
    tracker.positions[ci] = 1;
    tracker.positions[di] = 0;
}

fn u32ToLE(comptime n: u32) [4]u8 {
    return .{
        @intCast(n & 0xff),
        @intCast((n >> 8) & 0xff),
        @intCast((n >> 16) & 0xff),
        @intCast((n >> 24) & 0xff),
    };
}

fn u32ToBE(comptime n: u32) [4]u8 {
    return .{
        @intCast((n >> 24) & 0xff),
        @intCast((n >> 16) & 0xff),
        @intCast((n >> 8) & 0xff),
        @intCast(n & 0xff),
    };
}

fn buildIvBE() [32]u8 {
    var out: [32]u8 = undefined;
    inline for (blake3_iv_words, 0..) |word, idx| {
        const be = u32ToBE(word);
        out[idx * 4 + 0] = be[0];
        out[idx * 4 + 1] = be[1];
        out[idx * 4 + 2] = be[2];
        out[idx * 4 + 3] = be[3];
    }
    return out;
}

fn computeMsgSchedule() [7][16]u8 {
    var schedule: [7][16]u8 = undefined;
    var current: [16]u8 = undefined;
    for (0..16) |i| {
        current[i] = @intCast(i);
    }

    for (0..7) |round| {
        schedule[round] = current;
        var next: [16]u8 = undefined;
        for (0..16) |i| {
            next[i] = current[msg_permutation[i]];
        }
        current = next;
    }

    return schedule;
}

test "blake3 compress emitter emits expected instruction count" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(Blake3Instruction) = .empty;
    defer list.deinit(allocator);

    try appendBlake3CompressInstructions(&list, allocator);

    try std.testing.expectEqual(@as(usize, 10819), list.items.len);
    try std.testing.expectEqualDeep(Blake3Instruction{ .push_int = 4 }, list.items[0]);
    try std.testing.expectEqualDeep(Blake3Instruction{ .op_name = "OP_SPLIT" }, list.items[1]);
    try std.testing.expectEqualDeep(Blake3Instruction{ .op_name = "OP_DROP" }, list.items[list.items.len - 1]);
}

test "blake3 compress emitter includes IV words after chaining state" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(Blake3Instruction) = .empty;
    defer list.deinit(allocator);

    try appendBlake3CompressInstructions(&list, allocator);

    var found = false;
    for (0..list.items.len - 3) |i| {
        if (!std.meta.eql(list.items[i], Blake3Instruction{ .push_data = blake3_iv_le_slices[0] })) continue;
        if (!std.meta.eql(list.items[i + 1], Blake3Instruction{ .push_data = blake3_iv_le_slices[1] })) continue;
        if (!std.meta.eql(list.items[i + 2], Blake3Instruction{ .push_data = blake3_iv_le_slices[2] })) continue;
        if (!std.meta.eql(list.items[i + 3], Blake3Instruction{ .push_data = blake3_iv_le_slices[3] })) continue;
        found = true;
        break;
    }

    try std.testing.expect(found);
}

test "blake3 hash emitter emits expected instruction count" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(Blake3Instruction) = .empty;
    defer list.deinit(allocator);

    try appendBlake3HashInstructions(&list, allocator);

    try std.testing.expectEqual(@as(usize, 10829), list.items.len);
    try std.testing.expectEqualDeep(Blake3Instruction{ .op_name = "OP_SIZE" }, list.items[0]);
    try std.testing.expectEqualDeep(Blake3Instruction{ .op_name = "OP_DROP" }, list.items[list.items.len - 1]);
}

test "blake3 builtin alias emits hash instruction sequence" {
    const allocator = std.testing.allocator;
    var hash_list: std.ArrayListUnmanaged(Blake3Instruction) = .empty;
    defer hash_list.deinit(allocator);
    var alias_list: std.ArrayListUnmanaged(Blake3Instruction) = .empty;
    defer alias_list.deinit(allocator);

    try appendBlake3HashInstructions(&hash_list, allocator);
    try appendBlake3Instructions(&alias_list, allocator);

    try std.testing.expectEqual(hash_list.items.len, alias_list.items.len);
    for (hash_list.items, alias_list.items) |expected, actual| {
        try std.testing.expectEqualDeep(expected, actual);
    }
}
