const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Sha256Instruction = union(enum) {
    op_name: []const u8,
    push_int: i64,
    push_data: []const u8,
};

pub const Sha256Builtin = enum {
    compress,
    finalize,
};

pub const Sha256EmitterError = error{
    OutOfMemory,
    UnexpectedDepth,
};

const sha256_k_le = [_][4]u8{
    u32ToLE(0x428a2f98), u32ToLE(0x71374491), u32ToLE(0xb5c0fbcf), u32ToLE(0xe9b5dba5),
    u32ToLE(0x3956c25b), u32ToLE(0x59f111f1), u32ToLE(0x923f82a4), u32ToLE(0xab1c5ed5),
    u32ToLE(0xd807aa98), u32ToLE(0x12835b01), u32ToLE(0x243185be), u32ToLE(0x550c7dc3),
    u32ToLE(0x72be5d74), u32ToLE(0x80deb1fe), u32ToLE(0x9bdc06a7), u32ToLE(0xc19bf174),
    u32ToLE(0xe49b69c1), u32ToLE(0xefbe4786), u32ToLE(0x0fc19dc6), u32ToLE(0x240ca1cc),
    u32ToLE(0x2de92c6f), u32ToLE(0x4a7484aa), u32ToLE(0x5cb0a9dc), u32ToLE(0x76f988da),
    u32ToLE(0x983e5152), u32ToLE(0xa831c66d), u32ToLE(0xb00327c8), u32ToLE(0xbf597fc7),
    u32ToLE(0xc6e00bf3), u32ToLE(0xd5a79147), u32ToLE(0x06ca6351), u32ToLE(0x14292967),
    u32ToLE(0x27b70a85), u32ToLE(0x2e1b2138), u32ToLE(0x4d2c6dfc), u32ToLE(0x53380d13),
    u32ToLE(0x650a7354), u32ToLE(0x766a0abb), u32ToLE(0x81c2c92e), u32ToLE(0x92722c85),
    u32ToLE(0xa2bfe8a1), u32ToLE(0xa81a664b), u32ToLE(0xc24b8b70), u32ToLE(0xc76c51a3),
    u32ToLE(0xd192e819), u32ToLE(0xd6990624), u32ToLE(0xf40e3585), u32ToLE(0x106aa070),
    u32ToLE(0x19a4c116), u32ToLE(0x1e376c08), u32ToLE(0x2748774c), u32ToLE(0x34b0bcb5),
    u32ToLE(0x391c0cb3), u32ToLE(0x4ed8aa4a), u32ToLE(0x5b9cca4f), u32ToLE(0x682e6ff3),
    u32ToLE(0x748f82ee), u32ToLE(0x78a5636f), u32ToLE(0x84c87814), u32ToLE(0x8cc70208),
    u32ToLE(0x90befffa), u32ToLE(0xa4506ceb), u32ToLE(0xbef9a3f7), u32ToLE(0xc67178f2),
};

const byte_80 = [_]u8{0x80};

fn u32ToLE(comptime n: u32) [4]u8 {
    return .{
        @intCast(n & 0xff),
        @intCast((n >> 8) & 0xff),
        @intCast((n >> 16) & 0xff),
        @intCast((n >> 24) & 0xff),
    };
}

const Emitter = struct {
    allocator: Allocator,
    instructions: std.ArrayListUnmanaged(Sha256Instruction) = .empty,
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

    fn emitOp(self: *Emitter, op_name: []const u8) Sha256EmitterError!void {
        try self.instructions.append(self.allocator, .{ .op_name = op_name });
    }

    fn emitPushInt(self: *Emitter, value: i64) Sha256EmitterError!void {
        try self.instructions.append(self.allocator, .{ .push_int = value });
        self.depth += 1;
    }

    fn emitPushData(self: *Emitter, value: []const u8) Sha256EmitterError!void {
        try self.instructions.append(self.allocator, .{ .push_data = value });
        self.depth += 1;
    }

    fn dup(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_DUP");
        self.depth += 1;
    }

    fn drop(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_DROP");
        self.depth -= 1;
    }

    fn swap(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_SWAP");
    }

    fn over(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_OVER");
        self.depth += 1;
    }

    fn nip(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_NIP");
        self.depth -= 1;
    }

    fn rot(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_ROT");
    }

    fn pick(self: *Emitter, d: usize) Sha256EmitterError!void {
        switch (d) {
            0 => try self.dup(),
            1 => try self.over(),
            else => {
                try self.emitPushInt(@intCast(d));
                try self.emitOp("OP_PICK");
            },
        }
    }

    fn roll(self: *Emitter, d: usize) Sha256EmitterError!void {
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

    fn toAlt(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_TOALTSTACK");
        self.depth -= 1;
        self.alt_depth += 1;
    }

    fn fromAlt(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_FROMALTSTACK");
        self.depth += 1;
        self.alt_depth -= 1;
    }

    fn binOp(self: *Emitter, op_name: []const u8) Sha256EmitterError!void {
        try self.emitOp(op_name);
        self.depth -= 1;
    }

    fn uniOp(self: *Emitter, op_name: []const u8) Sha256EmitterError!void {
        try self.emitOp(op_name);
    }

    fn dup2(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_2DUP");
        self.depth += 2;
    }

    fn split(self: *Emitter) Sha256EmitterError!void {
        try self.emitOp("OP_SPLIT");
    }

    fn split4(self: *Emitter) Sha256EmitterError!void {
        try self.emitPushInt(4);
        try self.split();
    }

    fn assertDepth(self: *const Emitter, expected: usize) Sha256EmitterError!void {
        if (self.depth != expected) return error.UnexpectedDepth;
    }

    fn reverseBytes4(self: *Emitter) Sha256EmitterError!void {
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

    fn le2num(self: *Emitter) Sha256EmitterError!void {
        try self.emitPushData(&.{0x00});
        try self.binOp("OP_CAT");
        try self.uniOp("OP_BIN2NUM");
    }

    fn num2le(self: *Emitter) Sha256EmitterError!void {
        try self.emitPushInt(5);
        try self.binOp("OP_NUM2BIN");
        try self.emitPushInt(4);
        try self.split();
        try self.drop();
    }

    fn add32(self: *Emitter) Sha256EmitterError!void {
        try self.le2num();
        try self.swap();
        try self.le2num();
        try self.binOp("OP_ADD");
        try self.num2le();
    }

    fn addN(self: *Emitter, n: usize) Sha256EmitterError!void {
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

    fn rotrBE(self: *Emitter, n: usize) Sha256EmitterError!void {
        try self.dup();
        try self.emitPushInt(@intCast(n));
        try self.binOp("OP_RSHIFT");
        try self.swap();
        try self.emitPushInt(@intCast(32 - n));
        try self.binOp("OP_LSHIFT");
        try self.binOp("OP_OR");
    }

    fn shrBE(self: *Emitter, n: usize) Sha256EmitterError!void {
        try self.emitPushInt(@intCast(n));
        try self.binOp("OP_RSHIFT");
    }

    fn bigSigma0(self: *Emitter) Sha256EmitterError!void {
        try self.reverseBytes4();
        try self.dup();
        try self.dup();
        try self.rotrBE(2);
        try self.swap();
        try self.rotrBE(13);
        try self.binOp("OP_XOR");
        try self.swap();
        try self.rotrBE(22);
        try self.binOp("OP_XOR");
        try self.reverseBytes4();
    }

    fn bigSigma1(self: *Emitter) Sha256EmitterError!void {
        try self.reverseBytes4();
        try self.dup();
        try self.dup();
        try self.rotrBE(6);
        try self.swap();
        try self.rotrBE(11);
        try self.binOp("OP_XOR");
        try self.swap();
        try self.rotrBE(25);
        try self.binOp("OP_XOR");
        try self.reverseBytes4();
    }

    fn smallSigma0(self: *Emitter) Sha256EmitterError!void {
        try self.reverseBytes4();
        try self.dup();
        try self.dup();
        try self.rotrBE(7);
        try self.swap();
        try self.rotrBE(18);
        try self.binOp("OP_XOR");
        try self.swap();
        try self.shrBE(3);
        try self.binOp("OP_XOR");
        try self.reverseBytes4();
    }

    fn smallSigma1(self: *Emitter) Sha256EmitterError!void {
        try self.reverseBytes4();
        try self.dup();
        try self.dup();
        try self.rotrBE(17);
        try self.swap();
        try self.rotrBE(19);
        try self.binOp("OP_XOR");
        try self.swap();
        try self.shrBE(10);
        try self.binOp("OP_XOR");
        try self.reverseBytes4();
    }

    fn ch(self: *Emitter) Sha256EmitterError!void {
        try self.rot();
        try self.dup();
        try self.uniOp("OP_INVERT");
        try self.rot();
        try self.binOp("OP_AND");
        try self.toAlt();
        try self.binOp("OP_AND");
        try self.fromAlt();
        try self.binOp("OP_XOR");
    }

    fn maj(self: *Emitter) Sha256EmitterError!void {
        try self.toAlt();
        try self.dup2();
        try self.binOp("OP_AND");
        try self.toAlt();
        try self.binOp("OP_XOR");
        try self.fromAlt();
        try self.swap();
        try self.fromAlt();
        try self.binOp("OP_AND");
        try self.binOp("OP_OR");
    }

    fn beWordsToLE(self: *Emitter, n: usize) Sha256EmitterError!void {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            try self.reverseBytes4();
            try self.toAlt();
        }
        i = 0;
        while (i < n) : (i += 1) {
            try self.fromAlt();
        }
    }

    fn beWordsToLEReversed8(self: *Emitter) Sha256EmitterError!void {
        var i: usize = 8;
        while (i > 0) {
            i -= 1;
            try self.roll(i);
            try self.reverseBytes4();
            try self.toAlt();
        }
        i = 0;
        while (i < 8) : (i += 1) {
            try self.fromAlt();
        }
    }
};

pub fn requiredArgCount(builtin: Sha256Builtin) usize {
    return switch (builtin) {
        .compress => 2,
        .finalize => 3,
    };
}

pub fn appendBuiltinInstructions(
    list: *std.ArrayListUnmanaged(Sha256Instruction),
    allocator: Allocator,
    builtin: Sha256Builtin,
) Sha256EmitterError!void {
    var emitter = Emitter.init(allocator, switch (builtin) {
        .compress => 2,
        .finalize => 3,
    });
    defer emitter.deinit();

    switch (builtin) {
        .compress => try appendCompressProgram(&emitter),
        .finalize => try appendFinalizeProgram(&emitter),
    }

    try list.appendSlice(allocator, emitter.instructions.items);
}

fn appendCompressProgram(emitter: *Emitter) Sha256EmitterError!void {
    try emitter.swap();
    try emitter.dup();
    try emitter.toAlt();
    try emitter.toAlt();
    try emitter.assertDepth(1);

    var i: usize = 0;
    while (i < 15) : (i += 1) {
        try emitter.split4();
    }
    try emitter.assertDepth(16);
    try emitter.beWordsToLE(16);
    try emitter.assertDepth(16);

    i = 16;
    while (i < 64) : (i += 1) {
        try emitter.over();
        try emitter.smallSigma1();
        try emitter.pick(7);
        try emitter.pick(16);
        try emitter.smallSigma0();
        try emitter.pick(18);
        try emitter.addN(4);
    }
    try emitter.assertDepth(64);

    try emitter.fromAlt();
    i = 0;
    while (i < 7) : (i += 1) {
        try emitter.split4();
    }
    try emitter.assertDepth(72);
    try emitter.beWordsToLEReversed8();
    try emitter.assertDepth(72);

    i = 0;
    while (i < 64) : (i += 1) {
        const before_depth = emitter.depth;
        try emitRound(emitter, i);
        if (emitter.depth != before_depth) return error.UnexpectedDepth;
    }

    try emitter.fromAlt();
    try emitter.assertDepth(73);

    i = 0;
    while (i < 7) : (i += 1) {
        try emitter.split4();
    }
    try emitter.beWordsToLEReversed8();
    try emitter.assertDepth(80);

    i = 0;
    while (i < 8) : (i += 1) {
        try emitter.roll(8 - i);
        try emitter.add32();
        try emitter.toAlt();
    }
    try emitter.assertDepth(64);

    try emitter.fromAlt();
    try emitter.reverseBytes4();
    i = 1;
    while (i < 8) : (i += 1) {
        try emitter.fromAlt();
        try emitter.reverseBytes4();
        try emitter.swap();
        try emitter.binOp("OP_CAT");
    }
    try emitter.assertDepth(65);

    i = 0;
    while (i < 64) : (i += 1) {
        try emitter.swap();
        try emitter.drop();
    }
    try emitter.assertDepth(1);
}

fn appendFinalizeProgram(emitter: *Emitter) Sha256EmitterError!void {
    try emitter.emitPushInt(9);
    try emitter.binOp("OP_NUM2BIN");
    try emitter.emitPushInt(8);
    try emitter.split();
    try emitter.drop();
    try emitter.emitPushInt(4);
    try emitter.split();
    try emitter.reverseBytes4();
    try emitter.swap();
    try emitter.reverseBytes4();
    try emitter.binOp("OP_CAT");
    try emitter.toAlt();
    try emitter.assertDepth(2);

    try emitter.emitPushData(byte_80[0..]);
    try emitter.binOp("OP_CAT");

    try emitter.emitOp("OP_SIZE");
    emitter.depth += 1;

    try emitter.dup();
    try emitter.emitPushInt(57);
    try emitter.binOp("OP_LESSTHAN");

    try emitter.emitOp("OP_IF");
    emitter.depth -= 1;

    try emitter.emitPushInt(56);
    try emitter.swap();
    try emitter.binOp("OP_SUB");
    try emitter.emitPushInt(0);
    try emitter.swap();
    try emitter.binOp("OP_NUM2BIN");
    try emitter.binOp("OP_CAT");
    try emitter.fromAlt();
    try emitter.binOp("OP_CAT");
    try appendCompressProgram(emitter);

    try emitter.emitOp("OP_ELSE");
    emitter.depth = 3;
    emitter.alt_depth = 1;

    try emitter.emitPushInt(120);
    try emitter.swap();
    try emitter.binOp("OP_SUB");
    try emitter.emitPushInt(0);
    try emitter.swap();
    try emitter.binOp("OP_NUM2BIN");
    try emitter.binOp("OP_CAT");
    try emitter.fromAlt();
    try emitter.binOp("OP_CAT");

    try emitter.emitPushInt(64);
    try emitter.split();
    try emitter.toAlt();

    try appendCompressProgram(emitter);
    try emitter.fromAlt();
    try appendCompressProgram(emitter);

    try emitter.emitOp("OP_ENDIF");
    try emitter.assertDepth(1);
}

fn emitRound(emitter: *Emitter, t: usize) Sha256EmitterError!void {
    try emitter.pick(4);
    try emitter.bigSigma1();

    try emitter.pick(5);
    try emitter.pick(7);
    try emitter.pick(9);
    try emitter.ch();

    try emitter.pick(9);
    try emitter.emitPushData(sha256_k_le[t][0..]);
    try emitter.pick(75 - t);
    try emitter.addN(5);

    try emitter.dup();
    try emitter.toAlt();

    try emitter.pick(1);
    try emitter.bigSigma0();

    try emitter.pick(2);
    try emitter.pick(4);
    try emitter.pick(6);
    try emitter.maj();
    try emitter.add32();

    try emitter.fromAlt();
    try emitter.swap();
    try emitter.add32();

    try emitter.swap();
    try emitter.roll(5);
    try emitter.add32();

    try emitter.roll(8);
    try emitter.drop();

    try emitter.swap();
    try emitter.roll(4);
    try emitter.roll(4);
    try emitter.roll(4);
    try emitter.roll(3);
}

fn expectContainsOp(items: []const Sha256Instruction, op_name: []const u8) !void {
    for (items) |inst| {
        switch (inst) {
            .op_name => |name| if (std.mem.eql(u8, name, op_name)) return,
            else => {},
        }
    }
    return error.TestUnexpectedResult;
}

test "sha256 compress emits expected opcode families" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(Sha256Instruction) = .empty;
    defer list.deinit(allocator);

    try appendBuiltinInstructions(&list, allocator, .compress);

    try std.testing.expect(list.items.len > 100);
    try std.testing.expectEqualDeep(Sha256Instruction{ .op_name = "OP_SWAP" }, list.items[0]);
    try expectContainsOp(list.items, "OP_LSHIFT");
    try expectContainsOp(list.items, "OP_RSHIFT");
    try expectContainsOp(list.items, "OP_AND");
    try expectContainsOp(list.items, "OP_XOR");
    try expectContainsOp(list.items, "OP_NUM2BIN");
    try expectContainsOp(list.items, "OP_BIN2NUM");
}

test "sha256 finalize emits padding branch structure" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(Sha256Instruction) = .empty;
    defer list.deinit(allocator);

    try appendBuiltinInstructions(&list, allocator, .finalize);

    try std.testing.expect(list.items.len > 200);
    try std.testing.expectEqualDeep(Sha256Instruction{ .push_int = 9 }, list.items[0]);
    try expectContainsOp(list.items, "OP_IF");
    try expectContainsOp(list.items, "OP_ELSE");
    try expectContainsOp(list.items, "OP_ENDIF");
    try expectContainsOp(list.items, "OP_LSHIFT");
    try expectContainsOp(list.items, "OP_RSHIFT");
}
