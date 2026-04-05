//! Baby Bear field arithmetic codegen — Baby Bear prime field operations for Bitcoin Script.
//!
//! Follows the ec_emitters.zig pattern: self-contained module imported by
//! stack_lower.zig. Uses a BBTracker for named stack state tracking.
//!
//! Baby Bear prime: p = 2^31 - 2^27 + 1 = 2013265921
//! Used by SP1 STARK proofs (FRI verification).
//!
//! All values fit in a single BSV script number (31-bit prime).
//! No multi-limb arithmetic needed.

const std = @import("std");
const ec = @import("ec_emitters.zig");

const Allocator = std.mem.Allocator;
const StackOp = ec.StackOp;
const StackIf = ec.StackIf;
const PushValue = ec.PushValue;
const EcOpBundle = ec.EcOpBundle;

/// Baby Bear field prime p = 2^31 - 2^27 + 1
const BB_P: i64 = 2013265921;
/// p - 2, used for Fermat's little theorem modular inverse
const BB_P_MINUS_2: u32 = 2013265919;

pub const BBBuiltin = enum {
    bb_field_add,
    bb_field_sub,
    bb_field_mul,
    bb_field_inv,
};

pub fn buildBuiltinOps(allocator: Allocator, builtin: BBBuiltin) !EcOpBundle {
    var tracker = try BBTracker.init(allocator, initialNames(builtin));
    errdefer tracker.deinit();

    switch (builtin) {
        .bb_field_add => try emitBBFieldAdd(&tracker),
        .bb_field_sub => try emitBBFieldSub(&tracker),
        .bb_field_mul => try emitBBFieldMul(&tracker),
        .bb_field_inv => try emitBBFieldInv(&tracker),
    }

    return tracker.takeBundle();
}

fn initialNames(builtin: BBBuiltin) []const ?[]const u8 {
    return switch (builtin) {
        .bb_field_add => &.{ "a", "b" },
        .bb_field_sub => &.{ "a", "b" },
        .bb_field_mul => &.{ "a", "b" },
        .bb_field_inv => &.{ "a" },
    };
}

// ===========================================================================
// BBTracker — named stack state tracker (mirrors ECTracker)
// ===========================================================================

const BBTracker = struct {
    allocator: Allocator,
    names: std.ArrayListUnmanaged(?[]const u8),
    ops: std.ArrayListUnmanaged(StackOp),
    owned_bytes: std.ArrayListUnmanaged([]u8),

    fn init(allocator: Allocator, initial_names: []const ?[]const u8) !BBTracker {
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

    fn deinit(self: *BBTracker) void {
        ec.deinitOpsRecursive(self.allocator, self.ops.items);
        self.ops.deinit(self.allocator);
        self.names.deinit(self.allocator);
        for (self.owned_bytes.items) |bytes| self.allocator.free(bytes);
        self.owned_bytes.deinit(self.allocator);
    }

    fn takeBundle(self: *BBTracker) !EcOpBundle {
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

    fn findDepth(self: *const BBTracker, name: []const u8) !usize {
        var i = self.names.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.names.items[i] orelse continue;
            if (std.mem.eql(u8, slot, name)) {
                return self.names.items.len - 1 - i;
            }
        }
        return error.NameNotFound;
    }

    fn emitRaw(self: *BBTracker, op: StackOp) !void {
        try self.ops.append(self.allocator, op);
    }

    fn emitOpcode(self: *BBTracker, code: []const u8) !void {
        try self.emitRaw(.{ .opcode = code });
    }

    fn emitPushInt(self: *BBTracker, value: i64) !void {
        try self.emitRaw(.{ .push = .{ .integer = value } });
    }

    fn pushInt(self: *BBTracker, name: ?[]const u8, value: i64) !void {
        try self.emitPushInt(value);
        try self.names.append(self.allocator, name);
    }

    fn dup(self: *BBTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .dup = {} });
        try self.names.append(self.allocator, name);
    }

    fn drop(self: *BBTracker) !void {
        try self.emitRaw(.{ .drop = {} });
        _ = self.names.pop();
    }

    fn swap(self: *BBTracker) !void {
        try self.emitRaw(.{ .swap = {} });
        const len = self.names.items.len;
        if (len >= 2) {
            const tmp = self.names.items[len - 1];
            self.names.items[len - 1] = self.names.items[len - 2];
            self.names.items[len - 2] = tmp;
        }
    }

    fn nip(self: *BBTracker) !void {
        try self.emitRaw(.{ .nip = {} });
        const len = self.names.items.len;
        if (len >= 2) {
            _ = self.names.orderedRemove(len - 2);
        }
    }

    fn over(self: *BBTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .over = {} });
        try self.names.append(self.allocator, name);
    }

    fn rot(self: *BBTracker) !void {
        try self.emitRaw(.{ .rot = {} });
        const len = self.names.items.len;
        if (len >= 3) {
            const rolled = self.names.orderedRemove(len - 3);
            try self.names.append(self.allocator, rolled);
        }
    }

    fn roll(self: *BBTracker, depth_from_top: usize) !void {
        if (depth_from_top == 0) return;
        if (depth_from_top == 1) return self.swap();
        if (depth_from_top == 2) return self.rot();
        try self.emitRaw(.{ .roll = @intCast(depth_from_top) });
        const idx = self.names.items.len - 1 - depth_from_top;
        const rolled = self.names.orderedRemove(idx);
        try self.names.append(self.allocator, rolled);
    }

    fn pick(self: *BBTracker, depth_from_top: usize, name: ?[]const u8) !void {
        if (depth_from_top == 0) return self.dup(name);
        if (depth_from_top == 1) return self.over(name);
        try self.emitRaw(.{ .pick = @intCast(depth_from_top) });
        try self.names.append(self.allocator, name);
    }

    fn toTop(self: *BBTracker, name: []const u8) !void {
        try self.roll(try self.findDepth(name));
    }

    fn copyToTop(self: *BBTracker, name: []const u8, copy_name: ?[]const u8) !void {
        try self.pick(try self.findDepth(name), copy_name);
    }

    fn renameTop(self: *BBTracker, name: ?[]const u8) void {
        if (self.names.items.len > 0) {
            self.names.items[self.names.items.len - 1] = name;
        }
    }

    fn popNames(self: *BBTracker, count: usize) void {
        var i: usize = 0;
        while (i < count and self.names.items.len > 0) : (i += 1) {
            _ = self.names.pop();
        }
    }
};

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

/// fieldMod: ensure value is in [0, p).
/// Pattern: (a % p + p) % p — handles negative values from sub.
fn fieldMod(t: *BBTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    // (a % p + p) % p
    t.popNames(1);
    try t.emitPushInt(BB_P);
    try t.emitOpcode("OP_MOD");
    try t.emitPushInt(BB_P);
    try t.emitOpcode("OP_ADD");
    try t.emitPushInt(BB_P);
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

/// fieldAdd: (a + b) mod p
fn fieldAdd(t: *BBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    // OP_ADD
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, "_bb_add");
    // Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
    try t.toTop("_bb_add");
    t.popNames(1);
    try t.emitPushInt(BB_P);
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

/// fieldSub: (a - b) mod p (non-negative)
fn fieldSub(t: *BBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    // OP_SUB
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.names.append(t.allocator, "_bb_diff");
    // Difference can be negative, need full mod-reduce
    try fieldMod(t, "_bb_diff", result_name);
}

/// fieldMul: (a * b) mod p
fn fieldMul(t: *BBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    // OP_MUL
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.names.append(t.allocator, "_bb_prod");
    // Product of two non-negative values is non-negative, simple OP_MOD
    try t.toTop("_bb_prod");
    t.popNames(1);
    try t.emitPushInt(BB_P);
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

/// fieldSqr: (a * a) mod p
fn fieldSqr(t: *BBTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_bb_sqr_copy");
    try fieldMul(t, a_name, "_bb_sqr_copy", result_name);
}

/// fieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
/// p-2 = 2013265919 = 0b111_0111_1111_1111_1111_1111_1111_1111
/// 31 bits, popcount 28.
/// ~30 squarings + ~27 multiplies = ~57 compound operations.
fn fieldInv(t: *BBTracker, a_name: []const u8, result_name: []const u8) !void {
    // Start: result = a (for MSB bit 30 = 1)
    try t.copyToTop(a_name, "_inv_r");

    // Process bits 29 down to 0 (30 bits)
    var i: i32 = 29;
    while (i >= 0) : (i -= 1) {
        // Always square
        try fieldSqr(t, "_inv_r", "_inv_r2");
        t.renameTop("_inv_r");

        // Multiply if bit is set
        if (((BB_P_MINUS_2 >> @as(u5, @intCast(i))) & 1) != 0) {
            try t.copyToTop(a_name, "_inv_a");
            try fieldMul(t, "_inv_r", "_inv_a", "_inv_m");
            t.renameTop("_inv_r");
        }
    }

    // Clean up original input and rename result
    try t.toTop(a_name);
    try t.drop();
    try t.toTop("_inv_r");
    t.renameTop(result_name);
}

// ===========================================================================
// Public emit functions — entry points
// ===========================================================================

/// emitBBFieldAdd: Baby Bear field addition.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a + b) mod p]
fn emitBBFieldAdd(t: *BBTracker) !void {
    try fieldAdd(t, "a", "b", "result");
}

/// emitBBFieldSub: Baby Bear field subtraction.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a - b) mod p]
fn emitBBFieldSub(t: *BBTracker) !void {
    try fieldSub(t, "a", "b", "result");
}

/// emitBBFieldMul: Baby Bear field multiplication.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a * b) mod p]
fn emitBBFieldMul(t: *BBTracker) !void {
    try fieldMul(t, "a", "b", "result");
}

/// emitBBFieldInv: Baby Bear field multiplicative inverse.
/// Stack in: [..., a]
/// Stack out: [..., a^(p-2) mod p]
fn emitBBFieldInv(t: *BBTracker) !void {
    try fieldInv(t, "a", "result");
}

// ===========================================================================
// Tests
// ===========================================================================

test "buildBuiltinOps produces ops for all BB builtins" {
    const allocator = std.testing.allocator;

    inline for (@typeInfo(BBBuiltin).@"enum".fields) |field| {
        const builtin: BBBuiltin = @enumFromInt(field.value);
        var bundle = try buildBuiltinOps(allocator, builtin);
        defer bundle.deinit();
        try std.testing.expect(bundle.ops.len > 0);
    }
}

test "bb_field_add produces expected opcode sequence" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bb_field_add);
    defer bundle.deinit();
    // Should contain OP_ADD and OP_MOD at minimum
    var has_add = false;
    var has_mod = false;
    for (bundle.ops) |op| {
        switch (op) {
            .opcode => |name| {
                if (std.mem.eql(u8, name, "OP_ADD")) has_add = true;
                if (std.mem.eql(u8, name, "OP_MOD")) has_mod = true;
            },
            else => {},
        }
    }
    try std.testing.expect(has_add);
    try std.testing.expect(has_mod);
}

test "bb_field_inv produces ops for square-and-multiply" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bb_field_inv);
    defer bundle.deinit();
    // Should produce many ops due to unrolled exponentiation
    try std.testing.expect(bundle.ops.len > 50);
}
