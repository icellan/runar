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
    bb_ext4_mul0,
    bb_ext4_mul1,
    bb_ext4_mul2,
    bb_ext4_mul3,
    bb_ext4_inv0,
    bb_ext4_inv1,
    bb_ext4_inv2,
    bb_ext4_inv3,
};

pub fn buildBuiltinOps(allocator: Allocator, builtin: BBBuiltin) !EcOpBundle {
    var tracker = try BBTracker.init(allocator, initialNames(builtin));
    errdefer tracker.deinit();

    switch (builtin) {
        .bb_field_add => try emitBBFieldAdd(&tracker),
        .bb_field_sub => try emitBBFieldSub(&tracker),
        .bb_field_mul => try emitBBFieldMul(&tracker),
        .bb_field_inv => try emitBBFieldInv(&tracker),
        .bb_ext4_mul0 => try emitExt4MulComponent(&tracker, 0),
        .bb_ext4_mul1 => try emitExt4MulComponent(&tracker, 1),
        .bb_ext4_mul2 => try emitExt4MulComponent(&tracker, 2),
        .bb_ext4_mul3 => try emitExt4MulComponent(&tracker, 3),
        .bb_ext4_inv0 => try emitExt4InvComponent(&tracker, 0),
        .bb_ext4_inv1 => try emitExt4InvComponent(&tracker, 1),
        .bb_ext4_inv2 => try emitExt4InvComponent(&tracker, 2),
        .bb_ext4_inv3 => try emitExt4InvComponent(&tracker, 3),
    }

    return tracker.takeBundle();
}

fn initialNames(builtin: BBBuiltin) []const ?[]const u8 {
    return switch (builtin) {
        .bb_field_add => &.{ "a", "b" },
        .bb_field_sub => &.{ "a", "b" },
        .bb_field_mul => &.{ "a", "b" },
        .bb_field_inv => &.{"a"},
        .bb_ext4_mul0, .bb_ext4_mul1, .bb_ext4_mul2, .bb_ext4_mul3 => &.{ "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3" },
        .bb_ext4_inv0, .bb_ext4_inv1, .bb_ext4_inv2, .bb_ext4_inv3 => &.{ "a0", "a1", "a2", "a3" },
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
// Quartic extension field helpers (W = 11)
// ===========================================================================

/// Extension polynomial: X^4 - W where W = 11.
const BB_W: i64 = 11;

/// fieldMulConst: (a * c) mod p where c is a compile-time constant.
fn fieldMulConst(t: *BBTracker, a_name: []const u8, c: i64, result_name: []const u8) !void {
    try t.toTop(a_name);
    t.popNames(1);
    try t.emitPushInt(c);
    try t.emitOpcode("OP_MUL");
    try t.emitPushInt(BB_P);
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

/// Emit ext4 multiplication component.
/// Stack in:  [a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [result]  (the selected component r0..r3)
fn emitExt4MulComponent(t: *BBTracker, component: u2) !void {
    switch (component) {
        0 => {
            // r0 = a0*b0 + 11*(a1*b3 + a2*b2 + a3*b1)
            try t.copyToTop("a0", "_a0");
            try t.copyToTop("b0", "_b0");
            try fieldMul(t, "_a0", "_b0", "_t0"); // a0*b0
            try t.copyToTop("a1", "_a1");
            try t.copyToTop("b3", "_b3");
            try fieldMul(t, "_a1", "_b3", "_t1"); // a1*b3
            try t.copyToTop("a2", "_a2");
            try t.copyToTop("b2", "_b2");
            try fieldMul(t, "_a2", "_b2", "_t2"); // a2*b2
            try fieldAdd(t, "_t1", "_t2", "_t12"); // a1*b3 + a2*b2
            try t.copyToTop("a3", "_a3");
            try t.copyToTop("b1", "_b1");
            try fieldMul(t, "_a3", "_b1", "_t3"); // a3*b1
            try fieldAdd(t, "_t12", "_t3", "_cross"); // a1*b3 + a2*b2 + a3*b1
            try fieldMulConst(t, "_cross", BB_W, "_wcross"); // W * cross
            try fieldAdd(t, "_t0", "_wcross", "_r"); // a0*b0 + W*cross
        },
        1 => {
            // r1 = a0*b1 + a1*b0 + 11*(a2*b3 + a3*b2)
            try t.copyToTop("a0", "_a0");
            try t.copyToTop("b1", "_b1");
            try fieldMul(t, "_a0", "_b1", "_t0"); // a0*b1
            try t.copyToTop("a1", "_a1");
            try t.copyToTop("b0", "_b0");
            try fieldMul(t, "_a1", "_b0", "_t1"); // a1*b0
            try fieldAdd(t, "_t0", "_t1", "_direct"); // a0*b1 + a1*b0
            try t.copyToTop("a2", "_a2");
            try t.copyToTop("b3", "_b3");
            try fieldMul(t, "_a2", "_b3", "_t2"); // a2*b3
            try t.copyToTop("a3", "_a3");
            try t.copyToTop("b2", "_b2");
            try fieldMul(t, "_a3", "_b2", "_t3"); // a3*b2
            try fieldAdd(t, "_t2", "_t3", "_cross"); // a2*b3 + a3*b2
            try fieldMulConst(t, "_cross", BB_W, "_wcross"); // W * cross
            try fieldAdd(t, "_direct", "_wcross", "_r");
        },
        2 => {
            // r2 = a0*b2 + a1*b1 + a2*b0 + 11*(a3*b3)
            try t.copyToTop("a0", "_a0");
            try t.copyToTop("b2", "_b2");
            try fieldMul(t, "_a0", "_b2", "_t0"); // a0*b2
            try t.copyToTop("a1", "_a1");
            try t.copyToTop("b1", "_b1");
            try fieldMul(t, "_a1", "_b1", "_t1"); // a1*b1
            try fieldAdd(t, "_t0", "_t1", "_sum01");
            try t.copyToTop("a2", "_a2");
            try t.copyToTop("b0", "_b0");
            try fieldMul(t, "_a2", "_b0", "_t2"); // a2*b0
            try fieldAdd(t, "_sum01", "_t2", "_direct");
            try t.copyToTop("a3", "_a3");
            try t.copyToTop("b3", "_b3");
            try fieldMul(t, "_a3", "_b3", "_t3"); // a3*b3
            try fieldMulConst(t, "_t3", BB_W, "_wcross"); // W * a3*b3
            try fieldAdd(t, "_direct", "_wcross", "_r");
        },
        3 => {
            // r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
            try t.copyToTop("a0", "_a0");
            try t.copyToTop("b3", "_b3");
            try fieldMul(t, "_a0", "_b3", "_t0"); // a0*b3
            try t.copyToTop("a1", "_a1");
            try t.copyToTop("b2", "_b2");
            try fieldMul(t, "_a1", "_b2", "_t1"); // a1*b2
            try fieldAdd(t, "_t0", "_t1", "_sum01");
            try t.copyToTop("a2", "_a2");
            try t.copyToTop("b1", "_b1");
            try fieldMul(t, "_a2", "_b1", "_t2"); // a2*b1
            try fieldAdd(t, "_sum01", "_t2", "_sum012");
            try t.copyToTop("a3", "_a3");
            try t.copyToTop("b0", "_b0");
            try fieldMul(t, "_a3", "_b0", "_t3"); // a3*b0
            try fieldAdd(t, "_sum012", "_t3", "_r");
        },
    }

    // Clean up: drop the 8 input values, keep only _r
    for ([_][]const u8{ "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3" }) |name| {
        try t.toTop(name);
        try t.drop();
    }
    try t.toTop("_r");
    t.renameTop("result");
}

/// Emit ext4 inverse component.
/// Tower-of-quadratic-extensions algorithm (matches Plonky3):
///
/// View element as (even, odd) where even = (a0, a2), odd = (a1, a3)
/// in the quadratic extension F[X^2]/(X^4-W) = F'[Y]/(Y^2-W) where Y = X^2.
///
/// norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
/// norm_1 = 2*a0*a2 - a1^2 - W*a3^2
///
/// scalar = (norm_0^2 - W*norm_1^2)^(-1)
/// inv_n0 = norm_0 * scalar
/// inv_n1 = -norm_1 * scalar
///
/// quad_mul((x0,x1),(y0,y1)) = (x0*y0 + W*x1*y1, x0*y1 + x1*y0)
/// out_even = quad_mul((a0, a2), (inv_n0, inv_n1))
/// out_odd  = quad_mul((-a1, -a3), (inv_n0, inv_n1))
/// r0 = out_even[0], r1 = -out_odd[0], r2 = out_even[1], r3 = -out_odd[1]
///
/// Stack in:  [a0, a1, a2, a3]
/// Stack out: [result]  (the selected component r0..r3)
fn emitExt4InvComponent(t: *BBTracker, component: u2) !void {
    // 2*W mod p  — used in norm_0 computation
    const TWO_W: i64 = @mod(BB_W * 2, BB_P);

    // Step 1: norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
    try t.copyToTop("a0", "_a0c");
    try fieldSqr(t, "_a0c", "_a0sq"); // a0^2
    try t.copyToTop("a2", "_a2c");
    try fieldSqr(t, "_a2c", "_a2sq"); // a2^2
    try fieldMulConst(t, "_a2sq", BB_W, "_wa2sq"); // W*a2^2
    try fieldAdd(t, "_a0sq", "_wa2sq", "_n0a"); // a0^2 + W*a2^2
    try t.copyToTop("a1", "_a1c");
    try t.copyToTop("a3", "_a3c");
    try fieldMul(t, "_a1c", "_a3c", "_a1a3"); // a1*a3
    try fieldMulConst(t, "_a1a3", TWO_W, "_2wa1a3"); // 2*W*a1*a3
    try fieldSub(t, "_n0a", "_2wa1a3", "_norm0"); // norm_0

    // Step 2: norm_1 = 2*a0*a2 - a1^2 - W*a3^2
    try t.copyToTop("a0", "_a0d");
    try t.copyToTop("a2", "_a2d");
    try fieldMul(t, "_a0d", "_a2d", "_a0a2"); // a0*a2
    try fieldMulConst(t, "_a0a2", 2, "_2a0a2"); // 2*a0*a2
    try t.copyToTop("a1", "_a1d");
    try fieldSqr(t, "_a1d", "_a1sq"); // a1^2
    try fieldSub(t, "_2a0a2", "_a1sq", "_n1a"); // 2*a0*a2 - a1^2
    try t.copyToTop("a3", "_a3d");
    try fieldSqr(t, "_a3d", "_a3sq"); // a3^2
    try fieldMulConst(t, "_a3sq", BB_W, "_wa3sq"); // W*a3^2
    try fieldSub(t, "_n1a", "_wa3sq", "_norm1"); // norm_1

    // Step 3: scalar = (norm_0^2 - W*norm_1^2)^(-1)
    try t.copyToTop("_norm0", "_n0copy");
    try fieldSqr(t, "_n0copy", "_n0sq"); // norm_0^2
    try t.copyToTop("_norm1", "_n1copy");
    try fieldSqr(t, "_n1copy", "_n1sq"); // norm_1^2
    try fieldMulConst(t, "_n1sq", BB_W, "_wn1sq"); // W*norm_1^2
    try fieldSub(t, "_n0sq", "_wn1sq", "_det"); // norm_0^2 - W*norm_1^2
    try fieldInv(t, "_det", "_scalar"); // scalar = det^(-1)

    // Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
    try t.copyToTop("_scalar", "_sc0");
    try fieldMul(t, "_norm0", "_sc0", "_inv_n0"); // inv_n0 = norm_0 * scalar

    // -norm_1 = (p - norm_1) mod p  — must match TS: copyToTop + pushInt(p) + swap + OP_SUB + fieldMod
    try t.copyToTop("_norm1", "_neg_n1_pre");
    try t.pushInt("_pval", BB_P);
    try t.toTop("_neg_n1_pre");
    // rawBlock: consumes _pval and _neg_n1_pre, produces _neg_n1_sub
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.names.append(t.allocator, "_neg_n1_sub");
    try fieldMod(t, "_neg_n1_sub", "_neg_norm1");
    try fieldMul(t, "_neg_norm1", "_scalar", "_inv_n1");

    // Step 5: Compute result components using quad_mul
    switch (component) {
        0 => {
            // r0 = out_even[0] = a0*inv_n0 + W*a2*inv_n1
            try t.copyToTop("a0", "_ea0");
            try t.copyToTop("_inv_n0", "_ein0");
            try fieldMul(t, "_ea0", "_ein0", "_ep0"); // a0*inv_n0
            try t.copyToTop("a2", "_ea2");
            try t.copyToTop("_inv_n1", "_ein1");
            try fieldMul(t, "_ea2", "_ein1", "_ep1"); // a2*inv_n1
            try fieldMulConst(t, "_ep1", BB_W, "_wep1"); // W*a2*inv_n1
            try fieldAdd(t, "_ep0", "_wep1", "_r");
        },
        1 => {
            // r1 = -odd_part[0] where odd0 = a1*inv_n0 + W*a3*inv_n1
            try t.copyToTop("a1", "_oa1");
            try t.copyToTop("_inv_n0", "_oin0");
            try fieldMul(t, "_oa1", "_oin0", "_op0"); // a1*inv_n0
            try t.copyToTop("a3", "_oa3");
            try t.copyToTop("_inv_n1", "_oin1");
            try fieldMul(t, "_oa3", "_oin1", "_op1"); // a3*inv_n1
            try fieldMulConst(t, "_op1", BB_W, "_wop1"); // W*a3*inv_n1
            try fieldAdd(t, "_op0", "_wop1", "_odd0");
            // Negate: r = (0 - odd0) mod p — match TS: pushInt('_zero1', 0) + fieldSub
            try t.pushInt("_zero1", 0);
            try fieldSub(t, "_zero1", "_odd0", "_r");
        },
        2 => {
            // r2 = out_even[1] = a0*inv_n1 + a2*inv_n0
            try t.copyToTop("a0", "_ea0");
            try t.copyToTop("_inv_n1", "_ein1");
            try fieldMul(t, "_ea0", "_ein1", "_ep0"); // a0*inv_n1
            try t.copyToTop("a2", "_ea2");
            try t.copyToTop("_inv_n0", "_ein0");
            try fieldMul(t, "_ea2", "_ein0", "_ep1"); // a2*inv_n0
            try fieldAdd(t, "_ep0", "_ep1", "_r");
        },
        3 => {
            // r3 = -odd_part[1] where odd1 = a1*inv_n1 + a3*inv_n0
            try t.copyToTop("a1", "_oa1");
            try t.copyToTop("_inv_n1", "_oin1");
            try fieldMul(t, "_oa1", "_oin1", "_op0"); // a1*inv_n1
            try t.copyToTop("a3", "_oa3");
            try t.copyToTop("_inv_n0", "_oin0");
            try fieldMul(t, "_oa3", "_oin0", "_op1"); // a3*inv_n0
            try fieldAdd(t, "_op0", "_op1", "_odd1");
            // Negate: r = (0 - odd1) mod p — match TS: pushInt('_zero3', 0) + fieldSub
            try t.pushInt("_zero3", 0);
            try fieldSub(t, "_zero3", "_odd1", "_r");
        },
    }

    // Clean up: drop all intermediate and input values, keep only _r
    // Must match TS: snapshot names bottom-to-top (excluding null and _r), then drop in that order.
    {
        // Snapshot the name stack (bottom to top), collecting non-null, non-_r names.
        var remaining: std.ArrayListUnmanaged([]const u8) = .empty;
        defer remaining.deinit(t.allocator);
        for (t.names.items) |slot| {
            const name = slot orelse continue;
            if (!std.mem.eql(u8, name, "_r")) {
                try remaining.append(t.allocator, name);
            }
        }
        for (remaining.items) |name| {
            try t.toTop(name);
            try t.drop();
        }
    }
    try t.toTop("_r");
    t.renameTop("result");
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
