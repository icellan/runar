//! KoalaBear field arithmetic codegen — KoalaBear prime field operations for Bitcoin Script.
//!
//! Follows the babybear_emitters.zig pattern: self-contained module imported by
//! stack_lower.zig. Uses a KBTracker for named stack state tracking.
//!
//! KoalaBear prime: p = 2^31 - 2^24 + 1 = 2,130,706,433 (0x7f000001)
//! Used by SP1 v6 STARK proofs (StackedBasefold verification).
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

/// KoalaBear field prime p = 2^31 - 2^24 + 1 = 2,130,706,433
const KB_P: i64 = 2130706433;
/// p - 2, used for Fermat's little theorem modular inverse
/// p - 2 = 0x7eFFFFFF = 0b0111_1110_1111_1111_1111_1111_1111_1111
const KB_P_MINUS_2: u32 = 2130706431;
/// Extension non-residue W = 3 (used for ext4: x^4 - 3)
const KB_W: i64 = 3;

pub const KBBuiltin = enum {
    kb_field_add,
    kb_field_sub,
    kb_field_mul,
    kb_field_inv,
    kb_ext4_mul0,
    kb_ext4_mul1,
    kb_ext4_mul2,
    kb_ext4_mul3,
    kb_ext4_inv0,
    kb_ext4_inv1,
    kb_ext4_inv2,
    kb_ext4_inv3,
};

pub fn buildBuiltinOps(allocator: Allocator, builtin: KBBuiltin) !EcOpBundle {
    var tracker = try KBTracker.init(allocator, initialNames(builtin));
    errdefer tracker.deinit();

    switch (builtin) {
        .kb_field_add => try emitKBFieldAdd(&tracker),
        .kb_field_sub => try emitKBFieldSub(&tracker),
        .kb_field_mul => try emitKBFieldMul(&tracker),
        .kb_field_inv => try emitKBFieldInv(&tracker),
        .kb_ext4_mul0 => try emitExt4MulComponent(&tracker, 0),
        .kb_ext4_mul1 => try emitExt4MulComponent(&tracker, 1),
        .kb_ext4_mul2 => try emitExt4MulComponent(&tracker, 2),
        .kb_ext4_mul3 => try emitExt4MulComponent(&tracker, 3),
        .kb_ext4_inv0 => try emitExt4InvComponent(&tracker, 0),
        .kb_ext4_inv1 => try emitExt4InvComponent(&tracker, 1),
        .kb_ext4_inv2 => try emitExt4InvComponent(&tracker, 2),
        .kb_ext4_inv3 => try emitExt4InvComponent(&tracker, 3),
    }

    return tracker.takeBundle();
}

fn initialNames(builtin: KBBuiltin) []const ?[]const u8 {
    return switch (builtin) {
        .kb_field_add => &.{ "a", "b" },
        .kb_field_sub => &.{ "a", "b" },
        .kb_field_mul => &.{ "a", "b" },
        .kb_field_inv => &.{"a"},
        .kb_ext4_mul0, .kb_ext4_mul1, .kb_ext4_mul2, .kb_ext4_mul3 => &.{ "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3" },
        .kb_ext4_inv0, .kb_ext4_inv1, .kb_ext4_inv2, .kb_ext4_inv3 => &.{ "a0", "a1", "a2", "a3" },
    };
}

// ===========================================================================
// KBTracker — named stack state tracker (mirrors BBTracker)
// ===========================================================================

pub const KBTracker = struct {
    allocator: Allocator,
    names: std.ArrayListUnmanaged(?[]const u8),
    ops: std.ArrayListUnmanaged(StackOp),
    owned_bytes: std.ArrayListUnmanaged([]u8),
    prime_cache_active: bool,

    pub fn init(allocator: Allocator, initial_names: []const ?[]const u8) !KBTracker {
        var names: std.ArrayListUnmanaged(?[]const u8) = .empty;
        errdefer names.deinit(allocator);
        try names.appendSlice(allocator, initial_names);
        return .{
            .allocator = allocator,
            .names = names,
            .ops = .empty,
            .owned_bytes = .empty,
            .prime_cache_active = false,
        };
    }

    pub fn deinit(self: *KBTracker) void {
        ec.deinitOpsRecursive(self.allocator, self.ops.items);
        self.ops.deinit(self.allocator);
        self.names.deinit(self.allocator);
        for (self.owned_bytes.items) |bytes| self.allocator.free(bytes);
        self.owned_bytes.deinit(self.allocator);
    }

    pub fn takeBundle(self: *KBTracker) !EcOpBundle {
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

    pub fn findDepth(self: *const KBTracker, name: []const u8) !usize {
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

    pub fn emitRaw(self: *KBTracker, op: StackOp) !void {
        try self.ops.append(self.allocator, op);
    }

    pub fn emitOpcode(self: *KBTracker, code: []const u8) !void {
        try self.emitRaw(.{ .opcode = code });
    }

    pub fn emitPushInt(self: *KBTracker, value: i64) !void {
        try self.emitRaw(.{ .push = .{ .integer = value } });
    }

    pub fn pushInt(self: *KBTracker, name: ?[]const u8, value: i64) !void {
        try self.emitPushInt(value);
        try self.names.append(self.allocator, name);
    }

    pub fn dup(self: *KBTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .dup = {} });
        try self.names.append(self.allocator, name);
    }

    pub fn drop(self: *KBTracker) !void {
        try self.emitRaw(.{ .drop = {} });
        _ = self.names.pop();
    }

    pub fn swap(self: *KBTracker) !void {
        try self.emitRaw(.{ .swap = {} });
        const len = self.names.items.len;
        if (len >= 2) {
            const tmp = self.names.items[len - 1];
            self.names.items[len - 1] = self.names.items[len - 2];
            self.names.items[len - 2] = tmp;
        }
    }

    pub fn nip(self: *KBTracker) !void {
        try self.emitRaw(.{ .nip = {} });
        const len = self.names.items.len;
        if (len >= 2) {
            _ = self.names.orderedRemove(len - 2);
        }
    }

    pub fn over(self: *KBTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .over = {} });
        try self.names.append(self.allocator, name);
    }

    pub fn rot(self: *KBTracker) !void {
        try self.emitRaw(.{ .rot = {} });
        const len = self.names.items.len;
        if (len >= 3) {
            const rolled = self.names.orderedRemove(len - 3);
            try self.names.append(self.allocator, rolled);
        }
    }

    pub fn roll(self: *KBTracker, depth_from_top: usize) !void {
        if (depth_from_top == 0) return;
        if (depth_from_top == 1) return self.swap();
        if (depth_from_top == 2) return self.rot();
        try self.emitRaw(.{ .roll = @intCast(depth_from_top) });
        const idx = self.names.items.len - 1 - depth_from_top;
        const rolled = self.names.orderedRemove(idx);
        try self.names.append(self.allocator, rolled);
    }

    pub fn pick(self: *KBTracker, depth_from_top: usize, name: ?[]const u8) !void {
        if (depth_from_top == 0) return self.dup(name);
        if (depth_from_top == 1) return self.over(name);
        try self.emitRaw(.{ .pick = @intCast(depth_from_top) });
        try self.names.append(self.allocator, name);
    }

    pub fn toTop(self: *KBTracker, name: []const u8) !void {
        try self.roll(try self.findDepth(name));
    }

    pub fn copyToTop(self: *KBTracker, name: []const u8, copy_name: ?[]const u8) !void {
        try self.pick(try self.findDepth(name), copy_name);
    }

    pub fn renameTop(self: *KBTracker, name: ?[]const u8) void {
        if (self.names.items.len > 0) {
            self.names.items[self.names.items.len - 1] = name;
        }
    }

    pub fn popNames(self: *KBTracker, count: usize) void {
        var i: usize = 0;
        while (i < count and self.names.items.len > 0) : (i += 1) {
            _ = self.names.pop();
        }
    }

    /// pushPrimeCache pushes KB_P to the alt-stack for caching.
    /// All subsequent emitPrime calls use the cached prime via FROMALTSTACK/DUP/TOALTSTACK.
    pub fn pushPrimeCache(self: *KBTracker) !void {
        try self.emitPushInt(KB_P);
        try self.emitOpcode("OP_TOALTSTACK");
        self.prime_cache_active = true;
    }

    /// popPrimeCache removes the cached prime from the alt-stack.
    pub fn popPrimeCache(self: *KBTracker) !void {
        try self.emitOpcode("OP_FROMALTSTACK");
        try self.emitOpcode("OP_DROP");
        self.prime_cache_active = false;
    }

    /// emitPrime emits the field prime onto the stack — from cache or fresh push.
    pub fn emitPrime(self: *KBTracker) !void {
        if (self.prime_cache_active) {
            try self.emitOpcode("OP_FROMALTSTACK");
            try self.emitOpcode("OP_DUP");
            try self.emitOpcode("OP_TOALTSTACK");
        } else {
            try self.emitPushInt(KB_P);
        }
    }
};

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

/// fieldMod: ensure value is in [0, p).
/// Pattern: (a % p + p) % p — handles negative values from sub.
fn fieldMod(t: *KBTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    t.popNames(1);
    // (a % p + p) % p
    try t.emitPrime();
    try t.emitOpcode("OP_MOD");
    try t.emitPrime();
    try t.emitOpcode("OP_ADD");
    try t.emitPrime();
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

/// fieldAddUnreduced: a + b WITHOUT modular reduction.
/// Result is in [0, 2p-2]. Safe when immediately consumed by mul or further adds.
fn fieldAddUnreduced(t: *KBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, result_name);
}

/// fieldAdd: (a + b) mod p
fn fieldAdd(t: *KBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, "_kb_add");
    // Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
    try t.toTop("_kb_add");
    t.popNames(1);
    try t.emitPrime();
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

/// fieldSub: (a - b) mod p (non-negative)
fn fieldSub(t: *KBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.names.append(t.allocator, "_kb_diff");
    try fieldMod(t, "_kb_diff", result_name);
}

/// fieldMul: (a * b) mod p
fn fieldMul(t: *KBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.names.append(t.allocator, "_kb_prod");
    try t.toTop("_kb_prod");
    t.popNames(1);
    try t.emitPrime();
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

/// fieldSqr: (a * a) mod p
fn fieldSqr(t: *KBTracker, a_name: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_kb_sqr_copy");
    try fieldMul(t, a_name, "_kb_sqr_copy", result_name);
}

/// fieldMulConst: (a * c) mod p where c is a compile-time constant.
/// Uses OP_2MUL when c==2, OP_LSHIFTNUM when c is a higher power of 2,
/// otherwise OP_MUL with an explicit push.
fn fieldMulConst(t: *KBTracker, a_name: []const u8, c: i64, result_name: []const u8) !void {
    try t.toTop(a_name);
    t.popNames(1);
    if (c == 2) {
        try t.emitOpcode("OP_2MUL");
    } else if (c > 2 and (c & (c - 1)) == 0) {
        // c is a power of 2: use OP_LSHIFTNUM
        var shift: u6 = 0;
        var tmp = @as(u64, @intCast(c));
        while (tmp > 1) {
            tmp >>= 1;
            shift += 1;
        }
        try t.emitPushInt(@intCast(shift));
        try t.emitOpcode("OP_LSHIFTNUM");
    } else {
        try t.emitPushInt(c);
        try t.emitOpcode("OP_MUL");
    }
    try t.names.append(t.allocator, "_kb_mc");
    // mod reduction
    try t.toTop("_kb_mc");
    t.popNames(1);
    try t.emitPrime();
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

/// fieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
/// p-2 = 2130706431 = 0x7eFFFFFF
/// 31 bits, popcount 30.
fn fieldInv(t: *KBTracker, a_name: []const u8, result_name: []const u8) !void {
    // Start: result = a (for MSB bit 30 = 1)
    try t.copyToTop(a_name, "_inv_r");

    // Process bits 29 down to 0 (30 bits)
    var i: i32 = 29;
    while (i >= 0) : (i -= 1) {
        // Always square
        try fieldSqr(t, "_inv_r", "_inv_r2");
        t.renameTop("_inv_r");

        // Multiply if bit is set
        if (((KB_P_MINUS_2 >> @as(u5, @intCast(i))) & 1) != 0) {
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
// Quartic extension field helpers (W = 3)
// ===========================================================================
//
// Extension field F_p^4 over KoalaBear using irreducible x^4 - W where W = 3.
// Elements are (a0, a1, a2, a3) representing a0 + a1*x + a2*x^2 + a3*x^3.
//
// Multiplication:
//   r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
//   r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
//   r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
//   r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0

/// Emit ext4 multiplication component.
/// Stack in:  [a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [result]  (the selected component r0..r3)
fn emitExt4MulComponent(t: *KBTracker, component: u2) !void {
    switch (component) {
        0 => {
            // r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
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
            try fieldMulConst(t, "_cross", KB_W, "_wcross"); // W * cross
            try fieldAdd(t, "_t0", "_wcross", "_r"); // a0*b0 + W*cross
        },
        1 => {
            // r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
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
            try fieldMulConst(t, "_cross", KB_W, "_wcross"); // W * cross
            try fieldAdd(t, "_direct", "_wcross", "_r");
        },
        2 => {
            // r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
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
            try fieldMulConst(t, "_t3", KB_W, "_wcross"); // W * a3*b3
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
/// Tower-of-quadratic-extensions algorithm:
///
/// norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
/// norm_1 = 2*a0*a2 - a1^2 - W*a3^2
/// scalar = (norm_0^2 - W*norm_1^2)^(-1)
/// inv_n0 = norm_0 * scalar
/// inv_n1 = -norm_1 * scalar
///
/// r0 = a0*inv_n0 + W*a2*inv_n1
/// r1 = -(a1*inv_n0 + W*a3*inv_n1)
/// r2 = a0*inv_n1 + a2*inv_n0
/// r3 = -(a1*inv_n1 + a3*inv_n0)
///
/// Stack in:  [a0, a1, a2, a3]
/// Stack out: [result]  (the selected component r0..r3)
fn emitExt4InvComponent(t: *KBTracker, component: u2) !void {
    // Step 1: norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
    try t.copyToTop("a0", "_a0c");
    try fieldSqr(t, "_a0c", "_a0sq"); // a0^2
    try t.copyToTop("a2", "_a2c");
    try fieldSqr(t, "_a2c", "_a2sq"); // a2^2
    try fieldMulConst(t, "_a2sq", KB_W, "_wa2sq"); // W*a2^2
    try fieldAdd(t, "_a0sq", "_wa2sq", "_n0a"); // a0^2 + W*a2^2
    try t.copyToTop("a1", "_a1c");
    try t.copyToTop("a3", "_a3c");
    try fieldMul(t, "_a1c", "_a3c", "_a1a3"); // a1*a3
    const TWO_W: i64 = KB_W * 2; // 2*W = 6
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
    try fieldMulConst(t, "_a3sq", KB_W, "_wa3sq"); // W*a3^2
    try fieldSub(t, "_n1a", "_wa3sq", "_norm1"); // norm_1

    // Step 3: scalar = (norm_0^2 - W*norm_1^2)^(-1)
    try t.copyToTop("_norm0", "_n0copy");
    try fieldSqr(t, "_n0copy", "_n0sq"); // norm_0^2
    try t.copyToTop("_norm1", "_n1copy");
    try fieldSqr(t, "_n1copy", "_n1sq"); // norm_1^2
    try fieldMulConst(t, "_n1sq", KB_W, "_wn1sq"); // W*norm_1^2
    try fieldSub(t, "_n0sq", "_wn1sq", "_det"); // norm_0^2 - W*norm_1^2
    try fieldInv(t, "_det", "_scalar"); // scalar = det^(-1)

    // Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
    try t.copyToTop("_scalar", "_sc0");
    try fieldMul(t, "_norm0", "_sc0", "_inv_n0"); // inv_n0 = norm_0 * scalar

    // -norm_1 = (p - norm_1) mod p — match Go: copyToTop + pushInt(p) + toTop + OP_SUB + fieldMod
    try t.copyToTop("_norm1", "_neg_n1_pre");
    try t.pushInt("_pval", KB_P);
    try t.toTop("_neg_n1_pre");
    // consumes _pval and _neg_n1_pre (order: _pval deep, _neg_n1_pre on top)
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.names.append(t.allocator, "_neg_n1_sub");
    try fieldMod(t, "_neg_n1_sub", "_neg_norm1");
    try fieldMul(t, "_neg_norm1", "_scalar", "_inv_n1");

    // Step 5: Compute result components using quad_mul
    switch (component) {
        0 => {
            // r0 = a0*inv_n0 + W*a2*inv_n1
            try t.copyToTop("a0", "_ea0");
            try t.copyToTop("_inv_n0", "_ein0");
            try fieldMul(t, "_ea0", "_ein0", "_ep0"); // a0*inv_n0
            try t.copyToTop("a2", "_ea2");
            try t.copyToTop("_inv_n1", "_ein1");
            try fieldMul(t, "_ea2", "_ein1", "_ep1"); // a2*inv_n1
            try fieldMulConst(t, "_ep1", KB_W, "_wep1"); // W*a2*inv_n1
            try fieldAdd(t, "_ep0", "_wep1", "_r");
        },
        1 => {
            // r1 = -(a1*inv_n0 + W*a3*inv_n1)
            try t.copyToTop("a1", "_oa1");
            try t.copyToTop("_inv_n0", "_oin0");
            try fieldMul(t, "_oa1", "_oin0", "_op0"); // a1*inv_n0
            try t.copyToTop("a3", "_oa3");
            try t.copyToTop("_inv_n1", "_oin1");
            try fieldMul(t, "_oa3", "_oin1", "_op1"); // a3*inv_n1
            try fieldMulConst(t, "_op1", KB_W, "_wop1"); // W*a3*inv_n1
            try fieldAdd(t, "_op0", "_wop1", "_odd0");
            // Negate: r = (0 - odd0) mod p
            try t.pushInt("_zero1", 0);
            try fieldSub(t, "_zero1", "_odd0", "_r");
        },
        2 => {
            // r2 = a0*inv_n1 + a2*inv_n0
            try t.copyToTop("a0", "_ea0");
            try t.copyToTop("_inv_n1", "_ein1");
            try fieldMul(t, "_ea0", "_ein1", "_ep0"); // a0*inv_n1
            try t.copyToTop("a2", "_ea2");
            try t.copyToTop("_inv_n0", "_ein0");
            try fieldMul(t, "_ea2", "_ein0", "_ep1"); // a2*inv_n0
            try fieldAdd(t, "_ep0", "_ep1", "_r");
        },
        3 => {
            // r3 = -(a1*inv_n1 + a3*inv_n0)
            try t.copyToTop("a1", "_oa1");
            try t.copyToTop("_inv_n1", "_oin1");
            try fieldMul(t, "_oa1", "_oin1", "_op0"); // a1*inv_n1
            try t.copyToTop("a3", "_oa3");
            try t.copyToTop("_inv_n0", "_oin0");
            try fieldMul(t, "_oa3", "_oin0", "_op1"); // a3*inv_n0
            try fieldAdd(t, "_op0", "_op1", "_odd1");
            // Negate: r = (0 - odd1) mod p
            try t.pushInt("_zero3", 0);
            try fieldSub(t, "_zero3", "_odd1", "_r");
        },
    }

    // Clean up: drop all intermediate and input values, keep only _r
    {
        var remaining = std.ArrayListUnmanaged([]const u8){};
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

/// emitKBFieldAdd: KoalaBear field addition.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a + b) mod p]
fn emitKBFieldAdd(t: *KBTracker) !void {
    try fieldAdd(t, "a", "b", "result");
}

/// emitKBFieldSub: KoalaBear field subtraction.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a - b) mod p]
fn emitKBFieldSub(t: *KBTracker) !void {
    try fieldSub(t, "a", "b", "result");
}

/// emitKBFieldMul: KoalaBear field multiplication.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a * b) mod p]
fn emitKBFieldMul(t: *KBTracker) !void {
    try fieldMul(t, "a", "b", "result");
}

/// emitKBFieldInv: KoalaBear field multiplicative inverse.
/// Stack in: [..., a]
/// Stack out: [..., a^(p-2) mod p]
fn emitKBFieldInv(t: *KBTracker) !void {
    try fieldInv(t, "a", "result");
}

// ===========================================================================
// Internal field helpers exposed for Poseidon2 codegen
// ===========================================================================

/// kbFieldAdd exposed for poseidon2_koalabear.zig
pub fn kbFieldAdd(t: *KBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try fieldAdd(t, a_name, b_name, result_name);
}

/// kbFieldAddUnreduced exposed for poseidon2_koalabear.zig
pub fn kbFieldAddUnreduced(t: *KBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try fieldAddUnreduced(t, a_name, b_name, result_name);
}

/// kbFieldSub exposed for poseidon2_koalabear.zig
pub fn kbFieldSub(t: *KBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try fieldSub(t, a_name, b_name, result_name);
}

/// kbFieldMul exposed for poseidon2_koalabear.zig
pub fn kbFieldMul(t: *KBTracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try fieldMul(t, a_name, b_name, result_name);
}

/// kbFieldSqr exposed for poseidon2_koalabear.zig
pub fn kbFieldSqr(t: *KBTracker, a_name: []const u8, result_name: []const u8) !void {
    try fieldSqr(t, a_name, result_name);
}

/// kbFieldMulConst exposed for poseidon2_koalabear.zig
pub fn kbFieldMulConst(t: *KBTracker, a_name: []const u8, c: i64, result_name: []const u8) !void {
    try fieldMulConst(t, a_name, c, result_name);
}

// ===========================================================================
// Tests
// ===========================================================================

test "buildBuiltinOps produces ops for all KB builtins" {
    const allocator = std.testing.allocator;

    inline for (@typeInfo(KBBuiltin).@"enum".fields) |field| {
        const builtin: KBBuiltin = @enumFromInt(field.value);
        var bundle = try buildBuiltinOps(allocator, builtin);
        defer bundle.deinit();
        try std.testing.expect(bundle.ops.len > 0);
    }
}

test "kb_field_add produces expected opcode sequence" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .kb_field_add);
    defer bundle.deinit();
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

test "kb_field_inv produces ops for square-and-multiply" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .kb_field_inv);
    defer bundle.deinit();
    // Should produce many ops due to unrolled exponentiation (p-2 has popcount 30)
    try std.testing.expect(bundle.ops.len > 50);
}

test "kb_field_mul uses OP_MUL and OP_MOD" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .kb_field_mul);
    defer bundle.deinit();
    var has_mul = false;
    var has_mod = false;
    for (bundle.ops) |op| {
        switch (op) {
            .opcode => |name| {
                if (std.mem.eql(u8, name, "OP_MUL")) has_mul = true;
                if (std.mem.eql(u8, name, "OP_MOD")) has_mod = true;
            },
            else => {},
        }
    }
    try std.testing.expect(has_mul);
    try std.testing.expect(has_mod);
}
