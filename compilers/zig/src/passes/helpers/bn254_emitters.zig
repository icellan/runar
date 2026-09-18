//! BN254 codegen — BN254 elliptic curve field arithmetic and G1 point operations
//! for Bitcoin Script.
//!
//! Follows the koalabear_emitters.zig / ec_emitters.zig pattern: self-contained
//! module imported by stack_lower.zig. Uses a BN254Tracker for named stack state
//! tracking.
//!
//! BN254 parameters:
//!   Field prime: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
//!   Curve order: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//!   Curve:       y^2 = x^3 + 3
//!   Generator:   G1 = (1, 2)
//!
//! Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
//! Internal arithmetic uses Jacobian coordinates for scalar multiplication.

const std = @import("std");
const ec = @import("ec_emitters.zig");

const Allocator = std.mem.Allocator;
const StackOp = ec.StackOp;
const StackIf = ec.StackIf;
const PushValue = ec.PushValue;
const EcOpBundle = ec.EcOpBundle;

// ===========================================================================
// Constants — BN254 field prime, curve order, and derived values as 32-byte
// big-endian byte arrays. Encoded to script-num format at runtime.
// ===========================================================================

/// BN254 field prime p
/// = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
const bn254_field_p_be = [_]u8{
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
};

/// BN254 curve order r
/// = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
/// BN254 curve order r in decimal, for `big_int_decimal` pushes.
const bn254_curve_r_decimal =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

const bn254_curve_r_be = [_]u8{
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
};

/// BN254 p - 2, used for Fermat's little theorem modular inverse.
/// = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
/// 254 bits, MSB at bit 253 (always set).
const bn254_p_minus_2_be = [_]u8{
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x45,
};

/// Returns bit `i` of p-2 (0 = clear, 1 = set). `i` must be in [0, 253].
fn bn254PMinus2Bit(i: u32) u1 {
    const byte_index: usize = 31 - (i / 8);
    const bit_index: u3 = @intCast(i % 8);
    return @intCast((bn254_p_minus_2_be[byte_index] >> bit_index) & 1);
}

// ===========================================================================
// Public builtin enum + entry points
// ===========================================================================

pub const BN254Builtin = enum {
    bn254_field_add,
    bn254_field_sub,
    bn254_field_mul,
    bn254_field_inv,
    bn254_field_neg,
    bn254_g1_add,
    bn254_g1_scalar_mul,
    bn254_g1_negate,
    bn254_g1_on_curve,
};

pub fn buildBuiltinOps(allocator: Allocator, builtin: BN254Builtin) !EcOpBundle {
    var tracker = try BN254Tracker.init(allocator, initialNames(builtin));
    errdefer tracker.deinit();

    switch (builtin) {
        .bn254_field_add => try emitBN254FieldAdd(&tracker),
        .bn254_field_sub => try emitBN254FieldSub(&tracker),
        .bn254_field_mul => try emitBN254FieldMul(&tracker),
        .bn254_field_inv => try emitBN254FieldInv(&tracker),
        .bn254_field_neg => try emitBN254FieldNeg(&tracker),
        .bn254_g1_add => try emitBN254G1Add(&tracker),
        .bn254_g1_scalar_mul => try emitBN254G1ScalarMul(&tracker),
        .bn254_g1_negate => try emitBN254G1Negate(&tracker),
        .bn254_g1_on_curve => try emitBN254G1OnCurve(&tracker),
    }

    return tracker.takeBundle();
}

fn initialNames(builtin: BN254Builtin) []const ?[]const u8 {
    return switch (builtin) {
        .bn254_field_add, .bn254_field_sub, .bn254_field_mul => &.{ "a", "b" },
        .bn254_field_inv, .bn254_field_neg => &.{"a"},
        .bn254_g1_add => &.{ "_pa", "_pb" },
        .bn254_g1_scalar_mul => &.{ "_pt", "_k" },
        .bn254_g1_negate, .bn254_g1_on_curve => &.{"_pt"},
    };
}

// ===========================================================================
// BN254Tracker — named stack state tracker (mirrors KBTracker / ECTracker)
// ===========================================================================

pub const BN254Tracker = struct {
    allocator: Allocator,
    names: std.ArrayListUnmanaged(?[]const u8),
    ops: std.ArrayListUnmanaged(StackOp),
    owned_bytes: std.ArrayListUnmanaged([]u8),
    prime_cache_active: bool,

    pub fn init(allocator: Allocator, initial_names: []const ?[]const u8) !BN254Tracker {
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

    pub fn deinit(self: *BN254Tracker) void {
        ec.deinitOpsRecursive(self.allocator, self.ops.items);
        self.ops.deinit(self.allocator);
        self.names.deinit(self.allocator);
        for (self.owned_bytes.items) |bytes| self.allocator.free(bytes);
        self.owned_bytes.deinit(self.allocator);
    }

    pub fn takeBundle(self: *BN254Tracker) !EcOpBundle {
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

    pub fn findDepth(self: *const BN254Tracker, name: []const u8) !usize {
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

    pub fn emitRaw(self: *BN254Tracker, op: StackOp) !void {
        try self.ops.append(self.allocator, op);
    }

    pub fn emitOpcode(self: *BN254Tracker, code: []const u8) !void {
        try self.emitRaw(.{ .opcode = code });
    }

    pub fn emitPushInt(self: *BN254Tracker, value: i64) !void {
        try self.emitRaw(.{ .push = .{ .integer = value } });
    }

    pub fn pushInt(self: *BN254Tracker, name: ?[]const u8, value: i64) !void {
        try self.emitPushInt(value);
        try self.names.append(self.allocator, name);
    }

    /// Push the BN254 field prime as script-num bytes, recording the owned
    /// buffer so it is freed when the tracker is destroyed.
    pub fn pushFieldP(self: *BN254Tracker, name: ?[]const u8) !void {
        const encoded = try beToUnsignedScriptNumAlloc(self.allocator, bn254_field_p_be[0..]);
        try self.owned_bytes.append(self.allocator, encoded);
        try self.emitRaw(.{ .push = .{ .bytes = encoded } });
        try self.names.append(self.allocator, name);
    }

    /// Push the BN254 curve order r as script-num bytes.
    /// Push the BN254 curve order r.
    ///
    /// Emitted as `big_int_decimal`, NOT as raw script-num bytes. The two
    /// encode to the identical 32 push bytes, but `raw_bytes` is a HARD
    /// peephole barrier (`tryWindow4` bails on it), so with a bytes push the
    /// ladder's `+r +r +r` stayed three separate adds while Go / TS / Python /
    /// Ruby folded it into a single `+3r` via rule 27. That was a 67-byte
    /// cross-tier divergence in every `bn254G1ScalarMul`.
    pub fn pushCurveR(self: *BN254Tracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .push = .{ .big_int_decimal = bn254_curve_r_decimal } });
        try self.names.append(self.allocator, name);
    }

    pub fn dup(self: *BN254Tracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .dup = {} });
        try self.names.append(self.allocator, name);
    }

    pub fn drop(self: *BN254Tracker) !void {
        try self.emitRaw(.{ .drop = {} });
        _ = self.names.pop();
    }

    pub fn swap(self: *BN254Tracker) !void {
        try self.emitRaw(.{ .swap = {} });
        const len = self.names.items.len;
        if (len >= 2) {
            const tmp = self.names.items[len - 1];
            self.names.items[len - 1] = self.names.items[len - 2];
            self.names.items[len - 2] = tmp;
        }
    }

    pub fn over(self: *BN254Tracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .over = {} });
        try self.names.append(self.allocator, name);
    }

    pub fn rot(self: *BN254Tracker) !void {
        try self.emitRaw(.{ .rot = {} });
        const len = self.names.items.len;
        if (len >= 3) {
            const rolled = self.names.orderedRemove(len - 3);
            try self.names.append(self.allocator, rolled);
        }
    }

    pub fn roll(self: *BN254Tracker, depth_from_top: usize) !void {
        if (depth_from_top == 0) return;
        if (depth_from_top == 1) return self.swap();
        if (depth_from_top == 2) return self.rot();
        try self.emitRaw(.{ .roll = @intCast(depth_from_top) });
        const idx = self.names.items.len - 1 - depth_from_top;
        const rolled = self.names.orderedRemove(idx);
        try self.names.append(self.allocator, rolled);
    }

    pub fn pick(self: *BN254Tracker, depth_from_top: usize, name: ?[]const u8) !void {
        if (depth_from_top == 0) return self.dup(name);
        if (depth_from_top == 1) return self.over(name);
        try self.emitRaw(.{ .pick = @intCast(depth_from_top) });
        try self.names.append(self.allocator, name);
    }

    pub fn toTop(self: *BN254Tracker, name: []const u8) !void {
        try self.roll(try self.findDepth(name));
    }

    pub fn copyToTop(self: *BN254Tracker, name: []const u8, copy_name: ?[]const u8) !void {
        try self.pick(try self.findDepth(name), copy_name);
    }

    pub fn renameTop(self: *BN254Tracker, name: ?[]const u8) void {
        if (self.names.items.len > 0) {
            self.names.items[self.names.items.len - 1] = name;
        }
    }

    pub fn popNames(self: *BN254Tracker, count: usize) void {
        var i: usize = 0;
        while (i < count and self.names.items.len > 0) : (i += 1) {
            _ = self.names.pop();
        }
    }

    /// pushPrimeCache pushes the field prime to the alt-stack for caching.
    /// Subsequent fetchPrime() calls emit OP_FROMALTSTACK/DUP/OP_TOALTSTACK
    /// instead of pushing the ~34-byte prime literal, saving ~93 bytes per mod.
    pub fn pushPrimeCache(self: *BN254Tracker) !void {
        try self.pushFieldP("_pcache_p");
        try self.emitOpcode("OP_TOALTSTACK");
        // OP_TOALTSTACK consumes the top-of-main-stack item
        _ = self.names.pop();
        self.prime_cache_active = true;
    }

    /// popPrimeCache removes the cached field prime from the alt-stack.
    pub fn popPrimeCache(self: *BN254Tracker) !void {
        try self.emitOpcode("OP_FROMALTSTACK");
        try self.names.append(self.allocator, "_pcache_cleanup");
        try self.drop();
        self.prime_cache_active = false;
    }

    /// fetchPrime emits the field prime onto the main stack — from cache or
    /// via a fresh push. Tracker does not track the name (caller should use
    /// rawBlock-style sequences immediately after).
    pub fn fetchPrimeRaw(self: *BN254Tracker) !void {
        if (self.prime_cache_active) {
            try self.emitOpcode("OP_FROMALTSTACK");
            try self.emitOpcode("OP_DUP");
            try self.emitOpcode("OP_TOALTSTACK");
        } else {
            const encoded = try beToUnsignedScriptNumAlloc(self.allocator, bn254_field_p_be[0..]);
            try self.owned_bytes.append(self.allocator, encoded);
            try self.emitRaw(.{ .push = .{ .bytes = encoded } });
        }
    }
};

// ===========================================================================
// Helper: encode big-endian bytes to Bitcoin Script number (little-endian,
// with optional sign byte). Unsigned values only.
// ===========================================================================

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

// ===========================================================================
// Reverse a 32-byte value on the top of the stack (big-endian <-> little-endian).
// Mirrors ec_emitters.emitReverse32Raw. Used by point decompose/compose.
// ===========================================================================

fn emitReverse32(t: *BN254Tracker) !void {
    try t.emitOpcode("OP_0");
    try t.emitRaw(.{ .swap = {} });
    for (0..32) |_| {
        try t.emitPushInt(1);
        try t.emitOpcode("OP_SPLIT");
        try t.emitRaw(.{ .rot = {} });
        try t.emitRaw(.{ .rot = {} });
        try t.emitRaw(.{ .swap = {} });
        try t.emitOpcode("OP_CAT");
        try t.emitRaw(.{ .swap = {} });
    }
    try t.emitRaw(.{ .drop = {} });
}

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

/// fieldMod reduces TOS mod p, ensuring non-negative result.
/// Pattern: (a % p + p) % p. Handles negative inputs from subtraction.
fn fieldMod(t: *BN254Tracker, a_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    if (t.prime_cache_active) {
        // [a]
        t.popNames(1);
        try t.fetchPrimeRaw();
        // [a, p] -> TUCK -> [p, a, p]
        try t.emitOpcode("OP_TUCK");
        // [p, a, p] -> MOD -> [p, a%p]
        try t.emitOpcode("OP_MOD");
        // [p, a%p] -> OVER -> [p, a%p, p]
        try t.emitRaw(.{ .over = {} });
        // [p, a%p, p] -> ADD -> [p, a%p+p]
        try t.emitOpcode("OP_ADD");
        // [p, a%p+p] -> SWAP -> [a%p+p, p]
        try t.emitRaw(.{ .swap = {} });
        // [a%p+p, p] -> MOD -> [(a%p+p)%p]
        try t.emitOpcode("OP_MOD");
        try t.names.append(t.allocator, result_name);
    } else {
        try t.pushFieldP("_fmod_p");
        // [a, _fmod_p]
        t.popNames(2);
        try t.emitOpcode("OP_TUCK");
        try t.emitOpcode("OP_MOD");
        try t.emitRaw(.{ .over = {} });
        try t.emitOpcode("OP_ADD");
        try t.emitRaw(.{ .swap = {} });
        try t.emitOpcode("OP_MOD");
        try t.names.append(t.allocator, result_name);
    }
}

/// fieldModPositive reduces a non-negative value modulo p using a single OP_MOD.
/// Use when the input is guaranteed non-negative (e.g., after OP_MUL or OP_ADD
/// of non-negative values). Saves 6 bytes per call vs the full double-mod form.
fn fieldModPositive(t: *BN254Tracker, a_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    if (t.prime_cache_active) {
        t.popNames(1);
        try t.fetchPrimeRaw();
        try t.emitOpcode("OP_MOD");
        try t.names.append(t.allocator, result_name);
    } else {
        try t.pushFieldP("_fmodp_p");
        t.popNames(2);
        try t.emitOpcode("OP_MOD");
        try t.names.append(t.allocator, result_name);
    }
}

/// fieldAdd: (a + b) mod p. Both operands non-negative so sum is non-negative;
/// a single-mod reduction suffices.
fn fieldAdd(t: *BN254Tracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, "_fadd_sum");
    try fieldModPositive(t, "_fadd_sum", result_name);
}

/// fieldSub: (a - b) mod p. Computes (a - b + p) mod p using a single OP_MOD
/// (since a - b + p is always positive for a >= 0 and b in [0, p-1]).
fn fieldSub(t: *BN254Tracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    if (t.prime_cache_active) {
        t.popNames(2);
        // [diff]
        try t.emitOpcode("OP_SUB");
        // fetch p
        try t.fetchPrimeRaw();
        // [diff, p] -> TUCK -> [p, diff, p]
        try t.emitOpcode("OP_TUCK");
        // [p, diff, p] -> ADD -> [p, diff+p]
        try t.emitOpcode("OP_ADD");
        // [p, diff+p] -> SWAP -> [diff+p, p]
        try t.emitRaw(.{ .swap = {} });
        // [diff+p, p] -> MOD
        try t.emitOpcode("OP_MOD");
        try t.names.append(t.allocator, result_name);
    } else {
        t.popNames(2);
        try t.emitOpcode("OP_SUB");
        try t.names.append(t.allocator, "_fsub_diff");
        try fieldMod(t, "_fsub_diff", result_name);
    }
}

/// fieldMul: (a * b) mod p. Product is non-negative so single-mod suffices.
fn fieldMul(t: *BN254Tracker, a_name: []const u8, b_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.names.append(t.allocator, "_fmul_prod");
    try fieldModPositive(t, "_fmul_prod", result_name);
}

/// fieldSqr: (a * a) mod p
fn fieldSqr(t: *BN254Tracker, a_name: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_fsqr_copy");
    try fieldMul(t, a_name, "_fsqr_copy", result_name);
}

/// fieldMulConst: (a * c) mod p where c is a compile-time constant.
/// Uses OP_2MUL for c==2, OP_LSHIFTNUM for higher powers of 2, else OP_MUL + push.
fn fieldMulConst(t: *BN254Tracker, a_name: []const u8, c: i64, result_name: []const u8) !void {
    try t.toTop(a_name);
    t.popNames(1);
    if (c == 2) {
        try t.emitOpcode("OP_2MUL");
    } else if (c > 2 and (c & (c - 1)) == 0) {
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
    try t.names.append(t.allocator, "_fmc_prod");
    try fieldModPositive(t, "_fmc_prod", result_name);
}

/// fieldNeg: (p - a) mod p.
fn fieldNeg(t: *BN254Tracker, a_name: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    if (t.prime_cache_active) {
        t.popNames(1);
        // [a]
        try t.fetchPrimeRaw();
        // [a, p] -> DUP -> [a, p, p]
        try t.emitOpcode("OP_DUP");
        // [a, p, p] -> ROT -> [p, p, a]
        try t.emitRaw(.{ .rot = {} });
        // [p, p, a] -> SUB -> [p, p-a]
        try t.emitOpcode("OP_SUB");
        // [p, p-a] -> SWAP -> [p-a, p]
        try t.emitRaw(.{ .swap = {} });
        // [p-a, p] -> MOD
        try t.emitOpcode("OP_MOD");
        try t.names.append(t.allocator, result_name);
    } else {
        try t.pushFieldP("_fneg_p");
        t.popNames(2);
        try t.emitOpcode("OP_DUP");
        try t.emitRaw(.{ .rot = {} });
        try t.emitOpcode("OP_SUB");
        try t.emitRaw(.{ .swap = {} });
        try t.emitOpcode("OP_MOD");
        try t.names.append(t.allocator, result_name);
    }
}

/// fieldInv computes a^(p-2) mod p via Fermat's little theorem.
///
/// BN254 p is a 254-bit prime; p-2 has MSB at bit 253 (always set). We handle
/// the MSB by initializing result = a, then looping over bits 252..0 — that's
/// 253 squarings (one per loop iter) and ~109 conditional multiplies (popcount
/// of p-2 is 110; the MSB is implicit).
fn fieldInv(t: *BN254Tracker, a_name: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_inv_r");

    var i: i32 = 252;
    while (i >= 0) : (i -= 1) {
        try fieldSqr(t, "_inv_r", "_inv_r2");
        t.renameTop("_inv_r");

        if (bn254PMinus2Bit(@intCast(i)) == 1) {
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

// ===========================================================================
// Point decompose / compose
// ===========================================================================

/// bn254DecomposePoint decomposes a 64-byte point into (x_num, y_num) on stack.
/// Consumes point_name, produces x_name (deeper) and y_name (on top).
fn decomposePoint(t: *BN254Tracker, point_name: []const u8, x_name: []const u8, y_name: []const u8) !void {
    try t.toTop(point_name);
    t.popNames(1);
    // R-141: gate the WIDTH here, so every consumer that decomposes a BN254
    // Point inherits the check -- the same placement CL-BUG-095 chose for
    // ec_emitters.zig. Without it OP_SPLIT at 32 discards whatever follows byte
    // 64, so bn254G1OnCurve(G || 0xff) returned TRUE. ABORTING form:
    // emitBN254G1OnCurve must stay TOTAL, so it clamps and flags the length
    // BEFORE calling this.
    try t.emitOpcode("OP_SIZE");
    try t.emitPushInt(64);
    try t.emitOpcode("OP_NUMEQUALVERIFY");
    // OP_SPLIT at 32: [point] -> [x_bytes, y_bytes]
    try t.emitPushInt(32);
    try t.emitOpcode("OP_SPLIT");
    try t.names.append(t.allocator, "_dp_xb");
    try t.names.append(t.allocator, "_dp_yb");

    // Convert y_bytes (top) to unsigned num (reverse BE -> LE, append 0x00 sign byte, BIN2NUM)
    try t.toTop("_dp_yb");
    t.popNames(1);
    try emitReverse32(t);
    try t.emitRaw(.{ .push = .{ .bytes = &.{0x00} } });
    try t.emitOpcode("OP_CAT");
    try t.emitOpcode("OP_BIN2NUM");
    try t.names.append(t.allocator, y_name);

    // Convert x_bytes to num
    try t.toTop("_dp_xb");
    t.popNames(1);
    try emitReverse32(t);
    try t.emitRaw(.{ .push = .{ .bytes = &.{0x00} } });
    try t.emitOpcode("OP_CAT");
    try t.emitOpcode("OP_BIN2NUM");
    try t.names.append(t.allocator, x_name);

    // Stack: [..., y_name, x_name] → swap to [..., x_name, y_name]
    try t.swap();
}

/// bn254ComposePoint composes (x_num, y_num) into a 64-byte point.
/// Consumes x_name and y_name, produces result_name.
fn composePoint(t: *BN254Tracker, x_name: []const u8, y_name: []const u8, result_name: []const u8) !void {
    // Convert x to 32-byte big-endian
    try t.toTop(x_name);
    t.popNames(1);
    try t.emitPushInt(33);
    try t.emitOpcode("OP_NUM2BIN");
    try t.emitPushInt(32);
    try t.emitOpcode("OP_SPLIT");
    try t.emitRaw(.{ .drop = {} });
    try emitReverse32(t);
    try t.names.append(t.allocator, "_cp_xb");

    // Convert y to 32-byte big-endian
    try t.toTop(y_name);
    t.popNames(1);
    try t.emitPushInt(33);
    try t.emitOpcode("OP_NUM2BIN");
    try t.emitPushInt(32);
    try t.emitOpcode("OP_SPLIT");
    try t.emitRaw(.{ .drop = {} });
    try emitReverse32(t);
    try t.names.append(t.allocator, "_cp_yb");

    // Concatenate: x_be || y_be
    try t.toTop("_cp_xb");
    try t.toTop("_cp_yb");
    t.popNames(2);
    try t.emitOpcode("OP_CAT");
    try t.names.append(t.allocator, result_name);
}

// ===========================================================================
// Affine G1 addition (unified slope formula — handles P==Q correctly)
// ===========================================================================

/// bn254G1AffineAdd performs affine addition on BN254 G1 using the unified
/// slope formula
///
///     s = (px^2 + px*qx + qx^2) / (py + qy)
///
/// which is equivalent to the chord slope (qy-py)/(qx-px) for distinct points
/// (via the curve equation y^2 = x^3 + b) and collapses to the doubling slope
/// 3*px^2 / (2*py) when P == Q.
///
/// The remaining zero-denominator input (py + qy == 0) is handled by the
/// caller: emitBN254G1Add masks P == -Q to the all-zero point at infinity
/// (see g1InfinityFlag); the Groth16 MSM path shares this helper unmasked and
/// stays fail-closed.
///
/// Expects px, py, qx, qy on the tracker. Consumes all four and produces rx, ry.
fn g1AffineAdd(t: *BN254Tracker) !void {
    // s_num = px^2 + px*qx + qx^2
    try t.copyToTop("px", "_px_sq_in");
    try fieldSqr(t, "_px_sq_in", "_px_sq");
    try t.copyToTop("px", "_px_m");
    try t.copyToTop("qx", "_qx_m");
    try fieldMul(t, "_px_m", "_qx_m", "_px_qx");
    try t.copyToTop("qx", "_qx_sq_in");
    try fieldSqr(t, "_qx_sq_in", "_qx_sq");
    try fieldAdd(t, "_px_sq", "_px_qx", "_s_num_tmp");
    try fieldAdd(t, "_s_num_tmp", "_qx_sq", "_s_num");

    // s_den = py + qy
    try t.copyToTop("py", "_py_a");
    try t.copyToTop("qy", "_qy_a");
    try fieldAdd(t, "_py_a", "_qy_a", "_s_den");

    // s = s_num / s_den
    try fieldInv(t, "_s_den", "_s_den_inv");
    try fieldMul(t, "_s_num", "_s_den_inv", "_s");

    // rx = s^2 - px - qx
    try t.copyToTop("_s", "_s_keep");
    try fieldSqr(t, "_s", "_s2");
    try t.copyToTop("px", "_px2");
    try fieldSub(t, "_s2", "_px2", "_rx1");
    try t.copyToTop("qx", "_qx2");
    try fieldSub(t, "_rx1", "_qx2", "rx");

    // ry = s * (px - rx) - py
    try t.copyToTop("px", "_px3");
    try t.copyToTop("rx", "_rx2");
    try fieldSub(t, "_px3", "_rx2", "_px_rx");
    try fieldMul(t, "_s_keep", "_px_rx", "_s_px_rx");
    try t.copyToTop("py", "_py2");
    try fieldSub(t, "_s_px_rx", "_py2", "ry");

    // Drop originals
    try t.toTop("px");
    try t.drop();
    try t.toTop("py");
    try t.drop();
    try t.toTop("qx");
    try t.drop();
    try t.toTop("qy");
    try t.drop();
}

// ===========================================================================
// Point at infinity for the bn254G1Add builtin
// ===========================================================================

/// g1InfinityFlag computes `_notinf`, 0 exactly when P == -Q and 1 otherwise,
/// reading px/py/qx/qy WITHOUT consuming them. Call it before g1AffineAdd;
/// apply the result with g1MaskInfinity afterwards.
///
/// P + (-P) is the point at infinity, which affine x||y cannot represent. This
/// codegen already has an encoding for O — the ALL-ZERO blob, which is what
/// bn254G1ScalarMul returns for k = 0 mod r and what secp256k1 and both NIST
/// curves return for their own P + (-P). bn254G1Add is a general
/// contract-callable builtin, so it owes callers the same answer rather than
/// the off-curve blob the unified slope produces there (py + qy == 0 and the
/// field inverse is Fermat, so inv(0) = 0). O is not on the curve
/// (0^2 != 0^3 + 3), so the documented assert(bn254G1OnCurve(r)) idiom still
/// rejects the result.
///
/// THE PREDICATE IS px == qx AND py != qy, NOT a zero denominator. BN254 has
/// j-invariant 0 with p = 1 mod 3, so F_p holds a primitive cube root of unity
/// w and Q = (w*px, -py) is an ordinary point that also zeroes py + qy while
/// P + Q is an ordinary point, not O. Masking on the denominator would answer
/// "infinity" there: plausible and wrong — the exact failure mode 03f50d48
/// introduced on the NIST curves and f16790a9 had to undo. Testing px == qx
/// ALONE would be wrong in the other direction: it would swallow doubling.
///
/// Deliberately NOT inside g1AffineAdd: the Groth16 MSM bind shares that
/// helper and keeps its fail-closed behaviour and its bytes unchanged.
///
/// Byte-identical to `bn254G1InfinityFlag` in compilers/go/codegen/bn254.go.
fn g1InfinityFlag(t: *BN254Tracker) !void {
    try t.copyToTop("px", "_inf_px");
    try t.copyToTop("qx", "_inf_qx");
    t.popNames(2);
    try t.emitOpcode("OP_NUMEQUAL");
    try t.names.append(t.allocator, "_xeq");

    try t.copyToTop("py", "_inf_py");
    try t.copyToTop("qy", "_inf_qy");
    t.popNames(2);
    try t.emitOpcode("OP_NUMEQUAL");
    try t.names.append(t.allocator, "_yeq");

    // cond = xeq AND yeq: 1 when doubling.
    try t.copyToTop("_xeq", "_xeq_c");
    try t.toTop("_yeq");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.names.append(t.allocator, "_cond");

    // notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and the
    // points are not equal, i.e. exactly the P == -Q case.
    try t.toTop("_xeq");
    try t.toTop("_cond");
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.emitOpcode("OP_NOT");
    try t.names.append(t.allocator, "_notinf");
}

/// g1MaskInfinity zeroes rx and ry when `_notinf` is 0, consuming it.
///
/// The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
/// and notinf is 0 or 1, so the product is canonical either way.
fn g1MaskInfinity(t: *BN254Tracker) !void {
    try t.toTop("rx");
    try t.copyToTop("_notinf", "_notinf_x");
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.names.append(t.allocator, "rx");

    try t.toTop("ry");
    try t.toTop("_notinf");
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.names.append(t.allocator, "ry");
}

// ===========================================================================
// Jacobian point operations (for scalar multiplication)
// ===========================================================================

/// g1JacobianDouble performs Jacobian point doubling (a=0 for BN254).
/// Expects jx, jy, jz on tracker. Replaces with updated values.
///
/// Formulas (a=0 since y^2 = x^3 + b):
///   A  = Y^2
///   B  = 4*X*A
///   C  = 8*A^2
///   D  = 3*X^2
///   X' = D^2 - 2*B
///   Y' = D*(B - X') - C
///   Z' = 2*Y*Z
fn g1JacobianDouble(t: *BN254Tracker) !void {
    // Save copies of jx, jy, jz
    try t.copyToTop("jy", "_jy_save");
    try t.copyToTop("jx", "_jx_save");
    try t.copyToTop("jz", "_jz_save");

    // A = jy^2
    try fieldSqr(t, "jy", "_A");

    // B = 4 * jx * A
    try t.copyToTop("_A", "_A_save");
    try fieldMul(t, "jx", "_A", "_xA");
    try t.pushInt("_four", 4);
    try fieldMul(t, "_xA", "_four", "_B");

    // C = 8 * A^2
    try fieldSqr(t, "_A_save", "_A2");
    try t.pushInt("_eight", 8);
    try fieldMul(t, "_A2", "_eight", "_C");

    // D = 3 * X^2
    try fieldSqr(t, "_jx_save", "_x2");
    try t.pushInt("_three", 3);
    try fieldMul(t, "_x2", "_three", "_D");

    // nx = D^2 - 2*B
    try t.copyToTop("_D", "_D_save");
    try t.copyToTop("_B", "_B_save");
    try fieldSqr(t, "_D", "_D2");
    try t.copyToTop("_B", "_B1");
    try fieldMulConst(t, "_B1", 2, "_2B");
    try fieldSub(t, "_D2", "_2B", "_nx");

    // ny = D*(B - nx) - C
    try t.copyToTop("_nx", "_nx_copy");
    try fieldSub(t, "_B_save", "_nx_copy", "_B_nx");
    try fieldMul(t, "_D_save", "_B_nx", "_D_B_nx");
    try fieldSub(t, "_D_B_nx", "_C", "_ny");

    // nz = 2 * Y * Z
    try fieldMul(t, "_jy_save", "_jz_save", "_yz");
    try fieldMulConst(t, "_yz", 2, "_nz");

    // Clean up leftover _B and old jz
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

/// g1JacobianToAffine converts Jacobian to affine coordinates.
/// Consumes jx, jy, jz and produces rx_name, ry_name.
fn g1JacobianToAffine(t: *BN254Tracker, rx_name: []const u8, ry_name: []const u8) !void {
    try fieldInv(t, "jz", "_zinv");
    try t.copyToTop("_zinv", "_zinv_keep");
    try fieldSqr(t, "_zinv", "_zinv2");
    try t.copyToTop("_zinv2", "_zinv2_keep");
    try fieldMul(t, "_zinv_keep", "_zinv2", "_zinv3");
    try fieldMul(t, "jx", "_zinv2_keep", rx_name);
    try fieldMul(t, "jy", "_zinv3", ry_name);
}

/// g1BuildJacobianAddAffineStandard emits the standard Jacobian mixed-add
/// sequence assuming the doubling case has been excluded by the caller.
///
/// Consumes jx, jy, jz on the tracker (the affine base point ax, ay is read
/// via copy-to-top) and produces replacement jx, jy, jz.
///
/// WARNING: this fails (H = 0) when the Jacobian accumulator equals the affine
/// base point — callers MUST guard that case via g1BuildJacobianAddAffineInline.
fn g1BuildJacobianAddAffineStandard(it: *BN254Tracker) !void {
    // Save copies of values that get consumed but are needed later
    try it.copyToTop("jz", "_jz_for_z1cu");
    try it.copyToTop("jz", "_jz_for_z3");
    try it.copyToTop("jy", "_jy_for_y3");
    try it.copyToTop("jx", "_jx_for_u1h2");

    // Z1sq = jz^2
    try fieldSqr(it, "jz", "_Z1sq");

    // Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
    try it.copyToTop("_Z1sq", "_Z1sq_for_u2");
    try fieldMul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu");

    // U2 = ax * Z1sq_for_u2
    try it.copyToTop("ax", "_ax_c");
    try fieldMul(it, "_ax_c", "_Z1sq_for_u2", "_U2");

    // S2 = ay * Z1cu
    try it.copyToTop("ay", "_ay_c");
    try fieldMul(it, "_ay_c", "_Z1cu", "_S2");

    // H = U2 - jx
    try fieldSub(it, "_U2", "jx", "_H");

    // R = S2 - jy
    try fieldSub(it, "_S2", "jy", "_R");

    // Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
    try it.copyToTop("_H", "_H_for_h3");
    try it.copyToTop("_H", "_H_for_z3");

    // H2 = H^2
    try fieldSqr(it, "_H", "_H2");

    // Save H2 for U1H2
    try it.copyToTop("_H2", "_H2_for_u1h2");

    // H3 = H_for_h3 * H2
    try fieldMul(it, "_H_for_h3", "_H2", "_H3");

    // U1H2 = _jx_for_u1h2 * H2_for_u1h2
    try fieldMul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2");

    // Save R, U1H2, H3 for Y3 computation
    try it.copyToTop("_R", "_R_for_y3");
    try it.copyToTop("_U1H2", "_U1H2_for_y3");
    try it.copyToTop("_H3", "_H3_for_y3");

    // X3 = R^2 - H3 - 2*U1H2
    try fieldSqr(it, "_R", "_R2");
    try fieldSub(it, "_R2", "_H3", "_x3_tmp");
    try fieldMulConst(it, "_U1H2", 2, "_2U1H2");
    try fieldSub(it, "_x3_tmp", "_2U1H2", "_X3");

    // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    try it.copyToTop("_X3", "_X3_c");
    try fieldSub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x");
    try fieldMul(it, "_R_for_y3", "_u_minus_x", "_r_tmp");
    try fieldMul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3");
    try fieldSub(it, "_r_tmp", "_jy_h3", "_Y3");

    // Z3 = _jz_for_z3 * _H_for_z3
    try fieldMul(it, "_jz_for_z3", "_H_for_z3", "_Z3");

    // Rename results to jx/jy/jz
    try it.toTop("_X3");
    it.renameTop("jx");
    try it.toTop("_Y3");
    it.renameTop("jy");
    try it.toTop("_Z3");
    it.renameTop("jz");
}

/// g1BuildJacobianAddAffineInline builds doubling-safe Jacobian mixed-add ops.
///
/// The standard Jacobian mixed-add formula divides by H = ax*jz^2 - jx, which
/// is 0 when the accumulator's affine image equals the base point — a
/// deterministic trajectory for certain scalars. To handle the doubling case,
/// we check H == 0 at runtime and delegate to Jacobian doubling when it fires.
/// Otherwise the standard mixed-add runs.
///
/// The negation case (H == 0 with R != 0) produces incorrect results, but is
/// cryptographically unreachable for valid Groth16 public inputs.
///
/// Returns an owned bundle that the caller must merge into its parent tracker.
fn buildJacobianAddAffineInline(
    allocator: Allocator,
    base_names: []const ?[]const u8,
    parent_prime_cache_active: bool,
    strict: bool,
) !EcOpBundle {
    var it = try BN254Tracker.init(allocator, base_names);
    errdefer it.deinit();
    it.prime_cache_active = parent_prime_cache_active;

    // ------------------------------------------------------------------
    // Doubling-case detection: H = ax*jz^2 - jx == 0 ?
    // Compute U2 = ax * jz^2 via copies (do not consume jx/jy/jz), then
    // compare against a fresh copy of jx.
    // ------------------------------------------------------------------
    try it.copyToTop("jz", "_jz_chk_in");
    try fieldSqr(&it, "_jz_chk_in", "_jz_chk_sq");
    if (strict) {
        // Z1sq is consumed by U2 below; keep a copy for Z1cu.
        try it.copyToTop("_jz_chk_sq", "_jz_chk_sq_keep");
    }
    try it.copyToTop("ax", "_ax_chk_copy");
    try fieldMul(&it, "_ax_chk_copy", "_jz_chk_sq", "_u2_chk");
    try it.copyToTop("jx", "_jx_chk_copy");
    // Stack top: [..., _u2_chk, _jx_chk_copy]; consume both via OP_NUMEQUAL.
    // No OP_SWAP first: OP_NUMEQUAL is commutative and the six other tiers
    // compare in this order, so the swap was a byte of pure divergence on
    // every one of the ladder's 255 steps.
    it.popNames(2);
    try it.emitOpcode("OP_NUMEQUAL");
    try it.names.append(it.allocator, "_h_is_zero");

    var cond_name: []const u8 = "_h_is_zero";
    if (strict) {
        // R = ay*jz^3 - jy == 0 ? Only H == 0 AND R == 0 means the two
        // operands are the SAME point; H == 0 with R != 0 means they are
        // negatives, whose sum is O -- and the standard mixed-add already
        // answers that correctly, with Z3 = jz*H = 0 flowing through the
        // Fermat inverse to the all-zero point.
        try it.copyToTop("jz", "_jz_chk_for_cu");
        try fieldMul(&it, "_jz_chk_for_cu", "_jz_chk_sq_keep", "_z1cu_chk");
        try it.copyToTop("ay", "_ay_chk_copy");
        try fieldMul(&it, "_ay_chk_copy", "_z1cu_chk", "_s2_chk");
        try it.copyToTop("jy", "_jy_chk_copy");
        it.popNames(2);
        try it.emitOpcode("OP_NUMEQUAL");
        try it.names.append(it.allocator, "_r_is_zero");
        try it.toTop("_h_is_zero");
        try it.toTop("_r_is_zero");
        it.popNames(2);
        try it.emitOpcode("OP_BOOLAND");
        try it.names.append(it.allocator, "_dbl_cond");
        cond_name = "_dbl_cond";
    }

    // Move the condition to top and consume (OP_IF consumes it).
    try it.toTop(cond_name);
    it.popNames(1);

    // ------------------------------------------------------------------
    // Gather doubling-branch ops (Jacobian doubling on (jx, jy, jz))
    // ------------------------------------------------------------------
    var doubling_tracker = try BN254Tracker.init(it.allocator, it.names.items);
    errdefer doubling_tracker.deinit();
    doubling_tracker.prime_cache_active = it.prime_cache_active;
    try g1JacobianDouble(&doubling_tracker);

    // Capture the post-doubling name state before the bundle destroys it.
    const post_names_slice = try it.allocator.alloc(?[]const u8, doubling_tracker.names.items.len);
    defer it.allocator.free(post_names_slice);
    @memcpy(post_names_slice, doubling_tracker.names.items);

    var doubling_bundle = try doubling_tracker.takeBundle();
    errdefer doubling_bundle.deinit();

    // ------------------------------------------------------------------
    // Gather standard-add-branch ops
    // ------------------------------------------------------------------
    var add_tracker = try BN254Tracker.init(it.allocator, it.names.items);
    errdefer add_tracker.deinit();
    add_tracker.prime_cache_active = it.prime_cache_active;
    try g1BuildJacobianAddAffineStandard(&add_tracker);
    var add_bundle = try add_tracker.takeBundle();
    errdefer add_bundle.deinit();

    // Merge owned byte buffers from both branches into the outer tracker,
    // then emit the IF with the branch op slices transferred into the
    // outer tracker's ownership.
    try it.owned_bytes.appendSlice(it.allocator, doubling_bundle.owned_bytes);
    it.allocator.free(doubling_bundle.owned_bytes);
    doubling_bundle.owned_bytes = &.{};

    try it.owned_bytes.appendSlice(it.allocator, add_bundle.owned_bytes);
    it.allocator.free(add_bundle.owned_bytes);
    add_bundle.owned_bytes = &.{};

    try it.emitRaw(.{ .@"if" = .{ .then = doubling_bundle.ops, .@"else" = add_bundle.ops } });
    doubling_bundle.ops = &.{};
    add_bundle.ops = &.{};

    // Both branches leave (jx, jy, jz) in the same slots. Replace the outer
    // tracker's names with the captured post-branch state.
    it.names.clearRetainingCapacity();
    try it.names.appendSlice(it.allocator, post_names_slice);

    return it.takeBundle();
}

// ===========================================================================
// G1 point negation
// ===========================================================================

/// g1Negate negates a point: (x, p - y).
fn g1Negate(t: *BN254Tracker, point_name: []const u8, result_name: []const u8) !void {
    try decomposePoint(t, point_name, "_nx", "_ny");
    // R-141: composePoint below is documented as requiring [0, p-1] and does
    // not check, so without this the negation of a non-canonical point
    // re-emitted its x half verbatim.
    try bn254EmitCoordCanonVerify(t, "_nx", "_ny");
    try fieldNeg(t, "_ny", "_neg_y");
    try composePoint(t, "_nx", "_neg_y", result_name);
}

// ===========================================================================
// Public emit entry points
// ===========================================================================

fn emitBN254FieldAdd(t: *BN254Tracker) !void {
    try t.pushPrimeCache();
    try fieldAdd(t, "a", "b", "result");
    try t.popPrimeCache();
}

fn emitBN254FieldSub(t: *BN254Tracker) !void {
    try t.pushPrimeCache();
    try fieldSub(t, "a", "b", "result");
    try t.popPrimeCache();
}

fn emitBN254FieldMul(t: *BN254Tracker) !void {
    try t.pushPrimeCache();
    try fieldMul(t, "a", "b", "result");
    try t.popPrimeCache();
}

fn emitBN254FieldInv(t: *BN254Tracker) !void {
    try t.pushPrimeCache();
    try fieldInv(t, "a", "result");
    try t.popPrimeCache();
}

fn emitBN254FieldNeg(t: *BN254Tracker) !void {
    try t.pushPrimeCache();
    try fieldNeg(t, "a", "result");
    try t.popPrimeCache();
}

/// bn254EmitPointLengthGate -- R-141, CLAMPING form, the BN254 twin of the EC
/// point length gate. Leaves [flag, clamped] on the tracker. Used by
/// emitBN254G1OnCurve, whose job is to answer "is this an acceptable point?"
/// over untrusted bytes: for a wrong-length blob the correct answer is FALSE,
/// not an aborted script.
fn bn254EmitPointLengthGate(t: *BN254Tracker, name: []const u8, want: i64, flag_name: []const u8) !void {
    try t.toTop(name);
    t.popNames(1);
    try t.emitOpcode("OP_SIZE");
    try t.emitPushInt(want);
    try t.emitOpcode("OP_NUMEQUAL");
    try t.emitRaw(.{ .swap = {} });
    try t.emitRaw(.{ .push = .{ .bytes = &[_]u8{0} ** 64 } });
    try t.emitOpcode("OP_CAT");
    try t.emitPushInt(want);
    try t.emitOpcode("OP_SPLIT");
    try t.emitRaw(.{ .drop = {} });
    try t.names.append(t.allocator, flag_name);
    try t.names.append(t.allocator, name);
}

/// bn254EmitCoordCanonVerify -- R-141: a BN254 G1 Point's two coordinates must
/// be FIELD ELEMENTS, aborting form. The direct analogue of the R-117 EC gate,
/// with the placement re-derived for this curve.
///
/// decomposePoint BIN2NUMs each half as an UNSIGNED integer, so any value that
/// fits 32 bytes is accepted; p is ~2^253.6, so x + p < 2^256 for EVERY x < p
/// -- unlike secp256k1, the alias exists for every point on the curve.
/// Measured before this gate, with G = (1, 2):
///
/// ```text
/// bn254G1OnCurve((1+p) || 2) -> 1
/// bn254G1OnCurve(1 || (2+p)) -> 1
/// bn254G1OnCurve(G || 0xff)  -> 1
/// ```
///
/// The value builtins abort for a DIFFERENT reason than secp256k1's did:
/// BN254's adder is not fooled into a wrong answer (bn254G1Add(G, (1+p)||2)
/// returns the correct 2G, because g1InfinityFlag reduces before it compares),
/// but composePoint is documented as requiring [0, p-1] and not checking, and
/// g1Negate handed it the raw decomposed x -- a value builtin PRODUCING
/// something that is not a point.
///
/// Deliberately NOT folded into decomposePoint: that helper also runs inside
/// emitBN254G1OnCurve, which must return FALSE rather than abort.
fn bn254EmitCoordCanonVerify(t: *BN254Tracker, x_name: []const u8, y_name: []const u8) !void {
    try t.copyToTop(x_name, "_cc_x");
    try t.pushFieldP("_cc_px");
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.names.append(t.allocator, "_cc_xok");
    try t.copyToTop(y_name, "_cc_y");
    try t.pushFieldP("_cc_py");
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.names.append(t.allocator, "_cc_yok");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.emitOpcode("OP_VERIFY");
}

fn emitBN254G1Add(t: *BN254Tracker) !void {
    try t.pushPrimeCache();
    try decomposePoint(t, "_pa", "px", "py");
    try decomposePoint(t, "_pb", "qx", "qy");
    // R-141: both points must be canonical before anything consumes them.
    try bn254EmitCoordCanonVerify(t, "px", "py");
    try bn254EmitCoordCanonVerify(t, "qx", "qy");
    // The flag must be computed BEFORE the add: g1AffineAdd consumes
    // px/py/qx/qy.
    try g1InfinityFlag(t);
    try g1AffineAdd(t);
    try g1MaskInfinity(t);
    try composePoint(t, "rx", "ry", "_result");
    try t.popPrimeCache();
}

fn emitBN254G1ScalarMul(t: *BN254Tracker) !void {
    try t.pushPrimeCache();
    // Decompose base point to affine (ax, ay)
    try decomposePoint(t, "_pt", "ax", "ay");
    // R-141: the ladder's base point must be canonical.
    try bn254EmitCoordCanonVerify(t, "ax", "ay");

    // Reduce first: the +3r trick below is only sound for k in [0, r-1], and
    // the scalar is caller input.
    //
    // ((k mod r) + r) mod r. OP_MOD takes the sign of the DIVIDEND, so
    // `k mod r` alone lands in (-r, r); the `+ r, mod r` normalises the
    // negative half. One push of r covers both reductions.
    //
    // Without it the ladder below is correct only while
    // 2^255 <= k + 3r < 2^256. A scalar >= 2^256 - 3r (about 2.2902*r) sets
    // bit 256, which the loop never reads, and one <= 2^255 - 3r drops k'
    // under 2^255, invalidating the accumulator seed; either way the ladder
    // returns a DIFFERENT multiple of P rather than failing. In Groth16 the
    // scalars are the caller-supplied PUBLIC INPUTS of
    // vk_x = IC[0] + sum(IC[i] * pub_i), so the domain is attacker-chosen.
    try t.toTop("_k");
    try t.pushCurveR("_r_red");
    t.popNames(2);
    try t.emitOpcode("OP_2DUP");
    try t.emitOpcode("OP_MOD");
    try t.emitRaw(.{ .rot = {} });
    try t.emitRaw(.{ .drop = {} });
    try t.emitRaw(.{ .over = {} });
    try t.emitOpcode("OP_ADD");
    try t.emitRaw(.{ .swap = {} });
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, "_kr");
    t.renameTop("_k");

    // k' = k + 3*r  (guarantees bit 255 is set)
    // k in [0, r-1], so k+3r in [3r, 4r-1]. 3r >= 2^255, so bit 255 always 1.
    // Adding 3r (= 0 mod r) preserves the EC point: k*G = (k+3r)*G.
    try t.toTop("_k");
    try t.pushCurveR("_r1");
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, "_kr1");
    try t.pushCurveR("_r2");
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, "_kr2");
    try t.pushCurveR("_r3");
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, "_kr3");
    t.renameTop("_k");

    // Init accumulator = P (bit 255 of k+3r is always 1)
    try t.copyToTop("ax", "jx");
    try t.copyToTop("ay", "jy");
    try t.pushInt("jz", 1);

    // 255 iterations: bits 254 down to 0
    var bit: i32 = 254;
    while (bit >= 0) : (bit -= 1) {
        try g1JacobianDouble(t);

        // Extract bit: (k >> bit) & 1
        try t.copyToTop("_k", "_k_copy");
        if (bit == 1) {
            t.popNames(1);
            try t.emitOpcode("OP_2DIV");
            try t.names.append(t.allocator, "_shifted");
        } else if (bit > 1) {
            try t.pushInt("_shift", @as(i64, bit));
            t.popNames(2);
            try t.emitOpcode("OP_RSHIFTNUM");
            try t.names.append(t.allocator, "_shifted");
        } else {
            t.renameTop("_shifted");
        }
        try t.pushInt("_two", 2);
        t.popNames(2);
        try t.emitOpcode("OP_MOD");
        try t.names.append(t.allocator, "_bit");

        // Move _bit to TOS and remove from tracker BEFORE gathering add ops,
        // because OP_IF consumes _bit and the add ops run with it gone.
        try t.toTop("_bit");
        t.popNames(1);

        // Only the LAST step can be handed accumulator == -base (k = 0 mod r);
        // see buildJacobianAddAffineInline for why the strict H == 0 AND
        // R == 0 test is paid there and nowhere else.
        var add_bundle = try buildJacobianAddAffineInline(t.allocator, t.names.items, t.prime_cache_active, bit == 0);
        errdefer add_bundle.deinit();

        // Transfer ownership of owned_bytes into the outer tracker so the
        // branch's owned buffers survive past this iteration.
        try t.owned_bytes.appendSlice(t.allocator, add_bundle.owned_bytes);
        t.allocator.free(add_bundle.owned_bytes);
        add_bundle.owned_bytes = &.{};

        try t.emitRaw(.{ .@"if" = .{ .then = add_bundle.ops, .@"else" = null } });
        add_bundle.ops = &.{};
    }

    // Convert Jacobian to affine
    try g1JacobianToAffine(t, "_rx", "_ry");

    // Clean up base point and scalar
    try t.toTop("ax");
    try t.drop();
    try t.toTop("ay");
    try t.drop();
    try t.toTop("_k");
    try t.drop();

    try composePoint(t, "_rx", "_ry", "_result");
    try t.popPrimeCache();
}

fn emitBN254G1Negate(t: *BN254Tracker) !void {
    try t.pushPrimeCache();
    try g1Negate(t, "_pt", "_result");
    try t.popPrimeCache();
}

fn emitBN254G1OnCurve(t: *BN254Tracker) !void {
    try t.pushPrimeCache();

    // R-141: width. bn254G1OnCurve(G || 0xff) returned TRUE -- the OP_SPLIT at
    // 32 inside decomposePoint discarded the surplus byte. Clamp and remember
    // the width rather than abort: this predicate must stay TOTAL.
    try bn254EmitPointLengthGate(t, "_pt", 64, "_len_ok");

    try decomposePoint(t, "_pt", "_x", "_y");

    // R-141: coordinate canonicity. Reject x >= p or y >= p and AND the result
    // in at the end, so the predicate still returns a boolean.
    try t.copyToTop("_x", "_x_lt");
    try t.pushFieldP("_p_for_x");
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.names.append(t.allocator, "_x_canon");
    try t.copyToTop("_y", "_y_lt");
    try t.pushFieldP("_p_for_y");
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.names.append(t.allocator, "_y_canon");
    try t.toTop("_x_canon");
    try t.toTop("_y_canon");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.names.append(t.allocator, "_canon");

    // lhs = y^2
    try fieldSqr(t, "_y", "_y2");

    // rhs = x^3 + 3
    try t.copyToTop("_x", "_x_copy");
    try fieldSqr(t, "_x", "_x2");
    try fieldMul(t, "_x2", "_x_copy", "_x3");
    try t.pushInt("_three", 3);
    try fieldAdd(t, "_x3", "_three", "_rhs");

    // Compare
    try t.toTop("_y2");
    try t.toTop("_rhs");
    t.popNames(2);
    try t.emitOpcode("OP_EQUAL");
    try t.names.append(t.allocator, "_curve_eq");

    // on-curve = right width AND canonical AND curve-equation
    try t.toTop("_canon");
    try t.toTop("_curve_eq");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.names.append(t.allocator, "_eq_ok");
    try t.toTop("_len_ok");
    try t.toTop("_eq_ok");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.names.append(t.allocator, "_result");
    try t.popPrimeCache();
}

// ===========================================================================
// Tests
// ===========================================================================

test "buildBuiltinOps produces ops for every BN254 builtin" {
    const allocator = std.testing.allocator;
    inline for (@typeInfo(BN254Builtin).@"enum".fields) |field| {
        const builtin: BN254Builtin = @enumFromInt(field.value);
        var bundle = try buildBuiltinOps(allocator, builtin);
        defer bundle.deinit();
        try std.testing.expect(bundle.ops.len > 0);
    }
}

test "bn254_field_add contains OP_ADD and OP_MOD" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bn254_field_add);
    defer bundle.deinit();

    var has_add = false;
    var has_mod = false;
    for (bundle.ops) |op| switch (op) {
        .opcode => |name| {
            if (std.mem.eql(u8, name, "OP_ADD")) has_add = true;
            if (std.mem.eql(u8, name, "OP_MOD")) has_mod = true;
        },
        else => {},
    };
    try std.testing.expect(has_add);
    try std.testing.expect(has_mod);
}

test "bn254_field_mul contains OP_MUL and OP_MOD" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bn254_field_mul);
    defer bundle.deinit();

    var has_mul = false;
    var has_mod = false;
    for (bundle.ops) |op| switch (op) {
        .opcode => |name| {
            if (std.mem.eql(u8, name, "OP_MUL")) has_mul = true;
            if (std.mem.eql(u8, name, "OP_MOD")) has_mod = true;
        },
        else => {},
    };
    try std.testing.expect(has_mul);
    try std.testing.expect(has_mod);
}

test "bn254_field_inv produces large op count for 253-iteration exponentiation" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bn254_field_inv);
    defer bundle.deinit();
    // 253 squarings + ~109 multiplications, each generating many ops.
    try std.testing.expect(bundle.ops.len > 500);
}

test "bn254_g1_on_curve ends in OP_EQUAL" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bn254_g1_on_curve);
    defer bundle.deinit();
    // After popPrimeCache the last ops involve alt-stack cleanup;
    // the OP_EQUAL must appear before that.
    var has_equal = false;
    for (bundle.ops) |op| switch (op) {
        .opcode => |name| if (std.mem.eql(u8, name, "OP_EQUAL")) {
            has_equal = true;
        },
        else => {},
    };
    try std.testing.expect(has_equal);
}

test "bn254_g1_scalar_mul emits 255 conditional additions" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bn254_g1_scalar_mul);
    defer bundle.deinit();

    var if_count: usize = 0;
    for (bundle.ops) |op| switch (op) {
        .@"if" => if_count += 1,
        else => {},
    };

    // 255 bit-iteration IFs (bits 254..0). Nested IFs inside the add branch
    // are not counted at the top level, so this is exactly 255.
    try std.testing.expectEqual(@as(usize, 255), if_count);
}

test "field prime encoding produces 33-byte script num with sign byte" {
    const encoded = try beToUnsignedScriptNumAlloc(std.testing.allocator, bn254_field_p_be[0..]);
    defer std.testing.allocator.free(encoded);
    // BN254 p is 254 bits; the high byte is 0x30 (no sign bit), so no
    // extra sign byte needed → 32 bytes.
    try std.testing.expectEqual(@as(usize, 32), encoded.len);
    // Little-endian: first byte is low byte of p.
    try std.testing.expectEqual(@as(u8, 0x47), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x30), encoded[31]);
}

test "p-2 bit 253 is set (MSB of exponent)" {
    try std.testing.expectEqual(@as(u1, 1), bn254PMinus2Bit(253));
    try std.testing.expectEqual(@as(u1, 1), bn254PMinus2Bit(252));
    // bit 1 of p-2 = 0x...45 → 0b0100_0101 → bit 1 = 0, bit 2 = 1
    try std.testing.expectEqual(@as(u1, 0), bn254PMinus2Bit(1));
    try std.testing.expectEqual(@as(u1, 1), bn254PMinus2Bit(2));
    // bit 0 of p-2 (= 0x45) is 1
    try std.testing.expectEqual(@as(u1, 1), bn254PMinus2Bit(0));
}

// ===========================================================================
// Scalar-domain tests for bn254G1ScalarMul
// ===========================================================================
//
// `bn254G1ScalarMul` is a contract-callable builtin in every tier (see
// passes/typecheck.zig), and until these pins existed nothing outside the Go
// tier had ever compared its emitted ladder against the reference. What the
// comparison found: the scalar was never reduced mod r.
//
// The ladder builds k' = k + 3r, seeds the accumulator at bit 255 rather than
// stepping it, and iterates bits 254..0. That is sound ONLY while
// 2^255 <= k' < 2^256, i.e. while 2^255 - 3r <= k < 2^256 - 3r (about
// -0.3549*r to 2.2902*r). Outside that window the ladder does not fail — it
// applies the multiplier 2^255 + ((k + 3r) mod 2^255), which is not congruent
// to k mod r. In Groth16 the scalars are the caller-supplied PUBLIC INPUTS of
// vk_x = IC[0] + sum(IC[i] * pub_i), so the domain is attacker-chosen.
//
// Reducing also makes k = 0 mod r reachable, and there the final ladder step
// is handed accumulator == -base. The mixed-add's H == 0 test cannot tell
// -base from +base, so the last step additionally needs R == 0 (`strict`) or
// it returns -2P where the answer is the point at infinity.

/// Name a bundle op for sequence matching. A push of r answers "PUSH_R" in
/// EITHER representation (`big_int_decimal` or raw script-num `bytes`), so the
/// shape assertion below is independent of the push-kind change that let the
/// peephole fold `+r +r +r` into `+3r`.
fn bn254TestOpName(op: StackOp, r_script_num: []const u8) []const u8 {
    return switch (op) {
        .opcode => |name| name,
        .rot => "OP_ROT",
        .drop => "OP_DROP",
        .over => "OP_OVER",
        .swap => "OP_SWAP",
        .push => |v| switch (v) {
            .big_int_decimal => |d| if (std.mem.eql(u8, d, bn254_curve_r_decimal)) "PUSH_R" else "_",
            .bytes => |b| if (std.mem.eql(u8, b, r_script_num)) "PUSH_R" else "_",
            else => "_",
        },
        else => "_",
    };
}

test "bn254_g1_scalar_mul reduces the scalar mod r before the ladder" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bn254_g1_scalar_mul);
    defer bundle.deinit();

    const r_script_num = try beToUnsignedScriptNumAlloc(allocator, bn254_curve_r_be[0..]);
    defer allocator.free(r_script_num);

    // ((k mod r) + r) mod r. OP_MOD takes the sign of the DIVIDEND, so
    // `k mod r` alone lands in (-r, r); the `+ r, mod r` normalises the
    // negative half.
    const want = [_][]const u8{
        "PUSH_R", "OP_2DUP", "OP_MOD",  "OP_ROT", "OP_DROP",
        "OP_OVER", "OP_ADD", "OP_SWAP", "OP_MOD",
    };

    var hits: usize = 0;
    var i: usize = 0;
    while (i + want.len <= bundle.ops.len) : (i += 1) {
        var all = true;
        for (want, 0..) |w, j| {
            if (!std.mem.eql(u8, bn254TestOpName(bundle.ops[i + j], r_script_num), w)) {
                all = false;
                break;
            }
        }
        if (all) hits += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), hits);
}

test "bn254_g1_scalar_mul pays the strict R == 0 test at the last step only" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .bn254_g1_scalar_mul);
    defer bundle.deinit();

    // The 255 bit-iteration IFs, in emission order (bit 254 down to bit 0).
    var branches: std.ArrayList([]StackOp) = .empty;
    defer branches.deinit(allocator);
    for (bundle.ops) |op| switch (op) {
        .@"if" => |b| try branches.append(allocator, b.then),
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 255), branches.items.len);

    const boolands = struct {
        fn count(ops: []const StackOp) usize {
            var n: usize = 0;
            for (ops) |o| switch (o) {
                .opcode => |name| {
                    if (std.mem.eql(u8, name, "OP_BOOLAND")) n += 1;
                },
                else => {},
            };
            return n;
        }
    }.count;

    const base = boolands(branches.items[0]);
    // The final step gains exactly one OP_BOOLAND: it combines H == 0 with
    // R == 0, which is what separates accumulator == -base (sum is O) from
    // accumulator == +base (double it).
    try std.testing.expectEqual(base + 1, boolands(branches.items[254]));
    // Every earlier step keeps the cheap H == 0 test. Paying the strict test
    // at all 255 steps would be ~5.8 KB re-deciding a branch that provably
    // cannot fire before the last one.
    for (branches.items[0..254]) |b| {
        try std.testing.expectEqual(base, boolands(b));
    }
}
