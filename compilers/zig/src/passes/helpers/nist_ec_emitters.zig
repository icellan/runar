//! NIST P-256 and P-384 elliptic curve codegen for Bitcoin Script.
//!
//! Follows the same pattern as ec_emitters.zig and bn254_emitters.zig.
//! Uses ECTracker for named stack state tracking.
//!
//! Point representation:
//!   P-256: 64 bytes (x[32] || y[32], big-endian unsigned)
//!   P-384: 96 bytes (x[48] || y[48], big-endian unsigned)
//!
//! Key difference from secp256k1: a = -3 (not 0), giving an optimized
//! Jacobian doubling formula.

const std = @import("std");
const ec = @import("ec_emitters.zig");
const registry = @import("crypto_builtins.zig");

const Allocator = std.mem.Allocator;
const StackOp = ec.StackOp;
const StackIf = ec.StackIf;
const PushValue = ec.PushValue;
const EcOpBundle = ec.EcOpBundle;

// ===========================================================================
// P-256 (secp256r1) constants — 32-byte big-endian
// ===========================================================================

/// P-256 field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
const p256_field_p_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// P-256 curve parameter b
const p256_b_be = [_]u8{
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
    0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
    0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
};

/// P-256 curve order n
const p256_n_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};

/// P-256 generator x
const p256_gx_be = [_]u8{
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
};

/// P-256 generator y
const p256_gy_be = [_]u8{
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};

/// P-256 field p-2 (for Fermat inversion). 256 bits; stored big-endian.
/// p - 2 = ffffffff00000001000000000000000000000000ffffffffffffffffffffffff - 2
///       = ffffffff00000001000000000000000000000000fffffffffffffffffffffffd
const p256_p_minus_2_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
};

/// P-256 curve order n-2 (for group inversion).
/// n - 2 = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f
const p256_n_minus_2_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
};

/// P-256 3*n (pre-computed for k+3n in scalar multiplication, matching Go peephole output)
/// 3n = 0x02fffffffd00000002ffffffffffffffff36b4f008f546db8edb2d6048f5296ff3
const p256_3n_be = [_]u8{
    0x02, 0xff, 0xff, 0xff, 0xfd, 0x00, 0x00, 0x00,
    0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x36, 0xb4, 0xf0, 0x08, 0xf5, 0x46, 0xdb,
    0x8e, 0xdb, 0x2d, 0x60, 0x48, 0xf5, 0x29, 0x6f,
    0xf3,
};

/// P-256 sqrt exponent = (p+1)/4
/// = 3fffffffc0000000400000000000000000000000400000000000000000000000
const p256_sqrt_exp_be = [_]u8{
    0x3f, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// ===========================================================================
// P-384 (secp384r1) constants — 48-byte big-endian
// ===========================================================================

/// P-384 field prime p
const p384_field_p_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

/// P-384 curve parameter b
const p384_b_be = [_]u8{
    0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4,
    0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
    0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12,
    0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a,
    0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d,
    0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
};

/// P-384 curve order n
const p384_n_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
    0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
};

/// P-384 generator x
const p384_gx_be = [_]u8{
    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37,
    0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
    0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
    0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
    0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c,
    0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
};

/// P-384 generator y
const p384_gy_be = [_]u8{
    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f,
    0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
    0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
    0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
    0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d,
    0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
};

/// P-384 field p-2 (for Fermat inversion)
const p384_p_minus_2_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfd,
};

/// P-384 curve order n-2 (for group inversion)
const p384_n_minus_2_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
    0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x71,
};

/// P-384 sqrt exponent = (p+1)/4
const p384_sqrt_exp_be = [_]u8{
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
};

/// P-384 3*n (pre-computed for k+3n in scalar multiplication, matching Go peephole output)
/// 3n = 0x02ffffffffffffffffffffffffffffffffffffffffffffffff5629e885dca5899e084e2916da11f670c6c44c40664f7c59
const p384_3n_be = [_]u8{
    0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x56, 0x29, 0xe8, 0x85, 0xdc, 0xa5, 0x89,
    0x9e, 0x08, 0x4e, 0x29, 0x16, 0xda, 0x11, 0xf6,
    0x70, 0xc6, 0xc4, 0x4c, 0x40, 0x66, 0x4f, 0x7c,
    0x59,
};

// ===========================================================================
// Helper: encode big-endian bytes to Bitcoin Script number (unsigned LE + sign byte)
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

/// Get bit `i` (0 = LSB) of a big-endian byte slice.
fn getBit(be: []const u8, i: usize) u1 {
    const byte_index = be.len - 1 - (i / 8);
    const bit_index: u3 = @intCast(i % 8);
    return @intCast((be[byte_index] >> bit_index) & 1);
}

/// Find index of the most significant set bit in a big-endian byte slice.
/// Returns null if the value is zero (no bits set).
fn msbIndex(be: []const u8) ?usize {
    var i: usize = 0;
    while (i < be.len * 8) : (i += 1) {
        const bit_i = be.len * 8 - 1 - i;
        if (getBit(be, bit_i) == 1) {
            return bit_i;
        }
    }
    return null;
}

// ===========================================================================
// Curve parameter struct
// ===========================================================================

const NistCurveParams = struct {
    coord_bytes: usize, // 32 for P-256, 48 for P-384
    field_p_be: []const u8,
    field_p_minus_2_be: []const u8,
    group_n_be: []const u8,
    group_n_minus_2_be: []const u8,
    three_n_be: []const u8, // pre-computed 3*n for k+3n (matches Go peephole output)
    curve_b_be: []const u8,
    sqrt_exp_be: []const u8,
    gen_x_be: []const u8,
    gen_y_be: []const u8,
};

const p256_params = NistCurveParams{
    .coord_bytes = 32,
    .field_p_be = p256_field_p_be[0..],
    .field_p_minus_2_be = p256_p_minus_2_be[0..],
    .group_n_be = p256_n_be[0..],
    .group_n_minus_2_be = p256_n_minus_2_be[0..],
    .three_n_be = p256_3n_be[0..],
    .curve_b_be = p256_b_be[0..],
    .sqrt_exp_be = p256_sqrt_exp_be[0..],
    .gen_x_be = p256_gx_be[0..],
    .gen_y_be = p256_gy_be[0..],
};

const p384_params = NistCurveParams{
    .coord_bytes = 48,
    .field_p_be = p384_field_p_be[0..],
    .field_p_minus_2_be = p384_p_minus_2_be[0..],
    .group_n_be = p384_n_be[0..],
    .group_n_minus_2_be = p384_n_minus_2_be[0..],
    .three_n_be = p384_3n_be[0..],
    .curve_b_be = p384_b_be[0..],
    .sqrt_exp_be = p384_sqrt_exp_be[0..],
    .gen_x_be = p384_gx_be[0..],
    .gen_y_be = p384_gy_be[0..],
};

// ===========================================================================
// NistTracker — named stack state tracker for NIST EC operations
// ===========================================================================

const NistTracker = struct {
    allocator: Allocator,
    names: std.ArrayListUnmanaged(?[]const u8),
    ops: std.ArrayListUnmanaged(StackOp),
    owned_bytes: std.ArrayListUnmanaged([]u8),
    params: *const NistCurveParams,

    fn init(allocator: Allocator, initial_names: []const ?[]const u8, params: *const NistCurveParams) !NistTracker {
        var names: std.ArrayListUnmanaged(?[]const u8) = .empty;
        errdefer names.deinit(allocator);
        try names.appendSlice(allocator, initial_names);
        return .{
            .allocator = allocator,
            .names = names,
            .ops = .empty,
            .owned_bytes = .empty,
            .params = params,
        };
    }

    fn deinit(self: *NistTracker) void {
        ec.deinitOpsRecursive(self.allocator, self.ops.items);
        self.ops.deinit(self.allocator);
        self.names.deinit(self.allocator);
        for (self.owned_bytes.items) |bytes| self.allocator.free(bytes);
        self.owned_bytes.deinit(self.allocator);
    }

    fn takeBundle(self: *NistTracker) !EcOpBundle {
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

    fn findDepth(self: *const NistTracker, name: []const u8) !usize {
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

    fn emitRaw(self: *NistTracker, op: StackOp) !void {
        try self.ops.append(self.allocator, op);
    }

    fn emitOpcode(self: *NistTracker, code: []const u8) !void {
        try self.emitRaw(.{ .opcode = code });
    }

    fn emitPushInt(self: *NistTracker, value: i64) !void {
        try self.emitRaw(.{ .push = .{ .integer = value } });
    }

    fn pushInt(self: *NistTracker, name: ?[]const u8, value: i64) !void {
        try self.emitPushInt(value);
        try self.names.append(self.allocator, name);
    }

    fn pushOwnedBytes(self: *NistTracker, name: ?[]const u8, value: []u8) !void {
        try self.owned_bytes.append(self.allocator, value);
        try self.emitRaw(.{ .push = .{ .bytes = value } });
        try self.names.append(self.allocator, name);
    }

    fn pushStaticBytes(self: *NistTracker, name: ?[]const u8, value: []const u8) !void {
        try self.emitRaw(.{ .push = .{ .bytes = value } });
        try self.names.append(self.allocator, name);
    }

    fn pushBigIntBE(self: *NistTracker, name: ?[]const u8, be: []const u8) !void {
        const encoded = try beToUnsignedScriptNumAlloc(self.allocator, be);
        try self.pushOwnedBytes(name, encoded);
    }

    fn dup(self: *NistTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .dup = {} });
        try self.names.append(self.allocator, name);
    }

    fn drop(self: *NistTracker) !void {
        try self.emitRaw(.{ .drop = {} });
        _ = self.names.pop();
    }

    fn swap(self: *NistTracker) !void {
        try self.emitRaw(.{ .swap = {} });
        const len = self.names.items.len;
        if (len >= 2) {
            const tmp = self.names.items[len - 1];
            self.names.items[len - 1] = self.names.items[len - 2];
            self.names.items[len - 2] = tmp;
        }
    }

    fn over(self: *NistTracker, name: ?[]const u8) !void {
        try self.emitRaw(.{ .over = {} });
        try self.names.append(self.allocator, name);
    }

    fn rot(self: *NistTracker) !void {
        try self.emitRaw(.{ .rot = {} });
        const len = self.names.items.len;
        if (len >= 3) {
            const rolled = self.names.orderedRemove(len - 3);
            try self.names.append(self.allocator, rolled);
        }
    }

    fn roll(self: *NistTracker, depth_from_top: usize) !void {
        if (depth_from_top == 0) return;
        if (depth_from_top == 1) return self.swap();
        if (depth_from_top == 2) return self.rot();
        try self.emitRaw(.{ .roll = @intCast(depth_from_top) });
        const idx = self.names.items.len - 1 - depth_from_top;
        const rolled = self.names.orderedRemove(idx);
        try self.names.append(self.allocator, rolled);
    }

    fn pick(self: *NistTracker, depth_from_top: usize, name: ?[]const u8) !void {
        if (depth_from_top == 0) return self.dup(name);
        if (depth_from_top == 1) return self.over(name);
        try self.emitRaw(.{ .pick = @intCast(depth_from_top) });
        try self.names.append(self.allocator, name);
    }

    fn toTop(self: *NistTracker, name: []const u8) !void {
        try self.roll(try self.findDepth(name));
    }

    fn copyToTop(self: *NistTracker, name: []const u8, copy_name: ?[]const u8) !void {
        try self.pick(try self.findDepth(name), copy_name);
    }

    fn renameTop(self: *NistTracker, name: ?[]const u8) void {
        if (self.names.items.len > 0) {
            self.names.items[self.names.items.len - 1] = name;
        }
    }

    fn popNames(self: *NistTracker, count: usize) void {
        var i: usize = 0;
        while (i < count and self.names.items.len > 0) : (i += 1) {
            _ = self.names.pop();
        }
    }

    fn toAlt(self: *NistTracker) !void {
        try self.emitOpcode("OP_TOALTSTACK");
        _ = self.names.pop();
    }

    fn fromAlt(self: *NistTracker, name: ?[]const u8) !void {
        try self.emitOpcode("OP_FROMALTSTACK");
        try self.names.append(self.allocator, name);
    }
};

// ===========================================================================
// Byte reversal emitters (for coord_bytes = 32 or 48)
// ===========================================================================

fn emitReverseN(t: *NistTracker, n: usize) !void {
    try t.emitOpcode("OP_0");
    try t.emitRaw(.{ .swap = {} });
    for (0..n) |_| {
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

/// Convert N big-endian bytes on TOS to an unsigned script-num (little-endian + sign byte 0x00).
fn emitBytesToUnsignedNum(t: *NistTracker, coord_bytes: usize) !void {
    try emitReverseN(t, coord_bytes);
    try t.emitRaw(.{ .push = .{ .bytes = &.{0x00} } });
    try t.emitOpcode("OP_CAT");
    try t.emitOpcode("OP_BIN2NUM");
}

/// Convert an unsigned script-num on TOS to N big-endian bytes.
fn emitUnsignedNumToBeBytes(t: *NistTracker, coord_bytes: usize) !void {
    const n_plus_1 = @as(i64, @intCast(coord_bytes + 1));
    try t.emitPushInt(n_plus_1);
    try t.emitOpcode("OP_NUM2BIN");
    try t.emitPushInt(@as(i64, @intCast(coord_bytes)));
    try t.emitOpcode("OP_SPLIT");
    try t.emitRaw(.{ .drop = {} });
    try emitReverseN(t, coord_bytes);
}

// ===========================================================================
// Point decompose / compose
// ===========================================================================

fn decomposePoint(t: *NistTracker, point_name: []const u8, x_name: []const u8, y_name: []const u8) !void {
    const cb = t.params.coord_bytes;
    try t.toTop(point_name);
    t.popNames(1);
    try t.emitPushInt(@intCast(cb));
    try t.emitOpcode("OP_SPLIT");
    try t.names.append(t.allocator, "_dp_xb");
    try t.names.append(t.allocator, "_dp_yb");

    // Convert y_bytes (on top) to num
    try t.toTop("_dp_yb");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, cb);
    try t.names.append(t.allocator, y_name);

    // Convert x_bytes to num
    try t.toTop("_dp_xb");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, cb);
    try t.names.append(t.allocator, x_name);

    try t.swap();
}

fn composePoint(t: *NistTracker, x_name: []const u8, y_name: []const u8, result_name: []const u8) !void {
    const cb = t.params.coord_bytes;

    try t.toTop(x_name);
    t.popNames(1);
    try emitUnsignedNumToBeBytes(t, cb);
    try t.names.append(t.allocator, "_cp_xb");

    try t.toTop(y_name);
    t.popNames(1);
    try emitUnsignedNumToBeBytes(t, cb);
    try t.names.append(t.allocator, "_cp_yb");

    try t.toTop("_cp_xb");
    try t.toTop("_cp_yb");
    t.popNames(2);
    try t.emitOpcode("OP_CAT");
    try t.names.append(t.allocator, result_name);
}

// ===========================================================================
// Field arithmetic (parameterized by the field prime)
// ===========================================================================

fn fieldMod(t: *NistTracker, a_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.pushBigIntBE("_fmod_p", p_be);
    t.popNames(2);
    try t.emitOpcode("OP_2DUP");
    try t.emitOpcode("OP_MOD");
    try t.emitRaw(.{ .rot = {} });
    try t.emitRaw(.{ .drop = {} });
    try t.emitRaw(.{ .over = {} });
    try t.emitOpcode("OP_ADD");
    try t.emitRaw(.{ .swap = {} });
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

fn fieldAdd(t: *NistTracker, a_name: []const u8, b_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, "_fadd_sum");
    try fieldMod(t, "_fadd_sum", p_be, result_name);
}

fn fieldSub(t: *NistTracker, a_name: []const u8, b_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.names.append(t.allocator, "_fsub_diff");
    try fieldMod(t, "_fsub_diff", p_be, result_name);
}

fn fieldMul(t: *NistTracker, a_name: []const u8, b_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.names.append(t.allocator, "_fmul_prod");
    try fieldMod(t, "_fmul_prod", p_be, result_name);
}

fn fieldSqr(t: *NistTracker, a_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_fsqr_copy");
    try fieldMul(t, a_name, "_fsqr_copy", p_be, result_name);
}

fn fieldMulConst(t: *NistTracker, a_name: []const u8, c: i64, p_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    t.popNames(1);
    if (c == 2) {
        try t.emitOpcode("OP_2MUL");
    } else {
        try t.emitPushInt(c);
        try t.emitOpcode("OP_MUL");
    }
    try t.names.append(t.allocator, "_fmc_prod");
    try fieldMod(t, "_fmc_prod", p_be, result_name);
}

/// Field inversion via Fermat's little theorem: a^(p-2) mod p.
/// Iterates over bits of p-2 from MSB-1 down to 0, using square-and-multiply.
fn fieldInv(t: *NistTracker, a_name: []const u8, exp_be: []const u8, p_be: []const u8, result_name: []const u8) !void {
    // Find MSB
    const msb_opt = msbIndex(exp_be);
    if (msb_opt == null) {
        // Degenerate: exponent is zero (should not happen for p-2)
        try t.copyToTop(a_name, result_name);
        return;
    }
    const msb = msb_opt.?;

    // Initialize result = a (implicit MSB = 1)
    try t.copyToTop(a_name, "_inv_r");

    // Iterate from MSB-1 down to 0
    var i: i64 = @as(i64, @intCast(msb)) - 1;
    while (i >= 0) : (i -= 1) {
        // Always square
        try fieldSqr(t, "_inv_r", p_be, "_inv_r2");
        t.renameTop("_inv_r");

        // Conditional multiply if bit i is set
        if (getBit(exp_be, @intCast(i)) == 1) {
            try t.copyToTop(a_name, "_inv_a");
            try fieldMul(t, "_inv_r", "_inv_a", p_be, "_inv_m");
            t.renameTop("_inv_r");
        }
    }

    // Drop the original a
    try t.toTop(a_name);
    try t.drop();
    try t.toTop("_inv_r");
    t.renameTop(result_name);
}

// ===========================================================================
// Group-order arithmetic (mod n)
// ===========================================================================

fn groupMod(t: *NistTracker, a_name: []const u8, n_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.pushBigIntBE("_gmod_n", n_be);
    t.popNames(2);
    try t.emitOpcode("OP_2DUP");
    try t.emitOpcode("OP_MOD");
    try t.emitRaw(.{ .rot = {} });
    try t.emitRaw(.{ .drop = {} });
    try t.emitRaw(.{ .over = {} });
    try t.emitOpcode("OP_ADD");
    try t.emitRaw(.{ .swap = {} });
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, result_name);
}

fn groupMul(t: *NistTracker, a_name: []const u8, b_name: []const u8, n_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.names.append(t.allocator, "_gmul_prod");
    try groupMod(t, "_gmul_prod", n_be, result_name);
}

fn groupInv(t: *NistTracker, a_name: []const u8, exp_be: []const u8, n_be: []const u8, result_name: []const u8) !void {
    const msb_opt = msbIndex(exp_be);
    if (msb_opt == null) {
        try t.copyToTop(a_name, result_name);
        return;
    }
    const msb = msb_opt.?;

    try t.copyToTop(a_name, "_ginv_r");

    var i: i64 = @as(i64, @intCast(msb)) - 1;
    while (i >= 0) : (i -= 1) {
        try t.copyToTop("_ginv_r", "_ginv_sq_copy");
        try groupMul(t, "_ginv_r", "_ginv_sq_copy", n_be, "_ginv_sq");
        t.renameTop("_ginv_r");

        if (getBit(exp_be, @intCast(i)) == 1) {
            try t.copyToTop(a_name, "_ginv_a");
            try groupMul(t, "_ginv_r", "_ginv_a", n_be, "_ginv_m");
            t.renameTop("_ginv_r");
        }
    }

    try t.toTop(a_name);
    try t.drop();
    try t.toTop("_ginv_r");
    t.renameTop(result_name);
}

// ===========================================================================
// Affine point addition (for use in ECDSA and addition operations)
// ===========================================================================

fn affineAdd(t: *NistTracker, p_be: []const u8) !void {
    try t.copyToTop("qy", "_qy1");
    try t.copyToTop("py", "_py1");
    try fieldSub(t, "_qy1", "_py1", p_be, "_s_num");

    try t.copyToTop("qx", "_qx1");
    try t.copyToTop("px", "_px1");
    try fieldSub(t, "_qx1", "_px1", p_be, "_s_den");

    try fieldInv(t, "_s_den", t.params.field_p_minus_2_be, p_be, "_s_den_inv");
    try fieldMul(t, "_s_num", "_s_den_inv", p_be, "_s");

    try t.copyToTop("_s", "_s_keep");
    try fieldSqr(t, "_s", p_be, "_s2");
    try t.copyToTop("px", "_px2");
    try fieldSub(t, "_s2", "_px2", p_be, "_rx1");
    try t.copyToTop("qx", "_qx2");
    try fieldSub(t, "_rx1", "_qx2", p_be, "rx");

    try t.copyToTop("px", "_px3");
    try t.copyToTop("rx", "_rx2");
    try fieldSub(t, "_px3", "_rx2", p_be, "_px_rx");
    try fieldMul(t, "_s_keep", "_px_rx", p_be, "_s_px_rx");
    try t.copyToTop("py", "_py2");
    try fieldSub(t, "_s_px_rx", "_py2", p_be, "ry");

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
// Jacobian point doubling with a=-3 optimization
// ===========================================================================

fn jacobianDouble(t: *NistTracker, p_be: []const u8) !void {
    // Z^2
    try t.copyToTop("jz", "_jz_sq_tmp");
    try fieldSqr(t, "_jz_sq_tmp", p_be, "_Z2");

    // X - Z^2 and X + Z^2
    try t.copyToTop("jx", "_jx_c1");
    try t.copyToTop("_Z2", "_Z2_c1");
    try fieldSub(t, "_jx_c1", "_Z2_c1", p_be, "_X_minus_Z2");
    try t.copyToTop("jx", "_jx_c2");
    try fieldAdd(t, "_jx_c2", "_Z2", p_be, "_X_plus_Z2");

    // A = 3*(X-Z^2)*(X+Z^2)
    try fieldMul(t, "_X_minus_Z2", "_X_plus_Z2", p_be, "_prod");
    try t.pushInt("_three", 3);
    try fieldMul(t, "_prod", "_three", p_be, "_A");

    // B = 4*X*Y^2
    try t.copyToTop("jy", "_jy_sq_tmp");
    try fieldSqr(t, "_jy_sq_tmp", p_be, "_Y2");
    try t.copyToTop("_Y2", "_Y2_c1");
    try t.copyToTop("jx", "_jx_c3");
    try fieldMul(t, "_jx_c3", "_Y2", p_be, "_xY2");
    try t.pushInt("_four", 4);
    try fieldMul(t, "_xY2", "_four", p_be, "_B");

    // C = 8*Y^4
    try fieldSqr(t, "_Y2_c1", p_be, "_Y4");
    try t.pushInt("_eight", 8);
    try fieldMul(t, "_Y4", "_eight", p_be, "_C");

    // X3 = A^2 - 2*B
    try t.copyToTop("_A", "_A_save");
    try t.copyToTop("_B", "_B_save");
    try fieldSqr(t, "_A", p_be, "_A2");
    try t.copyToTop("_B", "_B_c1");
    try fieldMulConst(t, "_B_c1", 2, p_be, "_2B");
    try fieldSub(t, "_A2", "_2B", p_be, "_X3");

    // Y3 = A*(B - X3) - C
    try t.copyToTop("_X3", "_X3_c");
    try fieldSub(t, "_B_save", "_X3_c", p_be, "_B_minus_X3");
    try fieldMul(t, "_A_save", "_B_minus_X3", p_be, "_A_tmp");
    try fieldSub(t, "_A_tmp", "_C", p_be, "_Y3");

    // Z3 = 2*Y*Z
    try t.copyToTop("jy", "_jy_c");
    try t.copyToTop("jz", "_jz_c");
    try fieldMul(t, "_jy_c", "_jz_c", p_be, "_yz");
    try fieldMulConst(t, "_yz", 2, p_be, "_Z3");

    // Clean up and rename
    try t.toTop("_B");
    try t.drop();
    try t.toTop("jz");
    try t.drop();
    try t.toTop("jx");
    try t.drop();
    try t.toTop("jy");
    try t.drop();
    try t.toTop("_X3");
    t.renameTop("jx");
    try t.toTop("_Y3");
    t.renameTop("jy");
    try t.toTop("_Z3");
    t.renameTop("jz");
}

// ===========================================================================
// Jacobian to affine conversion
// ===========================================================================

fn jacobianToAffine(t: *NistTracker, rx_name: []const u8, ry_name: []const u8, p_be: []const u8, p_minus_2_be: []const u8) !void {
    try fieldInv(t, "jz", p_minus_2_be, p_be, "_zinv");
    try t.copyToTop("_zinv", "_zinv_keep");
    try fieldSqr(t, "_zinv", p_be, "_zinv2");
    try t.copyToTop("_zinv2", "_zinv2_keep");
    try fieldMul(t, "_zinv_keep", "_zinv2", p_be, "_zinv3");
    try fieldMul(t, "jx", "_zinv2_keep", p_be, rx_name);
    try fieldMul(t, "jy", "_zinv3", p_be, ry_name);
}

// ===========================================================================
// Jacobian mixed addition (point_jacobian + point_affine) — for inside OP_IF
// ===========================================================================

fn buildJacobianAddAffineInline(allocator: Allocator, base_names: []const ?[]const u8, params: *const NistCurveParams) !EcOpBundle {
    var inner = try NistTracker.init(allocator, base_names, params);
    errdefer inner.deinit();

    const p_be = params.field_p_be;

    try inner.copyToTop("jz", "_jz_for_z1cu");
    try inner.copyToTop("jz", "_jz_for_z3");
    try inner.copyToTop("jy", "_jy_for_y3");
    try inner.copyToTop("jx", "_jx_for_u1h2");

    // Z1sq = jz^2
    try fieldSqr(&inner, "jz", p_be, "_Z1sq");
    try inner.copyToTop("_Z1sq", "_Z1sq_for_u2");
    try fieldMul(&inner, "_jz_for_z1cu", "_Z1sq", p_be, "_Z1cu");

    // U2 = ax * Z1sq_for_u2
    try inner.copyToTop("ax", "_ax_c");
    try fieldMul(&inner, "_ax_c", "_Z1sq_for_u2", p_be, "_U2");

    // S2 = ay * Z1cu
    try inner.copyToTop("ay", "_ay_c");
    try fieldMul(&inner, "_ay_c", "_Z1cu", p_be, "_S2");

    // H = U2 - jx
    try fieldSub(&inner, "_U2", "jx", p_be, "_H");

    // R = S2 - jy
    try fieldSub(&inner, "_S2", "jy", p_be, "_R");

    try inner.copyToTop("_H", "_H_for_h3");
    try inner.copyToTop("_H", "_H_for_z3");

    // H2 = H^2
    try fieldSqr(&inner, "_H", p_be, "_H2");
    try inner.copyToTop("_H2", "_H2_for_u1h2");

    // H3 = H_for_h3 * H2
    try fieldMul(&inner, "_H_for_h3", "_H2", p_be, "_H3");

    // U1H2 = _jx_for_u1h2 * H2_for_u1h2
    try fieldMul(&inner, "_jx_for_u1h2", "_H2_for_u1h2", p_be, "_U1H2");

    try inner.copyToTop("_R", "_R_for_y3");
    try inner.copyToTop("_U1H2", "_U1H2_for_y3");
    try inner.copyToTop("_H3", "_H3_for_y3");

    // X3 = R^2 - H3 - 2*U1H2
    try fieldSqr(&inner, "_R", p_be, "_R2");
    try fieldSub(&inner, "_R2", "_H3", p_be, "_x3_tmp");
    try fieldMulConst(&inner, "_U1H2", 2, p_be, "_2U1H2");
    try fieldSub(&inner, "_x3_tmp", "_2U1H2", p_be, "_X3");

    // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    try inner.copyToTop("_X3", "_X3_c");
    try fieldSub(&inner, "_U1H2_for_y3", "_X3_c", p_be, "_u_minus_x");
    try fieldMul(&inner, "_R_for_y3", "_u_minus_x", p_be, "_r_tmp");
    try fieldMul(&inner, "_jy_for_y3", "_H3_for_y3", p_be, "_jy_h3");
    try fieldSub(&inner, "_r_tmp", "_jy_h3", p_be, "_Y3");

    // Z3 = _jz_for_z3 * _H_for_z3
    try fieldMul(&inner, "_jz_for_z3", "_H_for_z3", p_be, "_Z3");

    try inner.toTop("_X3");
    inner.renameTop("jx");
    try inner.toTop("_Y3");
    inner.renameTop("jy");
    try inner.toTop("_Z3");
    inner.renameTop("jz");

    return inner.takeBundle();
}

// ===========================================================================
// Scalar multiplication (generic for P-256 and P-384)
// ===========================================================================

/// buildScalarMulBundle creates a standalone bundle for scalar multiplication.
/// Expects exactly two items on the stack: [point, scalar] (scalar on top).
/// Produces exactly one result item: the result point.
fn buildScalarMulBundle(allocator: Allocator, params: *const NistCurveParams) !EcOpBundle {
    var t = try NistTracker.init(allocator, &.{ "_pt", "_k" }, params);
    errdefer t.deinit();
    try emitScalarMulOnTracker(&t);
    return t.takeBundle();
}

/// emitScalarMulOnTracker performs scalar mul using the tracker's current names.
/// The tracker must have "_pt" and "_k" as named items (in any position).
fn emitScalarMulOnTracker(t: *NistTracker) !void {
    const c = t.params;
    const p_be = c.field_p_be;

    try decomposePoint(t, "_pt", "ax", "ay");

    // k' = k + 3n (pre-compute 3n to match Go peephole optimizer output)
    try t.toTop("_k");
    try t.pushBigIntBE("_3n", c.three_n_be);
    t.popNames(2);
    try t.emitOpcode("OP_ADD");
    try t.names.append(t.allocator, "_k");

    // Determine iteration count based on 3n bit length.
    // The max value of k+3n is 4n-1 which has the same MSB as 3n.
    const three_n_msb = msbIndex(c.three_n_be).?;
    const start_bit: i64 = @as(i64, @intCast(three_n_msb)) - 1;

    // Init accumulator = P (top bit of k+3n is always 1)
    try t.copyToTop("ax", "jx");
    try t.copyToTop("ay", "jy");
    try t.pushInt("jz", 1);

    var bit: i64 = start_bit;
    while (bit >= 0) : (bit -= 1) {
        try jacobianDouble(t, p_be);

        // Extract bit: (k >> bit) & 1
        try t.copyToTop("_k", "_k_copy");
        if (bit == 1) {
            t.popNames(1);
            try t.emitOpcode("OP_2DIV");
            try t.names.append(t.allocator, "_shifted");
        } else if (bit > 1) {
            try t.pushInt("_shift", bit);
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

        // Conditional add
        try t.toTop("_bit");
        t.popNames(1);

        var add_bundle = try buildJacobianAddAffineInline(t.allocator, t.names.items, c);
        errdefer add_bundle.deinit();

        try t.owned_bytes.appendSlice(t.allocator, add_bundle.owned_bytes);
        t.allocator.free(add_bundle.owned_bytes);
        add_bundle.owned_bytes = &.{};

        try t.emitRaw(.{ .@"if" = .{ .then = add_bundle.ops, .@"else" = null } });
        add_bundle.ops = &.{};
    }

    try jacobianToAffine(t, "_rx", "_ry", p_be, c.field_p_minus_2_be);

    try t.toTop("ax");
    try t.drop();
    try t.toTop("ay");
    try t.drop();
    try t.toTop("_k");
    try t.drop();

    try composePoint(t, "_rx", "_ry", "_result");
}

/// emitScalarMulInline emits scalar mul ops into `outer` tracker.
/// Before calling, the outer tracker must have pushed the point and scalar
/// (point then scalar, scalar on top) and removed their names via popNames(2).
/// After the call, one result name is appended to the outer tracker.
fn emitScalarMulInline(outer: *NistTracker, result_name: []const u8) !void {
    var bundle = try buildScalarMulBundle(outer.allocator, outer.params);
    errdefer bundle.deinit();

    // Transfer owned_bytes pointers to outer tracker, then free the outer slice.
    try outer.owned_bytes.appendSlice(outer.allocator, bundle.owned_bytes);
    outer.allocator.free(bundle.owned_bytes);
    bundle.owned_bytes = &.{}; // prevent double-free in errdefer/deinit

    // Transfer ops to outer tracker, then free the outer slice.
    try outer.ops.appendSlice(outer.allocator, bundle.ops);
    outer.allocator.free(bundle.ops);
    bundle.ops = &.{}; // prevent double-free in errdefer/deinit

    try outer.names.append(outer.allocator, result_name);
}

// ===========================================================================
// Field power for square root (a^sqrtExp mod p)
// ===========================================================================

fn fieldPow(t: *NistTracker, base_name: []const u8, exp_be: []const u8, p_be: []const u8, result_name: []const u8) !void {
    const msb_opt = msbIndex(exp_be);
    if (msb_opt == null) {
        // Degenerate: exponent is zero
        try t.copyToTop(base_name, result_name);
        return;
    }
    const msb = msb_opt.?;

    try t.copyToTop(base_name, "_pow_r");

    var i: i64 = @as(i64, @intCast(msb)) - 1;
    while (i >= 0) : (i -= 1) {
        try fieldSqr(t, "_pow_r", p_be, "_pow_sq");
        t.renameTop("_pow_r");
        if (getBit(exp_be, @intCast(i)) == 1) {
            try t.copyToTop(base_name, "_pow_b");
            try fieldMul(t, "_pow_r", "_pow_b", p_be, "_pow_m");
            t.renameTop("_pow_r");
        }
    }

    try t.toTop(base_name);
    try t.drop();
    try t.toTop("_pow_r");
    t.renameTop(result_name);
}

// ===========================================================================
// Public key decompression: (prefix_byte || x_bytes) -> (x, y)
// ===========================================================================

fn decompressPubKey(t: *NistTracker, pk_name: []const u8, qx_name: []const u8, qy_name: []const u8) !void {
    const c = t.params;
    const p_be = c.field_p_be;

    try t.toTop(pk_name);
    t.popNames(1);
    // Split: [prefix_byte, x_bytes]
    try t.emitPushInt(1);
    try t.emitOpcode("OP_SPLIT");
    try t.names.append(t.allocator, "_dk_prefix");
    try t.names.append(t.allocator, "_dk_xbytes");

    // Convert prefix to parity: 0x02 -> 0, 0x03 -> 1
    try t.toTop("_dk_prefix");
    t.popNames(1);
    try t.emitOpcode("OP_BIN2NUM");
    try t.emitPushInt(2);
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, "_dk_parity");

    // Stash parity on altstack
    try t.toAlt();

    // Convert x_bytes to number
    try t.toTop("_dk_xbytes");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, c.coord_bytes);
    try t.names.append(t.allocator, "_dk_x");

    // Save x for later
    try t.copyToTop("_dk_x", "_dk_x_save");

    // Compute y^2 = x^3 - 3x + b mod p
    // x^2
    try t.copyToTop("_dk_x", "_dk_x_c1");
    try fieldSqr(t, "_dk_x", p_be, "_dk_x2");
    // x^3 = x^2 * x
    try fieldMul(t, "_dk_x2", "_dk_x_c1", p_be, "_dk_x3");
    // 3 * x_save
    try t.copyToTop("_dk_x_save", "_dk_x_for_3");
    try fieldMulConst(t, "_dk_x_for_3", 3, p_be, "_dk_3x");
    // x^3 - 3x
    try fieldSub(t, "_dk_x3", "_dk_3x", p_be, "_dk_x3m3x");
    // + b
    try t.pushBigIntBE("_dk_b", c.curve_b_be);
    try fieldAdd(t, "_dk_x3m3x", "_dk_b", p_be, "_dk_y2");

    // y = (y^2)^sqrtExp mod p
    try fieldPow(t, "_dk_y2", c.sqrt_exp_be, p_be, "_dk_y_cand");

    // Check if candidate y has the right parity
    try t.copyToTop("_dk_y_cand", "_dk_y_check");
    t.popNames(1);
    try t.emitPushInt(2);
    try t.emitOpcode("OP_MOD");
    try t.names.append(t.allocator, "_dk_y_par");

    // Retrieve parity from altstack
    try t.fromAlt("_dk_parity");

    // Compare
    try t.toTop("_dk_y_par");
    try t.toTop("_dk_parity");
    t.popNames(2);
    try t.emitOpcode("OP_EQUAL");
    try t.names.append(t.allocator, "_dk_match");

    // Compute p - y_cand
    try t.copyToTop("_dk_y_cand", "_dk_y_for_neg");
    try t.pushBigIntBE("_dk_pfn", p_be);
    try t.toTop("_dk_y_for_neg");
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.names.append(t.allocator, "_dk_neg_y");

    // Use OP_IF to select: if match, use y_cand (drop neg_y), else use neg_y (drop y_cand)
    try t.toTop("_dk_match");
    t.popNames(1);

    const then_ops = try t.allocator.dupe(StackOp, &.{StackOp{ .drop = {} }});
    errdefer t.allocator.free(then_ops);
    const else_ops = try t.allocator.dupe(StackOp, &.{StackOp{ .nip = {} }});
    errdefer t.allocator.free(else_ops);
    try t.emitRaw(.{ .@"if" = .{ .then = then_ops, .@"else" = else_ops } });

    // Remove one from tracker (the branch consumed one of _dk_neg_y / _dk_y_cand)
    var neg_idx: ?usize = null;
    {
        var idx = t.names.items.len;
        while (idx > 0) {
            idx -= 1;
            if (t.names.items[idx]) |n| {
                if (std.mem.eql(u8, n, "_dk_neg_y")) {
                    neg_idx = idx;
                    break;
                }
            }
        }
    }
    if (neg_idx) |idx| {
        _ = t.names.orderedRemove(idx);
    }

    // Rename _dk_y_cand -> qyName and _dk_x_save -> qxName
    {
        var idx = t.names.items.len;
        while (idx > 0) {
            idx -= 1;
            if (t.names.items[idx]) |n| {
                if (std.mem.eql(u8, n, "_dk_y_cand")) {
                    t.names.items[idx] = qy_name;
                    break;
                }
            }
        }
    }
    {
        var idx = t.names.items.len;
        while (idx > 0) {
            idx -= 1;
            if (t.names.items[idx]) |n| {
                if (std.mem.eql(u8, n, "_dk_x_save")) {
                    t.names.items[idx] = qx_name;
                    break;
                }
            }
        }
    }
}

// ===========================================================================
// ECDSA verification
// ===========================================================================

fn emitVerifyECDSA(t: *NistTracker) !void {
    const c = t.params;
    const p_be = c.field_p_be;
    const n_be = c.group_n_be;
    const n_minus_2_be = c.group_n_minus_2_be;
    const cb = c.coord_bytes;

    // Step 1: e = SHA-256(msg) as integer
    try t.toTop("_msg");
    t.popNames(1);
    try t.emitOpcode("OP_SHA256");
    // SHA-256 produces 32 bytes BE. Reverse to get LE, cat 0x00, BIN2NUM.
    try emitReverseN(t, 32);
    try t.emitRaw(.{ .push = .{ .bytes = &.{0x00} } });
    try t.emitOpcode("OP_CAT");
    try t.emitOpcode("OP_BIN2NUM");
    try t.names.append(t.allocator, "_e");

    // Step 2: Parse sig into (r, s) — each coord_bytes bytes
    try t.toTop("_sig");
    t.popNames(1);
    try t.emitPushInt(@intCast(cb));
    try t.emitOpcode("OP_SPLIT");
    try t.names.append(t.allocator, "_r_bytes");
    try t.names.append(t.allocator, "_s_bytes");

    // Convert r_bytes to integer
    try t.toTop("_r_bytes");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, cb);
    try t.names.append(t.allocator, "_r");

    // Convert s_bytes to integer
    try t.toTop("_s_bytes");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, cb);
    try t.names.append(t.allocator, "_s");

    // Step 3: Decompress pubkey
    try decompressPubKey(t, "_pk", "_qx", "_qy");

    // Step 4: w = s^{-1} mod n
    try groupInv(t, "_s", n_minus_2_be, n_be, "_w");

    // Step 5: u1 = e * w mod n
    try t.copyToTop("_w", "_w_c1");
    try groupMul(t, "_e", "_w_c1", n_be, "_u1");

    // Step 6: u2 = r * w mod n
    try t.copyToTop("_r", "_r_save");
    try groupMul(t, "_r", "_w", n_be, "_u2");

    // Step 7: R1 = u1*G
    // Push G point, bring u1 to top, stash everything else on altstack
    const point_bytes = cb * 2;
    const g_point = try t.allocator.alloc(u8, point_bytes);
    @memcpy(g_point[0..cb], c.gen_x_be);
    @memcpy(g_point[cb..point_bytes], c.gen_y_be);
    try t.pushOwnedBytes("_G", g_point);
    try t.toTop("_u1");

    // Stash items on altstack (pushed in reverse retrieval order)
    try t.toTop("_r_save");
    try t.toAlt();
    try t.toTop("_u2");
    try t.toAlt();
    try t.toTop("_qy");
    try t.toAlt();
    try t.toTop("_qx");
    try t.toAlt();

    // Stack now has: [..., _G, _u1]
    // Pop those names and emit scalar mul inline (consuming _G and _u1)
    t.popNames(1); // _u1
    t.popNames(1); // _G
    try emitScalarMulInline(t, "_R1_point");

    // Pop qx/qy/u2 from altstack (LIFO order)
    try t.fromAlt("_qx");
    try t.fromAlt("_qy");
    try t.fromAlt("_u2");

    // Stash R1 point while we compute R2
    try t.toTop("_R1_point");
    try t.toAlt();

    // Compose Q point from qx, qy
    try composePoint(t, "_qx", "_qy", "_Q_point");

    // Stack now has: [..., _Q_point, _u2]
    // Bring _Q_point below _u2 to match expected [point, scalar] order
    try t.toTop("_Q_point");
    try t.toTop("_u2");

    // Pop those names and emit scalar mul inline (consuming _Q_point and _u2)
    t.popNames(1); // _u2
    t.popNames(1); // _Q_point
    try emitScalarMulInline(t, "_R2_point");

    // Restore R1 point
    try t.fromAlt("_R1_point");

    // Swap so _R2_point is on top, _R1_point below
    try t.swap();

    // Decompose both points and do affine addition
    try decomposePoint(t, "_R1_point", "px", "py");
    try decomposePoint(t, "_R2_point", "qx", "qy");

    try affineAdd(t, p_be);

    // Step 8: x_R mod n == r
    try t.toTop("ry");
    try t.drop();

    try groupMod(t, "rx", n_be, "_rx_mod_n");

    // Restore r
    try t.fromAlt("_r_save");

    // Compare
    try t.toTop("_rx_mod_n");
    try t.toTop("_r_save");
    t.popNames(2);
    try t.emitOpcode("OP_EQUAL");
    try t.names.append(t.allocator, "_result");

}

// ===========================================================================
// Public API — build EcOpBundle for each builtin
// ===========================================================================

pub fn buildBuiltinOps(allocator: Allocator, builtin: registry.CryptoBuiltin) !EcOpBundle {
    switch (builtin) {
        .verify_ecdsa_p256 => {
            var t = try NistTracker.init(allocator, &.{ "_msg", "_sig", "_pk" }, &p256_params);
            errdefer t.deinit();
            try emitVerifyECDSA(&t);
            return t.takeBundle();
        },
        .p256_add => {
            var t = try NistTracker.init(allocator, &.{ "_pa", "_pb" }, &p256_params);
            errdefer t.deinit();
            try decomposePoint(&t, "_pa", "px", "py");
            try decomposePoint(&t, "_pb", "qx", "qy");
            try affineAdd(&t, p256_field_p_be[0..]);
            try composePoint(&t, "rx", "ry", "_result");
            return t.takeBundle();
        },
        .p256_mul => {
            var t = try NistTracker.init(allocator, &.{ "_pt", "_k" }, &p256_params);
            errdefer t.deinit();
            try emitScalarMulOnTracker(&t);
            return t.takeBundle();
        },
        .p256_mul_gen => {
            var t = try NistTracker.init(allocator, &.{"_k"}, &p256_params);
            errdefer t.deinit();
            const g_point = try allocator.alloc(u8, 64);
            @memcpy(g_point[0..32], p256_gx_be[0..]);
            @memcpy(g_point[32..64], p256_gy_be[0..]);
            try t.pushOwnedBytes("_pt", g_point);
            try t.swap();
            try emitScalarMulOnTracker(&t);
            return t.takeBundle();
        },
        .p256_negate => {
            var t = try NistTracker.init(allocator, &.{"_pt"}, &p256_params);
            errdefer t.deinit();
            try decomposePoint(&t, "_pt", "_nx", "_ny");
            try t.pushBigIntBE("_fp", p256_field_p_be[0..]);
            try fieldSub(&t, "_fp", "_ny", p256_field_p_be[0..], "_neg_y");
            try composePoint(&t, "_nx", "_neg_y", "_result");
            return t.takeBundle();
        },
        .p256_on_curve => {
            var t = try NistTracker.init(allocator, &.{"_pt"}, &p256_params);
            errdefer t.deinit();
            try decomposePoint(&t, "_pt", "_x", "_y");
            try fieldSqr(&t, "_y", p256_field_p_be[0..], "_y2");
            try t.copyToTop("_x", "_x_copy");
            try t.copyToTop("_x", "_x_copy2");
            try fieldSqr(&t, "_x", p256_field_p_be[0..], "_x2");
            try fieldMul(&t, "_x2", "_x_copy", p256_field_p_be[0..], "_x3");
            try fieldMulConst(&t, "_x_copy2", 3, p256_field_p_be[0..], "_3x");
            try fieldSub(&t, "_x3", "_3x", p256_field_p_be[0..], "_x3m3x");
            try t.pushBigIntBE("_b", p256_b_be[0..]);
            try fieldAdd(&t, "_x3m3x", "_b", p256_field_p_be[0..], "_rhs");
            try t.toTop("_y2");
            try t.toTop("_rhs");
            t.popNames(2);
            try t.emitOpcode("OP_EQUAL");
            try t.names.append(t.allocator, "_result");
            return t.takeBundle();
        },
        .p256_encode_compressed => {
            var t = try NistTracker.init(allocator, &.{"_pt"}, &p256_params);
            errdefer t.deinit();
            // Split at 32: [x_bytes, y_bytes]
            try t.toTop("_pt");
            t.popNames(1);
            try t.emitPushInt(32);
            try t.emitOpcode("OP_SPLIT");
            try t.names.append(t.allocator, "_x_bytes");
            try t.names.append(t.allocator, "_y_bytes");
            // Get last byte of y for parity
            try t.toTop("_y_bytes");
            t.popNames(1);
            try t.emitOpcode("OP_SIZE");
            try t.emitPushInt(1);
            try t.emitOpcode("OP_SUB");
            try t.emitOpcode("OP_SPLIT");
            try t.names.append(t.allocator, "_y_prefix");
            try t.names.append(t.allocator, "_last_byte");
            // Parity
            try t.toTop("_last_byte");
            t.popNames(1);
            try t.emitOpcode("OP_BIN2NUM");
            try t.emitPushInt(2);
            try t.emitOpcode("OP_MOD");
            try t.names.append(t.allocator, "_parity");
            try t.toTop("_y_prefix");
            try t.drop();
            // [x_bytes, parity]
            const then_ops = try t.allocator.dupe(StackOp, &.{StackOp{ .push = .{ .bytes = &.{0x03} } }});
            errdefer t.allocator.free(then_ops);
            const else_ops = try t.allocator.dupe(StackOp, &.{StackOp{ .push = .{ .bytes = &.{0x02} } }});
            errdefer t.allocator.free(else_ops);
            try t.toTop("_parity");
            t.popNames(1);
            try t.emitRaw(.{ .@"if" = .{ .then = then_ops, .@"else" = else_ops } });
            try t.names.append(t.allocator, "_prefix");
            // [x_bytes, prefix] -> swap -> prefix || x_bytes
            try t.swap();
            t.popNames(2);
            try t.emitOpcode("OP_CAT");
            try t.names.append(t.allocator, "_result");
            return t.takeBundle();
        },
        // P-384
        .verify_ecdsa_p384 => {
            var t = try NistTracker.init(allocator, &.{ "_msg", "_sig", "_pk" }, &p384_params);
            errdefer t.deinit();
            try emitVerifyECDSA(&t);
            return t.takeBundle();
        },
        .p384_add => {
            var t = try NistTracker.init(allocator, &.{ "_pa", "_pb" }, &p384_params);
            errdefer t.deinit();
            try decomposePoint(&t, "_pa", "px", "py");
            try decomposePoint(&t, "_pb", "qx", "qy");
            try affineAdd(&t, p384_field_p_be[0..]);
            try composePoint(&t, "rx", "ry", "_result");
            return t.takeBundle();
        },
        .p384_mul => {
            var t = try NistTracker.init(allocator, &.{ "_pt", "_k" }, &p384_params);
            errdefer t.deinit();
            try emitScalarMulOnTracker(&t);
            return t.takeBundle();
        },
        .p384_mul_gen => {
            var t = try NistTracker.init(allocator, &.{"_k"}, &p384_params);
            errdefer t.deinit();
            const g_point = try allocator.alloc(u8, 96);
            @memcpy(g_point[0..48], p384_gx_be[0..]);
            @memcpy(g_point[48..96], p384_gy_be[0..]);
            try t.pushOwnedBytes("_pt", g_point);
            try t.swap();
            try emitScalarMulOnTracker(&t);
            return t.takeBundle();
        },
        .p384_negate => {
            var t = try NistTracker.init(allocator, &.{"_pt"}, &p384_params);
            errdefer t.deinit();
            try decomposePoint(&t, "_pt", "_nx", "_ny");
            try t.pushBigIntBE("_fp", p384_field_p_be[0..]);
            try fieldSub(&t, "_fp", "_ny", p384_field_p_be[0..], "_neg_y");
            try composePoint(&t, "_nx", "_neg_y", "_result");
            return t.takeBundle();
        },
        .p384_on_curve => {
            var t = try NistTracker.init(allocator, &.{"_pt"}, &p384_params);
            errdefer t.deinit();
            try decomposePoint(&t, "_pt", "_x", "_y");
            try fieldSqr(&t, "_y", p384_field_p_be[0..], "_y2");
            try t.copyToTop("_x", "_x_copy");
            try t.copyToTop("_x", "_x_copy2");
            try fieldSqr(&t, "_x", p384_field_p_be[0..], "_x2");
            try fieldMul(&t, "_x2", "_x_copy", p384_field_p_be[0..], "_x3");
            try fieldMulConst(&t, "_x_copy2", 3, p384_field_p_be[0..], "_3x");
            try fieldSub(&t, "_x3", "_3x", p384_field_p_be[0..], "_x3m3x");
            try t.pushBigIntBE("_b", p384_b_be[0..]);
            try fieldAdd(&t, "_x3m3x", "_b", p384_field_p_be[0..], "_rhs");
            try t.toTop("_y2");
            try t.toTop("_rhs");
            t.popNames(2);
            try t.emitOpcode("OP_EQUAL");
            try t.names.append(t.allocator, "_result");
            return t.takeBundle();
        },
        .p384_encode_compressed => {
            var t = try NistTracker.init(allocator, &.{"_pt"}, &p384_params);
            errdefer t.deinit();
            // Split at 48: [x_bytes, y_bytes]
            try t.toTop("_pt");
            t.popNames(1);
            try t.emitPushInt(48);
            try t.emitOpcode("OP_SPLIT");
            try t.names.append(t.allocator, "_x_bytes");
            try t.names.append(t.allocator, "_y_bytes");
            // Get last byte of y for parity
            try t.toTop("_y_bytes");
            t.popNames(1);
            try t.emitOpcode("OP_SIZE");
            try t.emitPushInt(1);
            try t.emitOpcode("OP_SUB");
            try t.emitOpcode("OP_SPLIT");
            try t.names.append(t.allocator, "_y_prefix");
            try t.names.append(t.allocator, "_last_byte");
            // Parity
            try t.toTop("_last_byte");
            t.popNames(1);
            try t.emitOpcode("OP_BIN2NUM");
            try t.emitPushInt(2);
            try t.emitOpcode("OP_MOD");
            try t.names.append(t.allocator, "_parity");
            try t.toTop("_y_prefix");
            try t.drop();
            // [x_bytes, parity]
            const then_ops = try t.allocator.dupe(StackOp, &.{StackOp{ .push = .{ .bytes = &.{0x03} } }});
            errdefer t.allocator.free(then_ops);
            const else_ops = try t.allocator.dupe(StackOp, &.{StackOp{ .push = .{ .bytes = &.{0x02} } }});
            errdefer t.allocator.free(else_ops);
            try t.toTop("_parity");
            t.popNames(1);
            try t.emitRaw(.{ .@"if" = .{ .then = then_ops, .@"else" = else_ops } });
            try t.names.append(t.allocator, "_prefix");
            // [x_bytes, prefix] -> swap -> prefix || x_bytes
            try t.swap();
            t.popNames(2);
            try t.emitOpcode("OP_CAT");
            try t.names.append(t.allocator, "_result");
            return t.takeBundle();
        },
        else => return error.UnsupportedBuiltin,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

test "nist_ec_emitters: P-256 add emits ops" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .p256_add);
    defer bundle.deinit();
    try std.testing.expect(bundle.ops.len > 0);
}

test "nist_ec_emitters: P-256 on_curve emits ops" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .p256_on_curve);
    defer bundle.deinit();
    try std.testing.expect(bundle.ops.len > 0);
}

test "nist_ec_emitters: P-256 encode_compressed emits ops" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .p256_encode_compressed);
    defer bundle.deinit();
    try std.testing.expect(bundle.ops.len > 0);
}

test "nist_ec_emitters: P-384 add emits ops" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .p384_add);
    defer bundle.deinit();
    try std.testing.expect(bundle.ops.len > 0);
}

test "nist_ec_emitters: P-384 negate emits ops" {
    var bundle = try buildBuiltinOps(std.testing.allocator, .p384_negate);
    defer bundle.deinit();
    try std.testing.expect(bundle.ops.len > 0);
}

test "nist_ec_emitters: beToUnsignedScriptNumAlloc" {
    const allocator = std.testing.allocator;

    // All zeros -> empty
    const zero = try beToUnsignedScriptNumAlloc(allocator, &.{ 0x00, 0x00 });
    defer allocator.free(zero);
    try std.testing.expectEqual(@as(usize, 0), zero.len);

    // 0x01 -> 0x01 (no sign byte needed)
    const one = try beToUnsignedScriptNumAlloc(allocator, &.{0x01});
    defer allocator.free(one);
    try std.testing.expectEqual(@as(usize, 1), one.len);
    try std.testing.expectEqual(@as(u8, 0x01), one[0]);

    // 0xFF -> 0xFF 0x00 (needs sign byte)
    const ff = try beToUnsignedScriptNumAlloc(allocator, &.{0xff});
    defer allocator.free(ff);
    try std.testing.expectEqual(@as(usize, 2), ff.len);
    try std.testing.expectEqual(@as(u8, 0xff), ff[0]);
    try std.testing.expectEqual(@as(u8, 0x00), ff[1]);
}

test "nist_ec_emitters: getBit" {
    // 0x01 has bit 0 set
    try std.testing.expectEqual(@as(u1, 1), getBit(&.{0x01}, 0));
    try std.testing.expectEqual(@as(u1, 0), getBit(&.{0x01}, 1));

    // 0x02 has bit 1 set
    try std.testing.expectEqual(@as(u1, 0), getBit(&.{0x02}, 0));
    try std.testing.expectEqual(@as(u1, 1), getBit(&.{0x02}, 1));

    // Multi-byte: 0x01 0x00 -> bit 8 set
    try std.testing.expectEqual(@as(u1, 1), getBit(&.{ 0x01, 0x00 }, 8));
    try std.testing.expectEqual(@as(u1, 0), getBit(&.{ 0x01, 0x00 }, 0));
}
