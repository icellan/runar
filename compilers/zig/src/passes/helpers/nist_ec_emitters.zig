//! NIST P-256 and P-384 elliptic curve codegen for Bitcoin Script.
//!
//! Follows the same pattern as ec_emitters.zig and bn254_emitters.zig, and
//! shares that module's `ECTracker` — including its sign lattice — rather than
//! keeping a second copy. See the tracker section below for why.
//!
//! Point representation:
//!   P-256: 64 bytes (x[32] || y[32], big-endian unsigned)
//!   P-384: 96 bytes (x[48] || y[48], big-endian unsigned)
//!
//! Key difference from secp256k1: a = -3 (not 0), giving an optimized
//! Jacobian doubling formula.
//!
//! The three EXPERIMENTAL size flags (`EcCodegenOptions`) are honoured here as
//! they are for secp256k1: an all-false value leaves every emitter byte-
//! identical to what this tier shipped before they existed.

const std = @import("std");
const ec = @import("ec_emitters.zig");
const comb = @import("comb.zig");
const registry = @import("crypto_builtins.zig");

const Allocator = std.mem.Allocator;
const StackOp = ec.StackOp;
const StackIf = ec.StackIf;
const PushValue = ec.PushValue;
const EcOpBundle = ec.EcOpBundle;
const Dom = ec.Dom;
const EcCodegenOptions = ec.EcCodegenOptions;
const POOL_FIELD_P = ec.POOL_FIELD_P;
const POOL_GROUP_N = ec.POOL_GROUP_N;

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
    0xbf, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
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

/// Shared with `ec_emitters.zig` rather than reimplemented: a second encoder
/// free to drift is a second spelling of the same constant, and the pool prices
/// call sites off the length this returns.
const beToUnsignedScriptNumAlloc = ec.beToUnsignedScriptNumAlloc;

/// Length of `be`'s unsigned script-number encoding, without allocating.
///
/// `cheapSubPays` prices the prime before anything is emitted, and the pool's
/// cheaper-of-two comparison must be exact or it could make a call site bigger.
fn scriptNumLen(be: []const u8) usize {
    var first: usize = 0;
    while (first < be.len and be[first] == 0) : (first += 1) {}
    if (first == be.len) return 0;
    const trimmed = be[first..];
    return trimmed.len + @as(usize, if ((trimmed[0] & 0x80) != 0) 1 else 0);
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
    /// The same curve for `comb.zig`'s compile-time table. Kept here so the
    /// fixed-base comb can never be handed a curve whose field prime disagrees
    /// with the one the emitted reductions use — that would build a table of
    /// points on a DIFFERENT curve, which this curve's on-curve check would
    /// happily accept.
    comb_curve: comb.Curve,
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
    .comb_curve = comb.P256_COMB_CURVE,
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
    .comb_curve = comb.P384_COMB_CURVE,
};

// ===========================================================================
// Tracker — shared with ec_emitters.zig
// ===========================================================================

/// The NIST emitters run on `ec_emitters.ECTracker`, the same tracker the
/// secp256k1 ones use. They kept a private copy of it until the size flags
/// landed; the copy carried no sign lattice, and adding a second one would have
/// been two chances to prove `.reduced` where only `.non_negative` holds — a
/// script that is smaller, passes every local test, and is wrong on an
/// adversarial coordinate.
///
/// The curve-specific state that copy carried (`params`) is a function
/// parameter here instead. Nothing about a tracker is per-curve: the prime, the
/// order and the coordinate width all reach the emitters through the call, and
/// one emitter only ever works on one curve.
const NistTracker = ec.ECTracker;

/// Push a positive big-endian constant as a script number.
///
/// The reference spells this `t.pushInt(name, value)`, and the `.non_negative`
/// fact that comes with a positive literal there is load-bearing: it is what
/// lets `fieldAdd(x^3 - 3x, b)` take the short reduction. Arriving as a byte
/// slice it would otherwise be `.unknown` — see `ECTracker.poolConstant`.
fn pushBigIntBE(t: *NistTracker, name: []const u8, be: []const u8) !void {
    const encoded = try beToUnsignedScriptNumAlloc(t.allocator, be);
    try t.pushOwnedBytes(name, encoded);
    t.setDomain(name, .non_negative);
}

/// The field prime, from the pooled slot when that is cheaper.
fn pushFieldP(t: *NistTracker, name: []const u8, p_be: []const u8) !void {
    try t.pushConst(POOL_FIELD_P, p_be, name);
}

/// The group order, from the pooled slot when that is cheaper.
fn pushGroupN(t: *NistTracker, name: []const u8, n_be: []const u8) !void {
    try t.pushConst(POOL_GROUP_N, n_be, name);
}

// `rawBlock` takes a plain function pointer, not a closure, so every body it
// can run has to be a fixed sequence with its operands already on the stack.
// These are those bodies; anything parameterised (the byte reversals, the
// width-dependent splits) does its own popNames / emit / pushTracked instead.

fn emitAddOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_ADD");
}

fn emitSubOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_SUB");
}

fn emitMulOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_MUL");
}

fn emitModOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_MOD");
}

fn emit2DivOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_2DIV");
}

fn emitRshiftnumOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_RSHIFTNUM");
}

fn emitNumEqualOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_NUMEQUAL");
}

fn emit0NotEqualOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_0NOTEQUAL");
}

fn emitModSequence(t: *NistTracker) !void {
    try t.emitOpcode("OP_2DUP");
    try t.emitOpcode("OP_MOD");
    try t.emitRaw(.{ .rot = {} });
    try t.emitRaw(.{ .drop = {} });
    try t.emitRaw(.{ .over = {} });
    try t.emitOpcode("OP_ADD");
    try t.emitRaw(.{ .swap = {} });
    try t.emitOpcode("OP_MOD");
}

// ===========================================================================
// Byte reversal emitters (for coord_bytes = 32 or 48)
// ===========================================================================

fn emitReverseN(t: *NistTracker, n: usize) !void {
    try t.emitOpcode("OP_0");
    try t.emitRaw(.{ .swap = {} });
    for (0..n) |_| {
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
    try t.emitPushIntRaw(n_plus_1);
    try t.emitOpcode("OP_NUM2BIN");
    try t.emitPushIntRaw(@as(i64, @intCast(coord_bytes)));
    try t.emitOpcode("OP_SPLIT");
    try t.emitRaw(.{ .drop = {} });
    try emitReverseN(t, coord_bytes);
}

// ===========================================================================
// Point decompose / compose
// ===========================================================================

fn decomposePoint(
    t: *NistTracker,
    c: *const NistCurveParams,
    point_name: []const u8,
    x_name: []const u8,
    y_name: []const u8,
) !void {
    const cb = c.coord_bytes;
    try t.toTop(point_name);
    t.popNames(1);
    try t.emitPushIntRaw(@intCast(cb));
    try t.emitOpcode("OP_SPLIT");
    try t.pushTracked("_dp_xb", .unknown);
    try t.pushTracked("_dp_yb", .unknown);

    // Convert y_bytes (on top) to num
    try t.toTop("_dp_yb");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, cb);
    try t.pushTracked(y_name, .unknown);
    // A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
    // UNSIGNED: >= 0, but it may be up to 2^(8*cb) - 1 and therefore >= p. That
    // gap is exactly what the subtraction precondition turns on — recording
    // `.reduced` here would make `p256Add((0,1), (2^256-1,1))` wrong by exactly
    // 2^256 - p while passing every ordinary test.
    t.setDomain(y_name, .non_negative);

    // Convert x_bytes to num
    try t.toTop("_dp_xb");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, cb);
    try t.pushTracked(x_name, .unknown);
    t.setDomain(x_name, .non_negative);

    try t.swap();
}

fn composePoint(
    t: *NistTracker,
    c: *const NistCurveParams,
    x_name: []const u8,
    y_name: []const u8,
    result_name: []const u8,
) !void {
    const cb = c.coord_bytes;

    try t.toTop(x_name);
    t.popNames(1);
    try emitUnsignedNumToBeBytes(t, cb);
    try t.pushTracked("_cp_xb", .unknown);

    try t.toTop(y_name);
    t.popNames(1);
    try emitUnsignedNumToBeBytes(t, cb);
    try t.pushTracked("_cp_yb", .unknown);

    try t.toTop("_cp_xb");
    try t.toTop("_cp_yb");
    t.popNames(2);
    try t.emitOpcode("OP_CAT");
    try t.pushTracked(result_name, .unknown);
}

// ===========================================================================
// Field arithmetic (parameterized by the field prime)
// ===========================================================================

/// `a mod p` with no sign fix-up: 1 opcode instead of 7.
///
/// Sound only when the dividend is provably >= 0, because `OP_MOD` takes the
/// sign of the dividend. The caller proves that; this function does not check.
fn fieldModShort(t: *NistTracker, a_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try pushFieldP(t, "_fmods_p", p_be);
    try t.rawBlock(2, result_name, emitModOpcode);
    t.setDomain(result_name, .reduced);
}

/// Does the cheap `a - b + p` subtraction shape pay here?
///
/// It references the prime TWICE where the shipping shape references it once and
/// pays six more opcodes, so it only wins when the prime is cheap to materialise
/// — i.e. when it is pooled. Without a pool the rewrite makes the script LARGER,
/// which is why it is a cost comparison and not a flag.
fn cheapSubPays(t: *const NistTracker, p_be: []const u8) bool {
    const c = t.constCost(POOL_FIELD_P, scriptNumLen(p_be));
    return 2 * c + 2 < c + 8;
}

fn fieldMod(t: *NistTracker, a_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    if (t.opts.reduction_sinking and t.domainOf(a_name).isNonNegative()) {
        try fieldModShort(t, a_name, p_be, result_name);
        return;
    }
    try t.toTop(a_name);
    try pushFieldP(t, "_fmod_p", p_be);
    try t.rawBlock(2, result_name, emitModSequence);
    t.setDomain(result_name, .reduced);
}

fn fieldAdd(t: *NistTracker, a_name: []const u8, b_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    // Read the operand facts BEFORE rawBlock consumes their slots.
    const sum_non_neg = t.domainOf(a_name).isNonNegative() and t.domainOf(b_name).isNonNegative();
    try t.toTop(a_name);
    try t.toTop(b_name);
    try t.rawBlock(2, "_fadd_sum", emitAddOpcode);
    if (sum_non_neg) t.setDomain("_fadd_sum", .non_negative);
    try fieldMod(t, "_fadd_sum", p_be, result_name);
}

fn fieldSub(t: *NistTracker, a_name: []const u8, b_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    // The cheap shape needs a >= 0 AND b in [0, p): then a - b > -p, so a single
    // shifted reduction is exact. `b >= 0` alone is NOT enough — a coordinate
    // decoded from 32 / 48 unsigned bytes can exceed p, which is precisely the
    // `p256Add((0,1), (2^256-1,1))` counterexample.
    const cheap = t.opts.reduction_sinking and
        t.domainOf(a_name).isNonNegative() and
        t.domainOf(b_name) == .reduced and
        cheapSubPays(t, p_be);

    try t.rawBlock(2, "_fsub_diff", emitSubOpcode);

    if (cheap) {
        try pushFieldP(t, "_fsub_p", p_be);
        try t.rawBlock(2, "_fsub_shift", emitAddOpcode);
        t.setDomain("_fsub_shift", .non_negative);
        try fieldModShort(t, "_fsub_shift", p_be, result_name);
        return;
    }
    try fieldMod(t, "_fsub_diff", p_be, result_name);
}

fn fieldMul(t: *NistTracker, a_name: []const u8, b_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try fieldMulSigned(t, a_name, b_name, p_be, result_name, false);
}

/// `fieldMul` with an explicit assertion about the product's sign, independent
/// of the operands — `fieldSqr` uses it, since a*a >= 0 for any a whatsoever.
fn fieldMulSigned(
    t: *NistTracker,
    a_name: []const u8,
    b_name: []const u8,
    p_be: []const u8,
    result_name: []const u8,
    product_non_negative: bool,
) !void {
    const non_neg = product_non_negative or
        (t.domainOf(a_name).isNonNegative() and t.domainOf(b_name).isNonNegative());
    try t.toTop(a_name);
    try t.toTop(b_name);
    try t.rawBlock(2, "_fmul_prod", emitMulOpcode);
    if (non_neg) t.setDomain("_fmul_prod", .non_negative);
    try fieldMod(t, "_fmul_prod", p_be, result_name);
}

/// `(a * a) mod p`. A square is non-negative whatever a's sign is.
fn fieldSqr(t: *NistTracker, a_name: []const u8, p_be: []const u8, result_name: []const u8) !void {
    try t.copyToTop(a_name, "_fsqr_copy");
    try fieldMulSigned(t, a_name, "_fsqr_copy", p_be, result_name, true);
}

fn emit2MulOpcode(t: *NistTracker) !void {
    try t.emitOpcode("OP_2MUL");
}

fn fieldMulConst(t: *NistTracker, a_name: []const u8, c: i64, p_be: []const u8, result_name: []const u8) !void {
    // Every call site passes a small positive c, so the product keeps a's sign.
    const non_neg = c > 0 and t.domainOf(a_name).isNonNegative();
    try t.toTop(a_name);
    if (c == 2) {
        try t.rawBlock(1, "_fmc_prod", emit2MulOpcode);
    } else {
        try t.pushInt("_fmc_c", c);
        try t.rawBlock(2, "_fmc_prod", emitMulOpcode);
    }
    if (non_neg) t.setDomain("_fmc_prod", .non_negative);
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

/// `((a mod n) + n) mod n`, always in the long form.
///
/// Deliberately NOT sunk the way `fieldMod` is. The lattice tracks values
/// against the FIELD prime, and the pool's `.reduced` fact means "in [0, p)" —
/// which says nothing about [0, n). Reusing the short form here would be
/// proving a bound about the wrong modulus; the scalar reduce that gates the
/// ladder's whole interval argument runs through this function.
fn groupMod(t: *NistTracker, a_name: []const u8, n_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try pushGroupN(t, "_gmod_n", n_be);
    try t.rawBlock(2, result_name, emitModSequence);
}

fn groupMul(t: *NistTracker, a_name: []const u8, b_name: []const u8, n_be: []const u8, result_name: []const u8) !void {
    try t.toTop(a_name);
    try t.toTop(b_name);
    try t.rawBlock(2, "_gmul_prod", emitMulOpcode);
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

/// GAP-301: coordinate canonicity, leaving "_canon" on the tracker.
///
/// decomposePoint BIN2NUMs each coordinate as an unsigned value that may be
/// >= p; the curve equation reduces it mod p, so (x + p)||y would pass as a
/// point it is not the canonical encoding of. Reject it: require x < p AND
/// y < p (coordinates are unsigned, so the 0 <= bound holds by construction).
/// The caller ANDs "_canon" into its result so the check still returns a
/// boolean. This mirrors secp256k1's emitEcOnCurve, whose guard the a = -3
/// curves never received — leaving pNNNOnCurve accepting inputs ecOnCurve
/// rejects even though both are documented as THE gate for untrusted points.
fn emitCanonicityGuard(t: *NistTracker, x_name: []const u8, y_name: []const u8, p_be: []const u8) !void {
    try t.copyToTop(x_name, "_x_lt");
    try pushFieldP(t, "_p_for_x", p_be);
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.pushTracked("_x_canon", .unknown);
    try t.copyToTop(y_name, "_y_lt");
    try pushFieldP(t, "_p_for_y", p_be);
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.pushTracked("_y_canon", .unknown);
    try t.toTop("_x_canon");
    try t.toTop("_y_canon");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_canon", .unknown);
}

/// Affine point addition.
///
/// The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
/// denominator is zero and the correct slope is the TANGENT, (3px^2 + a)/(2py)
/// — and a = -3 on both NIST curves, so the numerator is 3px^2 - 3. The
/// secp256k1 fix (a = 0) was never ported here, so p256Add(P, P) and
/// p384Add(P, P) produced a wrong point and every contract that doubled
/// deployed an unspendable script.
///
/// Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR are
/// selected and the single expensive fieldInv still runs exactly once.
/// rx and ry below are already correct for doubling.
///
///   cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
///   num    = cond ? 3*px^2 - 3 : (qy - py)
///   den    = cond ? 2*py       : (qx - px)
///
/// selected as `b + cond*(a - b)`, which needs no branch and keeps the emitted
/// op sequence identical on both paths.
///
/// THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
/// sends it down the tangent path and returns 2P — an on-curve, entirely
/// plausible, WRONG point, which is strictly worse than the pre-fix chord
/// path: that one divided by zero (fieldInv is Fermat, inv(0) = 0) and
/// produced an OFF-curve blob, so `assert(pNNNOnCurve(pNNNAdd(a, b)))` — the
/// idiom examples/ts/p384-primitives writes verbatim — rejected it.
///
/// P + (-P) is the point at infinity, which affine x||y cannot represent. This
/// codegen already has a representation for O: the ALL-ZERO blob, which is
/// what `pNNNMul(P, 0n)` returns. So return that, by masking the result with
/// `notinf = NOT(px == qx AND NOT cond)`. O is not on the curve (0^2 != b),
/// so the on-curve gate rejects it and the idiom works again; and it adds no
/// failure channel to a pure value-producing expression, the same reason the
/// scalar reduce in emitScalarMulOnTracker reduces instead of rejecting.
///
/// The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
/// and notinf is 0 or 1, so the product is canonical either way.
fn affineAdd(t: *NistTracker, c: *const NistCurveParams) !void {
    const p_be = c.field_p_be;
    try t.copyToTop("px", "_px_eq");
    try t.copyToTop("qx", "_qx_eq");
    t.popNames(2);
    try t.emitOpcode("OP_NUMEQUAL");
    try t.pushTracked("_xeq", .unknown);

    try t.copyToTop("py", "_py_eq");
    try t.copyToTop("qy", "_qy_eq");
    t.popNames(2);
    try t.emitOpcode("OP_NUMEQUAL");
    try t.pushTracked("_yeq", .unknown);

    try t.copyToTop("_xeq", "_xeq_c");
    try t.toTop("_yeq");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_cond", .unknown);

    // notinf = NOT(xeq - cond): 1 exactly when px == qx and the points differ.
    try t.toTop("_xeq");
    try t.copyToTop("_cond", "_cond_c");
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.emitOpcode("OP_NOT");
    try t.pushTracked("_notinf", .unknown);

    // chord numerator / denominator
    try t.copyToTop("qy", "_qy1");
    try t.copyToTop("py", "_py1");
    try fieldSub(t, "_qy1", "_py1", p_be, "_num_chord");
    try t.copyToTop("qx", "_qx1");
    try t.copyToTop("px", "_px1");
    try fieldSub(t, "_qx1", "_px1", p_be, "_den_chord");

    // tangent numerator / denominator: 3*px^2 + a (a = -3) and 2*py
    try t.copyToTop("px", "_px_t");
    try fieldSqr(t, "_px_t", p_be, "_px_sq");
    try fieldMulConst(t, "_px_sq", 3, p_be, "_3px_sq");
    try t.pushInt("_a_neg", 3);
    try fieldSub(t, "_3px_sq", "_a_neg", p_be, "_num_tan");
    try t.copyToTop("py", "_py_t");
    try fieldMulConst(t, "_py_t", 2, p_be, "_den_tan");

    // num = num_chord + cond*(num_tan - num_chord)
    try t.copyToTop("_num_chord", "_num_chord_c");
    try fieldSub(t, "_num_tan", "_num_chord_c", p_be, "_num_diff");
    try t.copyToTop("_cond", "_cond_n");
    try fieldMul(t, "_num_diff", "_cond_n", p_be, "_num_sel");
    try fieldAdd(t, "_num_chord", "_num_sel", p_be, "_s_num");

    // den = den_chord + cond*(den_tan - den_chord)
    try t.copyToTop("_den_chord", "_den_chord_c");
    try fieldSub(t, "_den_tan", "_den_chord_c", p_be, "_den_diff");
    try t.toTop("_cond");
    t.renameTop("_cond_d");
    try fieldMul(t, "_den_diff", "_cond_d", p_be, "_den_sel");
    try fieldAdd(t, "_den_chord", "_den_sel", p_be, "_s_den");

    try fieldInv(t, "_s_den", c.field_p_minus_2_be, p_be, "_s_den_inv");
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

    // P == -Q -> force the all-zero point (see the header comment).
    try t.toTop("rx");
    try t.copyToTop("_notinf", "_notinf_x");
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.pushTracked("rx", .unknown);
    try t.toTop("ry");
    try t.toTop("_notinf");
    t.popNames(2);
    try t.emitOpcode("OP_MUL");
    try t.pushTracked("ry", .unknown);
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

fn buildJacobianAddAffineInline(
    allocator: Allocator,
    base_names: []const ?[]const u8,
    params: *const NistCurveParams,
    opts: EcCodegenOptions,
    base_doms: []const Dom,
) !EcOpBundle {
    // The inner tracker inherits the stack state AND the lattice facts: the
    // operands' proved domains are what decide which reduction shape the body
    // emits, so dropping them here would silently fall back everywhere.
    var inner = try NistTracker.initOpts(allocator, base_names, opts, base_doms);
    errdefer inner.deinit();

    try jacobianAddAffineBody(&inner, params, false);
    return inner.takeBundle();
}

/// The mixed-add itself, emitting through a tracker the caller owns.
///
/// `keep_hr` additionally leaves copies of H and R on the stack: both are zero
/// exactly when the Jacobian accumulator is the same curve point as the affine
/// operand, the one case these formulas cannot compute. See
/// buildJacobianAddOrDoubleInline.
fn jacobianAddAffineBody(inner: *NistTracker, c: *const NistCurveParams, keep_hr: bool) !void {
    const p_be = c.field_p_be;

    try inner.copyToTop("jz", "_jz_for_z1cu");
    try inner.copyToTop("jz", "_jz_for_z3");
    try inner.copyToTop("jy", "_jy_for_y3");
    try inner.copyToTop("jx", "_jx_for_u1h2");

    // Z1sq = jz^2
    try fieldSqr(inner, "jz", p_be, "_Z1sq");
    try inner.copyToTop("_Z1sq", "_Z1sq_for_u2");
    try fieldMul(inner, "_jz_for_z1cu", "_Z1sq", p_be, "_Z1cu");

    // U2 = ax * Z1sq_for_u2
    try inner.copyToTop("ax", "_ax_c");
    try fieldMul(inner, "_ax_c", "_Z1sq_for_u2", p_be, "_U2");

    // S2 = ay * Z1cu
    try inner.copyToTop("ay", "_ay_c");
    try fieldMul(inner, "_ay_c", "_Z1cu", p_be, "_S2");

    // H = U2 - jx
    try fieldSub(inner, "_U2", "jx", p_be, "_H");

    // R = S2 - jy
    try fieldSub(inner, "_S2", "jy", p_be, "_R");

    if (keep_hr) {
        try inner.copyToTop("_H", "_H_keep");
        try inner.copyToTop("_R", "_R_keep");
    }

    try inner.copyToTop("_H", "_H_for_h3");
    try inner.copyToTop("_H", "_H_for_z3");

    // H2 = H^2
    try fieldSqr(inner, "_H", p_be, "_H2");
    try inner.copyToTop("_H2", "_H2_for_u1h2");

    // H3 = H_for_h3 * H2
    try fieldMul(inner, "_H_for_h3", "_H2", p_be, "_H3");

    // U1H2 = _jx_for_u1h2 * H2_for_u1h2
    try fieldMul(inner, "_jx_for_u1h2", "_H2_for_u1h2", p_be, "_U1H2");

    try inner.copyToTop("_R", "_R_for_y3");
    try inner.copyToTop("_U1H2", "_U1H2_for_y3");
    try inner.copyToTop("_H3", "_H3_for_y3");

    // X3 = R^2 - H3 - 2*U1H2
    try fieldSqr(inner, "_R", p_be, "_R2");
    try fieldSub(inner, "_R2", "_H3", p_be, "_x3_tmp");
    try fieldMulConst(inner, "_U1H2", 2, p_be, "_2U1H2");
    try fieldSub(inner, "_x3_tmp", "_2U1H2", p_be, "_X3");

    // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    try inner.copyToTop("_X3", "_X3_c");
    try fieldSub(inner, "_U1H2_for_y3", "_X3_c", p_be, "_u_minus_x");
    try fieldMul(inner, "_R_for_y3", "_u_minus_x", p_be, "_r_tmp");
    try fieldMul(inner, "_jy_for_y3", "_H3_for_y3", p_be, "_jy_h3");
    try fieldSub(inner, "_r_tmp", "_jy_h3", p_be, "_Y3");

    // Z3 = _jz_for_z3 * _H_for_z3
    try fieldMul(inner, "_jz_for_z3", "_H_for_z3", p_be, "_Z3");

    try inner.toTop("_X3");
    inner.renameTop("jx");
    try inner.toTop("_Y3");
    inner.renameTop("jy");
    try inner.toTop("_Z3");
    inner.renameTop("jz");
}

/// Branchless select of one Jacobian coordinate: `add + cond*(dbl - add)`.
/// Consumes add_name, dbl_name and cond_name.
fn selectCoord(
    t: *NistTracker,
    c: *const NistCurveParams,
    add_name: []const u8,
    dbl_name: []const u8,
    cond_name: []const u8,
    result_name: []const u8,
) !void {
    const p_be = c.field_p_be;
    try t.copyToTop(add_name, "_sel_add_c");
    try fieldSub(t, dbl_name, "_sel_add_c", p_be, "_sel_diff");
    try fieldMul(t, "_sel_diff", cond_name, p_be, "_sel_scaled");
    try fieldAdd(t, add_name, "_sel_scaled", p_be, result_name);
}

/// The ladder's LAST conditional step: mixed-add, but correct when the
/// accumulator already equals the point being added.
///
/// The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
/// two operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at
/// infinity — and since fieldInv is Fermat (inv(0) = 0), jacobianToAffine turns
/// that into the ALL-ZERO point instead of 2P. p256Mul(P, 2n) and
/// p384Mul(P, 2n) returned 64 / 96 zero bytes.
///
/// WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
/// c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
/// (c_i - 1)*P. P-256 and P-384 both have cofactor 1, so P has order n and the
/// degenerate cases are exactly c_i == 2 (mod n) — accumulator == P — and
/// c_i == 0 or 1 (mod n) — accumulator == -P or O. c_i ranges over a
/// CONTIGUOUS interval determined only by i, so this is decidable by interval
/// arithmetic rather than by sampling, and over the whole domain k in [0, n-1]
/// only two steps qualify, both at i = 0:
///
///   k = 2  ->  c_0 = 3n+2 == 2, odd, so the add runs: accumulator == P. <- bug
///   k = 0  ->  c_0 = 3n   == 0, odd, so the add runs: accumulator == -P,
///              true result the point at infinity, which affine coordinates
///              cannot represent; it stays the all-zero point, as before.
///
/// At i >= 1, c_i lies in [3n>>i, (4n-1)>>i] — the lower bound is 3n, not 3n+1,
/// because the reduce puts k = 0 in the domain.
///
/// Handling H == 0 at every step would cost ~75% more script bytes — on P-384
/// that is another 600 KB; handling it here costs ~0.2%. The operand P is
/// caller-supplied but cannot move the exception, because the condition depends
/// only on c_i mod ord(P) and ord(P) = n for every point on these curves.
/// Points that are NOT on the curve carry no such guarantee — gate untrusted
/// input on p256OnCurve / p384OnCurve first. decompressPubKey now enforces that
/// itself for the one in-tree caller that takes a pubkey as input.
///
/// THE ENTIRE ARGUMENT IS CONDITIONED ON k in [0, n-1], which is only true
/// because emitScalarMulOnTracker reduces k mod n before adding 3n. That reduce
/// landed one commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON
/// ITS OWN IS UNSOUND: a last-step-only select while the scalar is still
/// unbounded leaves c_i free to hit 0, 1 or 2 (mod n) at other steps. The two
/// commits must land together and must never be bisected, cherry-picked or
/// reverted apart.
///
/// The interval argument does 100% of the work; there is no defence in depth
/// here. In particular c_i == 1 (mod n) — a pre-add accumulator of O — is
/// UNREACHABLE, not handled: were it reachable the select would still take the
/// ADD path, because O is carried as Z1 = 0, which makes U2 = 0 and
/// H = -X1 != 0. Anything that changes the +3n offset, the iteration count or
/// the reduce must redo the interval check, not assume this still holds.
///
/// Stack layout: [..., ax, ay, _k, jx, jy, jz] — same in and out.
fn buildJacobianAddOrDoubleInline(
    allocator: Allocator,
    base_names: []const ?[]const u8,
    params: *const NistCurveParams,
    opts: EcCodegenOptions,
    base_doms: []const Dom,
) !EcOpBundle {
    var inner = try NistTracker.initOpts(allocator, base_names, opts, base_doms);
    errdefer inner.deinit();

    const p_be = params.field_p_be;

    // Keep the pre-add accumulator: it is what must be DOUBLED in the
    // exceptional case, and the add below consumes jx/jy/jz.
    try inner.copyToTop("jx", "_sx");
    try inner.copyToTop("jy", "_sy");
    try inner.copyToTop("jz", "_sz");

    try jacobianAddAffineBody(&inner, params, true);

    // cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
    // accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
    // signals the point at infinity.
    try inner.toTop("_H_keep");
    try inner.pushInt("_zero_h", 0);
    inner.popNames(2);
    try inner.emitOpcode("OP_NUMEQUAL");
    try inner.pushTracked("_h_is0", .unknown);
    try inner.toTop("_R_keep");
    try inner.pushInt("_zero_r", 0);
    inner.popNames(2);
    try inner.emitOpcode("OP_NUMEQUAL");
    try inner.pushTracked("_r_is0", .unknown);
    try inner.toTop("_h_is0");
    try inner.toTop("_r_is0");
    inner.popNames(2);
    try inner.emitOpcode("OP_BOOLAND");
    try inner.pushTracked("_cond", .unknown);

    // Move the add result aside so jacobianDouble can work on jx/jy/jz again,
    // this time holding the saved accumulator.
    try inner.toTop("jx");
    inner.renameTop("_add_x");
    try inner.toTop("jy");
    inner.renameTop("_add_y");
    try inner.toTop("jz");
    inner.renameTop("_add_z");
    try inner.toTop("_sx");
    inner.renameTop("jx");
    try inner.toTop("_sy");
    inner.renameTop("jy");
    try inner.toTop("_sz");
    inner.renameTop("jz");
    try jacobianDouble(&inner, p_be);
    try inner.toTop("jx");
    inner.renameTop("_dbl_x");
    try inner.toTop("jy");
    inner.renameTop("_dbl_y");
    try inner.toTop("jz");
    inner.renameTop("_dbl_z");

    try inner.copyToTop("_cond", "_cond_x");
    try selectCoord(&inner, params, "_add_x", "_dbl_x", "_cond_x", "jx");
    try inner.copyToTop("_cond", "_cond_y");
    try selectCoord(&inner, params, "_add_y", "_dbl_y", "_cond_y", "jy");
    try inner.toTop("_cond");
    inner.renameTop("_cond_z");
    try selectCoord(&inner, params, "_add_z", "_dbl_z", "_cond_z", "jz");

    return inner.takeBundle();
}

// ===========================================================================
// Scalar multiplication (generic for P-256 and P-384)
// ===========================================================================

/// buildScalarMulBundle creates a standalone bundle for scalar multiplication.
/// Expects exactly two items on the stack: [point, scalar] (scalar on top).
/// Produces exactly one result item: the result point.
fn buildScalarMulBundle(
    allocator: Allocator,
    params: *const NistCurveParams,
    opts: EcCodegenOptions,
) !EcOpBundle {
    var t = try NistTracker.initOpts(allocator, &.{ "_pt", "_k" }, opts, null);
    errdefer t.deinit();
    try emitScalarMulOnTracker(&t, params);
    return t.takeBundle();
}

/// emitScalarMulOnTracker performs scalar mul using the tracker's current names.
/// The tracker must have "_pt" and "_k" as named items (in any position).
fn emitScalarMulOnTracker(t: *NistTracker, c: *const NistCurveParams) !void {
    const p_be = c.field_p_be;

    try t.poolConstant(POOL_FIELD_P, c.field_p_be);
    try t.poolConstant(POOL_GROUP_N, c.group_n_be);
    try decomposePoint(t, c, "_pt", "ax", "ay");

    // k' = k + 3n, PRE-FOLDED — on every path, including the pooled ones.
    //
    // The reference emits three literal `+n` steps (`cEmitMul`, raw `pushInt`
    // under every flag combination) and lets its peephole reassociate them back
    // to `push 3n; OP_ADD`. This tier's peephole folds only i64 `push_int`
    // chains (peephole.zig rule 27) and a 256/384-bit constant is a `push_data`
    // blob here, so three steps would SHIP 70 / 102 extra bytes rather than
    // collapsing. Same shipped bytes as the reference, different pre-peephole
    // spelling — which is why the Zig parity test allows exactly that delta on
    // exactly these emitters and zero everywhere else.
    //
    // Note this differs from the secp256k1 ladder next door: there the reference
    // uses POOLED pushes, so that tier emits three pooled steps and matches
    // raw-for-raw whenever the pool is on. Do not copy this shape there, or that
    // one here.
    //
    // The "k in [1, n-1]" precondition is one the caller cannot enforce — the
    // scalar is usually an unlock argument — so reduce it to [0, n-1] first.
    // groupMod IS ((k mod n) + n) mod n, which is exactly that.
    try t.toTop("_k");
    try groupMod(t, "_k", c.group_n_be, "_kr");
    if (t.opts.constant_pool) {
        // Three separate `+n` steps, each served from the pooled slot — the
        // shape the reference emits, and the shape `emitEcMul` already uses for
        // secp256k1 in this tier.
        //
        // The reference used to push three raw literals here, so pre-folding
        // `3n` made this tier 70 bytes SMALLER per P-256 ladder. It now pools
        // them (a pooled constant redeemed once was a strict loss for it), and
        // pre-folding would make this tier 26 bytes LARGER instead: one 34-byte
        // `push 3n` against three ~3-byte picks. Follow the reference.
        try pushGroupN(t, "_n", c.group_n_be);
        try t.rawBlock(2, "_kn", emitAddOpcode);
        try pushGroupN(t, "_n2", c.group_n_be);
        try t.rawBlock(2, "_kn2", emitAddOpcode);
        try pushGroupN(t, "_n3", c.group_n_be);
        try t.rawBlock(2, "_k", emitAddOpcode);
    } else {
        // Pre-folded `3n` on the DEFAULT path, and only there. With no pool to
        // draw from, the reference emits three literal pushes and lets its
        // peephole reassociate them; this tier's peephole folds only i64
        // `push_int` chains (peephole.zig rule 27) and a 256/384-bit constant is
        // a `push_data` blob here, so it pre-folds instead. Same shipped bytes,
        // different pre-peephole spelling — the divergence `allowedDelta` prices.
        try pushBigIntBE(t, "_3n", c.three_n_be);
        try t.rawBlock(2, "_k", emitAddOpcode);
    }

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
            try t.pushTracked("_shifted", .unknown);
        } else if (bit > 1) {
            try t.pushInt("_shift", bit);
            t.popNames(2);
            try t.emitOpcode("OP_RSHIFTNUM");
            try t.pushTracked("_shifted", .unknown);
        } else {
            t.renameTop("_shifted");
        }
        try t.pushInt("_two", 2);
        t.popNames(2);
        try t.emitOpcode("OP_MOD");
        try t.pushTracked("_bit", .unknown);

        // Conditional add
        try t.toTop("_bit");
        t.popNames(1);

        // Only the final step can be handed two equal operands — see
        // buildJacobianAddOrDoubleInline for why, and for what it costs not to.
        var add_bundle = if (bit == 0)
            try buildJacobianAddOrDoubleInline(t.allocator, t.names.items, c, t.opts, t.doms.items)
        else
            try buildJacobianAddAffineInline(t.allocator, t.names.items, c, t.opts, t.doms.items);
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

    try composePoint(t, c, "_rx", "_ry", "_result");
    try t.releaseConstant(POOL_GROUP_N);
    try t.releaseConstant(POOL_FIELD_P);
}

/// emitScalarMulInline emits scalar mul ops into `outer` tracker.
/// Before calling, the outer tracker must have pushed the point and scalar
/// (point then scalar, scalar on top) and removed their names via popNames(2).
/// After the call, one result name is appended to the outer tracker.
fn emitScalarMulInline(
    outer: *NistTracker,
    params: *const NistCurveParams,
    result_name: []const u8,
) !void {
    // The ladder runs on its OWN tracker seeded with just its two operands, so
    // it cannot see — and cannot pool against — anything the caller left below
    // them. That is why it pools its own copies of p and n.
    var bundle = try buildScalarMulBundle(outer.allocator, params, outer.opts);
    errdefer bundle.deinit();

    // Transfer owned_bytes pointers to outer tracker, then free the outer slice.
    try outer.owned_bytes.appendSlice(outer.allocator, bundle.owned_bytes);
    outer.allocator.free(bundle.owned_bytes);
    bundle.owned_bytes = &.{}; // prevent double-free in errdefer/deinit

    // Transfer ops to outer tracker, then free the outer slice.
    try outer.ops.appendSlice(outer.allocator, bundle.ops);
    outer.allocator.free(bundle.ops);
    bundle.ops = &.{}; // prevent double-free in errdefer/deinit

    try outer.pushTracked(result_name, .unknown);
}

// ===========================================================================
// Fixed-base comb (P-256 / P-384)
// ===========================================================================

/// Render a comb table coordinate as a `len`-byte big-endian buffer.
fn combCoordBeAlloc(allocator: Allocator, v: comb.Big, len: usize) ![]u8 {
    const out = try allocator.alloc(u8, len);
    var x = v;
    var i: usize = len;
    while (i > 0) {
        i -= 1;
        out[i] = @truncate(@as(u1024, @intCast(x)) & 0xff);
        x >>= 8;
    }
    return out;
}

/// Push a comb table coordinate as an unsigned script number.
fn pushCombCoord(t: *NistTracker, name: []const u8, v: comb.Big, len: usize) !void {
    const be = try combCoordBeAlloc(t.allocator, v, len);
    defer t.allocator.free(be);
    const encoded = try beToUnsignedScriptNumAlloc(t.allocator, be);
    try t.pushOwnedBytes(name, encoded);
}

/// Round `i`'s digit and the selected table entry, as `ax`/`ay`/`_flag`.
///
/// Exactly one equality holds, so `sum(eq_j * T_j)` is that entry's coordinate
/// and every term is non-negative and below p — no reduction is needed, and the
/// result is `.reduced` by construction. When the digit is zero every term
/// vanishes and `_flag` is 0, so no add runs.
fn combEmitSelect(t: *NistTracker, i: usize, w: usize, d: usize) !void {
    var buf: [24]u8 = undefined;
    const entries = (@as(usize, 1) << @intCast(w)) - 1;

    var b: usize = 0;
    while (b < w) : (b += 1) {
        const shift = i + b * d;
        const kc = try t.internName(try std.fmt.bufPrint(&buf, "_kc{d}", .{b}));
        const sh = try t.internName(try std.fmt.bufPrint(&buf, "_sh{d}", .{b}));
        try t.copyToTop("_k", kc);
        if (shift == 0) {
            t.renameTop(sh);
        } else if (shift == 1) {
            try t.rawBlock(1, sh, emit2DivOpcode);
        } else {
            const sd = try t.internName(try std.fmt.bufPrint(&buf, "_sd{d}", .{b}));
            try t.pushInt(sd, @intCast(shift));
            try t.rawBlock(2, sh, emitRshiftnumOpcode);
        }
        const two = try t.internName(try std.fmt.bufPrint(&buf, "_two{d}", .{b}));
        const bit = try t.internName(try std.fmt.bufPrint(&buf, "_b{d}", .{b}));
        try t.pushInt(two, 2);
        try t.rawBlock(2, bit, emitModOpcode);
        t.setDomain(bit, .reduced);
    }

    try t.toTop("_b0");
    t.renameTop("_idx");
    b = 1;
    while (b < w) : (b += 1) {
        const bit = try t.internName(try std.fmt.bufPrint(&buf, "_b{d}", .{b}));
        const wt = try t.internName(try std.fmt.bufPrint(&buf, "_wt{d}", .{b}));
        const bw = try t.internName(try std.fmt.bufPrint(&buf, "_bw{d}", .{b}));
        try t.toTop(bit);
        try t.pushInt(wt, @as(i64, 1) << @intCast(b));
        try t.rawBlock(2, bw, emitMulOpcode);
        try t.toTop("_idx");
        try t.rawBlock(2, "_idx", emitAddOpcode);
    }
    t.setDomain("_idx", .reduced);

    var j: usize = 1;
    while (j <= entries) : (j += 1) {
        const ic = try t.internName(try std.fmt.bufPrint(&buf, "_ic{d}", .{j}));
        const jv = try t.internName(try std.fmt.bufPrint(&buf, "_jv{d}", .{j}));
        const eq = try t.internName(try std.fmt.bufPrint(&buf, "_eq{d}", .{j}));
        try t.copyToTop("_idx", ic);
        try t.pushInt(jv, @intCast(j));
        try t.rawBlock(2, eq, emitNumEqualOpcode);
        t.setDomain(eq, .reduced);
    }

    for ([_][]const u8{ "x", "y" }) |coord| {
        const acc: []const u8 = if (coord[0] == 'x') "ax" else "ay";
        j = 1;
        while (j <= entries) : (j += 1) {
            const ec_n = try t.internName(try std.fmt.bufPrint(&buf, "_e{s}{d}", .{ coord, j }));
            const tc = try t.internName(try std.fmt.bufPrint(&buf, "_t{s}{d}", .{ coord, j }));
            const pr = try t.internName(try std.fmt.bufPrint(&buf, "_pr{s}{d}", .{ coord, j }));
            const eq = try t.internName(try std.fmt.bufPrint(&buf, "_eq{d}", .{j}));
            const tj = try t.internName(try std.fmt.bufPrint(&buf, "_T{s}{d}", .{ coord, j }));
            try t.copyToTop(eq, ec_n);
            try t.copyToTop(tj, tc);
            try t.rawBlock(2, pr, emitMulOpcode);
            if (j == 1) {
                t.renameTop(acc);
            } else {
                try t.toTop(acc);
                try t.rawBlock(2, acc, emitAddOpcode);
            }
        }
        t.setDomain(acc, .reduced);
    }

    j = entries;
    while (j >= 1) : (j -= 1) {
        const eq = try t.internName(try std.fmt.bufPrint(&buf, "_eq{d}", .{j}));
        try t.toTop(eq);
        try t.drop();
        if (j == 1) break;
    }

    try t.toTop("_idx");
    try t.rawBlock(1, "_flag", emit0NotEqualOpcode);
}

/// `k*G` by a Lim-Lee fixed-base comb instead of the binary ladder.
///
/// The ladder doubles and conditionally adds once per SCALAR BIT. A comb splits
/// the scalar into `w` blocks of `d` bits and reads one bit from each block per
/// round, so it performs one doubling and one conditional add per COLUMN: the
/// round count falls from `w*d` to `d` at the price of a `2^w - 1` entry table.
/// G is a compile-time constant here, so the table costs nothing to build.
///
/// SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add
/// accumulator equal to the addend, its negation, or the point at infinity.
/// `buildJacobianAddOrDoubleInline`'s comment justifies using it everywhere but
/// the ladder's LAST step by an interval argument over `c_i mod n`, and insists
/// that argument be re-derived by anything changing the offset or the iteration
/// count. A comb changes both, so it is re-derived: `comb.combSafeRounds`
/// evaluates the same argument as executable interval arithmetic over the comb's
/// own geometry, and any round it cannot prove gets the complete add-or-double
/// form instead. Nothing is assumed safe.
///
/// The other half of that argument is that the accumulator never starts at
/// infinity, which needs the first digit non-zero. `comb.combGeometry` searches
/// for the scalar offset that guarantees it rather than reusing the ladder's
/// hardcoded `+3n` — right for P-256 at w=3 (m=3), WRONG for P-384 at w=3,
/// where the search returns m=5. Assuming `+3n` there would let the leading
/// digit vanish and start the accumulator at infinity.
///
/// Stack in: [_k]. Stack out: [_result]. False when no geometry exists for `w`.
fn emitCombMulGen(t: *NistTracker, c: *const NistCurveParams, w: usize) !bool {
    const curve = c.comb_curve;
    const params = comb.combGeometry(w, curve) orelse return false;
    const d = params.d;
    if (d > comb.MAX_D) return false;
    var table: [1 << comb.MAX_W]?comb.Point = undefined;
    comb.combTable(w, d, curve, &table);
    var safe: [comb.MAX_D]bool = undefined;
    comb.combSafeRounds(params, curve, &safe);
    const entries = (@as(usize, 1) << @intCast(w)) - 1;
    const p_be = c.field_p_be;
    var buf: [24]u8 = undefined;

    try t.poolConstant(POOL_FIELD_P, c.field_p_be);
    try t.poolConstant(POOL_GROUP_N, c.group_n_be);

    // k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so
    // what makes the interval argument apply at all.
    try t.toTop("_k");
    try groupMod(t, "_k", c.group_n_be, "_kr");
    t.renameTop("_k");
    var i: usize = 0;
    while (i < params.offset_multiple) : (i += 1) {
        const off = try t.internName(try std.fmt.bufPrint(&buf, "_off{d}", .{i}));
        try pushGroupN(t, off, c.group_n_be);
        try t.rawBlock(2, "_k", emitAddOpcode);
    }
    t.setDomain("_k", .non_negative);

    // Table, resident for the whole comb: picking an entry costs 2-3 bytes
    // against a 33 / 49-byte literal push, and every round reads all of them.
    var j: usize = 1;
    while (j <= entries) : (j += 1) {
        const pt = table[j].?;
        const tx = try t.internName(try std.fmt.bufPrint(&buf, "_Tx{d}", .{j}));
        const ty = try t.internName(try std.fmt.bufPrint(&buf, "_Ty{d}", .{j}));
        try pushCombCoord(t, tx, pt.x, c.coord_bytes);
        try pushCombCoord(t, ty, pt.y, c.coord_bytes);
        t.setDomain(tx, .reduced);
        t.setDomain(ty, .reduced);
    }

    // Round d-1 initialises the accumulator. The first digit is non-zero by
    // construction (combGeometry), so this is a real point, never infinity.
    try combEmitSelect(t, d - 1, w, d);
    try t.toTop("_flag");
    try t.drop();
    try t.toTop("ax");
    t.renameTop("jx");
    try t.toTop("ay");
    t.renameTop("jy");
    try t.pushInt("jz", 1);
    t.setDomain("jz", .reduced);

    var round: usize = d - 1;
    while (round > 0) {
        round -= 1;
        try jacobianDouble(t, p_be);
        try combEmitSelect(t, round, w, d);

        // `jacobianAddAffineBody` documents its layout as
        // [..., ax, ay, jx, jy, jz] and replaces the accumulator IN PLACE at the
        // top. The selection leaves ax/ay above jz, so restore the contract
        // before the branch — otherwise the add arm would reorder the stack and
        // the empty else arm would not, leaving the two arms with different
        // layouts at OP_ENDIF.
        try t.toTop("_flag");
        try t.toAlt();
        try t.toTop("jx");
        try t.toTop("jy");
        try t.toTop("jz");
        try t.fromAlt("_flag");

        t.popNames(1); // consumed by OP_IF
        var add_bundle = if (safe[round])
            try buildJacobianAddAffineInline(t.allocator, t.names.items, c, t.opts, t.doms.items)
        else
            try buildJacobianAddOrDoubleInline(t.allocator, t.names.items, c, t.opts, t.doms.items);
        errdefer add_bundle.deinit();

        try t.owned_bytes.appendSlice(t.allocator, add_bundle.owned_bytes);
        t.allocator.free(add_bundle.owned_bytes);
        add_bundle.owned_bytes = &.{};
        try t.emitRaw(.{ .@"if" = .{ .then = add_bundle.ops, .@"else" = null } });
        add_bundle.ops = &.{};

        // The addend was selected fresh for this round; the add only copied it.
        try t.toTop("ay");
        try t.drop();
        try t.toTop("ax");
        try t.drop();
    }

    try jacobianToAffine(t, "_rx", "_ry", p_be, c.field_p_minus_2_be);

    j = entries;
    while (j >= 1) : (j -= 1) {
        const ty = try t.internName(try std.fmt.bufPrint(&buf, "_Ty{d}", .{j}));
        const tx = try t.internName(try std.fmt.bufPrint(&buf, "_Tx{d}", .{j}));
        try t.toTop(ty);
        try t.drop();
        try t.toTop(tx);
        try t.drop();
        if (j == 1) break;
    }
    try t.toTop("_k");
    try t.drop();

    try composePoint(t, c, "_rx", "_ry", "_result");
    try t.releaseConstant(POOL_GROUP_N);
    try t.releaseConstant(POOL_FIELD_P);
    return true;
}

/// Emit the cheapest comb over the candidate window widths into `t`.
///
/// Each candidate is rendered in full and scored with the same byte-cost model
/// the emitter is measured by, and the smallest wins — the window width is not
/// hardcoded. w=1 is the binary ladder and is excluded; beyond w=4 the `2^w`
/// selection logic outgrows the saving.
///
/// Returns false when no candidate could be built, so the caller falls back to
/// the ladder rather than emitting nothing.
fn emitCombBest(t: *NistTracker, c: *const NistCurveParams) !bool {
    var best_w: ?usize = null;
    var best_bytes: usize = 0;
    for ([_]usize{ 2, 3, 4 }) |w| {
        var probe = try NistTracker.initOpts(t.allocator, t.names.items, t.opts, t.doms.items);
        defer probe.deinit();
        const built = emitCombMulGen(&probe, c, w) catch continue;
        if (!built) continue;
        const bytes = ec.estimateScriptBytes(probe.ops.items);
        if (best_w == null or bytes < best_bytes) {
            best_w = w;
            best_bytes = bytes;
        }
    }
    const w = best_w orelse return false;
    return emitCombMulGen(t, c, w);
}

/// The comb as a standalone bundle, for `emitVerifyECDSA`'s `u1*G` half.
///
/// Null when no candidate builds, so the caller falls back to pushing G and
/// running the ladder. Like the ladder, it runs on its own tracker seeded with
/// just `_k` and cannot see the verifier's stack.
fn buildCombBundle(
    allocator: Allocator,
    c: *const NistCurveParams,
    opts: EcCodegenOptions,
) !?EcOpBundle {
    var t = try NistTracker.initOpts(allocator, &.{"_k"}, opts, null);
    errdefer t.deinit();
    if (!try emitCombBest(&t, c)) {
        t.deinit();
        return null;
    }
    return try t.takeBundle();
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

/// Decompress a compressed pubkey: [prefix||x] -> (x_num, y_num, valid).
///
/// For P-256/P-384 where a = -3:
///   y^2 = x^3 - 3x + b mod p
///   y = (y^2)^((p+1)/4) mod p
///   Select y or p-y based on prefix parity.
///
/// `(y^2)^((p+1)/4)` is a square root ONLY when y^2 is a quadratic residue; both
/// primes are == 3 (mod 4), so for a non-residue it returns a square root of
/// -y^2 instead and the recovered point is NOT on the curve. Nor is x checked
/// against p: decomposePoint-style BIN2NUM accepts any width-fitting value and
/// every field op silently reduces it, so a non-canonical x decompresses
/// happily too.
///
/// Both matter because the only consumer is emitVerifyECDSA, which feeds the
/// result straight into the scalar-mul ladder. That ladder's exception analysis
/// (see buildJacobianAddOrDoubleInline) is stated for points ON the curve,
/// where cofactor 1 pins ord(P) = n; an off-curve point lands on the twist,
/// whose order is composite, so the degenerate steps the interval argument
/// rules out become reachable. The pubkey is a caller-supplied unlock argument.
///
/// So this emits a third output, `_dk_valid` = (x < p) AND (y_cand^2 == y^2)
/// AND (prefix in {0x02, 0x03}), which the caller ANDs into the verifier's
/// boolean result. A flag, not an OP_VERIFY: `verifyECDSA_*` is a total
/// boolean-valued builtin and turning attacker-chosen bytes into a script abort
/// would be a liveness regression — the same argument the scalar reduce makes
/// for reducing rather than rejecting.
fn decompressPubKey(
    t: *NistTracker,
    c: *const NistCurveParams,
    pk_name: []const u8,
    qx_name: []const u8,
    qy_name: []const u8,
) !void {
    const p_be = c.field_p_be;

    try t.toTop(pk_name);
    t.popNames(1);
    // Split: [prefix_byte, x_bytes]
    try t.emitPushIntRaw(1);
    try t.emitOpcode("OP_SPLIT");
    try t.pushTracked("_dk_prefix", .unknown);
    try t.pushTracked("_dk_xbytes", .unknown);

    // SEC1 §2.3.4 requires the prefix to be exactly 0x02 or 0x03. The parity
    // reduction below is `BIN2NUM, 2 MOD`, which accepts far more than that:
    // 0x00 / 0x04 / 0x82 all alias to "even", and 0x83 is worse than an alias —
    // BIN2NUM(0x83) = -3 (sign-magnitude), -3 mod 2 = -1, which encodes as 0x81
    // and can never equal `_dk_y_par` in {<>, 0x01}, so the select silently
    // returns the OTHER square root. Test the byte itself.
    try t.copyToTop("_dk_prefix", "_dk_pfx_in");
    t.popNames(1);
    try t.emitRaw(.{ .dup = {} });
    try t.emitRaw(.{ .push = .{ .bytes = &.{0x02} } });
    try t.emitOpcode("OP_EQUAL");
    try t.emitRaw(.{ .swap = {} });
    try t.emitRaw(.{ .push = .{ .bytes = &.{0x03} } });
    try t.emitOpcode("OP_EQUAL");
    try t.emitOpcode("OP_BOOLOR");
    try t.pushTracked("_dk_pfx_ok", .unknown);

    // Convert prefix to parity: 0x02 -> 0, 0x03 -> 1
    try t.toTop("_dk_prefix");
    t.popNames(1);
    try t.emitOpcode("OP_BIN2NUM");
    try t.emitPushIntRaw(2);
    try t.emitOpcode("OP_MOD");
    try t.pushTracked("_dk_parity", .unknown);

    // Stash parity on altstack
    try t.toAlt();

    // Convert x_bytes to number
    try t.toTop("_dk_xbytes");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, c.coord_bytes);
    try t.pushTracked("_dk_x", .unknown);

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
    try pushBigIntBE(t, "_dk_b", c.curve_b_be);
    try fieldAdd(t, "_dk_x3m3x", "_dk_b", p_be, "_dk_y2");

    // y = (y^2)^sqrtExp mod p. fieldPow CONSUMES its base, so keep a copy of
    // y^2 for the residue check at the end. It has to sit BELOW _dk_y_cand: the
    // parity select below is an OP_IF whose branches are a bare drop / nip, so
    // nothing may come between _dk_y_cand and the negated candidate.
    try t.copyToTop("_dk_y2", "_dk_y2_keep");
    try fieldPow(t, "_dk_y2", c.sqrt_exp_be, p_be, "_dk_y_cand");

    // Check if candidate y has the right parity
    try t.copyToTop("_dk_y_cand", "_dk_y_check");
    t.popNames(1);
    try t.emitPushIntRaw(2);
    try t.emitOpcode("OP_MOD");
    try t.pushTracked("_dk_y_par", .unknown);

    // Retrieve parity from altstack
    try t.fromAlt("_dk_parity");

    // Compare
    try t.toTop("_dk_y_par");
    try t.toTop("_dk_parity");
    t.popNames(2);
    try t.emitOpcode("OP_EQUAL");
    try t.pushTracked("_dk_match", .unknown);

    // Compute p - y_cand
    try t.copyToTop("_dk_y_cand", "_dk_y_for_neg");
    try pushFieldP(t, "_dk_pfn", p_be);
    try t.toTop("_dk_y_for_neg");
    t.popNames(2);
    try t.emitOpcode("OP_SUB");
    try t.pushTracked("_dk_neg_y", .unknown);

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
        _ = t.removeSlotAt(idx);
    }

    // Rename _dk_y_cand -> qyName and _dk_x_save -> qxName
    {
        var idx = t.names.items.len;
        while (idx > 0) {
            idx -= 1;
            if (t.names.items[idx]) |n| {
                if (std.mem.eql(u8, n, "_dk_y_cand")) {
                    t.names.items[idx] = qy_name;
                    // FORGET what was known about the slot: `_dk_y_cand` carries Reduced
                    // from cFieldPow, but that fact describes only the THEN path. The else
                    // arm leaves `p - y_cand` (bare OP_SUB, Unknown, range (0, p]) in this
                    // same slot, and p - 0 = p is not < p. This is the join emitIf refuses
                    // to make, and the raw `if` here bypasses that rule, so the reset must
                    // be explicit. Sound today only via an unwritten argument (y_cand = 0
                    // needs an order-2 point, impossible on a prime-order curve) and
                    // unexploited only because nothing uses qy as a fieldSub subtrahend.
                    t.setDomain(qy_name, .unknown);
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

    // valid = (qy^2 == y^2) AND (qx < p) AND (prefix in {0x02, 0x03}).
    // The selected qy is y_cand or p - y_cand, so squaring it tests the same
    // residue property either way. The first conjunct rejects an x whose RHS is
    // a quadratic non-residue — the recovered point is then off the curve; the
    // second rejects a non-canonical encoding of an otherwise fine x; the third
    // rejects a prefix byte the parity reduction would otherwise alias or, for
    // 0x83, silently invert.
    try t.copyToTop(qy_name, "_dk_y_sq_in");
    try fieldSqr(t, "_dk_y_sq_in", p_be, "_dk_y_sq");
    try t.toTop("_dk_y_sq");
    try t.toTop("_dk_y2_keep");
    t.popNames(2);
    try t.emitOpcode("OP_NUMEQUAL");
    try t.pushTracked("_dk_res_ok", .unknown);

    try t.copyToTop(qx_name, "_dk_x_lt");
    try pushFieldP(t, "_dk_p_lt", p_be);
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.pushTracked("_dk_x_ok", .unknown);

    try t.toTop("_dk_res_ok");
    try t.toTop("_dk_x_ok");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_dk_curve_ok", .unknown);

    try t.toTop("_dk_pfx_ok");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_dk_valid", .unknown);
}

// ===========================================================================
// ECDSA verification
// ===========================================================================

/// Length gate for an untrusted byte argument: leaves `[flag, clamped]`.
///
/// `flag` is `OP_SIZE(v) == want`; `clamped` is `v` forced to exactly `want`
/// bytes by `v || 00*want`, split at `want`, tail dropped — truncating a long
/// value and zero-extending a short one.
///
/// The clamp exists so the gate can stay a FLAG. Everything downstream peels a
/// fixed number of bytes (`OP_SPLIT coord_bytes`, then 32/48 single-byte splits
/// inside emitReverseN); handed 32 <= len(sig) < 64 the reversal runs out of
/// bytes mid-loop and the SCRIPT ABORTS, which would make
/// `verifyECDSA_P256(...) || fallback` unwritable and contradict this module's
/// own totality rule (see decompressPubKey). Clamping first makes every path
/// total; the caller ANDs `flag` into the result so a wrong-length argument can
/// never verify whatever the clamped bytes computed.
///
/// Branch-free on purpose: the tracker's static stack model, and the emitted op
/// sequence, are the same for every input length — the argument affineAdd makes
/// for selecting operands instead of branching.
fn emitLengthGate(t: *NistTracker, name: []const u8, want: usize, flag_name: []const u8) !void {
    try t.toTop(name);
    t.popNames(1);
    try t.emitOpcode("OP_SIZE");
    try t.emitPushIntRaw(@intCast(want));
    try t.emitOpcode("OP_NUMEQUAL");
    try t.emitRaw(.{ .swap = {} });
    const pad = try t.allocator.alloc(u8, want);
    @memset(pad, 0);
    try t.owned_bytes.append(t.allocator, pad);
    try t.emitRaw(.{ .push = .{ .bytes = pad } });
    try t.emitOpcode("OP_CAT");
    try t.emitPushIntRaw(@intCast(want));
    try t.emitOpcode("OP_SPLIT");
    try t.emitRaw(.{ .drop = {} });
    try t.pushTracked(flag_name, .unknown);
    try t.pushTracked(name, .unknown);
}

/// SEC1 §4.1.4 step 1 / FIPS 186-5 §6.4.2: verify 1 <= r <= n-1 and
/// 1 <= s <= n-1. Consumes nothing, leaves `_range_ok` above `_r` and `_s`.
///
/// ==> THIS IS A UNIVERSAL FORGERY GUARD, NOT A HYGIENE CHECK. <==
///
/// Nothing checked r or s at all, and `groupInv` is Fermat (a^(n-2) mod n), so
/// inv(0) = 0 instead of an error. With `sig = 0x00...` and the contract's own
/// genuine, PUBLIC key:
///
///   r = s = 0            (BIN2NUM of coord_bytes zero bytes -> empty vector)
///   w = s^(n-2) = 0      Fermat, no failure channel
///   u1 = u2 = 0          every groupMul in the ladder is 0*0 mod n
///   R1 = R2 = O          the ladder reduces 0, k' = 3n = 0 mod n, so Z3 = 0 and
///                        jacobianToAffine's Fermat inverse turns it all-zero
///   R1 + R2              affineAdd sees xeq = yeq = 1, takes the tangent with
///                        den = 2*0 = 0, so s = 0 and rx = ry = 0
///   (R.x mod n) == r     OP_EQUAL(<>, <>) = 1
///
/// ...and `_dk_valid` is 1 because the pubkey is genuine. TRUE. No secret, no
/// off-curve point, not bound to the message: an all-zero signature verified for
/// ANY message under ANY public key. `examples/ts/p256-wallet` made exactly that
/// call its second authentication factor.
///
/// BOTH conjuncts are load-bearing and neither is redundant:
///   - s = 0 (or s = n, which Fermat also inverts to 0) is what collapses both
///     ladders to O;
///   - r = 0 is what makes the final OP_EQUAL compare the resulting 0 against
///     something that is also 0.
/// `r = 0, s = n` is a second spelling of the same forgery that an `s != 0`
/// check alone would miss, which is why the bound is `< n` and not `!= 0`.
///
/// A flag rather than an OP_VERIFY, for the reason decompressPubKey gives.
fn emitSigRangeGate(t: *NistTracker, n_be: []const u8) !void {
    try t.copyToTop("_r", "_r_nz_in");
    t.popNames(1);
    try t.emitOpcode("OP_0NOTEQUAL");
    try t.pushTracked("_r_nz", .unknown);

    try t.copyToTop("_r", "_r_lt_in");
    try pushGroupN(t, "_n_for_r", n_be);
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.pushTracked("_r_lt", .unknown);

    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_r_ok", .unknown);

    try t.copyToTop("_s", "_s_nz_in");
    t.popNames(1);
    try t.emitOpcode("OP_0NOTEQUAL");
    try t.pushTracked("_s_nz", .unknown);

    try t.copyToTop("_s", "_s_lt_in");
    try pushGroupN(t, "_n_for_s", n_be);
    t.popNames(2);
    try t.emitOpcode("OP_LESSTHAN");
    try t.pushTracked("_s_lt", .unknown);

    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_s_ok", .unknown);

    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_range_ok", .unknown);
}

fn emitVerifyECDSA(t: *NistTracker, c: *const NistCurveParams) !void {
    const n_be = c.group_n_be;
    const n_minus_2_be = c.group_n_minus_2_be;
    const cb = c.coord_bytes;

    // The verifier does hundreds of reductions OUTSIDE the two ladders — the
    // decompression sqrt chain, groupInv, affineAdd, the final groupMod. Each
    // ladder pools separately: it runs on its own tracker that deliberately
    // cannot see this stack, so it cannot reach this slot.
    try t.poolConstant(POOL_FIELD_P, c.field_p_be);
    try t.poolConstant(POOL_GROUP_N, c.group_n_be);

    // Step 0: length gate. `_sig` and `_pk` are bare ByteString in the builtin
    // table and the type checker imposes no width, so both arrive attacker-sized.
    // Clamp them and remember whether they were the right size — see
    // emitLengthGate for why a clamp and not an abort. Without it `sig || junk`
    // verified identically to `sig` (fatal for any contract using signature bytes
    // as a nullifier), and a short `sig` aborted the script outright.
    try emitLengthGate(t, "_pk", cb + 1, "_pk_len_ok");
    try emitLengthGate(t, "_sig", cb * 2, "_sig_len_ok");
    try t.toTop("_pk_len_ok");
    try t.toTop("_sig_len_ok");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_len_ok", .unknown);

    // Step 1: e = SHA-256(msg) as integer
    try t.toTop("_msg");
    t.popNames(1);
    try t.emitOpcode("OP_SHA256");
    // SHA-256 produces 32 bytes BE. Reverse to get LE, cat 0x00, BIN2NUM.
    try emitReverseN(t, 32);
    try t.emitRaw(.{ .push = .{ .bytes = &.{0x00} } });
    try t.emitOpcode("OP_CAT");
    try t.emitOpcode("OP_BIN2NUM");
    try t.pushTracked("_e", .unknown);

    // Step 2: Parse sig into (r, s) — each coord_bytes bytes
    try t.toTop("_sig");
    t.popNames(1);
    try t.emitPushIntRaw(@intCast(cb));
    try t.emitOpcode("OP_SPLIT");
    try t.pushTracked("_r_bytes", .unknown);
    try t.pushTracked("_s_bytes", .unknown);

    // Convert r_bytes to integer
    try t.toTop("_r_bytes");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, cb);
    try t.pushTracked("_r", .unknown);

    // Convert s_bytes to integer
    try t.toTop("_s_bytes");
    t.popNames(1);
    try emitBytesToUnsignedNum(t, cb);
    try t.pushTracked("_s", .unknown);

    // Step 2b: 1 <= r, s <= n-1. Without this an all-zero signature verifies for
    // any message under any pubkey — see emitSigRangeGate.
    try emitSigRangeGate(t, n_be);

    // Step 3: Decompress pubkey. Also yields `_dk_valid`: 0 when the pubkey
    // bytes do not decompress to a canonical on-curve point, which is ANDed into
    // the result below so such a key can never verify.
    try decompressPubKey(t, c, "_pk", "_qx", "_qy");

    // Collapse the three argument verdicts into one flag. Everything below then
    // carries a single item, as it did when `_dk_valid` was the only one.
    try t.toTop("_len_ok");
    try t.toTop("_range_ok");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_arg_ok", .unknown);
    try t.toTop("_dk_valid");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_input_ok", .unknown);

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
    // u1*G. G is a compile-time constant, so THIS half can use a fixed-base comb
    // — one doubling and one add per COLUMN instead of per bit. u2*Q below
    // cannot: Q arrives in the witness, and the comb's interval argument is
    // stated for a base of known order.
    //
    // Rendered before the `_G` push is decided, because whether that push
    // happens at all is what the comb changes.
    var comb_bundle: ?EcOpBundle = if (t.opts.fixed_base_comb)
        try buildCombBundle(t.allocator, c, t.opts)
    else
        null;
    errdefer if (comb_bundle) |*b| b.deinit();

    if (comb_bundle == null) {
        const g_point = try t.allocator.alloc(u8, point_bytes);
        @memcpy(g_point[0..cb], c.gen_x_be);
        @memcpy(g_point[cb..point_bytes], c.gen_y_be);
        try t.pushOwnedBytes("_G", g_point);
    }
    try t.toTop("_u1");

    // Stash items on altstack (pushed in reverse retrieval order).
    // _input_ok goes DEEPEST — the altstack is LIFO and it is popped last.
    try t.toTop("_input_ok");
    try t.toAlt();
    try t.toTop("_r_save");
    try t.toAlt();
    try t.toTop("_u2");
    try t.toAlt();
    try t.toTop("_qy");
    try t.toAlt();
    try t.toTop("_qx");
    try t.toAlt();

    // Stack now has: [..., (_G,) _u1]
    // Pop those names and emit the multiply (consuming _G and _u1, or just _u1
    // for the comb, which takes the scalar alone).
    t.popNames(1); // _u1
    if (comb_bundle) |*bundle| {
        try t.owned_bytes.appendSlice(t.allocator, bundle.owned_bytes);
        t.allocator.free(bundle.owned_bytes);
        bundle.owned_bytes = &.{};
        try t.ops.appendSlice(t.allocator, bundle.ops);
        t.allocator.free(bundle.ops);
        bundle.ops = &.{};
        try t.pushTracked("_R1_point", .unknown);
    } else {
        t.popNames(1); // _G
        try emitScalarMulInline(t, c, "_R1_point");
    }

    // Pop qx/qy/u2 from altstack (LIFO order)
    try t.fromAlt("_qx");
    try t.fromAlt("_qy");
    try t.fromAlt("_u2");

    // Stash R1 point while we compute R2
    try t.toTop("_R1_point");
    try t.toAlt();

    // Compose Q point from qx, qy
    try composePoint(t, c, "_qx", "_qy", "_Q_point");

    // Stack now has: [..., _Q_point, _u2]
    // Bring _Q_point below _u2 to match expected [point, scalar] order
    try t.toTop("_Q_point");
    try t.toTop("_u2");

    // Pop those names and emit scalar mul inline (consuming _Q_point and _u2)
    t.popNames(1); // _u2
    t.popNames(1); // _Q_point
    try emitScalarMulInline(t, c, "_R2_point");

    // Restore R1 point
    try t.fromAlt("_R1_point");

    // Swap so _R2_point is on top, _R1_point below
    try t.swap();

    // Decompose both points and do affine addition
    try decomposePoint(t, c, "_R1_point", "px", "py");
    try decomposePoint(t, c, "_R2_point", "qx", "qy");

    try affineAdd(t, c);

    // Step 8: x_R mod n == r
    try t.toTop("ry");
    try t.drop();

    try groupMod(t, "rx", n_be, "_rx_mod_n");

    // Restore r, then the argument verdict beneath it
    try t.fromAlt("_r_save");
    try t.fromAlt("_input_ok");

    // Compare
    try t.toTop("_rx_mod_n");
    try t.toTop("_r_save");
    t.popNames(2);
    try t.emitOpcode("OP_EQUAL");
    try t.pushTracked("_sig_ok", .unknown);

    // Arguments that were the wrong length, out of range, or did not decompress
    // to a canonical on-curve point can never verify, whatever the ladder made
    // of them.
    try t.toTop("_input_ok");
    try t.toTop("_sig_ok");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_result", .unknown);
    try t.releaseConstant(POOL_GROUP_N);
    try t.releaseConstant(POOL_FIELD_P);
}

// ===========================================================================
// Public API — build EcOpBundle for each builtin
// ===========================================================================
//
// The per-builtin bodies below are curve-generic: P-256 and P-384 differ only
// in their `NistCurveParams`. They were two verbatim copies until the size
// flags landed, and every copy is one more place the comb could be wired to one
// curve and not the other.

fn emitAdd(t: *NistTracker, c: *const NistCurveParams) !void {
    try t.poolConstant(POOL_FIELD_P, c.field_p_be);
    try decomposePoint(t, c, "_pa", "px", "py");
    try decomposePoint(t, c, "_pb", "qx", "qy");
    try affineAdd(t, c);
    try composePoint(t, c, "rx", "ry", "_result");
    try t.releaseConstant(POOL_FIELD_P);
}

fn emitMulGen(t: *NistTracker, c: *const NistCurveParams) !void {
    // G is a compile-time constant, so this is the one NIST scalar-mul call
    // site where a fixed-base comb applies. `p256Mul` / `p384Mul` cannot use it:
    // their base arrives at run time.
    if (t.opts.fixed_base_comb) {
        if (try emitCombBest(t, c)) return;
    }

    const point_bytes = c.coord_bytes * 2;
    const g_point = try t.allocator.alloc(u8, point_bytes);
    @memcpy(g_point[0..c.coord_bytes], c.gen_x_be);
    @memcpy(g_point[c.coord_bytes..point_bytes], c.gen_y_be);
    try t.pushOwnedBytes("_pt", g_point);
    try t.swap();
    try emitScalarMulOnTracker(t, c);
}

fn emitNegate(t: *NistTracker, c: *const NistCurveParams) !void {
    try t.poolConstant(POOL_FIELD_P, c.field_p_be);
    try decomposePoint(t, c, "_pt", "_nx", "_ny");
    try pushFieldP(t, "_fp", c.field_p_be);
    try fieldSub(t, "_fp", "_ny", c.field_p_be, "_neg_y");
    try composePoint(t, c, "_nx", "_neg_y", "_result");
    try t.releaseConstant(POOL_FIELD_P);
}

fn emitOnCurve(t: *NistTracker, c: *const NistCurveParams) !void {
    const p_be = c.field_p_be;
    try t.poolConstant(POOL_FIELD_P, p_be);
    try decomposePoint(t, c, "_pt", "_x", "_y");
    try emitCanonicityGuard(t, "_x", "_y", p_be);

    // lhs = y^2
    try fieldSqr(t, "_y", p_be, "_y2");

    // rhs = x^3 - 3x + b
    try t.copyToTop("_x", "_x_copy");
    try t.copyToTop("_x", "_x_copy2");
    try fieldSqr(t, "_x", p_be, "_x2");
    try fieldMul(t, "_x2", "_x_copy", p_be, "_x3");
    try fieldMulConst(t, "_x_copy2", 3, p_be, "_3x");
    try fieldSub(t, "_x3", "_3x", p_be, "_x3m3x");
    try pushBigIntBE(t, "_b", c.curve_b_be);
    try fieldAdd(t, "_x3m3x", "_b", p_be, "_rhs");

    try t.toTop("_y2");
    try t.toTop("_rhs");
    t.popNames(2);
    try t.emitOpcode("OP_EQUAL");
    try t.pushTracked("_curve_eq", .unknown);

    // on-curve = canonical AND curve-equation
    try t.toTop("_canon");
    try t.toTop("_curve_eq");
    t.popNames(2);
    try t.emitOpcode("OP_BOOLAND");
    try t.pushTracked("_result", .unknown);
    try t.releaseConstant(POOL_FIELD_P);
}

/// Point compression. No field arithmetic, so no flag reaches it — the three
/// options leave this emitter byte-identical, as they do in the reference.
fn emitEncodeCompressed(t: *NistTracker, c: *const NistCurveParams) !void {
    // Split at coord_bytes: [x_bytes, y_bytes]
    try t.toTop("_pt");
    t.popNames(1);
    try t.emitPushIntRaw(@intCast(c.coord_bytes));
    try t.emitOpcode("OP_SPLIT");
    try t.pushTracked("_x_bytes", .unknown);
    try t.pushTracked("_y_bytes", .unknown);
    // Get last byte of y for parity
    try t.toTop("_y_bytes");
    t.popNames(1);
    try t.emitOpcode("OP_SIZE");
    try t.emitPushIntRaw(1);
    try t.emitOpcode("OP_SUB");
    try t.emitOpcode("OP_SPLIT");
    try t.pushTracked("_y_prefix", .unknown);
    try t.pushTracked("_last_byte", .unknown);
    // Parity
    try t.toTop("_last_byte");
    t.popNames(1);
    try t.emitOpcode("OP_BIN2NUM");
    try t.emitPushIntRaw(2);
    try t.emitOpcode("OP_MOD");
    try t.pushTracked("_parity", .unknown);
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
    try t.pushTracked("_prefix", .unknown);
    // [x_bytes, prefix] -> swap -> prefix || x_bytes
    try t.swap();
    t.popNames(2);
    try t.emitOpcode("OP_CAT");
    try t.pushTracked("_result", .unknown);
}

pub fn buildBuiltinOps(allocator: Allocator, builtin: registry.CryptoBuiltin) !EcOpBundle {
    return buildBuiltinOpsOpts(allocator, builtin, .{});
}

/// Render the comb at one window width, for the width-selection test.
///
/// The emitter picks `w` by rendering every candidate and keeping the smallest;
/// this exposes a single candidate so the test can pin WHICH width wins rather
/// than only that the total matches.
pub fn buildCombProbeForTest(allocator: Allocator, p384: bool, w: usize) !EcOpBundle {
    const c: *const NistCurveParams = if (p384) &p384_params else &p256_params;
    var t = try NistTracker.initOpts(allocator, &.{"_k"}, .{
        .constant_pool = true,
        .reduction_sinking = true,
        .fixed_base_comb = true,
    }, null);
    errdefer t.deinit();
    _ = try emitCombMulGen(&t, c, w);
    return t.takeBundle();
}

/// `buildBuiltinOps` with the EXPERIMENTAL EC script-size options.
///
/// An all-false value keeps every emitter byte-identical to the shipping output;
/// see `ec_emitters.EcCodegenOptions` and
/// docs/experiments/script-size-optimizer-results.md.
pub fn buildBuiltinOpsOpts(
    allocator: Allocator,
    builtin: registry.CryptoBuiltin,
    opts: EcCodegenOptions,
) !EcOpBundle {
    const c: *const NistCurveParams = switch (builtin) {
        .verify_ecdsa_p256,
        .p256_add,
        .p256_mul,
        .p256_mul_gen,
        .p256_negate,
        .p256_on_curve,
        .p256_encode_compressed,
        => &p256_params,
        .verify_ecdsa_p384,
        .p384_add,
        .p384_mul,
        .p384_mul_gen,
        .p384_negate,
        .p384_on_curve,
        .p384_encode_compressed,
        => &p384_params,
        else => return error.UnsupportedBuiltin,
    };

    const initial: []const ?[]const u8 = switch (builtin) {
        .verify_ecdsa_p256, .verify_ecdsa_p384 => &.{ "_msg", "_sig", "_pk" },
        .p256_add, .p384_add => &.{ "_pa", "_pb" },
        .p256_mul, .p384_mul => &.{ "_pt", "_k" },
        .p256_mul_gen, .p384_mul_gen => &.{"_k"},
        else => &.{"_pt"},
    };

    var t = try NistTracker.initOpts(allocator, initial, opts, null);
    errdefer t.deinit();

    switch (builtin) {
        .verify_ecdsa_p256, .verify_ecdsa_p384 => try emitVerifyECDSA(&t, c),
        .p256_add, .p384_add => try emitAdd(&t, c),
        .p256_mul, .p384_mul => try emitScalarMulOnTracker(&t, c),
        .p256_mul_gen, .p384_mul_gen => try emitMulGen(&t, c),
        .p256_negate, .p384_negate => try emitNegate(&t, c),
        .p256_on_curve, .p384_on_curve => try emitOnCurve(&t, c),
        .p256_encode_compressed, .p384_encode_compressed => try emitEncodeCompressed(&t, c),
        else => unreachable,
    }

    return t.takeBundle();
}

// ===========================================================================
// Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// T-11: Op-count goldens for the Zig NIST EC helper bundles (P-256 / P-384).
//
// The "emits ops" tests below only assert `ops.len > 0`. These goldens
// pin the Zig helper's pre-stack-lowering bundle size so a regression in
// `buildBuiltinOps` surfaces here as a localized failure rather than
// only as a cross-tier hex mismatch from the golden harness. Counts are
// op-TREE sizes (if bodies included, see countOpTree) and still differ
// slightly from the Python/Java peers because the Zig tier bundles some
// sequences differently at the helper level; final compiled hex is
// byte-identical (enforced by the conformance harness).
// ---------------------------------------------------------------------------

/// Total number of StackOps in `ops`, INCLUDING the bodies of `.@"if"` ops.
///
/// A flat `ops.len` cannot see inside a branch, so any emitter whose work sits
/// in an if body — the scalar ladders emit 257 / 385 conditional additions —
/// reports a count that barely moves no matter what the branch contains.
/// Adding +1.3 KB of script inside the ladder's last step left the p256Mul /
/// p384Mul goldens byte-identical. Recursing is what makes the golden a gate.
fn countOpTree(ops: []const StackOp) usize {
    var total: usize = 0;
    for (ops) |op| {
        total += 1;
        switch (op) {
            .@"if" => |stack_if| {
                total += countOpTree(stack_if.then);
                if (stack_if.@"else") |else_ops| total += countOpTree(else_ops);
            },
            else => {},
        }
    }
    return total;
}

test "nist_ec helper op-count goldens" {
    // p256Add 6623 -> 6639 and p384Add 11429 -> 11445 (+16 each): affineAdd now
    // detects P == -Q (px == qx but py != qy) and masks the result to the
    // all-zero point instead of taking the tangent and returning a plausible,
    // WRONG 2P. Curve-independent, as it must be — the added ops are the same
    // sequence for both curves; only the push widths differ, and those are
    // bytes, not ops. +21 script BYTES on each. See the same note in
    // ec_emitters.zig for why the TS/Go/Rust/Python/Ruby/Java peers book this
    // as +21 OPS: they count a deep pick/roll as two ops, this tracker as one.
    //
    // verifyECDSA_P256 / _P384 also moved (decompressPubKey's `_dk_valid`
    // residue + canonicity guard, +148 / +434 bytes; then the argument
    // validation gates — length clamp, r/s range, prefix byte — for a further
    // +225 / +306 bytes) but carry no op-count golden here — the conformance
    // hex is their gate.
    const cases = .{
        .{ registry.CryptoBuiltin.p256_add, "p256Add", @as(usize, 6639) },
        .{ registry.CryptoBuiltin.p256_mul, "p256Mul", @as(usize, 129192) },
        .{ registry.CryptoBuiltin.p256_mul_gen, "p256MulGen", @as(usize, 129194) },
        .{ registry.CryptoBuiltin.p256_negate, "p256Negate", @as(usize, 945) },
        .{ registry.CryptoBuiltin.p256_on_curve, "p256OnCurve", @as(usize, 555) },
        .{ registry.CryptoBuiltin.p256_encode_compressed, "p256EncodeCompressed", @as(usize, 16) },
        .{ registry.CryptoBuiltin.p384_add, "p384Add", @as(usize, 11445) },
        .{ registry.CryptoBuiltin.p384_mul, "p384Mul", @as(usize, 194958) },
        .{ registry.CryptoBuiltin.p384_mul_gen, "p384MulGen", @as(usize, 194960) },
        .{ registry.CryptoBuiltin.p384_negate, "p384Negate", @as(usize, 1393) },
    };
    inline for (cases) |c| {
        var bundle = try buildBuiltinOps(std.testing.allocator, c[0]);
        defer bundle.deinit();
        const got = countOpTree(bundle.ops);
        if (got != c[2]) {
            std.debug.print(
                "{s}: op-count drift — got {d}, want {d}\n",
                .{ c[1], got, c[2] },
            );
        }
        try std.testing.expectEqual(c[2], got);
    }
}

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
