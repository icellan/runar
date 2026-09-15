//! CL-BUG-095 — a `Point` argument's WIDTH is now checked.
//!
//! A `Point` is DEFINED as exactly 2*w bytes (x[w] ‖ y[w], big-endian, no
//! prefix byte): 64 for secp256k1 and P-256, 96 for P-384. Nothing in any tier
//! checked that, and surplus bytes were silently DISCARDED — `decomposePoint`
//! splits at the coordinate width and the byte-reversal helper reverses exactly
//! w bytes and drops the remainder. Measured on the real @bsv/sdk interpreter
//! before the fix:
//!
//!   - `ecOnCurve(G ‖ 0xff)`          -> TRUE  (must be false)
//!   - `ecPointX(32-byte blob)`       -> succeeds, returns the blob
//!   - `ecEncodeCompressed(G)`        -> 02‖x
//!     `ecEncodeCompressed(G ‖ 0x01)` -> 03‖x  — one appended byte FLIPS the
//!                                      parity of a compressed pubkey, so
//!                                      anything that hashes one (a P2PKH
//!                                      address, a commitment) is forgeable
//!                                      between the two spellings.
//!
//! The op-count goldens in ec_emitters.zig / nist_ec_emitters.zig move when the
//! gate lands, but a number is satisfiable by re-stamping it. These assertions
//! pin the SHAPE: the exact opcode sequence, at the exact position, so removing
//! the gate fails here and not only in a count that someone can update.
//!
//! Two forms, deliberately different:
//!   - ABORTING (`OP_SIZE <want> OP_NUMEQUALVERIFY`) for every consumer that
//!     produces a VALUE and has no error channel — there is no correct value to
//!     return for a blob that is not a point.
//!   - CLAMPING (the 9-op gate, flag ANDed into the result) for the on-curve
//!     PREDICATES, because for them "no" is an answer and
//!     `if (ecOnCurve(p)) … else …` has to keep working.

const std = @import("std");
const ec = @import("../passes/helpers/ec_emitters.zig");
const nist = @import("../passes/helpers/nist_ec_emitters.zig");
const crypto = @import("../passes/helpers/crypto_emitters.zig");
const registry = @import("../passes/helpers/crypto_builtins.zig");

const StackOp = ec.StackOp;

fn expectOpcode(op: StackOp, code: []const u8) !void {
    switch (op) {
        .opcode => |c| try std.testing.expectEqualStrings(code, c),
        else => return error.NotAnOpcode,
    }
}

fn expectPushInt(op: StackOp, value: i64) !void {
    switch (op) {
        .push => |p| switch (p) {
            .integer => |v| try std.testing.expectEqual(value, v),
            else => return error.NotAnIntegerPush,
        },
        else => return error.NotAPush,
    }
}

/// Silent predicate: is `ops[start..start+3]` the aborting gate? Used by the
/// scanning tests, which try every offset — `std.testing.expect*` would print a
/// diff at each of the ~200k misses and bury the build log.
fn isLenVerifyAt(ops: []const StackOp, start: usize, want: i64) bool {
    if (ops.len < start + 3) return false;
    const a = switch (ops[start]) {
        .opcode => |c| std.mem.eql(u8, c, "OP_SIZE"),
        else => false,
    };
    const b = switch (ops[start + 1]) {
        .push => |p| switch (p) {
            .integer => |v| v == want,
            else => false,
        },
        else => false,
    };
    const c = switch (ops[start + 2]) {
        .opcode => |code| std.mem.eql(u8, code, "OP_NUMEQUALVERIFY"),
        else => false,
    };
    return a and b and c;
}

fn countLenVerifies(ops: []const StackOp, want: i64) usize {
    var n: usize = 0;
    for (0..ops.len) |i| {
        if (isLenVerifyAt(ops, i, want)) n += 1;
    }
    return n;
}

/// `OP_SIZE <want> OP_NUMEQUALVERIFY` at `ops[start..start+3]`.
fn expectLenVerifyAt(ops: []const StackOp, start: usize, want: i64) !void {
    try std.testing.expect(ops.len >= start + 3);
    try expectOpcode(ops[start], "OP_SIZE");
    try expectPushInt(ops[start + 1], want);
    try expectOpcode(ops[start + 2], "OP_NUMEQUALVERIFY");
}

/// The 9-op clamping gate at `ops[0..9]`, leaving [flag, clamped].
fn expectClampGateAtHead(ops: []const StackOp, want: i64) !void {
    try std.testing.expect(ops.len >= 9);
    try expectOpcode(ops[0], "OP_SIZE");
    try expectPushInt(ops[1], want);
    try expectOpcode(ops[2], "OP_NUMEQUAL");
    try std.testing.expect(ops[3] == .swap);
    switch (ops[4]) {
        .push => |p| switch (p) {
            // The pad is `want` zero bytes: `v ‖ 00*want` then split at `want`.
            .bytes => |b| {
                try std.testing.expectEqual(@as(usize, @intCast(want)), b.len);
                for (b) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
            },
            else => return error.PadNotBytes,
        },
        else => return error.PadNotAPush,
    }
    try expectOpcode(ops[5], "OP_CAT");
    try expectPushInt(ops[6], want);
    try expectOpcode(ops[7], "OP_SPLIT");
    try std.testing.expect(ops[8] == .drop);
}

fn countTopLevelOpcode(ops: []const StackOp, code: []const u8) usize {
    var n: usize = 0;
    for (ops) |op| switch (op) {
        .opcode => |c| {
            if (std.mem.eql(u8, c, code)) n += 1;
        },
        else => {},
    };
    return n;
}

fn findInstruction(
    items: []const crypto.CryptoInstruction,
    op_name: []const u8,
) ?usize {
    for (items, 0..) |ins, i| switch (ins) {
        .op_name => |c| {
            if (std.mem.eql(u8, c, op_name)) return i;
        },
        else => {},
    };
    return null;
}

// ---------------------------------------------------------------------------
// secp256k1 — ec_emitters
// ---------------------------------------------------------------------------

test "CL-BUG-095: ecNegate verifies the 64-byte width before decomposing" {
    var bundle = try ec.buildBuiltinOps(std.testing.allocator, .ec_negate);
    defer bundle.deinit();
    // `_pt` is the only value on the stack, so decomposePoint's `toTop` is a
    // no-op and the verify is literally the first thing the builtin emits.
    try expectLenVerifyAt(bundle.ops, 0, 64);
}

test "CL-BUG-095: ecAdd verifies BOTH point arguments" {
    var bundle = try ec.buildBuiltinOps(std.testing.allocator, .ec_add);
    defer bundle.deinit();
    // One per decomposePoint. A single verify would mean only `_pa` is gated
    // and an over-long `_pb` still gets its surplus silently dropped.
    try std.testing.expectEqual(@as(usize, 2), countLenVerifies(bundle.ops, 64));
}

test "CL-BUG-095: ecOnCurve clamps rather than aborts, and ANDs the flag in" {
    var bundle = try ec.buildBuiltinOps(std.testing.allocator, .ec_on_curve);
    defer bundle.deinit();
    // The predicate must stay TOTAL — contracts are told to write
    // `if (ecOnCurve(p))`, so a wrong-length blob must answer `false`, not
    // abort the script.
    try expectClampGateAtHead(bundle.ops, 64);
    // ...and the decompose that follows still carries its own verify, which is
    // unreachable-by-construction here (the clamp guarantees 64) but is what
    // every OTHER consumer of decomposePoint relies on.
    try expectLenVerifyAt(bundle.ops, 9, 64);
    // canon(x<p AND y<p) -> 1, canon AND curve_eq -> 2, len_ok AND eq_ok -> 3.
    try std.testing.expectEqual(@as(usize, 3), countTopLevelOpcode(bundle.ops, "OP_BOOLAND"));
    try expectOpcode(bundle.ops[bundle.ops.len - 1], "OP_BOOLAND");
}

test "CL-BUG-095: ecPointX / ecPointY verify the width first" {
    const allocator = std.testing.allocator;
    inline for (.{ registry.CryptoBuiltin.ec_point_x, registry.CryptoBuiltin.ec_point_y }) |builtin| {
        var list: std.ArrayListUnmanaged(crypto.CryptoInstruction) = .empty;
        defer list.deinit(allocator);
        try crypto.appendBuiltinInstructions(&list, allocator, builtin);
        try std.testing.expectEqualDeep(
            crypto.CryptoInstruction{ .op_name = "OP_SIZE" },
            list.items[0],
        );
        try std.testing.expectEqualDeep(
            crypto.CryptoInstruction{ .push_int = 64 },
            list.items[1],
        );
        try std.testing.expectEqualDeep(
            crypto.CryptoInstruction{ .op_name = "OP_NUMEQUALVERIFY" },
            list.items[2],
        );
    }
}

test "CL-BUG-095: ecEncodeCompressed reads parity from a FIXED offset" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(crypto.CryptoInstruction) = .empty;
    defer list.deinit(allocator);
    try crypto.appendBuiltinInstructions(&list, allocator, .ec_encode_compressed);

    try std.testing.expectEqualDeep(crypto.CryptoInstruction{ .op_name = "OP_SIZE" }, list.items[0]);
    try std.testing.expectEqualDeep(crypto.CryptoInstruction{ .push_int = 64 }, list.items[1]);
    try std.testing.expectEqualDeep(crypto.CryptoInstruction{ .op_name = "OP_NUMEQUALVERIFY" }, list.items[2]);
    try std.testing.expectEqualDeep(crypto.CryptoInstruction{ .push_int = 32 }, list.items[3]);
    try std.testing.expectEqualDeep(crypto.CryptoInstruction{ .op_name = "OP_SPLIT" }, list.items[4]);
    // y[31], not "the last byte of whatever arrived".
    try std.testing.expectEqualDeep(crypto.CryptoInstruction{ .push_int = 31 }, list.items[5]);
    try std.testing.expectEqualDeep(crypto.CryptoInstruction{ .op_name = "OP_SPLIT" }, list.items[6]);
    try std.testing.expectEqualDeep(crypto.CryptoInstruction{ .op_name = "OP_NIP" }, list.items[7]);
    // The OP_SIZE/1/OP_SUB last-byte walk is GONE — that is the parity-flip.
    try std.testing.expectEqual(@as(?usize, null), findInstruction(list.items, "OP_SUB"));
}

// ---------------------------------------------------------------------------
// NIST P-256 / P-384 — nist_ec_emitters
// ---------------------------------------------------------------------------

test "CL-BUG-095: p256/p384 negate verify their curve-specific widths" {
    var p256 = try nist.buildBuiltinOps(std.testing.allocator, .p256_negate);
    defer p256.deinit();
    try expectLenVerifyAt(p256.ops, 0, 64);

    var p384 = try nist.buildBuiltinOps(std.testing.allocator, .p384_negate);
    defer p384.deinit();
    // 96, not 64: a P384Point is 2*48 bytes. A shared constant here would let a
    // 64-byte blob through as a P-384 point.
    try expectLenVerifyAt(p384.ops, 0, 96);
}

test "CL-BUG-095: p256/p384 onCurve clamp and AND the flag in" {
    var p256 = try nist.buildBuiltinOps(std.testing.allocator, .p256_on_curve);
    defer p256.deinit();
    try expectClampGateAtHead(p256.ops, 64);
    try expectLenVerifyAt(p256.ops, 9, 64);
    try expectOpcode(p256.ops[p256.ops.len - 1], "OP_BOOLAND");

    var p384 = try nist.buildBuiltinOps(std.testing.allocator, .p384_on_curve);
    defer p384.deinit();
    try expectClampGateAtHead(p384.ops, 96);
    try expectLenVerifyAt(p384.ops, 9, 96);
    try expectOpcode(p384.ops[p384.ops.len - 1], "OP_BOOLAND");
}

test "CL-BUG-095: p256/p384 encodeCompressed verify width and fix the offset" {
    const cases = .{
        .{ registry.CryptoBuiltin.p256_encode_compressed, @as(i64, 64), @as(i64, 32), @as(i64, 31) },
        .{ registry.CryptoBuiltin.p384_encode_compressed, @as(i64, 96), @as(i64, 48), @as(i64, 47) },
    };
    inline for (cases) |c| {
        var bundle = try nist.buildBuiltinOps(std.testing.allocator, c[0]);
        defer bundle.deinit();
        try expectLenVerifyAt(bundle.ops, 0, c[1]);
        try expectPushInt(bundle.ops[3], c[2]);
        try expectOpcode(bundle.ops[4], "OP_SPLIT");
        try expectPushInt(bundle.ops[5], c[3]);
        try expectOpcode(bundle.ops[6], "OP_SPLIT");
        try expectOpcode(bundle.ops[7], "OP_NIP");
        try std.testing.expectEqual(@as(usize, 0), countTopLevelOpcode(bundle.ops, "OP_SUB"));
    }
}

test "CL-BUG-095: verifyECDSA decomposes the decompressed pubkey under a gate" {
    // verifyECDSA_P256/P384 reach cDecomposePoint through the ladder, so the
    // gate arrives for free — pin that it is actually there, since this is the
    // path an attacker reaches with a caller-supplied signature and pubkey.
    inline for (.{
        .{ registry.CryptoBuiltin.verify_ecdsa_p256, @as(i64, 64) },
        .{ registry.CryptoBuiltin.verify_ecdsa_p384, @as(i64, 96) },
    }) |c| {
        var bundle = try nist.buildBuiltinOps(std.testing.allocator, c[0]);
        defer bundle.deinit();
        try std.testing.expect(countLenVerifies(bundle.ops, c[1]) > 0);
    }
}
