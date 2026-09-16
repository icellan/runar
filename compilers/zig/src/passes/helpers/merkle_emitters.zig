//! Merkle proof codegen — Merkle root computation for Bitcoin Script.
//!
//! Follows the ec_emitters.zig / babybear_emitters.zig pattern: self-contained
//! module imported by stack_lower.zig.
//!
//! Provides two variants:
//! - merkleRootSha256: uses OP_SHA256 (single SHA-256, used by FRI/STARK)
//! - merkleRootHash256: uses OP_HASH256 (double SHA-256, standard Bitcoin Merkle)
//!
//! The depth parameter must be a compile-time constant because the loop is
//! unrolled at compile time (Bitcoin Script has no loops).
//!
//! Stack convention:
//!   Input:  [..., leaf(32B), proof(depth*32 bytes), index(bigint)]
//!   Output: [..., root(32B)]
//!
//! Algorithm per level i (0 to depth-1):
//!   1. Extract sibling_i from proof (split first 32 bytes)
//!   2. Compute direction: (index >> i) & 1
//!   3. If direction=1: hash(sibling || current), else hash(current || sibling)
//!   4. Result becomes current for next level

const std = @import("std");
const ec = @import("ec_emitters.zig");

const Allocator = std.mem.Allocator;
const StackOp = ec.StackOp;
const StackIf = ec.StackIf;
const PushValue = ec.PushValue;
const EcOpBundle = ec.EcOpBundle;

pub const MerkleBuiltin = enum {
    merkle_root_sha256,
    merkle_root_hash256,
};

/// Build StackOps for Merkle root computation.
/// `depth` must be a compile-time constant between 1 and 64.
/// R-120: the `2^depth` operand of the index-domain gate.
///
/// `depth` runs to 64 for the SHA-256 Merkle builtins, and 2^63 / 2^64 do not
/// fit the `integer: i64` push variant, so those two land on
/// `big_int_decimal` — which `emitScriptNumberFromDecimal` encodes to the same
/// minimal script number the other six tiers produce from their bignums.
/// Everything at or below 2^62 stays on the integer variant, so the fixtures
/// that exist today are byte-identical by the ordinary path.
fn indexBoundPush(depth: u32) StackOp {
    return switch (depth) {
        63 => .{ .push = .{ .big_int_decimal = "9223372036854775808" } },
        64 => .{ .push = .{ .big_int_decimal = "18446744073709551616" } },
        else => .{ .push = .{ .integer = @as(i64, 1) << @as(u6, @intCast(depth)) } },
    };
}

pub fn buildBuiltinOps(allocator: Allocator, builtin: MerkleBuiltin, depth: u32) !EcOpBundle {
    if (depth < 1 or depth > 64) return error.InvalidDepth;

    const hash_op: []const u8 = switch (builtin) {
        .merkle_root_sha256 => "OP_SHA256",
        .merkle_root_hash256 => "OP_HASH256",
    };

    var ops: std.ArrayListUnmanaged(StackOp) = .empty;
    errdefer {
        ec.deinitOpsRecursive(allocator, ops.items);
        ops.deinit(allocator);
    }

    // Stack at entry: [leaf, proof, index]
    // R-120: bound the index BEFORE walking the tree. Bit i is read at level i,
    // nothing above bit depth-1 is ever consulted, and the index is then
    // dropped, so index, index + 2^depth and any NEGATIVE index walk the same
    // path and produce the same root (measured at depth 2: 1, 5, 9, 1025 and
    // -1 all returned 5306f72f...6ee0f336). ABORT, not clamp: these are VALUE
    // builtins. OP_WITHIN is half-open, so this is exactly 0 <= index < 2^depth.
    try ops.append(allocator, .{ .opcode = "OP_DUP" });
    try ops.append(allocator, .{ .push = .{ .integer = 0 } });
    try ops.append(allocator, indexBoundPush(depth));
    try ops.append(allocator, .{ .opcode = "OP_WITHIN" });
    try ops.append(allocator, .{ .opcode = "OP_VERIFY" });

    // Unroll the loop for each level
    for (0..depth) |i| {
        // Stack: [current, proof, index]

        // --- Step 1: Extract sibling from proof ---
        // Roll proof to top (swap index and proof)
        // Stack: [current, proof, index]
        // After roll(1): [current, index, proof]
        try ops.append(allocator, .{ .swap = {} });

        // Split proof at 32 to get sibling
        // Stack: [current, index, proof]
        try ops.append(allocator, .{ .push = .{ .integer = 32 } });
        try ops.append(allocator, .{ .opcode = "OP_SPLIT" });
        // Stack: [current, index, sibling(32B), rest_proof]

        // Move rest_proof out of the way (to alt stack)
        try ops.append(allocator, .{ .opcode = "OP_TOALTSTACK" });
        // Stack: [current, index, sibling]  Alt: [rest_proof]

        // --- Step 2: Get direction bit ---
        // Bring index to top (it's at depth 1)
        try ops.append(allocator, .{ .swap = {} });
        // Stack: [current, sibling, index]

        // Compute direction bit: (index / 2^i) % 2
        try ops.append(allocator, .{ .dup = {} });
        // Stack: [current, sibling, index, index]
        if (i == 1) {
            // Single-bit shift: OP_2DIV (no push needed)
            try ops.append(allocator, .{ .opcode = "OP_2DIV" });
        } else if (i > 1) {
            // Multi-bit shift: push shift amount, OP_RSHIFTNUM
            try ops.append(allocator, .{ .push = .{ .integer = @as(i64, @intCast(i)) } });
            try ops.append(allocator, .{ .opcode = "OP_RSHIFTNUM" });
        }
        try ops.append(allocator, .{ .push = .{ .integer = 2 } });
        try ops.append(allocator, .{ .opcode = "OP_MOD" });
        // Stack: [current, sibling, index, direction_bit]

        // Move index below for safekeeping
        // Current stack: [current, sibling, index, direction_bit]
        try ops.append(allocator, .{ .swap = {} });
        // Stack: [current, sibling, direction_bit, index]
        try ops.append(allocator, .{ .opcode = "OP_TOALTSTACK" });
        // Stack: [current, sibling, direction_bit]  Alt: [rest_proof, index]

        // --- Step 3: Conditional swap + concatenate + hash ---
        // Rearrange to get current and sibling adjacent with direction_bit:
        // Roll current to top:
        try ops.append(allocator, .{ .rot = {} });
        // Stack: [sibling, direction_bit, current]
        try ops.append(allocator, .{ .rot = {} });
        // Stack: [direction_bit, current, sibling]

        // Now: if direction_bit=1, swap current and sibling before CAT
        try ops.append(allocator, .{ .rot = {} });
        // Stack: [current, sibling, direction_bit]

        // Build the if-then block: if direction=1, swap
        const then_ops = try allocator.alloc(StackOp, 1);
        then_ops[0] = .{ .swap = {} };

        try ops.append(allocator, .{ .@"if" = .{
            .then = then_ops,
            .@"else" = null,
        } });
        // Stack: [a, b] where a||b is the correct concatenation order

        try ops.append(allocator, .{ .opcode = "OP_CAT" });
        try ops.append(allocator, .{ .opcode = hash_op });
        // Stack: [new_current]

        // Restore index and rest_proof from alt stack
        try ops.append(allocator, .{ .opcode = "OP_FROMALTSTACK" });
        // Stack: [new_current, index]
        try ops.append(allocator, .{ .opcode = "OP_FROMALTSTACK" });
        // Stack: [new_current, index, rest_proof]

        // Reorder to [new_current, rest_proof, index]
        try ops.append(allocator, .{ .swap = {} });
        // Stack: [new_current, rest_proof, index]
    }

    // Final stack: [root, empty_proof, index]
    try ops.append(allocator, .{ .drop = {} }); // drop index

    // R-120: the proof remainder must be EMPTY. Each level OP_SPLITs 32 bytes
    // off the front; what was left after the last level used to be dropped
    // unexamined, so a blob of 32*depth + k bytes verified for every k >= 0
    // and yielded the same root. The SHORT direction already aborted inside
    // OP_SPLIT.
    try ops.append(allocator, .{ .opcode = "OP_SIZE" });
    try ops.append(allocator, .{ .push = .{ .integer = 0 } });
    try ops.append(allocator, .{ .opcode = "OP_NUMEQUALVERIFY" });
    try ops.append(allocator, .{ .drop = {} }); // drop the (now empty) proof
    // Stack: [root]

    const result_ops = try ops.toOwnedSlice(allocator);
    return .{
        .allocator = allocator,
        .ops = result_ops,
        .owned_bytes = &.{},
    };
}

// ===========================================================================
// Tests
// ===========================================================================

test "buildBuiltinOps produces ops for sha256 merkle" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .merkle_root_sha256, 4);
    defer bundle.deinit();
    try std.testing.expect(bundle.ops.len > 0);

    // Should contain OP_SHA256, OP_SPLIT, OP_CAT
    var has_sha256 = false;
    var has_split = false;
    var has_cat = false;
    for (bundle.ops) |op| {
        switch (op) {
            .opcode => |name| {
                if (std.mem.eql(u8, name, "OP_SHA256")) has_sha256 = true;
                if (std.mem.eql(u8, name, "OP_SPLIT")) has_split = true;
                if (std.mem.eql(u8, name, "OP_CAT")) has_cat = true;
            },
            else => {},
        }
    }
    try std.testing.expect(has_sha256);
    try std.testing.expect(has_split);
    try std.testing.expect(has_cat);
}

test "buildBuiltinOps produces ops for hash256 merkle" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .merkle_root_hash256, 2);
    defer bundle.deinit();

    var has_hash256 = false;
    for (bundle.ops) |op| {
        switch (op) {
            .opcode => |name| {
                if (std.mem.eql(u8, name, "OP_HASH256")) has_hash256 = true;
            },
            else => {},
        }
    }
    try std.testing.expect(has_hash256);
}

test "buildBuiltinOps rejects invalid depth" {
    const allocator = std.testing.allocator;

    const result0 = buildBuiltinOps(allocator, .merkle_root_sha256, 0);
    try std.testing.expectError(error.InvalidDepth, result0);

    const result65 = buildBuiltinOps(allocator, .merkle_root_sha256, 65);
    try std.testing.expectError(error.InvalidDepth, result65);
}

test "merkle depth=1 has expected structure" {
    const allocator = std.testing.allocator;
    var bundle = try buildBuiltinOps(allocator, .merkle_root_sha256, 1);
    defer bundle.deinit();
    // R-120 changed the epilogue. It used to be two bare drops (index, then the
    // proof remainder, unexamined); the remainder is now PROVED empty first, so
    // the tail is:
    //
    //     drop                 -- index
    //     OP_SIZE <0> OP_NUMEQUALVERIFY
    //     drop                 -- the (now proved empty) proof
    //
    // and the prologue gained OP_DUP <0> <2^depth> OP_WITHIN OP_VERIFY.
    const len = bundle.ops.len;
    try std.testing.expect(len >= 6);
    try std.testing.expect(std.meta.activeTag(bundle.ops[len - 1]) == .drop);
    try std.testing.expect(std.mem.eql(u8, bundle.ops[len - 2].opcode, "OP_NUMEQUALVERIFY"));
    try std.testing.expect(std.meta.activeTag(bundle.ops[len - 3]) == .push);
    try std.testing.expect(std.mem.eql(u8, bundle.ops[len - 4].opcode, "OP_SIZE"));
    try std.testing.expect(std.meta.activeTag(bundle.ops[len - 5]) == .drop);

    // The index-domain gate is the first thing emitted.
    try std.testing.expect(std.mem.eql(u8, bundle.ops[0].opcode, "OP_DUP"));
    try std.testing.expect(std.meta.activeTag(bundle.ops[1]) == .push);
    try std.testing.expect(std.meta.activeTag(bundle.ops[2]) == .push);
    try std.testing.expect(std.mem.eql(u8, bundle.ops[3].opcode, "OP_WITHIN"));
    try std.testing.expect(std.mem.eql(u8, bundle.ops[4].opcode, "OP_VERIFY"));
}
