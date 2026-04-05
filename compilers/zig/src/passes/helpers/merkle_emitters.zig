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
        if (i > 0) {
            const shift: u6 = @intCast(i);
            try ops.append(allocator, .{ .push = .{ .integer = @as(i64, 1) << shift } });
            try ops.append(allocator, .{ .opcode = "OP_DIV" });
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
    // Clean up: drop index and empty proof
    try ops.append(allocator, .{ .drop = {} }); // drop index
    try ops.append(allocator, .{ .drop = {} }); // drop empty proof
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
    // depth=1: one iteration + 2 drops at end
    // Verify we end with two drops
    const len = bundle.ops.len;
    try std.testing.expect(len >= 2);
    try std.testing.expect(std.meta.activeTag(bundle.ops[len - 1]) == .drop);
    try std.testing.expect(std.meta.activeTag(bundle.ops[len - 2]) == .drop);
}
