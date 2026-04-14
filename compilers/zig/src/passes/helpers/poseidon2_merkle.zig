//! Poseidon2 Merkle proof codegen — Merkle root computation for Bitcoin Script
//! using Poseidon2 KoalaBear compression.
//!
//! Follows the merkle_emitters.zig pattern: self-contained module imported by
//! stack_lower.zig.
//!
//! Unlike the SHA-256 Merkle variants (which use 32-byte hash digests),
//! Poseidon2 KoalaBear Merkle trees represent each node as 8 KoalaBear field
//! elements. Compression feeds two 8-element digests (16 elements total) into
//! the Poseidon2 permutation and takes the first 8 elements of the output.
//!
//! The depth parameter must be a compile-time constant because the loop is
//! unrolled at compile time (Bitcoin Script has no loops).
//!
//! Stack convention:
//!   Input:  [..., leaf_0..leaf_7, sib0_0..sib0_7, ..., sib(D-1)_0..sib(D-1)_7, index]
//!   Output: [..., root_0..root_7]
//!
//! Where D = depth. The leaf is 8 field elements, each sibling is 8 field
//! elements, and index is a bigint whose bits determine left/right ordering at
//! each tree level.

const std = @import("std");
const ec = @import("ec_emitters.zig");
const p2kb = @import("poseidon2_koalabear.zig");

const Allocator = std.mem.Allocator;
const StackOp = ec.StackOp;
const StackIf = ec.StackIf;
const PushValue = ec.PushValue;
const EcOpBundle = ec.EcOpBundle;

/// emitRoll appends a ROLL operation for a given depth to an ops list.
fn emitRoll(ops: *std.ArrayListUnmanaged(StackOp), allocator: Allocator, d: u32) !void {
    if (d == 0) return;
    if (d == 1) {
        try ops.append(allocator, .{ .swap = {} });
        return;
    }
    if (d == 2) {
        try ops.append(allocator, .{ .rot = {} });
        return;
    }
    try ops.append(allocator, .{ .push = .{ .integer = @intCast(d) } });
    try ops.append(allocator, .{ .roll = d });
}

/// buildPoseidon2MerkleRootOps emits Poseidon2 Merkle root computation.
///
/// Stack in:  [..., leaf(8 elems), proof(depth*8 elems), index]
/// Stack out: [..., root(8 elems)]
///
/// depth is a compile-time constant (unrolled loop). Must be in [1, 32].
/// Higher depths produce quadratically larger scripts due to roll operations.
pub fn buildPoseidon2MerkleRootOps(allocator: Allocator, depth: u32) !EcOpBundle {
    if (depth < 1 or depth > 32) return error.InvalidDepth;

    var ops: std.ArrayListUnmanaged(StackOp) = .empty;
    errdefer {
        ec.deinitOpsRecursive(allocator, ops.items);
        ops.deinit(allocator);
    }

    // Strategy overview:
    //
    // At each level i, the stack is:
    //   [..., current(8), sib_i(8), future_sibs((depth-i-1)*8), index]
    //
    // 1. Dup index, compute direction bit ((index >> i) % 2).
    // 2. Save bit then index to alt-stack (bit on top of alt).
    // 3. Roll current(8)+sib_i(8) above future_sibs so they become the top 16.
    // 4. Retrieve index from alt, retrieve bit from alt, do conditional swap.
    // 5. Poseidon2 compress (top 16 → top 8).
    // 6. Roll new_current(8) back below future_sibs.
    // 7. Restore index from alt.

    for (0..depth) |i| {
        // Stack: [..., current(8), sib_i(8), future_sibs(F*8), index]
        // F = depth - i - 1
        const future_elems: u32 = @intCast((depth - @as(u32, @intCast(i)) - 1) * 8);

        // ----- Compute direction bit and save index + bit to alt -----
        try ops.append(allocator, .{ .opcode = "OP_DUP" }); // dup index
        if (i > 0) {
            if (i == 1) {
                try ops.append(allocator, .{ .opcode = "OP_2DIV" });
            } else {
                try ops.append(allocator, .{ .push = .{ .integer = @intCast(i) } });
                try ops.append(allocator, .{ .opcode = "OP_RSHIFTNUM" });
            }
        }
        try ops.append(allocator, .{ .push = .{ .integer = 2 } });
        try ops.append(allocator, .{ .opcode = "OP_MOD" });
        // Stack: [..., current(8), sib_i(8), future_sibs, index, bit]

        // Save bit then index to alt-stack.
        try ops.append(allocator, .{ .opcode = "OP_TOALTSTACK" }); // save bit
        try ops.append(allocator, .{ .opcode = "OP_TOALTSTACK" }); // save index
        // Alt (top→bottom): [index, bit]

        // ----- Roll current+sib_i above future_sibs -----
        if (future_elems > 0) {
            const roll_depth: u32 = future_elems + 15;
            for (0..16) |_| {
                try emitRoll(&ops, allocator, roll_depth);
            }
        }
        // Stack: [..., future_sibs, current(8), sib_i(8)]

        // ----- Retrieve bit and conditional swap -----
        try ops.append(allocator, .{ .opcode = "OP_FROMALTSTACK" }); // get index
        try ops.append(allocator, .{ .opcode = "OP_FROMALTSTACK" }); // get bit
        // Stack: [..., future_sibs, current(8), sib_i(8), index, bit]

        // Save index back to alt
        try ops.append(allocator, .{ .swap = {} });
        try ops.append(allocator, .{ .opcode = "OP_TOALTSTACK" }); // save index
        // Stack: [..., future_sibs, current(8), sib_i(8), bit]
        // Alt: [index]

        // OP_IF: if bit==1, swap the two groups of 8 elements.
        var then_ops: std.ArrayListUnmanaged(StackOp) = .empty;
        for (0..8) |_| {
            try then_ops.append(allocator, .{ .push = .{ .integer = 15 } });
            try then_ops.append(allocator, .{ .roll = 15 });
        }
        const then_slice = try then_ops.toOwnedSlice(allocator);
        try ops.append(allocator, .{
            .@"if" = .{
                .then = then_slice,
                .@"else" = null,
            },
        });
        // Stack: [..., future_sibs, left(8), right(8)]

        // ----- Poseidon2 compress -----
        // Build compress ops and append inline.
        var compress_bundle = try p2kb.buildCompressBundleOps(allocator);
        defer compress_bundle.deinit();
        try ops.appendSlice(allocator, compress_bundle.ops);
        // Stack: [..., future_sibs, new_current(8)]

        // ----- Roll new_current back below future_sibs -----
        if (future_elems > 0) {
            const roll_depth: u32 = 7 + future_elems;
            for (0..future_elems) |_| {
                try emitRoll(&ops, allocator, roll_depth);
            }
        }
        // Stack: [..., new_current(8), future_sibs]

        // ----- Restore index from alt -----
        try ops.append(allocator, .{ .opcode = "OP_FROMALTSTACK" });
        // Stack: [..., new_current(8), future_sibs, index]
    }

    // After all levels: [..., root(8), index]
    try ops.append(allocator, .{ .drop = {} });
    // Stack: [..., root_0..root_7]

    const ops_slice = try ops.toOwnedSlice(allocator);
    // owned_bytes is empty for this module — all strings are compile-time literals.
    const empty_owned = try allocator.alloc([]u8, 0);
    return .{
        .allocator = allocator,
        .ops = ops_slice,
        .owned_bytes = empty_owned,
    };
}

// ===========================================================================
// Tests
// ===========================================================================

test "buildPoseidon2MerkleRootOps depth=1 produces ops" {
    const allocator = std.testing.allocator;
    var bundle = try buildPoseidon2MerkleRootOps(allocator, 1);
    defer bundle.deinit();
    try std.testing.expect(bundle.ops.len > 10);
}

test "buildPoseidon2MerkleRootOps depth=4 produces more ops than depth=1" {
    const allocator = std.testing.allocator;
    var bundle1 = try buildPoseidon2MerkleRootOps(allocator, 1);
    defer bundle1.deinit();
    var bundle4 = try buildPoseidon2MerkleRootOps(allocator, 4);
    defer bundle4.deinit();
    try std.testing.expect(bundle4.ops.len > bundle1.ops.len);
}

test "buildPoseidon2MerkleRootOps invalid depth returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidDepth, buildPoseidon2MerkleRootOps(allocator, 0));
    try std.testing.expectError(error.InvalidDepth, buildPoseidon2MerkleRootOps(allocator, 33));
}

test "buildPoseidon2MerkleRootOps depth=1 ends with drop" {
    const allocator = std.testing.allocator;
    var bundle = try buildPoseidon2MerkleRootOps(allocator, 1);
    defer bundle.deinit();
    const last = bundle.ops[bundle.ops.len - 1];
    try std.testing.expectEqual(StackOp{ .drop = {} }, last);
}
