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
///
/// N-254: `StackOp.roll` is a single logical op whose own lowering
/// (`emitEcStackOp`'s `.roll` case in stack_lower.zig) ALREADY emits the
/// depth push before `OP_ROLL` -- every other emitter module (ec_emitters,
/// koalabear_emitters, babybear_emitters, bn254_emitters, nist_ec_emitters)
/// appends bare `.{ .roll = depth }` for exactly that reason. This function
/// used to append an extra explicit `.push` first, so each roll it emitted
/// became `PUSH d, PUSH d, OP_ROLL` instead of `PUSH d, OP_ROLL` -- one dead
/// byte of push data per roll. Invisible while `merkleRootPoseidon2KB` was
/// unreachable (the builtin_map key bug); surfaced as an 8-byte divergence
/// from Go once the key was fixed (8 rolls of depth 15 in the per-level
/// conditional swap, at depth 1 alone).
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
    try ops.append(allocator, .{ .roll = d });
}

/// buildPoseidon2MerkleRootOps emits Poseidon2 Merkle root computation.
///
/// Stack in:  [..., leaf(8 elems), proof(depth*8 elems), index]
/// Stack out: [..., root(8 elems)]
///
/// depth is a compile-time constant (unrolled loop). Must be in [1, 32].
/// Higher depths produce quadratically larger scripts due to roll operations.
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

    // R-120: bound the index BEFORE walking the tree — the same hole and the same
    // gate as merkle_emitters.zig. No proof-remainder twin here: the siblings
    // are separate stack items, not one splittable blob.
    try ops.append(allocator, .{ .opcode = "OP_DUP" });
    try ops.append(allocator, .{ .push = .{ .integer = 0 } });
    try ops.append(allocator, indexBoundPush(depth));
    try ops.append(allocator, .{ .opcode = "OP_WITHIN" });
    try ops.append(allocator, .{ .opcode = "OP_VERIFY" });

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

        // OP_IF: if bit==1, swap the two groups of 8 elements. `.roll = 15`
        // alone is correct (see `emitRoll`'s N-254 note): `emitEcStackOp`
        // emits the depth push itself.
        var then_ops: std.ArrayListUnmanaged(StackOp) = .empty;
        for (0..8) |_| {
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

/// poseidon2_root_pack_base is the radix used to pack the 8-element Poseidon2
/// KoalaBear root into a single Script integer. Every KoalaBear element is
/// < p = 2^31 - 2^24 + 1 < 2^32, so base-2^32 positional packing is INJECTIVE
/// over the whole root: two roots pack to the same integer if and only if all
/// eight of their elements are equal.
const poseidon2_root_pack_base: i64 = 1 << 32;

/// buildPoseidon2RootPackOps folds the 8-element Poseidon2 KoalaBear root
/// that `buildPoseidon2MerkleRootOps` leaves on the stack into ONE Script
/// integer.
///
/// Stack in:  [..., root_0, root_1, ..., root_7]   (root_7 on top)
/// Stack out: [..., packed]
///
/// where packed = sum(root_i * (2^32)^i) -- root_7 is the most significant
/// limb and root_0 the least significant.
///
/// WHY THIS EXISTS (CL-BUG-099 / R-056). The Rúnar type system has no
/// multi-word return type: `merkleRootPoseidon2KB` is declared to return one
/// `bigint`. Reconciling the eight-element result with seven OP_NIPs would
/// keep root_7 and discard root_0..root_6, so a contract writing
/// `assert(merkleRootPoseidon2KB(...) === expected)` would authenticate
/// against a SINGLE ~31-bit field element. Packing keeps every limb
/// load-bearing: equality on the packed value is equality on all eight
/// limbs. Direct port of Go's `EmitPoseidon2RootPack`
/// (codegen/poseidon2_merkle.go), matched the same way by the Rust (N-237)
/// and Ruby (N-248) tiers.
///
/// This is deliberately NOT folded into `buildPoseidon2MerkleRootOps`: Go's
/// SP1 FRI verifier (Go-only) consumes the eight raw limbs directly.
pub fn buildPoseidon2RootPackOps(allocator: Allocator) !EcOpBundle {
    var ops: std.ArrayListUnmanaged(StackOp) = .empty;
    errdefer {
        ec.deinitOpsRecursive(allocator, ops.items);
        ops.deinit(allocator);
    }

    // Horner from the top of the stack down: after step k the top holds
    // sum_{j=7-k..7} root_j * (2^32)^(j-(7-k)), and root_(6-k) sits directly
    // below it, so OP_ADD folds in the next limb with no rolls at all.
    for (0..7) |_| {
        try ops.append(allocator, .{ .push = .{ .integer = poseidon2_root_pack_base } });
        try ops.append(allocator, .{ .opcode = "OP_MUL" });
        try ops.append(allocator, .{ .opcode = "OP_ADD" });
    }

    const ops_slice = try ops.toOwnedSlice(allocator);
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

// N-254 / CL-BUG-099: `buildPoseidon2RootPackOps` must emit 7 repetitions of
// (push 2^32, OP_MUL, OP_ADD) -- the Horner fold that binds all eight root
// limbs into the comparison, port of Go's `EmitPoseidon2RootPack`. Before
// this port, `stack_lower.zig`'s caller reconciled the 8-element result with
// seven OP_NIPs, discarding root_0..root_6 (CL-BUG-099). This test proves the
// fold shape in isolation; it does not prove the caller actually uses it
// (that is pinned at the lowering level in
// `src/tests/n254_merkle_root_poseidon2kb_ir_test.zig`) nor byte-identity
// with Go (that is the `--ir` leg of
// conformance/go-only-parity/go-only-parity.test.ts).
test "buildPoseidon2RootPackOps emits 7x (push 2^32, mul, add)" {
    const allocator = std.testing.allocator;
    var bundle = try buildPoseidon2RootPackOps(allocator);
    defer bundle.deinit();

    try std.testing.expectEqual(@as(usize, 21), bundle.ops.len);
    var i: usize = 0;
    while (i < 7) : (i += 1) {
        try std.testing.expectEqual(
            StackOp{ .push = .{ .integer = 1 << 32 } },
            bundle.ops[i * 3],
        );
        try std.testing.expectEqualStrings("OP_MUL", bundle.ops[i * 3 + 1].opcode);
        try std.testing.expectEqualStrings("OP_ADD", bundle.ops[i * 3 + 2].opcode);
    }
}
