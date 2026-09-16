//! Merkle proof codegen -- Merkle root computation for Bitcoin Script.
//!
//! Port of packages/runar-compiler/src/passes/merkle-codegen.ts.
//! Follows the ec.rs / babybear.rs pattern: self-contained module imported by stack.rs.
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

use num_bigint::BigInt;
use super::stack::{PushValue, StackOp};

/// Compute Merkle root using SHA-256.
/// Stack in: [..., leaf(32B), proof(depth*32B), index(bigint)]
/// Stack out: [..., root(32B)]
pub fn emit_merkle_root_sha256(emit: &mut dyn FnMut(StackOp), depth: usize) {
    emit_merkle_root(emit, depth, "OP_SHA256");
}

/// Compute Merkle root using Hash256 (double SHA-256).
/// Stack in: [..., leaf(32B), proof(depth*32B), index(bigint)]
/// Stack out: [..., root(32B)]
pub fn emit_merkle_root_hash256(emit: &mut dyn FnMut(StackOp), depth: usize) {
    emit_merkle_root(emit, depth, "OP_HASH256");
}

/// Core Merkle root computation.
///
/// Stack layout at entry: [leaf, proof, index]
///
/// For each level i from 0 to depth-1:
///   Stack before iteration: [current, remaining_proof, index]
///
///   1. Get sibling: split remaining_proof at offset 32
///      -> [current, sibling, rest_proof, index]
///
///   2. Get direction bit: (index >> i) & 1
///      We keep index on the stack and use it with shifting.
///
///   3. OP_IF (direction=1): swap current and sibling before concatenating
///
///   4. OP_CAT + hash -> new current
///
/// After all levels: [root, empty_proof, index]
/// Clean up: drop empty proof and index, leave root.
fn emit_merkle_root(emit: &mut dyn FnMut(StackOp), depth: usize, hash_op: &str) {
    // Stack: [leaf, proof, index]

    // R-120: bound the index BEFORE walking the tree.
    //
    // The loop below reads bit i of the index at level i and never looks above bit
    // depth-1, then drops the index unexamined. So index, index + 2^depth,
    // index + 2^40 and any NEGATIVE index walk the same path and produce the same
    // root: measured at depth 2, indices 1, 5, 9, 1025 and -1 all returned
    // 5306f72f...6ee0f336. ABORT rather than clamp -- these are VALUE builtins, and
    // CL-BUG-095 set the policy that predicates clamp and flag while value producers
    // OP_VERIFY. OP_WITHIN is half-open: exactly 0 <= index < 2^depth, and the lower
    // bound is what rejects a negative index.
    emit(StackOp::Opcode("OP_DUP".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(0))));
    emit(StackOp::Push(PushValue::Int(BigInt::from(1) << depth)));
    emit(StackOp::Opcode("OP_WITHIN".into()));
    emit(StackOp::Opcode("OP_VERIFY".into()));

    for i in 0..depth {
        // Stack: [current, proof, index]

        // --- Step 1: Extract sibling from proof ---
        // Roll proof to top: swap index and proof
        // Stack: [current, proof, index]
        // After roll(1): [current, index, proof]
        emit(StackOp::Swap);

        // Split proof at 32 to get sibling
        // Stack: [current, index, proof]
        emit(StackOp::Push(PushValue::Int(BigInt::from(32))));
        emit(StackOp::Opcode("OP_SPLIT".into()));
        // Stack: [current, index, sibling(32B), rest_proof]

        // Move rest_proof out of the way (to alt stack)
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        // Stack: [current, index, sibling]  Alt: [rest_proof]

        // --- Step 2: Get direction bit ---
        // Bring index to top (it's at depth 1)
        emit(StackOp::Swap);
        // Stack: [current, sibling, index]

        // Compute direction bit: (index >> i) & 1
        emit(StackOp::Dup);
        // Stack: [current, sibling, index, index]
        // Extract bit i: Chronicle opcodes: OP_2DIV (i=1), OP_RSHIFTNUM (i>1)
        if i == 1 {
            emit(StackOp::Opcode("OP_2DIV".into()));
        } else if i > 1 {
            emit(StackOp::Push(PushValue::Int(BigInt::from(i as i128))));
            emit(StackOp::Opcode("OP_RSHIFTNUM".into()));
        }
        emit(StackOp::Push(PushValue::Int(BigInt::from(2))));
        emit(StackOp::Opcode("OP_MOD".into()));
        // Stack: [current, sibling, index, direction_bit]

        // Move index below for safekeeping
        // Current stack: [current, sibling, index, direction_bit]
        emit(StackOp::Swap);
        // Stack: [current, sibling, direction_bit, index]
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        // Stack: [current, sibling, direction_bit]  Alt: [rest_proof, index]

        // --- Step 3: Conditional swap + concatenate + hash ---
        // Rearrange to get current and sibling adjacent:
        // Roll current to top:
        emit(StackOp::Rot);
        // Stack: [sibling, direction_bit, current]
        emit(StackOp::Rot);
        // Stack: [direction_bit, current, sibling]

        // Now: if direction_bit=1, swap current and sibling before CAT
        emit(StackOp::Rot);
        // Stack: [current, sibling, direction_bit]

        emit(StackOp::If {
            then_ops: vec![
                // direction = 1: want hash(sibling || current), so swap
                StackOp::Swap,
            ],
            // direction = 0: want hash(current || sibling), already in order
            else_ops: vec![],
        });
        // Stack: [a, b] where a||b is the correct concatenation order

        emit(StackOp::Opcode("OP_CAT".into()));
        emit(StackOp::Opcode(hash_op.into()));
        // Stack: [new_current]

        // Restore index and rest_proof from alt stack
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        // Stack: [new_current, index]
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        // Stack: [new_current, index, rest_proof]

        // Reorder to [new_current, rest_proof, index]
        emit(StackOp::Swap);
        // Stack: [new_current, rest_proof, index]
    }

    // Final stack: [root, empty_proof, index]
    emit(StackOp::Drop); // drop index
    // Stack: [root, rest_proof]

    // R-120: the proof remainder must be EMPTY.
    //
    // Each level OP_SPLITs 32 bytes off the front of the blob; what was left after
    // the last level used to be dropped without ever being looked at, so a proof of
    // 32*depth + k bytes verified for every k >= 0 and produced the same root as the
    // correctly-sized one (measured at depth 2: 64, 65, 96 and 128 bytes all returned
    // 5306f72f...6ee0f336). The SHORT direction was already closed -- OP_SPLIT aborts
    // when the blob runs out.
    emit(StackOp::Opcode("OP_SIZE".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(0))));
    emit(StackOp::Opcode("OP_NUMEQUALVERIFY".into()));
    emit(StackOp::Drop); // drop the (now proved empty) proof
    // Stack: [root]
}
