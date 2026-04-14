//! Poseidon2 Merkle proof codegen -- Merkle root computation for Bitcoin Script
//! using Poseidon2 KoalaBear compression.
//!
//! Port of compilers/go/codegen/poseidon2_merkle.go.
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
//! Where D = depth.

use super::poseidon2_koalabear::emit_poseidon2_kb_compress;
use super::stack::{PushValue, StackOp};

/// emit_roll emits a ROLL operation for a given depth.
fn emit_roll(emit: &mut dyn FnMut(StackOp), d: usize) {
    if d == 0 {
        return;
    }
    if d == 1 {
        emit(StackOp::Swap);
        return;
    }
    if d == 2 {
        emit(StackOp::Rot);
        return;
    }
    emit(StackOp::Push(PushValue::Int(d as i128)));
    emit(StackOp::Roll { depth: d });
}

/// emit_poseidon2_merkle_root emits Poseidon2 Merkle root computation.
///
/// Stack in:  [..., leaf(8 elems), proof(depth*8 elems), index]
/// Stack out: [..., root(8 elems)]
///
/// depth is a compile-time constant (unrolled loop). Must be in [1, 32].
pub fn emit_poseidon2_merkle_root(emit: &mut dyn FnMut(StackOp), depth: usize) {
    assert!(
        depth >= 1 && depth <= 32,
        "emit_poseidon2_merkle_root: depth must be in [1, 32], got {}",
        depth
    );

    // Strategy overview:
    //
    // At each level i, the stack is:
    //   [..., current(8), sib_i(8), future_sibs((depth-i-1)*8), index]
    //
    // 1. Save index to alt-stack (it stays there for the whole level).
    // 2. Compute direction bit from index (DUP before saving).
    // 3. Roll current(8)+sib_i(8) above future_sibs so they become the top 16.
    // 4. Retrieve bit from alt, do conditional swap.
    // 5. Poseidon2 compress (top 16 -> top 8).
    // 6. Roll new_current(8) back below future_sibs.
    // 7. Restore index from alt.
    //
    // At the end, drop index and leave root(8) on the stack.

    for i in 0..depth {
        // Stack: [..., current(8), sib_i(8), future_sibs(F*8), index]
        // where F = depth - i - 1 (number of future sibling groups).
        let future_elems = (depth - i - 1) * 8;

        // ----- Compute direction bit and save index + bit to alt -----
        emit(StackOp::Dup); // dup index
        if i > 0 {
            if i == 1 {
                emit(StackOp::Opcode("OP_2DIV".into()));
            } else {
                emit(StackOp::Push(PushValue::Int(i as i128)));
                emit(StackOp::Opcode("OP_RSHIFTNUM".into()));
            }
        }
        emit(StackOp::Push(PushValue::Int(2)));
        emit(StackOp::Opcode("OP_MOD".into()));
        // Stack: [..., current(8), sib_i(8), future_sibs, index, bit]

        // Save bit then index to alt-stack
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // save bit
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // save index
        // Stack: [..., current(8), sib_i(8), future_sibs]
        // Alt (top->bottom): [index, bit]

        // ----- Roll current+sib_i above future_sibs -----
        if future_elems > 0 {
            let roll_depth = future_elems + 15;
            for _ in 0..16 {
                emit_roll(emit, roll_depth);
            }
        }
        // Stack: [..., future_sibs, current(8), sib_i(8)]

        // ----- Retrieve bit and conditional swap -----
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // get index
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // get bit
        // Stack: [..., future_sibs, current(8), sib_i(8), index, bit]

        // Save index back to alt
        emit(StackOp::Swap);
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // save index
        // Stack: [..., future_sibs, current(8), sib_i(8), bit]
        // Alt: [index]

        // OP_IF consumes bit. If bit==1, swap current and sibling groups.
        emit(StackOp::If {
            then_ops: vec![
                // bit==1: swap the two groups of 8 elements.
                // 8x roll(15) moves each element of the bottom group (current)
                // above the top group (sibling), producing [sibling(8), current(8)].
                StackOp::Push(PushValue::Int(15)),
                StackOp::Roll { depth: 15 },
                StackOp::Push(PushValue::Int(15)),
                StackOp::Roll { depth: 15 },
                StackOp::Push(PushValue::Int(15)),
                StackOp::Roll { depth: 15 },
                StackOp::Push(PushValue::Int(15)),
                StackOp::Roll { depth: 15 },
                StackOp::Push(PushValue::Int(15)),
                StackOp::Roll { depth: 15 },
                StackOp::Push(PushValue::Int(15)),
                StackOp::Roll { depth: 15 },
                StackOp::Push(PushValue::Int(15)),
                StackOp::Roll { depth: 15 },
                StackOp::Push(PushValue::Int(15)),
                StackOp::Roll { depth: 15 },
            ],
            // bit==0: already in correct order [current(8), sibling(8)]
            else_ops: vec![],
        });
        // Stack: [..., future_sibs, left(8), right(8)]

        // ----- Poseidon2 compress -----
        emit_poseidon2_kb_compress(emit);
        // Stack: [..., future_sibs, new_current(8)]

        // ----- Roll new_current back below future_sibs -----
        if future_elems > 0 {
            let roll_depth = 7 + future_elems;
            for _ in 0..future_elems {
                emit_roll(emit, roll_depth);
            }
        }
        // Stack: [..., new_current(8), future_sibs]

        // ----- Restore index from alt -----
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        // Stack: [..., new_current(8), future_sibs, index]
    }

    // After all levels: [..., root(8), index]
    emit(StackOp::Drop);
    // Stack: [..., root_0..root_7]
}
