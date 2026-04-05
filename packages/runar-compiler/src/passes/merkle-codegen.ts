/**
 * Merkle proof codegen — Merkle root computation for Bitcoin Script.
 *
 * Follows the ec-codegen.ts / babybear-codegen.ts pattern: self-contained
 * module imported by 05-stack-lower.ts.
 *
 * Provides two variants:
 * - merkleRootSha256: uses OP_SHA256 (single SHA-256, used by FRI/STARK)
 * - merkleRootHash256: uses OP_HASH256 (double SHA-256, standard Bitcoin Merkle)
 *
 * The depth parameter must be a compile-time constant because the loop is
 * unrolled at compile time (Bitcoin Script has no loops).
 *
 * Stack convention:
 *   Input:  [..., leaf(32B), proof(depth*32 bytes), index(bigint)]
 *   Output: [..., root(32B)]
 *
 * Algorithm per level i (0 to depth-1):
 *   1. Extract sibling_i from proof (split first 32 bytes)
 *   2. Compute direction: (index >> i) & 1
 *   3. If direction=1: hash(sibling || current), else hash(current || sibling)
 *   4. Result becomes current for next level
 */

import type { StackOp } from '../ir/index.js';

/**
 * emitMerkleRootSha256: compute Merkle root using SHA-256.
 * Stack in: [..., leaf(32B), proof(depth*32B), index(bigint)]
 * Stack out: [..., root(32B)]
 * @param depth - compile-time constant: number of levels in the Merkle tree
 */
export function emitMerkleRootSha256(emit: (op: StackOp) => void, depth: number): void {
  emitMerkleRoot(emit, depth, 'OP_SHA256');
}

/**
 * emitMerkleRootHash256: compute Merkle root using Hash256 (double SHA-256).
 * Stack in: [..., leaf(32B), proof(depth*32B), index(bigint)]
 * Stack out: [..., root(32B)]
 * @param depth - compile-time constant: number of levels in the Merkle tree
 */
export function emitMerkleRootHash256(emit: (op: StackOp) => void, depth: number): void {
  emitMerkleRoot(emit, depth, 'OP_HASH256');
}

/**
 * Core Merkle root computation.
 *
 * Stack layout at entry: [leaf, proof, index]
 *
 * For each level i from 0 to depth-1:
 *   Stack before iteration: [current, remaining_proof, index]
 *
 *   1. Get sibling: split remaining_proof at offset 32
 *      → [current, sibling, rest_proof, index]
 *
 *   2. Get direction bit: (index >> i) & 1
 *      We keep index on the stack and use it with shifting.
 *      For level 0: index & 1. For level i: (index >> i) & 1.
 *      Simpler: use index, check bit i.
 *
 *   3. OP_IF (direction=1): swap current and sibling before concatenating
 *
 *   4. OP_CAT + hash → new current
 *
 * After all levels: [root, empty_proof, index]
 * Clean up: drop empty proof and index, leave root.
 */
function emitMerkleRoot(emit: (op: StackOp) => void, depth: number, hashOp: string): void {
  // Stack: [leaf, proof, index]

  for (let i = 0; i < depth; i++) {
    // Stack: [current, proof, index]

    // --- Step 1: Extract sibling from proof ---
    // Bring proof to top: ROLL(1) — proof is at depth 1 (index is on top... wait)
    // Actually: [current, proof, index] — index on TOS
    // We need to get proof. It's at depth 1.

    // Roll proof to top: swap index and proof
    // Stack: [current, proof, index]
    // After roll(1): [current, index, proof]
    emit({ op: 'swap' });

    // Split proof at 32 to get sibling
    // Stack: [current, index, proof]
    emit({ op: 'push', value: 32n });
    emit({ op: 'opcode', code: 'OP_SPLIT' });
    // Stack: [current, index, sibling(32B), rest_proof]

    // Move rest_proof out of the way (to alt stack)
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // Stack: [current, index, sibling]  Alt: [rest_proof]

    // --- Step 2: Get direction bit ---
    // Bring index to top (it's at depth 1)
    emit({ op: 'swap' });
    // Stack: [current, sibling, index]

    // Compute (index >> i) & 1
    emit({ op: 'opcode', code: 'OP_DUP' });
    // Stack: [current, sibling, index, index]
    if (i > 0) {
      emit({ op: 'push', value: BigInt(i) });
      emit({ op: 'opcode', code: 'OP_RSHIFT' });
    }
    emit({ op: 'push', value: 1n });
    emit({ op: 'opcode', code: 'OP_AND' });
    // Stack: [current, sibling, index, direction_bit]

    // Move index below for safekeeping (swap with sibling area)
    // Rearrange: we need [current, sibling, direction_bit] with index saved
    // Current stack: [current, sibling, index, direction_bit]
    // Roll index down: swap last two, then roll to position
    emit({ op: 'swap' });
    // Stack: [current, sibling, direction_bit, index]
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // Stack: [current, sibling, direction_bit]  Alt: [rest_proof, index]

    // --- Step 3: Conditional swap + concatenate + hash ---
    // If direction_bit = 1, we want hash(sibling || current), so swap
    // If direction_bit = 0, we want hash(current || sibling), no swap needed

    // But current is at depth 2, sibling at depth 1, direction_bit at top.
    // We need: if bit=1 → cat(sibling, current), else cat(current, sibling)

    // Rearrange to get current and sibling adjacent:
    // Roll current to top:
    emit({ op: 'rot' });
    // Stack: [sibling, direction_bit, current]
    emit({ op: 'rot' });
    // Stack: [direction_bit, current, sibling]

    // Now: if direction_bit=1, swap current and sibling before CAT
    emit({ op: 'rot' });
    // Stack: [current, sibling, direction_bit]

    emit({ op: 'if',
      then: [
        // direction = 1: want hash(sibling || current), so swap
        { op: 'swap' as const },
      ],
      // direction = 0: want hash(current || sibling), already in order
    });
    // Stack: [a, b] where a||b is the correct concatenation order

    emit({ op: 'opcode', code: 'OP_CAT' });
    emit({ op: 'opcode', code: hashOp });
    // Stack: [new_current]

    // Restore index and rest_proof from alt stack
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    // Stack: [new_current, index]
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    // Stack: [new_current, index, rest_proof]

    // Reorder to [new_current, rest_proof, index]
    emit({ op: 'swap' });
    // Stack: [new_current, rest_proof, index]
  }

  // Final stack: [root, empty_proof, index]
  // Clean up: drop index and empty proof
  emit({ op: 'drop' });          // drop index
  emit({ op: 'drop' });          // drop empty proof
  // Stack: [root]
}
