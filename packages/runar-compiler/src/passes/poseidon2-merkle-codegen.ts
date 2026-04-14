/**
 * Poseidon2 KoalaBear Merkle proof codegen — Merkle root computation for
 * Bitcoin Script using Poseidon2 KoalaBear compression.
 *
 * Ports compilers/go/codegen/poseidon2_merkle.go to TypeScript.
 *
 * Unlike SHA-256 Merkle variants (which use 32-byte hash digests),
 * Poseidon2 KoalaBear Merkle trees represent each node as 8 KoalaBear field
 * elements. Compression feeds two 8-element digests (16 elements total) into
 * the Poseidon2 permutation and takes the first 8 elements of the output.
 *
 * The depth parameter must be a compile-time constant because the loop is
 * unrolled at compile time (Bitcoin Script has no loops).
 *
 * Stack convention:
 *   Input:  [..., leaf(8 elems), proof(depth*8 elems), index]
 *   Output: [..., root(8 elems)]
 *
 * Where depth is the number of tree levels. The leaf is 8 field elements, each
 * sibling is 8 field elements, and index is a bigint whose bits determine
 * left/right ordering at each tree level.
 *
 * Script size is O(depth^2) due to Bitcoin Script's stack roll operations.
 * Depth must be in [1, 32].
 */

import type { StackOp } from '../ir/index.js';
import { emitPoseidon2KBCompress } from './poseidon2-koalabear-codegen.js';

// ===========================================================================
// Internal helpers
// ===========================================================================

/** emitRollOp: emit a ROLL operation for a given depth d. */
function emitRollOp(emit: (op: StackOp) => void, d: number): void {
  if (d === 0) return;
  if (d === 1) { emit({ op: 'swap' }); return; }
  if (d === 2) { emit({ op: 'rot' }); return; }
  emit({ op: 'push', value: BigInt(d) });
  emit({ op: 'roll', depth: d });
}

// ===========================================================================
// Public emit function
// ===========================================================================

/**
 * emitPoseidon2MerkleRoot: emit Poseidon2 Merkle root computation.
 *
 * Stack in:  [..., leaf(8 elems), proof(depth*8 elems), index]
 * Stack out: [..., root(8 elems)]
 *
 * depth is a compile-time constant (loop unrolled). Must be in [1, 32].
 * Higher depths produce quadratically larger scripts due to roll operations.
 *
 * Algorithm per level i (0 to depth-1):
 *   Stack: [..., current(8), sib_i(8), future_sibs((depth-i-1)*8), index]
 *
 *   1. Dup index, compute direction bit (index >> i) % 2.
 *   2. Save bit then index to altstack.
 *   3. Roll current(8) + sib_i(8) above future_sibs (they become top 16).
 *   4. Retrieve index and bit from altstack.
 *   5. If bit==1: swap the two groups of 8 (conditional swap).
 *   6. Poseidon2 compress: top 16 → top 8.
 *   7. Roll new_current back below future_sibs.
 *   8. Restore index from altstack.
 *
 * After all levels: drop index, leave root(8).
 */
export function emitPoseidon2MerkleRoot(emit: (op: StackOp) => void, depth: number): void {
  if (depth < 1 || depth > 32) {
    throw new Error(`emitPoseidon2MerkleRoot: depth must be in [1, 32], got ${depth}`);
  }

  for (let i = 0; i < depth; i++) {
    // Stack: [..., current(8), sib_i(8), future_sibs(F*8), index]
    // F = depth - i - 1 (number of future sibling groups remaining)
    const futureElems = (depth - i - 1) * 8;

    // ----- Compute direction bit and save index + bit to alt -----
    emit({ op: 'dup' }); // dup index
    if (i > 0) {
      if (i === 1) {
        emit({ op: 'opcode', code: 'OP_2DIV' });
      } else {
        emit({ op: 'push', value: BigInt(i) });
        emit({ op: 'opcode', code: 'OP_RSHIFTNUM' });
      }
    }
    emit({ op: 'push', value: 2n });
    emit({ op: 'opcode', code: 'OP_MOD' });
    // Stack: [..., current(8), sib_i(8), future_sibs, index, bit]

    // Save bit then index to alt-stack (bit is on top of alt when retrieved)
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // save bit
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // save index
    // Stack: [..., current(8), sib_i(8), future_sibs]
    // Alt (top→bottom): [index, bit]

    // ----- Roll current + sib_i above future_sibs -----
    // current_0 is at depth futureElems + 15 from top.
    // Each of 16 rolls brings one element of the working pair to the top.
    if (futureElems > 0) {
      const rollDepth = futureElems + 15;
      for (let j = 0; j < 16; j++) {
        emitRollOp(emit, rollDepth);
      }
    }
    // Stack: [..., future_sibs, current(8), sib_i(8)]
    // Top 16: current_0..7 then sib_0..7 (sib_7 on top)
    //   i.e. left=current, right=sib_i in compress terms

    // ----- Retrieve bit and conditional swap -----
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // get index
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // get bit
    // Stack: [..., future_sibs, current(8), sib_i(8), index, bit]

    // Save index back to alt, keep bit on main stack
    emit({ op: 'swap' });
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // save index
    // Stack: [..., future_sibs, current(8), sib_i(8), bit]
    // Alt: [index]

    // OP_IF on bit: if bit==1, swap current and sibling groups
    // 8x roll(15) moves each element of the lower group above the upper group
    emit({
      op: 'if',
      then: [
        // bit==1: swap the two groups of 8
        { op: 'push', value: 15n }, { op: 'roll', depth: 15 },
        { op: 'push', value: 15n }, { op: 'roll', depth: 15 },
        { op: 'push', value: 15n }, { op: 'roll', depth: 15 },
        { op: 'push', value: 15n }, { op: 'roll', depth: 15 },
        { op: 'push', value: 15n }, { op: 'roll', depth: 15 },
        { op: 'push', value: 15n }, { op: 'roll', depth: 15 },
        { op: 'push', value: 15n }, { op: 'roll', depth: 15 },
        { op: 'push', value: 15n }, { op: 'roll', depth: 15 },
      ],
      // bit==0: already in correct order [current(8), sib(8)]
    });
    // Stack: [..., future_sibs, left(8), right(8)]

    // ----- Poseidon2 compress -----
    emitPoseidon2KBCompress(emit);
    // Stack: [..., future_sibs, new_current(8)]

    // ----- Roll new_current back below future_sibs -----
    // Roll each future_sib element from its current position to the top,
    // repeating futureElems times. The bottom future_sib is at depth
    // 7 + futureElems initially; after each roll it stays at the same depth.
    if (futureElems > 0) {
      const rollDepth = 7 + futureElems;
      for (let j = 0; j < futureElems; j++) {
        emitRollOp(emit, rollDepth);
      }
    }
    // Stack: [..., new_current(8), future_sibs]

    // ----- Restore index from alt -----
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    // Stack: [..., new_current(8), future_sibs, index]
  }

  // After all levels: [..., root(8), index]
  emit({ op: 'drop' }); // drop index
  // Stack: [..., root_0..root_7]
}
