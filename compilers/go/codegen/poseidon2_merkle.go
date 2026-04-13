// Poseidon2 Merkle proof codegen — Merkle root computation for Bitcoin Script
// using Poseidon2 KoalaBear compression.
//
// Follows the merkle.go pattern: self-contained module imported by stack.go.
//
// Unlike the SHA-256 Merkle variants (which use 32-byte hash digests),
// Poseidon2 KoalaBear Merkle trees represent each node as 8 KoalaBear field
// elements. Compression feeds two 8-element digests (16 elements total) into
// the Poseidon2 permutation and takes the first 8 elements of the output.
//
// The depth parameter must be a compile-time constant because the loop is
// unrolled at compile time (Bitcoin Script has no loops).
//
// Stack convention:
//
//	Input:  [..., leaf_0..leaf_7, sib0_0..sib0_7, ..., sib(D-1)_0..sib(D-1)_7, index]
//	Output: [..., root_0..root_7]
//
// Where D = depth. The leaf is 8 field elements, each sibling is 8 field
// elements, and index is a bigint whose bits determine left/right ordering at
// each tree level.
package codegen

import (
	"fmt"
	"math/big"
)

// emitRoll emits a ROLL operation for a given depth.
func emitRoll(emit func(StackOp), d int) {
	if d == 0 {
		return
	}
	if d == 1 {
		emit(StackOp{Op: "swap"})
		return
	}
	if d == 2 {
		emit(StackOp{Op: "rot"})
		return
	}
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(int64(d))}})
	emit(StackOp{Op: "roll", Depth: d})
}

// EmitPoseidon2MerkleRoot emits Poseidon2 Merkle root computation.
//
// Stack in:  [..., leaf(8 elems), proof(depth*8 elems), index]
// Stack out: [..., root(8 elems)]
//
// depth is a compile-time constant (unrolled loop). Must be in [1, 32].
// Higher depths produce quadratically larger scripts due to roll operations.
func EmitPoseidon2MerkleRoot(emit func(StackOp), depth int) {
	if depth < 1 || depth > 32 {
		panic(fmt.Sprintf("EmitPoseidon2MerkleRoot: depth must be in [1, 32], got %d", depth))
	}
	// Strategy overview:
	//
	// At each level i, the stack is:
	//   [..., current(8), sib_i(8), future_sibs((depth-i-1)*8), index]
	//
	// 1. Save index to alt-stack (it stays there for the whole level).
	// 2. Compute direction bit from index (DUP before saving).
	// 3. Roll current(8)+sib_i(8) above future_sibs so they become the top 16.
	// 4. Retrieve bit from alt, do conditional swap.
	// 5. Poseidon2 compress (top 16 → top 8).
	// 6. Roll new_current(8) back below future_sibs.
	// 7. Restore index from alt.
	//
	// At the end, drop index and leave root(8) on the stack.

	for i := 0; i < depth; i++ {
		// Stack: [..., current(8), sib_i(8), future_sibs(F*8), index]
		// where F = depth - i - 1 (number of future sibling groups).
		futureElems := (depth - i - 1) * 8

		// ----- Compute direction bit and save index + bit to alt -----
		emit(StackOp{Op: "opcode", Code: "OP_DUP"}) // dup index
		if i > 0 {
			if i == 1 {
				emit(StackOp{Op: "opcode", Code: "OP_2DIV"})
			} else {
				emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(int64(i))}})
				emit(StackOp{Op: "opcode", Code: "OP_RSHIFTNUM"})
			}
		}
		emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(2)}})
		emit(StackOp{Op: "opcode", Code: "OP_MOD"})
		// Stack: [..., current(8), sib_i(8), future_sibs, index, bit]

		// Save bit then index to alt-stack. We need bit first (on top of alt)
		// when we retrieve it later.
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // save bit
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // save index
		// Stack: [..., current(8), sib_i(8), future_sibs]
		// Alt (top→bottom): [index, bit]

		// ----- Roll current+sib_i above future_sibs -----
		// current_0 is the deepest element of the working area.
		// Its depth from stack top = futureElems + 15.
		// After each roll from that depth, the next target element ends up
		// at the same depth (the removed element came from below, so the
		// block above it shifts down to fill the gap).
		if futureElems > 0 {
			rollDepth := futureElems + 15
			for j := 0; j < 16; j++ {
				emitRoll(emit, rollDepth)
			}
		}
		// Stack: [..., future_sibs, current(8), sib_i(8)]
		// Top 16 elements: current_0..7 then sib_i_0..7 (sib_i_7 on top)
		// This means: left = current, right = sib_i (in compress terms: s0..s7 = current, s8..s15 = sib_i)

		// ----- Retrieve bit and conditional swap -----
		// Pop index from alt (it's on top), save to main, get bit.
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // get index
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // get bit
		// Stack: [..., future_sibs, current(8), sib_i(8), index, bit]

		// Save index back to alt
		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // save index
		// Stack: [..., future_sibs, current(8), sib_i(8), bit]
		// Alt: [index]

		// OP_IF consumes bit. If bit==1, swap current and sibling groups.
		emit(StackOp{
			Op: "if",
			Then: []StackOp{
				// bit==1: swap the two groups of 8 elements.
				// 8x roll(15) moves each element of the bottom group (current)
				// above the top group (sibling), producing [sibling(8), current(8)].
				{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(15)}},
				{Op: "roll", Depth: 15},
				{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(15)}},
				{Op: "roll", Depth: 15},
				{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(15)}},
				{Op: "roll", Depth: 15},
				{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(15)}},
				{Op: "roll", Depth: 15},
				{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(15)}},
				{Op: "roll", Depth: 15},
				{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(15)}},
				{Op: "roll", Depth: 15},
				{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(15)}},
				{Op: "roll", Depth: 15},
				{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(15)}},
				{Op: "roll", Depth: 15},
			},
			// bit==0: already in correct order [current(8), sibling(8)]
		})
		// Stack: [..., future_sibs, left(8), right(8)]

		// ----- Poseidon2 compress -----
		EmitPoseidon2KBCompress(emit)
		// Stack: [..., future_sibs, new_current(8)]

		// ----- Roll new_current back below future_sibs -----
		// new_current is the top 8 elements. future_sibs has futureElems items below.
		// We need to push each of the 8 elements down past futureElems items.
		// Roll the deepest future_sib element to the top, repeat futureElems times.
		// Actually, we roll the TOP element (new_current_7) to below future_sibs.
		// There's no single op to push top to deep. Instead: roll all future_sibs
		// above new_current. Each roll brings one future_sib element from depth 8+j
		// to the top.
		//
		// Alternative: Roll each new_current element below future_sibs by rolling
		// from depth futureElems + 7 (bringing a future_sib from the bottom to
		// the top). After futureElems rolls, all future_sibs are on top.
		//
		// Simpler: just roll each future_sib element to the top.
		// After that, future_sibs are above new_current.
		// NOTE: This is O(futureElems) rolls per level, making total script size
		// quadratic in tree depth — a known limitation of Bitcoin Script's stack model.
		if futureElems > 0 {
			// The bottom future_sib element is at depth 7 + futureElems.
			// After each roll, the stack rearranges and the next target is
			// at the same depth.
			rollDepth := 7 + futureElems
			for j := 0; j < futureElems; j++ {
				emitRoll(emit, rollDepth)
			}
		}
		// Stack: [..., new_current(8), future_sibs]

		// ----- Restore index from alt -----
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		// Stack: [..., new_current(8), future_sibs, index]
	}

	// After all levels: [..., root(8), index]
	emit(StackOp{Op: "drop"})
	// Stack: [..., root_0..root_7]
}
