// Merkle proof codegen — Merkle root computation for Bitcoin Script.
//
// Follows the ec.go / babybear.go pattern: self-contained module imported
// by stack.go.
//
// Provides two variants:
// - EmitMerkleRootSha256: uses OP_SHA256 (single SHA-256, used by FRI/STARK)
// - EmitMerkleRootHash256: uses OP_HASH256 (double SHA-256, standard Bitcoin Merkle)
//
// The depth parameter must be a compile-time constant because the loop is
// unrolled at compile time (Bitcoin Script has no loops).
//
// Stack convention:
//
//	Input:  [..., leaf(32B), proof(depth*32 bytes), index(bigint)]
//	Output: [..., root(32B)]
//
// Algorithm per level i (0 to depth-1):
//  1. Extract sibling_i from proof (split first 32 bytes)
//  2. Compute direction: (index >> i) & 1
//  3. If direction=1: hash(sibling || current), else hash(current || sibling)
//  4. Result becomes current for next level
package codegen

import "math/big"

// EmitMerkleRootSha256 emits Merkle root computation using SHA-256.
// Stack in: [..., leaf(32B), proof(depth*32B), index(bigint)]
// Stack out: [..., root(32B)]
func EmitMerkleRootSha256(emit func(StackOp), depth int) {
	emitMerkleRoot(emit, depth, "OP_SHA256")
}

// EmitMerkleRootHash256 emits Merkle root computation using Hash256 (double SHA-256).
// Stack in: [..., leaf(32B), proof(depth*32B), index(bigint)]
// Stack out: [..., root(32B)]
func EmitMerkleRootHash256(emit func(StackOp), depth int) {
	emitMerkleRoot(emit, depth, "OP_HASH256")
}

// emitMerkleRoot is the core Merkle root computation.
//
// Stack layout at entry: [leaf, proof, index]
//
// For each level i from 0 to depth-1:
//
//	Stack before iteration: [current, remaining_proof, index]
//
//	1. Get sibling: split remaining_proof at offset 32
//	   → [current, sibling, rest_proof, index]
//
//	2. Get direction bit: (index >> i) & 1
//
//	3. OP_IF (direction=1): swap current and sibling before concatenating
//
//	4. OP_CAT + hash → new current
//
// After all levels: [root, empty_proof, index]
// Clean up: drop empty proof and index, leave root.
func emitMerkleRoot(emit func(StackOp), depth int, hashOp string) {
	// Stack: [leaf, proof, index]

	for i := 0; i < depth; i++ {
		// Stack: [current, proof, index]

		// --- Step 1: Extract sibling from proof ---
		// Roll proof to top: swap index and proof
		// Stack: [current, proof, index]
		// After roll(1): [current, index, proof]
		emit(StackOp{Op: "swap"})

		// Split proof at 32 to get sibling
		// Stack: [current, index, proof]
		emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(32)}})
		emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		// Stack: [current, index, sibling(32B), rest_proof]

		// Move rest_proof out of the way (to alt stack)
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		// Stack: [current, index, sibling]  Alt: [rest_proof]

		// --- Step 2: Get direction bit ---
		// Bring index to top (it's at depth 1)
		emit(StackOp{Op: "swap"})
		// Stack: [current, sibling, index]

		// Compute direction bit: (index / 2^i) % 2
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		// Stack: [current, sibling, index, index]
		// Extract bit i: (index >> i) & 1
		// Chronicle opcodes: OP_2DIV (i=1), OP_RSHIFTNUM (i>1)
		if i == 1 {
			emit(StackOp{Op: "opcode", Code: "OP_2DIV"})
		} else if i > 1 {
			emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(int64(i))}})
			emit(StackOp{Op: "opcode", Code: "OP_RSHIFTNUM"})
		}
		emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(2)}})
		emit(StackOp{Op: "opcode", Code: "OP_MOD"})
		// Stack: [current, sibling, index, direction_bit]

		// Move index below for safekeeping
		// Current stack: [current, sibling, index, direction_bit]
		// Roll index down: swap last two, then to alt stack
		emit(StackOp{Op: "swap"})
		// Stack: [current, sibling, direction_bit, index]
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		// Stack: [current, sibling, direction_bit]  Alt: [rest_proof, index]

		// --- Step 3: Conditional swap + concatenate + hash ---
		// If direction_bit = 1, we want hash(sibling || current), so swap
		// If direction_bit = 0, we want hash(current || sibling), no swap needed

		// Rearrange to get current and sibling adjacent:
		// Roll current to top:
		emit(StackOp{Op: "rot"})
		// Stack: [sibling, direction_bit, current]
		emit(StackOp{Op: "rot"})
		// Stack: [direction_bit, current, sibling]

		// Now: if direction_bit=1, swap current and sibling before CAT
		emit(StackOp{Op: "rot"})
		// Stack: [current, sibling, direction_bit]

		emit(StackOp{
			Op: "if",
			Then: []StackOp{
				// direction = 1: want hash(sibling || current), so swap
				{Op: "swap"},
			},
			// direction = 0: want hash(current || sibling), already in order
		})
		// Stack: [a, b] where a||b is the correct concatenation order

		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		emit(StackOp{Op: "opcode", Code: hashOp})
		// Stack: [new_current]

		// Restore index and rest_proof from alt stack
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		// Stack: [new_current, index]
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		// Stack: [new_current, index, rest_proof]

		// Reorder to [new_current, rest_proof, index]
		emit(StackOp{Op: "swap"})
		// Stack: [new_current, rest_proof, index]
	}

	// Final stack: [root, empty_proof, index]
	// Clean up: drop index and empty proof
	emit(StackOp{Op: "drop"}) // drop index
	emit(StackOp{Op: "drop"}) // drop empty proof
	// Stack: [root]
}
