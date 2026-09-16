package codegen

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// R-120 -- the Merkle index was a completely unbounded witness, and the proof
// remainder was dropped without ever being looked at.
//
// `emitMerkleRoot` unrolls `depth` levels and reads bit i of the index at level
// i. Bits at or above `depth` are never consulted; the index is then simply
// dropped. So for depth 4, `index`, `index + 16`, `index + 4096` and a NEGATIVE
// index all walk the identical path and produce the identical root. Measured on
// the go-sdk interpreter before the gate landed, at depth 2:
//
//	merkleRoot(idx=1)    -> 5306f72f...6ee0f336
//	merkleRoot(idx=5)    -> 5306f72f...6ee0f336
//	merkleRoot(idx=1025) -> 5306f72f...6ee0f336
//	merkleRoot(idx=-1)   -> 5306f72f...6ee0f336
//
// A contract that authenticates "leaf L sits at position i of the tree rooted
// at R" therefore authenticates nothing about i beyond its low `depth` bits:
// one accepted proof is simultaneously a proof for every index congruent to it
// mod 2^depth. Where the index is the thing being committed to -- a UTXO set
// slot, a nullifier position, a FRI query index -- that is the whole property.
//
// The proof blob had the same shape of hole. Each level OP_SPLITs 32 bytes off
// the front; whatever is left over after the last level is dropped unexamined,
// so a proof of 32*depth + k bytes is accepted for every k >= 0 and yields the
// same root as the correctly-sized one. Measured, depth 2: proof lengths 64,
// 65, 96 and 128 all returned 5306f72f...6ee0f336.
//
// Two gates, both aborting -- `merkleRootSha256` / `merkleRootHash256` are
// VALUE builtins, and the policy CL-BUG-095 set (predicates clamp and flag,
// value producers OP_VERIFY) puts them on the aborting side:
//
//	prologue:  OP_DUP <0> <2^depth> OP_WITHIN OP_VERIFY   -- index in domain
//	epilogue:  OP_SIZE <0> OP_NUMEQUALVERIFY              -- proof fully consumed
//
// A SHORT proof already aborted inside OP_SPLIT ("n is larger than length of
// array"), so only the over-long direction needed closing.
// ---------------------------------------------------------------------------

// merkleRootRef is the off-chain reference: the same walk the emitted script
// performs, so a control that accepts is proved to compute the RIGHT root and
// not merely to run without error.
func merkleRootRef(leaf []byte, proof []byte, index int64, depth int, double bool) []byte {
	cur := append([]byte{}, leaf...)
	for i := 0; i < depth; i++ {
		sib := proof[i*32 : (i+1)*32]
		var buf []byte
		if (index>>uint(i))&1 == 1 {
			buf = append(append([]byte{}, sib...), cur...)
		} else {
			buf = append(append([]byte{}, cur...), sib...)
		}
		h := sha256.Sum256(buf)
		if double {
			h = sha256.Sum256(h[:])
		}
		cur = h[:]
	}
	return cur
}

type merkleVariant struct {
	name   string
	emit   func(func(StackOp), int)
	double bool
}

var merkleVariants = []merkleVariant{
	{"sha256", EmitMerkleRootSha256, false},
	{"hash256", EmitMerkleRootHash256, true},
}

// runMerkle builds `push leaf, push proof, push index, <merkle>, push want,
// OP_EQUAL` and returns whether the script ACCEPTED. Classification is by the
// interpreter's error, never by prose.
func runMerkle(t *testing.T, v merkleVariant, depth int, leaf, proof []byte, index *big.Int, want []byte) bool {
	t.Helper()
	ops := []StackOp{
		{Op: "push", Value: PushValue{Kind: "bytes", Bytes: leaf}},
		{Op: "push", Value: PushValue{Kind: "bytes", Bytes: proof}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: index}},
	}
	ops = append(ops, gatherOps(func(e func(StackOp)) { v.emit(e, depth) })...)
	ops = append(ops,
		StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: want}},
		StackOp{Op: "opcode", Code: "OP_EQUAL"},
	)
	return BuildAndExecuteOps(ops) == nil
}

func merkleInputs(depth int) (leaf []byte, proof []byte) {
	leaf = make([]byte, 32)
	leaf[31] = 0xaa
	proof = make([]byte, 32*depth)
	for i := 0; i < depth; i++ {
		proof[i*32+31] = byte(i + 1)
	}
	return
}

// TestR120_MerkleIndexOutOfDomainIsRejected -- the finding itself. An index
// carrying any bit at or above `depth` must not verify.
func TestR120_MerkleIndexOutOfDomainIsRejected(t *testing.T) {
	const depth = 3
	leaf, proof := merkleInputs(depth)

	for _, v := range merkleVariants {
		t.Run(v.name, func(t *testing.T) {
			for _, idx := range []int64{1, 3, 5, 7} {
				want := merkleRootRef(leaf, proof, idx, depth, v.double)

				// CONTROL WITH TEETH: the legitimate index must still verify,
				// against the independently computed root.
				if !runMerkle(t, v, depth, leaf, proof, big.NewInt(idx), want) {
					t.Fatalf("control: index %d must still verify against root %s",
						idx, hex.EncodeToString(want))
				}

				// The attack: the same index with a high bit set. Before the
				// gate every one of these returned the SAME root.
				for _, add := range []int64{8, 16, 1024, 1 << 40} {
					alias := idx + add
					if runMerkle(t, v, depth, leaf, proof, big.NewInt(alias), want) {
						t.Errorf("index %d (= %d + 2^k) verified against the root of index %d",
							alias, idx, idx)
					}
				}
			}

			// A negative index is out of domain on the other side. OP_WITHIN's
			// lower bound is what catches it.
			want0 := merkleRootRef(leaf, proof, 0, depth, v.double)
			for _, neg := range []int64{-1, -8, -1024} {
				if runMerkle(t, v, depth, leaf, proof, big.NewInt(neg), want0) {
					t.Errorf("negative index %d verified", neg)
				}
			}
		})
	}
}

// TestR120_MerkleIndexDomainBoundIsExact -- the bound is 2^depth, pinned on
// both sides, so an over-strict gate reddens here.
func TestR120_MerkleIndexDomainBoundIsExact(t *testing.T) {
	for _, depth := range []int{1, 2, 4} {
		leaf, proof := merkleInputs(depth)
		maxIdx := int64(1)<<uint(depth) - 1

		// Every index in [0, 2^depth) must verify against its own root.
		for idx := int64(0); idx <= maxIdx; idx++ {
			want := merkleRootRef(leaf, proof, idx, depth, false)
			if !runMerkle(t, merkleVariants[0], depth, leaf, proof, big.NewInt(idx), want) {
				t.Errorf("depth %d: in-domain index %d was rejected", depth, idx)
			}
		}
		// 2^depth itself is the first rejected value.
		want0 := merkleRootRef(leaf, proof, 0, depth, false)
		if runMerkle(t, merkleVariants[0], depth, leaf, proof, big.NewInt(1<<uint(depth)), want0) {
			t.Errorf("depth %d: index 2^depth was accepted", depth)
		}
	}
}

// TestR120_MerkleOverlongProofIsRejected -- the leftover-proof drop. A proof
// blob longer than 32*depth used to be accepted with the surplus discarded.
func TestR120_MerkleOverlongProofIsRejected(t *testing.T) {
	const depth = 3
	leaf, proof := merkleInputs(depth)

	for _, v := range merkleVariants {
		t.Run(v.name, func(t *testing.T) {
			want := merkleRootRef(leaf, proof, 5, depth, v.double)

			// CONTROL: the exactly-sized proof verifies.
			if !runMerkle(t, v, depth, leaf, proof, big.NewInt(5), want) {
				t.Fatalf("control: exact-length proof must verify")
			}

			for _, extra := range []int{1, 2, 31, 32, 64, 97} {
				long := append(append([]byte{}, proof...), make([]byte, extra)...)
				if runMerkle(t, v, depth, leaf, long, big.NewInt(5), want) {
					t.Errorf("proof of %d bytes (%d too many) verified", len(long), extra)
				}
			}

			// A SHORT proof was already rejected by OP_SPLIT; pin that it stays
			// rejected rather than becoming an accept.
			for _, missing := range []int{1, 32} {
				short := proof[:len(proof)-missing]
				if runMerkle(t, v, depth, leaf, short, big.NewInt(5), want) {
					t.Errorf("proof of %d bytes (%d too few) verified", len(short), missing)
				}
			}
		})
	}
}
