package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// R-120 -- executed coverage for the Merkle index domain and the proof length,
// on the merkle-proof FIXTURE's own compiled bytes.
//
// The fixture existed, it was compiled by seven tiers, and its golden was
// byte-stable for months. Nothing ever SPENT it: `conformance/witnesses/` has
// no entry for merkle-proof (coverage-ledger.json routes it to an integration
// test on a regtest node, which runs in a different job and only ever spends
// the HAPPY path). So neither of the two holes below was reachable by any gate
// in this repository:
//
//   - the index is read one bit per level and then dropped, so `index`,
//     `index + 2^depth` and any negative index authenticate the same leaf;
//   - the proof blob is OP_SPLIT 32 bytes at a time and the remainder is
//     dropped unread, so a blob longer than 32*depth verifies too.
//
// Both are now gated in stack lowering (see compilers/go/codegen/merkle.go).
// These tests compile the fixture through the TYPESCRIPT compiler -- the tier
// the cross-tier hex gate in conformance/go-only-parity/ holds byte-identical
// to Go -- and execute the result on the go-sdk consensus interpreter. Two
// independent implementations on each side of the assertion.
//
// Every case is classified by the interpreter's error, never by prose.
// ---------------------------------------------------------------------------

// merkleProofDepth is the depth the fixture's `verifySha256` / `verifyHash256`
// hard-code (`merkleRootSha256(leaf, proof, index, 4n)`).
const merkleProofDepth = 4

// merkleRefRoot walks the tree exactly as the emitted script does, so a spend
// that ACCEPTS is proved to have computed the right root rather than merely to
// have run without aborting.
func merkleRefRoot(leaf, proof []byte, index int64, depth int, double bool) []byte {
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

func merkleFixtureInputs() (leaf, proof []byte) {
	leaf = make([]byte, 32)
	leaf[31] = 0xaa
	proof = make([]byte, 32*merkleProofDepth)
	for i := 0; i < merkleProofDepth; i++ {
		proof[i*32+31] = byte(i + 1)
	}
	return
}

// merkleMethodIdx: the fixture has two public methods, so the unlocking script
// carries a trailing selector. 0 = verifySha256, 1 = verifyHash256.
const (
	merkleMethodSha256  = 0
	merkleMethodHash256 = 1
)

// spendMerkleFixture compiles merkle-proof with `root` baked in as
// `expectedRoot` and spends it with (leaf, proof, index). Returns whether the
// consensus interpreter ACCEPTED.
func spendMerkleFixture(t *testing.T, root, leaf, proof []byte, index int64, method int) bool {
	t.Helper()
	lockingHex, err := compileRúnar("merkle-proof",
		fmt.Sprintf(`{"expectedRoot":"%s"}`, hex.EncodeToString(root)))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	unlockingHex := encodePushBytes(leaf) + encodePushBytes(proof) +
		encodePushInt(index) + encodePushInt(int64(method))
	return executeScript(lockingHex, unlockingHex) == nil
}

// TestR120_MerkleFixture_IndexOutOfDomainRejected is the finding, executed.
func TestR120_MerkleFixture_IndexOutOfDomainRejected(t *testing.T) {
	leaf, proof := merkleFixtureInputs()

	for _, m := range []struct {
		name   string
		idx    int
		double bool
	}{
		{"verifySha256", merkleMethodSha256, false},
		{"verifyHash256", merkleMethodHash256, true},
	} {
		t.Run(m.name, func(t *testing.T) {
			const legit = int64(5)
			root := merkleRefRoot(leaf, proof, legit, merkleProofDepth, m.double)

			// CONTROL WITH TEETH: the honest spend still succeeds, against a
			// root computed outside the compiler.
			if !spendMerkleFixture(t, root, leaf, proof, legit, m.idx) {
				t.Fatalf("control: index %d must still spend", legit)
			}

			// The attack. Every one of these used to spend the SAME output:
			// the script never reads a bit above depth-1.
			for _, alias := range []int64{legit + 16, legit + 32, legit + 4096, legit + (1 << 40)} {
				if spendMerkleFixture(t, root, leaf, proof, alias, m.idx) {
					t.Errorf("index %d spent an output committed to index %d", alias, legit)
				}
			}
			// ... and on the other side of the domain.
			root0 := merkleRefRoot(leaf, proof, 0, merkleProofDepth, m.double)
			for _, neg := range []int64{-1, -16, -4096} {
				if spendMerkleFixture(t, root0, leaf, proof, neg, m.idx) {
					t.Errorf("negative index %d spent", neg)
				}
			}
		})
	}
}

// TestR120_MerkleFixture_DomainBoundIsExact pins the bound at 2^depth on both
// sides: an over-strict gate reddens on the accept half.
func TestR120_MerkleFixture_DomainBoundIsExact(t *testing.T) {
	leaf, proof := merkleFixtureInputs()

	for idx := int64(0); idx < 1<<merkleProofDepth; idx++ {
		root := merkleRefRoot(leaf, proof, idx, merkleProofDepth, false)
		if !spendMerkleFixture(t, root, leaf, proof, idx, merkleMethodSha256) {
			t.Errorf("in-domain index %d was rejected", idx)
		}
	}
	root0 := merkleRefRoot(leaf, proof, 0, merkleProofDepth, false)
	if spendMerkleFixture(t, root0, leaf, proof, 1<<merkleProofDepth, merkleMethodSha256) {
		t.Errorf("index 2^depth (%d) was accepted", 1<<merkleProofDepth)
	}
}

// TestR120_MerkleFixture_OverlongProofRejected is the leftover-proof half.
func TestR120_MerkleFixture_OverlongProofRejected(t *testing.T) {
	leaf, proof := merkleFixtureInputs()
	const legit = int64(5)
	root := merkleRefRoot(leaf, proof, legit, merkleProofDepth, false)

	// CONTROL: the exactly-sized proof spends.
	if !spendMerkleFixture(t, root, leaf, proof, legit, merkleMethodSha256) {
		t.Fatalf("control: exact-length proof must spend")
	}

	for _, extra := range []int{1, 31, 32, 64} {
		long := append(append([]byte{}, proof...), make([]byte, extra)...)
		if spendMerkleFixture(t, root, leaf, long, legit, merkleMethodSha256) {
			t.Errorf("proof of %d bytes (%d surplus) spent", len(long), extra)
		}
	}
	// The short direction already aborted inside OP_SPLIT; pin that it stays
	// a rejection rather than turning into an accept.
	for _, missing := range []int{1, 32} {
		short := proof[:len(proof)-missing]
		if spendMerkleFixture(t, root, leaf, short, legit, merkleMethodSha256) {
			t.Errorf("proof of %d bytes (%d short) spent", len(short), missing)
		}
	}
}
