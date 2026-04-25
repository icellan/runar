package sp1fri

import (
	"os"
	"path/filepath"
	"testing"
)

const minimalGuestProofRel = "../../../tests/vectors/sp1/fri/minimal-guest/proof.postcard"

// loadMinimalGuestProof reads and decodes the fixture proof.
func loadMinimalGuestProof(t *testing.T) *Proof {
	t.Helper()
	abs, err := filepath.Abs(minimalGuestProofRel)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	bs, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p, err := DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return p
}

// TestVerifyMinimalGuest is the main acceptance test: the real Plonky3
// Fibonacci STARK + FRI proof produced by `regen/src/main.rs` should verify.
//
// Public values (from regen): a=0, b=1, x=fib(7)=21.
//
// The fixture is generated against `default_koalabear_poseidon2_16()` so
// the round constants match the canonical SP1 v6.0.2
// KOALABEAR_POSEIDON2_RC_16_* tables embedded in `poseidon2.go`. End-to-end
// path exercised: postcard decode → DuplexChallenger transcript replay →
// FRI commit-phase PoW + Merkle openings + colinearity fold → final-poly
// equality → AIR symbolic constraint evaluation at the OOD point ζ →
// quotient recompose check.
func TestVerifyMinimalGuest(t *testing.T) {
	p := loadMinimalGuestProof(t)
	pis := []uint32{0, 1, 21}
	if err := Verify(p, pis); err != nil {
		t.Fatalf("Verify rejected the canonical minimal-guest fixture: %v", err)
	}
}

// TestRejectMutatedProof asserts that flipping a single byte of the proof
// causes verification to fail.
func TestRejectMutatedProof(t *testing.T) {
	abs, err := filepath.Abs(minimalGuestProofRel)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	bs, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// Flip a byte well inside the FRI proof region (after the commitments
	// header). Byte offset 64 is in the middle of the trace MerkleCap.
	mutated := append([]byte(nil), bs...)
	mutated[64] ^= 0x01

	p, err := DecodeProof(mutated)
	if err != nil {
		// Decode failure is itself a (very strict) form of rejection. We
		// accept either path: rejected at decode time, or rejected at verify.
		t.Logf("mutated proof rejected at decode: %v", err)
		return
	}
	if err := Verify(p, []uint32{0, 1, 21}); err == nil {
		t.Fatalf("Verify accepted a mutated proof; expected rejection")
	}
	// (Either decoder rejection or verifier rejection counts as a pass.)
}
