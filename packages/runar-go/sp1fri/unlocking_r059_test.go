package sp1fri

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
)

// R-059 / CL-BUG-102 — the proof-blob binding binds the blob to eight dummy
// chunks, not to the transcript inputs the verifier consumes.
//
//	"Step 1 asserts SHA256(proofBlob)==SHA256(chunk_0||...||chunk_7), then drops
//	 the eight chunks unused, while every value the verifier consumes comes from
//	 a separate pre-pushed layer step 1 does not cover. Trivially satisfiable:
//	 choose a blob, split it into eight pieces, push both."
//
// The attack needs no cryptography: hand the encoder a proofBlob of arbitrary
// bytes. The chunks are derived FROM that blob, so Step 1's equality holds by
// construction, and every value the verifier actually checks comes from the
// transcript-input layer — which the blob never touched. The "proof" argument
// named in the ABI is decorative.
//
// This test is the gate for the fix: Step 1 must bind the blob to the values
// the verifier CONSUMES, so a blob that is not their canonical serialisation is
// refused.
func TestEncodeUnlockingScript_RejectsForgedProofBlob(t *testing.T) {
	bs := readMinimalGuestProofBlob(t)
	proof, err := DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if err := Verify(proof, []uint32{0, 1, 21}); err != nil {
		t.Fatalf("ground-truth Verify rejected the canonical fixture: %v", err)
	}

	params := MinimalGuestParams()
	pubVals := publicValuesPoCBytes()
	var vkeyHash []byte

	// The forgery: a blob the attacker chose, the same length as the real one
	// so nothing downstream can object on size alone. Its bytes have no
	// relationship to the proof — that is the point.
	forged := make([]byte, len(bs))
	for i := range forged {
		forged[i] = byte(0xA5 ^ (i * 7))
	}
	if hex.EncodeToString(forged) == hex.EncodeToString(bs) {
		t.Fatal("test scaffold bug: the forged blob equals the real one")
	}

	// The encoder refuses a non-canonical blob outright, which is a real part
	// of the fix — but a spender is not obliged to use this encoder. `forceBlob`
	// bypasses that check so the SCRIPT is what has to refuse the forgery.
	if _, err := EncodeUnlockingScript(proof, forged, pubVals, vkeyHash, params); err == nil {
		t.Fatal("EncodeUnlockingScript accepted a non-canonical proofBlob")
	}
	unlockingBytes, _, err := buildUnlockingScript(proof, nil, pubVals, vkeyHash, params, forged)
	if err != nil {
		t.Fatalf("buildUnlockingScript(forceBlob): %v", err)
	}

	_ = unlockingBytes
	// F-007: rewritten to expect refusal — the compiler refuses verifySP1FRI in v1, so there is no locking script to
	// execute the forged blob against. The encoder-side refusal above still holds.
	contractPath := pocContractPath(t)
	if _, err := os.Stat(contractPath); err != nil {
		t.Fatalf("PoC contract not found at %s: %v", contractPath, err)
	}
	if _, err := compiler.CompileFromSource(contractPath); err == nil {
		t.Fatal("F-007: compiling the SP1 FRI PoC contract must be refused in v1")
	}
}
