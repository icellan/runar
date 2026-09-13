package sp1fri

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
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

	contractPath := pocContractPath(t)
	if _, err := os.Stat(contractPath); err != nil {
		t.Fatalf("PoC contract not found at %s: %v", contractPath, err)
	}
	artifact, err := compiler.CompileFromSource(contractPath)
	if err != nil {
		t.Fatalf("compile PoC contract: %v", err)
	}
	lockingScriptHex := spliceConstructorArgs(t, artifact.Script,
		artifact.ConstructorSlots, []interface{}{hex.EncodeToString(vkeyHash)})

	lockScript, err := script.NewFromHex(lockingScriptHex)
	if err != nil {
		t.Fatalf("parse locking script: %v", err)
	}
	unlockScript := script.NewFromBytes(unlockingBytes)

	eng := interpreter.NewEngine()
	err = eng.Execute(
		interpreter.WithScripts(lockScript, unlockScript),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
	if err == nil {
		forgedHash := sha256.Sum256(forged)
		realHash := sha256.Sum256(bs)
		t.Fatalf(
			"the verifier ACCEPTED a spend whose proofBlob is %d bytes of the attacker's choosing.\n"+
				"  forged blob sha256: %x\n"+
				"  real proof  sha256: %x\n"+
				"Step 1 binds the blob only to chunks derived from that same blob, so the argument "+
				"the ABI calls the proof constrains nothing (R-059 / CL-BUG-102).",
			len(forged), forgedHash, realHash)
	}
	t.Logf("forged proofBlob rejected by the script VM, as it must be: %v", err)
}
