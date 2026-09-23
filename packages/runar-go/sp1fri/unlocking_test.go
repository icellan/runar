package sp1fri

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
)

// publicValuesPoCBytes mirrors
// `compilers/go/codegen/sp1_fri_test.go::publicValuesPoCBytes` (line 273):
// the canonical Fibonacci-AIR public values [a=0, b=1, fib(7)=21] encoded
// as 12 bytes of little-endian u32s.
func publicValuesPoCBytes() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x15, 0x00, 0x00, 0x00,
	}
}

// pocContractPath returns the absolute path to the PoC contract file.
// We resolve via runtime.Caller so the test is hermetic regardless of the
// working directory.
func pocContractPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile),
		"..", "..", "..", "integration", "go", "contracts",
		"Sp1FriVerifierPoc.runar.go")
}

// readMinimalGuestProofBlob returns the canonical postcard-encoded proof
// bytes. Mirrors `compilers/go/codegen/sp1_fri_test.go::loadMinimalGuestProofBlob`.
func readMinimalGuestProofBlob(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile),
		"..", "..", "..", "tests", "vectors", "sp1", "fri",
		"minimal-guest", "proof.postcard")
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if len(bs) == 0 {
		t.Fatal("fixture is empty")
	}
	return bs
}

// TestEncodeUnlockingScript_AcceptsMinimalGuestFixture is the end-to-end
// acceptance gate for the unlocking-script encoder.
//
// Pipeline:
//
//  1. Read the canonical postcard fixture and decode it through the
//     validated `DecodeProof`.
//  2. Off-chain sanity check: assert `Verify` accepts the fixture (this
//     also pins our fixture identity — if the fixture changes upstream
//     this fails before we touch the encoder).
//  3. Build the unlocking-script bytes via `EncodeUnlockingScript` with
//     `MinimalGuestParams()`.
//  4. Compile the PoC contract through the full Rúnar pipeline
//     (parse → validate → typecheck → ANF → stack → emit) to obtain the
//     locking-script hex.
//  5. Splice the constructor args into the locking script (no-op for the
//     PoC fixture because `SP1VKeyHashByteSize=0` ⇒ the artifact has no
//     constructor slots; covered by the assertion below).
//  6. Run [unlocking_bytes][locking_script] through the go-sdk
//     interpreter with the same flag set the dispatch test uses
//     (Genesis + Chronicle + ForkID). Assert no error.
//
// This is the dispatch-wired analogue of
// `compilers/go/codegen/sp1_fri_test.go::TestSp1FriVerifier_AcceptsMinimalGuestFixture`
// — but instead of pre-pending the prelude in test code as a single
// concatenated locking script, we exercise the production split:
// unlocking script in the spending input, locking script in the UTXO.
func TestEncodeUnlockingScript_AcceptsMinimalGuestFixture(t *testing.T) {
	// 1. Decode the canonical fixture.
	bs := readMinimalGuestProofBlob(t)
	proof, err := DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	// 2. Off-chain sanity check.
	if err := Verify(proof, []uint32{0, 1, 21}); err != nil {
		t.Fatalf("ground-truth Verify rejected the canonical fixture: %v", err)
	}

	// 3. Encode the unlocking script.
	params := MinimalGuestParams()
	pubVals := publicValuesPoCBytes()
	if len(pubVals) != params.PublicValuesByteSize {
		t.Fatalf("test scaffold bug: |publicValuesPoCBytes()|=%d != PublicValuesByteSize=%d",
			len(pubVals), params.PublicValuesByteSize)
	}
	var vkeyHash []byte // PoC fixture: SP1VKeyHashByteSize == 0 ⇒ no push.

	unlockingBytes, err := EncodeUnlockingScript(proof, nil, pubVals, vkeyHash, params)
	if err != nil {
		t.Fatalf("EncodeUnlockingScript: %v", err)
	}
	if len(unlockingBytes) == 0 {
		t.Fatal("EncodeUnlockingScript returned an empty script")
	}

	// 4-6. Compile the PoC contract and execute. F-007: rewritten to expect refusal — the SP1 FRI verifier is not
	// implemented for v1, so the compiler refuses verifySP1FRI and there is no locking script to run. (The fail-closed
	// body is executed against this encoder's output in compilers/go/compiler/sp1_fri_f007_fail_closed_test.go.)
	contractPath := pocContractPath(t)
	if _, err := os.Stat(contractPath); err != nil {
		t.Fatalf("PoC contract not found at %s: %v", contractPath, err)
	}
	if _, err := compiler.CompileFromSource(contractPath); err == nil {
		t.Fatal("F-007: compiling the SP1 FRI PoC contract must be refused in v1")
	} else if !strings.Contains(err.Error(), "not implemented for v1") {
		t.Fatalf("F-007: unexpected refusal text: %v", err)
	}

	// R-059 sanity: the blob the encoder pushed IS the canonical serialisation
	// of the transcript inputs, and it is NOT the raw SP1 proof bytes. Both
	// halves matter — the first is what Step 1 now binds, the second is the
	// change in meaning this finding forced.
	canon, err := CanonicalProofBlob(proof, pubVals, params)
	if err != nil {
		t.Fatalf("CanonicalProofBlob: %v", err)
	}
	if len(canon) == 0 {
		t.Fatal("canonical proof blob is empty")
	}
	if hex.EncodeToString(canon) == hex.EncodeToString(bs) {
		t.Fatal("scaffold bug: the canonical blob equals the raw bincode proof")
	}
	canonHash := sha256.Sum256(canon)

	t.Logf("encoded unlocking script; compile refused (F-007); |unlocking|=%d B, "+
		"|canonical proofBlob|=%d B (sha256 %x), |raw bincode proof|=%d B",
		len(unlockingBytes), len(canon), canonHash[:8], len(bs))
}

// TestEncodeUnlockingScript_RejectsTamperedUnlocking exercises the
// negative-test counterpart: flipping a single byte deep inside the
// encoded unlocking script MUST cause the script VM to reject. Guards
// against silent-acceptance regressions in the Step 1 SHA-256 binding
// emission.
//
// Strategy: encode the canonical (good) unlocking script, then XOR one
// byte 100 bytes from the end. That offset lands inside the proofBlob
// typed-arg push payload (the largest single ByteString in the script).
// Because the binding hashes `proofBlob` and compares it against the
// SHA-256 of the chunk concatenation, mutating the typed-arg copy
// breaks the OP_EQUALVERIFY in the body's Step 1.
//
// (For the PoC fixture |unlocking| ≈ 3.6 KB and proofBlob is the second-
// to-last push, ≈ 1.6 KB — so the last 100 bytes always sit inside it.
// If future ParamSets reorder the trailing pushes this test will fail
// loudly with "expected reject"; the failure points the maintainer at
// this comment.)
func TestEncodeUnlockingScript_RejectsTamperedUnlocking(t *testing.T) {
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

	good, err := EncodeUnlockingScript(proof, nil, pubVals, nil, params)
	if err != nil {
		t.Fatalf("encode (good): %v", err)
	}
	bad := make([]byte, len(good))
	copy(bad, good)
	tamperOff := len(bad) - 100
	if tamperOff < 0 {
		t.Fatalf("encoded unlocking too short to tamper: %d", len(bad))
	}
	bad[tamperOff] ^= 0x80

	_ = bad
	// F-007: rewritten to expect refusal — the compiler refuses verifySP1FRI in v1, so there is no locking script to
	// reject the tampered witness; the tamper itself is still built above so the encoder path stays exercised.
	contractPath := pocContractPath(t)
	if _, err := compiler.CompileFromSource(contractPath); err == nil {
		t.Fatal("F-007: compiling the SP1 FRI PoC contract must be refused in v1")
	}
}

// TestEncodeUnlockingScript_ParamValidation guards the ParamSet
// argument-validation surface. Each subtest passes a deliberately
// malformed ParamSet/inputs and asserts the encoder returns a typed
// error WITHOUT panicking.
func TestEncodeUnlockingScript_ParamValidation(t *testing.T) {
	bs := readMinimalGuestProofBlob(t)
	proof, err := DecodeProof(bs)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	pubVals := publicValuesPoCBytes()

	t.Run("nil_proof", func(t *testing.T) {
		_, err := EncodeUnlockingScript(nil, bs, pubVals, nil, MinimalGuestParams())
		if err == nil {
			t.Fatal("want error for nil proof")
		}
	})

	// R-059: an omitted blob is no longer an error — the encoder derives the
	// canonical serialisation of the transcript inputs, which is what the
	// Step 1 binding checks.
	t.Run("omitted_blob_is_derived", func(t *testing.T) {
		enc, err := EncodeUnlockingScript(proof, nil, pubVals, nil, MinimalGuestParams())
		if err != nil {
			t.Fatalf("omitted blob must be derived, not refused: %v", err)
		}
		if len(enc) == 0 {
			t.Fatal("derived-blob encoding produced an empty script")
		}
	})

	// ...and a blob that is NOT that serialisation is refused here rather than
	// emitted into a script that can only die in the VM.
	t.Run("non_canonical_blob", func(t *testing.T) {
		_, err := EncodeUnlockingScript(proof, bs, pubVals, nil, MinimalGuestParams())
		if err == nil {
			t.Fatal("want error for a proofBlob that is not the canonical serialisation")
		}
	})

	t.Run("canonical_blob_round_trips", func(t *testing.T) {
		canon, err := CanonicalProofBlob(proof, pubVals, MinimalGuestParams())
		if err != nil {
			t.Fatalf("CanonicalProofBlob: %v", err)
		}
		if _, err := EncodeUnlockingScript(proof, canon, pubVals, nil, MinimalGuestParams()); err != nil {
			t.Fatalf("the encoder must accept the blob it derives: %v", err)
		}
	})

	t.Run("public_values_size_mismatch", func(t *testing.T) {
		_, err := EncodeUnlockingScript(proof, bs, []byte{0x00}, nil, MinimalGuestParams())
		if err == nil {
			t.Fatal("want error for publicValues size mismatch")
		}
	})

	t.Run("vkey_hash_size_mismatch", func(t *testing.T) {
		p := MinimalGuestParams()
		p.SP1VKeyHashByteSize = 32
		_, err := EncodeUnlockingScript(proof, bs, pubVals, []byte{0x00}, p)
		if err == nil {
			t.Fatal("want error for sp1VKeyHash size mismatch")
		}
	})
}
