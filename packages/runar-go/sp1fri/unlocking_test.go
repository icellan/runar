package sp1fri

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/icellan/runar/compilers/go/compiler"
)


// spliceConstructorArgs splices encoded constructor arg push-data into a
// hex locking script template, replacing each 1-byte OP_0 placeholder at
// `slots[i].ByteOffset` with `EncodePushData(<arg>)` bytes (encoded as
// hex). Mirrors the splice algorithm used by
// `packages/runar-go/sdk_contract.go::buildCodeScript` (lines 1233-1275).
//
// `args[slot.ParamIndex]` MUST be a hex-encoded string (the SDK convention
// for ByteString constructor params); callers that have raw bytes should
// `hex.EncodeToString(...)` first.
func spliceConstructorArgs(t *testing.T, scriptHex string, slots []compiler.ConstructorSlot, args []interface{}) string {
	t.Helper()
	if len(slots) == 0 {
		return scriptHex
	}

	type sub struct {
		byteOffset int
		encoded    string
	}
	subs := make([]sub, 0, len(slots))
	for _, slot := range slots {
		if slot.ParamIndex >= len(args) {
			t.Fatalf("spliceConstructorArgs: slot.ParamIndex=%d out of range (len(args)=%d)",
				slot.ParamIndex, len(args))
		}
		argHex, ok := args[slot.ParamIndex].(string)
		if !ok {
			t.Fatalf("spliceConstructorArgs: arg[%d] is %T, want hex string",
				slot.ParamIndex, args[slot.ParamIndex])
		}
		subs = append(subs, sub{
			byteOffset: slot.ByteOffset,
			encoded:    encodePushDataHex(argHex),
		})
	}
	sort.Slice(subs, func(i, j int) bool {
		return subs[i].byteOffset > subs[j].byteOffset
	})
	out := scriptHex
	for _, s := range subs {
		hexOff := s.byteOffset * 2
		if hexOff+2 > len(out) {
			t.Fatalf("spliceConstructorArgs: byteOffset=%d out of range (|script|=%d B)",
				s.byteOffset, len(out)/2)
		}
		out = out[:hexOff] + s.encoded + out[hexOff+2:]
	}
	return out
}

// encodePushDataHex mirrors `packages/runar-go/sdk_state.go::EncodePushData`
// — wraps `dataHex` in the smallest Bitcoin Script push-data prefix.
func encodePushDataHex(dataHex string) string {
	dataLen := len(dataHex) / 2
	switch {
	case dataLen <= 75:
		return fmt.Sprintf("%02x", dataLen) + dataHex
	case dataLen <= 0xff:
		return "4c" + fmt.Sprintf("%02x", dataLen) + dataHex
	case dataLen <= 0xffff:
		lo := dataLen & 0xff
		hi := (dataLen >> 8) & 0xff
		return "4d" + fmt.Sprintf("%02x%02x", lo, hi) + dataHex
	default:
		b0 := dataLen & 0xff
		b1 := (dataLen >> 8) & 0xff
		b2 := (dataLen >> 16) & 0xff
		b3 := (dataLen >> 24) & 0xff
		return "4e" + fmt.Sprintf("%02x%02x%02x%02x", b0, b1, b2, b3) + dataHex
	}
}

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

	unlockingBytes, err := EncodeUnlockingScript(proof, bs, pubVals, vkeyHash, params)
	if err != nil {
		t.Fatalf("EncodeUnlockingScript: %v", err)
	}
	if len(unlockingBytes) == 0 {
		t.Fatal("EncodeUnlockingScript returned an empty script")
	}

	// 4. Compile the PoC contract.
	contractPath := pocContractPath(t)
	if _, err := os.Stat(contractPath); err != nil {
		t.Fatalf("PoC contract not found at %s: %v", contractPath, err)
	}
	artifact, err := compiler.CompileFromSource(contractPath)
	if err != nil {
		t.Fatalf("compile PoC contract: %v", err)
	}
	if artifact == nil || artifact.Script == "" {
		t.Fatal("compile produced no locking script")
	}

	// 5. Splice constructor args. The Sp1FriVerifierPoc contract has one
	// readonly `Sp1VKeyHash` ByteString property; the compiler always
	// emits a constructor slot for it (a 1-byte OP_0 placeholder at the
	// offset baked into the locking script). We splice the actual
	// `sp1VKeyHash` bytes into each slot using the same byte-offset-
	// descending splice algorithm `packages/runar-go/sdk_contract.go`
	// uses (lines 1233-1275). For the PoC fixture
	// `SP1VKeyHashByteSize=0` ⇒ EncodePushData("") yields the single
	// byte `00` which equals the OP_0 placeholder, so the splice is a
	// no-op. We exercise it anyway so this test continues to pass when
	// the production tuple lands (`SP1VKeyHashByteSize=32`).
	lockingScriptHex := spliceConstructorArgs(t, artifact.Script,
		artifact.ConstructorSlots, []interface{}{hex.EncodeToString(vkeyHash)})

	// 6. Execute through the script VM.
	lockScript, err := script.NewFromHex(lockingScriptHex)
	if err != nil {
		t.Fatalf("parse locking script: %v", err)
	}
	unlockScript := script.NewFromBytes(unlockingBytes)

	eng := interpreter.NewEngine()
	if err := eng.Execute(
		interpreter.WithScripts(lockScript, unlockScript),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	); err != nil {
		t.Fatalf("script VM rejected canonical fixture: %v", err)
	}

	// Sanity: the chunks we encoded reconstruct the proofBlob.
	chunks := chunkProofBytes(bs, params.NumChunks)
	var rebuilt []byte
	for _, c := range chunks {
		rebuilt = append(rebuilt, c...)
	}
	got := sha256.Sum256(rebuilt)
	want := sha256.Sum256(bs)
	if hex.EncodeToString(got[:]) != hex.EncodeToString(want[:]) {
		t.Fatalf("chunkProofBytes scaffold bug: rebuilt sha256=%x, proofBlob sha256=%x",
			got, want)
	}

	t.Logf("encoded unlocking script accepted by script VM; |unlocking|=%d B, |locking|=%d B (%d KB), |proofBlob|=%d B, |chunks|=%d",
		len(unlockingBytes), len(lockingScriptHex)/2, len(lockingScriptHex)/2/1024,
		len(bs), len(chunks))
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

	good, err := EncodeUnlockingScript(proof, bs, pubVals, nil, params)
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

	contractPath := pocContractPath(t)
	artifact, err := compiler.CompileFromSource(contractPath)
	if err != nil {
		t.Fatalf("compile PoC contract: %v", err)
	}
	lockScript, err := script.NewFromHex(artifact.Script)
	if err != nil {
		t.Fatalf("parse locking script: %v", err)
	}
	unlockScript := script.NewFromBytes(bad)

	eng := interpreter.NewEngine()
	err = eng.Execute(
		interpreter.WithScripts(lockScript, unlockScript),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
	if err == nil {
		t.Fatal("expected script VM to reject tampered unlocking, but it accepted")
	}
	t.Logf("tampered unlocking correctly rejected: %v", err)
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

	t.Run("empty_blob", func(t *testing.T) {
		_, err := EncodeUnlockingScript(proof, nil, pubVals, nil, MinimalGuestParams())
		if err == nil {
			t.Fatal("want error for empty proof blob")
		}
	})

	t.Run("zero_chunks", func(t *testing.T) {
		p := MinimalGuestParams()
		p.NumChunks = 0
		_, err := EncodeUnlockingScript(proof, bs, pubVals, nil, p)
		if err == nil {
			t.Fatal("want error for NumChunks=0")
		}
	})

	t.Run("chunks_exceed_blob", func(t *testing.T) {
		p := MinimalGuestParams()
		p.NumChunks = len(bs) + 1
		_, err := EncodeUnlockingScript(proof, bs, pubVals, nil, p)
		if err == nil {
			t.Fatal("want error for NumChunks > |proofBlob|")
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
