package runar

import (
	"math/big"
	"strings"
	"testing"

	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Unit tests for sdk_groth16.go
//
// These tests are fast and do NOT broadcast to regtest. They verify:
//   - NewGroth16WAContract accepts a valid Groth16 WA artifact
//   - NewGroth16WAContract panics on nil or non-Groth16 artifacts
//   - Metadata accessors (NumPubInputs, VKDigest) expose the embedded fields
//   - serializeWitnessToUnlock produces a non-empty hex stream of push ops
//   - CallWithWitness input validation (no UTXO, nil witness, etc.) errors
//     cleanly without panicking
//   - Deploy + spend can be driven end-to-end against MockProvider so we
//     exercise the full Groth16WAContract control flow without leaving the
//     unit-test harness.
// ---------------------------------------------------------------------------

// buildFakeGroth16WAArtifact returns a minimal RunarArtifact with the
// Groth16WA metadata field populated. The script is a trivial
// OP_1/OP_TRUE locking script so that MockProvider deploy/spend round
// trips succeed without running the real ~700 KB verifier.
func buildFakeGroth16WAArtifact() *RunarArtifact {
	return &RunarArtifact{
		Version:         "1",
		CompilerVersion: "test",
		ContractName:    "Groth16Verifier",
		Script:          "51", // OP_1 — always-true locking script
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{}},
			Methods: []ABIMethod{
				{Name: "verify", Params: []ABIParam{}, IsPublic: true},
			},
		},
		Groth16WA: &Groth16WAMeta{
			NumPubInputs: 5,
			VKDigest:     "ba315d87303b212ac0c221881a34468013e6afc6b865e2abe3d68ad1c500c1d7",
		},
	}
}

// buildFakeWitness returns a minimal Witness with every slot populated.
// This is enough to exercise ToStackOps → serializeWitnessToUnlock → push
// data encoding without needing to regenerate a real witness from a
// proof (which costs ~1 s).
func buildFakeWitness() *bn254witness.Witness {
	mk := func(v int64) *big.Int { return big.NewInt(v) }
	w := &bn254witness.Witness{
		Q: mk(21888),
	}
	// Miller gradients: one loop iteration worth = 6 values.
	w.MillerGradients = []*big.Int{mk(1), mk(2), mk(3), mk(4), mk(5), mk(6)}
	// Final exp witnesses: 4 × 12 Fp values.
	for i := 0; i < 12; i++ {
		w.FinalExpFInv[i] = mk(int64(i + 100))
		w.FinalExpA[i] = mk(int64(i + 200))
		w.FinalExpB[i] = mk(int64(i + 300))
		w.FinalExpC[i] = mk(int64(i + 400))
	}
	w.PreparedInputs = [2]*big.Int{mk(11), mk(22)}
	w.ProofA = [2]*big.Int{mk(1001), mk(1002)}
	w.ProofB = [4]*big.Int{mk(2001), mk(2002), mk(2003), mk(2004)}
	w.ProofC = [2]*big.Int{mk(3001), mk(3002)}
	return w
}

func TestGroth16WASDK_NewGroth16WAContract_Happy(t *testing.T) {
	artifact := buildFakeGroth16WAArtifact()
	g := NewGroth16WAContract(artifact)
	if g == nil {
		t.Fatalf("NewGroth16WAContract returned nil")
	}
	if g.Artifact() != artifact {
		t.Errorf("Artifact() did not return the wrapped artifact")
	}
	if g.NumPubInputs() != 5 {
		t.Errorf("NumPubInputs = %d, want 5", g.NumPubInputs())
	}
	if g.VKDigest() != "ba315d87303b212ac0c221881a34468013e6afc6b865e2abe3d68ad1c500c1d7" {
		t.Errorf("VKDigest mismatch: %s", g.VKDigest())
	}
	if g.CurrentUTXO() != nil {
		t.Errorf("CurrentUTXO on fresh contract should be nil")
	}
	if g.LockingScript() != "51" {
		t.Errorf("LockingScript mismatch: %s", g.LockingScript())
	}
}

func TestGroth16WASDK_NewGroth16WAContract_NilArtifactPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil artifact")
		}
	}()
	_ = NewGroth16WAContract(nil)
}

func TestGroth16WASDK_NewGroth16WAContract_NoMetadataPanics(t *testing.T) {
	// A normal Rúnar artifact has Groth16WA == nil; NewGroth16WAContract
	// must reject it.
	artifact := &RunarArtifact{
		Version:      "1",
		ContractName: "P2PKH",
		Script:       "51",
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{}},
			Methods: []ABIMethod{
				{Name: "unlock", IsPublic: true},
			},
		},
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on artifact with no Groth16WA metadata")
		}
	}()
	_ = NewGroth16WAContract(artifact)
}

func TestGroth16WASDK_SerializeWitnessToUnlock_NonEmpty(t *testing.T) {
	w := buildFakeWitness()
	hex, err := serializeWitnessToUnlock(w)
	if err != nil {
		t.Fatalf("serializeWitnessToUnlock: %v", err)
	}
	if hex == "" {
		t.Fatalf("serializeWitnessToUnlock returned empty string")
	}
	// Each of the 1 (Q) + 6 (gradients) + 48 (final exp) + 2 (prepared) +
	// 8 (proof) = 65 values is pushed. Small values 1..16 encode as a
	// single byte (OP_1..OP_16). Larger values encode as pushdata
	// opcode + payload. Just sanity-check the length is in a sensible
	// range (at least 65 bytes, at most ~200 bytes for this fake input).
	byteLen := len(hex) / 2
	if byteLen < 65 {
		t.Errorf("serialized unlock too short: %d bytes", byteLen)
	}
	if byteLen > 400 {
		t.Errorf("serialized unlock suspiciously long: %d bytes", byteLen)
	}
}

func TestGroth16WASDK_SerializeWitnessToUnlock_NilWitness(t *testing.T) {
	if _, err := serializeWitnessToUnlock(nil); err == nil {
		t.Errorf("expected error for nil witness")
	}
}

func TestGroth16WASDK_CallWithWitness_NoUtxo(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	provider := NewMockProvider("mocknet")
	signer := NewMockSigner("", "")
	w := buildFakeWitness()
	_, _, err := g.CallWithWitness(provider, signer, w, "fakeaddr", "")
	if err == nil {
		t.Fatalf("expected error (no UTXO) but CallWithWitness returned nil")
	}
	if !strings.Contains(err.Error(), "no current UTXO") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGroth16WASDK_CallWithWitness_NoProvider(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    50000,
		Script:      "51",
	})
	_, _, err := g.CallWithWitness(nil, nil, buildFakeWitness(), "fakeaddr", "")
	if err == nil {
		t.Fatalf("expected error when neither provider argument nor Connect() are set")
	}
	if !strings.Contains(err.Error(), "no provider") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGroth16WASDK_CallWithWitness_NilWitness(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    50000,
		Script:      "51",
	})
	provider := NewMockProvider("mocknet")
	signer := NewMockSigner("", "")
	_, _, err := g.CallWithWitness(provider, signer, nil, "fakeaddr", "")
	if err == nil {
		t.Fatalf("expected error on nil witness")
	}
}

func TestGroth16WASDK_CallWithWitness_BothDestinationsError(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    50000,
		Script:      "51",
	})
	provider := NewMockProvider("mocknet")
	signer := NewMockSigner("", "")
	_, _, err := g.CallWithWitness(provider, signer, buildFakeWitness(), "fakeaddr", "deadbeef")
	if err == nil {
		t.Fatalf("expected error when both changeAddress and outputScriptHex are set")
	}
	if !strings.Contains(err.Error(), "only one of") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGroth16WASDK_CallWithWitness_NeitherDestinationError(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    50000,
		Script:      "51",
	})
	provider := NewMockProvider("mocknet")
	signer := NewMockSigner("", "")
	_, _, err := g.CallWithWitness(provider, signer, buildFakeWitness(), "", "")
	if err == nil {
		t.Fatalf("expected error when no destination is provided")
	}
}

func TestGroth16WASDK_CallWithWitness_EndToEndMock(t *testing.T) {
	// Drive the entire wrapper lifecycle through MockProvider:
	//   1. Simulate a pre-funded contract UTXO.
	//   2. Call CallWithWitness with a P2PKH output destination.
	//   3. Assert the spend was broadcast exactly once and that the
	//      contract's tracked UTXO was cleared.
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	utxo := &UTXO{
		Txid:        strings.Repeat("bb", 32),
		OutputIndex: 0,
		Satoshis:    50_000,
		Script:      "51",
	}
	g.SetCurrentUTXO(utxo)

	provider := NewMockProvider("mocknet")
	signer := NewMockSigner("", "")

	// Use a raw P2PKH-ish script hex as the destination; we don't care
	// about its validity on mocknet.
	destScript := "76a914" + strings.Repeat("00", 20) + "88ac"
	txid, txData, err := g.CallWithWitness(provider, signer, buildFakeWitness(), "", destScript)
	if err != nil {
		t.Fatalf("CallWithWitness: %v", err)
	}
	if txid == "" {
		t.Errorf("empty txid after broadcast")
	}
	if txData == nil {
		t.Fatalf("nil txData")
	}
	if len(txData.Outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(txData.Outputs))
	}
	if txData.Outputs[0].Script != destScript {
		t.Errorf("output script mismatch: %s", txData.Outputs[0].Script)
	}
	if txData.Outputs[0].Satoshis <= 0 || txData.Outputs[0].Satoshis >= utxo.Satoshis {
		t.Errorf("output satoshis out of range: %d", txData.Outputs[0].Satoshis)
	}
	if len(provider.GetBroadcastedTxs()) != 1 {
		t.Errorf("expected exactly 1 broadcast, got %d", len(provider.GetBroadcastedTxs()))
	}
	if g.CurrentUTXO() != nil {
		t.Errorf("CurrentUTXO should be nil after successful spend")
	}
}
