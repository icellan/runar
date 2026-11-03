package runar

// N-253: since F-369/N-213 the k=1 OP_PUSH_TX ECDSA signature is unused on the
// stateful PrepareCall path (buildStatefulPrefix ignores it; the on-chain
// script derives it from the preimage), yet the path still computed and
// discarded one per pass. The fix adds ComputeOpPushTxPreimageWithSigHash and
// uses it there; ComputeOpPushTx* stay public and unchanged.
//
// Proves: a stateful merge PrepareCall (the shared N-286 vector: primary +
// extra contract input) performs zero OP_PUSH_TX signs, counted through the
// opPushTxSign seam; the control shows the seam does see
// ComputeOpPushTxWithSigHash sign, and that the preimage-only variant returns
// byte-identical preimages without signing. Byte-identity of PrepareCall output
// is proven by TestN286_StatefulMergePrepareFinalize_MatchesSharedVector.
// Does not prove anything about the stateless / terminal paths.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func countOpPushTxSigns(t *testing.T) *int {
	t.Helper()
	n := 0
	orig := opPushTxSign
	opPushTxSign = func(h []byte) (*ec.Signature, error) {
		n++
		return orig(h)
	}
	t.Cleanup(func() { opPushTxSign = orig })
	return &n
}

func TestN253_StatefulPrepareCallDoesNotComputeOpPushTxSignature(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-call", "stateful-merge-prepared.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v n286Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(v.Artifact, &art); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	signer, err := NewLocalSigner(v.PrivKeyHex)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	addr, _ := signer.GetAddress()
	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, v.FundingUtxo)
	cu := v.ContractUtxo
	provider.AddContractUtxo(cu.Script, &cu)
	eu := v.ExtraContractUtxo
	provider.AddContractUtxo(eu.Script+":extra", &eu)
	c, err := FromUtxo(&art, v.ContractUtxo)
	if err != nil {
		t.Fatalf("FromUtxo: %v", err)
	}

	signs := countOpPushTxSigns(t)
	prepared, err := c.PrepareCall(v.Method, []interface{}{nil}, provider, signer, &CallOptions{
		AdditionalContractInputs: []*UTXO{&eu},
	})
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	if prepared.Sighash != v.Expected.Sighash {
		t.Fatalf("sighash = %s, want %s", prepared.Sighash, v.Expected.Sighash)
	}
	if *signs != 0 {
		t.Fatalf("stateful PrepareCall computed %d OP_PUSH_TX signature(s); want 0", *signs)
	}
}

func TestN253_PreimageOnlyVariantMatchesFullHelperWithoutSigning(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-call", "stateful-merge-prepared.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v n286Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	txHex := v.Expected.ReferenceTxHex
	sub := v.ContractUtxo.Script
	for _, sigHashType := range []int{0, 0x41, 0x43} {
		signs := countOpPushTxSigns(t)
		_, full, err := ComputeOpPushTxWithSigHash(txHex, 0, sub, v.ContractUtxo.Satoshis, -1, sigHashType)
		if err != nil {
			t.Fatalf("full: %v", err)
		}
		if *signs != 1 {
			t.Fatalf("control: ComputeOpPushTxWithSigHash signed %d times, want 1", *signs)
		}
		only, err := ComputeOpPushTxPreimageWithSigHash(txHex, 0, sub, v.ContractUtxo.Satoshis, -1, sigHashType)
		if err != nil {
			t.Fatalf("preimage-only: %v", err)
		}
		if *signs != 1 {
			t.Fatalf("preimage-only variant signed (count %d)", *signs)
		}
		if !bytes.Equal(only, full) {
			t.Fatalf("preimage differs for sigHashType %#x", sigHashType)
		}
	}
	// Same refusals as the full helper.
	if _, err := ComputeOpPushTxPreimageWithSigHash(txHex, 0, "", 1, -1, 0); err == nil {
		t.Fatal("empty subscript must be refused")
	}
	if _, err := ComputeOpPushTxPreimageWithSigHash(txHex, 99, sub, 1, -1, 0); err == nil {
		t.Fatal("out-of-range input index must be refused")
	}
}
