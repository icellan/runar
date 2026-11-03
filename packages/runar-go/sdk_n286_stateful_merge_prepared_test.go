package runar

// N-286: a stateful merge through the two-phase API (PrepareCall /
// FinalizeCall). Replays the shared cross-SDK vector
// conformance/sdk-call/stateful-merge-prepared.json (produced by the TS SDK,
// whose MockProvider Spend-validated all three inputs; re-checked with Spend in
// conformance/sdk-call/stateful-merge.test.ts).
//
// Proves: given the vector's artifact, two contract UTXOs, funding UTXO and
// key, Go's PrepareCall yields the same primary sighash and sig indices, and
// FinalizeCall with the vector's primary signature broadcasts a tx byte-equal
// to the TS reference (so the extra contract input's unlock, the fee and the
// change match too). Does not prove a live node.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type n286Vector struct {
	Artifact          json.RawMessage `json:"artifact"`
	PrivKeyHex        string          `json:"privKeyHex"`
	ContractUtxo      UTXO            `json:"contractUtxo"`
	ExtraContractUtxo UTXO            `json:"extraContractUtxo"`
	FundingUtxo       UTXO            `json:"fundingUtxo"`
	Method            string          `json:"method"`
	Expected          struct {
		SigIndices          []int  `json:"sigIndices"`
		Sighash             string `json:"sighash"`
		PrimarySignatureHex string `json:"primarySignatureHex"`
		ReferenceTxHex      string `json:"referenceTxHex"`
	} `json:"expected"`
}

func TestN286_StatefulMergePrepareFinalize_MatchesSharedVector(t *testing.T) {
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
	prepared, err := c.PrepareCall(v.Method, []interface{}{nil}, provider, signer, &CallOptions{
		AdditionalContractInputs: []*UTXO{&eu},
	})
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	if len(prepared.SigIndices) != 1 || prepared.SigIndices[0] != v.Expected.SigIndices[0] {
		t.Fatalf("sig indices = %v, want %v", prepared.SigIndices, v.Expected.SigIndices)
	}
	if prepared.Sighash != v.Expected.Sighash {
		t.Fatalf("sighash = %s, want %s", prepared.Sighash, v.Expected.Sighash)
	}
	if _, _, err := c.FinalizeCall(prepared, map[int]string{0: v.Expected.PrimarySignatureHex}, provider); err != nil {
		t.Fatalf("FinalizeCall: %v", err)
	}
	txs := provider.GetBroadcastedTxs()
	if len(txs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(txs))
	}
	if txs[0] != v.Expected.ReferenceTxHex {
		t.Fatalf("broadcast tx differs from the shared TS vector:\n got %s\nwant %s", txs[0], v.Expected.ReferenceTxHex)
	}
}
