package runar

// N-412: a STATELESS contract method that takes the auto-injected intent
// witness `_prevOutScript_0`. Replays the shared cross-SDK vector
// conformance/sdk-call/stateless-witness.json (produced by the TS SDK, whose
// MockProvider Spend-validated every input; re-checked with @bsv/sdk Spend —
// including a tampered/omitted witness push — in
// conformance/sdk-call/stateless-witness.test.ts).
//
// Proves: Go's Call (no-Sig `peek`, Sig `spend`) and PrepareCall +
// FinalizeCall (`spend`) push `<declared args> <witness> <selector>` on input 0
// and broadcast a tx byte-equal to the TS reference. Does not prove a live
// node, or `_serialisedOutputs` on a stateless method (the compiler refuses
// requireOutputP2PKH outside StatefulSmartContract).

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

type n412Scenario struct {
	Input0UnlockingHex string `json:"input0UnlockingHex"`
	ReferenceTxHex     string `json:"referenceTxHex"`
	SignatureHex       string `json:"signatureHex"`
}

type n412Vector struct {
	Artifact         json.RawMessage `json:"artifact"`
	PrivKeyHex       string          `json:"privKeyHex"`
	PubKeyHex        string          `json:"pubKeyHex"`
	PrevOutScriptHex string          `json:"prevOutScriptHex"`
	ContractUtxo     UTXO            `json:"contractUtxo"`
	FundingUtxo      UTXO            `json:"fundingUtxo"`
	Expected         struct {
		Peek  n412Scenario `json:"peek"`
		Spend n412Scenario `json:"spend"`
	} `json:"expected"`
}

func n412Load(t *testing.T) (*n412Vector, *RunarArtifact) {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-call", "stateless-witness.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v n412Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(v.Artifact, &art); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	return &v, &art
}

func n412Fresh(t *testing.T, v *n412Vector, art *RunarArtifact) (*RunarContract, *MockProvider, *LocalSigner) {
	t.Helper()
	signer, err := NewLocalSigner(v.PrivKeyHex)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	addr, _ := signer.GetAddress()
	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, v.FundingUtxo)
	cu := v.ContractUtxo
	provider.AddContractUtxo(cu.Script, &cu)
	c, err := FromUtxo(art, v.ContractUtxo)
	if err != nil {
		t.Fatalf("FromUtxo: %v", err)
	}
	if err := c.SetPrevOutScript(0, v.PrevOutScriptHex); err != nil {
		t.Fatalf("SetPrevOutScript: %v", err)
	}
	return c, provider, signer
}

func n412AssertBroadcast(t *testing.T, provider *MockProvider, want n412Scenario) {
	t.Helper()
	txs := provider.GetBroadcastedTxs()
	if len(txs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(txs))
	}
	tx, err := transaction.NewTransactionFromHex(txs[0])
	if err != nil {
		t.Fatalf("parse broadcast tx: %v", err)
	}
	if got := tx.Inputs[0].UnlockingScript.String(); got != want.Input0UnlockingHex {
		t.Fatalf("input 0 unlocking script differs from the shared TS vector:\n got %s\nwant %s", got, want.Input0UnlockingHex)
	}
	if txs[0] != want.ReferenceTxHex {
		t.Fatalf("broadcast tx differs from the shared TS vector:\n got %s\nwant %s", txs[0], want.ReferenceTxHex)
	}
}

func TestN412_StatelessIntentWitness_CallPeek(t *testing.T) {
	v, art := n412Load(t)
	c, provider, signer := n412Fresh(t, v, art)
	if _, _, err := c.Call("peek", []interface{}{big.NewInt(5)}, provider, signer, nil); err != nil {
		t.Fatalf("Call peek: %v", err)
	}
	n412AssertBroadcast(t, provider, v.Expected.Peek)
}

func TestN412_StatelessIntentWitness_CallSpend(t *testing.T) {
	v, art := n412Load(t)
	c, provider, signer := n412Fresh(t, v, art)
	if _, _, err := c.Call("spend", []interface{}{nil, v.PubKeyHex}, provider, signer, nil); err != nil {
		t.Fatalf("Call spend: %v", err)
	}
	n412AssertBroadcast(t, provider, v.Expected.Spend)
}

func TestN412_StatelessIntentWitness_PrepareFinalizeSpend(t *testing.T) {
	v, art := n412Load(t)
	c, provider, signer := n412Fresh(t, v, art)
	prepared, err := c.PrepareCall("spend", []interface{}{nil, v.PubKeyHex}, provider, signer, nil)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	if len(prepared.SigIndices) != 1 || prepared.SigIndices[0] != 0 {
		t.Fatalf("sig indices = %v, want [0]", prepared.SigIndices)
	}
	if _, _, err := c.FinalizeCall(prepared, map[int]string{0: v.Expected.Spend.SignatureHex}, provider); err != nil {
		t.Fatalf("FinalizeCall: %v", err)
	}
	n412AssertBroadcast(t, provider, v.Expected.Spend)
}
