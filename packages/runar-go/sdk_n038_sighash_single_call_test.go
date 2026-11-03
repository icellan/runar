package runar

// N-038 (R64): a stateful @sighash SINGLE|FORKID call carrying a change output.
// Replays the shared cross-SDK vector conformance/sdk-call/sighash-single-stateful.json
// (produced by the TS SDK and Spend-validated in conformance/sdk-call/sdk-call.test.ts)
// through the Go SDK. Proves: the Go SDK pushes byte-identical input-0 unlocking
// bytes (no _changePKH / _changeAmount — the SINGLE method's ABI declares none),
// builds the same continuation output[0], still adds a change output, tracks the
// new state, and the go-sdk interpreter accepts input 0 and rejects a tampered
// output[0] (state byte or satoshis). Does not prove the change value / fee
// match other tiers (tier policy, not committed by SINGLE) or a live node.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type n038Vector struct {
	Artifact     json.RawMessage `json:"artifact"`
	PrivKeyHex   string          `json:"privKeyHex"`
	ContractUtxo UTXO            `json:"contractUtxo"`
	FundingUtxo  UTXO            `json:"fundingUtxo"`
	Method       string          `json:"method"`
	Expected     struct {
		Input0UnlockingHex string `json:"input0UnlockingHex"`
		Output0            struct {
			Satoshis  int64  `json:"satoshis"`
			ScriptHex string `json:"scriptHex"`
		} `json:"output0"`
		OutputCount int    `json:"outputCount"`
		NewCount    string `json:"newCount"`
	} `json:"expected"`
}

func TestN038_SighashSingleCallWithChange_MatchesSharedVector(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-call", "sighash-single-stateful.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v n038Vector
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

	c, err := FromUtxo(&art, v.ContractUtxo)
	if err != nil {
		t.Fatalf("FromUtxo: %v", err)
	}
	if _, _, err := c.Call(v.Method, nil, provider, signer, nil); err != nil {
		t.Fatalf("call %s: %v", v.Method, err)
	}
	txs := provider.GetBroadcastedTxs()
	if len(txs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(txs))
	}
	callTx, err := transaction.NewTransactionFromHex(txs[0])
	if err != nil {
		t.Fatalf("parse call tx: %v", err)
	}

	if got := hex.EncodeToString(*callTx.Inputs[0].UnlockingScript); got != v.Expected.Input0UnlockingHex {
		t.Errorf("input 0 unlocking script differs from the shared vector:\n got %d hex chars\nwant %d hex chars", len(got), len(v.Expected.Input0UnlockingHex))
	}
	if len(callTx.Outputs) != v.Expected.OutputCount {
		t.Fatalf("outputs = %d, want %d (continuation + change)", len(callTx.Outputs), v.Expected.OutputCount)
	}
	if int64(callTx.Outputs[0].Satoshis) != v.Expected.Output0.Satoshis ||
		hex.EncodeToString(*callTx.Outputs[0].LockingScript) != v.Expected.Output0.ScriptHex {
		t.Errorf("output 0 differs from the shared vector")
	}
	if got := anfToBigInt(c.state["count"]).String(); got != v.Expected.NewCount {
		t.Errorf("state count = %s, want %s", got, v.Expected.NewCount)
	}

	ls, err := script.NewFromHex(v.ContractUtxo.Script)
	if err != nil {
		t.Fatal(err)
	}
	prevOut := &transaction.TransactionOutput{Satoshis: uint64(v.ContractUtxo.Satoshis), LockingScript: ls}
	exec := func(tx *transaction.Transaction) error {
		return interpreter.NewEngine().Execute(
			interpreter.WithTx(tx, 0, prevOut),
			interpreter.WithAfterGenesis(),
			interpreter.WithAfterChronicle(),
			interpreter.WithForkID(),
		)
	}
	if err := exec(callTx); err != nil {
		t.Fatalf("contract input REJECTED by go-sdk interpreter: %v", err)
	}

	stateTamper, _ := transaction.NewTransactionFromHex(txs[0])
	s := *stateTamper.Outputs[0].LockingScript
	tampered := append(script.Script{}, s...)
	tampered[len(tampered)-1] ^= 0xff
	stateTamper.Outputs[0].LockingScript = &tampered
	if err := exec(stateTamper); err == nil {
		t.Errorf("tampered output[0] state byte was ACCEPTED")
	}
	satsTamper, _ := transaction.NewTransactionFromHex(txs[0])
	satsTamper.Outputs[0].Satoshis--
	if err := exec(satsTamper); err == nil {
		t.Errorf("tampered output[0] satoshis was ACCEPTED")
	}
}

// N-038: the typed-wrapper codegen must not classify a SIGHASH_SINGLE
// continuation method (no _changePKH in its ABI) as terminal.
func TestN038_CodegenSingleMethodIsNotTerminal(t *testing.T) {
	single := 0x43
	acpSingle := 0xc3
	terminal := true
	cases := []struct {
		name string
		m    ABIMethod
		want bool
	}{
		{"SINGLE continuation", ABIMethod{Name: "bump", IsPublic: true, SigHashType: &single, Params: []ABIParam{{Name: "txPreimage", Type: "SigHashPreimage"}}}, false},
		{"SINGLE|ACP continuation", ABIMethod{Name: "bump", IsPublic: true, SigHashType: &acpSingle, Params: []ABIParam{{Name: "txPreimage", Type: "SigHashPreimage"}}}, false},
		{"SINGLE terminal", ABIMethod{Name: "close", IsPublic: true, SigHashType: &single, IsTerminal: &terminal, Params: []ABIParam{{Name: "txPreimage", Type: "SigHashPreimage"}}}, true},
		{"ALL without change", ABIMethod{Name: "close", IsPublic: true, Params: []ABIParam{{Name: "txPreimage", Type: "SigHashPreimage"}}}, true},
		{"ALL with change", ABIMethod{Name: "inc", IsPublic: true, Params: []ABIParam{{Name: "_changePKH", Type: "Ripemd160"}, {Name: "txPreimage", Type: "SigHashPreimage"}}}, false},
	}
	for _, c := range cases {
		if got := isTerminalMethod(c.m, true); got != c.want {
			t.Errorf("%s: isTerminalMethod = %v, want %v", c.name, got, c.want)
		}
	}
}
