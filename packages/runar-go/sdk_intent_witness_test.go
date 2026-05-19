package runar

// ---------------------------------------------------------------------------
// sdk_intent_witness_test.go
//
// R-6 — SDK consumer support for intent-intrinsic auto-injected witness params
// (`_prevOutScript_<i>`, `_serialisedOutputs`).
//
// Covers:
//   - filter: auto-injected witness params are NOT part of the user arg count
//   - setters: SetPrevOutScript / SetSerialisedOutputs store witness bytes
//   - errors: missing witness raises a typed WitnessValueMissingError
//   - wiring: witness bytes are appended to the primary unlocking script in
//     ABI order (`_prevOutScript_*` first, then `_serialisedOutputs`)
// ---------------------------------------------------------------------------

import (
	"errors"
	"strings"
	"testing"
)

func makeArtifactWithIntentWitness(prevOutInputs []int, serialised bool) *RunarArtifact {
	stateFields := []StateField{{Name: "count", Type: "bigint", Index: 0}}

	params := []ABIParam{
		// One ordinary user param
		{Name: "amount", Type: "bigint"},
		// Compiler-injected continuation params for stateful methods
		{Name: "_changePKH", Type: "Ripemd160"},
		{Name: "_changeAmount", Type: "bigint"},
		{Name: "_newAmount", Type: "bigint"},
		{Name: "txPreimage", Type: "SigHashPreimage"},
	}
	// Compiler-injected intent witness params (this is what R-6 covers)
	for _, i := range prevOutInputs {
		params = append(params, ABIParam{
			Name: "_prevOutScript_" + itoaSimple(i),
			Type: "ByteString",
		})
	}
	if serialised {
		params = append(params, ABIParam{Name: "_serialisedOutputs", Type: "ByteString"})
	}

	abi := ABI{
		Constructor: ABIConstructor{Params: []ABIParam{{Name: "count", Type: "bigint"}}},
		Methods: []ABIMethod{
			{
				Name:     "move",
				Params:   params,
				IsPublic: true,
			},
		},
	}

	return makeArtifact("51", abi, func(a *RunarArtifact) {
		a.ContractName = "IntentWitnessTest"
		a.StateFields = stateFields
		// Stateful artifact: codeSeparatorIndex=0 keeps the stateful branch
		// active in PrepareCall without requiring real OP_CODESEPARATOR ops.
		csi := 0
		a.CodeSeparatorIndex = &csi
	})
}

func itoaSimple(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

func setupContractAndDeploy(t *testing.T, art *RunarArtifact) (*RunarContract, *MockProvider, Signer) {
	t.Helper()
	contract := NewRunarContract(art, []interface{}{int64(0)})

	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)

	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})
	if _, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000}); err != nil {
		t.Fatalf("Deploy error: %v", err)
	}
	// Funding UTXO for the call
	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("bb", 32),
		OutputIndex: 1,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})
	return contract, provider, signer
}

// ---------------------------------------------------------------------------
// Filter: arg-count check excludes _prevOutScript_* / _serialisedOutputs
// ---------------------------------------------------------------------------

func TestIntentWitness_FilterExcludesAutoInjectedWitnessParams(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{0, 1}, true)
	contract, provider, signer := setupContractAndDeploy(t, art)

	if err := contract.SetPrevOutScript(0, "aa"); err != nil {
		t.Fatalf("SetPrevOutScript: %v", err)
	}
	if err := contract.SetPrevOutScript(1, "bb"); err != nil {
		t.Fatalf("SetPrevOutScript: %v", err)
	}
	if err := contract.SetSerialisedOutputs("cc"); err != nil {
		t.Fatalf("SetSerialisedOutputs: %v", err)
	}

	// 1 user-facing arg (`amount`). Without the filter we'd hit
	// "expects 7 args, got 1".
	_, _, err := contract.Call("move", []interface{}{int64(123)}, provider, signer, &CallOptions{
		NewState: map[string]interface{}{"count": int64(1)},
	})
	if err != nil {
		t.Fatalf("Call error: %v", err)
	}
	if contract.GetState()["count"] != int64(1) {
		t.Fatalf("state not updated: %v", contract.GetState())
	}
}

func TestIntentWitness_FilterStillRejectsRealMismatches(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{0}, true)
	contract, provider, signer := setupContractAndDeploy(t, art)

	// Pass 2 args when only `amount` is user-facing
	_, _, err := contract.Call("move", []interface{}{int64(1), int64(2)}, provider, signer, nil)
	if err == nil {
		t.Fatal("expected arg count error")
	}
	if !strings.Contains(err.Error(), "expects 1 args, got 2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Missing witness ⇒ typed WitnessValueMissingError
// ---------------------------------------------------------------------------

func TestIntentWitness_MissingPrevOutScriptRaisesTypedError(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{0}, false)
	contract, provider, signer := setupContractAndDeploy(t, art)

	_, _, err := contract.Call("move", []interface{}{int64(1)}, provider, signer, nil)
	if err == nil {
		t.Fatal("expected WitnessValueMissingError")
	}
	var wErr *WitnessValueMissingError
	if !errors.As(err, &wErr) {
		t.Fatalf("expected *WitnessValueMissingError, got %T: %v", err, err)
	}
	if wErr.ParamName != "_prevOutScript_0" {
		t.Errorf("ParamName: got %q", wErr.ParamName)
	}
	if wErr.MethodName != "move" {
		t.Errorf("MethodName: got %q", wErr.MethodName)
	}
	if wErr.ContractName != "IntentWitnessTest" {
		t.Errorf("ContractName: got %q", wErr.ContractName)
	}
}

func TestIntentWitness_MissingSerialisedOutputsRaisesTypedError(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{}, true)
	contract, provider, signer := setupContractAndDeploy(t, art)

	_, _, err := contract.Call("move", []interface{}{int64(1)}, provider, signer, nil)
	if err == nil {
		t.Fatal("expected WitnessValueMissingError")
	}
	var wErr *WitnessValueMissingError
	if !errors.As(err, &wErr) {
		t.Fatalf("expected *WitnessValueMissingError, got %T: %v", err, err)
	}
	if wErr.ParamName != "_serialisedOutputs" {
		t.Errorf("ParamName: got %q", wErr.ParamName)
	}
}

// ---------------------------------------------------------------------------
// Wiring: witness bytes appear in the broadcast unlocking script
// ---------------------------------------------------------------------------

func TestIntentWitness_AppendsMultiplePrevOutScriptsInAbiOrder(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{0, 1}, false)
	contract, provider, signer := setupContractAndDeploy(t, art)

	w0Hex := "deadbeef"
	w1Hex := "cafebabe"
	if err := contract.SetPrevOutScript(0, w0Hex); err != nil {
		t.Fatalf("SetPrevOutScript: %v", err)
	}
	if err := contract.SetPrevOutScript(1, w1Hex); err != nil {
		t.Fatalf("SetPrevOutScript: %v", err)
	}

	_, _, err := contract.Call("move", []interface{}{int64(1)}, provider, signer, &CallOptions{
		NewState: map[string]interface{}{"count": int64(1)},
	})
	if err != nil {
		t.Fatalf("Call error: %v", err)
	}

	txs := provider.GetBroadcastedTxs()
	if len(txs) != 2 {
		t.Fatalf("expected 2 broadcasts (deploy + call), got %d", len(txs))
	}
	callTxHex := txs[1]
	// PUSHDATA for 4 bytes = `04` + data
	push0 := "04" + w0Hex
	push1 := "04" + w1Hex
	idx0 := strings.Index(callTxHex, push0)
	idx1 := strings.Index(callTxHex, push1)
	if idx0 < 0 {
		t.Fatalf("witness 0 push %q not found in call tx hex", push0)
	}
	if idx1 <= idx0 {
		t.Fatalf("witness 1 push must follow witness 0 push (idx0=%d, idx1=%d)", idx0, idx1)
	}
}

func TestIntentWitness_AppendsPrevOutAndSerialisedWithPrevFirst(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{0}, true)
	contract, provider, signer := setupContractAndDeploy(t, art)

	prevHex := "11223344"
	serialHex := "55667788"
	_ = contract.SetPrevOutScript(0, prevHex)
	_ = contract.SetSerialisedOutputs(serialHex)

	_, _, err := contract.Call("move", []interface{}{int64(1)}, provider, signer, &CallOptions{
		NewState: map[string]interface{}{"count": int64(1)},
	})
	if err != nil {
		t.Fatalf("Call error: %v", err)
	}

	callTxHex := provider.GetBroadcastedTxs()[1]
	pushPrev := "04" + prevHex
	pushSerial := "04" + serialHex
	idxPrev := strings.Index(callTxHex, pushPrev)
	idxSerial := strings.Index(callTxHex, pushSerial)
	if idxPrev < 0 {
		t.Fatalf("prevOut push %q not found", pushPrev)
	}
	if idxSerial <= idxPrev {
		t.Fatalf("serialised push must follow prevOut push (prev=%d, serial=%d)", idxPrev, idxSerial)
	}
}

func TestIntentWitness_AcceptsBytesViaConvenienceSetter(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{0}, false)
	contract, provider, signer := setupContractAndDeploy(t, art)

	contract.SetPrevOutScriptBytes(0, []byte{0xab, 0xcd})
	_, _, err := contract.Call("move", []interface{}{int64(1)}, provider, signer, &CallOptions{
		NewState: map[string]interface{}{"count": int64(1)},
	})
	if err != nil {
		t.Fatalf("Call error: %v", err)
	}
	callTxHex := provider.GetBroadcastedTxs()[1]
	// 2-byte push = "02abcd"
	if !strings.Contains(callTxHex, "02abcd") {
		t.Fatalf("expected witness bytes push not found in tx hex")
	}
}

func TestIntentWitness_RejectsInvalidHex(t *testing.T) {
	art := makeArtifactWithIntentWitness([]int{0}, false)
	contract := NewRunarContract(art, []interface{}{int64(0)})

	if err := contract.SetPrevOutScript(0, "not-hex!"); err == nil {
		t.Fatal("expected error for invalid hex")
	}
	if err := contract.SetSerialisedOutputs("abc"); err == nil {
		t.Fatal("expected error for odd-length hex")
	}
}
