package runar

import (
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Item 8 — ScriptSizeExceededError at SDK entry points (Go)
// ---------------------------------------------------------------------------

func oversizedScriptHex() string {
	return strings.Repeat("51", MaxScriptBytes+1)
}

func atLimitScriptHex() string {
	return strings.Repeat("51", MaxScriptBytes)
}

// (a) script over limit at Deploy is rejected with typed error
// (b) message includes limit + actual + context
// (c) no broadcast happens
func TestDeploy_RejectsOversizedScript(t *testing.T) {
	artifact := makeArtifact(oversizedScriptHex(), ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     nil,
	}, func(a *RunarArtifact) { a.ContractName = "OversizedContract" })

	contract := NewRunarContract(artifact, nil)
	provider := NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := NewMockSigner("", mockAddr)
	provider.AddUtxo(mockAddr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	_, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 1000})
	if err == nil {
		t.Fatal("expected ScriptSizeExceededError, got nil")
	}
	var sizeErr *ScriptSizeExceededError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("expected *ScriptSizeExceededError, got %T: %v", err, err)
	}
	if sizeErr.Limit != MaxScriptBytes {
		t.Errorf("expected Limit=%d, got %d", MaxScriptBytes, sizeErr.Limit)
	}
	if sizeErr.Actual != MaxScriptBytes+1 {
		t.Errorf("expected Actual=%d, got %d", MaxScriptBytes+1, sizeErr.Actual)
	}
	if !strings.Contains(sizeErr.Context, "OversizedContract.Deploy") {
		t.Errorf("expected Context to contain OversizedContract.Deploy, got %s", sizeErr.Context)
	}
	if !strings.Contains(sizeErr.Error(), "limit=") || !strings.Contains(sizeErr.Error(), "actual=") {
		t.Errorf("expected error message to contain limit + actual, got %s", sizeErr.Error())
	}

	if len(provider.GetBroadcastedTxs()) != 0 {
		t.Errorf("expected no broadcasts after rejection, got %d", len(provider.GetBroadcastedTxs()))
	}
}

// Call() with an oversized currentUtxo.Script must be rejected BEFORE any signing.
func TestCall_RejectsOversizedScript(t *testing.T) {
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: nil},
		Methods:     []ABIMethod{{Name: "spend", Params: nil, IsPublic: true}},
	}, func(a *RunarArtifact) { a.ContractName = "OversizedContract" })

	contract := NewRunarContract(artifact, nil)
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
		t.Fatalf("Deploy unexpected error: %v", err)
	}

	// Poison the contract's currentUtxo with an oversized script.
	contract.currentUtxo.Script = oversizedScriptHex()

	priorBroadcasts := len(provider.GetBroadcastedTxs())
	_, _, err := contract.Call("spend", nil, provider, signer, nil)
	if err == nil {
		t.Fatal("expected ScriptSizeExceededError, got nil")
	}
	var sizeErr *ScriptSizeExceededError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("expected *ScriptSizeExceededError, got %T: %v", err, err)
	}
	if sizeErr.Limit != MaxScriptBytes {
		t.Errorf("expected Limit=%d, got %d", MaxScriptBytes, sizeErr.Limit)
	}
	if !strings.Contains(sizeErr.Context, "OversizedContract.Call(spend)") {
		t.Errorf("expected Context to contain OversizedContract.Call(spend), got %s", sizeErr.Context)
	}

	// No additional broadcast should have happened.
	if len(provider.GetBroadcastedTxs()) != priorBroadcasts {
		t.Errorf("expected broadcasts unchanged after rejected call, got %d (prior %d)",
			len(provider.GetBroadcastedTxs()), priorBroadcasts)
	}
}

func TestMockProvider_GetUtxos_RejectsOversizedScript(t *testing.T) {
	provider := NewMockProvider("testnet")
	provider.AddUtxo("addr", UTXO{
		Txid:        strings.Repeat("bb", 32),
		OutputIndex: 0,
		Satoshis:    1000,
		Script:      oversizedScriptHex(),
	})
	_, err := provider.GetUtxos("addr")
	if err == nil {
		t.Fatal("expected ScriptSizeExceededError, got nil")
	}
	var sizeErr *ScriptSizeExceededError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("expected *ScriptSizeExceededError, got %T: %v", err, err)
	}
	if !strings.Contains(sizeErr.Context, "MockProvider.GetUtxos") {
		t.Errorf("expected Context to contain MockProvider.GetUtxos, got %s", sizeErr.Context)
	}
}

func TestMockProvider_GetContractUtxo_RejectsOversizedScript(t *testing.T) {
	provider := NewMockProvider("testnet")
	provider.AddContractUtxo("script-hash", &UTXO{
		Txid:        strings.Repeat("cc", 32),
		OutputIndex: 0,
		Satoshis:    1000,
		Script:      oversizedScriptHex(),
	})
	_, err := provider.GetContractUtxo("script-hash")
	if err == nil {
		t.Fatal("expected ScriptSizeExceededError, got nil")
	}
	var sizeErr *ScriptSizeExceededError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("expected *ScriptSizeExceededError, got %T: %v", err, err)
	}
	if !strings.Contains(sizeErr.Context, "MockProvider.GetContractUtxo") {
		t.Errorf("expected Context to contain MockProvider.GetContractUtxo, got %s", sizeErr.Context)
	}
}

func TestMockProvider_AtLimitScript_Passes(t *testing.T) {
	provider := NewMockProvider("testnet")
	provider.AddUtxo("addr", UTXO{
		Txid:        strings.Repeat("dd", 32),
		OutputIndex: 0,
		Satoshis:    1000,
		Script:      atLimitScriptHex(),
	})
	utxos, err := provider.GetUtxos("addr")
	if err != nil {
		t.Fatalf("expected at-limit script to pass, got %v", err)
	}
	if len(utxos) != 1 {
		t.Fatalf("expected 1 utxo, got %d", len(utxos))
	}
	if len(utxos[0].Script) != MaxScriptBytes*2 {
		t.Errorf("unexpected script length: %d", len(utxos[0].Script))
	}
}
