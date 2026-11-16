//go:build integration

package integration

import (
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

var state1bArtifact *runar.RunarArtifact
var state1bOnce sync.Once

func getState1bArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	state1bOnce.Do(func() {
		var err error
		state1bArtifact, err = helpers.CompileToSDKArtifact(
			"integration/contracts/constructs/StateByteString1B.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile StateByteString1B: %v", err)
		}
	})
	return state1bArtifact
}

func stateString(t *testing.T, c *runar.RunarContract, field string) string {
	t.Helper()
	st := c.GetState()
	v, ok := st[field]
	if !ok {
		t.Fatalf("state has no %q; got %#v", field, st)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("state.%s is %T, expected string; got %#v", field, v, v)
	}
	return s
}

func TestStateByteString1B_Update(t *testing.T) {
	artifact := getState1bArtifact(t)
	contract := runar.NewRunarContract(artifact, []interface{}{"05"})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	txid, _, err := contract.Call("setTag", []interface{}{"ab"}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call setTag: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("txid length: %d", len(txid))
	}
	if got := stateString(t, contract, "tag"); got != "ab" {
		t.Fatalf("tag=%q, want ab", got)
	}
	if _, err := helpers.AssertOnChainState(artifact, txid, 0, map[string]interface{}{"tag": "ab"}); err != nil {
		t.Fatalf("on-chain state: %v", err)
	}
	raw, err := helpers.GetRawTransaction(txid)
	if err != nil {
		t.Fatalf("getrawtx: %v", err)
	}
	hexStr, _ := raw["hex"].(string)
	outs, err := helpers.ParseOutputsFromRawTxHex(hexStr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := helpers.AssertByteString1BFraming(outs[0].Script, "ab"); err != nil {
		t.Fatalf("framing: %v", err)
	}
}

func TestStateByteString1B_RejectWrongLength(t *testing.T) {
	artifact := getState1bArtifact(t)
	contract := runar.NewRunarContract(artifact, []interface{}{"05"})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	before := provider.BroadcastAttempts
	_, _, callErr := contract.Call("setTag", []interface{}{"abcd"}, provider, signer, nil)
	if callErr == nil {
		t.Fatal("expected reject for 2-byte tag")
	}
	if bad := helpers.CheckNodeRejected(provider, before, callErr, helpers.ScriptVerifyFailed); bad != nil {
		t.Fatalf("not a node rejection: %v", bad)
	}
}

func TestStateByteString1B_Chain(t *testing.T) {
	artifact := getState1bArtifact(t)
	contract := runar.NewRunarContract(artifact, []interface{}{"01"})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	if _, _, err := contract.Call("setTag", []interface{}{"02"}, provider, signer, nil); err != nil {
		t.Fatalf("setTag 02: %v", err)
	}
	if _, _, err := contract.Call("setTag", []interface{}{"ff"}, provider, signer, nil); err != nil {
		t.Fatalf("setTag ff: %v", err)
	}
	if got := stateString(t, contract, "tag"); got != "ff" {
		t.Fatalf("tag=%q, want ff", got)
	}
}
