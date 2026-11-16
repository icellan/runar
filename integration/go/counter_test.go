//go:build integration

package integration

import (
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

var counterArtifact *runar.RunarArtifact
var counterOnce sync.Once

func getCounterArtifact(t *testing.T) *runar.RunarArtifact {
	counterOnce.Do(func() {
		var err error
		counterArtifact, err = helpers.CompileToSDKArtifact(
			"examples/ts/stateful-counter/Counter.runar.ts",
			map[string]interface{}{},
		)
		if err != nil {
			t.Fatalf("compile Counter: %v", err)
		}
	})
	return counterArtifact
}

// assertOnChainCount decodes the `count` field out of the state section of
// the contract's CURRENT on-chain UTXO (i.e. the real bytes the node just
// accepted) and compares it to want. Deliberately does NOT use
// contract.GetState() — see helpers.ReadOnChainState's doc comment for why
// the SDK's in-memory next-state prediction is the wrong oracle here.
func assertOnChainCount(t *testing.T, artifact *runar.RunarArtifact, contract *runar.RunarContract, want int64) {
	t.Helper()
	utxo := contract.GetCurrentUtxo()
	if utxo == nil {
		t.Fatalf("assertOnChainCount: no current UTXO tracked on the contract")
	}
	state, err := helpers.ReadOnChainState(artifact, utxo.Txid, utxo.OutputIndex)
	if err != nil {
		t.Fatalf("assertOnChainCount: %v", err)
	}
	got, ok := state["count"].(int64)
	if !ok {
		t.Fatalf("assertOnChainCount: on-chain state.count is %T (%#v), want int64", state["count"], state["count"])
	}
	if got != want {
		t.Fatalf("on-chain state.count (tx %s output %d): got %d, want %d", utxo.Txid, utxo.OutputIndex, got, want)
	}
}

func TestCounter_Increment(t *testing.T) {
	artifact := getCounterArtifact(t)
	t.Logf("Counter script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err := helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	callTxid, _, err := contract.Call("increment", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call increment: %v", err)
	}
	t.Logf("increment TX confirmed: %s", callTxid)

	// increment: count 0 -> 1. Read the value back out of the ACTUAL output
	// script the node accepted, not the SDK's predicted next state.
	assertOnChainCount(t, artifact, contract, 1)
}

func TestCounter_IncrementChain(t *testing.T) {
	artifact := getCounterArtifact(t)

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err := helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	// Increment 0 -> 1
	txid1, _, err := contract.Call("increment", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call increment (0->1): %v", err)
	}
	t.Logf("count->1 TX: %s", txid1)
	assertOnChainCount(t, artifact, contract, 1)

	// Increment 1 -> 2
	txid2, _, err := contract.Call("increment", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call increment (1->2): %v", err)
	}
	t.Logf("count->2 TX: %s", txid2)
	assertOnChainCount(t, artifact, contract, 2)
	t.Logf("chain: 0->1->2 succeeded")
}

func TestCounter_IncrementThenDecrement(t *testing.T) {
	artifact := getCounterArtifact(t)

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err := helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	// Increment 0 -> 1
	txid1, _, err := contract.Call("increment", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call increment (0->1): %v", err)
	}
	t.Logf("count->1 TX: %s", txid1)
	assertOnChainCount(t, artifact, contract, 1)

	// Decrement 1 -> 0
	txid2, _, err := contract.Call("decrement", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call decrement (1->0): %v", err)
	}
	t.Logf("count->0 TX: %s", txid2)
	assertOnChainCount(t, artifact, contract, 0)
	t.Logf("chain: 0->1->0 succeeded")
}

func TestCounter_WrongStateHash_Rejected(t *testing.T) {
	artifact := getCounterArtifact(t)

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err := helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// Call increment but claim count=99 instead of 1 — hashOutputs mismatch should cause rejection
	before := provider.BroadcastAttempts
	_, _, err = contract.Call("increment", []interface{}{}, provider, signer, &runar.CallOptions{
		NewState: map[string]interface{}{"count": int64(99)},
	})
	if err == nil {
		t.Fatalf("expected call with wrong state to be rejected, but it succeeded")
	}
	if bad := helpers.CheckNodeRejected(provider, before, err, helpers.ScriptVerifyFailed); bad != nil {
		t.Fatalf("not a node rejection: %v", bad)
	}
	t.Logf("correctly rejected: %v", err)
}

func TestCounter_DecrementFromZero_Rejected(t *testing.T) {
	artifact := getCounterArtifact(t)

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err := helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// Decrement from 0 — assert(count > 0) in the contract should fail
	before := provider.BroadcastAttempts
	_, _, err = contract.Call("decrement", []interface{}{}, provider, signer, &runar.CallOptions{
		NewState: map[string]interface{}{"count": int64(-1)},
	})
	if err == nil {
		t.Fatalf("expected decrement from zero to be rejected, but it succeeded")
	}
	if bad := helpers.CheckNodeRejected(provider, before, err, helpers.ScriptVerifyFailed); bad != nil {
		t.Fatalf("not a node rejection: %v", bad)
	}
	t.Logf("correctly rejected: %v", err)
}
