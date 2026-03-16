//go:build integration

package integration

import (
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestCounter_Increment(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/stateful-counter/Counter.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Counter script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
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
}

func TestCounter_IncrementChain(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/stateful-counter/Counter.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
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

	// Increment 1 -> 2
	txid2, _, err := contract.Call("increment", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call increment (1->2): %v", err)
	}
	t.Logf("count->2 TX: %s", txid2)
	t.Logf("chain: 0->1->2 succeeded")
}

func TestCounter_IncrementThenDecrement(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/stateful-counter/Counter.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
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

	// Decrement 1 -> 0
	txid2, _, err := contract.Call("decrement", []interface{}{}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call decrement (1->0): %v", err)
	}
	t.Logf("count->0 TX: %s", txid2)
	t.Logf("chain: 0->1->0 succeeded")
}

func TestCounter_WrongStateHash_Rejected(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/stateful-counter/Counter.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// Call increment but claim count=99 instead of 1 — hashOutputs mismatch should cause rejection
	_, _, err = contract.Call("increment", []interface{}{}, provider, signer, &runar.CallOptions{
		NewState: map[string]interface{}{"count": int64(99)},
	})
	if err == nil {
		t.Fatalf("expected call with wrong state to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestCounter_DecrementFromZero_Rejected(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/stateful-counter/Counter.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 5000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// Decrement from 0 — assert(count > 0) in the contract should fail
	_, _, err = contract.Call("decrement", []interface{}{}, provider, signer, &runar.CallOptions{
		NewState: map[string]interface{}{"count": int64(-1)},
	})
	if err == nil {
		t.Fatalf("expected decrement from zero to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}
