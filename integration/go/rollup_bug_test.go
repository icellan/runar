//go:build integration

package integration

import (
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// TestRollupBug_AdvanceState reproduces bsv-evm RUNAR-OPSPLIT-BUG.md.
//
// Smallest known shape that triggers
//   `mandatory-script-verify-flag-failed (Invalid OP_SPLIT range)`
// on regtest:
//
//   - StatefulSmartContract with one ByteString mutable state field.
//   - One Point readonly field.
//   - One method calling runar.Bn254G1ScalarMulP.
//
// Once the codegen bug is fixed this test must pass.

// hexZeros64 returns a 64-byte all-zero Point (x[32]||y[32]).
func hexZeros64() string {
	return "0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"
}

func deployRollupBug(t *testing.T) (*runar.RunarContract, *helpers.Wallet) {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifact(
		"integration/go/contracts/RollupBug.runar.go",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("RollupBug script: %d bytes (%d KB)", len(artifact.Script)/2, len(artifact.Script)/2/1024)

	contract := runar.NewRunarContract(artifact, []interface{}{
		hexZeros32(), // initial State (32-byte ByteString)
	})

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

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", txid)
	return contract, wallet
}

func TestRollupBug_AdvanceState(t *testing.T) {
	contract, wallet := deployRollupBug(t)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	args := []interface{}{
		hexStateRoot(1), // newState
		int64(1),        // scalar
	}
	txid, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err != nil {
		t.Fatalf("advanceState: %v", err)
	}
	t.Logf("advance TX: %s", txid)
}
