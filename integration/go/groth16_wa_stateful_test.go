//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// TestRollupGroth16WA_AdvanceState exercises the Mode 3 deliverable end-to-end:
// a stateful Rúnar contract whose AdvanceState method begins with a call to
// runar.AssertGroth16WitnessAssistedWithMSM (the witness-assisted Groth16
// verifier preamble) is compiled with CompileOptions.Groth16WAVKey pointing at
// the real SP1 v6.0.0 vk.json PLUS pinnedPublicInputs for the program
// verifying-key hash, exit code and vk root (the contract binds its statement
// through those pins — see RollupGroth16WA.runar.go), deployed to regtest, and
// advanced once with a real SP1 proof witness pushed on top of the regular ABI
// args.
//
// This contract used the raw runar.AssertGroth16WitnessAssisted until
// GK-BUG-006 made it a compile error: that verifier never saw the public
// inputs, so it accepted a proof of any statement.
func TestRollupGroth16WA_AdvanceState(t *testing.T) {
	vkPath := writePinnedSP1V6VK(t)

	contract, wallet := deployRollupGroth16WA(t, vkPath)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	witness := loadSP1V6MSMWitness(t)

	args := []interface{}{
		hexStateRoot(1), // newStateRoot
		int64(1),        // newBlockNumber
	}
	txid, _, err := contract.Call("advanceState", args, provider, signer, &runar.CallOptions{
		Groth16WAWitness: witness,
	})
	if err != nil {
		t.Fatalf("advanceState: %v", err)
	}
	t.Logf("advance TX: %s", txid)
}

// deployRollupGroth16WA compiles the RollupGroth16WA stateful contract with the
// SP1 vkey (and its public-input pins) baked into the witness-assisted
// preamble, deploys it to regtest, and returns the contract handle plus the
// funding wallet.
func deployRollupGroth16WA(t *testing.T, vkPath string) (*runar.RunarContract, *helpers.Wallet) {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifactWithGroth16WAVKey(
		"integration/go/contracts/RollupGroth16WA.runar.go",
		vkPath,
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("RollupGroth16WA script: %d bytes (%d KB)", len(artifact.Script)/2, len(artifact.Script)/2/1024)

	contract := runar.NewRunarContract(artifact, []interface{}{
		hexZeros32(), // initial StateRoot
		int64(0),     // initial BlockNumber
	})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	sdkSigner, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txid, _, err := contract.Deploy(provider, sdkSigner, runar.DeployOptions{Satoshis: 100000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", txid)
	return contract, wallet
}

// writePinnedSP1V6VK writes the SP1 v6.0.0 vk.json with "pinnedPublicInputs"
// fixing public inputs 0 (program verifying-key hash), 2 (exit code) and 3
// (vk root) to the fixture's values, and returns its path. RollupGroth16WA
// binds its statement through these pins.
func writePinnedSP1V6VK(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(sp1V6FixturePath(t, "vk.json"))
	if err != nil {
		t.Fatalf("read vk.json: %v", err)
	}
	var vk map[string]interface{}
	if err := json.Unmarshal(raw, &vk); err != nil {
		t.Fatalf("parse vk.json: %v", err)
	}
	pubs, err := bn254witness.LoadSP1PublicInputs(sp1V6FixturePath(t, "groth16_public_inputs.txt"))
	if err != nil {
		t.Fatalf("LoadSP1PublicInputs: %v", err)
	}
	pins := map[string]string{}
	for _, i := range []int{0, 2, 3} {
		pins[strconv.Itoa(i)] = pubs[i].String()
	}
	vk["pinnedPublicInputs"] = pins
	out, err := json.Marshal(vk)
	if err != nil {
		t.Fatalf("encode pinned vk.json: %v", err)
	}
	p := filepath.Join(t.TempDir(), "vk.pinned.json")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatalf("write pinned vk.json: %v", err)
	}
	return p
}

// sp1V6FixturePath returns the absolute path to a file in the SP1 v6.0.0
// fixture directory at tests/vectors/sp1/v6.0.0/. The path is computed
// relative to this test source file so it works regardless of where
// `go test` is invoked from.
func sp1V6FixturePath(t *testing.T, fileName string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	p := filepath.Join(repoRoot, "tests", "vectors", "sp1", "v6.0.0", fileName)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture %s not found at %s: %v", fileName, p, err)
	}
	return p
}
