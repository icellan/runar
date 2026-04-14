//go:build integration

package integration

import (
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// TestRollupGroth16WA_AdvanceState exercises the Mode 3 deliverable end-to-end:
// a stateful Rúnar contract whose AdvanceState method begins with a call to
// runar.AssertGroth16WitnessAssisted (the witness-assisted Groth16 verifier
// preamble) is compiled with CompileOptions.Groth16WAVKey pointing at a real
// SP1 v6.0.0 vk.json, deployed to regtest, and advanced once with a real SP1
// proof witness pushed on top of the regular ABI args.
//
// Until the Mode 3 wiring lands this test fails at compile time:
//
//   - Groth16WAVKey is not yet a field on CompileOptions, and
//     CompileToSDKArtifactWithGroth16WAVKey does not exist.
//   - Groth16WAWitness is not yet a field on CallOptions.
//   - The frontend type-checker does not know assertGroth16WitnessAssisted, so
//     CompileFromSource rejects the .runar.go source file.
//
// The test exists FIRST so the implementation has a concrete green-or-red
// signal driving it (per project memory: failing test before fix).
func TestRollupGroth16WA_AdvanceState(t *testing.T) {
	vkPath := sp1V6FixturePath(t, "vk.json")

	contract, wallet := deployRollupGroth16WA(t, vkPath)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	witness := loadSP1V6Witness(t)

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
// SP1 vkey baked into the witness-assisted preamble, deploys it to regtest, and
// returns the contract handle plus the funding wallet.
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

// loadSP1V6Witness loads the canonical SP1 v6.0.0 fixture (vk.json + raw proof
// + 5 public inputs) and runs GenerateWitness to produce the prover-side
// witness bundle the on-chain verifier consumes.
func loadSP1V6Witness(t *testing.T) *bn254witness.Witness {
	t.Helper()

	vkPath := sp1V6FixturePath(t, "vk.json")
	rawProofPath := sp1V6FixturePath(t, "groth16_raw_proof.hex")
	pubInputsPath := sp1V6FixturePath(t, "groth16_public_inputs.txt")

	vk, err := bn254witness.LoadSP1VKFromFile(vkPath)
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}

	rawHex, err := os.ReadFile(rawProofPath)
	if err != nil {
		t.Fatalf("read raw proof: %v", err)
	}
	proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawHex)))
	if err != nil {
		t.Fatalf("ParseSP1RawProof: %v", err)
	}

	publicInputs, err := bn254witness.LoadSP1PublicInputs(pubInputsPath)
	if err != nil {
		t.Fatalf("LoadSP1PublicInputs: %v", err)
	}
	if len(publicInputs) != 5 {
		t.Fatalf("expected 5 SP1 public inputs, got %d", len(publicInputs))
	}

	witness, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}

	// Sanity-check the witness has all expected fields populated. Catches
	// silent regressions in the witness generator before they masquerade
	// as on-chain pairing failures during the spend.
	if witness.Q == nil || witness.Q.Sign() == 0 {
		t.Fatal("witness Q is nil or zero")
	}
	if len(witness.MillerGradients) == 0 {
		t.Fatal("witness has no Miller gradients")
	}
	if witness.PreparedInputs[0] == nil || witness.PreparedInputs[1] == nil {
		t.Fatal("witness has no prepared inputs")
	}
	_ = big.NewInt(0)

	return witness
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
