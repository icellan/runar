//go:build integration

package integration

import (
	"math/big"
	"os"
	"strings"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// readTrimmed reads a file and returns its contents with surrounding
// whitespace stripped.
func readTrimmed(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// TestRollupGroth16WAMSM_AdvanceState exercises the MSM-binding preamble
// end-to-end. A stateful RollupGroth16WAMSM contract is compiled with a
// real SP1 v6.0.0 vk.json baked into Groth16Config.IC, deployed to
// regtest, and advanced once with a real SP1 proof + 5 public-input
// scalars pushed as part of the witness bundle.
//
// The positive case asserts the script accepts the proof. The negative
// case (deferred — see TODO below) will assert that replacing any of the
// 5 pub_i scalars with a wrong value causes the on-chain MSM to disagree
// with the prover-supplied prepared_inputs, which aborts the script at
// the MSM equality check.
func TestRollupGroth16WAMSM_AdvanceState(t *testing.T) {
	vkPath := sp1V6FixturePath(t, "vk.json")

	contract, wallet := deployRollupGroth16WAMSM(t, vkPath)

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

// deployRollupGroth16WAMSM compiles the RollupGroth16WAMSM stateful
// contract with the SP1 vkey baked into the MSM-binding preamble,
// deploys it to regtest, and returns the contract handle and funding
// wallet.
func deployRollupGroth16WAMSM(t *testing.T, vkPath string) (*runar.RunarContract, *helpers.Wallet) {
	t.Helper()

	artifact, err := helpers.CompileToSDKArtifactWithGroth16WAVKey(
		"integration/go/contracts/RollupGroth16WAMSM.runar.go",
		vkPath,
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("RollupGroth16WAMSM script: %d bytes (%d KB)", len(artifact.Script)/2, len(artifact.Script)/2/1024)

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

// loadSP1V6MSMWitness is the MSM-variant counterpart of loadSP1V6Witness.
// It populates Witness.PublicInputs with the 5 SP1 public-input scalars
// so ToStackOps emits them between the final-exp witnesses and
// prepared_inputs — matching the MSM preamble's initNames layout.
func loadSP1V6MSMWitness(t *testing.T) *bn254witness.Witness {
	t.Helper()

	vkPath := sp1V6FixturePath(t, "vk.json")
	rawProofPath := sp1V6FixturePath(t, "groth16_raw_proof.hex")
	pubInputsPath := sp1V6FixturePath(t, "groth16_public_inputs.txt")

	vk, err := bn254witness.LoadSP1VKFromFile(vkPath)
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}

	rawHex, err := readTrimmed(rawProofPath)
	if err != nil {
		t.Fatalf("read raw proof: %v", err)
	}
	proof, err := bn254witness.ParseSP1RawProof(rawHex)
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

	witness, err := bn254witness.BuildFromProofWithInputs(vk, proof, publicInputs)
	if err != nil {
		t.Fatalf("BuildFromProofWithInputs: %v", err)
	}

	// Sanity checks.
	if witness.Q == nil || witness.Q.Sign() == 0 {
		t.Fatal("witness Q is nil or zero")
	}
	if len(witness.MillerGradients) == 0 {
		t.Fatal("witness has no Miller gradients")
	}
	for i := 0; i < 5; i++ {
		if witness.PublicInputs[i] == nil {
			t.Fatalf("witness PublicInputs[%d] is nil", i)
		}
	}
	_ = big.NewInt(0)

	return witness
}
