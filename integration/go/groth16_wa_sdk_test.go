//go:build integration

package integration

import (
	"math/big"
	"testing"
	"time"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"

	"runar-integration/helpers"

	"github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Phase 7 — Groth16WAContract SDK wrapper regtest coverage.
//
// These tests mirror the raw-helper-based tests in groth16_wa_test.go but
// drive the entire lifecycle through the new runar.Groth16WAContract API.
// If they pass, bsv-evm and other downstream consumers can use the SDK
// wrapper as their only interface to Groth16 verifier contracts — they do
// not need to reach for integration/go/helpers.groth16 or raw transaction
// builders.
// ---------------------------------------------------------------------------

// buildGroth16WAArtifactFromCompiler compiles an SP1 VK file into a
// runar.RunarArtifact via the real `runarc groth16-wa` backend
// (compiler.CompileGroth16WA). This exercises the full Phase 6 pipeline
// — if the artifact's Groth16WA metadata is missing, the SDK wrapper
// will panic at the NewGroth16WAContract call, catching any regression
// in the compiler path.
func buildGroth16WAArtifactFromCompiler(t *testing.T, vkPath string) *runar.RunarArtifact {
	t.Helper()
	compArt, err := compiler.CompileGroth16WA(vkPath, compiler.Groth16WAOpts{})
	if err != nil {
		t.Fatalf("compiler.CompileGroth16WA: %v", err)
	}
	if compArt.Groth16WA == nil {
		t.Fatalf("compiled artifact has nil Groth16WA metadata")
	}
	// The compiler package and the SDK package each define their own
	// Artifact type with identical JSON shape. Translate by field copy
	// — this is the same thing downstream consumers will do when
	// loading an artifact JSON file produced by `runarc groth16-wa`.
	return &runar.RunarArtifact{
		Version:         compArt.Version,
		CompilerVersion: compArt.CompilerVersion,
		ContractName:    compArt.ContractName,
		Script:          compArt.Script,
		ASM:             compArt.ASM,
		BuildTimestamp:  compArt.BuildTimestamp,
		ABI: runar.ABI{
			Constructor: runar.ABIConstructor{Params: []runar.ABIParam{}},
			Methods: []runar.ABIMethod{
				{Name: "verify", Params: []runar.ABIParam{}, IsPublic: true},
			},
		},
		Groth16WA: &runar.Groth16WAMeta{
			NumPubInputs: compArt.Groth16WA.NumPubInputs,
			VKDigest:     compArt.Groth16WA.VKDigest,
		},
	}
}

// deployGroth16WASDK funds a fresh wallet, wraps the SP1 artifact in a
// runar.Groth16WAContract, and deploys it. Returns the SDK wrapper plus
// the deploy txid and tx size.
func deployGroth16WASDK(t *testing.T, artifact *runar.RunarArtifact, provider runar.Provider, contractSats int64) (*runar.Groth16WAContract, string, int) {
	t.Helper()

	funder := helpers.NewWallet()
	if _, err := helpers.RPCCall("importaddress", funder.Address, "", false); err != nil {
		t.Fatalf("importaddress: %v", err)
	}
	if _, err := helpers.FundWallet(funder, 1.0); err != nil {
		t.Fatalf("FundWallet: %v", err)
	}
	signer, err := helpers.SDKSignerFromWallet(funder)
	if err != nil {
		t.Fatalf("SDKSignerFromWallet: %v", err)
	}

	g := runar.NewGroth16WAContract(artifact)
	g.Connect(provider, signer)

	txid, txData, err := g.Deploy(provider, signer, runar.DeployOptions{Satoshis: contractSats})
	if err != nil {
		t.Fatalf("Groth16WAContract.Deploy: %v", err)
	}
	deployBytes := 0
	if txData != nil {
		deployBytes = len(txData.Raw) / 2
	}
	t.Logf("SDK deploy txid=%s size=%d bytes (%.1f KB)", txid, deployBytes, float64(deployBytes)/1024.0)
	if g.CurrentUTXO() == nil {
		t.Fatalf("no UTXO after SDK deploy")
	}
	return g, txid, deployBytes
}

// TestGroth16WASDK_DeployAndCall_SP1 is the full on-chain acceptance gate
// for the SDK wrapper. It compiles an SP1 VK via the Phase 6 compiler
// backend, deploys it via Groth16WAContract.Deploy, generates a real
// witness bundle, and then calls Groth16WAContract.CallWithWitness. If
// the node accepts the spend, every layer of Phase 7 is wired up
// correctly and downstream consumers can adopt the SDK.
func TestGroth16WASDK_DeployAndCall_SP1(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Groth16 WA SDK regtest test")
	}

	// Share the cached fixture (VK + proof + public inputs + pre-built
	// witness) from the existing Phase 4 integration test so we don't
	// pay the ~2 s generation cost twice in the same test binary.
	fix := getGroth16WAFixture(t)

	// Use the Phase 6 compiler backend to build the artifact — this
	// exercises compiler.CompileGroth16WA inside the integration test,
	// which is the entry point bsv-evm will use.
	vkPath := sp1FixtureDirForIntegration(t) + "/vk.json"
	artifact := buildGroth16WAArtifactFromCompiler(t, vkPath)
	if artifact.Groth16WA.NumPubInputs != len(fix.publicInputs) {
		t.Fatalf("artifact.NumPubInputs=%d, expected %d", artifact.Groth16WA.NumPubInputs, len(fix.publicInputs))
	}
	if got := artifact.Groth16WA.VKDigest; len(got) != 64 {
		t.Errorf("unexpected VKDigest length: %d", len(got))
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	g, deployTxid, deployBytes := deployGroth16WASDK(t, artifact, provider, 50000)
	t.Logf("SDK deploy succeeded: txid=%s size=%d bytes", deployTxid, deployBytes)

	// Build a receiver script for the spend output — we point it at a
	// fresh P2PKH so the test is independent of any wallet state.
	receiverWallet := helpers.NewWallet()
	receiverScriptHex := runar.BuildP2PKHScript(receiverWallet.Address)

	start := time.Now()
	spendTxid, spendData, err := g.CallWithWitness(
		nil, // provider/signer from Connect()
		nil,
		fix.witness,
		"",
		receiverScriptHex,
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Groth16WAContract.CallWithWitness: %v", err)
	}
	if spendTxid == "" {
		t.Fatalf("empty spend txid")
	}
	if spendData == nil {
		t.Fatalf("nil spendData")
	}
	spendBytes := len(spendData.Raw) / 2
	t.Logf("SDK spend txid=%s size=%d bytes (%.1f KB) total_wall=%s",
		spendTxid, spendBytes, float64(spendBytes)/1024.0, elapsed)

	if g.CurrentUTXO() != nil {
		t.Errorf("CurrentUTXO should be nil after successful spend")
	}
}

// TestGroth16WASDK_RejectsTamperedWitness mirrors the Phase 4
// TestGroth16WA_Regtest_TamperedProofA_Rejected case but drives the
// whole lifecycle through Groth16WAContract. Spending with a tampered
// proof.A must cause the node to reject the TX. CallWithWitness is
// expected to return an error; we assert that it does.
func TestGroth16WASDK_RejectsTamperedWitness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Groth16 WA SDK tamper test")
	}

	fix := getGroth16WAFixture(t)
	vkPath := sp1FixtureDirForIntegration(t) + "/vk.json"
	artifact := buildGroth16WAArtifactFromCompiler(t, vkPath)

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	g, _, _ := deployGroth16WASDK(t, artifact, provider, 50000)

	// Swap the proof's A point with the G1 generator (on-curve but not
	// the real prover's A). This keeps the on-curve check passing but
	// blows up the pairing product at the end. We regenerate the
	// witness from the tampered proof so the gradient / final-exp
	// consistency checks still pass locally — the failure should land
	// in the final pairing check inside the script.
	tamperedProof := bn254witness.Proof{
		A: [2]*big.Int{new(big.Int).Set(fix.proof.A[0]), new(big.Int).Set(fix.proof.A[1])},
		B: [4]*big.Int{
			new(big.Int).Set(fix.proof.B[0]), new(big.Int).Set(fix.proof.B[1]),
			new(big.Int).Set(fix.proof.B[2]), new(big.Int).Set(fix.proof.B[3]),
		},
		C: [2]*big.Int{new(big.Int).Set(fix.proof.C[0]), new(big.Int).Set(fix.proof.C[1])},
	}
	_, _, g1, _ := bn254.Generators()
	tamperedProof.A[0] = g1.X.BigInt(new(big.Int))
	tamperedProof.A[1] = g1.Y.BigInt(new(big.Int))

	badW, err := bn254witness.GenerateWitness(fix.vk, tamperedProof, fix.publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness for tampered proof.A: %v", err)
	}

	receiverWallet := helpers.NewWallet()
	receiverScriptHex := runar.BuildP2PKHScript(receiverWallet.Address)

	_, _, err = g.CallWithWitness(provider, nil, badW, "", receiverScriptHex)
	if err == nil {
		t.Fatalf("expected regtest node to reject tampered witness; got nil error")
	}
	t.Logf("tampered witness correctly rejected: %v", err)
}
