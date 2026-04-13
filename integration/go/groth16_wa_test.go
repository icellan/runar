//go:build integration

package integration

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"runar-integration/helpers"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/icellan/runar/compilers/go/codegen"
	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Phase 4 — Groth16 Witness-Assisted verifier regtest integration
//
// Deploys the Rúnar witness-assisted BN254 Groth16 verifier as a raw
// locking script on the regtest BSV node and executes a REAL SP1 v6.0.0
// proof against it.
//
// The fixtures come from tests/vectors/sp1/v6.0.0/ and are identical to
// the ones used by packages/runar-go/bn254witness/sp1_script_test.go. If
// the go-sdk interpreter test (`TestGroth16WA_EndToEnd_SP1Proof_Script`)
// passes, and these regtest tests fail, the failure is in regtest
// tooling (fees, TX size, node policy), not the verifier math.
// ---------------------------------------------------------------------------

// sp1FixtureDirForIntegration returns the path to the SP1 fixture directory.
// The integration test package lives at `integration/go/`, so the fixture
// path is three levels up from this file.
func sp1FixtureDirForIntegration(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "vectors", "sp1", "v6.0.0")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("SP1 fixture dir %s not found: %v", dir, err)
	}
	return dir
}

// loadSP1FixturesForIntegration loads the VK, raw proof, and public inputs
// from the SP1 v6.0.0 fixture directory.
func loadSP1FixturesForIntegration(t *testing.T) (bn254witness.VerifyingKey, bn254witness.Proof, []*big.Int) {
	t.Helper()
	fixDir := sp1FixtureDirForIntegration(t)

	vk, err := bn254witness.LoadSP1VKFromFile(filepath.Join(fixDir, "vk.json"))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}

	rawHex, err := os.ReadFile(filepath.Join(fixDir, "groth16_raw_proof.hex"))
	if err != nil {
		t.Fatalf("read raw proof: %v", err)
	}
	proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawHex)))
	if err != nil {
		t.Fatalf("ParseSP1RawProof: %v", err)
	}

	publicInputs, err := bn254witness.LoadSP1PublicInputs(filepath.Join(fixDir, "groth16_public_inputs.txt"))
	if err != nil {
		t.Fatalf("LoadSP1PublicInputs: %v", err)
	}
	if len(publicInputs) != 5 {
		t.Fatalf("expected 5 SP1 public inputs, got %d", len(publicInputs))
	}

	return vk, proof, publicInputs
}

// sanityCheckSP1 runs a gnark pairing over the fixtures to confirm they
// are self-consistent before we invest minutes broadcasting a 500 KB TX.
func sanityCheckSP1(t *testing.T, vk bn254witness.VerifyingKey, proof bn254witness.Proof, publicInputs []*big.Int) {
	t.Helper()

	alpha, err := bigToG1(vk.AlphaG1)
	if err != nil {
		t.Fatalf("alpha: %v", err)
	}
	betaNeg, err := bigToG2(vk.BetaNegG2)
	if err != nil {
		t.Fatalf("betaNeg: %v", err)
	}
	gammaNeg, err := bigToG2(vk.GammaNegG2)
	if err != nil {
		t.Fatalf("gammaNeg: %v", err)
	}
	deltaNeg, err := bigToG2(vk.DeltaNegG2)
	if err != nil {
		t.Fatalf("deltaNeg: %v", err)
	}
	if !alpha.IsOnCurve() || !betaNeg.IsOnCurve() || !gammaNeg.IsOnCurve() || !deltaNeg.IsOnCurve() {
		t.Fatalf("VK point not on curve")
	}

	a, err := bigToG1(proof.A)
	if err != nil {
		t.Fatalf("proof.A: %v", err)
	}
	b, err := bigToG2(proof.B)
	if err != nil {
		t.Fatalf("proof.B: %v", err)
	}
	c, err := bigToG1(proof.C)
	if err != nil {
		t.Fatalf("proof.C: %v", err)
	}
	if !a.IsOnCurve() || !b.IsOnCurve() || !c.IsOnCurve() {
		t.Fatalf("Proof point not on curve")
	}

	if len(vk.IC) != len(publicInputs)+1 {
		t.Fatalf("IC len %d != publicInputs+1 (%d)", len(vk.IC), len(publicInputs)+1)
	}
	ic0, err := bigToG1(*vk.IC[0])
	if err != nil {
		t.Fatalf("IC[0]: %v", err)
	}
	prepared := ic0
	for i := 0; i < len(publicInputs); i++ {
		icNext, err := bigToG1(*vk.IC[i+1])
		if err != nil {
			t.Fatalf("IC[%d]: %v", i+1, err)
		}
		var scaled bn254.G1Affine
		scaled.ScalarMultiplication(&icNext, publicInputs[i])
		var sum bn254.G1Affine
		sum.Add(&prepared, &scaled)
		prepared = sum
	}

	gt, err := bn254.Pair(
		[]bn254.G1Affine{a, prepared, c, alpha},
		[]bn254.G2Affine{b, gammaNeg, deltaNeg, betaNeg},
	)
	if err != nil {
		t.Fatalf("gnark.Pair: %v", err)
	}
	var one bn254.E12
	one.SetOne()
	if !gt.Equal(&one) {
		t.Fatalf("SP1 fixture sanity check failed: pairing != 1")
	}
	t.Log("SP1 fixture gnark sanity check passed (pairing product = 1)")
}

func bigToG1(p [2]*big.Int) (bn254.G1Affine, error) {
	var out bn254.G1Affine
	if p[0] == nil || p[1] == nil {
		return out, fmt.Errorf("nil coordinate")
	}
	out.X.SetBigInt(p[0])
	out.Y.SetBigInt(p[1])
	return out, nil
}

func bigToG2(p [4]*big.Int) (bn254.G2Affine, error) {
	var out bn254.G2Affine
	for i, v := range p {
		if v == nil {
			return out, fmt.Errorf("nil coordinate at index %d", i)
		}
	}
	var x0, x1, y0, y1 fp.Element
	x0.SetBigInt(p[0])
	x1.SetBigInt(p[1])
	y0.SetBigInt(p[2])
	y1.SetBigInt(p[3])
	out.X.A0 = x0
	out.X.A1 = x1
	out.Y.A0 = y0
	out.Y.A1 = y1
	return out, nil
}

// Cache the built locking script + witness across tests so we don't pay the
// (few seconds of) emit + witness generation cost four times over.
type groth16WAFixture struct {
	vk            bn254witness.VerifyingKey
	proof         bn254witness.Proof
	publicInputs  []*big.Int
	config        codegen.Groth16Config
	lockingHex    string
	lockingBytes  int
	witness       *bn254witness.Witness
	unlockingHex  string
	unlockingSize int
}

var (
	groth16WAOnce  sync.Once
	groth16WAFix   *groth16WAFixture
	groth16WAError error
)

func getGroth16WAFixture(t *testing.T) *groth16WAFixture {
	t.Helper()
	groth16WAOnce.Do(func() {
		vk, proof, publicInputs := loadSP1FixturesForIntegration(t)
		sanityCheckSP1(t, vk, proof, publicInputs)

		alphaNegBetaFp12, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
		if err != nil {
			groth16WAError = fmt.Errorf("PrecomputeAlphaNegBeta: %w", err)
			return
		}

		// ModuloThreshold=0 forces full mod reduction after every Fp op,
		// keeping intermediate bignums small (~32 bytes) instead of allowing
		// them to grow to the threshold size before reduction. This makes
		// the script LARGER but dramatically faster to execute on both the
		// Go interpreter and the native BSV node — schoolbook bignum
		// multiplication is O(n²) in the operand size, so reducing operand
		// size by 64x makes each mul ~4096x faster. With threshold=2048,
		// the 684K-op verifier takes >30 minutes on regtest; with 0 it
		// completes in seconds.
		config := codegen.Groth16Config{
			ModuloThreshold:  0,
			AlphaNegBetaFp12: alphaNegBetaFp12,
			GammaNegG2:       vk.GammaNegG2,
			DeltaNegG2:       vk.DeltaNegG2,
		}

		lockingHex, err := helpers.BuildGroth16WALockingScript(config)
		if err != nil {
			groth16WAError = fmt.Errorf("BuildGroth16WALockingScript: %w", err)
			return
		}

		w, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
		if err != nil {
			groth16WAError = fmt.Errorf("GenerateWitness: %w", err)
			return
		}

		unlockingHex, err := helpers.BuildGroth16WAUnlockingScript(w)
		if err != nil {
			groth16WAError = fmt.Errorf("BuildGroth16WAUnlockingScript: %w", err)
			return
		}

		groth16WAFix = &groth16WAFixture{
			vk:            vk,
			proof:         proof,
			publicInputs:  publicInputs,
			config:        config,
			lockingHex:    lockingHex,
			lockingBytes:  len(lockingHex) / 2,
			witness:       w,
			unlockingHex:  unlockingHex,
			unlockingSize: len(unlockingHex) / 2,
		}
		t.Logf("Groth16 WA locking script: %d bytes (%.1f KB), ModuloThreshold=%d",
			groth16WAFix.lockingBytes, float64(groth16WAFix.lockingBytes)/1024.0, config.ModuloThreshold)
		t.Logf("Groth16 WA unlocking script: %d bytes (%.1f KB), witness ops=%d",
			groth16WAFix.unlockingSize, float64(groth16WAFix.unlockingSize)/1024.0,
			helpers.WitnessPushCount(w))
	})
	if groth16WAError != nil {
		t.Fatalf("Groth16 WA fixture init: %v", groth16WAError)
	}
	return groth16WAFix
}

// buildGroth16WAArtifact wraps the raw locking script hex as a minimal
// runar.RunarArtifact so we can use RunarContract.Deploy() for UTXO
// selection, fee estimation and broadcast.
func buildGroth16WAArtifact(lockingHex string) *runar.RunarArtifact {
	return &runar.RunarArtifact{
		Version:         "1",
		CompilerVersion: "runar-phase4",
		ContractName:    "Groth16WAVerifier",
		ABI: runar.ABI{
			Constructor: runar.ABIConstructor{Params: []runar.ABIParam{}},
			Methods: []runar.ABIMethod{
				{Name: "verify", Params: []runar.ABIParam{}, IsPublic: true},
			},
		},
		Script: lockingHex,
		ASM:    "",
	}
}

// deployGroth16WA funds a fresh wallet, deploys the Groth16 WA verifier as a
// single-output TX, and returns the contract + deploy txid + deploy TX size.
func deployGroth16WA(t *testing.T, fix *groth16WAFixture, provider *helpers.BatchRPCProvider, contractSats int64) (*runar.RunarContract, string, int) {
	t.Helper()

	funder := helpers.NewWallet()
	if _, err := helpers.RPCCall("importaddress", funder.Address, "", false); err != nil {
		t.Fatalf("importaddress: %v", err)
	}

	// Deploying a ~470 KB script needs enough sats to cover fees + a
	// sensible contract value. Regtest's fee rate is 1 sat/KB, so a 500 KB
	// TX costs ~500 sats. We fund 1 BSV (1e8 sats) which is massively
	// over-provisioned.
	if _, err := helpers.FundWallet(funder, 1.0); err != nil {
		t.Fatalf("FundWallet: %v", err)
	}

	signer, err := helpers.SDKSignerFromWallet(funder)
	if err != nil {
		t.Fatalf("SDKSignerFromWallet: %v", err)
	}

	artifact := buildGroth16WAArtifact(fix.lockingHex)
	contract := runar.NewRunarContract(artifact, []interface{}{})

	txid, txData, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 50000})
	if err != nil {
		t.Fatalf("contract.Deploy: %v", err)
	}
	deployTxSize := 0
	if txData != nil {
		deployTxSize = len(txData.Raw) / 2
	}
	t.Logf("deploy txid=%s size=%d bytes (%.1f KB)", txid, deployTxSize, float64(deployTxSize)/1024.0)

	if contract.GetCurrentUtxo() == nil {
		t.Fatalf("no UTXO after deploy")
	}
	return contract, txid, deployTxSize
}

// spendGroth16WA builds a spend TX for the deployed contract, applies the
// given unlocking script hex, and broadcasts it. Returns the spend txid,
// spend TX size in bytes, and the wall-clock time spent in SendRawTransaction.
func spendGroth16WA(t *testing.T, contract *runar.RunarContract, unlockingHex string) (string, int, time.Duration) {
	t.Helper()

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverWallet := helpers.NewWallet()
	receiverScript := receiverWallet.P2PKHScript()

	// Leave ~1000 sats for fee headroom (the spend TX is another ~470 KB
	// since it repeats the prevout script on-chain for sighash).
	outputSats := utxo.Satoshis - 2000
	if outputSats < 546 {
		outputSats = 546
	}

	spendHex, err := helpers.SpendContract(utxo, unlockingHex, receiverScript, outputSats)
	if err != nil {
		t.Fatalf("SpendContract: %v", err)
	}
	spendBytes := len(spendHex) / 2

	start := time.Now()
	txid, sendErr := helpers.SendRawTransaction(spendHex)
	elapsed := time.Since(start)
	if sendErr != nil {
		t.Fatalf("sendrawtransaction failed: %v (spend TX size=%d)", sendErr, spendBytes)
	}
	t.Logf("spend txid=%s size=%d bytes (%.1f KB) node_time=%s",
		txid, spendBytes, float64(spendBytes)/1024.0, elapsed)
	return txid, spendBytes, elapsed
}

// spendGroth16WAExpectReject builds a spend TX and expects the node to
// reject it with a script execution error.
func spendGroth16WAExpectReject(t *testing.T, contract *runar.RunarContract, unlockingHex string) {
	t.Helper()

	utxo := helpers.SDKUtxoToHelper(contract.GetCurrentUtxo())
	receiverWallet := helpers.NewWallet()
	receiverScript := receiverWallet.P2PKHScript()

	outputSats := utxo.Satoshis - 2000
	if outputSats < 546 {
		outputSats = 546
	}

	spendHex, err := helpers.SpendContract(utxo, unlockingHex, receiverScript, outputSats)
	if err != nil {
		t.Fatalf("SpendContract: %v", err)
	}

	helpers.AssertTxRejected(t, spendHex)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestGroth16WA_Regtest_BuildOnly is a fast offline sanity check that
// confirms we can build the locking + unlocking scripts and that the
// fixture numbers line up with expectations. No regtest broadcast.
func TestGroth16WA_Regtest_BuildOnly(t *testing.T) {
	fix := getGroth16WAFixture(t)
	if fix.lockingBytes < 100_000 {
		t.Errorf("locking script unexpectedly small: %d bytes", fix.lockingBytes)
	}
	if fix.unlockingSize < 8_000 {
		t.Errorf("unlocking script unexpectedly small: %d bytes", fix.unlockingSize)
	}
}

// TestGroth16WA_Regtest_Deploy_SP1 deploys the witness-assisted Groth16
// verifier locking script to regtest and confirms the UTXO is created.
// This is the minimum on-chain signal — it proves the 470 KB script fits
// in a TX the node accepts.
func TestGroth16WA_Regtest_Deploy_SP1(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Groth16 WA regtest deploy")
	}
	fix := getGroth16WAFixture(t)
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	_, txid, size := deployGroth16WA(t, fix, provider, 50000)
	if txid == "" {
		t.Fatalf("empty txid")
	}
	t.Logf("Groth16 WA deployed: txid=%s deploy_tx_size=%d bytes", txid, size)
}

// TestGroth16WA_Regtest_ValidSpend_SP1 is the full on-chain acceptance gate:
// deploy the verifier, then spend it by supplying the witness bundle for a
// real SP1 v6.0.0 proof. If the TX is accepted, a genuine SP1 Groth16 proof
// just verified on a real BSV node through Rúnar's witness-assisted script.
func TestGroth16WA_Regtest_ValidSpend_SP1(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Groth16 WA regtest spend")
	}
	fix := getGroth16WAFixture(t)
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	contract, _, deploySize := deployGroth16WA(t, fix, provider, 50000)
	t.Logf("deploy TX size: %d bytes", deploySize)

	spendTxid, spendSize, nodeTime := spendGroth16WA(t, contract, fix.unlockingHex)
	t.Logf("spend TX size: %d bytes", spendSize)
	t.Logf("spend node evaluation time: %s", nodeTime)
	if spendTxid == "" {
		t.Fatalf("empty spend txid")
	}
}

// TestGroth16WA_Regtest_TamperedProofA_Rejected flips one byte of proof.A,
// regenerates the witness bundle from the tampered proof, and expects the
// node to reject the spend.
func TestGroth16WA_Regtest_TamperedProofA_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Groth16 WA regtest tamper test")
	}
	fix := getGroth16WAFixture(t)
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	// Flip the low bit of proof.A.x. This corrupts the off-chain pairing
	// identity, so the final exponentiation witnesses will not satisfy the
	// verifier. We regenerate the witness so the gradient / final-exp
	// consistency checks still pass — the failure should land in the
	// pairing check at the end.
	tamperedProof := bn254witness.Proof{
		A: [2]*big.Int{new(big.Int).Set(fix.proof.A[0]), new(big.Int).Set(fix.proof.A[1])},
		B: [4]*big.Int{
			new(big.Int).Set(fix.proof.B[0]), new(big.Int).Set(fix.proof.B[1]),
			new(big.Int).Set(fix.proof.B[2]), new(big.Int).Set(fix.proof.B[3]),
		},
		C: [2]*big.Int{new(big.Int).Set(fix.proof.C[0]), new(big.Int).Set(fix.proof.C[1])},
	}
	// Use a legal on-curve point by picking a different proof.A: take the
	// generator of G1 (which is on-curve but not the real proof.A). The
	// verifier does an on-curve check, so we must feed it a valid point.
	var g1 bn254.G1Affine
	_, _, g1Aff, _ := bn254.Generators()
	g1 = g1Aff
	tamperedProof.A[0] = g1.X.BigInt(new(big.Int))
	tamperedProof.A[1] = g1.Y.BigInt(new(big.Int))

	badW, err := bn254witness.GenerateWitness(fix.vk, tamperedProof, fix.publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness for tampered proof.A: %v", err)
	}
	badUnlock, err := helpers.BuildGroth16WAUnlockingScript(badW)
	if err != nil {
		t.Fatalf("BuildGroth16WAUnlockingScript: %v", err)
	}

	contract, _, _ := deployGroth16WA(t, fix, provider, 50000)
	spendGroth16WAExpectReject(t, contract, badUnlock)
}

// TestGroth16WA_Regtest_TamperedGradient_Rejected flips one Miller
// gradient in the witness bundle. This keeps the proof the same but
// breaks the gradient consistency check inside the Miller loop, so the
// script should abort before reaching the pairing final check.
func TestGroth16WA_Regtest_TamperedGradient_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Groth16 WA regtest tamper test")
	}
	fix := getGroth16WAFixture(t)
	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	// Recompute the witness freshly so we can mutate it without disturbing
	// the cached good one.
	goodW, err := bn254witness.GenerateWitness(fix.vk, fix.proof, fix.publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}
	if len(goodW.MillerGradients) == 0 {
		t.Fatalf("no Miller gradients in witness")
	}
	// XOR 1 into the first gradient; the verifier's emitWitnessGradientVerify*
	// step recomputes lambda*denom and OP_EQUALVERIFYs it against numer, so
	// any single-bit mutation aborts the script.
	mutated := new(big.Int).Set(goodW.MillerGradients[0])
	mutated.Xor(mutated, big.NewInt(1))
	goodW.MillerGradients[0] = mutated

	badUnlock, err := helpers.BuildGroth16WAUnlockingScript(goodW)
	if err != nil {
		t.Fatalf("BuildGroth16WAUnlockingScript: %v", err)
	}

	contract, _, _ := deployGroth16WA(t, fix, provider, 50000)
	spendGroth16WAExpectReject(t, contract, badUnlock)
}
