package bn254witness_test

// Phase 3 end-to-end validation: run a REAL SP1 v6.0.0 Groth16 BN254 proof
// through the Rúnar witness-assisted verifier. The fixtures live in
// tests/vectors/sp1/v6.0.0/ and come verbatim from bsv-evm's host-evm
// prover output (guest = simplified EVM balance transfer).
//
// This test is the "SP1 drops in with zero transformation" proof: the VK
// JSON is loaded as-is (β, γ, δ pre-negated on the Solidity side) and fed
// directly into Groth16Config without any additional swapping or negation.
// If the on-chain script accepts it, the SP1 convention refactor worked.
//
// Layered tests:
//   1. TestSP1Proof_SanityCheckViaGnark — fast offline validation that the
//      fixtures are self-consistent. Computes gnark.Pair(A, B, L, -γ, C, -δ,
//      α, -β) and asserts the result is 1 in Fp12. Runs in milliseconds.
//   2. TestGroth16WA_EndToEnd_SP1Proof_Script — slow on-chain validation
//      that pushes the witness through codegen.BuildAndExecuteOps. Only
//      useful if #1 passes first.

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// sp1FixtureDir returns the path to the SP1 v6.0.0 fixture directory
// relative to this test file's directory. The test file lives at
// `packages/runar-go/bn254witness/` and the fixtures are at
// `tests/vectors/sp1/v6.0.0/` from the repo root, so we climb 3 levels.
func sp1FixtureDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	dir := filepath.Join(wd, "..", "..", "..", "tests", "vectors", "sp1", "v6.0.0")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("fixture dir %s not found: %v", dir, err)
	}
	return dir
}

// loadSP1Fixtures loads vk.json, groth16_raw_proof.hex, and
// groth16_public_inputs.txt from the SP1 fixture directory.
func loadSP1Fixtures(t *testing.T) (bn254witness.VerifyingKey, bn254witness.Proof, []*big.Int) {
	t.Helper()
	fixDir := sp1FixtureDir(t)

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
		t.Fatalf("expected 5 public inputs, got %d", len(publicInputs))
	}

	return vk, proof, publicInputs
}

// TestSP1Proof_SanityCheckViaGnark validates the SP1 fixtures + VK extraction
// using gnark-crypto's high-level Pair function. If this test fails, the VK
// JSON has bad constants, the raw proof parser is broken, or we picked the
// wrong public input indexing — and running the full on-chain script test
// would waste minutes failing for an upstream reason.
//
// Equation (SP1 convention, β/γ/δ pre-negated in the VK):
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1   in GT
//
// where L = IC[0] + Σ pub_i · IC[i+1] is the prepared-inputs G1 accumulator.
func TestSP1Proof_SanityCheckViaGnark(t *testing.T) {
	vk, proof, publicInputs := loadSP1Fixtures(t)

	// Convert the VK's big.Int storage form back into gnark affine points.
	alpha, err := bigToG1Affine(vk.AlphaG1)
	if err != nil {
		t.Fatalf("alpha: %v", err)
	}
	betaNeg, err := bigToG2Affine(vk.BetaNegG2)
	if err != nil {
		t.Fatalf("betaNeg: %v", err)
	}
	gammaNeg, err := bigToG2Affine(vk.GammaNegG2)
	if err != nil {
		t.Fatalf("gammaNeg: %v", err)
	}
	deltaNeg, err := bigToG2Affine(vk.DeltaNegG2)
	if err != nil {
		t.Fatalf("deltaNeg: %v", err)
	}

	// Check that each VK point is actually on the curve. A subtle Fp2-swap
	// bug in either the vk.json authoring or the loader would produce
	// off-curve points, and we want a clear error message for that.
	if !alpha.IsOnCurve() {
		t.Fatalf("vk.alpha is not on G1 curve")
	}
	if !betaNeg.IsOnCurve() {
		t.Fatalf("vk.betaNeg is not on G2 curve")
	}
	if !gammaNeg.IsOnCurve() {
		t.Fatalf("vk.gammaNeg is not on G2 curve")
	}
	if !deltaNeg.IsOnCurve() {
		t.Fatalf("vk.deltaNeg is not on G2 curve")
	}

	// Parse the proof points.
	a, err := bigToG1Affine(proof.A)
	if err != nil {
		t.Fatalf("proof.A: %v", err)
	}
	b, err := bigToG2Affine(proof.B)
	if err != nil {
		t.Fatalf("proof.B: %v", err)
	}
	c, err := bigToG1Affine(proof.C)
	if err != nil {
		t.Fatalf("proof.C: %v", err)
	}
	if !a.IsOnCurve() {
		t.Fatalf("proof.A is not on G1 curve")
	}
	if !b.IsOnCurve() {
		t.Fatalf("proof.B is not on G2 curve")
	}
	if !c.IsOnCurve() {
		t.Fatalf("proof.C is not on G1 curve")
	}

	// Compute prepared inputs L = IC[0] + Σ pub_i · IC[i+1] on G1.
	if len(vk.IC) != len(publicInputs)+1 {
		t.Fatalf("VK IC len %d != publicInputs+1 (%d)", len(vk.IC), len(publicInputs)+1)
	}
	ic0, err := bigToG1Affine(*vk.IC[0])
	if err != nil {
		t.Fatalf("IC[0]: %v", err)
	}
	prepared := ic0
	for i := 0; i < len(publicInputs); i++ {
		icNext, err := bigToG1Affine(*vk.IC[i+1])
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
		t.Fatalf("bn254.Pair: %v", err)
	}

	var one bn254.E12
	one.SetOne()
	if !gt.Equal(&one) {
		t.Fatalf(
			"SP1 fixture sanity check failed: e(A,B)·e(L,-γ)·e(C,-δ)·e(α,-β) = %s (want 1)",
			gt.String(),
		)
	}
	t.Log("SP1 fixture sanity check passed: pairing product = 1 in GT")
}

// TestGroth16WA_EndToEnd_SP1Proof_Script runs the full witness-assisted
// verifier over a real SP1 v6.0.0 proof through the go-sdk Bitcoin Script
// interpreter. This is the Phase 3 acceptance gate — if it passes, the
// Rúnar Groth16 refactor to match SP1's convention is functionally correct
// and the SP1 verifying key drops in with zero transformation.
//
// This test is slow (minutes, not seconds) because the witness-assisted
// verifier is ~700K stack ops and the go-sdk interpreter uses O(n²) big
// int ops. Do not run it with ModuloThreshold=2048 on the go-sdk interp —
// use ModuloThreshold=0 (same as TestGroth16WA_EndToEnd_TrivialProof_Script).
func TestGroth16WA_EndToEnd_SP1Proof_Script(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SP1 D0 on -short (minutes-long interpreter run)")
	}
	vk, proof, publicInputs := loadSP1Fixtures(t)

	// Generate witnesses using ALL 5 public inputs (including the zero
	// exit_code and proof_nonce values). The MSM is now run off-chain by
	// the witness generator, so zero inputs are handled natively and no
	// pre-filtering is required — the whole VK drops in verbatim.
	t.Logf("SP1 public inputs: %d (all used, including zeros)", len(publicInputs))

	w, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}

	alphaNegBetaFp12, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	if err != nil {
		t.Fatalf("PrecomputeAlphaNegBeta: %v", err)
	}

	// Build the codegen config directly from the VK fields — no
	// transformation. This is the load-bearing "SP1 drops in" assertion.
	// ModuloThreshold=0 is the go-sdk interpreter performance workaround
	// documented in TestGroth16WA_EndToEnd_TrivialProof_Script; it's not a
	// correctness flag.
	config := codegen.Groth16Config{
		ModuloThreshold:  0,
		AlphaNegBetaFp12: alphaNegBetaFp12,
		GammaNegG2:       vk.GammaNegG2,
		DeltaNegG2:       vk.DeltaNegG2,
	}

	var verifierOps []codegen.StackOp
	codegen.EmitGroth16VerifierWitnessAssisted(func(op codegen.StackOp) {
		verifierOps = append(verifierOps, op)
	}, config)

	var ops []codegen.StackOp
	ops = append(ops, w.ToStackOps()...)
	ops = append(ops, verifierOps...)

	t.Logf("SP1 D0: witness ops=%d  verifier ops=%d  total=%d",
		len(w.ToStackOps()), len(verifierOps), len(ops))

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("SP1 Groth16 WA verifier failed: %v", err)
	}
}

// bigToG1Affine converts a [2]*big.Int (x, y) into a gnark bn254.G1Affine
// by setting the affine coordinates directly. No sanity check is applied —
// the caller should call IsOnCurve on the result.
func bigToG1Affine(p [2]*big.Int) (bn254.G1Affine, error) {
	var out bn254.G1Affine
	var x, y fp.Element
	if _, err := setFpFromBig(&x, p[0]); err != nil {
		return out, fmt.Errorf("G1 x: %w", err)
	}
	if _, err := setFpFromBig(&y, p[1]); err != nil {
		return out, fmt.Errorf("G1 y: %w", err)
	}
	out.X = x
	out.Y = y
	return out, nil
}

// bigToG2Affine converts a [4]*big.Int (x0, x1, y0, y1) in Rúnar (real, imag)
// order into a gnark bn254.G2Affine. gnark E2 is {A0=real, A1=imag}, so this
// is a direct assignment with no swap.
func bigToG2Affine(p [4]*big.Int) (bn254.G2Affine, error) {
	var out bn254.G2Affine
	if _, err := setFpFromBig(&out.X.A0, p[0]); err != nil {
		return out, fmt.Errorf("G2 x.A0: %w", err)
	}
	if _, err := setFpFromBig(&out.X.A1, p[1]); err != nil {
		return out, fmt.Errorf("G2 x.A1: %w", err)
	}
	if _, err := setFpFromBig(&out.Y.A0, p[2]); err != nil {
		return out, fmt.Errorf("G2 y.A0: %w", err)
	}
	if _, err := setFpFromBig(&out.Y.A1, p[3]); err != nil {
		return out, fmt.Errorf("G2 y.A1: %w", err)
	}
	return out, nil
}

// setFpFromBig sets an fp.Element from a *big.Int. Gnark's SetBigInt doesn't
// return an error — we wrap it so callers can attach location context.
func setFpFromBig(e *fp.Element, v *big.Int) (*fp.Element, error) {
	if v == nil {
		return nil, fmt.Errorf("nil big.Int")
	}
	e.SetBigInt(v)
	return e, nil
}
