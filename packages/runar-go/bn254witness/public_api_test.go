package bn254witness_test

// This file is a compile-time and run-time regression gate on the public
// API surface of the bn254witness package. It lives in an EXTERNAL test
// package (bn254witness_test, not bn254witness) so that it sees exactly
// what a downstream consumer would see — only the exported identifiers.
//
// If any of the symbols below accidentally become unexported (lowercase
// first letter, moved to an internal subpackage, etc.), this file will
// fail to compile and the build will break. This is intentional — adding
// or changing public API requires updating both this gate and the
// package README.
//
// The happy-path test at the bottom also exercises the SP1 fixture to
// confirm the public API is sufficient for real use — no private helper
// is required to get from "SP1 files on disk" to "witness ready to push".

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Compile-time assertions: every intended public symbol must be reachable
// from an external package by its exported name. These `var _ = ...`
// bindings are purely for the Go compiler — they have no runtime effect
// but they will fail the build if any symbol is renamed, removed, or
// given a new signature.
// ---------------------------------------------------------------------------

// Types.
var (
	_ bn254witness.Witness
	_ bn254witness.VerifyingKey
	_ bn254witness.Proof
	_ bn254witness.SP1VKFile
)

// Pointer types — callers frequently hold *Witness, etc.
var (
	_ *bn254witness.Witness
	_ *bn254witness.VerifyingKey
	_ *bn254witness.Proof
)

// Functions — take a function value for each exported func so the
// compiler checks the signature against our expectation.
var (
	_ func(vk bn254witness.VerifyingKey, proof bn254witness.Proof, publicInputs []*big.Int) (*bn254witness.Witness, error) = bn254witness.GenerateWitness
	_ func(alphaG1 [2]*big.Int, betaNegG2 [4]*big.Int) ([12]*big.Int, error)                                                = bn254witness.PrecomputeAlphaNegBeta
	_ func(path string) (bn254witness.VerifyingKey, error)                                                                  = bn254witness.LoadSP1VKFromFile
	_ func(rawProofHex string) (bn254witness.Proof, error)                                                                  = bn254witness.ParseSP1RawProof
	_ func(path string) ([]*big.Int, error)                                                                                 = bn254witness.LoadSP1PublicInputs
	_ func(alphaG1 bn254.G1Affine, betaNegG2, gammaNegG2, deltaNegG2 bn254.G2Affine, icG1 []bn254.G1Affine) bn254witness.VerifyingKey = bn254witness.GnarkVKToWitnessInputs
	_ func(alphaG1 bn254.G1Affine, betaG2, gammaG2, deltaG2 bn254.G2Affine, icG1 []bn254.G1Affine) bn254witness.VerifyingKey         = bn254witness.NewVerifyingKeyFromPositive
	_ func(ar bn254.G1Affine, bs bn254.G2Affine, krs bn254.G1Affine) bn254witness.Proof                                     = bn254witness.GnarkProofToWitnessInputs
	_ func(p bn254.G1Affine) [2]*big.Int                                                                                    = bn254witness.G1AffineToBig
	_ func(p bn254.G2Affine) [4]*big.Int                                                                                    = bn254witness.G2AffineToBig
)

// Method on *Witness — assert the exact method signature by assigning
// a method expression (not a method value; method expressions can be
// taken from the type without needing a non-nil receiver).
var _ func(*bn254witness.Witness) []codegen.StackOp = (*bn254witness.Witness).ToStackOps

// ---------------------------------------------------------------------------
// Run-time smoke test: a downstream consumer must be able to go from
// SP1 fixtures on disk to a Witness + PrecomputeAlphaNegBeta result using
// ONLY the public API (no private helpers). This asserts that.
// ---------------------------------------------------------------------------

// TestPublicAPI_SP1HappyPath_ExternalConsumer runs through the full SP1
// flow using only exported symbols. It mirrors the example in
// example_test.go but adds real assertions so the test framework will
// flag any regression, not just output drift.
func TestPublicAPI_SP1HappyPath_ExternalConsumer(t *testing.T) {
	fixDir := filepath.Join("..", "..", "..", "tests", "vectors", "sp1", "v6.0.0")

	vk, err := bn254witness.LoadSP1VKFromFile(filepath.Join(fixDir, "vk.json"))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}
	if len(vk.IC) != 6 {
		t.Fatalf("expected 6 IC entries (numPubInputs=5 + 1), got %d", len(vk.IC))
	}

	rawHex, err := os.ReadFile(filepath.Join(fixDir, "groth16_raw_proof.hex"))
	if err != nil {
		t.Fatalf("read raw proof: %v", err)
	}
	proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawHex)))
	if err != nil {
		t.Fatalf("ParseSP1RawProof: %v", err)
	}

	publicInputs, err := bn254witness.LoadSP1PublicInputs(
		filepath.Join(fixDir, "groth16_public_inputs.txt"),
	)
	if err != nil {
		t.Fatalf("LoadSP1PublicInputs: %v", err)
	}
	if len(publicInputs) != 5 {
		t.Fatalf("expected 5 public inputs, got %d", len(publicInputs))
	}

	w, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}
	if w == nil {
		t.Fatal("GenerateWitness returned nil witness with no error")
	}

	// Sanity-check the shape of the witness. Sizes are fixed by the Fp12
	// layout and the number of pairs — they are not fixture-dependent.
	if got := len(w.FinalExpFInv); got != 12 {
		t.Errorf("FinalExpFInv len = %d, want 12", got)
	}
	if got := len(w.FinalExpA); got != 12 {
		t.Errorf("FinalExpA len = %d, want 12", got)
	}
	if got := len(w.FinalExpB); got != 12 {
		t.Errorf("FinalExpB len = %d, want 12", got)
	}
	if got := len(w.FinalExpC); got != 12 {
		t.Errorf("FinalExpC len = %d, want 12", got)
	}
	if got := len(w.ProofB); got != 4 {
		t.Errorf("ProofB len = %d, want 4 (x0, x1, y0, y1)", got)
	}
	if w.Q == nil || w.Q.Sign() != 1 {
		t.Errorf("Witness.Q must be a positive *big.Int, got %v", w.Q)
	}

	// A non-empty gradient slice means the Miller loop ran. The exact
	// count is an implementation detail of codegen.Bn254SixXPlus2NAF,
	// so we only assert that it is non-trivial.
	if len(w.MillerGradients) == 0 {
		t.Error("MillerGradients is empty — Miller loop did not run")
	}

	// ToStackOps must return a push sequence matching the Witness shape.
	ops := w.ToStackOps()
	if len(ops) == 0 {
		t.Error("ToStackOps returned no ops")
	}

	// PrecomputeAlphaNegBeta reads from the VK — its output feeds the
	// codegen.Groth16Config, not the witness.
	alphaNegBetaFp12, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	if err != nil {
		t.Fatalf("PrecomputeAlphaNegBeta: %v", err)
	}
	if len(alphaNegBetaFp12) != 12 {
		t.Errorf("PrecomputeAlphaNegBeta returned %d slots, want 12", len(alphaNegBetaFp12))
	}
	for i, v := range alphaNegBetaFp12 {
		if v == nil {
			t.Errorf("PrecomputeAlphaNegBeta slot %d is nil", i)
		}
	}
}
