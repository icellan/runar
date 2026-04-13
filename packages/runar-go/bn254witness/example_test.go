package bn254witness_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ExampleGenerateWitness_sp1 walks the end-to-end SP1 path: load a
// committed SP1 v6.0.0 verifying key, parse the raw Groth16 proof bytes,
// read the public inputs, and generate a witness bundle that can be
// pushed onto the Rúnar witness-assisted Groth16 verifier's stack.
//
// It uses the fixtures checked in at tests/vectors/sp1/v6.0.0/, which
// come verbatim from SP1's Groth16 BN254 prover output.
//
// This example doubles as a runnable smoke test: "go test -run Example"
// will fail if any of the public API functions misbehave on the real
// SP1 fixture.
func ExampleGenerateWitness_sp1() {
	fixDir := filepath.Join("..", "..", "..", "tests", "vectors", "sp1", "v6.0.0")

	// 1. Load the verifying key. β/γ/δ are already pre-negated in the
	//    file, matching the SP1 Solidity verifier convention.
	vk, err := bn254witness.LoadSP1VKFromFile(filepath.Join(fixDir, "vk.json"))
	if err != nil {
		fmt.Println("load vk:", err)
		return
	}

	// 2. Parse the raw proof (gnark-crypto's WriteRawTo output). The
	//    parser converts the native imag-first G2 byte layout to Rúnar
	//    (real, imag) order automatically.
	rawHex, err := os.ReadFile(filepath.Join(fixDir, "groth16_raw_proof.hex"))
	if err != nil {
		fmt.Println("read raw proof:", err)
		return
	}
	proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawHex)))
	if err != nil {
		fmt.Println("parse raw proof:", err)
		return
	}

	// 3. Load the public inputs (one decimal scalar per line).
	publicInputs, err := bn254witness.LoadSP1PublicInputs(
		filepath.Join(fixDir, "groth16_public_inputs.txt"),
	)
	if err != nil {
		fmt.Println("load public inputs:", err)
		return
	}

	// 4. Generate the off-chain witness bundle.
	w, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
	if err != nil {
		fmt.Println("generate witness:", err)
		return
	}

	// 5. Precompute the MillerLoop(α, -β) constant that the verifier
	//    multiplies into its accumulator. The result lives in the
	//    verifier's Groth16Config, NOT the witness.
	alphaNegBetaFp12, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	if err != nil {
		fmt.Println("precompute alpha-neg-beta:", err)
		return
	}

	// Print deterministic summary facts. We deliberately avoid printing
	// the raw witness values (which are deterministic but noisy) or the
	// Miller loop iteration count (which is an implementation detail
	// shared with codegen.Bn254SixXPlus2NAF). Anything below is a
	// structural invariant of the SP1 v6 fixture + the Witness layout.
	fmt.Printf("public inputs: %d\n", len(publicInputs))
	fmt.Printf("vk ic entries: %d\n", len(vk.IC))
	fmt.Printf("witness q nonzero: %v\n", w.Q.Sign() == 1)
	fmt.Printf("witness final-exp slots: %d\n",
		len(w.FinalExpFInv)+len(w.FinalExpA)+len(w.FinalExpB)+len(w.FinalExpC))
	fmt.Printf("witness prepared-inputs coords: %d\n", len(w.PreparedInputs))
	fmt.Printf("witness proof A/B/C slots: %d/%d/%d\n",
		len(w.ProofA), len(w.ProofB), len(w.ProofC))
	fmt.Printf("witness stack-op count > 0: %v\n", len(w.ToStackOps()) > 0)
	fmt.Printf("alpha-neg-beta fp12 slots: %d\n", len(alphaNegBetaFp12))

	// Output:
	// public inputs: 5
	// vk ic entries: 6
	// witness q nonzero: true
	// witness final-exp slots: 48
	// witness prepared-inputs coords: 2
	// witness proof A/B/C slots: 2/4/2
	// witness stack-op count > 0: true
	// alpha-neg-beta fp12 slots: 12
}
