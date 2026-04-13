// Package bn254witness produces witness bundles for the Rúnar
// witness-assisted BN254 Groth16 verifier emitted by
// compilers/go/codegen.EmitGroth16VerifierWitnessAssisted.
//
// # Why witness-assisted verification
//
// Groth16 verification on BN254 is dominated by two costly operations:
// field inversions inside the Miller loop gradients, and the final
// exponentiation. Neither fits comfortably inside a Bitcoin Script budget.
// Witness-assisted verification moves both operations off-chain: the
// prover computes the per-iteration Miller loop gradients and four Fp12
// witness values (f^-1, f2^x, f2^(x^2), f2^(x^3)) and pushes them onto
// the stack alongside the proof. The on-chain verifier then only has to
// check that the supplied witnesses are consistent — multiplications,
// squarings, and Frobenius maps, all cheap — and that the resulting
// pairing product equals one. The same strategy is used by the
// prepared-inputs MSM: the prover folds public inputs into a single G1
// accumulator off-chain so the script does not have to run variable-base
// scalar multiplication.
//
// This package is the off-chain half of that protocol. It takes a
// verifying key, a proof, and a list of public input scalars, and produces
// a Witness bundle that matches, byte-for-byte, the stack layout the
// emitted verifier script expects at entry.
//
// # The two canonical input paths
//
// SP1 path — load fixtures straight from the SP1 Groth16 prover output:
//
//	vk, err := bn254witness.LoadSP1VKFromFile("vk.json")
//	proof, err := bn254witness.ParseSP1RawProof(rawProofHex)
//	pubs, err := bn254witness.LoadSP1PublicInputs("groth16_public_inputs.txt")
//	w, err := bn254witness.GenerateWitness(vk, proof, pubs)
//	ops := w.ToStackOps()
//
// Gnark path — build the VK from gnark-crypto affine points directly
// (useful for custom circuits or synthetic test instances):
//
//	vk := bn254witness.NewVerifyingKeyFromPositive(alphaG1, betaG2, gammaG2, deltaG2, icG1)
//	proof := bn254witness.GnarkProofToWitnessInputs(arG1, bsG2, krsG1)
//	w, err := bn254witness.GenerateWitness(vk, proof, pubs)
//
// In both paths the resulting Witness is fed into codegen-generated
// Groth16Config via PrecomputeAlphaNegBeta and then into
// codegen.EmitGroth16VerifierWitnessAssisted. See
// integration/go/helpers/groth16.go for the full deploy/spend flow.
//
// # Fp2 ordering
//
// Rúnar stores Fp2 elements as (real, imaginary) — real part first. This
// matches gnark-crypto's in-memory E2 type (A0 = real, A1 = imag) and the
// `_0`/`_1` naming used by SP1's Solidity verifier. It does NOT match the
// byte layout gnark-crypto uses when writing G2 points to disk (that
// format is imag-first). The converters in this package do the right
// thing for each source:
//
//   - GnarkVKToWitnessInputs / NewVerifyingKeyFromPositive /
//     GnarkProofToWitnessInputs take in-memory gnark-crypto affines, no swap.
//   - ParseSP1RawProof takes raw WriteRawTo bytes and does the swap.
//   - LoadSP1VKFromFile takes the Rúnar SP1 vk.json schema, which already
//     uses x0=real, x1=imag.
//
// # Negation convention
//
// The emitted verifier uses the SP1 rearrangement of Groth's 2016 equation:
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//
// so β, γ, and δ are stored PRE-NEGATED in VerifyingKey.BetaNegG2,
// GammaNegG2, DeltaNegG2. α is positive. If you are starting from positive
// β, γ, δ (e.g. a gnark-built VK), use NewVerifyingKeyFromPositive which
// applies the negation for you. For SP1 inputs, the vk.json already stores
// the negated values verbatim and LoadSP1VKFromFile is a pure deserializer.
//
// # Iteration alignment
//
// The Miller loop iterates over codegen.Bn254SixXPlus2NAF() — the NAF
// representation of |6x+2|. This package drives its internal triple Miller
// loop from the same slice, so the captured gradients land in exactly the
// slots the verifier checks. Any deviation in iteration count or digit
// order produces gradients in the wrong slot and the on-chain verifier
// will reject.
//
// See README.md and example_test.go in this package directory for a
// runnable quick start, and tests/vectors/sp1/v6.0.0/ for a real SP1 v6
// fixture.
package bn254witness

import (
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/icellan/runar/compilers/go/codegen"
)

// Witness is the complete prover-supplied bundle, in the exact order
// EmitGroth16VerifierWitnessAssisted expects at stack initialization.
//
// The fields below are documented bottom-to-top from the verifier's view:
// Q is pushed first (deepest), ProofC is pushed last (top of stack).
// ToStackOps emits this order.
//
// Note: public inputs themselves are NOT carried in the witness — the
// prover folds them into PreparedInputs off-chain. Callers pass the
// public input scalars to GenerateWitness and the helper computes the
// G1 accumulator. This lets the witness generator handle the zero-input
// case (0*IC = identity) that the strict on-chain add helper cannot
// represent.
type Witness struct {
	// Q is the BN254 field prime, pushed as _q at the deepest position.
	// The verifier verifies q == Bn254FieldPrime() at the start.
	Q *big.Int

	// MillerGradients is a flat slice of Fp values, interleaved per Miller
	// loop iteration as: d1_0, d1_1, d2_0, d2_1, d3_0, d3_1 (the three
	// pairs' doubling gradients), then if naf[i] != 0, a1_0, a1_1, a2_0,
	// a2_1, a3_0, a3_1 (the addition gradients). The number of iterations
	// is len(codegen.Bn254SixXPlus2NAF()) - 1 (msbIdx down to 0).
	MillerGradients []*big.Int

	// FinalExpFInv is f^-1 in Fp12, the witness for the easy-part inverse
	// check (12 Fp values in gnark flat order: C0.B0.A0, C0.B0.A1, ...,
	// C1.B2.A1).
	FinalExpFInv [12]*big.Int

	// FinalExpA is f2^x where f2 = f^((p^6-1)*(p^2+1)) (the easy part output).
	FinalExpA [12]*big.Int

	// FinalExpB is f2^(x^2) = (f2^x)^x.
	FinalExpB [12]*big.Int

	// FinalExpC is f2^(x^3) = (f2^(x^2))^x.
	FinalExpC [12]*big.Int

	// PreparedInputs is the off-chain-computed G1 point
	//   IC[0] + sum_{j} (publicInputs[j] * IC[j+1])
	// stored in Rúnar [x, y] order. The on-chain verifier does a single
	// on-curve check and uses this as the G1 input for pair 2 (against
	// -gamma_G2). Because the sum is computed off-chain, zero-valued
	// public inputs are handled natively (0*IC = identity is the additive
	// unit and contributes nothing).
	PreparedInputs [2]*big.Int

	// ProofA is the proof's A point (G1 affine, [x, y]).
	ProofA [2]*big.Int

	// ProofB is the proof's B point (G2 affine in Rúnar order: [x0, x1, y0, y1]
	// where x = x0 + x1*u, y = y0 + y1*u, real part first).
	ProofB [4]*big.Int

	// ProofC is the proof's C point (G1 affine, [x, y]).
	ProofC [2]*big.Int
}

// VerifyingKey is the input form of a Groth16 verification key. Mirrors
// the codegen.Groth16Config shape; G2 points must be in Rúnar (real, imag)
// order AND PRE-NEGATED (matching the SP1 Solidity verifier convention
// where β, γ, δ are stored as BETA_NEG, GAMMA_NEG, DELTA_NEG in the VK).
//
// The verifier checks the SP1 rearrangement:
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//
// so the fields below hold -β, -γ, -δ. α is positive. If you have
// POSITIVE β, γ, δ values (e.g. from a custom prover), use
// NewVerifyingKeyFromPositive to do the negation for you.
//
// Use GnarkProofToWitnessInputs or ParseSP1RawProof to convert from external
// formats — those helpers apply the Fp2 swap correctly.
type VerifyingKey struct {
	AlphaG1    [2]*big.Int    // (x, y) in Fp, positive
	BetaNegG2  [4]*big.Int    // -β, (x0, x1, y0, y1) in Rúnar order
	GammaNegG2 [4]*big.Int    // -γ, (x0, x1, y0, y1) in Rúnar order
	DeltaNegG2 [4]*big.Int    // -δ, (x0, x1, y0, y1) in Rúnar order
	IC         []*[2]*big.Int // IC[0], IC[1], ..., IC[numPubInputs] (G1 points)
}

// Proof is the input form of a Groth16 proof in Rúnar conventions.
// G2 (proof.B) is in (real, imag) order. Use GnarkProofToWitnessInputs or
// ParseSP1RawProof to convert from external formats.
type Proof struct {
	A [2]*big.Int
	B [4]*big.Int
	C [2]*big.Int
}

// GenerateWitness runs the off-chain computation that produces the complete
// witness bundle for a given VK + proof + public inputs. It validates that
// the input lengths are consistent (len(IC) == len(publicInputs)+1) and
// returns an error otherwise.
//
// The math is performed using gnark-crypto Fp/Fp2/Fp12 primitives. The
// Miller loop iteration is driven by codegen.Bn254SixXPlus2NAF() to stay
// in lockstep with the on-chain verifier.
//
// Note on zero public inputs: this helper computes the MSM
// (IC[0] + sum(pub_j * IC[j+1])) off-chain, so zero scalars are handled
// natively (0*IC = identity, the additive unit). Callers no longer need
// to pre-filter zero values.
func GenerateWitness(vk VerifyingKey, proof Proof, publicInputs []*big.Int) (*Witness, error) {
	if len(vk.IC) != len(publicInputs)+1 {
		return nil, fmt.Errorf(
			"bn254witness: VK has %d IC points but %d public inputs (expected %d IC)",
			len(vk.IC), len(publicInputs), len(publicInputs)+1,
		)
	}

	w := &Witness{
		Q:      codegen.Bn254FieldPrime(),
		ProofA: [2]*big.Int{new(big.Int).Set(proof.A[0]), new(big.Int).Set(proof.A[1])},
		ProofB: [4]*big.Int{new(big.Int).Set(proof.B[0]), new(big.Int).Set(proof.B[1]), new(big.Int).Set(proof.B[2]), new(big.Int).Set(proof.B[3])},
		ProofC: [2]*big.Int{new(big.Int).Set(proof.C[0]), new(big.Int).Set(proof.C[1])},
	}

	// 1. Compute prepared_inputs = IC[0] + sum(pub_j * IC[j+1]) off-chain.
	//    Handles zero inputs naturally: 0*IC = identity, which is the
	//    additive unit and contributes nothing to the accumulator.
	preparedInputs, err := computePreparedInputs(vk.IC, publicInputs)
	if err != nil {
		return nil, fmt.Errorf("bn254witness: prepared_inputs: %w", err)
	}
	w.PreparedInputs = preparedInputs

	// 2. Run the triple Miller loop with gradient capture.
	//    Pair 1: (proof_A, proof_B)         — both positive
	//    Pair 2: (prepared_inputs, -gamma)  — gamma pre-negated in VK
	//    Pair 3: (proof_C, -delta)          — delta pre-negated in VK
	//
	// Pair order MUST match EmitGroth16VerifierWitnessAssisted's Step 3
	// so witness gradients land in the right slots.
	gradients, fAfterLoop, err := tripleMillerLoopWithGradients(
		proof.A, proof.B,
		preparedInputs, vk.GammaNegG2,
		proof.C, vk.DeltaNegG2,
	)
	if err != nil {
		return nil, fmt.Errorf("bn254witness: Miller loop: %w", err)
	}
	w.MillerGradients = gradients

	// 3. Multiply f by precomputed MillerLoop(α, -β) to get the value
	//    that will feed the final exponentiation in the verifier.
	alphaNegBetaFp12, err := PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	if err != nil {
		return nil, fmt.Errorf("bn254witness: precompute MillerLoop(α,-β): %w", err)
	}
	fAfterAB, err := fp12Mul12(fAfterLoop, alphaNegBetaFp12)
	if err != nil {
		return nil, fmt.Errorf("bn254witness: Fp12 mul with alpha-neg-beta: %w", err)
	}

	// 4. Compute final exponentiation witnesses (fInv, a, b, c).
	fInv, a, b, c, err := computeFinalExpWitnesses(fAfterAB)
	if err != nil {
		return nil, fmt.Errorf("bn254witness: final exp witnesses: %w", err)
	}
	w.FinalExpFInv = fInv
	w.FinalExpA = a
	w.FinalExpB = b
	w.FinalExpC = c

	return w, nil
}

// ToStackOps emits the push sequence that initializes the verifier's stack,
// in the exact order EmitGroth16VerifierWitnessAssisted expects.
//
// The order is: q, MillerGradients (interleaved per iteration), FinalExpFInv,
// FinalExpA, FinalExpB, FinalExpC, PreparedInputs (x, y), ProofA (x, y),
// ProofB (x0, x1, y0, y1), ProofC (x, y).
func (w *Witness) ToStackOps() []codegen.StackOp {
	ops := make([]codegen.StackOp, 0, 1+len(w.MillerGradients)+48+2+8)

	// 1. q
	ops = append(ops, pushBig(w.Q))

	// 2. Miller gradients (already in flat, interleaved order)
	for _, g := range w.MillerGradients {
		ops = append(ops, pushBig(g))
	}

	// 3. Final exp witnesses: fInv, a, b, c — each as 12 Fp values in flat order
	for _, fp12 := range [4][12]*big.Int{w.FinalExpFInv, w.FinalExpA, w.FinalExpB, w.FinalExpC} {
		for i := 0; i < 12; i++ {
			ops = append(ops, pushBig(fp12[i]))
		}
	}

	// 4. prepared_inputs (G1, 2 Fp)
	ops = append(ops, pushBig(w.PreparedInputs[0]), pushBig(w.PreparedInputs[1]))

	// 5. Proof points: A (x, y), B (x0, x1, y0, y1), C (x, y)
	ops = append(ops, pushBig(w.ProofA[0]), pushBig(w.ProofA[1]))
	ops = append(ops, pushBig(w.ProofB[0]), pushBig(w.ProofB[1]), pushBig(w.ProofB[2]), pushBig(w.ProofB[3]))
	ops = append(ops, pushBig(w.ProofC[0]), pushBig(w.ProofC[1]))

	return ops
}

// pushBig produces a StackOp that pushes the given big.Int as a Bitcoin
// Script number.
func pushBig(n *big.Int) codegen.StackOp {
	return codegen.StackOp{
		Op:    "push",
		Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(n)},
	}
}

// fp12Mul12 multiplies two flat-Fp12 values (12 Fp each, gnark order) using
// gnark-crypto's E12 type. Used to combine the Miller loop output with the
// precomputed e(alpha, beta).
func fp12Mul12(a, b [12]*big.Int) ([12]*big.Int, error) {
	var ae, be bn254.E12
	if err := flatFp12ToE12(a, &ae); err != nil {
		return [12]*big.Int{}, fmt.Errorf("decode a: %w", err)
	}
	if err := flatFp12ToE12(b, &be); err != nil {
		return [12]*big.Int{}, fmt.Errorf("decode b: %w", err)
	}
	var r bn254.E12
	r.Mul(&ae, &be)
	return e12ToFlatFp12(&r), nil
}
