package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// Groth16Verifier verifies a Groth16 zero-knowledge proof over the BN254
// (alt_bn128) elliptic curve. This is the on-chain verifier for SP1
// Groth16 proofs, enabling succinct verification of arbitrary computation.
//
// # Groth16 Verification Equation
//
// The verifier checks a product of four pairings equals the identity in
// GT. Rúnar uses the SP1 Solidity rearrangement — negate β, γ, δ on the
// G2 side, so A, B, L, C, α all stay positive:
//
//	e(A, B) * e(prepared_inputs, -gamma) * e(C, -delta) * e(alpha, -beta) == 1
//
// Where:
//   - Proof: A (G1), B (G2), C (G1) -- provided by the prover
//   - VK: alpha (G1), -beta (G2), -gamma (G2), -delta (G2), IC (G1 array)
//   - prepared_inputs = IC[0] + sum(pub_i * IC[i+1]) for each public input
//
// β, γ, δ are stored PRE-NEGATED in the readonly VK properties below
// (hence the "Neg" suffix). This matches the SP1 Solidity verifier's
// BETA_NEG / GAMMA_NEG / DELTA_NEG constants and lets SP1-issued VKs
// drop directly into this contract with zero transformation.
//
// # BN254 Curve Parameters
//
// Field prime (Fp):
//
//	p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
//
// Group order:
//
//	r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//
// The pairing maps G1 x G2 -> GT (an element of Fp12). GT uses a degree-12
// extension field built as a tower: Fp -> Fp2 -> Fp6 -> Fp12.
//
// # Script Size
//
// The witness-assisted Groth16 verifier produces ~50-100 KB of Bitcoin Script,
// using the codegen in bn254_groth16.go which replaces expensive operations
// (Fp12 inverse, scalar multiplication, final exponentiation) with
// witness-assisted verification patterns.
type Groth16Verifier struct {
	runar.SmartContract

	// ---- Verification Key (readonly, baked into locking script) ----
	//
	// IMPORTANT — Fp2 ordering convention:
	// All G2 coordinates use Rúnar's (real, imaginary) order:
	//   X0 = real part of x,  X1 = imaginary part of x
	//   Y0 = real part of y,  Y1 = imaginary part of y
	//
	// The SP1 Solidity verifier uses the same convention (_0 = real /
	// c0, _1 = imaginary / c1), so values can be copied straight across.
	// Raw gnark Marshal()/EIP-197 serialization uses the opposite order
	// (imaginary first); if reading from those formats, swap each Fp2
	// pair before assignment.

	// AlphaG1 is the alpha element of the verification key (G1 point,
	// positive — no negation).
	AlphaG1 runar.Point `runar:"readonly"`

	// -Beta G2 coordinates, PRE-NEGATED (Fp2 element = two Fp components
	// per coordinate). G2 points live in the twist curve over Fp2,
	// represented as (x, y) where x = x0 + x1*u and y = y0 + y1*u.
	BetaNegG2X0 runar.Bigint `runar:"readonly"`
	BetaNegG2X1 runar.Bigint `runar:"readonly"`
	BetaNegG2Y0 runar.Bigint `runar:"readonly"`
	BetaNegG2Y1 runar.Bigint `runar:"readonly"`

	// -Gamma G2 coordinates, PRE-NEGATED (same Fp2 ordering as BetaNeg).
	GammaNegG2X0 runar.Bigint `runar:"readonly"`
	GammaNegG2X1 runar.Bigint `runar:"readonly"`
	GammaNegG2Y0 runar.Bigint `runar:"readonly"`
	GammaNegG2Y1 runar.Bigint `runar:"readonly"`

	// -Delta G2 coordinates, PRE-NEGATED (same Fp2 ordering as BetaNeg).
	DeltaNegG2X0 runar.Bigint `runar:"readonly"`
	DeltaNegG2X1 runar.Bigint `runar:"readonly"`
	DeltaNegG2Y0 runar.Bigint `runar:"readonly"`
	DeltaNegG2Y1 runar.Bigint `runar:"readonly"`

	// IC points for public input linearization (G1 points, positive).
	// For 1 public input, we need IC[0] and IC[1].
	IC0 runar.Point `runar:"readonly"`
	IC1 runar.Point `runar:"readonly"`
}

// Verify checks a Groth16 proof against the baked-in verification key.
//
// The proof consists of three elements: A (G1), B (G2), C (G1).
// The public input is the BN254 scalar field element derived from the
// SP1 public values (SHA-256 hash with top 3 bits zeroed).
//
// The verification uses bn254MultiPairing4 which checks:
//
//	e(A, B) * e(prepared_inputs, -gamma) * e(C, -delta) * e(alpha, -beta) == 1
//
// in a single optimized multi-Miller-loop + final exponentiation call.
// No on-chain negation is performed: the VK stores β, γ, δ pre-negated
// (SP1 Solidity verifier convention), and the proof points A, B, C are
// used positive.
func (c *Groth16Verifier) Verify(
	proofA runar.Point,
	proofBX0 runar.Bigint, // G2 x real part — swap if from raw gnark/Solidity ABI bytes
	proofBX1 runar.Bigint, // G2 x imaginary part
	proofBY0 runar.Bigint, // G2 y real part
	proofBY1 runar.Bigint, // G2 y imaginary part
	proofC runar.Point,
	publicInput runar.Bigint,
) {
	// Step 1: Compute prepared_inputs = IC[0] + publicInput * IC[1]
	scaledIC1 := runar.Bn254G1ScalarMulP(c.IC1, publicInput)
	preparedInputs := runar.Bn254G1AddP(c.IC0, scaledIC1)

	// Step 2: Verify prover-supplied G1 points lie on BN254 curve (y^2 = x^3 + 3)
	runar.Assert(runar.Bn254G1OnCurveP(proofA))
	runar.Assert(runar.Bn254G1OnCurveP(proofC))
	runar.Assert(runar.Bn254G1OnCurveP(preparedInputs))

	// Step 3: Verify the 4-pairing product equals 1 in GT (Fp12).
	//
	// e(A, B) · e(preparedInputs, -gamma) · e(C, -delta) · e(alpha, -beta) == 1
	//
	// No negations in the contract: the VK stores β, γ, δ pre-negated
	// (matching SP1 Solidity verifier convention).
	runar.Assert(runar.Bn254MultiPairing4(
		proofA, proofBX0, proofBX1, proofBY0, proofBY1,
		preparedInputs, c.GammaNegG2X0, c.GammaNegG2X1, c.GammaNegG2Y0, c.GammaNegG2Y1,
		proofC, c.DeltaNegG2X0, c.DeltaNegG2X1, c.DeltaNegG2Y0, c.DeltaNegG2Y1,
		c.AlphaG1, c.BetaNegG2X0, c.BetaNegG2X1, c.BetaNegG2Y0, c.BetaNegG2Y1,
	))
}
