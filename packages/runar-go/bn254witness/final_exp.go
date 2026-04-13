package bn254witness

import (
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

// bn254X is the BN254 curve parameter (positive convention used in Rúnar's
// codegen — see compilers/go/codegen/bn254_pairing.go:42-43).
var bn254X *big.Int

func init() {
	var ok bool
	bn254X, ok = new(big.Int).SetString("4965661367192848881", 10)
	if !ok {
		panic("bn254witness: failed to parse curve parameter x")
	}
}

// computeFinalExpWitnesses produces the four Fp12 witness values that
// emitWAFinalExp (bn254_groth16.go:672-815) consumes:
//
//	fInv = f^-1                                            (for the easy-part inverse check)
//	a    = f2^x      where f2 = f^((p^6-1) * (p^2+1))      (the "easy part")
//	b    = a^x = f2^(x^2)
//	c    = b^x = f2^(x^3)
//
// The verifier does NOT individually verify a, b, c — instead it uses them
// in the Devegili hard-part formula and relies on the final pairing check
// to catch any incorrect witness values. The math here MUST match what
// the verifier's hard-part formula expects, otherwise the on-chain check
// fails even though the witness "looks valid".
func computeFinalExpWitnesses(f [12]*big.Int) ([12]*big.Int, [12]*big.Int, [12]*big.Int, [12]*big.Int, error) {
	var fE bn254.E12
	if err := flatFp12ToE12(f, &fE); err != nil {
		return [12]*big.Int{}, [12]*big.Int{}, [12]*big.Int{}, [12]*big.Int{}, fmt.Errorf("decode f: %w", err)
	}

	// fInv = f^-1
	var fInvE bn254.E12
	fInvE.Inverse(&fE)

	// Easy part: f2 = f^((p^6 - 1) * (p^2 + 1))
	//   step 1: f^(p^6 - 1) = conj(f) * f^-1
	//   step 2: result^(p^2 + 1) = result * frobenius_p2(result)
	var fConj bn254.E12
	fConj.Conjugate(&fE)

	var f1 bn254.E12
	f1.Mul(&fConj, &fInvE) // f^(p^6 - 1)

	var f1FrobP2 bn254.E12
	f1FrobP2.FrobeniusSquare(&f1) // f1^(p^2)

	var f2 bn254.E12
	f2.Mul(&f1, &f1FrobP2) // f1^(p^2 + 1) = f^((p^6-1)*(p^2+1))

	// Hard part witnesses:
	//   a = f2^x
	//   b = a^x
	//   c = b^x
	var aE, bE, cE bn254.E12
	aE.Exp(f2, bn254X)
	bE.Exp(aE, bn254X)
	cE.Exp(bE, bn254X)

	return e12ToFlatFp12(&fInvE), e12ToFlatFp12(&aE), e12ToFlatFp12(&bE), e12ToFlatFp12(&cE), nil
}

// PrecomputeAlphaNegBeta computes the pre-final-exp Miller loop value
// MillerLoop(α, -β) which the verifier multiplies into its triple Miller
// loop accumulator before the single shared final exponentiation.
//
// The input betaNegG2 is ALREADY NEGATED (-β), matching the SP1 Solidity
// verifier convention where β is stored pre-negated in the VK. The helper
// reads it into a gnark G2Affine and calls bn254.MillerLoop directly —
// there is no further negation.
//
// The SP1 rearrangement of Groth's 2016 equation is:
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//
// The verifier multiplies the triple Miller loop accumulator by this
// precomputed constant BEFORE applying the final exponentiation, i.e.:
//
//	f = MillerLoop(A, B) · MillerLoop(prep, -γ) · MillerLoop(C, -δ) · MillerLoop(α, -β)
//	verify FinalExp(f) == 1
//
// Consequently this function returns the PRE-final-exp Miller loop
// value, NOT the post-final-exp GT element e(α, -β). Feeding the GT
// element into the verifier would require the unrealistic identity
// FinalExp(pre · post) == 1 (which generally fails because FinalExp is
// not the identity on GT: see `(p^12-1)/r` mod r ≠ 1 for BN254).
//
// alphaG1 is in Rúnar (x, y) order. betaNegG2 is in Rúnar (x0, x1, y0, y1)
// order (real, imag for each coordinate), holding -β.
func PrecomputeAlphaNegBeta(alphaG1 [2]*big.Int, betaNegG2 [4]*big.Int) ([12]*big.Int, error) {
	var alpha bn254.G1Affine
	alpha.X.SetBigInt(alphaG1[0])
	alpha.Y.SetBigInt(alphaG1[1])
	if !alpha.IsOnCurve() {
		return [12]*big.Int{}, fmt.Errorf("PrecomputeAlphaNegBeta: alpha is not on G1")
	}

	var negBeta bn254.G2Affine
	negBeta.X.A0.SetBigInt(betaNegG2[0])
	negBeta.X.A1.SetBigInt(betaNegG2[1])
	negBeta.Y.A0.SetBigInt(betaNegG2[2])
	negBeta.Y.A1.SetBigInt(betaNegG2[3])
	if !negBeta.IsOnCurve() {
		return [12]*big.Int{}, fmt.Errorf("PrecomputeAlphaNegBeta: -beta is not on G2")
	}

	// Use MillerLoop (pre-final-exp) so the result lives in the same space
	// as the triple Miller loop accumulator in the verifier script.
	ml, err := bn254.MillerLoop(
		[]bn254.G1Affine{alpha},
		[]bn254.G2Affine{negBeta},
	)
	if err != nil {
		return [12]*big.Int{}, fmt.Errorf("PrecomputeAlphaNegBeta: gnark MillerLoop failed: %w", err)
	}

	return e12ToFlatFp12(&ml), nil
}
