package bn254witness

import (
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/icellan/runar/compilers/go/codegen"
)

// affineG2 is a local affine G2 point representation built on top of
// gnark-crypto's bn254.E2. We don't use bn254.G2Affine directly because the
// gnark API doesn't expose the per-iteration affine arithmetic we need
// (gnark uses Jacobian internally for performance).
type affineG2 struct {
	X, Y bn254.E2
}

func toAffineG2(p [4]*big.Int) (affineG2, error) {
	var a affineG2
	a.X.A0.SetBigInt(p[0])
	a.X.A1.SetBigInt(p[1])
	a.Y.A0.SetBigInt(p[2])
	a.Y.A1.SetBigInt(p[3])
	return a, nil
}

// negateAffineG2 returns (x, -y).
func negateAffineG2(p affineG2) affineG2 {
	var r affineG2
	r.X.Set(&p.X)
	r.Y.Neg(&p.Y)
	return r
}

// affineG1 is a local affine G1 point.
type affineG1 struct {
	X, Y fp.Element
}

func toAffineG1(p [2]*big.Int) (affineG1, error) {
	var a affineG1
	a.X.SetBigInt(p[0])
	a.Y.SetBigInt(p[1])
	return a, nil
}

// tripleMillerLoopWithGradients runs three single Miller loops in lockstep
// over codegen.Bn254SixXPlus2NAF(), capturing per-iteration gradients in the
// order EmitGroth16VerifierWitnessAssisted's initNames slice expects.
//
// Pair 1: (p1, q1) — typically (prepared_inputs, gamma_G2)
// Pair 2: (p2, q2) — typically (proof_C,        delta_G2)
// Pair 3: (p3, q3) — typically (-proof_A,       proof_B)
//
// Returns:
//   - gradients: flat slice of Fp values, interleaved as
//     [d1_0, d1_1, d2_0, d2_1, d3_0, d3_1, (a1_0, a1_1, a2_0, a2_1, a3_0, a3_1 if naf[i] != 0), ...]
//     for i from msbIdx-1 down to 0.
//   - fAfterLoop: the Fp12 accumulator after the main loop AND the BN254
//     Frobenius corrections (Q1 = pi(Q), Q2 = -pi^2(Q)) for all 3 pairs.
//     This is the value the verifier's _f holds when emitWAFinalExp is called
//     (before multiplication with the precomputed e(alpha, beta)).
func tripleMillerLoopWithGradients(
	p1Big [2]*big.Int, q1Big [4]*big.Int,
	p2Big [2]*big.Int, q2Big [4]*big.Int,
	p3Big [2]*big.Int, q3Big [4]*big.Int,
) ([]*big.Int, [12]*big.Int, error) {
	p1, _ := toAffineG1(p1Big)
	p2, _ := toAffineG1(p2Big)
	p3, _ := toAffineG1(p3Big)
	q1, _ := toAffineG2(q1Big)
	q2, _ := toAffineG2(q2Big)
	q3, _ := toAffineG2(q3Big)

	// Initialize T_k = Q_k for each pair (these get doubled/added each iter).
	T := [3]affineG2{q1, q2, q3}
	Q := [3]affineG2{q1, q2, q3}
	negQ := [3]affineG2{negateAffineG2(q1), negateAffineG2(q2), negateAffineG2(q3)}
	P := [3]affineG1{p1, p2, p3}

	// f starts as 1 in Fp12.
	var f bn254.E12
	f.SetOne()

	naf := codegen.Bn254SixXPlus2NAF()

	// Find msbIdx (highest non-zero index). The Miller loop iterates
	// from msbIdx-1 DOWN to 0.
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	gradients := make([]*big.Int, 0, 6*msbIdx*2)

	for i := msbIdx - 1; i >= 0; i-- {
		// SHARED: f = f^2
		f.Square(&f)

		// Doubling step for all 3 pairs.
		for k := 0; k < 3; k++ {
			lambda, sparseLine, newT := doubleStepWithLambda(T[k], P[k])
			T[k] = newT

			// Append gradient (Fp2 = 2 Fp values, real then imag)
			gradients = append(gradients, fp2ToFlat(lambda)...)

			// Multiply f by sparse line (line is an Fp12 with sparse layout).
			var lineFp12 bn254.E12
			lineToFp12(sparseLine, &lineFp12)
			f.Mul(&f, &lineFp12)
		}

		// Addition step for non-zero NAF digits.
		if naf[i] != 0 {
			for k := 0; k < 3; k++ {
				var qChosen affineG2
				if naf[i] == 1 {
					qChosen = Q[k]
				} else {
					qChosen = negQ[k]
				}
				lambda, sparseLine, newT := addStepWithLambda(T[k], qChosen, P[k])
				T[k] = newT
				gradients = append(gradients, fp2ToFlat(lambda)...)

				var lineFp12 bn254.E12
				lineToFp12(sparseLine, &lineFp12)
				f.Mul(&f, &lineFp12)
			}
		}
	}

	// BN254 corrections: Q1_k = pi(Q_k), Q2_k = -pi^2(Q_k).
	// These use the standard (non-WA) line evaluation in the verifier
	// (bn254_groth16.go:597-629), so we just need to apply them here without
	// recording any extra witness data.
	for k := 0; k < 3; k++ {
		q1Frob := frobeniusG2(Q[k])
		q2FrobNeg := negateAffineG2(frobeniusG2Sq(Q[k]))

		_, sparseLine1, newT1 := addStepWithLambda(T[k], q1Frob, P[k])
		T[k] = newT1
		var lineFp12 bn254.E12
		lineToFp12(sparseLine1, &lineFp12)
		f.Mul(&f, &lineFp12)

		_, sparseLine2, newT2 := addStepWithLambda(T[k], q2FrobNeg, P[k])
		T[k] = newT2
		lineToFp12(sparseLine2, &lineFp12)
		f.Mul(&f, &lineFp12)
	}

	return gradients, e12ToFlatFp12(&f), nil
}

// fp2ToFlat returns [c0, c1] (real first) as []*big.Int.
func fp2ToFlat(e bn254.E2) []*big.Int {
	c0 := new(big.Int)
	e.A0.BigInt(c0)
	c1 := new(big.Int)
	e.A1.BigInt(c1)
	return []*big.Int{c0, c1}
}

// sparseLine represents a line evaluation in the canonical gnark-crypto form
// used by bn254.MillerLoop — the BN254 D-twist Miller loop. The three
// non-zero Fp2 coefficients (C0, C3, C4 in gnark's naming) populate the
// Fp12 slots (C0.B0, C1.B0, C1.B1) respectively; C0.B1 = C0.B2 = C1.B2 = 0.
// This matches gnark's MulBy034(c0, c3, c4) sparse multiplier.
//
// With affine gradient λ and Py-scaled form (Py-scaling is annihilated by
// the final exponentiation because Py ∈ Fp* and (p^12-1)/r is divisible by
// p-1, so Py^((p^12-1)/r) = 1 even after accumulation across all lines):
//
//	C0 = (Py, 0)              (Fp2; acts as the "1" slot scaled by Py)
//	C3 = -λ * Px              (Fp2 scaled by Fp Px, both components of λ)
//	C4 = λ * T.x - T.y        (Fp2)
//
// Stored as full Fp2 values; lineToFp12 converts to a dense Fp12.
type sparseLine struct {
	C0 bn254.E2 // Fp12 slot C0.B0
	C3 bn254.E2 // Fp12 slot C1.B0
	C4 bn254.E2 // Fp12 slot C1.B1
}

// lineToFp12 builds the full Fp12 element from a sparse line evaluation,
// using gnark-crypto's canonical BN254 Miller-loop slot pattern:
//
//	f.C0 (E6) = (C0, 0, 0)
//	f.C1 (E6) = (C3, C4, 0)
//
// This matches the layout expected by E12.MulBy034.
func lineToFp12(s sparseLine, out *bn254.E12) {
	out.C0.B0.SetZero()
	out.C0.B1.SetZero()
	out.C0.B2.SetZero()
	out.C1.B0.SetZero()
	out.C1.B1.SetZero()
	out.C1.B2.SetZero()
	out.C0.B0.Set(&s.C0)
	out.C1.B0.Set(&s.C3)
	out.C1.B1.Set(&s.C4)
}

// doubleStepWithLambda computes:
//
//	lambda = 3*T.x^2 / (2*T.y)         (Fp2)
//	T'.x   = lambda^2 - 2*T.x          (Fp2)
//	T'.y   = lambda*(T.x - T'.x) - T.y (Fp2)
//	line   = sparse line evaluation at P
//
// This must produce the same lambda the verifier verifies in
// emitWALineEvalDoubleSparse (bn254_groth16.go:297-380).
func doubleStepWithLambda(T affineG2, P affineG1) (bn254.E2, sparseLine, affineG2) {
	// num = 3 * T.x^2
	var num bn254.E2
	num.Square(&T.X)
	var three fp.Element
	three.SetUint64(3)
	num.A0.Mul(&num.A0, &three)
	num.A1.Mul(&num.A1, &three)

	// den = 2 * T.y
	var den bn254.E2
	den.Double(&T.Y)

	// lambda = num / den
	var denInv bn254.E2
	denInv.Inverse(&den)
	var lambda bn254.E2
	lambda.Mul(&num, &denInv)

	// T'.x = lambda^2 - 2*T.x
	var lambdaSq bn254.E2
	lambdaSq.Square(&lambda)
	var twoTx bn254.E2
	twoTx.Double(&T.X)
	var newTx bn254.E2
	newTx.Sub(&lambdaSq, &twoTx)

	// T'.y = lambda*(T.x - T'.x) - T.y
	var diff bn254.E2
	diff.Sub(&T.X, &newTx)
	var lProd bn254.E2
	lProd.Mul(&lambda, &diff)
	var newTy bn254.E2
	newTy.Sub(&lProd, &T.Y)

	// Canonical gnark-crypto BN254 D-twist sparse line (affine, Py-scaled):
	//
	//	C0 = (Py, 0)           — Fp2 from Fp, at Fp12 slot C0.B0
	//	C3 = -lambda * Px      — Fp2 scaled by Fp Px, at Fp12 slot C1.B0
	//	C4 = lambda * T.x - T.y — Fp2, at Fp12 slot C1.B1
	var sC0 bn254.E2
	sC0.A0.Set(&P.Y)
	sC0.A1.SetZero()

	var negLambda bn254.E2
	negLambda.Neg(&lambda)
	var sC3 bn254.E2
	sC3.A0.Mul(&negLambda.A0, &P.X)
	sC3.A1.Mul(&negLambda.A1, &P.X)

	var sC4 bn254.E2
	sC4.Mul(&lambda, &T.X)
	sC4.Sub(&sC4, &T.Y)

	newT := affineG2{X: newTx, Y: newTy}
	return lambda, sparseLine{C0: sC0, C3: sC3, C4: sC4}, newT
}

// addStepWithLambda computes:
//
//	lambda = (Q.y - T.y) / (Q.x - T.x)  (Fp2)
//	T'.x   = lambda^2 - T.x - Q.x
//	T'.y   = lambda*(T.x - T'.x) - T.y
//	line   = sparse line evaluation at P
//
// Matches the verifier's emitWALineEvalAddSparse (bn254_groth16.go:386-470).
func addStepWithLambda(T, Q affineG2, P affineG1) (bn254.E2, sparseLine, affineG2) {
	var num bn254.E2
	num.Sub(&Q.Y, &T.Y)
	var den bn254.E2
	den.Sub(&Q.X, &T.X)

	var denInv bn254.E2
	denInv.Inverse(&den)
	var lambda bn254.E2
	lambda.Mul(&num, &denInv)

	// T'.x = lambda^2 - T.x - Q.x
	var lambdaSq bn254.E2
	lambdaSq.Square(&lambda)
	var sub1 bn254.E2
	sub1.Sub(&lambdaSq, &T.X)
	var newTx bn254.E2
	newTx.Sub(&sub1, &Q.X)

	// T'.y = lambda*(T.x - T'.x) - T.y
	var diff bn254.E2
	diff.Sub(&T.X, &newTx)
	var lProd bn254.E2
	lProd.Mul(&lambda, &diff)
	var newTy bn254.E2
	newTy.Sub(&lProd, &T.Y)

	// Sparse line: same canonical gnark-crypto form as doubling but uses
	// T.x, T.y BEFORE update (the tangent is at T, the chord passes through T).
	var sC0 bn254.E2
	sC0.A0.Set(&P.Y)
	sC0.A1.SetZero()

	var negLambda bn254.E2
	negLambda.Neg(&lambda)
	var sC3 bn254.E2
	sC3.A0.Mul(&negLambda.A0, &P.X)
	sC3.A1.Mul(&negLambda.A1, &P.X)

	var sC4 bn254.E2
	sC4.Mul(&lambda, &T.X)
	sC4.Sub(&sC4, &T.Y)

	newT := affineG2{X: newTx, Y: newTy}
	return lambda, sparseLine{C0: sC0, C3: sC3, C4: sC4}, newT
}

// frobeniusG2 computes pi(Q) for a G2 affine point.
//
// For BN254 with sextic D-twist:
//
//	pi(Q) = (conj(Q.x) * gamma_{1,2}, conj(Q.y) * gamma_{1,3})
//
// where gamma_{1,2} and gamma_{1,3} are the standard BN254 Frobenius
// coefficients (must match the codegen's bn254Gamma12, bn254Gamma13).
//
// We delegate to gnark-crypto's bn254 package internals for these constants
// by performing the operation on a temporary E12 — actually, we can't easily
// reach into gnark's E12 frobenius for just G2. So we use the constants
// directly. They are baked in here as decimal strings to avoid depending on
// gnark internal types.
func frobeniusG2(Q affineG2) affineG2 {
	var r affineG2
	// conj(Q.x) = (Q.x.A0, -Q.x.A1)
	r.X.A0.Set(&Q.X.A0)
	r.X.A1.Neg(&Q.X.A1)
	// conj(Q.y) = (Q.y.A0, -Q.y.A1)
	r.Y.A0.Set(&Q.Y.A0)
	r.Y.A1.Neg(&Q.Y.A1)

	// Multiply r.X by gamma_{1,2}.
	// Value verified against gnark-crypto's MulByNonResidue1Power2 constant.
	var gamma12 bn254.E2
	mustSetFp(&gamma12.A0, "21575463638280843010398324269430826099269044274347216827212613867836435027261")
	mustSetFp(&gamma12.A1, "10307601595873709700152284273816112264069230130616436755625194854815875713954")
	r.X.Mul(&r.X, &gamma12)

	// Multiply r.Y by gamma_{1,3}.
	// Value verified against gnark-crypto's MulByNonResidue1Power3 constant.
	// Previous A1 (ending in ...021692181) was off — the correct value ends
	// in ...130930403 and matches gnark.
	var gamma13 bn254.E2
	mustSetFp(&gamma13.A0, "2821565182194536844548159561693502659359617185244120367078079554186484126554")
	mustSetFp(&gamma13.A1, "3505843767911556378687030309984248845540243509899259641013678093033130930403")
	r.Y.Mul(&r.Y, &gamma13)

	return r
}

// frobeniusG2Sq computes pi^2(Q) using the squared Frobenius coefficients.
// Both gamma_{2,2} and gamma_{2,3} are Fp elements (A1 = 0).
//
// Constants verified against gnark-crypto's MulByNonResidue2Power2 and
// Power3. The previous gamma_{2,2} value (ending in ...556617) was gnark's
// Power1; the correct Power2 value ends in ...556616.
func frobeniusG2Sq(Q affineG2) affineG2 {
	var r affineG2
	// X * gamma_{2,2} = ξ^((p²-1)/3) — gnark's MulByNonResidue2Power2.
	var gamma22 fp.Element
	mustSetFp(&gamma22, "21888242871839275220042445260109153167277707414472061641714758635765020556616")
	r.X.A0.Mul(&Q.X.A0, &gamma22)
	r.X.A1.Mul(&Q.X.A1, &gamma22)

	// Y * gamma_{2,3} = ξ^((p²-1)/2) = p - 1 — gnark's MulByNonResidue2Power3.
	var gamma23 fp.Element
	mustSetFp(&gamma23, "21888242871839275222246405745257275088696311157297823662689037894645226208582")
	r.Y.A0.Mul(&Q.Y.A0, &gamma23)
	r.Y.A1.Mul(&Q.Y.A1, &gamma23)

	return r
}

// mustSetFp parses a decimal string into an fp.Element. Used for constants.
func mustSetFp(e *fp.Element, s string) {
	var b big.Int
	if _, ok := b.SetString(s, 10); !ok {
		panic(fmt.Sprintf("bn254witness: failed to parse Fp constant: %s", s))
	}
	e.SetBigInt(&b)
}
