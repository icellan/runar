// BN254 optimal Ate pairing codegen — Miller loop and final exponentiation
// for Bitcoin Script.
//
// Follows the bn254.go / bn254_ext.go pattern: uses BN254Tracker for
// named stack state tracking.
//
// The pairing e: G1 x G2 -> Fp12 is computed as:
//   1. Miller loop over the NAF of |6x+2| (x = BN254 parameter)
//   2. Two correction steps for Q1 = π(Q), Q2 = -π²(Q)
//   3. Final exponentiation: f^((p^12 - 1) / r)
//
// G1 point: affine (x, y) in Fp — 2 Fp values.
// G2 point: affine (x, y) in Fp2 — 4 Fp values.
// Fp12 result: 12 Fp values.
//
// BN254 parameter: x = 4965661367192848881 (0x44E992B44A6909F1)
// |6x+2| = 29793968203157093288 (0x19D797039BE763BA8)
//
// All loops are unrolled at codegen time.
package codegen

import (
	"fmt"
	"math/big"
)

// ===========================================================================
// BN254 pairing constants
// ===========================================================================

// bn254X is the BN254 curve parameter x.
// x = 4965661367192848881 (0x44E992B44A6909F1)
var bn254X *big.Int

// bn254SixXPlus2 is |6x+2| used for the Miller loop.
// 6*4965661367192848881 + 2 = 29793968203157093288
var bn254SixXPlus2 *big.Int

// bn254SixXPlus2NAF is the non-adjacent form of |6x+2|.
// NAF representation minimizes non-zero digits.
// Entries are -1, 0, or 1. Index 0 is LSB.
var bn254SixXPlus2NAF []int

func init() {
	var ok bool
	bn254X, ok = new(big.Int).SetString("4965661367192848881", 10)
	if !ok {
		panic("bn254_pairing: failed to parse x")
	}

	// |6x+2| = 29793968203157093288
	bn254SixXPlus2, ok = new(big.Int).SetString("29793968203157093288", 10)
	if !ok {
		panic("bn254_pairing: failed to parse 6x+2")
	}

	// NAF of |6x+2| from LSB to MSB.
	// Computed: 29793968203157093288 in NAF
	bn254SixXPlus2NAF = computeNAF(bn254SixXPlus2)
}

// Bn254SixXPlus2NAF returns a copy of the NAF of |6x+2| used by the BN254
// optimal Ate pairing Miller loop. Index 0 is the least significant digit.
//
// External callers (e.g. witness generators that drive an off-chain Miller
// loop in lockstep with this codegen) MUST iterate over this exact slice
// to stay aligned with EmitGroth16VerifierWitnessAssisted's gradient
// expectations. The slice is defensively copied so callers cannot mutate it.
func Bn254SixXPlus2NAF() []int {
	cp := make([]int, len(bn254SixXPlus2NAF))
	copy(cp, bn254SixXPlus2NAF)
	return cp
}

// Bn254FieldPrime returns a copy of the BN254 field prime p.
func Bn254FieldPrime() *big.Int {
	return new(big.Int).Set(bn254FieldP)
}

// computeNAF computes the non-adjacent form of a positive big.Int.
// Returns a slice where index 0 is the least significant digit.
func computeNAF(n *big.Int) []int {
	if n.Sign() == 0 {
		return []int{0}
	}
	x := new(big.Int).Set(n)
	var naf []int
	for x.Sign() > 0 {
		if x.Bit(0) == 1 {
			// x is odd
			r := new(big.Int).And(x, big.NewInt(3))
			if r.Int64() == 3 {
				naf = append(naf, -1)
				x.Add(x, big.NewInt(1))
			} else {
				naf = append(naf, 1)
				x.Sub(x, big.NewInt(1))
			}
		} else {
			naf = append(naf, 0)
		}
		x.Rsh(x, 1)
	}
	return naf
}

// ===========================================================================
// G2 point operations (affine, over Fp2)
// ===========================================================================
//
// A G2 point has coordinates (x, y) in Fp2.
// On the stack: x0, x1, y0, y1 (x0 deepest, y1 on top).

// bn254G2Negate negates a G2 point: (x, -y).
// Consumes 4 Fp slots; produces 4 Fp slots.
func bn254G2Negate(t *BN254Tracker, prefix, rPrefix string) {
	// x unchanged
	t.toTop(prefix + "_x_0")
	t.rename(rPrefix + "_x_0")
	t.toTop(prefix + "_x_1")
	t.rename(rPrefix + "_x_1")
	// y negated
	bn254Fp2Neg(t, prefix+"_y_0", prefix+"_y_1", rPrefix+"_y_0", rPrefix+"_y_1")
}

// ===========================================================================
// Line evaluation functions
// ===========================================================================
//
// These compute the tangent/chord line at a G2 point, evaluated at a G1 point.
// The result is an Fp12 element (sparse — many components are zero).
//
// For efficiency, we represent line evaluation results as sparse Fp12 elements
// and multiply them into the accumulator using sparse multiplication.
// However, for correctness we produce full Fp12 results here.

// bn254LineEvalDouble computes the tangent line at T (G2 point in Fp2),
// evaluated at P (G1 point in Fp), and also doubles T. Produces a FULL
// Fp12 element (12 Fp slots) in the canonical gnark BN254 D-twist form,
// with only the 3 non-zero sparse coefficients populated and the other 9
// slots set to 0. For sparse-mul use the sparse variant below.
//
// Input on tracker:
//   T: tx0, tx1, ty0, ty1 (affine G2 point)
//   P: px, py (affine G1 point)
// Output on tracker:
//   T': updated T (doubled)
//   line: 12 Fp values laid out in Fp12 = Fp6[w]/(w² - v) order with
//         C0.B0 = c0 = (Py, 0),
//         C1.B0 = c3 = -λ*Px,
//         C1.B1 = c4 = λ*Tx - Ty,
//         all other components zero.
//
// λ = 3*Tx² / (2*Ty) in Fp2; Tx' = λ² - 2*Tx; Ty' = λ(Tx - Tx') - Ty.
func bn254LineEvalDouble(t *BN254Tracker, tPrefix, pxName, pyName, rTPrefix, linePrefix string) {
	// lambda_num = 3 * Tx^2
	bn254Fp2SqrCopy(t, tPrefix+"_x", "_led_txsq")
	t.copyToTop("_led_txsq_0", "_led_txsq0c")
	t.copyToTop("_led_txsq_1", "_led_txsq1c")
	// 3 * Tx^2: multiply each component by 3
	bn254FieldMulConst(t, "_led_txsq_0", 3, "_led_lnum_0")
	bn254FieldMulConst(t, "_led_txsq_1", 3, "_led_lnum_1")
	bn254DropNames(t, []string{"_led_txsq0c", "_led_txsq1c"})

	// lambda_den = 2 * Ty
	t.copyToTop(tPrefix+"_y_0", "_led_ty0c")
	t.copyToTop(tPrefix+"_y_1", "_led_ty1c")
	bn254FieldMulConst(t, "_led_ty0c", 2, "_led_lden_0")
	bn254FieldMulConst(t, "_led_ty1c", 2, "_led_lden_1")

	// lambda = lambda_num / lambda_den (Fp2 division)
	bn254Fp2Inv(t, "_led_lden_0", "_led_lden_1", "_led_ldinv_0", "_led_ldinv_1")
	bn254Fp2Mul(t, "_led_lnum_0", "_led_lnum_1", "_led_ldinv_0", "_led_ldinv_1", "_led_lam_0", "_led_lam_1")

	// Tx' = lambda^2 - 2*Tx
	bn254Fp2SqrCopy(t, "_led_lam", "_led_lamsq")
	t.copyToTop(tPrefix+"_x_0", "_led_tx0a")
	t.copyToTop(tPrefix+"_x_1", "_led_tx1a")
	bn254FieldMulConst(t, "_led_tx0a", 2, "_led_2tx0")
	bn254FieldMulConst(t, "_led_tx1a", 2, "_led_2tx1")
	bn254Fp2Sub(t, "_led_lamsq_0", "_led_lamsq_1", "_led_2tx0", "_led_2tx1", rTPrefix+"_x_0", rTPrefix+"_x_1")

	// Ty' = lambda*(Tx - Tx') - Ty
	t.copyToTop(tPrefix+"_x_0", "_led_txb0")
	t.copyToTop(tPrefix+"_x_1", "_led_txb1")
	t.copyToTop(rTPrefix+"_x_0", "_led_ntx0")
	t.copyToTop(rTPrefix+"_x_1", "_led_ntx1")
	bn254Fp2Sub(t, "_led_txb0", "_led_txb1", "_led_ntx0", "_led_ntx1", "_led_diff_0", "_led_diff_1")
	t.copyToTop("_led_lam_0", "_led_lamc0")
	t.copyToTop("_led_lam_1", "_led_lamc1")
	bn254Fp2Mul(t, "_led_lamc0", "_led_lamc1", "_led_diff_0", "_led_diff_1", "_led_lprod_0", "_led_lprod_1")
	t.copyToTop(tPrefix+"_y_0", "_led_ty0b")
	t.copyToTop(tPrefix+"_y_1", "_led_ty1b")
	bn254Fp2Sub(t, "_led_lprod_0", "_led_lprod_1", "_led_ty0b", "_led_ty1b", rTPrefix+"_y_0", rTPrefix+"_y_1")

	// Line evaluation in canonical gnark BN254 form (Py-scaled):
	//   c4 = lambda * Tx - Ty   → Fp12 slot C1.B1
	t.copyToTop("_led_lam_0", "_led_lamd0")
	t.copyToTop("_led_lam_1", "_led_lamd1")
	t.copyToTop(tPrefix+"_x_0", "_led_txc0")
	t.copyToTop(tPrefix+"_x_1", "_led_txc1")
	bn254Fp2Mul(t, "_led_lamd0", "_led_lamd1", "_led_txc0", "_led_txc1", "_led_ltx_0", "_led_ltx_1")
	t.copyToTop(tPrefix+"_y_0", "_led_ty0c")
	t.copyToTop(tPrefix+"_y_1", "_led_ty1c")
	bn254Fp2Sub(t, "_led_ltx_0", "_led_ltx_1", "_led_ty0c", "_led_ty1c", "_led_c4_0", "_led_c4_1")

	// c3 = -lambda * Px   → Fp12 slot C1.B0
	t.copyToTop("_led_lam_0", "_led_lame0")
	t.copyToTop("_led_lam_1", "_led_lame1")
	bn254Fp2Neg(t, "_led_lame0", "_led_lame1", "_led_nlam_0", "_led_nlam_1")
	t.copyToTop(pxName, "_led_pxc")
	bn254FieldMul(t, "_led_nlam_0", "_led_pxc", "_led_c3_0")
	t.copyToTop(pxName, "_led_pxc2")
	bn254FieldMul(t, "_led_nlam_1", "_led_pxc2", "_led_c3_1")

	// c0 = (Py, 0)   → Fp12 slot C0.B0
	t.copyToTop(pyName, "_led_c0_0")
	t.pushInt("_led_c0_1", 0)

	// Dense Fp12 layout:
	//   f_a (Fp6) = (c0, 0, 0)
	//   f_b (Fp6) = (c3, c4, 0)
	t.toTop("_led_c0_0")
	t.rename(linePrefix + "_a_0_0")
	t.toTop("_led_c0_1")
	t.rename(linePrefix + "_a_0_1")
	t.pushInt(linePrefix+"_a_1_0", 0)
	t.pushInt(linePrefix+"_a_1_1", 0)
	t.pushInt(linePrefix+"_a_2_0", 0)
	t.pushInt(linePrefix+"_a_2_1", 0)
	t.toTop("_led_c3_0")
	t.rename(linePrefix + "_b_0_0")
	t.toTop("_led_c3_1")
	t.rename(linePrefix + "_b_0_1")
	t.toTop("_led_c4_0")
	t.rename(linePrefix + "_b_1_0")
	t.toTop("_led_c4_1")
	t.rename(linePrefix + "_b_1_1")
	t.pushInt(linePrefix+"_b_2_0", 0)
	t.pushInt(linePrefix+"_b_2_1", 0)

	// Clean up lambda and old T
	bn254DropNames(t, []string{"_led_lam_0", "_led_lam_1"})
	bn254DropNames(t, []string{tPrefix + "_x_0", tPrefix + "_x_1", tPrefix + "_y_0", tPrefix + "_y_1"})
}

// bn254LineEvalAdd computes the chord line through T and Q (G2 points),
// evaluated at P (G1 point), and also computes T + Q.
//
// Similar structure to LineEvalDouble but uses the chord slope.
func bn254LineEvalAdd(t *BN254Tracker, tPrefix, qPrefix, pxName, pyName, rTPrefix, linePrefix string) {
	// lambda = (Qy - Ty) / (Qx - Tx)  in Fp2
	t.copyToTop(qPrefix+"_y_0", "_lea_qy0")
	t.copyToTop(qPrefix+"_y_1", "_lea_qy1")
	t.copyToTop(tPrefix+"_y_0", "_lea_ty0")
	t.copyToTop(tPrefix+"_y_1", "_lea_ty1")
	bn254Fp2Sub(t, "_lea_qy0", "_lea_qy1", "_lea_ty0", "_lea_ty1", "_lea_ydf_0", "_lea_ydf_1")

	t.copyToTop(qPrefix+"_x_0", "_lea_qx0")
	t.copyToTop(qPrefix+"_x_1", "_lea_qx1")
	t.copyToTop(tPrefix+"_x_0", "_lea_tx0")
	t.copyToTop(tPrefix+"_x_1", "_lea_tx1")
	bn254Fp2Sub(t, "_lea_qx0", "_lea_qx1", "_lea_tx0", "_lea_tx1", "_lea_xdf_0", "_lea_xdf_1")

	bn254Fp2Inv(t, "_lea_xdf_0", "_lea_xdf_1", "_lea_xdinv_0", "_lea_xdinv_1")
	bn254Fp2Mul(t, "_lea_ydf_0", "_lea_ydf_1", "_lea_xdinv_0", "_lea_xdinv_1", "_lea_lam_0", "_lea_lam_1")

	// Tx' = lambda^2 - Tx - Qx
	bn254Fp2SqrCopy(t, "_lea_lam", "_lea_lamsq")
	t.copyToTop(tPrefix+"_x_0", "_lea_tx0a")
	t.copyToTop(tPrefix+"_x_1", "_lea_tx1a")
	bn254Fp2Sub(t, "_lea_lamsq_0", "_lea_lamsq_1", "_lea_tx0a", "_lea_tx1a", "_lea_sub1_0", "_lea_sub1_1")
	t.copyToTop(qPrefix+"_x_0", "_lea_qx0a")
	t.copyToTop(qPrefix+"_x_1", "_lea_qx1a")
	bn254Fp2Sub(t, "_lea_sub1_0", "_lea_sub1_1", "_lea_qx0a", "_lea_qx1a", rTPrefix+"_x_0", rTPrefix+"_x_1")

	// Ty' = lambda*(Tx - Tx') - Ty
	t.copyToTop(tPrefix+"_x_0", "_lea_txb0")
	t.copyToTop(tPrefix+"_x_1", "_lea_txb1")
	t.copyToTop(rTPrefix+"_x_0", "_lea_ntx0")
	t.copyToTop(rTPrefix+"_x_1", "_lea_ntx1")
	bn254Fp2Sub(t, "_lea_txb0", "_lea_txb1", "_lea_ntx0", "_lea_ntx1", "_lea_diff_0", "_lea_diff_1")
	t.copyToTop("_lea_lam_0", "_lea_lamc0")
	t.copyToTop("_lea_lam_1", "_lea_lamc1")
	bn254Fp2Mul(t, "_lea_lamc0", "_lea_lamc1", "_lea_diff_0", "_lea_diff_1", "_lea_lprod_0", "_lea_lprod_1")
	t.copyToTop(tPrefix+"_y_0", "_lea_tyb0")
	t.copyToTop(tPrefix+"_y_1", "_lea_tyb1")
	bn254Fp2Sub(t, "_lea_lprod_0", "_lea_lprod_1", "_lea_tyb0", "_lea_tyb1", rTPrefix+"_y_0", rTPrefix+"_y_1")

	// Line evaluation (canonical gnark BN254, Py-scaled):
	//   c4 = lambda * Tx - Ty   → Fp12 slot C1.B1
	t.copyToTop("_lea_lam_0", "_lea_lamd0")
	t.copyToTop("_lea_lam_1", "_lea_lamd1")
	t.copyToTop(tPrefix+"_x_0", "_lea_txc0")
	t.copyToTop(tPrefix+"_x_1", "_lea_txc1")
	bn254Fp2Mul(t, "_lea_lamd0", "_lea_lamd1", "_lea_txc0", "_lea_txc1", "_lea_ltx_0", "_lea_ltx_1")
	t.copyToTop(tPrefix+"_y_0", "_lea_tyc0")
	t.copyToTop(tPrefix+"_y_1", "_lea_tyc1")
	bn254Fp2Sub(t, "_lea_ltx_0", "_lea_ltx_1", "_lea_tyc0", "_lea_tyc1", "_lea_c4_0", "_lea_c4_1")

	// c3 = -lambda * Px   → Fp12 slot C1.B0
	t.copyToTop("_lea_lam_0", "_lea_lame0")
	t.copyToTop("_lea_lam_1", "_lea_lame1")
	bn254Fp2Neg(t, "_lea_lame0", "_lea_lame1", "_lea_nlam_0", "_lea_nlam_1")
	t.copyToTop(pxName, "_lea_pxc")
	bn254FieldMul(t, "_lea_nlam_0", "_lea_pxc", "_lea_c3_0")
	t.copyToTop(pxName, "_lea_pxc2")
	bn254FieldMul(t, "_lea_nlam_1", "_lea_pxc2", "_lea_c3_1")

	// c0 = (Py, 0)   → Fp12 slot C0.B0
	t.copyToTop(pyName, "_lea_c0_0")
	t.pushInt("_lea_c0_1", 0)

	// Dense Fp12 layout: f_a = (c0,0,0), f_b = (c3, c4, 0)
	t.toTop("_lea_c0_0")
	t.rename(linePrefix + "_a_0_0")
	t.toTop("_lea_c0_1")
	t.rename(linePrefix + "_a_0_1")
	t.pushInt(linePrefix+"_a_1_0", 0)
	t.pushInt(linePrefix+"_a_1_1", 0)
	t.pushInt(linePrefix+"_a_2_0", 0)
	t.pushInt(linePrefix+"_a_2_1", 0)
	t.toTop("_lea_c3_0")
	t.rename(linePrefix + "_b_0_0")
	t.toTop("_lea_c3_1")
	t.rename(linePrefix + "_b_0_1")
	t.toTop("_lea_c4_0")
	t.rename(linePrefix + "_b_1_0")
	t.toTop("_lea_c4_1")
	t.rename(linePrefix + "_b_1_1")
	t.pushInt(linePrefix+"_b_2_0", 0)
	t.pushInt(linePrefix+"_b_2_1", 0)

	// Clean up
	bn254DropNames(t, []string{"_lea_lam_0", "_lea_lam_1"})
	bn254DropNames(t, []string{tPrefix + "_x_0", tPrefix + "_x_1", tPrefix + "_y_0", tPrefix + "_y_1"})
}

// ===========================================================================
// Sparse line evaluation functions
// ===========================================================================
//
// These produce only the 3 non-zero Fp2 components of the line evaluation
// result in the canonical gnark-crypto BN254 D-twist sparse form. The
// Miller-loop accumulator f ∈ Fp12 is multiplied by a line of shape
//
//	(c0, 0, 0, c3, c4, 0)       in component order (C0.B0, C0.B1, C0.B2, C1.B0, C1.B1, C1.B2)
//
// via gnark's MulBy034. The three coefficients are stored as 6 Fp values:
//
//	linePrefix_c0_0, linePrefix_c0_1  (Fp2, → Fp12 slot C0.B0)
//	linePrefix_c3_0, linePrefix_c3_1  (Fp2, → Fp12 slot C1.B0)
//	linePrefix_c4_0, linePrefix_c4_1  (Fp2, → Fp12 slot C1.B1)
//
// With affine λ and Py-scaled form (Py ∈ Fp* so the Py^N accumulated factor
// across all lines is killed by the final exponentiation):
//
//	c0 = (Py, 0)              — Fp2 from Fp
//	c3 = -λ * Px              — Fp2 scaled by Fp Px
//	c4 = λ * T.x - T.y        — Fp2
//
// This matches gnark-crypto/ecc/bn254/pairing.go's affine line evaluation in
// MillerLoopFixedQ (LineEvaluationAff{R0=λ, R1=λ*Tx-Ty}), additionally scaled
// by Py to remove the 1/Py factor so the evaluation is representable by
// MulBy034 directly rather than MulBy34.

// bn254LineEvalDoubleSparse computes the tangent line at T, evaluated at P,
// and doubles T. Same math as bn254LineEvalDouble but produces sparse output.
// Uses a unique prefix suffix to avoid name collisions in multi-pairing.
func bn254LineEvalDoubleSparse(t *BN254Tracker, tPrefix, pxName, pyName, rTPrefix, linePrefix, uniqueSfx string) {
	pfx := "_leds" + uniqueSfx + "_"
	// lambda_num = 3 * Tx^2
	bn254Fp2SqrCopy(t, tPrefix+"_x", pfx+"txsq")
	bn254FieldMulConst(t, pfx+"txsq_0", 3, pfx+"lnum_0")
	bn254FieldMulConst(t, pfx+"txsq_1", 3, pfx+"lnum_1")

	// lambda_den = 2 * Ty
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0c")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1c")
	bn254FieldMulConst(t, pfx+"ty0c", 2, pfx+"lden_0")
	bn254FieldMulConst(t, pfx+"ty1c", 2, pfx+"lden_1")

	// lambda = lambda_num / lambda_den
	bn254Fp2Inv(t, pfx+"lden_0", pfx+"lden_1", pfx+"ldinv_0", pfx+"ldinv_1")
	bn254Fp2Mul(t, pfx+"lnum_0", pfx+"lnum_1", pfx+"ldinv_0", pfx+"ldinv_1", pfx+"lam_0", pfx+"lam_1")

	// Tx' = lambda^2 - 2*Tx
	bn254Fp2SqrCopy(t, pfx+"lam", pfx+"lamsq")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0a")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1a")
	bn254FieldMulConst(t, pfx+"tx0a", 2, pfx+"2tx0")
	bn254FieldMulConst(t, pfx+"tx1a", 2, pfx+"2tx1")
	bn254Fp2Sub(t, pfx+"lamsq_0", pfx+"lamsq_1", pfx+"2tx0", pfx+"2tx1", rTPrefix+"_x_0", rTPrefix+"_x_1")

	// Ty' = lambda*(Tx - Tx') - Ty
	t.copyToTop(tPrefix+"_x_0", pfx+"txb0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txb1")
	t.copyToTop(rTPrefix+"_x_0", pfx+"ntx0")
	t.copyToTop(rTPrefix+"_x_1", pfx+"ntx1")
	bn254Fp2Sub(t, pfx+"txb0", pfx+"txb1", pfx+"ntx0", pfx+"ntx1", pfx+"diff_0", pfx+"diff_1")
	t.copyToTop(pfx+"lam_0", pfx+"lamc0")
	t.copyToTop(pfx+"lam_1", pfx+"lamc1")
	bn254Fp2Mul(t, pfx+"lamc0", pfx+"lamc1", pfx+"diff_0", pfx+"diff_1", pfx+"lprod_0", pfx+"lprod_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0b")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1b")
	bn254Fp2Sub(t, pfx+"lprod_0", pfx+"lprod_1", pfx+"ty0b", pfx+"ty1b", rTPrefix+"_y_0", rTPrefix+"_y_1")

	// Canonical gnark BN254 sparse line (affine, Py-scaled):
	//   c4 = lambda * Tx - Ty
	t.copyToTop(pfx+"lam_0", pfx+"lamd0")
	t.copyToTop(pfx+"lam_1", pfx+"lamd1")
	t.copyToTop(tPrefix+"_x_0", pfx+"txc0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txc1")
	bn254Fp2Mul(t, pfx+"lamd0", pfx+"lamd1", pfx+"txc0", pfx+"txc1", pfx+"ltx_0", pfx+"ltx_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0c")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1c")
	bn254Fp2Sub(t, pfx+"ltx_0", pfx+"ltx_1", pfx+"ty0c", pfx+"ty1c", pfx+"c4out_0", pfx+"c4out_1")

	// c3 = -lambda * Px  (Fp2 scaled by Fp Px)
	t.copyToTop(pfx+"lam_0", pfx+"lame0")
	t.copyToTop(pfx+"lam_1", pfx+"lame1")
	bn254Fp2Neg(t, pfx+"lame0", pfx+"lame1", pfx+"nlam_0", pfx+"nlam_1")
	t.copyToTop(pxName, pfx+"pxc")
	bn254FieldMul(t, pfx+"nlam_0", pfx+"pxc", pfx+"c3out_0")
	t.copyToTop(pxName, pfx+"pxc2")
	bn254FieldMul(t, pfx+"nlam_1", pfx+"pxc2", pfx+"c3out_1")

	// c0 = (Py, 0) — embed the G1 y-coord into Fp2 to carry the Py scaling.
	t.copyToTop(pyName, pfx+"c0out_0")
	t.pushInt(pfx+"c0out_1", 0)

	// Store as sparse: c0 → C0.B0, c3 → C1.B0, c4 → C1.B1.
	t.toTop(pfx + "c0out_0")
	t.rename(linePrefix + "_c0_0")
	t.toTop(pfx + "c0out_1")
	t.rename(linePrefix + "_c0_1")
	t.toTop(pfx + "c3out_0")
	t.rename(linePrefix + "_c3_0")
	t.toTop(pfx + "c3out_1")
	t.rename(linePrefix + "_c3_1")
	t.toTop(pfx + "c4out_0")
	t.rename(linePrefix + "_c4_0")
	t.toTop(pfx + "c4out_1")
	t.rename(linePrefix + "_c4_1")

	// Clean up lambda and old T
	bn254DropNames(t, []string{pfx + "lam_0", pfx + "lam_1"})
	bn254DropNames(t, []string{tPrefix + "_x_0", tPrefix + "_x_1", tPrefix + "_y_0", tPrefix + "_y_1"})
}

// bn254LineEvalAddSparse computes the chord line through T and Q,
// evaluated at P, and computes T + Q. Produces sparse output (6 Fp slots).
//
// Consumes both tPrefix (4 Fp slots of T) AND qPrefix (4 Fp slots of Q).
// Callers must pass a fresh Q copy (e.g. `_addQ<k>` or `_subQ<k>`) that they
// don't need afterwards; the original Q stored at `q<k>*` or `_nQ<k>*` is
// not touched. Failing to consume qPrefix used to leak 4 Fp slots per call
// — see the v2 bug report where that caused incorrect multi-pairing
// results for 4 distinct G2 inputs.
func bn254LineEvalAddSparse(t *BN254Tracker, tPrefix, qPrefix, pxName, pyName, rTPrefix, linePrefix, uniqueSfx string) {
	pfx := "_leas" + uniqueSfx + "_"
	// lambda = (Qy - Ty) / (Qx - Tx)
	t.copyToTop(qPrefix+"_y_0", pfx+"qy0")
	t.copyToTop(qPrefix+"_y_1", pfx+"qy1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1")
	bn254Fp2Sub(t, pfx+"qy0", pfx+"qy1", pfx+"ty0", pfx+"ty1", pfx+"ydf_0", pfx+"ydf_1")

	t.copyToTop(qPrefix+"_x_0", pfx+"qx0")
	t.copyToTop(qPrefix+"_x_1", pfx+"qx1")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1")
	bn254Fp2Sub(t, pfx+"qx0", pfx+"qx1", pfx+"tx0", pfx+"tx1", pfx+"xdf_0", pfx+"xdf_1")

	bn254Fp2Inv(t, pfx+"xdf_0", pfx+"xdf_1", pfx+"xdinv_0", pfx+"xdinv_1")
	bn254Fp2Mul(t, pfx+"ydf_0", pfx+"ydf_1", pfx+"xdinv_0", pfx+"xdinv_1", pfx+"lam_0", pfx+"lam_1")

	// Tx' = lambda^2 - Tx - Qx
	bn254Fp2SqrCopy(t, pfx+"lam", pfx+"lamsq")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0a")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1a")
	bn254Fp2Sub(t, pfx+"lamsq_0", pfx+"lamsq_1", pfx+"tx0a", pfx+"tx1a", pfx+"sub1_0", pfx+"sub1_1")
	t.copyToTop(qPrefix+"_x_0", pfx+"qx0a")
	t.copyToTop(qPrefix+"_x_1", pfx+"qx1a")
	bn254Fp2Sub(t, pfx+"sub1_0", pfx+"sub1_1", pfx+"qx0a", pfx+"qx1a", rTPrefix+"_x_0", rTPrefix+"_x_1")

	// Ty' = lambda*(Tx - Tx') - Ty
	t.copyToTop(tPrefix+"_x_0", pfx+"txb0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txb1")
	t.copyToTop(rTPrefix+"_x_0", pfx+"ntx0")
	t.copyToTop(rTPrefix+"_x_1", pfx+"ntx1")
	bn254Fp2Sub(t, pfx+"txb0", pfx+"txb1", pfx+"ntx0", pfx+"ntx1", pfx+"diff_0", pfx+"diff_1")
	t.copyToTop(pfx+"lam_0", pfx+"lamc0")
	t.copyToTop(pfx+"lam_1", pfx+"lamc1")
	bn254Fp2Mul(t, pfx+"lamc0", pfx+"lamc1", pfx+"diff_0", pfx+"diff_1", pfx+"lprod_0", pfx+"lprod_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"tyb0")
	t.copyToTop(tPrefix+"_y_1", pfx+"tyb1")
	bn254Fp2Sub(t, pfx+"lprod_0", pfx+"lprod_1", pfx+"tyb0", pfx+"tyb1", rTPrefix+"_y_0", rTPrefix+"_y_1")

	// Canonical gnark BN254 sparse line (affine, Py-scaled):
	//   c4 = lambda * Tx - Ty
	t.copyToTop(pfx+"lam_0", pfx+"lamd0")
	t.copyToTop(pfx+"lam_1", pfx+"lamd1")
	t.copyToTop(tPrefix+"_x_0", pfx+"txc0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txc1")
	bn254Fp2Mul(t, pfx+"lamd0", pfx+"lamd1", pfx+"txc0", pfx+"txc1", pfx+"ltx_0", pfx+"ltx_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"tyc0")
	t.copyToTop(tPrefix+"_y_1", pfx+"tyc1")
	bn254Fp2Sub(t, pfx+"ltx_0", pfx+"ltx_1", pfx+"tyc0", pfx+"tyc1", pfx+"c4out_0", pfx+"c4out_1")

	// c3 = -lambda * Px
	t.copyToTop(pfx+"lam_0", pfx+"lame0")
	t.copyToTop(pfx+"lam_1", pfx+"lame1")
	bn254Fp2Neg(t, pfx+"lame0", pfx+"lame1", pfx+"nlam_0", pfx+"nlam_1")
	t.copyToTop(pxName, pfx+"pxc")
	bn254FieldMul(t, pfx+"nlam_0", pfx+"pxc", pfx+"c3out_0")
	t.copyToTop(pxName, pfx+"pxc2")
	bn254FieldMul(t, pfx+"nlam_1", pfx+"pxc2", pfx+"c3out_1")

	// c0 = (Py, 0)
	t.copyToTop(pyName, pfx+"c0out_0")
	t.pushInt(pfx+"c0out_1", 0)

	// Store as sparse: c0 → C0.B0, c3 → C1.B0, c4 → C1.B1.
	t.toTop(pfx + "c0out_0")
	t.rename(linePrefix + "_c0_0")
	t.toTop(pfx + "c0out_1")
	t.rename(linePrefix + "_c0_1")
	t.toTop(pfx + "c3out_0")
	t.rename(linePrefix + "_c3_0")
	t.toTop(pfx + "c3out_1")
	t.rename(linePrefix + "_c3_1")
	t.toTop(pfx + "c4out_0")
	t.rename(linePrefix + "_c4_0")
	t.toTop(pfx + "c4out_1")
	t.rename(linePrefix + "_c4_1")

	// Clean up: drop lambda, tPrefix (the source T_k point), and qPrefix
	// (the Q copy passed in — the original Q at qN* is preserved because
	// callers copyToTop into a fresh _addQ/_subQ/_Q1/_Q2 prefix before
	// calling this function).
	bn254DropNames(t, []string{pfx + "lam_0", pfx + "lam_1"})
	bn254DropNames(t, []string{tPrefix + "_x_0", tPrefix + "_x_1", tPrefix + "_y_0", tPrefix + "_y_1"})
	bn254DropNames(t, []string{qPrefix + "_x_0", qPrefix + "_x_1", qPrefix + "_y_0", qPrefix + "_y_1"})
}

// ===========================================================================
// G2 Frobenius maps (for Miller loop corrections)
// ===========================================================================
//
// The untwist-Frobenius-twist maps are needed for the two correction steps.
// For BN254 with sextic twist:
//   π(Q) = (Qx^p * γ_{1,2}, Qy^p * γ_{1,3})
// where γ coefficients are Frobenius constants from bn254_ext.go.

// bn254G2FrobeniusP computes π(Q) for a G2 point.
// Consumes 4 Fp slots; produces 4 Fp slots.
func bn254G2FrobeniusP(t *BN254Tracker, prefix, rPrefix string) {
	// Conjugate Qx, then multiply by γ_{1,2}
	bn254Fp2Conjugate(t, prefix+"_x_0", prefix+"_x_1", "_g2f_cx_0", "_g2f_cx_1")
	bn254Fp2MulByFrobCoeff(t, "_g2f_cx", bn254Gamma12, rPrefix+"_x")

	// Conjugate Qy, then multiply by γ_{1,3}
	bn254Fp2Conjugate(t, prefix+"_y_0", prefix+"_y_1", "_g2f_cy_0", "_g2f_cy_1")
	bn254Fp2MulByFrobCoeff(t, "_g2f_cy", bn254Gamma13, rPrefix+"_y")
}

// bn254G2FrobeniusP2 computes π²(Q) for a G2 point.
// Uses squared Frobenius coefficients; no conjugation needed for p^2.
// Consumes 4 Fp slots; produces 4 Fp slots.
func bn254G2FrobeniusP2(t *BN254Tracker, prefix, rPrefix string) {
	// Qx * γ_{2,2}  (γ_{2,2} is an Fp element, so multiply both components)
	bn254Fp2MulByFrobCoeff(t, prefix+"_x", bn254Gamma12Sq, rPrefix+"_x")
	// Qy * γ_{2,3}
	bn254Fp2MulByFrobCoeff(t, prefix+"_y", bn254Gamma13Sq, rPrefix+"_y")
}

// ===========================================================================
// Miller loop
// ===========================================================================
//
// The optimal Ate pairing Miller loop for BN254:
//   T = Q (affine G2)
//   f = 1 (Fp12)
//   for each NAF digit of |6x+2| from MSB-1 down to LSB:
//     f = f^2
//     f *= line_double(T, P)   -- T is doubled
//     if digit == 1:
//       f *= line_add(T, Q, P) -- T = T + Q
//     if digit == -1:
//       f *= line_add(T, -Q, P) -- T = T - Q
//   // BN254 corrections:
//   Q1 = π(Q)
//   Q2 = -π²(Q)
//   f *= line_add(T, Q1, P); T = T + Q1
//   f *= line_add(T, Q2, P); T = T + Q2

// bn254MillerLoop computes the Miller loop for the optimal Ate pairing.
//
// Input on tracker:
//   P: px, py (G1 affine, 2 Fp values)
//   Q: qx0, qx1, qy0, qy1 (G2 affine, 4 Fp values)
// Output on tracker:
//   f: 12 Fp values (Fp12 element, the Miller loop result)
//
// Uses sparse Fp12 multiplication for line evaluations (saves ~28% of Fp2 muls
// per line multiply vs the full Fp12Mul).
//
// IMPORTANT: Callers must ensure P is a valid G1 point on y^2 = x^3 + 3 and
// Q is a valid G2 point on the twist curve. This function does not validate
// curve membership. Invalid points will produce mathematically meaningless
// pairing results without error.
//
// All iterations are unrolled at codegen time.
func bn254MillerLoop(t *BN254Tracker) {
	bn254MillerLoopNamed(t, "px", "py", "qx0", "qx1", "qy0", "qy1", "_f", "")
}

// bn254MillerLoopNamed is the parameterized version of bn254MillerLoop. It
// runs a single-pair optimal Ate Miller loop using the caller-supplied input
// slot names and writes its 12-Fp output under outPrefix. The slotSfx
// parameter is appended to all INTERNAL temporary slot names so multiple
// calls to this function can be stacked safely without internal-name
// collisions.
//
// Inputs (all 1 Fp slot each): pxName, pyName, qx0Name, qx1Name, qy0Name,
// qy1Name. These slots must exist on the tracker and are preserved (not
// consumed) across the call.
//
// Output: 12 Fp slots named outPrefix + "_a_0_0" .. outPrefix + "_b_2_1".
func bn254MillerLoopNamed(t *BN254Tracker, pxName, pyName, qx0Name, qx1Name, qy0Name, qy1Name, outPrefix, slotSfx string) {
	naf := bn254SixXPlus2NAF

	// Find MSB (highest non-zero NAF digit)
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	// All internal slot names are suffixed with slotSfx so multiple
	// concurrent Miller loops don't clash.
	tN := "_T" + slotSfx
	fN := "_f" + slotSfx
	negQN := "_negQ" + slotSfx
	nQN := "_nQ" + slotSfx
	addQN := "_addQ" + slotSfx
	subQN := "_subQ" + slotSfx
	fQN := "_fQ" + slotSfx
	fQ2N := "_fQ2" + slotSfx
	Q1N := "_Q1" + slotSfx
	Q2preN := "_Q2pre" + slotSfx
	Q2N := "_Q2" + slotSfx
	ldN := "_ld" + slotSfx
	laN := "_la" + slotSfx
	lsN := "_ls" + slotSfx
	lq1N := "_lq1" + slotSfx
	lq2N := "_lq2" + slotSfx
	T2N := "_T2m" + slotSfx
	T3N := "_T3m" + slotSfx
	T4N := "_T4m" + slotSfx
	T5N := "_T5m" + slotSfx
	T6N := "_T6m" + slotSfx
	fSqN := "_f_sq" + slotSfx
	fMulN := "_f_mul" + slotSfx
	fMul2N := "_f_mul2" + slotSfx
	fMul3N := "_f_mul3" + slotSfx
	fC1N := "_f_c1" + slotSfx
	fC2N := "_f_c2" + slotSfx

	// Line-eval uniqueSfx values. They must be unique both ACROSS iterations
	// (different NAF bit index) AND across concurrent Miller loops (slotSfx).
	mkLineSfx := func(kind string, iter int) string {
		return kind + slotSfx + "_" + fmt.Sprintf("%d", iter)
	}

	// Initialize T = Q (copy Q)
	t.copyToTop(qx0Name, tN+"_x_0")
	t.copyToTop(qx1Name, tN+"_x_1")
	t.copyToTop(qy0Name, tN+"_y_0")
	t.copyToTop(qy1Name, tN+"_y_1")

	// Initialize f = 1
	bn254Fp12SetOne(t, fN)

	// Also prepare -Q for NAF digit = -1
	t.copyToTop(qx0Name, negQN+"_x_0")
	t.copyToTop(qx1Name, negQN+"_x_1")
	t.copyToTop(qy0Name, negQN+"_y_0")
	t.copyToTop(qy1Name, negQN+"_y_1")
	bn254G2Negate(t, negQN, nQN)

	// Iterate from MSB-1 down to 0
	iter := 0
	for i := msbIdx - 1; i >= 0; i-- {
		// f = f^2
		bn254Fp12Sqr(t, fN, fSqN)
		bn254Fp12RenamePrefix(t, fSqN, fN)

		// Line evaluation at doubling: doubles T, produces sparse line
		bn254LineEvalDoubleSparse(t, tN, pxName, pyName, T2N, ldN, mkLineSfx("d", iter))
		bn254RenameG2(t, T2N, tN)

		// f *= line (sparse multiply)
		bn254Fp12MulSparse(t, fN, ldN, fMulN)
		bn254Fp12RenamePrefix(t, fMulN, fN)

		switch naf[i] {
		case 1:
			// f *= line_add(T, Q, P); T = T + Q
			t.copyToTop(qx0Name, addQN+"_x_0")
			t.copyToTop(qx1Name, addQN+"_x_1")
			t.copyToTop(qy0Name, addQN+"_y_0")
			t.copyToTop(qy1Name, addQN+"_y_1")
			bn254LineEvalAddSparse(t, tN, addQN, pxName, pyName, T3N, laN, mkLineSfx("a", iter))
			bn254RenameG2(t, T3N, tN)
			bn254Fp12MulSparse(t, fN, laN, fMul2N)
			bn254Fp12RenamePrefix(t, fMul2N, fN)
		case -1:
			// f *= line_add(T, -Q, P); T = T - Q
			t.copyToTop(nQN+"_x_0", subQN+"_x_0")
			t.copyToTop(nQN+"_x_1", subQN+"_x_1")
			t.copyToTop(nQN+"_y_0", subQN+"_y_0")
			t.copyToTop(nQN+"_y_1", subQN+"_y_1")
			bn254LineEvalAddSparse(t, tN, subQN, pxName, pyName, T4N, lsN, mkLineSfx("s", iter))
			bn254RenameG2(t, T4N, tN)
			bn254Fp12MulSparse(t, fN, lsN, fMul3N)
			bn254Fp12RenamePrefix(t, fMul3N, fN)
		}
		iter++
	}

	// Clean up -Q
	bn254DropNames(t, []string{nQN + "_x_0", nQN + "_x_1", nQN + "_y_0", nQN + "_y_1"})

	// BN254 corrections: Q1 = π(Q), Q2 = -π²(Q)
	// Q1 = frobenius(Q)
	t.copyToTop(qx0Name, fQN+"_x_0")
	t.copyToTop(qx1Name, fQN+"_x_1")
	t.copyToTop(qy0Name, fQN+"_y_0")
	t.copyToTop(qy1Name, fQN+"_y_1")
	bn254G2FrobeniusP(t, fQN, Q1N)

	// Q2 = -frobenius²(Q)
	t.copyToTop(qx0Name, fQ2N+"_x_0")
	t.copyToTop(qx1Name, fQ2N+"_x_1")
	t.copyToTop(qy0Name, fQ2N+"_y_0")
	t.copyToTop(qy1Name, fQ2N+"_y_1")
	bn254G2FrobeniusP2(t, fQ2N, Q2preN)
	bn254G2Negate(t, Q2preN, Q2N)

	// Correction lines also use sparse multiply
	bn254LineEvalAddSparse(t, tN, Q1N, pxName, pyName, T5N, lq1N, "c1"+slotSfx)
	bn254RenameG2(t, T5N, tN)
	bn254Fp12MulSparse(t, fN, lq1N, fC1N)
	bn254Fp12RenamePrefix(t, fC1N, fN)

	bn254LineEvalAddSparse(t, tN, Q2N, pxName, pyName, T6N, lq2N, "c2"+slotSfx)
	bn254RenameG2(t, T6N, tN)
	bn254Fp12MulSparse(t, fN, lq2N, fC2N)
	bn254Fp12RenamePrefix(t, fC2N, fN)

	// Drop final T (not needed after Miller loop)
	bn254DropNames(t, []string{tN + "_x_0", tN + "_x_1", tN + "_y_0", tN + "_y_1"})

	// Rename fN -> outPrefix (if different)
	if fN != outPrefix {
		bn254Fp12RenamePrefix(t, fN, outPrefix)
	}
}

// bn254RenameG2 renames a G2 point's 4 Fp slots from one prefix to another.
func bn254RenameG2(t *BN254Tracker, srcPrefix, dstPrefix string) {
	t.toTop(srcPrefix + "_x_0")
	t.rename(dstPrefix + "_x_0")
	t.toTop(srcPrefix + "_x_1")
	t.rename(dstPrefix + "_x_1")
	t.toTop(srcPrefix + "_y_0")
	t.rename(dstPrefix + "_y_0")
	t.toTop(srcPrefix + "_y_1")
	t.rename(dstPrefix + "_y_1")
}

// ===========================================================================
// Final exponentiation
// ===========================================================================
//
// The final exponentiation raises the Miller loop result to (p^12 - 1) / r.
// This is decomposed as:
//   (p^12 - 1) / r = (p^6 - 1) * (p^2 + 1) * hard_part
//
// Easy part:
//   f1 = f^(p^6 - 1) = conj(f) * f^(-1)
//   f2 = f1^(p^2 + 1) = f1 * frob_p2(f1)
//
// Hard part (BN-specific decomposition):
//   Uses several exponentiations by x and Frobenius maps.
//   f^((p^4 - p^2 + 1) / r) via Devegili et al. decomposition.

// bn254FinalExp computes the BN254 final exponentiation.
// Consumes 12 Fp slots (Miller loop result); produces 12 Fp slots.
//
// Uses the Fuentes-Castañeda / Duquesne-Ghammam decomposition of the hard
// part of the final exponent — the same formula that emitWAFinalExp uses
// (with witness-supplied a, b, c) but computes a = f2^x, b = f2^(x^2),
// c = f2^(x^3) on-chain via three ExpByX calls.
//
// An earlier version of this function used an incorrect Devegili-style
// decomposition whose exponent differed from the correct BN254 hard part;
// it happened to produce 1 for inputs that were already in the GT kernel
// (e.g., pairing products of inverse (P,Q)/(−P,Q) pair patterns) but
// produced the WRONG GT element for any input whose pairing value was
// not already mapped to 1 by the remaining kernel. That caused
// multi-pair correctness failures for 3+ distinct G2 inputs — the
// intermediate Fp12 product landed outside the Devegili kernel.
//
// Easy part:
//   f1 = f_conj * f_inv         (= f^(p^6 - 1))
//   f2 = f1 * frob_p2(f1)       (= f1^(p^2 + 1))
//
// Hard part (FC exponent, reusing emitWAFinalExp formula):
//   a = f2^x, b = f2^x², c = f2^x³
//   P0 = f2 · a^6 · b^12 · c^12
//   P1 = a^4 · b^6 · c^12
//   P2 = a^6 · b^6 · c^12
//   P3 = conj(f2) · a^4 · b^6 · c^12
//   result = P0 · Frob(P1) · FrobSq(P2) · FrobCube(P3)
func bn254FinalExp(t *BN254Tracker, fPrefix, rPrefix string) {
	// === Easy part ===

	// f_conj = conj(f)
	bn254Fp12CopyPrefix(t, fPrefix, "_fe_fc")
	bn254Fp12Conjugate(t, "_fe_fc", "_fe_fconj")

	// f_inv = f^(-1)
	bn254Fp12CopyPrefix(t, fPrefix, "_fe_finv_in")
	bn254Fp12Inv(t, "_fe_finv_in", "_fe_finv")

	// f1 = f_conj * f_inv = f^(p^6 - 1)
	bn254Fp12Mul(t, "_fe_fconj", "_fe_finv", "_fe_f1")

	// f2 = f1 * frob_p2(f1) = f1^(p^2 + 1)
	bn254Fp12CopyPrefix(t, "_fe_f1", "_fe_f1_frob")
	bn254Fp12FrobeniusP2(t, "_fe_f1_frob", "_fe_f1p2")
	bn254Fp12Mul(t, "_fe_f1", "_fe_f1p2", "_fe_f2")

	// === Hard part — Fuentes-Castañeda / Duquesne-Ghammam ===
	// Compute witnesses a = f2^x, b = f2^x², c = f2^x³ on-chain via ExpByX.

	// a = f2^x
	bn254Fp12CopyPrefix(t, "_fe_f2", "_fe_f2a")
	bn254Fp12ExpByX(t, "_fe_f2a", "_fe_a")

	// b = a^x = f2^(x^2)
	bn254Fp12CopyPrefix(t, "_fe_a", "_fe_a2")
	bn254Fp12ExpByX(t, "_fe_a2", "_fe_b")

	// c = b^x = f2^(x^3)
	bn254Fp12CopyPrefix(t, "_fe_b", "_fe_b2")
	bn254Fp12ExpByX(t, "_fe_b2", "_fe_c")

	// ---- Prepare a^4 and a^6 (need 2 copies of each). ----
	bn254Fp12CopyPrefix(t, "_fe_a", "_fe_a_w1")
	bn254Fp12Sqr(t, "_fe_a_w1", "_fe_a2sq") // a² (consumes _fe_a_w1)
	bn254Fp12CopyPrefix(t, "_fe_a2sq", "_fe_a2_for_a6")
	bn254Fp12Sqr(t, "_fe_a2sq", "_fe_a4_core") // a⁴ (consumes _fe_a2sq)
	bn254Fp12CopyPrefix(t, "_fe_a4_core", "_fe_a4_p1")
	bn254Fp12CopyPrefix(t, "_fe_a4_core", "_fe_a4_p3")
	bn254Fp12Mul(t, "_fe_a4_core", "_fe_a2_for_a6", "_fe_a6_core")
	bn254Fp12CopyPrefix(t, "_fe_a6_core", "_fe_a6_p2")
	bn254Fp12RenamePrefix(t, "_fe_a6_core", "_fe_a6_p0")

	// ---- Prepare b^6 and b^12. ----
	bn254Fp12CopyPrefix(t, "_fe_b", "_fe_b_w1")
	bn254Fp12Sqr(t, "_fe_b_w1", "_fe_b2sq")
	bn254Fp12CopyPrefix(t, "_fe_b2sq", "_fe_b2_for_b6")
	bn254Fp12Sqr(t, "_fe_b2sq", "_fe_b4")
	bn254Fp12Mul(t, "_fe_b4", "_fe_b2_for_b6", "_fe_b6_core")
	bn254Fp12CopyPrefix(t, "_fe_b6_core", "_fe_b6_p1")
	bn254Fp12CopyPrefix(t, "_fe_b6_core", "_fe_b6_p2")
	bn254Fp12CopyPrefix(t, "_fe_b6_core", "_fe_b6_p3")
	bn254Fp12Sqr(t, "_fe_b6_core", "_fe_b12_p0")

	// ---- Prepare c^12 (need 4 copies). ----
	bn254Fp12CopyPrefix(t, "_fe_c", "_fe_c_w1")
	bn254Fp12Sqr(t, "_fe_c_w1", "_fe_c2sq")
	bn254Fp12CopyPrefix(t, "_fe_c2sq", "_fe_c2_for_c6")
	bn254Fp12Sqr(t, "_fe_c2sq", "_fe_c4")
	bn254Fp12Mul(t, "_fe_c4", "_fe_c2_for_c6", "_fe_c6")
	bn254Fp12Sqr(t, "_fe_c6", "_fe_c12_core")
	bn254Fp12CopyPrefix(t, "_fe_c12_core", "_fe_c12_p0")
	bn254Fp12CopyPrefix(t, "_fe_c12_core", "_fe_c12_p1")
	bn254Fp12CopyPrefix(t, "_fe_c12_core", "_fe_c12_p2")
	bn254Fp12RenamePrefix(t, "_fe_c12_core", "_fe_c12_p3")

	// ---- Prepare f2 for P0 and conj(f2) for P3. ----
	bn254Fp12CopyPrefix(t, "_fe_f2", "_fe_f2_for_P3_src")
	bn254Fp12RenamePrefix(t, "_fe_f2", "_fe_f2_for_P0")

	// ---- P0 = f2 · a^6 · b^12 · c^12 ----
	bn254Fp12Mul(t, "_fe_f2_for_P0", "_fe_a6_p0", "_fe_P0_s1")
	bn254Fp12Mul(t, "_fe_P0_s1", "_fe_b12_p0", "_fe_P0_s2")
	bn254Fp12Mul(t, "_fe_P0_s2", "_fe_c12_p0", "_fe_P0")

	// ---- P1 = a^4 · b^6 · c^12 ----
	bn254Fp12Mul(t, "_fe_a4_p1", "_fe_b6_p1", "_fe_P1_s1")
	bn254Fp12Mul(t, "_fe_P1_s1", "_fe_c12_p1", "_fe_P1")

	// ---- P2 = a^6 · b^6 · c^12 ----
	bn254Fp12Mul(t, "_fe_a6_p2", "_fe_b6_p2", "_fe_P2_s1")
	bn254Fp12Mul(t, "_fe_P2_s1", "_fe_c12_p2", "_fe_P2")

	// ---- P3 = conj(f2) · a^4 · b^6 · c^12 ----
	bn254Fp12Conjugate(t, "_fe_f2_for_P3_src", "_fe_f2conj")
	bn254Fp12Mul(t, "_fe_f2conj", "_fe_a4_p3", "_fe_P3_s1")
	bn254Fp12Mul(t, "_fe_P3_s1", "_fe_b6_p3", "_fe_P3_s2")
	bn254Fp12Mul(t, "_fe_P3_s2", "_fe_c12_p3", "_fe_P3")

	// ---- Frobenius powers ----
	bn254Fp12FrobeniusP(t, "_fe_P1", "_fe_P1f")
	bn254Fp12FrobeniusP2(t, "_fe_P2", "_fe_P2f")
	bn254Fp12FrobeniusP2(t, "_fe_P3", "_fe_P3f_tmp")
	bn254Fp12FrobeniusP(t, "_fe_P3f_tmp", "_fe_P3f")

	// ---- Final product: result = P0 · P1f · P2f · P3f ----
	bn254Fp12Mul(t, "_fe_P0", "_fe_P1f", "_fe_r1")
	bn254Fp12Mul(t, "_fe_r1", "_fe_P2f", "_fe_r2")
	bn254Fp12Mul(t, "_fe_r2", "_fe_P3f", "_fe_result")

	// Rename result
	bn254Fp12RenamePrefix(t, "_fe_result", rPrefix)

	// Drop intermediates that were only used via copies:
	//   _fe_a, _fe_b, _fe_c — a, b, c witnesses. Consumed only via Copy,
	//     so the originals remain on the stack and must be dropped here.
	bn254Fp12DropInputs(t, "_fe_a")
	bn254Fp12DropInputs(t, "_fe_b")
	bn254Fp12DropInputs(t, "_fe_c")
	// Drop original f. f2 was consumed by the rename into _fe_f2_for_P0.
	bn254Fp12DropInputs(t, fPrefix)
}

// ===========================================================================
// Public emit function — entry point called from stack.go
// ===========================================================================

// EmitBN254Pairing computes the BN254 optimal Ate pairing e(P, Q).
//
// Stack in: [P_point(64B), Q_x0, Q_x1, Q_y0, Q_y1]
//   P is a 64-byte G1 point (x[32]||y[32], big-endian)
//   Q_x0, Q_x1 are the Fp components of G2 x-coordinate (Fp2)
//   Q_y0, Q_y1 are the Fp components of G2 y-coordinate (Fp2)
//
// Stack out: 12 Fp values representing the Fp12 pairing result.
//   The result is the final exponentiated value in GT = Fp12.
//
// WARNING: This produces an enormous script (millions of opcodes when fully
// unrolled). It is intended for use in Bitcoin SV where script size limits
// are relaxed. Production use should be verified against reference test vectors.
func EmitBN254Pairing(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"_P", "qx0", "qx1", "qy0", "qy1"}, emit)
	t.PushPrimeCache()

	// Decompose G1 point into (px, py) field elements
	bn254DecomposePoint(t, "_P", "px", "py")

	// Run Miller loop
	// Input: px, py, qx0, qx1, qy0, qy1 on tracker
	// Output: _f (12 Fp slots) on tracker; px, py, qx0..qy1 still present
	bn254MillerLoop(t)

	// Clean up P and Q inputs
	bn254DropNames(t, []string{"px", "py", "qx0", "qx1", "qy0", "qy1"})

	// Final exponentiation
	bn254FinalExp(t, "_f", "_result")
	t.PopPrimeCache()
}

// EmitBN254PairingRaw is a debug helper identical to EmitBN254Pairing but
// exposes the 12 Fp slots of the post-finalExp result at the top of the
// stack in gnark's canonical E12 order (C0.B0.A0 .. C1.B2.A1), fully mod
// reduced. Used to compare single-pair output byte-for-byte against
// gnark's Pair output.
func EmitBN254PairingRaw(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"_P", "qx0", "qx1", "qy0", "qy1"}, emit)
	t.PushPrimeCache()

	bn254DecomposePoint(t, "_P", "px", "py")
	bn254MillerLoop(t)
	bn254DropNames(t, []string{"px", "py", "qx0", "qx1", "qy0", "qy1"})
	bn254FinalExp(t, "_f", "_result")

	// Bring the 12 Fp slots of _result to the top in canonical order,
	// fully reduced mod p.
	suffixes := []string{
		"_a_0_0", "_a_0_1",
		"_a_1_0", "_a_1_1",
		"_a_2_0", "_a_2_1",
		"_b_0_0", "_b_0_1",
		"_b_1_0", "_b_1_1",
		"_b_2_0", "_b_2_1",
	}
	reduced := make([]string, 12)
	for i, suf := range suffixes {
		orig := "_result" + suf
		rn := "_result" + suf + "_r"
		bn254FieldMod(t, orig, rn)
		reduced[i] = rn
	}
	for _, n := range reduced {
		t.toTop(n)
	}
	t.PopPrimeCache()
}

// ===========================================================================
// Multi-pairing: shared Miller loop for 4 pairings
// ===========================================================================

// bn254MultiMillerLoop4 computes the product of 4 Miller loops simultaneously,
// sharing the Fp12 squaring across all 4 pairs.
//
// Input on tracker:
//   P1: p1x, p1y  (G1 affine)
//   Q1: q1x0, q1x1, q1y0, q1y1  (G2 affine)
//   P2: p2x, p2y
//   Q2: q2x0, q2x1, q2y0, q2y1
//   P3: p3x, p3y
//   Q3: q3x0, q3x1, q3y0, q3y1
//   P4: p4x, p4y
//   Q4: q4x0, q4x1, q4y0, q4y1
// Output on tracker:
//   _f: 12 Fp values (Fp12 element, the combined Miller loop result)
// NOTE: MultiMillerLoop3 and MultiMillerLoop4 share ~95% of their code.
// They are kept separate intentionally: parameterizing on pair count would
// add runtime branching in a performance-critical codegen hot path.
//
// Uses shared Fp12 squaring: `f = f^2` is computed once per NAF iteration
// and all 4 pairs' sparse lines are multiplied into the same accumulator
// in sequence. This saves ~3 Fp12 squarings per iteration × ~64
// iterations compared with the naive sequential variant.
func bn254MultiMillerLoop4(t *BN254Tracker) {
	naf := bn254SixXPlus2NAF
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	// Initialize T_i = Q_i for each pair
	for k := 1; k <= 4; k++ {
		ks := string(rune('0' + k))
		qpfx := "q" + ks
		tpfx := "_T" + ks
		t.copyToTop(qpfx+"x0", tpfx+"_x_0")
		t.copyToTop(qpfx+"x1", tpfx+"_x_1")
		t.copyToTop(qpfx+"y0", tpfx+"_y_0")
		t.copyToTop(qpfx+"y1", tpfx+"_y_1")
	}

	// Initialize f = 1
	bn254Fp12SetOne(t, "_f")

	// Prepare -Q_i for NAF digit = -1
	for k := 1; k <= 4; k++ {
		ks := string(rune('0' + k))
		qpfx := "q" + ks
		t.copyToTop(qpfx+"x0", "_negQ"+ks+"_x_0")
		t.copyToTop(qpfx+"x1", "_negQ"+ks+"_x_1")
		t.copyToTop(qpfx+"y0", "_negQ"+ks+"_y_0")
		t.copyToTop(qpfx+"y1", "_negQ"+ks+"_y_1")
		bn254G2Negate(t, "_negQ"+ks, "_nQ"+ks)
	}

	iterNum := 0

	// Main Miller loop
	for i := msbIdx - 1; i >= 0; i-- {
		// SHARED: f = f^2 (one squaring instead of four)
		bn254Fp12Sqr(t, "_f", "_f_sq")
		bn254Fp12RenamePrefix(t, "_f_sq", "_f")

		iterSfx := fmt.Sprintf("%d", iterNum)

		// Doubling step for all 4 pairs
		for k := 1; k <= 4; k++ {
			ks := string(rune('0' + k))
			tpfx := "_T" + ks
			ppfx := "p" + ks

			// Use iteration-specific uniqueSfx to avoid any potential state
			// reuse issues between iterations.
			bn254LineEvalDoubleSparse(t, tpfx, ppfx+"x", ppfx+"y", tpfx+"d", "_ld"+ks, "d"+ks+iterSfx)
			bn254RenameG2(t, tpfx+"d", tpfx)

			bn254Fp12MulSparse(t, "_f", "_ld"+ks, "_f_dbl"+ks)
			bn254Fp12RenamePrefix(t, "_f_dbl"+ks, "_f")
		}

		// Addition step (if NAF digit is non-zero)
		switch naf[i] {
		case 1:
			for k := 1; k <= 4; k++ {
				ks := string(rune('0' + k))
				tpfx := "_T" + ks
				qpfx := "q" + ks
				ppfx := "p" + ks

				t.copyToTop(qpfx+"x0", "_addQ"+ks+"_x_0")
				t.copyToTop(qpfx+"x1", "_addQ"+ks+"_x_1")
				t.copyToTop(qpfx+"y0", "_addQ"+ks+"_y_0")
				t.copyToTop(qpfx+"y1", "_addQ"+ks+"_y_1")
				bn254LineEvalAddSparse(t, tpfx, "_addQ"+ks, ppfx+"x", ppfx+"y", tpfx+"a", "_la"+ks, "a"+ks+iterSfx)
				bn254RenameG2(t, tpfx+"a", tpfx)

				bn254Fp12MulSparse(t, "_f", "_la"+ks, "_f_add"+ks)
				bn254Fp12RenamePrefix(t, "_f_add"+ks, "_f")
			}
		case -1:
			for k := 1; k <= 4; k++ {
				ks := string(rune('0' + k))
				tpfx := "_T" + ks
				ppfx := "p" + ks

				t.copyToTop("_nQ"+ks+"_x_0", "_subQ"+ks+"_x_0")
				t.copyToTop("_nQ"+ks+"_x_1", "_subQ"+ks+"_x_1")
				t.copyToTop("_nQ"+ks+"_y_0", "_subQ"+ks+"_y_0")
				t.copyToTop("_nQ"+ks+"_y_1", "_subQ"+ks+"_y_1")
				bn254LineEvalAddSparse(t, tpfx, "_subQ"+ks, ppfx+"x", ppfx+"y", tpfx+"s", "_ls"+ks, "s"+ks+iterSfx)
				bn254RenameG2(t, tpfx+"s", tpfx)

				bn254Fp12MulSparse(t, "_f", "_ls"+ks, "_f_sub"+ks)
				bn254Fp12RenamePrefix(t, "_f_sub"+ks, "_f")
			}
		}

		iterNum++
	}

	// Clean up -Q_i
	for k := 1; k <= 4; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{
			"_nQ" + ks + "_x_0", "_nQ" + ks + "_x_1",
			"_nQ" + ks + "_y_0", "_nQ" + ks + "_y_1",
		})
	}

	// BN254 corrections for all 4 pairs
	for k := 1; k <= 4; k++ {
		ks := string(rune('0' + k))
		qpfx := "q" + ks
		tpfx := "_T" + ks
		ppfx := "p" + ks

		// Q1_k = frobenius(Q_k)
		t.copyToTop(qpfx+"x0", "_fQ"+ks+"_x_0")
		t.copyToTop(qpfx+"x1", "_fQ"+ks+"_x_1")
		t.copyToTop(qpfx+"y0", "_fQ"+ks+"_y_0")
		t.copyToTop(qpfx+"y1", "_fQ"+ks+"_y_1")
		bn254G2FrobeniusP(t, "_fQ"+ks, "_Q1_"+ks)

		// Q2_k = -frobenius^2(Q_k)
		t.copyToTop(qpfx+"x0", "_fQ2"+ks+"_x_0")
		t.copyToTop(qpfx+"x1", "_fQ2"+ks+"_x_1")
		t.copyToTop(qpfx+"y0", "_fQ2"+ks+"_y_0")
		t.copyToTop(qpfx+"y1", "_fQ2"+ks+"_y_1")
		bn254G2FrobeniusP2(t, "_fQ2"+ks, "_Q2pre"+ks)
		bn254G2Negate(t, "_Q2pre"+ks, "_Q2_"+ks)

		// f *= line_add(T_k, Q1_k, P_k)
		bn254LineEvalAddSparse(t, tpfx, "_Q1_"+ks, ppfx+"x", ppfx+"y", tpfx+"c1", "_lq1_"+ks, "q1"+ks)
		bn254RenameG2(t, tpfx+"c1", tpfx)
		bn254Fp12MulSparse(t, "_f", "_lq1_"+ks, "_f_c1_"+ks)
		bn254Fp12RenamePrefix(t, "_f_c1_"+ks, "_f")

		// f *= line_add(T_k, Q2_k, P_k)
		bn254LineEvalAddSparse(t, tpfx, "_Q2_"+ks, ppfx+"x", ppfx+"y", tpfx+"c2", "_lq2_"+ks, "q2"+ks)
		bn254RenameG2(t, tpfx+"c2", tpfx)
		bn254Fp12MulSparse(t, "_f", "_lq2_"+ks, "_f_c2_"+ks)
		bn254Fp12RenamePrefix(t, "_f_c2_"+ks, "_f")
	}

	// Drop final T_i
	for k := 1; k <= 4; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{
			"_T" + ks + "_x_0", "_T" + ks + "_x_1",
			"_T" + ks + "_y_0", "_T" + ks + "_y_1",
		})
	}
}

// EmitBN254MultiPairing4 computes the product of 4 pairings:
//
//	e(A1,B1) * e(A2,B2) * e(A3,B3) * e(A4,B4)
//
// and checks if the result equals 1 in GT (the Groth16 verification equation).
//
// This is more efficient than 4 separate pairings because:
//  1. Only 1 Fp12 squaring per Miller loop iteration (shared across all 4 pairs)
//  2. Only 1 final exponentiation
//  3. Sparse Fp12 multiplication for all line evaluations
//
// Stack in: [A1(64B), B1_x0, B1_x1, B1_y0, B1_y1,
//
//	A2(64B), B2_x0, B2_x1, B2_y0, B2_y1,
//	A3(64B), B3_x0, B3_x1, B3_y0, B3_y1,
//	A4(64B), B4_x0, B4_x1, B4_y0, B4_y1]
//
// Stack out: [1 if product equals 1 in GT, 0 otherwise]
func EmitBN254MultiPairing4(emit func(StackOp)) {
	t := NewBN254Tracker([]string{
		"_P1", "q1x0", "q1x1", "q1y0", "q1y1",
		"_P2", "q2x0", "q2x1", "q2y0", "q2y1",
		"_P3", "q3x0", "q3x1", "q3y0", "q3y1",
		"_P4", "q4x0", "q4x1", "q4y0", "q4y1",
	}, emit)
	t.PushPrimeCache()

	// Decompose all G1 points
	bn254DecomposePoint(t, "_P1", "p1x", "p1y")
	bn254DecomposePoint(t, "_P2", "p2x", "p2y")
	bn254DecomposePoint(t, "_P3", "p3x", "p3y")
	bn254DecomposePoint(t, "_P4", "p4x", "p4y")

	// Run shared Miller loop for all 4 pairs
	bn254MultiMillerLoop4(t)

	// Clean up P and Q inputs
	for k := 1; k <= 4; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{
			"p" + ks + "x", "p" + ks + "y",
			"q" + ks + "x0", "q" + ks + "x1",
			"q" + ks + "y0", "q" + ks + "y1",
		})
	}

	// Single final exponentiation
	bn254FinalExp(t, "_f", "_result")

	// Check if result == 1 in Fp12
	// 1 in Fp12 = (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	// Compare each component
	bn254Fp12IsOne(t, "_result", "_is_one")
	t.PopPrimeCache()
}

// EmitBN254MultiMillerLoop4Raw is a test helper that runs bn254MultiMillerLoop4
// and leaves its 12-Fp output on the stack, WITHOUT the final exponentiation.
// Used to bisect whether the bug in EmitBN254MultiPairing4 lives in the
// multi-Miller-loop routine or in the final exponentiation.
//
// Stack in:  [A1(64B), B1x0, B1x1, B1y0, B1y1, A2(64B), ..., A4(64B), B4x0..B4y1]
// Stack out: [..., f_a_0_0, f_a_0_1, f_a_1_0, f_a_1_1, f_a_2_0, f_a_2_1,
//
//	f_b_0_0, f_b_0_1, f_b_1_0, f_b_1_1, f_b_2_0, f_b_2_1]
//
// (12 Fp slots in gnark E12 order: C0.B0.A0..C1.B2.A1)
func EmitBN254MultiMillerLoop4Raw(emit func(StackOp)) {
	t := NewBN254Tracker([]string{
		"_P1", "q1x0", "q1x1", "q1y0", "q1y1",
		"_P2", "q2x0", "q2x1", "q2y0", "q2y1",
		"_P3", "q3x0", "q3x1", "q3y0", "q3y1",
		"_P4", "q4x0", "q4x1", "q4y0", "q4y1",
	}, emit)
	t.PushPrimeCache()
	bn254DecomposePoint(t, "_P1", "p1x", "p1y")
	bn254DecomposePoint(t, "_P2", "p2x", "p2y")
	bn254DecomposePoint(t, "_P3", "p3x", "p3y")
	bn254DecomposePoint(t, "_P4", "p4x", "p4y")
	bn254MultiMillerLoop4(t)
	for k := 1; k <= 4; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{
			"p" + ks + "x", "p" + ks + "y",
			"q" + ks + "x0", "q" + ks + "x1",
			"q" + ks + "y0", "q" + ks + "y1",
		})
	}
	// Bring the 12 Fp slots of _f to the top in canonical order.
	suffixes := []string{
		"_a_0_0", "_a_0_1",
		"_a_1_0", "_a_1_1",
		"_a_2_0", "_a_2_1",
		"_b_0_0", "_b_0_1",
		"_b_1_0", "_b_1_1",
		"_b_2_0", "_b_2_1",
	}
	// Fully reduce each component so the result is directly comparable to
	// a reference encoding (gnark returns values in [0, p)).
	reduced := make([]string, 12)
	for i, suf := range suffixes {
		orig := "_f" + suf
		rn := "_f" + suf + "_r"
		bn254FieldMod(t, orig, rn)
		reduced[i] = rn
	}
	for _, n := range reduced {
		t.toTop(n)
	}
	t.PopPrimeCache()
}

// EmitBN254MultiPairing4Raw is a test helper that runs the full multi-pairing
// for 4 pairs (Miller loop + final exponentiation) and leaves the 12 Fp slots
// of the resulting GT element on the stack, WITHOUT the IsOne equality check.
// Used to compare Rúnar's output to a reference Fp12 value (e.g. from gnark).
//
// Stack in: same as EmitBN254MultiPairing4 (4 pairs of (A, B))
// Stack out: [..., f_a_0_0, f_a_0_1, ..., f_b_2_1]  (12 Fp values, fully mod-reduced)
func EmitBN254MultiPairing4Raw(emit func(StackOp)) {
	t := NewBN254Tracker([]string{
		"_P1", "q1x0", "q1x1", "q1y0", "q1y1",
		"_P2", "q2x0", "q2x1", "q2y0", "q2y1",
		"_P3", "q3x0", "q3x1", "q3y0", "q3y1",
		"_P4", "q4x0", "q4x1", "q4y0", "q4y1",
	}, emit)
	t.PushPrimeCache()

	bn254DecomposePoint(t, "_P1", "p1x", "p1y")
	bn254DecomposePoint(t, "_P2", "p2x", "p2y")
	bn254DecomposePoint(t, "_P3", "p3x", "p3y")
	bn254DecomposePoint(t, "_P4", "p4x", "p4y")

	bn254MultiMillerLoop4(t)

	for k := 1; k <= 4; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{
			"p" + ks + "x", "p" + ks + "y",
			"q" + ks + "x0", "q" + ks + "x1",
			"q" + ks + "y0", "q" + ks + "y1",
		})
	}

	bn254FinalExp(t, "_f", "_result")

	// Fully reduce each component mod p before exposing.
	suffixes := []string{
		"_a_0_0", "_a_0_1",
		"_a_1_0", "_a_1_1",
		"_a_2_0", "_a_2_1",
		"_b_0_0", "_b_0_1",
		"_b_1_0", "_b_1_1",
		"_b_2_0", "_b_2_1",
	}
	reduced := make([]string, 12)
	for i, suf := range suffixes {
		orig := "_result" + suf
		rn := "_result" + suf + "_r"
		bn254FieldMod(t, orig, rn)
		reduced[i] = rn
	}
	for _, n := range reduced {
		t.toTop(n)
	}
	t.PopPrimeCache()
}

// EmitBN254FinalExpIsOne is a test helper that exposes the final-exponentiation
// + Fp12-equals-one check without going through the Miller loop. Used to
// bisect Miller-loop bugs from final-exp bugs: push 12 Fp slots representing a
// Miller-loop output, then call this, and inspect whether the resulting
// boolean is 1.
//
// The 12 Fp slots must be pushed in this order (matching gnark's E12 layout):
//
//	C0.B0.A0, C0.B0.A1,
//	C0.B1.A0, C0.B1.A1,
//	C0.B2.A0, C0.B2.A1,
//	C1.B0.A0, C1.B0.A1,
//	C1.B1.A0, C1.B1.A1,
//	C1.B2.A0, C1.B2.A1
//
// Stack in:  [..., f_a_0_0, f_a_0_1, ..., f_b_2_1]  (12 Fp values)
// Stack out: [..., boolean]  (1 if finalExp(f) == 1 in Fp12, else 0)
func EmitBN254FinalExpIsOne(emit func(StackOp)) {
	t := NewBN254Tracker([]string{
		"_f_a_0_0", "_f_a_0_1",
		"_f_a_1_0", "_f_a_1_1",
		"_f_a_2_0", "_f_a_2_1",
		"_f_b_0_0", "_f_b_0_1",
		"_f_b_1_0", "_f_b_1_1",
		"_f_b_2_0", "_f_b_2_1",
	}, emit)
	t.PushPrimeCache()
	bn254FinalExp(t, "_f", "_result")
	bn254Fp12IsOne(t, "_result", "_is_one")
	t.PopPrimeCache()
}

// bn254Fp12IsOne checks if an Fp12 element equals 1.
// 1 in Fp12 = a_0_0 == 1, all other 11 components == 0.
// Consumes 12 Fp slots; produces 1 boolean.
func bn254Fp12IsOne(t *BN254Tracker, prefix, resultName string) {
	// Component suffixes for all 12 Fp slots of the Fp12 element.
	suffixes := []string{
		"_a_0_0", "_a_0_1",
		"_a_1_0", "_a_1_1",
		"_a_2_0", "_a_2_1",
		"_b_0_0", "_b_0_1",
		"_b_1_0", "_b_1_1",
		"_b_2_0", "_b_2_1",
	}

	// Fully reduce each component mod p before comparison.
	// Without this, deferred mod reduction could leave a component equal to
	// p or 2p instead of 0, causing the OP_NOT / OP_NUMEQUAL checks below
	// to produce incorrect results.
	reducedNames := make([]string, 12)
	for i, suf := range suffixes {
		orig := prefix + suf
		reduced := prefix + suf + "_r"
		bn254FieldMod(t, orig, reduced)
		reducedNames[i] = reduced
	}

	// Bring all 12 reduced components to top of stack in order
	for _, name := range reducedNames {
		t.toTop(name)
	}
	t.rawBlock(reducedNames, resultName, func(e func(StackOp)) {
		// Stack has 12 values. Top = b_2_1 ... bottom of group = a_0_0.
		// Check a_0_0 == 1 (deepest of the 12). Rotate it to top.
		// Use OP_ROLL with index 11 to bring a_0_0 to top.
		e(StackOp{Op: "push", Value: bigIntPush(11)})
		e(StackOp{Op: "opcode", Code: "OP_ROLL"})
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
		// Now stack: [b_2_1, b_2_0, ..., a_0_1, (a_0_0==1)]
		// For each remaining 11 values, check == 0 and AND
		for i := 0; i < 11; i++ {
			e(StackOp{Op: "swap"})
			e(StackOp{Op: "opcode", Code: "OP_NOT"})
			e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
		}
		// Stack: single boolean
	})
}

// ===========================================================================
// Multi-pairing with 3 pairs + precomputed Fp12 constant
// ===========================================================================

// bn254MultiMillerLoop3 computes the product of 3 Miller loops
// simultaneously, sharing the Fp12 squaring across all 3 pairs.
//
// Input on tracker:
//   P1: p1x, p1y  (G1 affine)
//   Q1: q1x0, q1x1, q1y0, q1y1  (G2 affine)
//   P2: p2x, p2y
//   Q2: q2x0, q2x1, q2y0, q2y1
//   P3: p3x, p3y
//   Q3: q3x0, q3x1, q3y0, q3y1
// Output on tracker:
//   _f: 12 Fp values (Fp12 element, the combined Miller loop result)
func bn254MultiMillerLoop3(t *BN254Tracker) {
	naf := bn254SixXPlus2NAF
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	// Initialize T_i = Q_i for each pair
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		qpfx := "q" + ks
		tpfx := "_T" + ks
		t.copyToTop(qpfx+"x0", tpfx+"_x_0")
		t.copyToTop(qpfx+"x1", tpfx+"_x_1")
		t.copyToTop(qpfx+"y0", tpfx+"_y_0")
		t.copyToTop(qpfx+"y1", tpfx+"_y_1")
	}

	// Initialize f = 1
	bn254Fp12SetOne(t, "_f")

	// Prepare -Q_i for NAF digit = -1
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		qpfx := "q" + ks
		t.copyToTop(qpfx+"x0", "_negQ"+ks+"_x_0")
		t.copyToTop(qpfx+"x1", "_negQ"+ks+"_x_1")
		t.copyToTop(qpfx+"y0", "_negQ"+ks+"_y_0")
		t.copyToTop(qpfx+"y1", "_negQ"+ks+"_y_1")
		bn254G2Negate(t, "_negQ"+ks, "_nQ"+ks)
	}

	iterNum := 0

	// Main Miller loop
	for i := msbIdx - 1; i >= 0; i-- {
		// SHARED: f = f^2 (one squaring instead of three)
		bn254Fp12Sqr(t, "_f", "_f_sq")
		bn254Fp12RenamePrefix(t, "_f_sq", "_f")

		iterSfx := fmt.Sprintf("%d", iterNum)

		// Doubling step for all 3 pairs
		for k := 1; k <= 3; k++ {
			ks := string(rune('0' + k))
			tpfx := "_T" + ks
			ppfx := "p" + ks

			bn254LineEvalDoubleSparse(t, tpfx, ppfx+"x", ppfx+"y", tpfx+"d", "_ld"+ks, "d"+ks+iterSfx)
			bn254RenameG2(t, tpfx+"d", tpfx)

			bn254Fp12MulSparse(t, "_f", "_ld"+ks, "_f_dbl"+ks)
			bn254Fp12RenamePrefix(t, "_f_dbl"+ks, "_f")
		}

		// Addition step (if NAF digit is non-zero)
		switch naf[i] {
		case 1:
			for k := 1; k <= 3; k++ {
				ks := string(rune('0' + k))
				tpfx := "_T" + ks
				qpfx := "q" + ks
				ppfx := "p" + ks

				t.copyToTop(qpfx+"x0", "_addQ"+ks+"_x_0")
				t.copyToTop(qpfx+"x1", "_addQ"+ks+"_x_1")
				t.copyToTop(qpfx+"y0", "_addQ"+ks+"_y_0")
				t.copyToTop(qpfx+"y1", "_addQ"+ks+"_y_1")
				bn254LineEvalAddSparse(t, tpfx, "_addQ"+ks, ppfx+"x", ppfx+"y", tpfx+"a", "_la"+ks, "a"+ks+iterSfx)
				bn254RenameG2(t, tpfx+"a", tpfx)

				bn254Fp12MulSparse(t, "_f", "_la"+ks, "_f_add"+ks)
				bn254Fp12RenamePrefix(t, "_f_add"+ks, "_f")
			}
		case -1:
			for k := 1; k <= 3; k++ {
				ks := string(rune('0' + k))
				tpfx := "_T" + ks
				ppfx := "p" + ks

				t.copyToTop("_nQ"+ks+"_x_0", "_subQ"+ks+"_x_0")
				t.copyToTop("_nQ"+ks+"_x_1", "_subQ"+ks+"_x_1")
				t.copyToTop("_nQ"+ks+"_y_0", "_subQ"+ks+"_y_0")
				t.copyToTop("_nQ"+ks+"_y_1", "_subQ"+ks+"_y_1")
				bn254LineEvalAddSparse(t, tpfx, "_subQ"+ks, ppfx+"x", ppfx+"y", tpfx+"s", "_ls"+ks, "s"+ks+iterSfx)
				bn254RenameG2(t, tpfx+"s", tpfx)

				bn254Fp12MulSparse(t, "_f", "_ls"+ks, "_f_sub"+ks)
				bn254Fp12RenamePrefix(t, "_f_sub"+ks, "_f")
			}
		}

		iterNum++
	}

	// Clean up -Q_i
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{
			"_nQ" + ks + "_x_0", "_nQ" + ks + "_x_1",
			"_nQ" + ks + "_y_0", "_nQ" + ks + "_y_1",
		})
	}

	// BN254 corrections for all 3 pairs
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		qpfx := "q" + ks
		tpfx := "_T" + ks
		ppfx := "p" + ks

		// Q1_k = frobenius(Q_k)
		t.copyToTop(qpfx+"x0", "_fQ"+ks+"_x_0")
		t.copyToTop(qpfx+"x1", "_fQ"+ks+"_x_1")
		t.copyToTop(qpfx+"y0", "_fQ"+ks+"_y_0")
		t.copyToTop(qpfx+"y1", "_fQ"+ks+"_y_1")
		bn254G2FrobeniusP(t, "_fQ"+ks, "_Q1_"+ks)

		// Q2_k = -frobenius^2(Q_k)
		t.copyToTop(qpfx+"x0", "_fQ2"+ks+"_x_0")
		t.copyToTop(qpfx+"x1", "_fQ2"+ks+"_x_1")
		t.copyToTop(qpfx+"y0", "_fQ2"+ks+"_y_0")
		t.copyToTop(qpfx+"y1", "_fQ2"+ks+"_y_1")
		bn254G2FrobeniusP2(t, "_fQ2"+ks, "_Q2pre"+ks)
		bn254G2Negate(t, "_Q2pre"+ks, "_Q2_"+ks)

		// f *= line_add(T_k, Q1_k, P_k)
		bn254LineEvalAddSparse(t, tpfx, "_Q1_"+ks, ppfx+"x", ppfx+"y", tpfx+"c1", "_lq1_"+ks, "q1"+ks)
		bn254RenameG2(t, tpfx+"c1", tpfx)
		bn254Fp12MulSparse(t, "_f", "_lq1_"+ks, "_f_c1_"+ks)
		bn254Fp12RenamePrefix(t, "_f_c1_"+ks, "_f")

		// f *= line_add(T_k, Q2_k, P_k)
		bn254LineEvalAddSparse(t, tpfx, "_Q2_"+ks, ppfx+"x", ppfx+"y", tpfx+"c2", "_lq2_"+ks, "q2"+ks)
		bn254RenameG2(t, tpfx+"c2", tpfx)
		bn254Fp12MulSparse(t, "_f", "_lq2_"+ks, "_f_c2_"+ks)
		bn254Fp12RenamePrefix(t, "_f_c2_"+ks, "_f")
	}

	// Drop final T_i
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{
			"_T" + ks + "_x_0", "_T" + ks + "_x_1",
			"_T" + ks + "_y_0", "_T" + ks + "_y_1",
		})
	}
}

// EmitBN254MultiPairing3WithPrecomputed computes:
//
//	e(A1,B1) * e(A2,B2) * e(A3,B3) * precomputed_fp12 == 1
//
// where precomputed_fp12 is a known Fp12 constant (e.g., the precomputed
// e(alpha, -beta) from a Groth16 verification key). This saves one full
// Miller loop pair computation, which is the most expensive part of the
// pairing.
//
// Stack in: [A1(64B), B1_x0, B1_x1, B1_y0, B1_y1,
//
//	A2(64B), B2_x0, B2_x1, B2_y0, B2_y1,
//	A3(64B), B3_x0, B3_x1, B3_y0, B3_y1,
//	pre0, pre1, pre2, pre3, pre4, pre5,
//	pre6, pre7, pre8, pre9, pre10, pre11]  (12 Fp values for precomputed Fp12)
//
// Stack out: [1 if product equals 1 in GT, 0 otherwise]
func EmitBN254MultiPairing3WithPrecomputed(emit func(StackOp)) {
	t := NewBN254Tracker([]string{
		"_P1", "q1x0", "q1x1", "q1y0", "q1y1",
		"_P2", "q2x0", "q2x1", "q2y0", "q2y1",
		"_P3", "q3x0", "q3x1", "q3y0", "q3y1",
		"pre_a_0_0", "pre_a_0_1", "pre_a_1_0", "pre_a_1_1", "pre_a_2_0", "pre_a_2_1",
		"pre_b_0_0", "pre_b_0_1", "pre_b_1_0", "pre_b_1_1", "pre_b_2_0", "pre_b_2_1",
	}, emit)
	t.PushPrimeCache()

	// Decompose all G1 points
	bn254DecomposePoint(t, "_P1", "p1x", "p1y")
	bn254DecomposePoint(t, "_P2", "p2x", "p2y")
	bn254DecomposePoint(t, "_P3", "p3x", "p3y")

	// Run shared Miller loop for 3 pairs
	bn254MultiMillerLoop3(t)

	// Clean up P and Q inputs
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{
			"p" + ks + "x", "p" + ks + "y",
			"q" + ks + "x0", "q" + ks + "x1",
			"q" + ks + "y0", "q" + ks + "y1",
		})
	}

	// Multiply Miller loop result by precomputed Fp12 constant
	// The precomputed values are already named pre_a_0_0 .. pre_b_2_1
	bn254Fp12Mul(t, "_f", "pre", "_f_with_pre")
	bn254Fp12RenamePrefix(t, "_f_with_pre", "_f")

	// Single final exponentiation
	bn254FinalExp(t, "_f", "_result")

	// Check if result == 1 in Fp12
	bn254Fp12IsOne(t, "_result", "_is_one")
	t.PopPrimeCache()
}
