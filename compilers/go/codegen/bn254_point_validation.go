package codegen

// BN254 input-point validation for the general-purpose pairing builtins.
//
// CL-BUG-103 / CL-BUG-034: `EmitBN254Pairing`, `EmitBN254MultiPairing4`,
// `EmitBN254MultiPairing3WithPrecomputed` and their Raw debug siblings used
// to feed caller-supplied G1/G2 coordinates straight into the Miller loop.
// Neither an on-curve check nor a G2 subgroup check was emitted, while the
// witness-assisted Groth16 preamble in bn254_groth16.go performed exactly
// those checks on the same coordinate shapes.
//
// BN254's twist E'(Fp²) has cofactor 2p − n ≈ 2^255, so an attacker can
// choose an on-twist point outside the prime-order subgroup and the pairing
// silently factors into the legitimate term times an attacker-controlled
// correction. EIP-197 — the canonical specification for this exact
// primitive — mandates that such inputs make the pairing FAIL. This file
// brings the general-purpose builtins in line with that rule.
//
// Three assertions are emitted per input point:
//
//	G1: y² == x³ + 3           (mod p)          — ~46 StackOps
//	G2: y² == x³ + b'          (in Fp2)         — ~177 StackOps
//	G2: ψ(P) == [6·x²]·P       (in E'(Fp²))     — ~705k StackOps
//
// Measured emitter cost of the mandatory validation, in StackOps:
//
//	EmitBN254Pairing                     1,532,976 → 2,237,791  (+46%)
//	EmitBN254MultiPairing3WithPrecomputed 2,510,306 → 4,624,753 (+84%)
//	EmitBN254MultiPairing4               2,993,548 → 5,812,811  (+94%)
//
// That is the price of the 126 doublings + 69 additions in the [6·x²]
// chain, each needing one on-chain Fp2 inversion (~2,951 StackOps). It is
// accepted deliberately: an opt-in check authors must remember to call is
// the same failure mode as no check at all, and these scripts are already
// multi-megabyte by construction.
//
// BN254's G1 has cofactor 1, so on-curve membership already implies
// prime-order membership there; only G2 needs the third assertion.
//
// The G2 subgroup identity is the same Scott characterisation the
// witness-assisted Groth16 path uses (see emitWAG2SubgroupCheck). The
// difference is who supplies the double-and-add gradients: the Groth16
// preamble reads 390 prover-supplied Fp values from the unlocking script,
// which is not an option for a builtin whose stack ABI is fixed by its
// Rúnar signature. The unassisted variant below therefore computes each
// slope on-chain with bn254Fp2Inv and then hands it to the very same
// emitWAG2DoubleAffine / emitWAG2AddAffine helpers, which re-derive the
// defining equation and OP_EQUALVERIFY it — so the soundness argument is
// unchanged and the computed slope is proved correct rather than trusted.

import "math/big"

// ---------------------------------------------------------------------------
// On-curve assertions
// ---------------------------------------------------------------------------

// bn254AssertG1OnCurve verifies y² == x³ + 3 mod p for a caller-supplied G1
// point and aborts the script via OP_EQUALVERIFY if it does not hold. The
// point is NOT consumed. `sfx` disambiguates the helper's temporary tracker
// slots when several points are validated in one script.
func bn254AssertG1OnCurve(t *BN254Tracker, xName, yName, sfx string) {
	pfx := "_occhk_" + sfx + "_"

	// GAP-301 / R-141 class: reject (x+k·p, y) before the curve equation.
	// Byte-level OP_EQUALVERIFY on unreduced coordinates would accept an
	// alias of a valid point. Require 0 ≤ x,y < p (unsigned by construction).
	t.copyToTop(xName, pfx+"cx")
	bn254PushFieldP(t, pfx+"cpx")
	t.rawBlock([]string{pfx + "cx", pfx + "cpx"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})
	t.copyToTop(yName, pfx+"cy")
	bn254PushFieldP(t, pfx+"cpy")
	t.rawBlock([]string{pfx + "cy", pfx + "cpy"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})

	// lhs = y^2 mod p
	t.copyToTop(yName, pfx+"y")
	bn254FieldSqr(t, pfx+"y", pfx+"lhs")

	// rhs = x^3 + 3 mod p
	t.copyToTop(xName, pfx+"xc")
	bn254FieldSqr(t, pfx+"xc", pfx+"x2")
	t.copyToTop(xName, pfx+"xc2")
	bn254FieldMul(t, pfx+"x2", pfx+"xc2", pfx+"x3")
	t.pushInt(pfx+"three", 3)
	bn254FieldAdd(t, pfx+"x3", pfx+"three", pfx+"rhs")

	// Check lhs == rhs
	t.toTop(pfx + "lhs")
	t.toTop(pfx + "rhs")
	t.rawBlock([]string{pfx + "lhs", pfx + "rhs"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
}

// bn254AssertG2OnCurve verifies y² == x³ + b' in Fp2 (b' = 3/(9+u)) for a
// caller-supplied G2 point and aborts via OP_EQUALVERIFY if it does not
// hold. The four coordinates are NOT consumed.
func bn254AssertG2OnCurve(t *BN254Tracker, x0, x1, y0, y1, sfx string) {
	pfx := "_g2occ_" + sfx + "_"

	// lhs = y^2  in Fp2 (preserve y0, y1: copy inputs first)
	t.copyToTop(y0, pfx+"y0")
	t.copyToTop(y1, pfx+"y1")
	bn254Fp2Sqr(t, pfx+"y0", pfx+"y1", pfx+"lhs_0", pfx+"lhs_1")

	// x2 = x^2  in Fp2 (preserve x0, x1)
	t.copyToTop(x0, pfx+"x0a")
	t.copyToTop(x1, pfx+"x1a")
	bn254Fp2Sqr(t, pfx+"x0a", pfx+"x1a", pfx+"x2_0", pfx+"x2_1")

	// x3 = x2 * x  in Fp2 (preserve x0, x1)
	t.copyToTop(x0, pfx+"x0b")
	t.copyToTop(x1, pfx+"x1b")
	bn254Fp2Mul(t, pfx+"x2_0", pfx+"x2_1", pfx+"x0b", pfx+"x1b", pfx+"x3_0", pfx+"x3_1")

	// rhs = x^3 + b'  in Fp2
	t.pushBigInt(pfx+"b0", bn254TwistB0)
	t.pushBigInt(pfx+"b1", bn254TwistB1)
	bn254Fp2Add(t, pfx+"x3_0", pfx+"x3_1", pfx+"b0", pfx+"b1", pfx+"rhs_0", pfx+"rhs_1")

	// Reduce both sides mod p for canonical byte-level OP_EQUALVERIFY.
	bn254FieldMod(t, pfx+"lhs_0", pfx+"lhs_0r")
	bn254FieldMod(t, pfx+"lhs_1", pfx+"lhs_1r")
	bn254FieldMod(t, pfx+"rhs_0", pfx+"rhs_0r")
	bn254FieldMod(t, pfx+"rhs_1", pfx+"rhs_1r")

	// Component-wise equality: abort if either fails.
	t.toTop(pfx + "lhs_0r")
	t.toTop(pfx + "rhs_0r")
	t.rawBlock([]string{pfx + "lhs_0r", pfx + "rhs_0r"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
	t.toTop(pfx + "lhs_1r")
	t.toTop(pfx + "rhs_1r")
	t.rawBlock([]string{pfx + "lhs_1r", pfx + "rhs_1r"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
}

// ---------------------------------------------------------------------------
// Unassisted G2 subgroup assertion
// ---------------------------------------------------------------------------

// bn254G2TangentSlope computes λ = 3·Tx² / (2·Ty) in Fp2 and leaves it
// under lamPrefix+"_0"/"_1". T is NOT consumed.
func bn254G2TangentSlope(t *BN254Tracker, tPrefix, lamPrefix, pfx string) {
	// numerator = 3·Tx²
	bn254Fp2SqrCopy(t, tPrefix+"_x", pfx+"sq")
	bn254FieldMulConst(t, pfx+"sq_0", 3, pfx+"num_0")
	bn254FieldMulConst(t, pfx+"sq_1", 3, pfx+"num_1")

	// denominator = 2·Ty
	t.copyToTop(tPrefix+"_y_0", pfx+"y0")
	t.copyToTop(tPrefix+"_y_1", pfx+"y1")
	bn254FieldMulConst(t, pfx+"y0", 2, pfx+"den_0")
	bn254FieldMulConst(t, pfx+"y1", 2, pfx+"den_1")

	bn254Fp2Inv(t, pfx+"den_0", pfx+"den_1", pfx+"dinv_0", pfx+"dinv_1")
	bn254Fp2Mul(t, pfx+"num_0", pfx+"num_1", pfx+"dinv_0", pfx+"dinv_1",
		lamPrefix+"_0", lamPrefix+"_1")
}

// bn254G2ChordSlope computes λ = (Qy − Ty) / (Qx − Tx) in Fp2 and leaves it
// under lamPrefix+"_0"/"_1". Neither T nor Q is consumed.
func bn254G2ChordSlope(t *BN254Tracker, tPrefix, qPrefix, lamPrefix, pfx string) {
	t.copyToTop(qPrefix+"_y_0", pfx+"qy0")
	t.copyToTop(qPrefix+"_y_1", pfx+"qy1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1")
	bn254Fp2Sub(t, pfx+"qy0", pfx+"qy1", pfx+"ty0", pfx+"ty1", pfx+"num_0", pfx+"num_1")

	t.copyToTop(qPrefix+"_x_0", pfx+"qx0")
	t.copyToTop(qPrefix+"_x_1", pfx+"qx1")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1")
	bn254Fp2Sub(t, pfx+"qx0", pfx+"qx1", pfx+"tx0", pfx+"tx1", pfx+"den_0", pfx+"den_1")

	bn254Fp2Inv(t, pfx+"den_0", pfx+"den_1", pfx+"dinv_0", pfx+"dinv_1")
	bn254Fp2Mul(t, pfx+"num_0", pfx+"num_1", pfx+"dinv_0", pfx+"dinv_1",
		lamPrefix+"_0", lamPrefix+"_1")
}

// bn254G2RenamePoint moves the 4 Fp slots of srcPrefix to dstPrefix.
func bn254G2RenamePoint(t *BN254Tracker, srcPrefix, dstPrefix string) {
	for _, comp := range []string{"_x_0", "_x_1", "_y_0", "_y_1"} {
		t.toTop(srcPrefix + comp)
		t.rename(dstPrefix + comp)
	}
}

// bn254G2FixedScalarMulUnassisted computes [k]·P on G2 in affine
// coordinates with NO prover witness: each double-and-add slope is derived
// on-chain via bn254Fp2Inv and then handed to emitWAG2DoubleAffine /
// emitWAG2AddAffine, which re-verify it against the defining equation
// before using it. P is read via copyToTop and is NOT consumed; the result
// is left under rPrefix's four slots.
//
// If any intermediate step degenerates (2-torsion, or an addition where
// Tx == Px) the slope's denominator is zero, bn254Fp2Inv returns 0 by
// Fermat, and the re-verification inside the helper aborts the script —
// which is the correct outcome for a subgroup test.
func bn254G2FixedScalarMulUnassisted(t *BN254Tracker, basePrefix string, k *big.Int, rPrefix, sfx string) {
	if k.Sign() <= 0 {
		panic("bn254G2FixedScalarMulUnassisted: scalar must be positive")
	}
	nbits := k.BitLen()

	acc := "_usmT" + sfx
	t.copyToTop(basePrefix+"_x_0", acc+"_x_0")
	t.copyToTop(basePrefix+"_x_1", acc+"_x_1")
	t.copyToTop(basePrefix+"_y_0", acc+"_y_0")
	t.copyToTop(basePrefix+"_y_1", acc+"_y_1")

	doubleIdx := 0
	addIdx := 0

	for i := nbits - 2; i >= 0; i-- {
		// --- T = 2T ---
		stepSfx := sfx + "d" + itoa(doubleIdx)
		lamD := "_usld" + stepSfx
		bn254G2TangentSlope(t, acc, lamD, "_ustg"+stepSfx+"_")
		emitWAG2DoubleAffine(t, acc, lamD, acc+"n", stepSfx)
		bn254G2RenamePoint(t, acc+"n", acc)
		doubleIdx++

		if k.Bit(i) != 1 {
			continue
		}

		// --- T = T + P ---
		addSfx := sfx + "a" + itoa(addIdx)
		lamA := "_usla" + addSfx
		bn254G2ChordSlope(t, acc, basePrefix, lamA, "_uscg"+addSfx+"_")

		// emitWAG2AddAffine consumes its Q operand, so give it a copy.
		pcopy := "_usmP" + addSfx
		t.copyToTop(basePrefix+"_x_0", pcopy+"_x_0")
		t.copyToTop(basePrefix+"_x_1", pcopy+"_x_1")
		t.copyToTop(basePrefix+"_y_0", pcopy+"_y_0")
		t.copyToTop(basePrefix+"_y_1", pcopy+"_y_1")

		emitWAG2AddAffine(t, acc, pcopy, lamA, acc+"n", addSfx)
		bn254G2RenamePoint(t, acc+"n", acc)
		addIdx++
	}

	bn254G2RenamePoint(t, acc, rPrefix)
}

// bn254AssertG2InSubgroup verifies that a caller-supplied G2 point lies in
// the prime-order subgroup G2 ⊂ E'(Fp²) via the BN endomorphism identity
//
//	ψ(P) == [6·x²]·P        (Scott, https://eprint.iacr.org/2021/1130 §8)
//
// and aborts the script if it does not hold. The four coordinates are NOT
// consumed. The caller MUST have already asserted that P is on the twist —
// the identity is only a subgroup characterisation for on-curve points.
func bn254AssertG2InSubgroup(t *BN254Tracker, x0, x1, y0, y1, sfx string) {
	pfx := "_g2sgu" + sfx + "_"

	// ψ(P). bn254G2FrobeniusP consumes its input prefix, so work on a copy.
	t.copyToTop(x0, pfx+"src_x_0")
	t.copyToTop(x1, pfx+"src_x_1")
	t.copyToTop(y0, pfx+"src_y_0")
	t.copyToTop(y1, pfx+"src_y_1")
	bn254G2FrobeniusP(t, pfx+"src", pfx+"psi")

	// Local copy of P under the prefix the scalar-mul helper reads.
	t.copyToTop(x0, pfx+"base_x_0")
	t.copyToTop(x1, pfx+"base_x_1")
	t.copyToTop(y0, pfx+"base_y_0")
	t.copyToTop(y1, pfx+"base_y_1")

	bn254G2FixedScalarMulUnassisted(t, pfx+"base", bn254SubgroupCheckScalar, pfx+"smul", sfx)

	bn254DropNames(t, []string{
		pfx + "base_x_0", pfx + "base_x_1",
		pfx + "base_y_0", pfx + "base_y_1",
	})

	// Canonicalise both sides mod p before the byte-level comparison.
	for _, comp := range []string{"x_0", "x_1", "y_0", "y_1"} {
		bn254FieldMod(t, pfx+"psi_"+comp, pfx+"psi_"+comp+"r")
		bn254FieldMod(t, pfx+"smul_"+comp, pfx+"smul_"+comp+"r")
	}

	for _, comp := range []string{"x_0", "x_1", "y_0", "y_1"} {
		t.toTop(pfx + "psi_" + comp + "r")
		t.toTop(pfx + "smul_" + comp + "r")
		t.rawBlock([]string{pfx + "psi_" + comp + "r", pfx + "smul_" + comp + "r"}, "", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
		})
	}
}

// ---------------------------------------------------------------------------
// Composite entry points used by the pairing emitters
// ---------------------------------------------------------------------------

// bn254ValidateG1Input asserts that a decomposed G1 input point is on the
// BN254 curve. G1's cofactor is 1, so on-curve membership already implies
// prime-order membership — no subgroup check is needed or emitted.
func bn254ValidateG1Input(t *BN254Tracker, xName, yName, sfx string) {
	bn254AssertG1OnCurve(t, xName, yName, sfx)
}

// bn254ValidateG2Input asserts that a G2 input point is on the twist AND in
// the prime-order subgroup. Order matters: the subgroup identity is only
// meaningful for a point that is already on E'(Fp²).
func bn254ValidateG2Input(t *BN254Tracker, x0, x1, y0, y1, sfx string) {
	bn254AssertG2OnCurve(t, x0, x1, y0, y1, sfx)
	bn254AssertG2InSubgroup(t, x0, x1, y0, y1, sfx)
}

// bn254ValidateMultiPairingInputs asserts the curve-membership and subgroup
// preconditions for every (G1, G2) pair of a multi-pairing. It expects the
// decomposed tracker layout the multi-Miller loops use: p{k}x/p{k}y for the
// G1 point and q{k}x0/q{k}x1/q{k}y0/q{k}y1 for the G2 point, k in [1, n].
func bn254ValidateMultiPairingInputs(t *BN254Tracker, n int, sfx string) {
	for k := 1; k <= n; k++ {
		ks := itoa(k)
		bn254ValidateG1Input(t, "p"+ks+"x", "p"+ks+"y", sfx+ks)
		bn254ValidateG2Input(t,
			"q"+ks+"x0", "q"+ks+"x1", "q"+ks+"y0", "q"+ks+"y1", sfx+ks)
	}
}
