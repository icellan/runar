// P-256 / P-384 codegen — NIST elliptic curve operations for Bitcoin Script.
//
// Follows the same pattern as ec.go (secp256k1). Uses ECTracker for
// named stack state tracking, but with different field primes, curve orders,
// and generator points.
//
// Point representation:
//   P-256: 64 bytes (x[32] || y[32], big-endian unsigned)
//   P-384: 96 bytes (x[48] || y[48], big-endian unsigned)
//
// Key difference from secp256k1: curve parameter a = -3 (not 0), which gives
// an optimized Jacobian doubling formula.
package codegen

import (
	"math/big"
)

// ===========================================================================
// P-256 constants (secp256r1 / NIST P-256)
// ===========================================================================

var (
	p256P        *big.Int
	p256PMinus2  *big.Int
	p256B        *big.Int
	p256N        *big.Int
	p256NMinus2  *big.Int
	p256GX       *big.Int
	p256GY       *big.Int
	p256SqrtExp  *big.Int
)

// ===========================================================================
// P-384 constants (secp384r1 / NIST P-384)
// ===========================================================================

var (
	p384P        *big.Int
	p384PMinus2  *big.Int
	p384B        *big.Int
	p384N        *big.Int
	p384NMinus2  *big.Int
	p384GX       *big.Int
	p384GY       *big.Int
	p384SqrtExp  *big.Int
)

func init() {
	p256P, _ = new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	p256PMinus2 = new(big.Int).Sub(p256P, big.NewInt(2))
	p256B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	p256N, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
	p256NMinus2 = new(big.Int).Sub(p256N, big.NewInt(2))
	p256GX, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
	p256GY, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
	// sqrtExp = (p + 1) / 4
	p256SqrtExp = new(big.Int).Add(p256P, big.NewInt(1))
	p256SqrtExp.Rsh(p256SqrtExp, 2)

	p384P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)
	p384PMinus2 = new(big.Int).Sub(p384P, big.NewInt(2))
	p384B, _ = new(big.Int).SetString("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
	p384N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
	p384NMinus2 = new(big.Int).Sub(p384N, big.NewInt(2))
	p384GX, _ = new(big.Int).SetString("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16)
	p384GY, _ = new(big.Int).SetString("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
	// sqrtExp = (p + 1) / 4
	p384SqrtExp = new(big.Int).Add(p384P, big.NewInt(1))
	p384SqrtExp.Rsh(p384SqrtExp, 2)
}

// ===========================================================================
// Curve parameter structs
// ===========================================================================

type nistCurveParams struct {
	fieldP       *big.Int
	fieldPMinus2 *big.Int
	coordBytes   int // 32 for P-256, 48 for P-384
	reverseBytes func(e func(StackOp))
}

type nistGroupParams struct {
	n       *big.Int
	nMinus2 *big.Int
}

var p256CurveParams = &nistCurveParams{
	fieldP:       nil, // set in init
	fieldPMinus2: nil,
	coordBytes:   32,
	reverseBytes: ecEmitReverse32, // reuse from ec.go
}

var p384CurveParams = &nistCurveParams{
	fieldP:       nil,
	fieldPMinus2: nil,
	coordBytes:   48,
	reverseBytes: emitReverse48,
}

var p256GroupParams = &nistGroupParams{n: nil, nMinus2: nil}
var p384GroupParams = &nistGroupParams{n: nil, nMinus2: nil}

func init() {
	p256CurveParams.fieldP = p256P
	p256CurveParams.fieldPMinus2 = p256PMinus2
	p384CurveParams.fieldP = p384P
	p384CurveParams.fieldPMinus2 = p384PMinus2
	p256GroupParams.n = p256N
	p256GroupParams.nMinus2 = p256NMinus2
	p384GroupParams.n = p384N
	p384GroupParams.nMinus2 = p384NMinus2
}

// ===========================================================================
// Byte reversal for 48 bytes (P-384)
// ===========================================================================

// emitReverse48 emits inline byte reversal for a 48-byte value on TOS.
func emitReverse48(e func(StackOp)) {
	e(StackOp{Op: "opcode", Code: "OP_0"})
	e(StackOp{Op: "swap"})
	for i := 0; i < 48; i++ {
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "rot"})
		e(StackOp{Op: "rot"})
		e(StackOp{Op: "swap"})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "swap"})
	}
	e(StackOp{Op: "drop"})
}

// ===========================================================================
// bigintToNBytes converts a *big.Int to an N-byte big-endian byte slice.
// ===========================================================================

func bigintToNBytes(n *big.Int, size int) []byte {
	bytes := make([]byte, size)
	b := n.Bytes()
	copy(bytes[size-len(b):], b)
	return bytes
}

// ===========================================================================
// Helper: bit length of a big.Int
// ===========================================================================

func bigIntBitLen(n *big.Int) int {
	return n.BitLen()
}

// ===========================================================================
// Generic curve field arithmetic (parameterized by prime)
// ===========================================================================

func cPushFieldP(t *ECTracker, name string, c *nistCurveParams) {
	t.pushBigInt(name, c.fieldP)
}

func cFieldMod(t *ECTracker, aName, resultName string, c *nistCurveParams) {
	t.toTop(aName)
	cPushFieldP(t, "_fmod_p", c)
	t.rawBlock([]string{aName, "_fmod_p"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_2DUP"})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
		e(StackOp{Op: "rot"})
		e(StackOp{Op: "drop"})
		e(StackOp{Op: "over"})
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
		e(StackOp{Op: "swap"})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

func cFieldAdd(t *ECTracker, aName, bName, resultName string, c *nistCurveParams) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fadd_sum", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	cFieldMod(t, "_fadd_sum", resultName, c)
}

func cFieldSub(t *ECTracker, aName, bName, resultName string, c *nistCurveParams) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fsub_diff", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})
	cFieldMod(t, "_fsub_diff", resultName, c)
}

func cFieldMul(t *ECTracker, aName, bName, resultName string, c *nistCurveParams) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fmul_prod", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	cFieldMod(t, "_fmul_prod", resultName, c)
}

func cFieldMulConst(t *ECTracker, aName string, cv int64, resultName string, c *nistCurveParams) {
	t.toTop(aName)
	t.rawBlock([]string{aName}, "_fmc_prod", func(e func(StackOp)) {
		if cv == 2 {
			e(StackOp{Op: "opcode", Code: "OP_2MUL"})
		} else {
			e(StackOp{Op: "push", Value: bigIntPush(cv)})
			e(StackOp{Op: "opcode", Code: "OP_MUL"})
		}
	})
	cFieldMod(t, "_fmc_prod", resultName, c)
}

func cFieldSqr(t *ECTracker, aName, resultName string, c *nistCurveParams) {
	t.copyToTop(aName, "_fsqr_copy")
	cFieldMul(t, aName, "_fsqr_copy", resultName, c)
}

// cFieldInv computes a^(p-2) mod p via generic square-and-multiply.
func cFieldInv(t *ECTracker, aName, resultName string, c *nistCurveParams) {
	exp := c.fieldPMinus2
	bits := bigIntBitLen(exp)

	// Start: result = a (highest bit of exp is 1)
	t.copyToTop(aName, "_inv_r")

	for i := bits - 2; i >= 0; i-- {
		cFieldSqr(t, "_inv_r", "_inv_r2", c)
		t.rename("_inv_r")
		if exp.Bit(i) == 1 {
			t.copyToTop(aName, "_inv_a")
			cFieldMul(t, "_inv_r", "_inv_a", "_inv_m", c)
			t.rename("_inv_r")
		}
	}

	t.toTop(aName)
	t.drop()
	t.toTop("_inv_r")
	t.rename(resultName)
}

// ===========================================================================
// Group-order arithmetic (for ECDSA: mod n operations)
// ===========================================================================

func cPushGroupN(t *ECTracker, name string, g *nistGroupParams) {
	t.pushBigInt(name, g.n)
}

func cGroupMod(t *ECTracker, aName, resultName string, g *nistGroupParams) {
	t.toTop(aName)
	cPushGroupN(t, "_gmod_n", g)
	t.rawBlock([]string{aName, "_gmod_n"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_2DUP"})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
		e(StackOp{Op: "rot"})
		e(StackOp{Op: "drop"})
		e(StackOp{Op: "over"})
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
		e(StackOp{Op: "swap"})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

func cGroupMul(t *ECTracker, aName, bName, resultName string, g *nistGroupParams) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_gmul_prod", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	cGroupMod(t, "_gmul_prod", resultName, g)
}

// cGroupInv computes a^(n-2) mod n via square-and-multiply.
func cGroupInv(t *ECTracker, aName, resultName string, g *nistGroupParams) {
	exp := g.nMinus2
	bits := bigIntBitLen(exp)

	t.copyToTop(aName, "_ginv_r")

	for i := bits - 2; i >= 0; i-- {
		// Square
		t.copyToTop("_ginv_r", "_ginv_sq_copy")
		cGroupMul(t, "_ginv_r", "_ginv_sq_copy", "_ginv_sq", g)
		t.rename("_ginv_r")
		if exp.Bit(i) == 1 {
			t.copyToTop(aName, "_ginv_a")
			cGroupMul(t, "_ginv_r", "_ginv_a", "_ginv_m", g)
			t.rename("_ginv_r")
		}
	}

	t.toTop(aName)
	t.drop()
	t.toTop("_ginv_r")
	t.rename(resultName)
}

// ===========================================================================
// Point decompose / compose (parameterized by coordinate byte size)
// ===========================================================================

func cDecomposePoint(t *ECTracker, pointName, xName, yName string, c *nistCurveParams) {
	t.toTop(pointName)
	t.rawBlock([]string{pointName}, "", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(int64(c.coordBytes))})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	})
	t.nm = append(t.nm, "_dp_xb")
	t.nm = append(t.nm, "_dp_yb")

	// Convert y_bytes (on top) to num
	t.rawBlock([]string{"_dp_yb"}, yName, func(e func(StackOp)) {
		c.reverseBytes(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Convert x_bytes to num
	t.toTop("_dp_xb")
	t.rawBlock([]string{"_dp_xb"}, xName, func(e func(StackOp)) {
		c.reverseBytes(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Swap to standard order [xName, yName]
	t.swap()
}

func cComposePoint(t *ECTracker, xName, yName, resultName string, c *nistCurveParams) {
	numBinSize := int64(c.coordBytes + 1)

	// Convert x to coordBytes big-endian
	t.toTop(xName)
	t.rawBlock([]string{xName}, "_cp_xb", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(numBinSize)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		e(StackOp{Op: "push", Value: bigIntPush(int64(c.coordBytes))})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "drop"})
		c.reverseBytes(e)
	})

	// Convert y to coordBytes big-endian
	t.toTop(yName)
	t.rawBlock([]string{yName}, "_cp_yb", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(numBinSize)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		e(StackOp{Op: "push", Value: bigIntPush(int64(c.coordBytes))})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "drop"})
		c.reverseBytes(e)
	})

	// Cat: x_be || y_be
	t.toTop("_cp_xb")
	t.toTop("_cp_yb")
	t.rawBlock([]string{"_cp_xb", "_cp_yb"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
	})
}

// ===========================================================================
// Affine point addition
// ===========================================================================

func cAffineAdd(t *ECTracker, c *nistCurveParams) {
	// s_num = qy - py
	t.copyToTop("qy", "_qy1")
	t.copyToTop("py", "_py1")
	cFieldSub(t, "_qy1", "_py1", "_s_num", c)

	// s_den = qx - px
	t.copyToTop("qx", "_qx1")
	t.copyToTop("px", "_px1")
	cFieldSub(t, "_qx1", "_px1", "_s_den", c)

	// s = s_num / s_den mod p
	cFieldInv(t, "_s_den", "_s_den_inv", c)
	cFieldMul(t, "_s_num", "_s_den_inv", "_s", c)

	// rx = s^2 - px - qx mod p
	t.copyToTop("_s", "_s_keep")
	cFieldSqr(t, "_s", "_s2", c)
	t.copyToTop("px", "_px2")
	cFieldSub(t, "_s2", "_px2", "_rx1", c)
	t.copyToTop("qx", "_qx2")
	cFieldSub(t, "_rx1", "_qx2", "rx", c)

	// ry = s * (px - rx) - py mod p
	t.copyToTop("px", "_px3")
	t.copyToTop("rx", "_rx2")
	cFieldSub(t, "_px3", "_rx2", "_px_rx", c)
	cFieldMul(t, "_s_keep", "_px_rx", "_s_px_rx", c)
	t.copyToTop("py", "_py2")
	cFieldSub(t, "_s_px_rx", "_py2", "ry", c)

	// Clean up original points
	t.toTop("px")
	t.drop()
	t.toTop("py")
	t.drop()
	t.toTop("qx")
	t.drop()
	t.toTop("qy")
	t.drop()
}

// ===========================================================================
// Jacobian point doubling with a=-3 optimization
// ===========================================================================

// cJacobianDouble performs Jacobian doubling for curves with a = -3 (P-256, P-384).
// Uses optimization: A = 3*(X - Z^2)*(X + Z^2) instead of 3*X^2 + a*Z^4.
func cJacobianDouble(t *ECTracker, c *nistCurveParams) {
	// Z^2
	t.copyToTop("jz", "_jz_sq_tmp")
	cFieldSqr(t, "_jz_sq_tmp", "_Z2", c)

	// X - Z^2 and X + Z^2
	t.copyToTop("jx", "_jx_c1")
	t.copyToTop("_Z2", "_Z2_c1")
	cFieldSub(t, "_jx_c1", "_Z2_c1", "_X_minus_Z2", c)
	t.copyToTop("jx", "_jx_c2")
	cFieldAdd(t, "_jx_c2", "_Z2", "_X_plus_Z2", c)

	// A = 3*(X-Z^2)*(X+Z^2)
	cFieldMul(t, "_X_minus_Z2", "_X_plus_Z2", "_prod", c)
	t.pushInt("_three", 3)
	cFieldMul(t, "_prod", "_three", "_A", c)

	// B = 4*X*Y^2
	t.copyToTop("jy", "_jy_sq_tmp")
	cFieldSqr(t, "_jy_sq_tmp", "_Y2", c)
	t.copyToTop("_Y2", "_Y2_c1")
	t.copyToTop("jx", "_jx_c3")
	cFieldMul(t, "_jx_c3", "_Y2", "_xY2", c)
	t.pushInt("_four", 4)
	cFieldMul(t, "_xY2", "_four", "_B", c)

	// C = 8*Y^4
	cFieldSqr(t, "_Y2_c1", "_Y4", c)
	t.pushInt("_eight", 8)
	cFieldMul(t, "_Y4", "_eight", "_C", c)

	// X3 = A^2 - 2*B
	t.copyToTop("_A", "_A_save")
	t.copyToTop("_B", "_B_save")
	cFieldSqr(t, "_A", "_A2", c)
	t.copyToTop("_B", "_B_c1")
	cFieldMulConst(t, "_B_c1", 2, "_2B", c)
	cFieldSub(t, "_A2", "_2B", "_X3", c)

	// Y3 = A*(B - X3) - C
	t.copyToTop("_X3", "_X3_c")
	cFieldSub(t, "_B_save", "_X3_c", "_B_minus_X3", c)
	cFieldMul(t, "_A_save", "_B_minus_X3", "_A_tmp", c)
	cFieldSub(t, "_A_tmp", "_C", "_Y3", c)

	// Z3 = 2*Y*Z
	t.copyToTop("jy", "_jy_c")
	t.copyToTop("jz", "_jz_c")
	cFieldMul(t, "_jy_c", "_jz_c", "_yz", c)
	cFieldMulConst(t, "_yz", 2, "_Z3", c)

	// Clean up and rename
	t.toTop("_B")
	t.drop()
	t.toTop("jz")
	t.drop()
	t.toTop("jx")
	t.drop()
	t.toTop("jy")
	t.drop()
	t.toTop("_X3")
	t.rename("jx")
	t.toTop("_Y3")
	t.rename("jy")
	t.toTop("_Z3")
	t.rename("jz")
}

// ===========================================================================
// Jacobian to affine conversion
// ===========================================================================

func cJacobianToAffine(t *ECTracker, rxName, ryName string, c *nistCurveParams) {
	cFieldInv(t, "jz", "_zinv", c)
	t.copyToTop("_zinv", "_zinv_keep")
	cFieldSqr(t, "_zinv", "_zinv2", c)
	t.copyToTop("_zinv2", "_zinv2_keep")
	cFieldMul(t, "_zinv_keep", "_zinv2", "_zinv3", c)
	cFieldMul(t, "jx", "_zinv2_keep", rxName, c)
	cFieldMul(t, "jy", "_zinv3", ryName, c)
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

// cBuildJacobianAddAffineInline builds Jacobian mixed-add ops for use inside OP_IF.
func cBuildJacobianAddAffineInline(e func(StackOp), t *ECTracker, c *nistCurveParams) {
	initNm := make([]string, len(t.nm))
	copy(initNm, t.nm)
	it := NewECTracker(initNm, e)

	it.copyToTop("jz", "_jz_for_z1cu")
	it.copyToTop("jz", "_jz_for_z3")
	it.copyToTop("jy", "_jy_for_y3")
	it.copyToTop("jx", "_jx_for_u1h2")

	// Z1sq = jz^2
	cFieldSqr(it, "jz", "_Z1sq", c)

	// Z1cu = _jz_for_z1cu * Z1sq
	it.copyToTop("_Z1sq", "_Z1sq_for_u2")
	cFieldMul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu", c)

	// U2 = ax * Z1sq_for_u2
	it.copyToTop("ax", "_ax_c")
	cFieldMul(it, "_ax_c", "_Z1sq_for_u2", "_U2", c)

	// S2 = ay * Z1cu
	it.copyToTop("ay", "_ay_c")
	cFieldMul(it, "_ay_c", "_Z1cu", "_S2", c)

	// H = U2 - jx
	cFieldSub(it, "_U2", "jx", "_H", c)

	// R = S2 - jy
	cFieldSub(it, "_S2", "jy", "_R", c)

	it.copyToTop("_H", "_H_for_h3")
	it.copyToTop("_H", "_H_for_z3")

	// H2 = H^2
	cFieldSqr(it, "_H", "_H2", c)

	it.copyToTop("_H2", "_H2_for_u1h2")

	// H3 = H_for_h3 * H2
	cFieldMul(it, "_H_for_h3", "_H2", "_H3", c)

	// U1H2 = _jx_for_u1h2 * H2_for_u1h2
	cFieldMul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2", c)

	it.copyToTop("_R", "_R_for_y3")
	it.copyToTop("_U1H2", "_U1H2_for_y3")
	it.copyToTop("_H3", "_H3_for_y3")

	// X3 = R^2 - H3 - 2*U1H2
	cFieldSqr(it, "_R", "_R2", c)
	cFieldSub(it, "_R2", "_H3", "_x3_tmp", c)
	cFieldMulConst(it, "_U1H2", 2, "_2U1H2", c)
	cFieldSub(it, "_x3_tmp", "_2U1H2", "_X3", c)

	// Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
	it.copyToTop("_X3", "_X3_c")
	cFieldSub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x", c)
	cFieldMul(it, "_R_for_y3", "_u_minus_x", "_r_tmp", c)
	cFieldMul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3", c)
	cFieldSub(it, "_r_tmp", "_jy_h3", "_Y3", c)

	// Z3 = _jz_for_z3 * _H_for_z3
	cFieldMul(it, "_jz_for_z3", "_H_for_z3", "_Z3", c)

	it.toTop("_X3")
	it.rename("jx")
	it.toTop("_Y3")
	it.rename("jy")
	it.toTop("_Z3")
	it.rename("jz")
}

// ===========================================================================
// Scalar multiplication (generic for both P-256 and P-384)
// ===========================================================================

func cEmitMul(emit func(StackOp), c *nistCurveParams, g *nistGroupParams) {
	t := NewECTracker([]string{"_pt", "_k"}, emit)
	cDecomposePoint(t, "_pt", "ax", "ay", c)

	// k' = k + 3n
	t.toTop("_k")
	t.pushBigInt("_n", g.n)
	t.rawBlock([]string{"_k", "_n"}, "_kn", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_n2", g.n)
	t.rawBlock([]string{"_kn", "_n2"}, "_kn2", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_n3", g.n)
	t.rawBlock([]string{"_kn2", "_n3"}, "_kn3", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.rename("_k")

	// Determine iteration count based on 3*n bit length
	// max value of k+3n is 4n-1
	fourNMinus1 := new(big.Int).Mul(big.NewInt(4), g.n)
	fourNMinus1.Sub(fourNMinus1, big.NewInt(1))
	topBit := fourNMinus1.BitLen()
	startBit := topBit - 2 // highest bit is always 1 (init), start from next

	// Init accumulator = P (top bit of k+3n is always 1)
	t.copyToTop("ax", "jx")
	t.copyToTop("ay", "jy")
	t.pushInt("jz", 1)

	// Iterate from startBit down to 0
	for bit := startBit; bit >= 0; bit-- {
		cJacobianDouble(t, c)

		// Extract bit: (k >> bit) & 1
		t.copyToTop("_k", "_k_copy")
		if bit == 1 {
			t.rawBlock([]string{"_k_copy"}, "_shifted", func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_2DIV"})
			})
		} else if bit > 1 {
			t.pushInt("_shift", int64(bit))
			t.rawBlock([]string{"_k_copy", "_shift"}, "_shifted", func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_RSHIFTNUM"})
			})
		} else {
			t.rename("_shifted")
		}
		t.pushInt("_two", 2)
		t.rawBlock([]string{"_shifted", "_two"}, "_bit", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})

		// Conditional add
		t.toTop("_bit")
		t.nm = t.nm[:len(t.nm)-1] // _bit consumed by IF
		var addOps []StackOp
		addEmit := func(op StackOp) { addOps = append(addOps, op) }
		cBuildJacobianAddAffineInline(addEmit, t, c)
		emit(StackOp{Op: "if", Then: addOps, Else: []StackOp{}})
	}

	cJacobianToAffine(t, "_rx", "_ry", c)

	// Clean up
	t.toTop("ax")
	t.drop()
	t.toTop("ay")
	t.drop()
	t.toTop("_k")
	t.drop()

	cComposePoint(t, "_rx", "_ry", "_result", c)
}

// ===========================================================================
// Square-and-multiply modular exponentiation (for sqrt)
// ===========================================================================

func cFieldPow(t *ECTracker, baseName string, exp *big.Int, resultName string, c *nistCurveParams) {
	bits := bigIntBitLen(exp)

	// Start: result = base (highest bit = 1)
	t.copyToTop(baseName, "_pow_r")

	for i := bits - 2; i >= 0; i-- {
		cFieldSqr(t, "_pow_r", "_pow_sq", c)
		t.rename("_pow_r")
		if exp.Bit(i) == 1 {
			t.copyToTop(baseName, "_pow_b")
			cFieldMul(t, "_pow_r", "_pow_b", "_pow_m", c)
			t.rename("_pow_r")
		}
	}

	t.toTop(baseName)
	t.drop()
	t.toTop("_pow_r")
	t.rename(resultName)
}

// ===========================================================================
// Pubkey decompression (prefix byte + x → (x, y))
// ===========================================================================

func cDecompressPubKey(
	t *ECTracker,
	pkName, qxName, qyName string,
	c *nistCurveParams,
	curveB, sqrtExp *big.Int,
) {
	t.toTop(pkName)

	// Split: [prefix_byte, x_bytes]
	t.rawBlock([]string{pkName}, "", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	})
	t.nm = append(t.nm, "_dk_prefix")
	t.nm = append(t.nm, "_dk_xbytes")

	// Convert prefix to parity: 0x02 → 0, 0x03 → 1
	t.toTop("_dk_prefix")
	t.rawBlock([]string{"_dk_prefix"}, "_dk_parity", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		e(StackOp{Op: "push", Value: bigIntPush(2)})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})

	// Stash parity on altstack
	t.toTop("_dk_parity")
	t.toAlt()

	// Convert x_bytes to number
	t.toTop("_dk_xbytes")
	t.rawBlock([]string{"_dk_xbytes"}, "_dk_x", func(e func(StackOp)) {
		c.reverseBytes(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Save x for later
	t.copyToTop("_dk_x", "_dk_x_save")

	// Compute y^2 = x^3 - 3x + b mod p
	// x^2
	t.copyToTop("_dk_x", "_dk_x_c1")
	cFieldSqr(t, "_dk_x", "_dk_x2", c)
	// x^3 = x^2 * x
	cFieldMul(t, "_dk_x2", "_dk_x_c1", "_dk_x3", c)
	// 3 * x_save
	t.copyToTop("_dk_x_save", "_dk_x_for_3")
	cFieldMulConst(t, "_dk_x_for_3", 3, "_dk_3x", c)
	// x^3 - 3x
	cFieldSub(t, "_dk_x3", "_dk_3x", "_dk_x3m3x", c)
	// + b
	t.pushBigInt("_dk_b", curveB)
	cFieldAdd(t, "_dk_x3m3x", "_dk_b", "_dk_y2", c)

	// y = (y^2)^sqrtExp mod p
	cFieldPow(t, "_dk_y2", sqrtExp, "_dk_y_cand", c)

	// Check if candidate y has the right parity
	t.copyToTop("_dk_y_cand", "_dk_y_check")
	t.rawBlock([]string{"_dk_y_check"}, "_dk_y_par", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(2)})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})

	// Retrieve parity from altstack
	t.fromAlt("_dk_parity")

	// Compare
	t.toTop("_dk_y_par")
	t.toTop("_dk_parity")
	t.rawBlock([]string{"_dk_y_par", "_dk_parity"}, "_dk_match", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	})

	// Compute p - y_cand
	t.copyToTop("_dk_y_cand", "_dk_y_for_neg")
	cPushFieldP(t, "_dk_pfn", c)
	t.toTop("_dk_y_for_neg")
	t.rawBlock([]string{"_dk_pfn", "_dk_y_for_neg"}, "_dk_neg_y", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})

	// Use OP_IF to select: if match, use y_cand (drop neg_y), else use neg_y (drop y_cand)
	t.toTop("_dk_match")
	t.nm = t.nm[:len(t.nm)-1] // condition consumed by IF

	thenOps := []StackOp{{Op: "drop"}}  // remove neg_y, leaving y_cand
	elseOps := []StackOp{{Op: "nip"}}   // remove y_cand, leaving neg_y
	t.e(StackOp{Op: "if", Then: thenOps, Else: elseOps})

	// Remove one from tracker and rename the surviving item
	negIdx := -1
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == "_dk_neg_y" {
			negIdx = i
			break
		}
	}
	if negIdx >= 0 {
		t.nm = append(t.nm[:negIdx], t.nm[negIdx+1:]...)
	}

	ycIdx := -1
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == "_dk_y_cand" {
			ycIdx = i
			break
		}
	}
	if ycIdx >= 0 {
		t.nm[ycIdx] = qyName
	}

	xsIdx := -1
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == "_dk_x_save" {
			xsIdx = i
			break
		}
	}
	if xsIdx >= 0 {
		t.nm[xsIdx] = qxName
	}
}

// ===========================================================================
// ECDSA verification
// ===========================================================================

func cEmitVerifyECDSA(
	emit func(StackOp),
	c *nistCurveParams,
	g *nistGroupParams,
	curveB, sqrtExp, gx, gy *big.Int,
) {
	t := NewECTracker([]string{"_msg", "_sig", "_pk"}, emit)

	// Step 1: e = SHA-256(msg) as integer
	t.toTop("_msg")
	t.rawBlock([]string{"_msg"}, "_e", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SHA256"})
		// SHA-256 produces 32 bytes BE. Convert to integer:
		ecEmitReverse32(e) // reuse 32-byte reversal from ec.go
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Step 2: Parse sig into (r, s)
	t.toTop("_sig")
	t.rawBlock([]string{"_sig"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(int64(c.coordBytes))})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	})
	t.nm = append(t.nm, "_r_bytes")
	t.nm = append(t.nm, "_s_bytes")

	// Convert r_bytes to integer
	t.toTop("_r_bytes")
	t.rawBlock([]string{"_r_bytes"}, "_r", func(e func(StackOp)) {
		c.reverseBytes(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Convert s_bytes to integer
	t.toTop("_s_bytes")
	t.rawBlock([]string{"_s_bytes"}, "_s", func(e func(StackOp)) {
		c.reverseBytes(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Step 3: Decompress pubkey
	cDecompressPubKey(t, "_pk", "_qx", "_qy", c, curveB, sqrtExp)

	// Step 4: w = s^{-1} mod n
	cGroupInv(t, "_s", "_w", g)

	// Step 5: u1 = e * w mod n
	t.copyToTop("_w", "_w_c1")
	cGroupMul(t, "_e", "_w_c1", "_u1", g)

	// Step 6: u2 = r * w mod n
	t.copyToTop("_r", "_r_save")
	cGroupMul(t, "_r", "_w", "_u2", g)

	// Step 7: R = u1*G + u2*Q
	pointBytes := c.coordBytes * 2
	gPointData := make([]byte, pointBytes)
	copy(gPointData[0:c.coordBytes], bigintToNBytes(gx, c.coordBytes))
	copy(gPointData[c.coordBytes:pointBytes], bigintToNBytes(gy, c.coordBytes))

	t.pushBytes("_G", gPointData)
	t.toTop("_u1")

	// Stash items on altstack
	t.toTop("_r_save")
	t.toAlt()
	t.toTop("_u2")
	t.toAlt()
	t.toTop("_qy")
	t.toAlt()
	t.toTop("_qx")
	t.toAlt()

	// Remove _G and _u1 from tracker before cEmitMul
	t.nm = t.nm[:len(t.nm)-1] // _u1
	t.nm = t.nm[:len(t.nm)-1] // _G

	cEmitMul(emit, c, g)

	// After mul, one result point is on the stack
	t.nm = append(t.nm, "_R1_point")

	// Pop qx/qy/u2 from altstack (LIFO order)
	t.fromAlt("_qx")
	t.fromAlt("_qy")
	t.fromAlt("_u2")

	// Stash R1 point
	t.toTop("_R1_point")
	t.toAlt()

	// Compose Q point
	cComposePoint(t, "_qx", "_qy", "_Q_point", c)

	t.toTop("_u2")

	// Remove from tracker, emit mul, push result
	t.nm = t.nm[:len(t.nm)-1] // _u2
	t.nm = t.nm[:len(t.nm)-1] // _Q_point
	cEmitMul(emit, c, g)
	t.nm = append(t.nm, "_R2_point")

	// Restore R1 point
	t.fromAlt("_R1_point")

	// Swap so R2 is on top
	t.swap()

	// Decompose both, add, compose
	cDecomposePoint(t, "_R1_point", "_rpx", "_rpy", c)
	cDecomposePoint(t, "_R2_point", "_rqx", "_rqy", c)

	// Rename to what cAffineAdd expects
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == "_rpx" {
			t.nm[i] = "px"
			break
		}
	}
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == "_rpy" {
			t.nm[i] = "py"
			break
		}
	}
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == "_rqx" {
			t.nm[i] = "qx"
			break
		}
	}
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == "_rqy" {
			t.nm[i] = "qy"
			break
		}
	}

	cAffineAdd(t, c)

	// Step 8: x_R mod n == r
	t.toTop("ry")
	t.drop()

	cGroupMod(t, "rx", "_rx_mod_n", g)

	// Restore r
	t.fromAlt("_r_save")

	// Compare
	t.toTop("_rx_mod_n")
	t.toTop("_r_save")
	t.rawBlock([]string{"_rx_mod_n", "_r_save"}, "_result", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	})
}

// ===========================================================================
// P-256 public API
// ===========================================================================

// EmitP256Add adds two P-256 points.
func EmitP256Add(emit func(StackOp)) {
	t := NewECTracker([]string{"_pa", "_pb"}, emit)
	cDecomposePoint(t, "_pa", "px", "py", p256CurveParams)
	cDecomposePoint(t, "_pb", "qx", "qy", p256CurveParams)
	cAffineAdd(t, p256CurveParams)
	cComposePoint(t, "rx", "ry", "_result", p256CurveParams)
}

// EmitP256Mul performs P-256 scalar multiplication.
func EmitP256Mul(emit func(StackOp)) {
	cEmitMul(emit, p256CurveParams, p256GroupParams)
}

// EmitP256MulGen performs P-256 generator multiplication.
func EmitP256MulGen(emit func(StackOp)) {
	gPoint := make([]byte, 64)
	copy(gPoint[0:32], bigintToNBytes(p256GX, 32))
	copy(gPoint[32:64], bigintToNBytes(p256GY, 32))
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: gPoint}})
	emit(StackOp{Op: "swap"}) // [point, scalar]
	EmitP256Mul(emit)
}

// EmitP256Negate negates a P-256 point.
func EmitP256Negate(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt"}, emit)
	cDecomposePoint(t, "_pt", "_nx", "_ny", p256CurveParams)
	cPushFieldP(t, "_fp", p256CurveParams)
	cFieldSub(t, "_fp", "_ny", "_neg_y", p256CurveParams)
	cComposePoint(t, "_nx", "_neg_y", "_result", p256CurveParams)
}

// EmitP256OnCurve checks if a P-256 point is on the curve (y^2 = x^3 - 3x + b mod p).
func EmitP256OnCurve(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt"}, emit)
	cDecomposePoint(t, "_pt", "_x", "_y", p256CurveParams)

	// lhs = y^2
	cFieldSqr(t, "_y", "_y2", p256CurveParams)

	// rhs = x^3 - 3x + b
	t.copyToTop("_x", "_x_copy")
	t.copyToTop("_x", "_x_copy2")
	cFieldSqr(t, "_x", "_x2", p256CurveParams)
	cFieldMul(t, "_x2", "_x_copy", "_x3", p256CurveParams)
	cFieldMulConst(t, "_x_copy2", 3, "_3x", p256CurveParams)
	cFieldSub(t, "_x3", "_3x", "_x3m3x", p256CurveParams)
	t.pushBigInt("_b", p256B)
	cFieldAdd(t, "_x3m3x", "_b", "_rhs", p256CurveParams)

	// Compare
	t.toTop("_y2")
	t.toTop("_rhs")
	t.rawBlock([]string{"_y2", "_rhs"}, "_result", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	})
}

// EmitP256EncodeCompressed encodes a P-256 point as 33-byte compressed pubkey.
func EmitP256EncodeCompressed(emit func(StackOp)) {
	// Split at 32: [x_bytes, y_bytes]
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// Get last byte of y for parity
	emit(StackOp{Op: "opcode", Code: "OP_SIZE"})
	emit(StackOp{Op: "push", Value: bigIntPush(1)})
	emit(StackOp{Op: "opcode", Code: "OP_SUB"})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// Stack: [x_bytes, y_prefix, last_byte]
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	emit(StackOp{Op: "push", Value: bigIntPush(2)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	// Stack: [x_bytes, y_prefix, parity]
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"}) // drop y_prefix
	// Stack: [x_bytes, parity]
	emit(StackOp{Op: "if",
		Then: []StackOp{{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x03}}}},
		Else: []StackOp{{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x02}}}},
	})
	// Stack: [x_bytes, prefix_byte]
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
}

// EmitVerifyECDSA_P256 verifies an ECDSA signature on P-256.
func EmitVerifyECDSA_P256(emit func(StackOp)) {
	cEmitVerifyECDSA(emit, p256CurveParams, p256GroupParams, p256B, p256SqrtExp, p256GX, p256GY)
}

// ===========================================================================
// P-384 public API
// ===========================================================================

// EmitP384Add adds two P-384 points.
func EmitP384Add(emit func(StackOp)) {
	t := NewECTracker([]string{"_pa", "_pb"}, emit)
	cDecomposePoint(t, "_pa", "px", "py", p384CurveParams)
	cDecomposePoint(t, "_pb", "qx", "qy", p384CurveParams)
	cAffineAdd(t, p384CurveParams)
	cComposePoint(t, "rx", "ry", "_result", p384CurveParams)
}

// EmitP384Mul performs P-384 scalar multiplication.
func EmitP384Mul(emit func(StackOp)) {
	cEmitMul(emit, p384CurveParams, p384GroupParams)
}

// EmitP384MulGen performs P-384 generator multiplication.
func EmitP384MulGen(emit func(StackOp)) {
	gPoint := make([]byte, 96)
	copy(gPoint[0:48], bigintToNBytes(p384GX, 48))
	copy(gPoint[48:96], bigintToNBytes(p384GY, 48))
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: gPoint}})
	emit(StackOp{Op: "swap"}) // [point, scalar]
	EmitP384Mul(emit)
}

// EmitP384Negate negates a P-384 point.
func EmitP384Negate(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt"}, emit)
	cDecomposePoint(t, "_pt", "_nx", "_ny", p384CurveParams)
	cPushFieldP(t, "_fp", p384CurveParams)
	cFieldSub(t, "_fp", "_ny", "_neg_y", p384CurveParams)
	cComposePoint(t, "_nx", "_neg_y", "_result", p384CurveParams)
}

// EmitP384OnCurve checks if a P-384 point is on the curve.
func EmitP384OnCurve(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt"}, emit)
	cDecomposePoint(t, "_pt", "_x", "_y", p384CurveParams)

	// lhs = y^2
	cFieldSqr(t, "_y", "_y2", p384CurveParams)

	// rhs = x^3 - 3x + b
	t.copyToTop("_x", "_x_copy")
	t.copyToTop("_x", "_x_copy2")
	cFieldSqr(t, "_x", "_x2", p384CurveParams)
	cFieldMul(t, "_x2", "_x_copy", "_x3", p384CurveParams)
	cFieldMulConst(t, "_x_copy2", 3, "_3x", p384CurveParams)
	cFieldSub(t, "_x3", "_3x", "_x3m3x", p384CurveParams)
	t.pushBigInt("_b", p384B)
	cFieldAdd(t, "_x3m3x", "_b", "_rhs", p384CurveParams)

	// Compare
	t.toTop("_y2")
	t.toTop("_rhs")
	t.rawBlock([]string{"_y2", "_rhs"}, "_result", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	})
}

// EmitP384EncodeCompressed encodes a P-384 point as 49-byte compressed pubkey.
func EmitP384EncodeCompressed(emit func(StackOp)) {
	// Split at 48: [x_bytes, y_bytes]
	emit(StackOp{Op: "push", Value: bigIntPush(48)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// Get last byte of y for parity
	emit(StackOp{Op: "opcode", Code: "OP_SIZE"})
	emit(StackOp{Op: "push", Value: bigIntPush(1)})
	emit(StackOp{Op: "opcode", Code: "OP_SUB"})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// Stack: [x_bytes, y_prefix, last_byte]
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	emit(StackOp{Op: "push", Value: bigIntPush(2)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	// Stack: [x_bytes, y_prefix, parity]
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"}) // drop y_prefix
	// Stack: [x_bytes, parity]
	emit(StackOp{Op: "if",
		Then: []StackOp{{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x03}}}},
		Else: []StackOp{{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x02}}}},
	})
	// Stack: [x_bytes, prefix_byte]
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
}

// EmitVerifyECDSA_P384 verifies an ECDSA signature on P-384.
func EmitVerifyECDSA_P384(emit func(StackOp)) {
	cEmitVerifyECDSA(emit, p384CurveParams, p384GroupParams, p384B, p384SqrtExp, p384GX, p384GY)
}
