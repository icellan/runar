// EC codegen -- secp256k1 elliptic curve operations for Bitcoin Script.
//
// Follows the slh_dsa.go pattern: self-contained module imported by stack.go.
// Uses an ECTracker (similar to SLHTracker) for named stack state tracking.
//
// Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
// Internal arithmetic uses Jacobian coordinates for scalar multiplication.
package codegen

import (
	"fmt"
	"math/big"
)

// ===========================================================================
// Constants
// ===========================================================================

// secp256k1 field prime p = 2^256 - 2^32 - 977
var ecFieldP *big.Int

// p - 2, used for Fermat's little theorem modular inverse
var ecFieldPMinus2 *big.Int

// secp256k1 generator x-coordinate
var ecGenX *big.Int

// secp256k1 generator y-coordinate
var ecGenY *big.Int

func init() {
	ecFieldP, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	ecFieldPMinus2 = new(big.Int).Sub(ecFieldP, big.NewInt(2))
	ecGenX, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	ecGenY, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
}

// bigintToBytes32 converts a *big.Int to a 32-byte big-endian byte slice.
func bigintToBytes32(n *big.Int) []byte {
	bytes := make([]byte, 32)
	b := n.Bytes()
	// Right-align into 32-byte slice
	copy(bytes[32-len(b):], b)
	return bytes
}

// ===========================================================================
// ECTracker -- named stack state tracker (mirrors TS ECTracker)
// ===========================================================================

// ECTracker tracks named stack positions and emits StackOps for EC codegen.
type ECTracker struct {
	nm []string // stack names ("" for anonymous)
	e  func(StackOp)
}

// NewECTracker creates a new tracker with initial named stack slots.
func NewECTracker(init []string, emit func(StackOp)) *ECTracker {
	nm := make([]string, len(init))
	copy(nm, init)
	return &ECTracker{nm: nm, e: emit}
}

func (t *ECTracker) findDepth(name string) int {
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == name {
			return len(t.nm) - 1 - i
		}
	}
	panic(fmt.Sprintf("ECTracker: '%s' not on stack %v", name, t.nm))
}

func (t *ECTracker) pushBytes(n string, v []byte) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: v}})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) pushBigInt(n string, v *big.Int) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(v)}})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) pushInt(n string, v int64) {
	t.e(StackOp{Op: "push", Value: bigIntPush(v)})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) dup(n string) {
	t.e(StackOp{Op: "dup"})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) drop() {
	t.e(StackOp{Op: "drop"})
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *ECTracker) nip() {
	t.e(StackOp{Op: "nip"})
	L := len(t.nm)
	if L >= 2 {
		t.nm = append(t.nm[:L-2], t.nm[L-1])
	}
}

func (t *ECTracker) over(n string) {
	t.e(StackOp{Op: "over"})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) swap() {
	t.e(StackOp{Op: "swap"})
	L := len(t.nm)
	if L >= 2 {
		t.nm[L-1], t.nm[L-2] = t.nm[L-2], t.nm[L-1]
	}
}

func (t *ECTracker) rot() {
	t.e(StackOp{Op: "rot"})
	L := len(t.nm)
	if L >= 3 {
		r := t.nm[L-3]
		t.nm = append(t.nm[:L-3], t.nm[L-2:]...)
		t.nm = append(t.nm, r)
	}
}

func (t *ECTracker) op(code string) {
	t.e(StackOp{Op: "opcode", Code: code})
}

func (t *ECTracker) roll(d int) {
	if d == 0 {
		return
	}
	if d == 1 {
		t.swap()
		return
	}
	if d == 2 {
		t.rot()
		return
	}
	t.e(StackOp{Op: "push", Value: bigIntPush(int64(d))})
	t.nm = append(t.nm, "")
	t.e(StackOp{Op: "roll", Depth: d})
	t.nm = t.nm[:len(t.nm)-1] // pop the push placeholder
	idx := len(t.nm) - 1 - d
	r := t.nm[idx]
	t.nm = append(t.nm[:idx], t.nm[idx+1:]...)
	t.nm = append(t.nm, r)
}

func (t *ECTracker) pick(d int, n string) {
	if d == 0 {
		t.dup(n)
		return
	}
	if d == 1 {
		t.over(n)
		return
	}
	t.e(StackOp{Op: "push", Value: bigIntPush(int64(d))})
	t.nm = append(t.nm, "")
	t.e(StackOp{Op: "pick", Depth: d})
	t.nm = t.nm[:len(t.nm)-1] // pop the push placeholder
	t.nm = append(t.nm, n)
}

func (t *ECTracker) toTop(name string) {
	t.roll(t.findDepth(name))
}

func (t *ECTracker) copyToTop(name, n string) {
	t.pick(t.findDepth(name), n)
}

func (t *ECTracker) toAlt() {
	t.op("OP_TOALTSTACK")
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *ECTracker) fromAlt(n string) {
	t.op("OP_FROMALTSTACK")
	t.nm = append(t.nm, n)
}

func (t *ECTracker) rename(n string) {
	if len(t.nm) > 0 {
		t.nm[len(t.nm)-1] = n
	}
}

// rawBlock emits raw opcodes; tracker only records net stack effect.
// produce="" means no output pushed.
func (t *ECTracker) rawBlock(consume []string, produce string, fn func(emit func(StackOp))) {
	for i := len(consume) - 1; i >= 0; i-- {
		if len(t.nm) > 0 {
			t.nm = t.nm[:len(t.nm)-1]
		}
	}
	fn(t.e)
	if produce != "" {
		t.nm = append(t.nm, produce)
	}
}

// emitIf emits if/else with tracked stack effect.
// resultName="" means no result pushed.
func (t *ECTracker) emitIf(condName string, thenFn func(func(StackOp)), elseFn func(func(StackOp)), resultName string) {
	t.toTop(condName)
	// condition consumed
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
	var thenOps []StackOp
	var elseOps []StackOp
	thenFn(func(op StackOp) { thenOps = append(thenOps, op) })
	elseFn(func(op StackOp) { elseOps = append(elseOps, op) })
	t.e(StackOp{Op: "if", Then: thenOps, Else: elseOps})
	if resultName != "" {
		t.nm = append(t.nm, resultName)
	}
}

// ===========================================================================
// Field arithmetic helpers
// ===========================================================================

// ecPushFieldP pushes the field prime p onto the stack as a script number.
func ecPushFieldP(t *ECTracker, name string) {
	t.pushBigInt(name, ecFieldP)
}

// ecFieldMod reduces TOS mod p, ensuring non-negative result.
func ecFieldMod(t *ECTracker, aName, resultName string) {
	t.toTop(aName)
	ecPushFieldP(t, "_fmod_p")
	// (a % p + p) % p
	t.rawBlock([]string{aName, "_fmod_p"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_2DUP"})  // a p a p
		e(StackOp{Op: "opcode", Code: "OP_MOD"})    // a p (a%p)
		e(StackOp{Op: "rot"})                        // p (a%p) a
		e(StackOp{Op: "drop"})                       // p (a%p)
		e(StackOp{Op: "over"})                       // p (a%p) p
		e(StackOp{Op: "opcode", Code: "OP_ADD"})     // p (a%p+p)
		e(StackOp{Op: "swap"})                       // (a%p+p) p
		e(StackOp{Op: "opcode", Code: "OP_MOD"})     // ((a%p+p)%p)
	})
}

// ecFieldAdd computes (a + b) mod p.
func ecFieldAdd(t *ECTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fadd_sum", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	ecFieldMod(t, "_fadd_sum", resultName)
}

// ecFieldSub computes (a - b) mod p (non-negative).
func ecFieldSub(t *ECTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fsub_diff", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})
	ecFieldMod(t, "_fsub_diff", resultName)
}

// ecFieldMul computes (a * b) mod p.
func ecFieldMul(t *ECTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fmul_prod", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	ecFieldMod(t, "_fmul_prod", resultName)
}

// ecFieldSqr computes (a * a) mod p.
func ecFieldSqr(t *ECTracker, aName, resultName string) {
	t.copyToTop(aName, "_fsqr_copy")
	ecFieldMul(t, aName, "_fsqr_copy", resultName)
}

// ecFieldInv computes a^(p-2) mod p via square-and-multiply.
// Consumes aName from the tracker.
func ecFieldInv(t *ECTracker, aName, resultName string) {
	// p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
	// Bits 255..32: 224 bits, all 1 except bit 32 which is 0
	// Bits 31..0: 0xFFFFFC2D

	// Start: result = a (bit 255 = 1)
	t.copyToTop(aName, "_inv_r")
	// Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0 (handled below).
	for i := 0; i < 222; i++ {
		ecFieldSqr(t, "_inv_r", "_inv_r2")
		t.rename("_inv_r")
		t.copyToTop(aName, "_inv_a")
		ecFieldMul(t, "_inv_r", "_inv_a", "_inv_m")
		t.rename("_inv_r")
	}
	// Bit 32 is 0: square only (no multiply)
	ecFieldSqr(t, "_inv_r", "_inv_r2")
	t.rename("_inv_r")
	// Bits 31 down to 0 of p-2
	lowBits := uint32(ecFieldPMinus2.Uint64() & 0xffffffff)
	for i := 31; i >= 0; i-- {
		ecFieldSqr(t, "_inv_r", "_inv_r2")
		t.rename("_inv_r")
		if (lowBits>>uint(i))&1 == 1 {
			t.copyToTop(aName, "_inv_a")
			ecFieldMul(t, "_inv_r", "_inv_a", "_inv_m")
			t.rename("_inv_r")
		}
	}
	// Clean up original input and rename result
	t.toTop(aName)
	t.drop()
	t.toTop("_inv_r")
	t.rename(resultName)
}

// ===========================================================================
// Point decompose / compose
// ===========================================================================

// ecDecomposePoint decomposes a 64-byte Point into (x_num, y_num) on stack.
// Consumes pointName, produces xName and yName.
func ecDecomposePoint(t *ECTracker, pointName, xName, yName string) {
	t.toTop(pointName)
	// OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
	t.rawBlock([]string{pointName}, "", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(32)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	})
	// Manually track the two new items
	t.nm = append(t.nm, "_dp_xb")
	t.nm = append(t.nm, "_dp_yb")

	// Convert y_bytes (on top) to num
	// Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
	t.rawBlock([]string{"_dp_yb"}, yName, func(e func(StackOp)) {
		ecEmitReverse32(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Convert x_bytes to num
	t.toTop("_dp_xb")
	t.rawBlock([]string{"_dp_xb"}, xName, func(e func(StackOp)) {
		ecEmitReverse32(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Stack: [yName, xName] -- swap to standard order [xName, yName]
	t.swap()
}

// ecComposePoint composes (x_num, y_num) into a 64-byte Point.
// Consumes xName and yName, produces resultName.
func ecComposePoint(t *ECTracker, xName, yName, resultName string) {
	// Convert x to 32-byte big-endian
	// Use NUM2BIN(33) to accommodate the sign byte, then drop the last byte
	t.toTop(xName)
	t.rawBlock([]string{xName}, "_cp_xb", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(33)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		// Drop the sign byte (last byte) — split at 32, keep left
		e(StackOp{Op: "push", Value: bigIntPush(32)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "drop"})
		ecEmitReverse32(e)
	})

	// Convert y to 32-byte big-endian
	t.toTop(yName)
	t.rawBlock([]string{yName}, "_cp_yb", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(33)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		e(StackOp{Op: "push", Value: bigIntPush(32)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "drop"})
		ecEmitReverse32(e)
	})

	// Cat: x_be || y_be (x is below y after the two toTop calls)
	t.toTop("_cp_xb")
	t.toTop("_cp_yb")
	t.rawBlock([]string{"_cp_xb", "_cp_yb"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
	})
}

// ecEmitReverse32 emits inline byte reversal for a 32-byte value on TOS.
func ecEmitReverse32(e func(StackOp)) {
	// Push empty accumulator, swap with data
	e(StackOp{Op: "opcode", Code: "OP_0"})
	e(StackOp{Op: "swap"})
	// 32 iterations: peel first byte, prepend to accumulator
	for i := 0; i < 32; i++ {
		// Stack: [accum, remaining]
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		// Stack: [accum, byte0, rest]
		e(StackOp{Op: "rot"})
		// Stack: [byte0, rest, accum]
		e(StackOp{Op: "rot"})
		// Stack: [rest, accum, byte0]
		e(StackOp{Op: "swap"})
		// Stack: [rest, byte0, accum]
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		// Stack: [rest, byte0||accum]
		e(StackOp{Op: "swap"})
		// Stack: [byte0||accum, rest]
	}
	// Stack: [reversed, empty]
	e(StackOp{Op: "drop"})
}

// ===========================================================================
// Affine point addition (for ecAdd)
// ===========================================================================

// ecAffineAdd performs affine point addition.
// Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
func ecAffineAdd(t *ECTracker) {
	// s_num = qy - py
	t.copyToTop("qy", "_qy1")
	t.copyToTop("py", "_py1")
	ecFieldSub(t, "_qy1", "_py1", "_s_num")

	// s_den = qx - px
	t.copyToTop("qx", "_qx1")
	t.copyToTop("px", "_px1")
	ecFieldSub(t, "_qx1", "_px1", "_s_den")

	// s = s_num / s_den mod p
	ecFieldInv(t, "_s_den", "_s_den_inv")
	ecFieldMul(t, "_s_num", "_s_den_inv", "_s")

	// rx = s^2 - px - qx mod p
	t.copyToTop("_s", "_s_keep")
	ecFieldSqr(t, "_s", "_s2")
	t.copyToTop("px", "_px2")
	ecFieldSub(t, "_s2", "_px2", "_rx1")
	t.copyToTop("qx", "_qx2")
	ecFieldSub(t, "_rx1", "_qx2", "rx")

	// ry = s * (px - rx) - py mod p
	t.copyToTop("px", "_px3")
	t.copyToTop("rx", "_rx2")
	ecFieldSub(t, "_px3", "_rx2", "_px_rx")
	ecFieldMul(t, "_s_keep", "_px_rx", "_s_px_rx")
	t.copyToTop("py", "_py2")
	ecFieldSub(t, "_s_px_rx", "_py2", "ry")

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
// Jacobian point operations (for ecMul)
// ===========================================================================

// ecJacobianDouble performs Jacobian point doubling (a=0 for secp256k1).
// Expects jx, jy, jz on tracker. Replaces with updated values.
func ecJacobianDouble(t *ECTracker) {
	// Save copies of jx, jy, jz for later use
	t.copyToTop("jy", "_jy_save")
	t.copyToTop("jx", "_jx_save")
	t.copyToTop("jz", "_jz_save")

	// A = jy^2
	ecFieldSqr(t, "jy", "_A")

	// B = 4 * jx * A
	t.copyToTop("_A", "_A_save")
	ecFieldMul(t, "jx", "_A", "_xA")
	t.pushInt("_four", 4)
	ecFieldMul(t, "_xA", "_four", "_B")

	// C = 8 * A^2
	ecFieldSqr(t, "_A_save", "_A2")
	t.pushInt("_eight", 8)
	ecFieldMul(t, "_A2", "_eight", "_C")

	// D = 3 * X^2
	ecFieldSqr(t, "_jx_save", "_x2")
	t.pushInt("_three", 3)
	ecFieldMul(t, "_x2", "_three", "_D")

	// nx = D^2 - 2*B
	t.copyToTop("_D", "_D_save")
	t.copyToTop("_B", "_B_save")
	ecFieldSqr(t, "_D", "_D2")
	t.copyToTop("_B", "_B1")
	t.pushInt("_two1", 2)
	ecFieldMul(t, "_B1", "_two1", "_2B")
	ecFieldSub(t, "_D2", "_2B", "_nx")

	// ny = D*(B - nx) - C
	t.copyToTop("_nx", "_nx_copy")
	ecFieldSub(t, "_B_save", "_nx_copy", "_B_nx")
	ecFieldMul(t, "_D_save", "_B_nx", "_D_B_nx")
	ecFieldSub(t, "_D_B_nx", "_C", "_ny")

	// nz = 2 * Y * Z
	ecFieldMul(t, "_jy_save", "_jz_save", "_yz")
	t.pushInt("_two2", 2)
	ecFieldMul(t, "_yz", "_two2", "_nz")

	// Clean up leftovers: _B and old jz (only copied, never consumed)
	t.toTop("_B")
	t.drop()
	t.toTop("jz")
	t.drop()
	t.toTop("_nx")
	t.rename("jx")
	t.toTop("_ny")
	t.rename("jy")
	t.toTop("_nz")
	t.rename("jz")
}

// ecJacobianToAffine converts Jacobian to affine coordinates.
// Consumes jx, jy, jz; produces rxName, ryName.
func ecJacobianToAffine(t *ECTracker, rxName, ryName string) {
	ecFieldInv(t, "jz", "_zinv")
	t.copyToTop("_zinv", "_zinv_keep")
	ecFieldSqr(t, "_zinv", "_zinv2")
	t.copyToTop("_zinv2", "_zinv2_keep")
	ecFieldMul(t, "_zinv_keep", "_zinv2", "_zinv3")
	ecFieldMul(t, "jx", "_zinv2_keep", rxName)
	ecFieldMul(t, "jy", "_zinv3", ryName)
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

// ecBuildJacobianAddAffineInline builds Jacobian mixed-add ops for use inside OP_IF.
// Uses an inner ECTracker to leverage field arithmetic helpers.
//
// Stack layout: [..., ax, ay, _k, jx, jy, jz]
// After:        [..., ax, ay, _k, jx', jy', jz']
func ecBuildJacobianAddAffineInline(e func(StackOp), t *ECTracker) {
	// Create inner tracker with cloned stack state
	initNm := make([]string, len(t.nm))
	copy(initNm, t.nm)
	it := NewECTracker(initNm, e)

	// Save copies of values that get consumed but are needed later
	it.copyToTop("jz", "_jz_for_z1cu")  // consumed by Z1sq, needed for Z1cu
	it.copyToTop("jz", "_jz_for_z3")    // needed for Z3
	it.copyToTop("jy", "_jy_for_y3")    // consumed by R, needed for Y3
	it.copyToTop("jx", "_jx_for_u1h2")  // consumed by H, needed for U1H2

	// Z1sq = jz^2
	ecFieldSqr(it, "jz", "_Z1sq")

	// Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
	it.copyToTop("_Z1sq", "_Z1sq_for_u2")
	ecFieldMul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu")

	// U2 = ax * Z1sq_for_u2
	it.copyToTop("ax", "_ax_c")
	ecFieldMul(it, "_ax_c", "_Z1sq_for_u2", "_U2")

	// S2 = ay * Z1cu
	it.copyToTop("ay", "_ay_c")
	ecFieldMul(it, "_ay_c", "_Z1cu", "_S2")

	// H = U2 - jx
	ecFieldSub(it, "_U2", "jx", "_H")

	// R = S2 - jy
	ecFieldSub(it, "_S2", "jy", "_R")

	// Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
	it.copyToTop("_H", "_H_for_h3")
	it.copyToTop("_H", "_H_for_z3")

	// H2 = H^2
	ecFieldSqr(it, "_H", "_H2")

	// Save H2 for U1H2
	it.copyToTop("_H2", "_H2_for_u1h2")

	// H3 = H_for_h3 * H2
	ecFieldMul(it, "_H_for_h3", "_H2", "_H3")

	// U1H2 = _jx_for_u1h2 * H2_for_u1h2
	ecFieldMul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2")

	// Save R, U1H2, H3 for Y3 computation
	it.copyToTop("_R", "_R_for_y3")
	it.copyToTop("_U1H2", "_U1H2_for_y3")
	it.copyToTop("_H3", "_H3_for_y3")

	// X3 = R^2 - H3 - 2*U1H2
	ecFieldSqr(it, "_R", "_R2")
	ecFieldSub(it, "_R2", "_H3", "_x3_tmp")
	it.pushInt("_two", 2)
	ecFieldMul(it, "_U1H2", "_two", "_2U1H2")
	ecFieldSub(it, "_x3_tmp", "_2U1H2", "_X3")

	// Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
	it.copyToTop("_X3", "_X3_c")
	ecFieldSub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x")
	ecFieldMul(it, "_R_for_y3", "_u_minus_x", "_r_tmp")
	ecFieldMul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3")
	ecFieldSub(it, "_r_tmp", "_jy_h3", "_Y3")

	// Z3 = _jz_for_z3 * _H_for_z3
	ecFieldMul(it, "_jz_for_z3", "_H_for_z3", "_Z3")

	// Rename results to jx/jy/jz
	it.toTop("_X3")
	it.rename("jx")
	it.toTop("_Y3")
	it.rename("jy")
	it.toTop("_Z3")
	it.rename("jz")
}

// ===========================================================================
// Public entry points (called from stack lowerer)
// ===========================================================================

// EmitEcAdd adds two points.
// Stack in: [point_a, point_b] (b on top)
// Stack out: [result_point]
func EmitEcAdd(emit func(StackOp)) {
	t := NewECTracker([]string{"_pa", "_pb"}, emit)
	ecDecomposePoint(t, "_pa", "px", "py")
	ecDecomposePoint(t, "_pb", "qx", "qy")
	ecAffineAdd(t)
	ecComposePoint(t, "rx", "ry", "_result")
}

// EmitEcMul performs scalar multiplication P * k.
// Stack in: [point, scalar] (scalar on top)
// Stack out: [result_point]
//
// Uses 256-iteration double-and-add with Jacobian coordinates.
func EmitEcMul(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt", "_k"}, emit)
	// Decompose to affine base point
	ecDecomposePoint(t, "_pt", "ax", "ay")

	// k' = k + 3n: guarantees bit 257 is set.
	// k ∈ [1, n-1], so k+3n ∈ [3n+1, 4n-1]. Since 3n > 2^257, bit 257
	// is always 1. Adding 3n (≡ 0 mod n) preserves the EC point: k*G = (k+3n)*G.
	curveN, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	t.toTop("_k")
	t.pushBigInt("_n", curveN)
	t.rawBlock([]string{"_k", "_n"}, "_kn", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_n2", curveN)
	t.rawBlock([]string{"_kn", "_n2"}, "_kn2", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_n3", curveN)
	t.rawBlock([]string{"_kn2", "_n3"}, "_kn3", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.rename("_k")

	// Init accumulator = P (bit 257 of k+3n is always 1)
	t.copyToTop("ax", "jx")
	t.copyToTop("ay", "jy")
	t.pushInt("jz", 1)

	// 257 iterations: bits 256 down to 0
	for bit := 256; bit >= 0; bit-- {
		// Double accumulator
		ecJacobianDouble(t)

		// Extract bit: (k >> bit) & 1, using OP_DIV for right-shift
		t.copyToTop("_k", "_k_copy")
		if bit > 0 {
			divisor := new(big.Int).Lsh(big.NewInt(1), uint(bit))
			t.pushBigInt("_div", divisor)
			t.rawBlock([]string{"_k_copy", "_div"}, "_shifted", func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_DIV"})
			})
		} else {
			t.rename("_shifted")
		}
		t.pushInt("_two", 2)
		t.rawBlock([]string{"_shifted", "_two"}, "_bit", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})

		// Move _bit to TOS and remove from tracker BEFORE generating add ops,
		// because OP_IF consumes _bit and the add ops run with _bit already gone.
		t.toTop("_bit")
		t.nm = t.nm[:len(t.nm)-1] // _bit consumed by IF
		var addOps []StackOp
		addEmit := func(op StackOp) { addOps = append(addOps, op) }
		ecBuildJacobianAddAffineInline(addEmit, t)
		emit(StackOp{Op: "if", Then: addOps, Else: []StackOp{}})
	}

	// Convert Jacobian to affine
	ecJacobianToAffine(t, "_rx", "_ry")

	// Clean up base point and scalar
	t.toTop("ax")
	t.drop()
	t.toTop("ay")
	t.drop()
	t.toTop("_k")
	t.drop()

	// Compose result
	ecComposePoint(t, "_rx", "_ry", "_result")
}

// EmitEcMulGen performs scalar multiplication G * k.
// Stack in: [scalar]
// Stack out: [result_point]
func EmitEcMulGen(emit func(StackOp)) {
	// Push generator point as 64-byte blob, then delegate to ecMul
	gPoint := make([]byte, 64)
	copy(gPoint[0:32], bigintToBytes32(ecGenX))
	copy(gPoint[32:64], bigintToBytes32(ecGenY))
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: gPoint}})
	emit(StackOp{Op: "swap"}) // [point, scalar]
	EmitEcMul(emit)
}

// EmitEcNegate negates a point (x, p - y).
// Stack in: [point]
// Stack out: [negated_point]
func EmitEcNegate(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt"}, emit)
	ecDecomposePoint(t, "_pt", "_nx", "_ny")
	ecPushFieldP(t, "_fp")
	ecFieldSub(t, "_fp", "_ny", "_neg_y")
	ecComposePoint(t, "_nx", "_neg_y", "_result")
}

// EmitEcOnCurve checks if point is on secp256k1 (y^2 = x^3 + 7 mod p).
// Stack in: [point]
// Stack out: [boolean]
func EmitEcOnCurve(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt"}, emit)
	ecDecomposePoint(t, "_pt", "_x", "_y")

	// lhs = y^2
	ecFieldSqr(t, "_y", "_y2")

	// rhs = x^3 + 7
	t.copyToTop("_x", "_x_copy")
	ecFieldSqr(t, "_x", "_x2")
	ecFieldMul(t, "_x2", "_x_copy", "_x3")
	t.pushInt("_seven", 7)
	ecFieldAdd(t, "_x3", "_seven", "_rhs")

	// Compare
	t.toTop("_y2")
	t.toTop("_rhs")
	t.rawBlock([]string{"_y2", "_rhs"}, "_result", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	})
}

// EmitEcModReduce computes ((value % mod) + mod) % mod.
// Stack in: [value, mod]
// Stack out: [result]
func EmitEcModReduce(emit func(StackOp)) {
	emit(StackOp{Op: "opcode", Code: "OP_2DUP"})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	emit(StackOp{Op: "rot"})
	emit(StackOp{Op: "drop"})
	emit(StackOp{Op: "over"})
	emit(StackOp{Op: "opcode", Code: "OP_ADD"})
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
}

// EmitEcEncodeCompressed encodes a point as a 33-byte compressed pubkey.
// Stack in: [point (64 bytes)]
// Stack out: [compressed (33 bytes)]
func EmitEcEncodeCompressed(emit func(StackOp)) {
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

// EmitEcMakePoint converts (x: bigint, y: bigint) to a 64-byte Point.
// Stack in: [x_num, y_num] (y on top)
// Stack out: [point_bytes (64 bytes)]
func EmitEcMakePoint(emit func(StackOp)) {
	// Convert y to 32 bytes big-endian (NUM2BIN(33) to handle sign byte, then take first 32)
	emit(StackOp{Op: "push", Value: bigIntPush(33)})
	emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "drop"})
	ecEmitReverse32(emit)
	// Stack: [x_num, y_be]
	emit(StackOp{Op: "swap"})
	// Stack: [y_be, x_num]
	emit(StackOp{Op: "push", Value: bigIntPush(33)})
	emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "drop"})
	ecEmitReverse32(emit)
	// Stack: [y_be, x_be]
	emit(StackOp{Op: "swap"})
	// Stack: [x_be, y_be]
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
}

// EmitEcPointX extracts the x-coordinate from a Point.
// Stack in: [point (64 bytes)]
// Stack out: [x as bigint]
func EmitEcPointX(emit func(StackOp)) {
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "drop"})
	ecEmitReverse32(emit)
	// Append 0x00 sign byte to ensure unsigned interpretation
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
}

// EmitEcPointY extracts the y-coordinate from a Point.
// Stack in: [point (64 bytes)]
// Stack out: [y as bigint]
func EmitEcPointY(emit func(StackOp)) {
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"})
	ecEmitReverse32(emit)
	// Append 0x00 sign byte to ensure unsigned interpretation
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
}
