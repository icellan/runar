// Baby Bear field arithmetic codegen — Baby Bear prime field operations for Bitcoin Script.
//
// Follows the ec.go pattern: self-contained module imported by stack.go.
// Uses a BBTracker for named stack state tracking.
//
// Baby Bear prime: p = 2^31 - 2^27 + 1 = 2013265921
// Used by SP1 STARK proofs (FRI verification).
//
// All values fit in a single BSV script number (31-bit prime).
// No multi-limb arithmetic needed.
package codegen

import (
	"fmt"
	"math/big"
)

// ===========================================================================
// Constants
// ===========================================================================

// bbFieldP is the Baby Bear field prime p = 2^31 - 2^27 + 1 = 2013265921.
var bbFieldP = big.NewInt(2013265921)

// bbFieldPMinus2 is p - 2, used for Fermat's little theorem modular inverse.
var bbFieldPMinus2 = big.NewInt(2013265919)

// ===========================================================================
// BBTracker — named stack state tracker (mirrors ECTracker)
// ===========================================================================

// BBTracker tracks named stack positions and emits StackOps for Baby Bear codegen.
type BBTracker struct {
	nm []string // stack names ("" for anonymous)
	e  func(StackOp)
}

// NewBBTracker creates a new tracker with initial named stack slots.
func NewBBTracker(init []string, emit func(StackOp)) *BBTracker {
	nm := make([]string, len(init))
	copy(nm, init)
	return &BBTracker{nm: nm, e: emit}
}

func (t *BBTracker) findDepth(name string) int {
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == name {
			return len(t.nm) - 1 - i
		}
	}
	panic(fmt.Sprintf("BBTracker: '%s' not on stack %v", name, t.nm))
}

func (t *BBTracker) pushInt(n string, v int64) {
	t.e(StackOp{Op: "push", Value: bigIntPush(v)})
	t.nm = append(t.nm, n)
}

func (t *BBTracker) pushBigInt(n string, v *big.Int) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(v)}})
	t.nm = append(t.nm, n)
}

func (t *BBTracker) dup(n string) {
	t.e(StackOp{Op: "dup"})
	t.nm = append(t.nm, n)
}

func (t *BBTracker) drop() {
	t.e(StackOp{Op: "drop"})
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *BBTracker) nip() {
	t.e(StackOp{Op: "nip"})
	L := len(t.nm)
	if L >= 2 {
		t.nm = append(t.nm[:L-2], t.nm[L-1])
	}
}

func (t *BBTracker) over(n string) {
	t.e(StackOp{Op: "over"})
	t.nm = append(t.nm, n)
}

func (t *BBTracker) swap() {
	t.e(StackOp{Op: "swap"})
	L := len(t.nm)
	if L >= 2 {
		t.nm[L-1], t.nm[L-2] = t.nm[L-2], t.nm[L-1]
	}
}

func (t *BBTracker) rot() {
	t.e(StackOp{Op: "rot"})
	L := len(t.nm)
	if L >= 3 {
		r := t.nm[L-3]
		t.nm = append(t.nm[:L-3], t.nm[L-2:]...)
		t.nm = append(t.nm, r)
	}
}

func (t *BBTracker) op(code string) {
	t.e(StackOp{Op: "opcode", Code: code})
}

func (t *BBTracker) roll(d int) {
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

func (t *BBTracker) pick(d int, n string) {
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

func (t *BBTracker) toTop(name string) {
	t.roll(t.findDepth(name))
}

func (t *BBTracker) copyToTop(name, n string) {
	t.pick(t.findDepth(name), n)
}

func (t *BBTracker) rename(n string) {
	if len(t.nm) > 0 {
		t.nm[len(t.nm)-1] = n
	}
}

// rawBlock emits raw opcodes; tracker only records net stack effect.
// produce="" means no output pushed.
func (t *BBTracker) rawBlock(consume []string, produce string, fn func(emit func(StackOp))) {
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

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

// bbFieldMod reduces value mod p, ensuring non-negative result.
// Pattern: (a % p + p) % p — handles negative values from sub.
func bbFieldMod(t *BBTracker, aName, resultName string) {
	t.toTop(aName)
	t.rawBlock([]string{aName}, resultName, func(e func(StackOp)) {
		// (a % p + p) % p
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bbFieldP)}})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bbFieldP)}})
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bbFieldP)}})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// bbFieldAdd computes (a + b) mod p.
func bbFieldAdd(t *BBTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_bb_add", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	// Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
	t.toTop("_bb_add")
	t.rawBlock([]string{"_bb_add"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bbFieldP)}})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// bbFieldSub computes (a - b) mod p (non-negative).
func bbFieldSub(t *BBTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_bb_diff", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})
	// Difference can be negative, need full mod-reduce
	bbFieldMod(t, "_bb_diff", resultName)
}

// bbFieldMul computes (a * b) mod p.
func bbFieldMul(t *BBTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_bb_prod", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	// Product of two non-negative values is non-negative, simple OP_MOD
	t.toTop("_bb_prod")
	t.rawBlock([]string{"_bb_prod"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bbFieldP)}})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// bbFieldSqr computes (a * a) mod p.
func bbFieldSqr(t *BBTracker, aName, resultName string) {
	t.copyToTop(aName, "_bb_sqr_copy")
	bbFieldMul(t, aName, "_bb_sqr_copy", resultName)
}

// bbFieldInv computes a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
// p-2 = 2013265919 = 0b111_0111_1111_1111_1111_1111_1111_1111
// 31 bits, popcount 28.
// ~30 squarings + ~27 multiplies = ~57 compound operations.
func bbFieldInv(t *BBTracker, aName, resultName string) {
	// Binary representation of p-2 = 2013265919:
	// Bit 30 (MSB): 1
	// Bits 29..28: 11
	// Bit 27: 0
	// Bits 26..0: all 1's (27 ones)

	// Start: result = a (for MSB bit 30 = 1)
	t.copyToTop(aName, "_inv_r")

	// Process bits 29 down to 0 (30 bits)
	pMinus2 := int(bbFieldPMinus2.Int64())
	for i := 29; i >= 0; i-- {
		// Always square
		bbFieldSqr(t, "_inv_r", "_inv_r2")
		t.rename("_inv_r")

		// Multiply if bit is set
		if (pMinus2>>uint(i))&1 == 1 {
			t.copyToTop(aName, "_inv_a")
			bbFieldMul(t, "_inv_r", "_inv_a", "_inv_m")
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
// Public emit functions — entry points called from stack.go
// ===========================================================================

// EmitBBFieldAdd emits Baby Bear field addition.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a + b) mod p]
func EmitBBFieldAdd(emit func(StackOp)) {
	t := NewBBTracker([]string{"a", "b"}, emit)
	bbFieldAdd(t, "a", "b", "result")
	// Stack should now be: [result]
}

// EmitBBFieldSub emits Baby Bear field subtraction.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a - b) mod p]
func EmitBBFieldSub(emit func(StackOp)) {
	t := NewBBTracker([]string{"a", "b"}, emit)
	bbFieldSub(t, "a", "b", "result")
}

// EmitBBFieldMul emits Baby Bear field multiplication.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a * b) mod p]
func EmitBBFieldMul(emit func(StackOp)) {
	t := NewBBTracker([]string{"a", "b"}, emit)
	bbFieldMul(t, "a", "b", "result")
}

// EmitBBFieldInv emits Baby Bear field multiplicative inverse.
// Stack in: [..., a]
// Stack out: [..., a^(p-2) mod p]
func EmitBBFieldInv(emit func(StackOp)) {
	t := NewBBTracker([]string{"a"}, emit)
	bbFieldInv(t, "a", "result")
}

// ===========================================================================
// Quartic extension field (ext4) operations
// ===========================================================================
//
// Extension field F_p^4 over Baby Bear using irreducible x^4 - W where W = 11.
// Elements are (a0, a1, a2, a3) representing a0 + a1*x + a2*x^2 + a3*x^3.
//
// Multiplication:
//   r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
//   r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
//   r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
//   r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
//
// Inverse (tower of quadratic extensions):
//   norm0 = a0^2 + W*a2^2 - 2*W*a1*a3
//   norm1 = 2*a0*a2 - a1^2 - W*a3^2
//   det   = norm0^2 - W*norm1^2
//   scalar = inv(det)
//   invN0 = norm0 * scalar
//   invN1 = -norm1 * scalar
//   r0 = a0*invN0 + W*a2*invN1
//   r1 = -(a1*invN0 + W*a3*invN1)
//   r2 = a0*invN1 + a2*invN0
//   r3 = -(a1*invN1 + a3*invN0)

// bbFieldW is the quadratic non-residue W = 11 used for ext4.
var bbFieldW int64 = 11

// bbFieldMulConst computes (a * c) mod p where c is a small constant.
func bbFieldMulConst(t *BBTracker, aName string, c int64, resultName string) {
	t.toTop(aName)
	t.rawBlock([]string{aName}, "_bb_mc", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(c)})
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	t.toTop("_bb_mc")
	t.rawBlock([]string{"_bb_mc"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bbFieldP)}})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// ---------------------------------------------------------------------------
// Ext4 multiplication component function (matches TS emitExt4MulComponent)
// ---------------------------------------------------------------------------

func bbExt4MulComponent(emit func(StackOp), component int) {
	t := NewBBTracker([]string{"a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"}, emit)

	switch component {
	case 0:
		// r0 = a0*b0 + 11*(a1*b3 + a2*b2 + a3*b1)
		t.copyToTop("a0", "_a0"); t.copyToTop("b0", "_b0")
		bbFieldMul(t, "_a0", "_b0", "_t0")     // a0*b0
		t.copyToTop("a1", "_a1"); t.copyToTop("b3", "_b3")
		bbFieldMul(t, "_a1", "_b3", "_t1")     // a1*b3
		t.copyToTop("a2", "_a2"); t.copyToTop("b2", "_b2")
		bbFieldMul(t, "_a2", "_b2", "_t2")     // a2*b2
		bbFieldAdd(t, "_t1", "_t2", "_t12")    // a1*b3 + a2*b2
		t.copyToTop("a3", "_a3"); t.copyToTop("b1", "_b1")
		bbFieldMul(t, "_a3", "_b1", "_t3")     // a3*b1
		bbFieldAdd(t, "_t12", "_t3", "_cross") // a1*b3 + a2*b2 + a3*b1
		bbFieldMulConst(t, "_cross", bbFieldW, "_wcross") // W * cross
		bbFieldAdd(t, "_t0", "_wcross", "_r")  // a0*b0 + W*cross

	case 1:
		// r1 = a0*b1 + a1*b0 + 11*(a2*b3 + a3*b2)
		t.copyToTop("a0", "_a0"); t.copyToTop("b1", "_b1")
		bbFieldMul(t, "_a0", "_b1", "_t0")     // a0*b1
		t.copyToTop("a1", "_a1"); t.copyToTop("b0", "_b0")
		bbFieldMul(t, "_a1", "_b0", "_t1")     // a1*b0
		bbFieldAdd(t, "_t0", "_t1", "_direct") // a0*b1 + a1*b0
		t.copyToTop("a2", "_a2"); t.copyToTop("b3", "_b3")
		bbFieldMul(t, "_a2", "_b3", "_t2")     // a2*b3
		t.copyToTop("a3", "_a3"); t.copyToTop("b2", "_b2")
		bbFieldMul(t, "_a3", "_b2", "_t3")     // a3*b2
		bbFieldAdd(t, "_t2", "_t3", "_cross")  // a2*b3 + a3*b2
		bbFieldMulConst(t, "_cross", bbFieldW, "_wcross") // W * cross
		bbFieldAdd(t, "_direct", "_wcross", "_r")

	case 2:
		// r2 = a0*b2 + a1*b1 + a2*b0 + 11*(a3*b3)
		t.copyToTop("a0", "_a0"); t.copyToTop("b2", "_b2")
		bbFieldMul(t, "_a0", "_b2", "_t0")     // a0*b2
		t.copyToTop("a1", "_a1"); t.copyToTop("b1", "_b1")
		bbFieldMul(t, "_a1", "_b1", "_t1")     // a1*b1
		bbFieldAdd(t, "_t0", "_t1", "_sum01")
		t.copyToTop("a2", "_a2"); t.copyToTop("b0", "_b0")
		bbFieldMul(t, "_a2", "_b0", "_t2")     // a2*b0
		bbFieldAdd(t, "_sum01", "_t2", "_direct")
		t.copyToTop("a3", "_a3"); t.copyToTop("b3", "_b3")
		bbFieldMul(t, "_a3", "_b3", "_t3")     // a3*b3
		bbFieldMulConst(t, "_t3", bbFieldW, "_wcross") // W * a3*b3
		bbFieldAdd(t, "_direct", "_wcross", "_r")

	case 3:
		// r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
		t.copyToTop("a0", "_a0"); t.copyToTop("b3", "_b3")
		bbFieldMul(t, "_a0", "_b3", "_t0")     // a0*b3
		t.copyToTop("a1", "_a1"); t.copyToTop("b2", "_b2")
		bbFieldMul(t, "_a1", "_b2", "_t1")     // a1*b2
		bbFieldAdd(t, "_t0", "_t1", "_sum01")
		t.copyToTop("a2", "_a2"); t.copyToTop("b1", "_b1")
		bbFieldMul(t, "_a2", "_b1", "_t2")     // a2*b1
		bbFieldAdd(t, "_sum01", "_t2", "_sum012")
		t.copyToTop("a3", "_a3"); t.copyToTop("b0", "_b0")
		bbFieldMul(t, "_a3", "_b0", "_t3")     // a3*b0
		bbFieldAdd(t, "_sum012", "_t3", "_r")

	default:
		panic(fmt.Sprintf("Invalid ext4 component: %d", component))
	}

	// Clean up: drop the 8 input values, keep only _r
	for _, name := range []string{"a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"} {
		t.toTop(name)
		t.drop()
	}
	t.toTop("_r")
	t.rename("result")
}

// EmitBBExt4Mul0 computes r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1) mod p.
func EmitBBExt4Mul0(emit func(StackOp)) { bbExt4MulComponent(emit, 0) }

// EmitBBExt4Mul1 computes r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2) mod p.
func EmitBBExt4Mul1(emit func(StackOp)) { bbExt4MulComponent(emit, 1) }

// EmitBBExt4Mul2 computes r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3) mod p.
func EmitBBExt4Mul2(emit func(StackOp)) { bbExt4MulComponent(emit, 2) }

// EmitBBExt4Mul3 computes r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 mod p.
func EmitBBExt4Mul3(emit func(StackOp)) { bbExt4MulComponent(emit, 3) }

// ---------------------------------------------------------------------------
// Ext4 inverse component function (matches TS emitExt4InvComponent)
// ---------------------------------------------------------------------------

func bbExt4InvComponent(emit func(StackOp), component int) {
	t := NewBBTracker([]string{"a0", "a1", "a2", "a3"}, emit)

	// Step 1: Compute norm_0 = a0² + W*a2² - 2*W*a1*a3
	t.copyToTop("a0", "_a0c")
	bbFieldSqr(t, "_a0c", "_a0sq")           // a0²
	t.copyToTop("a2", "_a2c")
	bbFieldSqr(t, "_a2c", "_a2sq")           // a2²
	bbFieldMulConst(t, "_a2sq", bbFieldW, "_wa2sq") // W*a2²
	bbFieldAdd(t, "_a0sq", "_wa2sq", "_n0a")    // a0² + W*a2²
	t.copyToTop("a1", "_a1c")
	t.copyToTop("a3", "_a3c")
	bbFieldMul(t, "_a1c", "_a3c", "_a1a3")   // a1*a3
	bbFieldMulConst(t, "_a1a3", 2*bbFieldW, "_2wa1a3") // 2*W*a1*a3
	bbFieldSub(t, "_n0a", "_2wa1a3", "_norm0") // norm_0

	// Step 2: Compute norm_1 = 2*a0*a2 - a1² - W*a3²
	t.copyToTop("a0", "_a0d")
	t.copyToTop("a2", "_a2d")
	bbFieldMul(t, "_a0d", "_a2d", "_a0a2")   // a0*a2
	bbFieldMulConst(t, "_a0a2", 2, "_2a0a2") // 2*a0*a2
	t.copyToTop("a1", "_a1d")
	bbFieldSqr(t, "_a1d", "_a1sq")           // a1²
	bbFieldSub(t, "_2a0a2", "_a1sq", "_n1a") // 2*a0*a2 - a1²
	t.copyToTop("a3", "_a3d")
	bbFieldSqr(t, "_a3d", "_a3sq")           // a3²
	bbFieldMulConst(t, "_a3sq", bbFieldW, "_wa3sq") // W*a3²
	bbFieldSub(t, "_n1a", "_wa3sq", "_norm1") // norm_1

	// Step 3: Quadratic inverse: scalar = (norm_0² - W*norm_1²)^(-1)
	t.copyToTop("_norm0", "_n0copy")
	bbFieldSqr(t, "_n0copy", "_n0sq")        // norm_0²
	t.copyToTop("_norm1", "_n1copy")
	bbFieldSqr(t, "_n1copy", "_n1sq")        // norm_1²
	bbFieldMulConst(t, "_n1sq", bbFieldW, "_wn1sq") // W*norm_1²
	bbFieldSub(t, "_n0sq", "_wn1sq", "_det") // norm_0² - W*norm_1²
	bbFieldInv(t, "_det", "_scalar")         // scalar = det^(-1)

	// Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
	t.copyToTop("_scalar", "_sc0")
	bbFieldMul(t, "_norm0", "_sc0", "_inv_n0") // inv_n0 = norm_0 * scalar

	// -norm_1 = (p - norm_1) mod p
	t.copyToTop("_norm1", "_neg_n1_pre")
	t.pushBigInt("_pval", bbFieldP)
	t.toTop("_neg_n1_pre")
	t.rawBlock([]string{"_pval", "_neg_n1_pre"}, "_neg_n1_sub", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})
	bbFieldMod(t, "_neg_n1_sub", "_neg_norm1")
	bbFieldMul(t, "_neg_norm1", "_scalar", "_inv_n1")

	// Step 5: Compute result components using quad_mul
	switch component {
	case 0:
		// r0 = out_even[0] = a0*inv_n0 + W*a2*inv_n1
		t.copyToTop("a0", "_ea0")
		t.copyToTop("_inv_n0", "_ein0")
		bbFieldMul(t, "_ea0", "_ein0", "_ep0")   // a0*inv_n0
		t.copyToTop("a2", "_ea2")
		t.copyToTop("_inv_n1", "_ein1")
		bbFieldMul(t, "_ea2", "_ein1", "_ep1")   // a2*inv_n1
		bbFieldMulConst(t, "_ep1", bbFieldW, "_wep1") // W*a2*inv_n1
		bbFieldAdd(t, "_ep0", "_wep1", "_r")

	case 1:
		// r1 = -odd_part[0] where odd_part = quad_mul((a1,a3), (inv_n0,inv_n1))
		// odd0 = a1*inv_n0 + W*a3*inv_n1
		// r1 = -odd0 = (0 - odd0) mod p
		t.copyToTop("a1", "_oa1")
		t.copyToTop("_inv_n0", "_oin0")
		bbFieldMul(t, "_oa1", "_oin0", "_op0")   // a1*inv_n0
		t.copyToTop("a3", "_oa3")
		t.copyToTop("_inv_n1", "_oin1")
		bbFieldMul(t, "_oa3", "_oin1", "_op1")   // a3*inv_n1
		bbFieldMulConst(t, "_op1", bbFieldW, "_wop1") // W*a3*inv_n1
		bbFieldAdd(t, "_op0", "_wop1", "_odd0")
		// Negate: r = (0 - odd0) mod p
		t.pushInt("_zero1", 0)
		bbFieldSub(t, "_zero1", "_odd0", "_r")

	case 2:
		// r2 = out_even[1] = a0*inv_n1 + a2*inv_n0
		t.copyToTop("a0", "_ea0")
		t.copyToTop("_inv_n1", "_ein1")
		bbFieldMul(t, "_ea0", "_ein1", "_ep0")   // a0*inv_n1
		t.copyToTop("a2", "_ea2")
		t.copyToTop("_inv_n0", "_ein0")
		bbFieldMul(t, "_ea2", "_ein0", "_ep1")   // a2*inv_n0
		bbFieldAdd(t, "_ep0", "_ep1", "_r")

	case 3:
		// r3 = -odd_part[1] where odd1 = a1*inv_n1 + a3*inv_n0
		// r3 = -odd1 = (0 - odd1) mod p
		t.copyToTop("a1", "_oa1")
		t.copyToTop("_inv_n1", "_oin1")
		bbFieldMul(t, "_oa1", "_oin1", "_op0")   // a1*inv_n1
		t.copyToTop("a3", "_oa3")
		t.copyToTop("_inv_n0", "_oin0")
		bbFieldMul(t, "_oa3", "_oin0", "_op1")   // a3*inv_n0
		bbFieldAdd(t, "_op0", "_op1", "_odd1")
		// Negate: r = (0 - odd1) mod p
		t.pushInt("_zero3", 0)
		bbFieldSub(t, "_zero3", "_odd1", "_r")

	default:
		panic(fmt.Sprintf("Invalid ext4 component: %d", component))
	}

	// Clean up: drop all intermediate and input values, keep only _r
	remaining := make([]string, 0)
	for _, n := range t.nm {
		if n != "" && n != "_r" {
			remaining = append(remaining, n)
		}
	}
	for _, name := range remaining {
		t.toTop(name)
		t.drop()
	}
	t.toTop("_r")
	t.rename("result")
}

// EmitBBExt4Inv0 computes r0 = a0*invN0 + W*a2*invN1.
func EmitBBExt4Inv0(emit func(StackOp)) { bbExt4InvComponent(emit, 0) }

// EmitBBExt4Inv1 computes r1 = -(a1*invN0 + W*a3*invN1).
func EmitBBExt4Inv1(emit func(StackOp)) { bbExt4InvComponent(emit, 1) }

// EmitBBExt4Inv2 computes r2 = a0*invN1 + a2*invN0.
func EmitBBExt4Inv2(emit func(StackOp)) { bbExt4InvComponent(emit, 2) }

// EmitBBExt4Inv3 computes r3 = -(a1*invN1 + a3*invN0).
func EmitBBExt4Inv3(emit func(StackOp)) { bbExt4InvComponent(emit, 3) }
