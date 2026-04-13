// KoalaBear field arithmetic codegen — KoalaBear prime field operations for Bitcoin Script.
//
// Follows the babybear.go pattern: self-contained module imported by stack.go.
// Uses a KBTracker for named stack state tracking.
//
// KoalaBear prime: p = 2^31 - 2^24 + 1 = 2,130,706,433 (0x7f000001)
// Used by SP1 v6 STARK proofs (StackedBasefold verification).
//
// All values fit in a single BSV script number (31-bit prime).
// No multi-limb arithmetic needed.
package codegen

import (
	"fmt"
	"math/big"
	"math/bits"
)

// ===========================================================================
// Constants
// ===========================================================================

// kbFieldP is the KoalaBear field prime p = 2^31 - 2^24 + 1 = 2,130,706,433.
var kbFieldP = big.NewInt(2130706433)

// kbFieldPMinus2 is p - 2, used for Fermat's little theorem modular inverse.
var kbFieldPMinus2 = big.NewInt(2130706431)

// ===========================================================================
// KBTracker — named stack state tracker (mirrors BBTracker)
// ===========================================================================

// KBTracker tracks named stack positions and emits StackOps for KoalaBear codegen.
type KBTracker struct {
	nm               []string // stack names ("" for anonymous)
	e                func(StackOp)
	primeCacheActive bool // true when kbFieldP is cached on the alt-stack
}

// NewKBTracker creates a new tracker with initial named stack slots.
func NewKBTracker(init []string, emit func(StackOp)) *KBTracker {
	nm := make([]string, len(init))
	copy(nm, init)
	return &KBTracker{nm: nm, e: emit}
}

func (t *KBTracker) findDepth(name string) int {
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == name {
			return len(t.nm) - 1 - i
		}
	}
	panic(fmt.Sprintf("KBTracker: '%s' not on stack %v", name, t.nm))
}

func (t *KBTracker) pushInt(n string, v int64) {
	t.e(StackOp{Op: "push", Value: bigIntPush(v)})
	t.nm = append(t.nm, n)
}

func (t *KBTracker) pushBigInt(n string, v *big.Int) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(v)}})
	t.nm = append(t.nm, n)
}

func (t *KBTracker) dup(n string) {
	t.e(StackOp{Op: "dup"})
	t.nm = append(t.nm, n)
}

func (t *KBTracker) drop() {
	t.e(StackOp{Op: "drop"})
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *KBTracker) nip() {
	t.e(StackOp{Op: "nip"})
	L := len(t.nm)
	if L >= 2 {
		t.nm = append(t.nm[:L-2], t.nm[L-1])
	}
}

func (t *KBTracker) over(n string) {
	t.e(StackOp{Op: "over"})
	t.nm = append(t.nm, n)
}

func (t *KBTracker) swap() {
	t.e(StackOp{Op: "swap"})
	L := len(t.nm)
	if L >= 2 {
		t.nm[L-1], t.nm[L-2] = t.nm[L-2], t.nm[L-1]
	}
}

func (t *KBTracker) rot() {
	t.e(StackOp{Op: "rot"})
	L := len(t.nm)
	if L >= 3 {
		r := t.nm[L-3]
		t.nm = append(t.nm[:L-3], t.nm[L-2:]...)
		t.nm = append(t.nm, r)
	}
}

func (t *KBTracker) op(code string) {
	t.e(StackOp{Op: "opcode", Code: code})
}

func (t *KBTracker) roll(d int) {
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

func (t *KBTracker) pick(d int, n string) {
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

func (t *KBTracker) toTop(name string) {
	t.roll(t.findDepth(name))
}

func (t *KBTracker) copyToTop(name, n string) {
	t.pick(t.findDepth(name), n)
}

func (t *KBTracker) rename(n string) {
	if len(t.nm) > 0 {
		t.nm[len(t.nm)-1] = n
	}
}

// rawBlock emits raw opcodes; tracker only records net stack effect.
// produce="" means no output pushed.
func (t *KBTracker) rawBlock(consume []string, produce string, fn func(emit func(StackOp))) {
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

// PushPrimeCache pushes the KoalaBear prime to the alt-stack for caching.
// All subsequent field operations will use the cached prime instead of pushing fresh.
func (t *KBTracker) PushPrimeCache() {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(kbFieldP)}})
	t.e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	t.primeCacheActive = true
}

// PopPrimeCache removes the cached prime from the alt-stack.
func (t *KBTracker) PopPrimeCache() {
	t.e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	t.e(StackOp{Op: "drop"})
	t.primeCacheActive = false
}

// emitPrime emits the field prime onto the stack — either from cache or fresh push.
func (t *KBTracker) emitPrime(e func(StackOp)) {
	if t.primeCacheActive {
		e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		e(StackOp{Op: "opcode", Code: "OP_DUP"})
		e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	} else {
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(kbFieldP)}})
	}
}

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

// kbFieldMod reduces value mod p, ensuring non-negative result.
// Pattern: (a % p + p) % p — handles negative values from sub.
// Uses cached prime from alt-stack when available.
func kbFieldMod(t *KBTracker, aName, resultName string) {
	t.toTop(aName)
	t.rawBlock([]string{aName}, resultName, func(e func(StackOp)) {
		// (a % p + p) % p
		t.emitPrime(e)
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
		t.emitPrime(e)
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
		t.emitPrime(e)
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// kbFieldAddUnreduced computes a + b WITHOUT modular reduction.
// Result is in [0, 2p-2]. Safe when the result will be immediately consumed
// by multiplication (which applies its own mod) or further additions where
// the total stays within BSV script number limits (~2^63).
// KoalaBear p ≈ 2^31, so up to ~2^32 unreduced sums are safe.
func kbFieldAddUnreduced(t *KBTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
}

// kbFieldAdd computes (a + b) mod p.
func kbFieldAdd(t *KBTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_kb_add", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	// Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
	t.toTop("_kb_add")
	t.rawBlock([]string{"_kb_add"}, resultName, func(e func(StackOp)) {
		t.emitPrime(e)
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// kbFieldSub computes (a - b) mod p (non-negative).
func kbFieldSub(t *KBTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_kb_diff", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})
	// Difference can be negative, need full mod-reduce
	kbFieldMod(t, "_kb_diff", resultName)
}

// kbFieldMul computes (a * b) mod p.
func kbFieldMul(t *KBTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_kb_prod", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	// Product of two non-negative values is non-negative, simple OP_MOD
	t.toTop("_kb_prod")
	t.rawBlock([]string{"_kb_prod"}, resultName, func(e func(StackOp)) {
		t.emitPrime(e)
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// kbFieldSqr computes (a * a) mod p.
func kbFieldSqr(t *KBTracker, aName, resultName string) {
	t.copyToTop(aName, "_kb_sqr_copy")
	kbFieldMul(t, aName, "_kb_sqr_copy", resultName)
}

// kbFieldInv computes a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
// p-2 = 2130706431 = 0x7eFFFFFF = 0b0111_1110_1111_1111_1111_1111_1111_1111
// 31 bits, popcount 30.
// ~30 squarings + ~29 multiplies = ~59 compound operations.
func kbFieldInv(t *KBTracker, aName, resultName string) {
	// Start: result = a (for MSB bit 30 = 1)
	t.copyToTop(aName, "_inv_r")

	// Process bits 29 down to 0 (30 bits)
	pMinus2 := int(kbFieldPMinus2.Int64())
	for i := 29; i >= 0; i-- {
		// Always square
		kbFieldSqr(t, "_inv_r", "_inv_r2")
		t.rename("_inv_r")

		// Multiply if bit is set
		if (pMinus2>>uint(i))&1 == 1 {
			t.copyToTop(aName, "_inv_a")
			kbFieldMul(t, "_inv_r", "_inv_a", "_inv_m")
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

// EmitKBFieldAdd emits KoalaBear field addition.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a + b) mod p]
func EmitKBFieldAdd(emit func(StackOp)) {
	t := NewKBTracker([]string{"a", "b"}, emit)
	kbFieldAdd(t, "a", "b", "result")
}

// EmitKBFieldSub emits KoalaBear field subtraction.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a - b) mod p]
func EmitKBFieldSub(emit func(StackOp)) {
	t := NewKBTracker([]string{"a", "b"}, emit)
	kbFieldSub(t, "a", "b", "result")
}

// EmitKBFieldMul emits KoalaBear field multiplication.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a * b) mod p]
func EmitKBFieldMul(emit func(StackOp)) {
	t := NewKBTracker([]string{"a", "b"}, emit)
	kbFieldMul(t, "a", "b", "result")
}

// EmitKBFieldInv emits KoalaBear field multiplicative inverse.
// Stack in: [..., a]
// Stack out: [..., a^(p-2) mod p]
func EmitKBFieldInv(emit func(StackOp)) {
	t := NewKBTracker([]string{"a"}, emit)
	kbFieldInv(t, "a", "result")
}

// ===========================================================================
// Quartic extension field (ext4) operations
// ===========================================================================
//
// Extension field F_p^4 over KoalaBear using irreducible x^4 - W where W = 3.
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

// kbFieldW is the quadratic non-residue W = 3 used for ext4 (irreducible x^4 - 3).
var kbFieldW int64 = 3

// isPowerOf2 returns true if n is a positive power of 2.
func isPowerOf2(n int64) bool {
	return n > 0 && (n&(n-1)) == 0
}

// kbFieldMulConst computes (a * c) mod p where c is a small constant.
// Uses OP_2MUL when c==2 and OP_LSHIFTNUM when c is a power of 2 > 2.
func kbFieldMulConst(t *KBTracker, aName string, c int64, resultName string) {
	t.toTop(aName)
	if c == 2 {
		t.rawBlock([]string{aName}, "_kb_mc", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_2MUL"})
		})
	} else if isPowerOf2(c) && c > 2 {
		shift := bits.TrailingZeros64(uint64(c))
		t.rawBlock([]string{aName}, "_kb_mc", func(e func(StackOp)) {
			e(StackOp{Op: "push", Value: bigIntPush(int64(shift))})
			e(StackOp{Op: "opcode", Code: "OP_LSHIFTNUM"})
		})
	} else {
		t.rawBlock([]string{aName}, "_kb_mc", func(e func(StackOp)) {
			e(StackOp{Op: "push", Value: bigIntPush(c)})
			e(StackOp{Op: "opcode", Code: "OP_MUL"})
		})
	}
	// mod reduction — uses cached prime when available
	t.toTop("_kb_mc")
	t.rawBlock([]string{"_kb_mc"}, resultName, func(e func(StackOp)) {
		t.emitPrime(e)
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// ---------------------------------------------------------------------------
// Ext4 multiplication component function
// ---------------------------------------------------------------------------

func kbExt4MulComponent(emit func(StackOp), component int) {
	t := NewKBTracker([]string{"a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"}, emit)

	switch component {
	case 0:
		// r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
		t.copyToTop("a0", "_a0"); t.copyToTop("b0", "_b0")
		kbFieldMul(t, "_a0", "_b0", "_t0")     // a0*b0
		t.copyToTop("a1", "_a1"); t.copyToTop("b3", "_b3")
		kbFieldMul(t, "_a1", "_b3", "_t1")     // a1*b3
		t.copyToTop("a2", "_a2"); t.copyToTop("b2", "_b2")
		kbFieldMul(t, "_a2", "_b2", "_t2")     // a2*b2
		kbFieldAdd(t, "_t1", "_t2", "_t12")    // a1*b3 + a2*b2
		t.copyToTop("a3", "_a3"); t.copyToTop("b1", "_b1")
		kbFieldMul(t, "_a3", "_b1", "_t3")     // a3*b1
		kbFieldAdd(t, "_t12", "_t3", "_cross") // a1*b3 + a2*b2 + a3*b1
		kbFieldMulConst(t, "_cross", kbFieldW, "_wcross") // W * cross
		kbFieldAdd(t, "_t0", "_wcross", "_r")  // a0*b0 + W*cross

	case 1:
		// r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
		t.copyToTop("a0", "_a0"); t.copyToTop("b1", "_b1")
		kbFieldMul(t, "_a0", "_b1", "_t0")     // a0*b1
		t.copyToTop("a1", "_a1"); t.copyToTop("b0", "_b0")
		kbFieldMul(t, "_a1", "_b0", "_t1")     // a1*b0
		kbFieldAdd(t, "_t0", "_t1", "_direct") // a0*b1 + a1*b0
		t.copyToTop("a2", "_a2"); t.copyToTop("b3", "_b3")
		kbFieldMul(t, "_a2", "_b3", "_t2")     // a2*b3
		t.copyToTop("a3", "_a3"); t.copyToTop("b2", "_b2")
		kbFieldMul(t, "_a3", "_b2", "_t3")     // a3*b2
		kbFieldAdd(t, "_t2", "_t3", "_cross")  // a2*b3 + a3*b2
		kbFieldMulConst(t, "_cross", kbFieldW, "_wcross") // W * cross
		kbFieldAdd(t, "_direct", "_wcross", "_r")

	case 2:
		// r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
		t.copyToTop("a0", "_a0"); t.copyToTop("b2", "_b2")
		kbFieldMul(t, "_a0", "_b2", "_t0")     // a0*b2
		t.copyToTop("a1", "_a1"); t.copyToTop("b1", "_b1")
		kbFieldMul(t, "_a1", "_b1", "_t1")     // a1*b1
		kbFieldAdd(t, "_t0", "_t1", "_sum01")
		t.copyToTop("a2", "_a2"); t.copyToTop("b0", "_b0")
		kbFieldMul(t, "_a2", "_b0", "_t2")     // a2*b0
		kbFieldAdd(t, "_sum01", "_t2", "_direct")
		t.copyToTop("a3", "_a3"); t.copyToTop("b3", "_b3")
		kbFieldMul(t, "_a3", "_b3", "_t3")     // a3*b3
		kbFieldMulConst(t, "_t3", kbFieldW, "_wcross") // W * a3*b3
		kbFieldAdd(t, "_direct", "_wcross", "_r")

	case 3:
		// r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
		t.copyToTop("a0", "_a0"); t.copyToTop("b3", "_b3")
		kbFieldMul(t, "_a0", "_b3", "_t0")     // a0*b3
		t.copyToTop("a1", "_a1"); t.copyToTop("b2", "_b2")
		kbFieldMul(t, "_a1", "_b2", "_t1")     // a1*b2
		kbFieldAdd(t, "_t0", "_t1", "_sum01")
		t.copyToTop("a2", "_a2"); t.copyToTop("b1", "_b1")
		kbFieldMul(t, "_a2", "_b1", "_t2")     // a2*b1
		kbFieldAdd(t, "_sum01", "_t2", "_sum012")
		t.copyToTop("a3", "_a3"); t.copyToTop("b0", "_b0")
		kbFieldMul(t, "_a3", "_b0", "_t3")     // a3*b0
		kbFieldAdd(t, "_sum012", "_t3", "_r")

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

// EmitKBExt4Mul0 computes r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1) mod p.
func EmitKBExt4Mul0(emit func(StackOp)) { kbExt4MulComponent(emit, 0) }

// EmitKBExt4Mul1 computes r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2) mod p.
func EmitKBExt4Mul1(emit func(StackOp)) { kbExt4MulComponent(emit, 1) }

// EmitKBExt4Mul2 computes r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3) mod p.
func EmitKBExt4Mul2(emit func(StackOp)) { kbExt4MulComponent(emit, 2) }

// EmitKBExt4Mul3 computes r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 mod p.
func EmitKBExt4Mul3(emit func(StackOp)) { kbExt4MulComponent(emit, 3) }

// ---------------------------------------------------------------------------
// Ext4 inverse component function
// ---------------------------------------------------------------------------

func kbExt4InvComponent(emit func(StackOp), component int) {
	t := NewKBTracker([]string{"a0", "a1", "a2", "a3"}, emit)

	// Step 1: Compute norm_0 = a0² + W*a2² - 2*W*a1*a3
	t.copyToTop("a0", "_a0c")
	kbFieldSqr(t, "_a0c", "_a0sq")           // a0²
	t.copyToTop("a2", "_a2c")
	kbFieldSqr(t, "_a2c", "_a2sq")           // a2²
	kbFieldMulConst(t, "_a2sq", kbFieldW, "_wa2sq") // W*a2²
	kbFieldAdd(t, "_a0sq", "_wa2sq", "_n0a")    // a0² + W*a2²
	t.copyToTop("a1", "_a1c")
	t.copyToTop("a3", "_a3c")
	kbFieldMul(t, "_a1c", "_a3c", "_a1a3")   // a1*a3
	kbFieldMulConst(t, "_a1a3", 2*kbFieldW, "_2wa1a3") // 2*W*a1*a3
	kbFieldSub(t, "_n0a", "_2wa1a3", "_norm0") // norm_0

	// Step 2: Compute norm_1 = 2*a0*a2 - a1² - W*a3²
	t.copyToTop("a0", "_a0d")
	t.copyToTop("a2", "_a2d")
	kbFieldMul(t, "_a0d", "_a2d", "_a0a2")   // a0*a2
	kbFieldMulConst(t, "_a0a2", 2, "_2a0a2") // 2*a0*a2
	t.copyToTop("a1", "_a1d")
	kbFieldSqr(t, "_a1d", "_a1sq")           // a1²
	kbFieldSub(t, "_2a0a2", "_a1sq", "_n1a") // 2*a0*a2 - a1²
	t.copyToTop("a3", "_a3d")
	kbFieldSqr(t, "_a3d", "_a3sq")           // a3²
	kbFieldMulConst(t, "_a3sq", kbFieldW, "_wa3sq") // W*a3²
	kbFieldSub(t, "_n1a", "_wa3sq", "_norm1") // norm_1

	// Step 3: Quadratic inverse: scalar = (norm_0² - W*norm_1²)^(-1)
	t.copyToTop("_norm0", "_n0copy")
	kbFieldSqr(t, "_n0copy", "_n0sq")        // norm_0²
	t.copyToTop("_norm1", "_n1copy")
	kbFieldSqr(t, "_n1copy", "_n1sq")        // norm_1²
	kbFieldMulConst(t, "_n1sq", kbFieldW, "_wn1sq") // W*norm_1²
	kbFieldSub(t, "_n0sq", "_wn1sq", "_det") // norm_0² - W*norm_1²
	kbFieldInv(t, "_det", "_scalar")         // scalar = det^(-1)

	// Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
	t.copyToTop("_scalar", "_sc0")
	kbFieldMul(t, "_norm0", "_sc0", "_inv_n0") // inv_n0 = norm_0 * scalar

	// -norm_1 = (p - norm_1) mod p
	t.copyToTop("_norm1", "_neg_n1_pre")
	t.pushBigInt("_pval", kbFieldP)
	t.toTop("_neg_n1_pre")
	t.rawBlock([]string{"_pval", "_neg_n1_pre"}, "_neg_n1_sub", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})
	kbFieldMod(t, "_neg_n1_sub", "_neg_norm1")
	kbFieldMul(t, "_neg_norm1", "_scalar", "_inv_n1")

	// Step 5: Compute result components using quad_mul
	switch component {
	case 0:
		// r0 = a0*inv_n0 + W*a2*inv_n1
		t.copyToTop("a0", "_ea0")
		t.copyToTop("_inv_n0", "_ein0")
		kbFieldMul(t, "_ea0", "_ein0", "_ep0")   // a0*inv_n0
		t.copyToTop("a2", "_ea2")
		t.copyToTop("_inv_n1", "_ein1")
		kbFieldMul(t, "_ea2", "_ein1", "_ep1")   // a2*inv_n1
		kbFieldMulConst(t, "_ep1", kbFieldW, "_wep1") // W*a2*inv_n1
		kbFieldAdd(t, "_ep0", "_wep1", "_r")

	case 1:
		// r1 = -(a1*inv_n0 + W*a3*inv_n1)
		t.copyToTop("a1", "_oa1")
		t.copyToTop("_inv_n0", "_oin0")
		kbFieldMul(t, "_oa1", "_oin0", "_op0")   // a1*inv_n0
		t.copyToTop("a3", "_oa3")
		t.copyToTop("_inv_n1", "_oin1")
		kbFieldMul(t, "_oa3", "_oin1", "_op1")   // a3*inv_n1
		kbFieldMulConst(t, "_op1", kbFieldW, "_wop1") // W*a3*inv_n1
		kbFieldAdd(t, "_op0", "_wop1", "_odd0")
		// Negate: r = (0 - odd0) mod p
		t.pushInt("_zero1", 0)
		kbFieldSub(t, "_zero1", "_odd0", "_r")

	case 2:
		// r2 = a0*inv_n1 + a2*inv_n0
		t.copyToTop("a0", "_ea0")
		t.copyToTop("_inv_n1", "_ein1")
		kbFieldMul(t, "_ea0", "_ein1", "_ep0")   // a0*inv_n1
		t.copyToTop("a2", "_ea2")
		t.copyToTop("_inv_n0", "_ein0")
		kbFieldMul(t, "_ea2", "_ein0", "_ep1")   // a2*inv_n0
		kbFieldAdd(t, "_ep0", "_ep1", "_r")

	case 3:
		// r3 = -(a1*inv_n1 + a3*inv_n0)
		t.copyToTop("a1", "_oa1")
		t.copyToTop("_inv_n1", "_oin1")
		kbFieldMul(t, "_oa1", "_oin1", "_op0")   // a1*inv_n1
		t.copyToTop("a3", "_oa3")
		t.copyToTop("_inv_n0", "_oin0")
		kbFieldMul(t, "_oa3", "_oin0", "_op1")   // a3*inv_n0
		kbFieldAdd(t, "_op0", "_op1", "_odd1")
		// Negate: r = (0 - odd1) mod p
		t.pushInt("_zero3", 0)
		kbFieldSub(t, "_zero3", "_odd1", "_r")

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

// EmitKBExt4Inv0 computes r0 = a0*invN0 + W*a2*invN1.
func EmitKBExt4Inv0(emit func(StackOp)) { kbExt4InvComponent(emit, 0) }

// EmitKBExt4Inv1 computes r1 = -(a1*invN0 + W*a3*invN1).
func EmitKBExt4Inv1(emit func(StackOp)) { kbExt4InvComponent(emit, 1) }

// EmitKBExt4Inv2 computes r2 = a0*invN1 + a2*invN0.
func EmitKBExt4Inv2(emit func(StackOp)) { kbExt4InvComponent(emit, 2) }

// EmitKBExt4Inv3 computes r3 = -(a1*invN1 + a3*invN0).
func EmitKBExt4Inv3(emit func(StackOp)) { kbExt4InvComponent(emit, 3) }
