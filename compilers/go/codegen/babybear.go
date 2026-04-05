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
