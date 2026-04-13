// BN254 extension field tower codegen — Fp2, Fp6, Fp12 arithmetic for Bitcoin Script.
//
// Follows the bn254.go pattern: uses BN254Tracker for named stack state tracking.
// All operations use bn254FieldAdd/Sub/Mul/Inv/Neg from bn254.go for Fp operations.
//
// Extension field tower:
//   Fp2 = Fp[u] / (u^2 + 1)          — elements (a0, a1) = a0 + a1*u
//   Fp6 = Fp2[v] / (v^3 - ξ)         — elements (c0, c1, c2), ξ = 9 + u
//   Fp12 = Fp6[w] / (w^2 - v)        — elements (a, b)
//
// Fp2 elements occupy 2 Fp slots on stack.
// Fp6 elements occupy 6 Fp slots on stack.
// Fp12 elements occupy 12 Fp slots on stack.
package codegen

import "math/big"

// ===========================================================================
// Fp2 = Fp[u] / (u^2 + 1)
// ===========================================================================
//
// Element: (a0, a1) representing a0 + a1*u.
// Two Fp values on the stack, a0 pushed first (deeper), a1 on top.
// Irreducible: u^2 = -1.
//
// Multiplication: (a0 + a1*u)(b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u

// bn254Fp2Add computes (a0+a1*u) + (b0+b1*u) component-wise.
// Consumes a0,a1,b0,b1; produces r0,r1.
func bn254Fp2Add(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	if t.qAtBottom {
		bn254Fp2AddFlat(t, a0, a1, b0, b1, r0, r1)
		return
	}
	// Original tracker-based implementation
	t.copyToTop(a0, "_fp2a_a0")
	t.copyToTop(b0, "_fp2a_b0")
	bn254FieldAdd(t, "_fp2a_a0", "_fp2a_b0", r0)
	t.copyToTop(a1, "_fp2a_a1")
	t.copyToTop(b1, "_fp2a_b1")
	bn254FieldAdd(t, "_fp2a_a1", "_fp2a_b1", r1)
	bn254DropNames(t, []string{a0, a1, b0, b1})
}

// bn254Fp2AddUnreduced computes (a0+a1*u) + (b0+b1*u) without mod reduction.
// Each component is an unreduced sum in [0, 2p-2]. Safe only when the result
// is immediately consumed by Fp2Mul or Fp2Sqr (which reduce via FieldMul).
// Do NOT chain multiple unreduced additions — at most one unreduced add may
// precede a reducing operation to maintain the [0, 2p-2] invariant.
// Consumes a0,a1,b0,b1; produces r0,r1.
func bn254Fp2AddUnreduced(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	if t.qAtBottom {
		bn254Fp2AddUnreducedFlat(t, a0, a1, b0, b1, r0, r1)
		return
	}
	t.copyToTop(a0, "_fp2au_a0")
	t.copyToTop(b0, "_fp2au_b0")
	bn254FieldAddUnreduced(t, "_fp2au_a0", "_fp2au_b0", r0)
	t.copyToTop(a1, "_fp2au_a1")
	t.copyToTop(b1, "_fp2au_b1")
	bn254FieldAddUnreduced(t, "_fp2au_a1", "_fp2au_b1", r1)
	bn254DropNames(t, []string{a0, a1, b0, b1})
}

// bn254Fp2Sub computes (a0+a1*u) - (b0+b1*u) component-wise.
// Consumes a0,a1,b0,b1; produces r0,r1.
func bn254Fp2Sub(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	if t.qAtBottom {
		bn254Fp2SubFlat(t, a0, a1, b0, b1, r0, r1)
		return
	}
	t.copyToTop(a0, "_fp2s_a0")
	t.copyToTop(b0, "_fp2s_b0")
	bn254FieldSub(t, "_fp2s_a0", "_fp2s_b0", r0)
	t.copyToTop(a1, "_fp2s_a1")
	t.copyToTop(b1, "_fp2s_b1")
	bn254FieldSub(t, "_fp2s_a1", "_fp2s_b1", r1)
	bn254DropNames(t, []string{a0, a1, b0, b1})
}

// bn254Fp2Mul computes (a0+a1*u)*(b0+b1*u) using Karatsuba with deferred
// modular reduction.
//
// Karatsuba formula:
//   t0 = a0 * b0           (unreduced, <= p^2 ~ 2^508)
//   t1 = a1 * b1           (unreduced, <= p^2 ~ 2^508)
//   r0 = (t0 - t1) mod p   (1 mod -- handles potentially negative result)
//   t2 = (a0+a1) * (b0+b1) (unreduced -- sums <= 2p, product <= 4p^2 ~ 2^510)
//   r1 = (t2 - t0 - t1) mod p  (1 mod -- always non-negative: = a0*b1 + a1*b0)
//
// Total: 3 unreduced Fp muls, 2 mod reductions (was: 4 Fp muls, 6 mods).
//
// Consumes a0,a1,b0,b1; produces r0,r1.
func bn254Fp2Mul(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	if t.qAtBottom {
		bn254Fp2MulFlat(t, a0, a1, b0, b1, r0, r1)
		return
	}
	bn254Fp2MulTracker(t, a0, a1, b0, b1, r0, r1)
}

// bn254Fp2MulTracker is the original tracker-based Fp2 mul implementation.
func bn254Fp2MulTracker(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	// t0 = a0 * b0 (unreduced)
	t.copyToTop(a0, "_fp2m_a0")
	t.copyToTop(b0, "_fp2m_b0")
	bn254FieldMulUnreduced(t, "_fp2m_a0", "_fp2m_b0", "_fp2m_t0")

	// t1 = a1 * b1 (unreduced)
	t.copyToTop(a1, "_fp2m_a1")
	t.copyToTop(b1, "_fp2m_b1")
	bn254FieldMulUnreduced(t, "_fp2m_a1", "_fp2m_b1", "_fp2m_t1")

	// r0 = (t0 - t1) mod p  -- may be negative, so full mod needed
	t.copyToTop("_fp2m_t0", "_fp2m_t0c")
	t.copyToTop("_fp2m_t1", "_fp2m_t1c")
	bn254FieldSubUnreduced(t, "_fp2m_t0c", "_fp2m_t1c", "_fp2m_r0raw")
	bn254FieldMod(t, "_fp2m_r0raw", r0)

	// s0 = a0 + a1 (unreduced sum, <= 2p-2)
	t.copyToTop(a0, "_fp2m_a0s")
	t.copyToTop(a1, "_fp2m_a1s")
	bn254FieldAddUnreduced(t, "_fp2m_a0s", "_fp2m_a1s", "_fp2m_s0")

	// s1 = b0 + b1 (unreduced sum, <= 2p-2)
	t.copyToTop(b0, "_fp2m_b0s")
	t.copyToTop(b1, "_fp2m_b1s")
	bn254FieldAddUnreduced(t, "_fp2m_b0s", "_fp2m_b1s", "_fp2m_s1")

	// t2 = s0 * s1 (unreduced, <= 4p^2 ~ 2^510)
	bn254FieldMulUnreduced(t, "_fp2m_s0", "_fp2m_s1", "_fp2m_t2")

	// r1 = (t2 - t0 - t1) mod p
	bn254FieldSubUnreduced(t, "_fp2m_t2", "_fp2m_t0", "_fp2m_r1a")
	bn254FieldSubUnreduced(t, "_fp2m_r1a", "_fp2m_t1", "_fp2m_r1raw")
	bn254FieldModPositive(t, "_fp2m_r1raw", r1)

	// Clean up inputs
	bn254DropNames(t, []string{a0, a1, b0, b1})
}

// bn254Fp2Sqr computes (a0+a1*u)^2 with deferred modular reduction.
//
// Formula:
//   sum  = a0 + a1        (unreduced)
//   diff = a0 - a1        (unreduced, may be negative)
//   r0   = (sum * diff) mod p   (1 mul unreduced + 1 mod -- = a0^2 - a1^2)
//   prod = a0 * a1        (unreduced)
//   r1   = (2 * prod) mod p     (1 mod -- = 2*a0*a1)
//
// Total: 2 unreduced muls, 2 mod reductions (was: 2 muls + 4 mods).
//
// Consumes a0,a1; produces r0,r1.
func bn254Fp2Sqr(t *BN254Tracker, a0, a1, r0, r1 string) {
	if t.qAtBottom {
		bn254Fp2SqrFlat(t, a0, a1, r0, r1)
		return
	}
	// Original tracker-based implementation
	t.copyToTop(a0, "_fp2sq_a0a")
	t.copyToTop(a1, "_fp2sq_a1a")
	bn254FieldAddUnreduced(t, "_fp2sq_a0a", "_fp2sq_a1a", "_fp2sq_sum")
	t.copyToTop(a0, "_fp2sq_a0b")
	t.copyToTop(a1, "_fp2sq_a1b")
	bn254FieldSubUnreduced(t, "_fp2sq_a0b", "_fp2sq_a1b", "_fp2sq_diff")
	bn254FieldMulUnreduced(t, "_fp2sq_sum", "_fp2sq_diff", "_fp2sq_r0raw")
	bn254FieldMod(t, "_fp2sq_r0raw", r0)
	t.copyToTop(a0, "_fp2sq_a0c")
	t.copyToTop(a1, "_fp2sq_a1c")
	bn254FieldMulUnreduced(t, "_fp2sq_a0c", "_fp2sq_a1c", "_fp2sq_prod")
	t.copyToTop("_fp2sq_prod", "_fp2sq_prod2")
	bn254FieldAddUnreduced(t, "_fp2sq_prod", "_fp2sq_prod2", "_fp2sq_r1raw")
	bn254FieldModPositive(t, "_fp2sq_r1raw", r1)
	bn254DropNames(t, []string{a0, a1})
}

// bn254Fp2Inv computes (a0+a1*u)^(-1).
// norm = a0^2 + a1^2, inv = norm^(-1), r0 = a0*inv, r1 = -a1*inv.
// Consumes a0,a1; produces r0,r1.
func bn254Fp2Inv(t *BN254Tracker, a0, a1, r0, r1 string) {
	// n0 = a0^2
	t.copyToTop(a0, "_fp2i_a0a")
	bn254FieldSqr(t, "_fp2i_a0a", "_fp2i_n0")
	// n1 = a1^2
	t.copyToTop(a1, "_fp2i_a1a")
	bn254FieldSqr(t, "_fp2i_a1a", "_fp2i_n1")
	// norm = n0 + n1 (unreduced: feeds directly into FieldInv which
	// starts with FieldSqr -> FieldMul -> FieldMod, so mod is applied)
	bn254FieldAddUnreduced(t, "_fp2i_n0", "_fp2i_n1", "_fp2i_norm")
	// inv = norm^(-1)
	bn254FieldInv(t, "_fp2i_norm", "_fp2i_inv")
	// r0 = a0 * inv
	t.copyToTop(a0, "_fp2i_a0b")
	t.copyToTop("_fp2i_inv", "_fp2i_inv0")
	bn254FieldMul(t, "_fp2i_a0b", "_fp2i_inv0", r0)
	// r1 = -(a1 * inv)
	t.copyToTop(a1, "_fp2i_a1b")
	bn254FieldMul(t, "_fp2i_a1b", "_fp2i_inv", "_fp2i_prod")
	bn254FieldNeg(t, "_fp2i_prod", r1)
	// Clean up inputs
	bn254DropNames(t, []string{a0, a1})
}

// bn254Fp2Conjugate computes conjugate: (a0, -a1).
// Consumes a0,a1; produces r0,r1.
func bn254Fp2Conjugate(t *BN254Tracker, a0, a1, r0, r1 string) {
	if t.qAtBottom {
		bn254Fp2ConjugateFlat(t, a0, a1, r0, r1)
		return
	}
	t.toTop(a0)
	t.rename(r0)
	bn254FieldNeg(t, a1, r1)
}

// bn254Fp2MulByNonResidue multiplies Fp2 element by ξ = 9+u.
// (a0 + a1*u)(9 + u) = (9*a0 - a1) + (a0 + 9*a1)*u.
//
// Optimization: skips mod after 9*a0 and 9*a1. The unreduced values (up to 9p)
// are safe because FieldSub's (diff+p)%p and FieldAdd's single-mod both handle
// multi-p-range inputs correctly via OP_MOD.
// This reduces from 4 mod reductions to 2.
// Consumes a0,a1; produces r0,r1.
func bn254Fp2MulByNonResidue(t *BN254Tracker, a0, a1, r0, r1 string) {
	if t.qAtBottom {
		bn254Fp2MulByNonResidueFlat(t, a0, a1, r0, r1)
		return
	}
	// Original tracker-based implementation
	t.copyToTop(a0, "_fp2nr_a0a")
	bn254FieldMulConstUnreduced(t, "_fp2nr_a0a", 9, "_fp2nr_9a0")
	t.copyToTop(a1, "_fp2nr_a1a")
	bn254FieldSub(t, "_fp2nr_9a0", "_fp2nr_a1a", r0)
	t.copyToTop(a1, "_fp2nr_a1b")
	bn254FieldMulConstUnreduced(t, "_fp2nr_a1b", 9, "_fp2nr_9a1")
	t.copyToTop(a0, "_fp2nr_a0b")
	bn254FieldAdd(t, "_fp2nr_a0b", "_fp2nr_9a1", r1)
	bn254DropNames(t, []string{a0, a1})
}

// bn254FieldMulConstUnreduced computes a * c WITHOUT modular reduction.
// Result is unreduced (up to c * (p-1)). Safe when the result feeds
// directly into FieldSub or FieldAdd which will apply mod reduction.
func bn254FieldMulConstUnreduced(t *BN254Tracker, aName string, c int64, resultName string) {
	t.toTop(aName)
	t.rawBlock([]string{aName}, resultName, func(e func(StackOp)) {
		if c == 2 {
			e(StackOp{Op: "opcode", Code: "OP_2MUL"})
		} else {
			e(StackOp{Op: "push", Value: bigIntPush(c)})
			e(StackOp{Op: "opcode", Code: "OP_MUL"})
		}
	})
}

// bn254Fp2Neg negates Fp2 element: (-a0, -a1).
// Consumes a0,a1; produces r0,r1.
func bn254Fp2Neg(t *BN254Tracker, a0, a1, r0, r1 string) {
	if t.qAtBottom {
		bn254Fp2NegFlat(t, a0, a1, r0, r1)
		return
	}
	bn254FieldNeg(t, a0, r0)
	bn254FieldNeg(t, a1, r1)
}

// bn254Fp2IsZero checks if Fp2 element is zero (both components zero).
// Consumes a0,a1; produces result (boolean).
func bn254Fp2IsZero(t *BN254Tracker, a0, a1, resultName string) {
	t.toTop(a0)
	t.toTop(a1)
	t.rawBlock([]string{a0, a1}, resultName, func(e func(StackOp)) {
		// a0 == 0
		e(StackOp{Op: "opcode", Code: "OP_NOT"})
		e(StackOp{Op: "swap"})
		// a1 == 0
		e(StackOp{Op: "opcode", Code: "OP_NOT"})
		// both zero
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})
}

// ===========================================================================
// Helper: multiply Fp element by small constant
// ===========================================================================

// bn254FieldMulConst computes (a * c) mod p where c is a small positive constant.
// Since both a (field element) and c (positive) are non-negative, use single-mod.
func bn254FieldMulConst(t *BN254Tracker, aName string, c int64, resultName string) {
	t.toTop(aName)
	if t.qAtBottom {
		t.rawBlock([]string{aName}, resultName, func(e func(StackOp)) {
			if c == 2 {
				e(StackOp{Op: "opcode", Code: "OP_2MUL"})
			} else {
				e(StackOp{Op: "push", Value: bigIntPush(c)})
				e(StackOp{Op: "opcode", Code: "OP_MUL"})
			}
			e(StackOp{Op: "opcode", Code: "OP_DEPTH"})
			e(StackOp{Op: "opcode", Code: "OP_1SUB"})
			e(StackOp{Op: "opcode", Code: "OP_PICK"})
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
		return
	}
	t.rawBlock([]string{aName}, "_bn_mc", func(e func(StackOp)) {
		if c == 2 {
			e(StackOp{Op: "opcode", Code: "OP_2MUL"})
		} else {
			e(StackOp{Op: "push", Value: bigIntPush(c)})
			e(StackOp{Op: "opcode", Code: "OP_MUL"})
		}
	})
	bn254FieldModPositive(t, "_bn_mc", resultName)
}

// ===========================================================================
// Helper: drop multiple named stack slots
// ===========================================================================

// bn254DropNames drops all named values from the stack.
func bn254DropNames(t *BN254Tracker, names []string) {
	for _, n := range names {
		t.toTop(n)
		t.drop()
	}
}

// ===========================================================================
// Fp6 = Fp2[v] / (v^3 - ξ), ξ = 9+u
// ===========================================================================
//
// Element: (c0, c1, c2) where each ci is Fp2.
// 6 Fp values on stack: c0_0, c0_1, c1_0, c1_1, c2_0, c2_1
// c0_0 is deepest, c2_1 is on top.
//
// Naming convention: element "X" occupies slots "X_0" and "X_1" for its Fp2 components.

// bn254Fp6Add computes component-wise Fp6 addition.
// Consumes a (6 slots: a0_0..a2_1) and b (6 slots: b0_0..b2_1); produces r (6 slots).
func bn254Fp6Add(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	// Component-wise: r_i = a_i + b_i for i in {0,1,2}
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		bn254Fp2Add(t,
			aPrefix+"_"+sfx+"_0", aPrefix+"_"+sfx+"_1",
			bPrefix+"_"+sfx+"_0", bPrefix+"_"+sfx+"_1",
			rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6AddUnreduced computes component-wise Fp6 addition without mod reduction.
// Each Fp component is an unreduced sum in [0, 2p-2]. Safe only when the result
// is immediately consumed by Fp6Mul (which reduces via Fp2Mul -> FieldMul).
// Do NOT chain multiple unreduced additions — at most one unreduced add may
// precede a reducing operation to maintain the [0, 2p-2] invariant.
// Consumes 12 Fp slots; produces 6 Fp slots.
func bn254Fp6AddUnreduced(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		bn254Fp2AddUnreduced(t,
			aPrefix+"_"+sfx+"_0", aPrefix+"_"+sfx+"_1",
			bPrefix+"_"+sfx+"_0", bPrefix+"_"+sfx+"_1",
			rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6Sub computes component-wise Fp6 subtraction.
func bn254Fp6Sub(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		bn254Fp2Sub(t,
			aPrefix+"_"+sfx+"_0", aPrefix+"_"+sfx+"_1",
			bPrefix+"_"+sfx+"_0", bPrefix+"_"+sfx+"_1",
			rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6MulByNonResidue multiplies Fp6 element by v (the variable).
// (c0, c1, c2) -> (ξ*c2, c0, c1)
// Consumes 6 slots; produces 6 slots.
func bn254Fp6MulByNonResidue(t *BN254Tracker, aPrefix, rPrefix string) {
	// r1 = a0  (just rename)
	t.toTop(aPrefix + "_0_0")
	t.rename(rPrefix + "_1_0")
	t.toTop(aPrefix + "_0_1")
	t.rename(rPrefix + "_1_1")
	// r2 = a1  (just rename)
	t.toTop(aPrefix + "_1_0")
	t.rename(rPrefix + "_2_0")
	t.toTop(aPrefix + "_1_1")
	t.rename(rPrefix + "_2_1")
	// r0 = ξ * a2
	bn254Fp2MulByNonResidue(t,
		aPrefix+"_2_0", aPrefix+"_2_1",
		rPrefix+"_0_0", rPrefix+"_0_1")
}

// bn254Fp6Mul computes Fp6 multiplication using schoolbook method.
// Given a = (a0, a1, a2) and b = (b0, b1, b2) in Fp2[v]/(v^3 - ξ):
//   r0 = a0*b0 + ξ*(a1*b2 + a2*b1)
//   r1 = a0*b1 + a1*b0 + ξ*a2*b2
//   r2 = a0*b2 + a1*b1 + a2*b0
// Consumes 12 Fp slots; produces 6 Fp slots.
func bn254Fp6Mul(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	// t0 = a0 * b0  (Fp2 mul)
	bn254Fp2MulCopy(t, aPrefix+"_0", bPrefix+"_0", "_f6m_t0")
	// t1 = a1 * b1
	bn254Fp2MulCopy(t, aPrefix+"_1", bPrefix+"_1", "_f6m_t1")
	// t2 = a2 * b2
	bn254Fp2MulCopy(t, aPrefix+"_2", bPrefix+"_2", "_f6m_t2")

	// --- r0 = t0 + ξ*(a1*b2 + a2*b1) ---
	// c01 = a1*b2
	bn254Fp2MulCopy(t, aPrefix+"_1", bPrefix+"_2", "_f6m_c01")
	// c02 = a2*b1
	bn254Fp2MulCopy(t, aPrefix+"_2", bPrefix+"_1", "_f6m_c02")
	// cross0 = c01 + c02 (unreduced: feeds directly into MulByNonResidue
	// which applies FieldMulConst -> FieldMod on each component)
	bn254Fp2AddUnreduced(t, "_f6m_c01_0", "_f6m_c01_1", "_f6m_c02_0", "_f6m_c02_1", "_f6m_cr0_0", "_f6m_cr0_1")
	// ξ * cross0
	bn254Fp2MulByNonResidue(t, "_f6m_cr0_0", "_f6m_cr0_1", "_f6m_ncr0_0", "_f6m_ncr0_1")
	// r0 = t0 + ξ*cross0
	t.copyToTop("_f6m_t0_0", "_f6m_t0c0")
	t.copyToTop("_f6m_t0_1", "_f6m_t0c1")
	bn254Fp2Add(t, "_f6m_t0c0", "_f6m_t0c1", "_f6m_ncr0_0", "_f6m_ncr0_1", rPrefix+"_0_0", rPrefix+"_0_1")

	// --- r1 = a0*b1 + a1*b0 + ξ*t2 ---
	bn254Fp2MulCopy(t, aPrefix+"_0", bPrefix+"_1", "_f6m_c10")
	bn254Fp2MulCopy(t, aPrefix+"_1", bPrefix+"_0", "_f6m_c11")
	bn254Fp2Add(t, "_f6m_c10_0", "_f6m_c10_1", "_f6m_c11_0", "_f6m_c11_1", "_f6m_dir1_0", "_f6m_dir1_1")
	t.copyToTop("_f6m_t2_0", "_f6m_t2c0")
	t.copyToTop("_f6m_t2_1", "_f6m_t2c1")
	bn254Fp2MulByNonResidue(t, "_f6m_t2c0", "_f6m_t2c1", "_f6m_nt2_0", "_f6m_nt2_1")
	bn254Fp2Add(t, "_f6m_dir1_0", "_f6m_dir1_1", "_f6m_nt2_0", "_f6m_nt2_1", rPrefix+"_1_0", rPrefix+"_1_1")

	// --- r2 = a0*b2 + a1*b1 + a2*b0 ---
	// c20 = a0*b2
	bn254Fp2MulCopy(t, aPrefix+"_0", bPrefix+"_2", "_f6m_c20")
	// c21 = a2*b0
	bn254Fp2MulCopy(t, aPrefix+"_2", bPrefix+"_0", "_f6m_c21")
	// sum = c20 + t1
	t.copyToTop("_f6m_t1_0", "_f6m_t1c0")
	t.copyToTop("_f6m_t1_1", "_f6m_t1c1")
	bn254Fp2Add(t, "_f6m_c20_0", "_f6m_c20_1", "_f6m_t1c0", "_f6m_t1c1", "_f6m_s20_0", "_f6m_s20_1")
	// r2 = sum + c21
	bn254Fp2Add(t, "_f6m_s20_0", "_f6m_s20_1", "_f6m_c21_0", "_f6m_c21_1", rPrefix+"_2_0", rPrefix+"_2_1")

	// Clean up intermediate t values and inputs
	bn254DropNames(t, []string{
		"_f6m_t0_0", "_f6m_t0_1",
		"_f6m_t1_0", "_f6m_t1_1",
		"_f6m_t2_0", "_f6m_t2_1",
	})
	// Clean up all 12 input slots
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		bn254DropNames(t, []string{
			aPrefix + "_" + sfx + "_0", aPrefix + "_" + sfx + "_1",
			bPrefix + "_" + sfx + "_0", bPrefix + "_" + sfx + "_1",
		})
	}
}

// bn254Fp6Neg negates all Fp2 components.
func bn254Fp6Neg(t *BN254Tracker, aPrefix, rPrefix string) {
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		bn254Fp2Neg(t,
			aPrefix+"_"+sfx+"_0", aPrefix+"_"+sfx+"_1",
			rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp2MulCopy performs Fp2 multiplication preserving the original operands.
// It copies a and b before multiplying, so aPrefix_0/aPrefix_1 and bPrefix_0/bPrefix_1 remain.
// Result is stored in rPrefix_0, rPrefix_1.
func bn254Fp2MulCopy(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	if t.qAtBottom {
		// Flat: pick all 4 operands directly, then flat fp2Mul.
		// The picks copy the values without moving originals.
		a0 := aPrefix + "_0"
		a1 := aPrefix + "_1"
		b0 := bPrefix + "_0"
		b1 := bPrefix + "_1"
		// Pick in order: a0, a1, b0, b1. Each pick shifts subsequent depths by +1.
		d0 := t.findDepth(a0)
		t.pick(d0, "_mc_a0")
		d1 := t.findDepth(a1)
		t.pick(d1, "_mc_a1")
		d2 := t.findDepth(b0)
		t.pick(d2, "_mc_b0")
		d3 := t.findDepth(b1)
		t.pick(d3, "_mc_b1")
		// Now top 4 are the copies. Use flat Fp2Mul.
		fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
		t.nm = t.nm[:len(t.nm)-4]
		fe.fp2Mul()
		t.nm = append(t.nm, rPrefix+"_0", rPrefix+"_1")
		return
	}
	t.copyToTop(aPrefix+"_0", "_mc_a0")
	t.copyToTop(aPrefix+"_1", "_mc_a1")
	t.copyToTop(bPrefix+"_0", "_mc_b0")
	t.copyToTop(bPrefix+"_1", "_mc_b1")
	bn254Fp2Mul(t, "_mc_a0", "_mc_a1", "_mc_b0", "_mc_b1", rPrefix+"_0", rPrefix+"_1")
}

// bn254Fp2SqrCopy performs Fp2 squaring preserving the original operands.
func bn254Fp2SqrCopy(t *BN254Tracker, aPrefix, rPrefix string) {
	if t.qAtBottom {
		a0 := aPrefix + "_0"
		a1 := aPrefix + "_1"
		d0 := t.findDepth(a0)
		t.pick(d0, "_sc_a0")
		d1 := t.findDepth(a1)
		t.pick(d1, "_sc_a1")
		fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
		t.nm = t.nm[:len(t.nm)-2]
		fe.fp2Sqr()
		t.nm = append(t.nm, rPrefix+"_0", rPrefix+"_1")
		return
	}
	t.copyToTop(aPrefix+"_0", "_sc_a0")
	t.copyToTop(aPrefix+"_1", "_sc_a1")
	bn254Fp2Sqr(t, "_sc_a0", "_sc_a1", rPrefix+"_0", rPrefix+"_1")
}

// ===========================================================================
// Fp12 = Fp6[w] / (w^2 - v)
// ===========================================================================
//
// Element: (a, b) where a, b are Fp6.
// 12 Fp values on stack.
// Naming: element "X" occupies "X_a_0_0" through "X_b_2_1" (12 Fp slots).
//
// w^2 = v, so the non-residue for Fp12 over Fp6 is "multiply by v" = Fp6MulByNonResidue.

// bn254Fp12Add computes component-wise Fp12 addition.
// Consumes 24 Fp slots; produces 12 Fp slots.
func bn254Fp12Add(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	bn254Fp6Add(t, aPrefix+"_a", bPrefix+"_a", rPrefix+"_a")
	bn254Fp6Add(t, aPrefix+"_b", bPrefix+"_b", rPrefix+"_b")
}

// bn254Fp12Sub computes component-wise Fp12 subtraction.
func bn254Fp12Sub(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	bn254Fp6Sub(t, aPrefix+"_a", bPrefix+"_a", rPrefix+"_a")
	bn254Fp6Sub(t, aPrefix+"_b", bPrefix+"_b", rPrefix+"_b")
}

// bn254Fp12Mul computes Fp12 multiplication using Karatsuba.
// a = (a_a, a_b), b = (b_a, b_b) in Fp6[w]/(w^2 - v):
//   t0 = a_a * b_a
//   t1 = a_b * b_b
//   r_a = t0 + v*t1  (where v* means Fp6MulByNonResidue)
//   r_b = (a_a + a_b)*(b_a + b_b) - t0 - t1
// Consumes 24 Fp slots; produces 12 Fp slots.
func bn254Fp12Mul(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	// t0 = a_a * b_a
	bn254Fp6MulCopy(t, aPrefix+"_a", bPrefix+"_a", "_f12m_t0")
	// t1 = a_b * b_b
	bn254Fp6MulCopy(t, aPrefix+"_b", bPrefix+"_b", "_f12m_t1")

	// r_a = t0 + v*t1
	bn254Fp6CopyPrefix(t, "_f12m_t1", "_f12m_t1v")
	bn254Fp6MulByNonResidue(t, "_f12m_t1v", "_f12m_vt1")
	bn254Fp6CopyPrefix(t, "_f12m_t0", "_f12m_t0a")
	bn254Fp6Add(t, "_f12m_t0a", "_f12m_vt1", rPrefix+"_a")

	// r_b = (a_a + a_b)*(b_a + b_b) - t0 - t1
	// OPTIMIZATION: Move (not copy) the input halves since they're consumed.
	// Use unreduced adds: the sums feed directly into Fp6Mul which
	// reduces each component via Fp2Mul -> FieldMul -> FieldMod.
	bn254Fp6RenamePrefix(t, aPrefix+"_a", "_f12m_aa")
	bn254Fp6RenamePrefix(t, aPrefix+"_b", "_f12m_ab")
	bn254Fp6AddUnreduced(t, "_f12m_aa", "_f12m_ab", "_f12m_sa")
	bn254Fp6RenamePrefix(t, bPrefix+"_a", "_f12m_ba")
	bn254Fp6RenamePrefix(t, bPrefix+"_b", "_f12m_bb")
	bn254Fp6AddUnreduced(t, "_f12m_ba", "_f12m_bb", "_f12m_sb")
	bn254Fp6Mul(t, "_f12m_sa", "_f12m_sb", "_f12m_prod")
	bn254Fp6Sub(t, "_f12m_prod", "_f12m_t0", "_f12m_sub1")
	bn254Fp6Sub(t, "_f12m_sub1", "_f12m_t1", rPrefix+"_b")

	// Inputs consumed by the rename + add above, no cleanup needed.
}

// bn254Fp12MulSparse multiplies a dense Fp12 element by a sparse one in the
// canonical gnark-crypto BN254 D-twist Miller-loop sparse form:
//
//	line = (c0, 0, 0, c3, c4, 0)   in Fp12 component order
//	                               (C0.B0, C0.B1, C0.B2, C1.B0, C1.B1, C1.B2)
//
// i.e. only C0.B0, C1.B0, C1.B1 are populated. In Fp6[w]/(w² - v) splitting
// a = d_a + d_b·w, this sparse line has:
//
//	s_a = (c0, 0, 0)    — Fp6 with only c0 nonzero (scalar Fp2 shape)
//	s_b = (c3, c4, 0)   — Fp6 with c2 = 0
//
// Gnark's MulBy034 implements this as:
//
//	a' = d_a · c0                 (Fp6 × Fp2 scalar, 3 Fp2 muls)
//	b' = d_b · (c3, c4, 0)        (Fp6 × sparse-c2-zero Fp6, 5 Fp2 muls via Karatsuba)
//	d0 = c0 + c3
//	d  = (d_a + d_b) · (d0, c4, 0)  (Fp6 × sparse-c2-zero Fp6, 5 Fp2 muls)
//	r_b = d - a' - b'
//	r_a = a' + v · b'
//
// Total: 3 + 5 + 5 = 13 Fp2 muls vs 18 for full Fp12 Karatsuba.
//
// The sparse element is stored on the tracker as 6 Fp values with slot suffixes
//
//	sparsePrefix_c0_0, sparsePrefix_c0_1  (Fp2 c0)
//	sparsePrefix_c3_0, sparsePrefix_c3_1  (Fp2 c3)
//	sparsePrefix_c4_0, sparsePrefix_c4_1  (Fp2 c4)
//
// Consumes dense (12 Fp slots) + sparse (6 Fp slots); produces result (12 Fp slots).
func bn254Fp12MulSparse(t *BN254Tracker, densePrefix, sparsePrefix, rPrefix string) {
	// a' = d_a * c0 (Fp6 × Fp2 scalar) — preserves d_a so we can reuse it below.
	bn254Fp6MulByFp2Copy(t, densePrefix+"_a", sparsePrefix+"_c0", "_f12sp_a")

	// b' = d_b * (c3, c4, 0) (Fp6 × sparse-c2-zero Fp6) — preserves d_b and (c3, c4).
	bn254Fp6MulByC2Zero(t, densePrefix+"_b", sparsePrefix+"_c3", sparsePrefix+"_c4", "_f12sp_b")

	// --- r_a = a' + v · b' ---
	bn254Fp6CopyPrefix(t, "_f12sp_b", "_f12sp_bv")
	bn254Fp6MulByNonResidue(t, "_f12sp_bv", "_f12sp_vb")
	bn254Fp6CopyPrefix(t, "_f12sp_a", "_f12sp_acopy")
	bn254Fp6Add(t, "_f12sp_acopy", "_f12sp_vb", rPrefix+"_a")

	// --- r_b = (d_a + d_b) * (c0+c3, c4, 0) - a' - b' ---
	// d0 = c0 + c3 (new Fp2). The sparse inputs c0 and c3 are consumed here.
	t.toTop(sparsePrefix + "_c0_0")
	t.rename("_f12sp_c0a")
	t.toTop(sparsePrefix + "_c0_1")
	t.rename("_f12sp_c0b")
	t.toTop(sparsePrefix + "_c3_0")
	t.rename("_f12sp_c3a")
	t.toTop(sparsePrefix + "_c3_1")
	t.rename("_f12sp_c3b")
	bn254Fp2AddUnreduced(t, "_f12sp_c0a", "_f12sp_c0b", "_f12sp_c3a", "_f12sp_c3b",
		"_f12sp_d0_0", "_f12sp_d0_1")

	// d_a + d_b (Fp6 sum), consuming the dense inputs.
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.toTop(densePrefix + "_a_" + sfx + "_0")
		t.rename("_f12sp_da_" + sfx + "_0")
		t.toTop(densePrefix + "_a_" + sfx + "_1")
		t.rename("_f12sp_da_" + sfx + "_1")
	}
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.toTop(densePrefix + "_b_" + sfx + "_0")
		t.rename("_f12sp_db_" + sfx + "_0")
		t.toTop(densePrefix + "_b_" + sfx + "_1")
		t.rename("_f12sp_db_" + sfx + "_1")
	}
	bn254Fp6AddUnreduced(t, "_f12sp_da", "_f12sp_db", "_f12sp_dsum")

	// Move c4 into the name bn254Fp6MulByC2Zero expects for the second sparse coef.
	t.toTop(sparsePrefix + "_c4_0")
	t.rename("_f12sp_c4sp_0")
	t.toTop(sparsePrefix + "_c4_1")
	t.rename("_f12sp_c4sp_1")

	// d = (d_a + d_b) * (d0, c4, 0) — Fp6 × sparse-c2-zero Fp6.
	bn254Fp6MulByC2Zero(t, "_f12sp_dsum", "_f12sp_d0", "_f12sp_c4sp", "_f12sp_d")

	// r_b = d - a' - b'
	bn254Fp6Sub(t, "_f12sp_d", "_f12sp_a", "_f12sp_sub1")
	bn254Fp6Sub(t, "_f12sp_sub1", "_f12sp_b", rPrefix+"_b")

	// Drop intermediates that were preserved by the MulByC2Zero copy semantics.
	// dsum (6 Fp), d0 (2 Fp), c4sp (2 Fp) were inputs to the final MulByC2Zero
	// and are not consumed. We drop them explicitly so they don't pollute the
	// tracker for subsequent iterations.
	bn254DropNames(t, []string{
		"_f12sp_dsum_0_0", "_f12sp_dsum_0_1",
		"_f12sp_dsum_1_0", "_f12sp_dsum_1_1",
		"_f12sp_dsum_2_0", "_f12sp_dsum_2_1",
		"_f12sp_d0_0", "_f12sp_d0_1",
		"_f12sp_c4sp_0", "_f12sp_c4sp_1",
	})
}

// bn254Fp12MulSparseDropInputs drops the 6 Fp slots of a sparse Fp12 element.
func bn254Fp12MulSparseDropInputs(t *BN254Tracker, prefix string) {
	bn254DropNames(t, []string{
		prefix + "_c0_0", prefix + "_c0_1",
		prefix + "_c3_0", prefix + "_c3_1",
		prefix + "_c4_0", prefix + "_c4_1",
	})
}

// bn254Fp12MulSparseBySparse was removed along with the old (ell_0, ell_vv, ell_vw)
// sparse line convention. It was unused in production code. The canonical
// gnark-crypto form uses (c0, c3, c4) slots and the pairing codegen now
// multiplies sparse lines into a dense accumulator via bn254Fp12MulSparse
// directly; a sparse-by-sparse accumulator is not needed here.

// bn254Fp6MulBothC2ZeroKaratsuba multiplies two sparse Fp6 elements where both
// have c2=0: a = (a0, a1, 0) and b = (b0, b1, 0) in Fp2[v]/(v^3 - xi).
//
// Product: (a0 + a1*v)(b0 + b1*v) = a0*b0 + (a0*b1 + a1*b0)*v + a1*b1*v^2
// Since v^2 does NOT reduce in Fp6 (only v^3 = xi), the result has all 3 components.
//
// With Karatsuba on two non-zero terms:
//
//	k0 = a0 * b0                    (1 Fp2 mul)
//	k1 = a1 * b1                    (1 Fp2 mul)
//	k2 = (a0 + a1) * (b0 + b1)     (1 Fp2 mul)
//	r_c0 = k0
//	r_c1 = k2 - k0 - k1
//	r_c2 = k1
//
// Total: 3 Fp2 muls (vs 4 schoolbook).
//
// Inputs: a0, a1, b0, b1 as Fp2 prefixes (preserved via copy). Result: rPrefix (6 Fp slots).
func bn254Fp6MulBothC2ZeroKaratsuba(t *BN254Tracker, a0Prefix, a1Prefix, b0Prefix, b1Prefix, rPrefix string) {
	// k0 = a0 * b0
	bn254Fp2MulCopy(t, a0Prefix, b0Prefix, "_f6kk_k0")

	// k1 = a1 * b1
	bn254Fp2MulCopy(t, a1Prefix, b1Prefix, "_f6kk_k1")

	// k2 = (a0 + a1) * (b0 + b1)
	t.copyToTop(a0Prefix+"_0", "_f6kk_a0c0")
	t.copyToTop(a0Prefix+"_1", "_f6kk_a0c1")
	t.copyToTop(a1Prefix+"_0", "_f6kk_a1c0")
	t.copyToTop(a1Prefix+"_1", "_f6kk_a1c1")
	bn254Fp2AddUnreduced(t, "_f6kk_a0c0", "_f6kk_a0c1", "_f6kk_a1c0", "_f6kk_a1c1",
		"_f6kk_sa_0", "_f6kk_sa_1")

	t.copyToTop(b0Prefix+"_0", "_f6kk_b0c0")
	t.copyToTop(b0Prefix+"_1", "_f6kk_b0c1")
	t.copyToTop(b1Prefix+"_0", "_f6kk_b1c0")
	t.copyToTop(b1Prefix+"_1", "_f6kk_b1c1")
	bn254Fp2AddUnreduced(t, "_f6kk_b0c0", "_f6kk_b0c1", "_f6kk_b1c0", "_f6kk_b1c1",
		"_f6kk_sb_0", "_f6kk_sb_1")

	bn254Fp2Mul(t, "_f6kk_sa_0", "_f6kk_sa_1", "_f6kk_sb_0", "_f6kk_sb_1",
		"_f6kk_k2_0", "_f6kk_k2_1")

	// r_c0 = k0
	t.copyToTop("_f6kk_k0_0", "_f6kk_k0cp0")
	t.copyToTop("_f6kk_k0_1", "_f6kk_k0cp1")
	t.toTop("_f6kk_k0_0")
	t.rename(rPrefix + "_0_0")
	t.toTop("_f6kk_k0_1")
	t.rename(rPrefix + "_0_1")

	// r_c1 = k2 - k0 - k1
	bn254Fp2Sub(t, "_f6kk_k2_0", "_f6kk_k2_1", "_f6kk_k0cp0", "_f6kk_k0cp1",
		"_f6kk_sub1_0", "_f6kk_sub1_1")
	t.copyToTop("_f6kk_k1_0", "_f6kk_k1cp0")
	t.copyToTop("_f6kk_k1_1", "_f6kk_k1cp1")
	bn254Fp2Sub(t, "_f6kk_sub1_0", "_f6kk_sub1_1", "_f6kk_k1cp0", "_f6kk_k1cp1",
		rPrefix+"_1_0", rPrefix+"_1_1")

	// r_c2 = k1
	t.toTop("_f6kk_k1_0")
	t.rename(rPrefix + "_2_0")
	t.toTop("_f6kk_k1_1")
	t.rename(rPrefix + "_2_1")
}

// bn254Fp6MulByC2Zero multiplies Fp6 element a by sparse Fp6 element (b0, b1, 0).
// Given a = (a0, a1, a2) and b = (b0, b1, 0) in Fp2[v]/(v^3 - xi):
//
//	r0 = a0*b0 + xi*a2*b1
//	r1 = a0*b1 + a1*b0
//	r2 = a1*b1 + a2*b0
//
// Total: 6 Fp2 muls (schoolbook).
// Consumes a (6 Fp slots, preserved via copy); b0, b1 (4 Fp slots, preserved via copy).
// Produces r (6 Fp slots).
func bn254Fp6MulByC2Zero(t *BN254Tracker, aPrefix, b0Prefix, b1Prefix, rPrefix string) {
	// r0 = a0*b0 + xi*a2*b1
	bn254Fp2MulCopy(t, aPrefix+"_0", b0Prefix, "_f6c2z_a0b0")
	bn254Fp2MulCopy(t, aPrefix+"_2", b1Prefix, "_f6c2z_a2b1")
	bn254Fp2MulByNonResidue(t, "_f6c2z_a2b1_0", "_f6c2z_a2b1_1", "_f6c2z_xa2b1_0", "_f6c2z_xa2b1_1")
	bn254Fp2Add(t, "_f6c2z_a0b0_0", "_f6c2z_a0b0_1", "_f6c2z_xa2b1_0", "_f6c2z_xa2b1_1",
		rPrefix+"_0_0", rPrefix+"_0_1")

	// r1 = a0*b1 + a1*b0
	bn254Fp2MulCopy(t, aPrefix+"_0", b1Prefix, "_f6c2z_a0b1")
	bn254Fp2MulCopy(t, aPrefix+"_1", b0Prefix, "_f6c2z_a1b0")
	bn254Fp2Add(t, "_f6c2z_a0b1_0", "_f6c2z_a0b1_1", "_f6c2z_a1b0_0", "_f6c2z_a1b0_1",
		rPrefix+"_1_0", rPrefix+"_1_1")

	// r2 = a1*b1 + a2*b0
	bn254Fp2MulCopy(t, aPrefix+"_1", b1Prefix, "_f6c2z_a1b1")
	bn254Fp2MulCopy(t, aPrefix+"_2", b0Prefix, "_f6c2z_a2b0")
	bn254Fp2Add(t, "_f6c2z_a1b1_0", "_f6c2z_a1b1_1", "_f6c2z_a2b0_0", "_f6c2z_a2b0_1",
		rPrefix+"_2_0", rPrefix+"_2_1")
}

// bn254Fp6MulByFp2Copy multiplies Fp6 element by a scalar Fp2 element (b, 0, 0).
// Given a = (a0, a1, a2) and scalar b (Fp2):
//   r = (a0*b, a1*b, a2*b)
// Total: 3 Fp2 muls.
// Preserves both operands via copy; produces r (6 Fp slots).
func bn254Fp6MulByFp2Copy(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	bn254Fp2MulCopy(t, aPrefix+"_0", bPrefix, rPrefix+"_0")
	bn254Fp2MulCopy(t, aPrefix+"_1", bPrefix, rPrefix+"_1")
	bn254Fp2MulCopy(t, aPrefix+"_2", bPrefix, rPrefix+"_2")
}

// bn254Fp12Sqr computes Fp12 squaring (optimized).
// a = (a_a, a_b):
//   t0 = a_a * a_b
//   r_a = (a_a + a_b)*(a_a + v*a_b) - t0 - v*t0
//   r_b = 2*t0
// Consumes 12 Fp slots; produces 12 Fp slots.
func bn254Fp12Sqr(t *BN254Tracker, aPrefix, rPrefix string) {
	// t0 = a_a * a_b
	bn254Fp6MulCopy(t, aPrefix+"_a", aPrefix+"_b", "_f12s_t0")

	// v*a_b
	bn254Fp6CopyPrefix(t, aPrefix+"_b", "_f12s_abv")
	bn254Fp6MulByNonResidue(t, "_f12s_abv", "_f12s_vab")

	// sum1 = a_a + a_b (unreduced: feeds directly into Fp6Mul below)
	// OPTIMIZATION: Move a_b (last use) instead of copying
	bn254Fp6CopyPrefix(t, aPrefix+"_a", "_f12s_aa1")
	bn254Fp6RenamePrefix(t, aPrefix+"_b", "_f12s_ab1")
	bn254Fp6AddUnreduced(t, "_f12s_aa1", "_f12s_ab1", "_f12s_sum1")

	// sum2 = a_a + v*a_b (unreduced: feeds directly into Fp6Mul below)
	// OPTIMIZATION: Move a_a (last use) instead of copying
	bn254Fp6RenamePrefix(t, aPrefix+"_a", "_f12s_aa2")
	bn254Fp6AddUnreduced(t, "_f12s_aa2", "_f12s_vab", "_f12s_sum2")

	// prod = sum1 * sum2
	bn254Fp6Mul(t, "_f12s_sum1", "_f12s_sum2", "_f12s_prod")

	// v*t0
	bn254Fp6CopyPrefix(t, "_f12s_t0", "_f12s_t0v")
	bn254Fp6MulByNonResidue(t, "_f12s_t0v", "_f12s_vt0")

	// r_a = prod - t0 - v*t0
	bn254Fp6CopyPrefix(t, "_f12s_t0", "_f12s_t0a")
	bn254Fp6Sub(t, "_f12s_prod", "_f12s_t0a", "_f12s_sub1")
	bn254Fp6Sub(t, "_f12s_sub1", "_f12s_vt0", rPrefix+"_a")

	// r_b = 2*t0
	bn254Fp6CopyPrefix(t, "_f12s_t0", "_f12s_t0b")
	bn254Fp6Add(t, "_f12s_t0", "_f12s_t0b", rPrefix+"_b")

	// Inputs a_a and a_b were consumed by rename above — no cleanup needed.
}

// bn254Fp12Conjugate computes (a, -b).
// Consumes 12 Fp slots; produces 12 Fp slots.
func bn254Fp12Conjugate(t *BN254Tracker, aPrefix, rPrefix string) {
	// r_a = a_a (rename)
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.toTop(aPrefix + "_a_" + sfx + "_0")
		t.rename(rPrefix + "_a_" + sfx + "_0")
		t.toTop(aPrefix + "_a_" + sfx + "_1")
		t.rename(rPrefix + "_a_" + sfx + "_1")
	}
	// r_b = -a_b
	bn254Fp6Neg(t, aPrefix+"_b", rPrefix+"_b")
}

// bn254Fp12Inv computes Fp12 multiplicative inverse.
// For a = (a_a, a_b): norm = a_a^2 - v*a_b^2, inv = norm^(-1)
// r_a = a_a * inv, r_b = -a_b * inv.
// Consumes 12 Fp slots; produces 12 Fp slots.
func bn254Fp12Inv(t *BN254Tracker, aPrefix, rPrefix string) {
	// t0 = a_a^2  (Fp6 squaring via self-mul)
	bn254Fp6MulCopy(t, aPrefix+"_a", aPrefix+"_a", "_f12i_aa2")

	// t1 = a_b^2
	bn254Fp6MulCopy(t, aPrefix+"_b", aPrefix+"_b", "_f12i_ab2")

	// v*t1
	bn254Fp6MulByNonResidue(t, "_f12i_ab2", "_f12i_vab2")

	// norm = t0 - v*t1
	bn254Fp6Sub(t, "_f12i_aa2", "_f12i_vab2", "_f12i_norm")

	// inv = norm^(-1) — Fp6 inverse via Fp2 operations
	// For simplicity, compute Fp6 inverse inline:
	// norm = (n0, n1, n2) in Fp2[v]/(v^3 - ξ)
	// This requires a full Fp6 inversion which is complex.
	// We use the formula: if n = (n0, n1, n2), then
	//   A = n0^2 - ξ*n1*n2
	//   B = ξ*n2^2 - n0*n1
	//   C = n1^2 - n0*n2
	//   F = ξ*n2*C + n0*A + ξ*n1*B ... actually this simplifies to:
	//   det = n0*A + ξ*(n2*B + n1*C)
	//   inv = (A/det, B/det, C/det)
	bn254Fp6Inv(t, "_f12i_norm", "_f12i_inv")

	// r_a = a_a * inv
	bn254Fp6MulCopy(t, aPrefix+"_a", "_f12i_inv", "_f12i_ra")
	// Rename to result
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.toTop("_f12i_ra_" + sfx + "_0")
		t.rename(rPrefix + "_a_" + sfx + "_0")
		t.toTop("_f12i_ra_" + sfx + "_1")
		t.rename(rPrefix + "_a_" + sfx + "_1")
	}

	// r_b = -(a_b * inv)
	bn254Fp6MulCopy(t, aPrefix+"_b", "_f12i_inv", "_f12i_rb")
	bn254Fp6Neg(t, "_f12i_rb", rPrefix+"_b")

	// Clean up inv and inputs
	bn254Fp6DropPrefix(t, "_f12i_inv")
	bn254Fp12DropInputs(t, aPrefix)
}

// bn254Fp6Inv computes the multiplicative inverse of an Fp6 element.
// Given n = (n0, n1, n2) in Fp2[v]/(v^3 - ξ):
//   A = n0^2 - ξ*n1*n2
//   B = ξ*n2^2 - n0*n1
//   C = n1^2 - n0*n2
//   det = n0*A + ξ*(n2*B + n1*C)
//   inv = (A/det, B/det, C/det)
// Consumes 6 Fp slots; produces 6 Fp slots.
func bn254Fp6Inv(t *BN254Tracker, prefix, rPrefix string) {
	// A = n0^2 - ξ*n1*n2
	bn254Fp2SqrCopy(t, prefix+"_0", "_f6i_n0sq")
	bn254Fp2MulCopy(t, prefix+"_1", prefix+"_2", "_f6i_n1n2")
	bn254Fp2MulByNonResidue(t, "_f6i_n1n2_0", "_f6i_n1n2_1", "_f6i_xn1n2_0", "_f6i_xn1n2_1")
	bn254Fp2Sub(t, "_f6i_n0sq_0", "_f6i_n0sq_1", "_f6i_xn1n2_0", "_f6i_xn1n2_1", "_f6i_A_0", "_f6i_A_1")

	// B = ξ*n2^2 - n0*n1
	bn254Fp2SqrCopy(t, prefix+"_2", "_f6i_n2sq")
	bn254Fp2MulByNonResidue(t, "_f6i_n2sq_0", "_f6i_n2sq_1", "_f6i_xn2sq_0", "_f6i_xn2sq_1")
	bn254Fp2MulCopy(t, prefix+"_0", prefix+"_1", "_f6i_n0n1")
	bn254Fp2Sub(t, "_f6i_xn2sq_0", "_f6i_xn2sq_1", "_f6i_n0n1_0", "_f6i_n0n1_1", "_f6i_B_0", "_f6i_B_1")

	// C = n1^2 - n0*n2
	bn254Fp2SqrCopy(t, prefix+"_1", "_f6i_n1sq")
	bn254Fp2MulCopy(t, prefix+"_0", prefix+"_2", "_f6i_n0n2")
	bn254Fp2Sub(t, "_f6i_n1sq_0", "_f6i_n1sq_1", "_f6i_n0n2_0", "_f6i_n0n2_1", "_f6i_C_0", "_f6i_C_1")

	// det = n0*A + ξ*(n2*B + n1*C)
	bn254Fp2MulCopy(t, prefix+"_0", "_f6i_A", "_f6i_n0A")
	bn254Fp2MulCopy(t, prefix+"_2", "_f6i_B", "_f6i_n2B")
	bn254Fp2MulCopy(t, prefix+"_1", "_f6i_C", "_f6i_n1C")
	// cross = n2B + n1C (unreduced: feeds directly into MulByNonResidue
	// which applies FieldMulConst -> FieldMod)
	bn254Fp2AddUnreduced(t, "_f6i_n2B_0", "_f6i_n2B_1", "_f6i_n1C_0", "_f6i_n1C_1", "_f6i_cross_0", "_f6i_cross_1")
	bn254Fp2MulByNonResidue(t, "_f6i_cross_0", "_f6i_cross_1", "_f6i_xcross_0", "_f6i_xcross_1")
	// det = n0A + xcross (unreduced: feeds directly into Fp2Inv which
	// starts with FieldSqr -> FieldMul -> FieldMod)
	bn254Fp2AddUnreduced(t, "_f6i_n0A_0", "_f6i_n0A_1", "_f6i_xcross_0", "_f6i_xcross_1", "_f6i_det_0", "_f6i_det_1")

	// det_inv = det^(-1)
	bn254Fp2Inv(t, "_f6i_det_0", "_f6i_det_1", "_f6i_di_0", "_f6i_di_1")

	// r0 = A * det_inv
	t.copyToTop("_f6i_A_0", "_f6i_Ac0")
	t.copyToTop("_f6i_A_1", "_f6i_Ac1")
	t.copyToTop("_f6i_di_0", "_f6i_dic0")
	t.copyToTop("_f6i_di_1", "_f6i_dic1")
	bn254Fp2Mul(t, "_f6i_Ac0", "_f6i_Ac1", "_f6i_dic0", "_f6i_dic1", rPrefix+"_0_0", rPrefix+"_0_1")

	// r1 = B * det_inv
	t.copyToTop("_f6i_B_0", "_f6i_Bc0")
	t.copyToTop("_f6i_B_1", "_f6i_Bc1")
	t.copyToTop("_f6i_di_0", "_f6i_dic2")
	t.copyToTop("_f6i_di_1", "_f6i_dic3")
	bn254Fp2Mul(t, "_f6i_Bc0", "_f6i_Bc1", "_f6i_dic2", "_f6i_dic3", rPrefix+"_1_0", rPrefix+"_1_1")

	// r2 = C * det_inv
	t.copyToTop("_f6i_C_0", "_f6i_Cc0")
	t.copyToTop("_f6i_C_1", "_f6i_Cc1")
	bn254Fp2Mul(t, "_f6i_Cc0", "_f6i_Cc1", "_f6i_di_0", "_f6i_di_1", rPrefix+"_2_0", rPrefix+"_2_1")

	// Clean up: A, B, C and input prefix
	bn254DropNames(t, []string{"_f6i_A_0", "_f6i_A_1", "_f6i_B_0", "_f6i_B_1", "_f6i_C_0", "_f6i_C_1"})
	bn254Fp6DropPrefix(t, prefix)
}

// ===========================================================================
// Fp12 Frobenius endomorphism
// ===========================================================================
//
// The Frobenius map π_p on Fp12 = Fp6[w]/(w^2 - v), Fp6 = Fp2[v]/(v^3 - ξ):
//   For a = (a_a, a_b) where a_a = (a0, a1, a2), a_b = (b0, b1, b2):
//   π(a) = (conj(a0) + conj(a1)*γ_12 + conj(a2)*γ_14,
//            (conj(b0)*γ_11 + conj(b1)*γ_13 + conj(b2)*γ_15) )
// where γ_ij are precomputed Fp2 constants (Frobenius coefficients).
//
// The Frobenius coefficients for BN254 are well-known constants.
// For the pairing we need π (Frobenius^1) and π^2 (Frobenius^2).
//
// Frobenius coefficients (γ_{1,*} and γ_{2,*}) are precomputed in init() below.
// Verified against gnark-crypto: Frobenius composition, γ_{2,3}=p-1, and
// Frobenius^12=identity all confirmed.

// bn254Fp12FrobeniusP computes the p-power Frobenius endomorphism on Fp12.
// Applies conjugation to each Fp2 coefficient and multiplies by the
// appropriate Frobenius γ_{1,*} coefficients.
//
// The γ constants are verified by TestBN254_FrobeniusCoefficients which checks:
// (1) γ_{2,3} = p - 1, (2) γ_{2,*} are within Fp, (3) Frobenius composition.
func bn254Fp12FrobeniusP(t *BN254Tracker, aPrefix, rPrefix string) {
	// For BN254, Frobenius on Fp2 is just conjugation: (a0, a1) -> (a0, -a1)
	// The full Frobenius on Fp12 multiplies each Fp2 coefficient by γ constants.

	// a_a part: conj(a0), conj(a1)*γ_12, conj(a2)*γ_14
	// Component 0: just conjugate
	bn254Fp2Conjugate(t,
		aPrefix+"_a_0_0", aPrefix+"_a_0_1",
		rPrefix+"_a_0_0", rPrefix+"_a_0_1")
	// Component 1: conjugate then multiply by γ_12
	bn254Fp2Conjugate(t,
		aPrefix+"_a_1_0", aPrefix+"_a_1_1",
		"_frob_ca1_0", "_frob_ca1_1")
	bn254Fp2MulByFrobCoeff(t, "_frob_ca1", bn254Gamma12, rPrefix+"_a_1")
	// Component 2: conjugate then multiply by γ_14
	bn254Fp2Conjugate(t,
		aPrefix+"_a_2_0", aPrefix+"_a_2_1",
		"_frob_ca2_0", "_frob_ca2_1")
	bn254Fp2MulByFrobCoeff(t, "_frob_ca2", bn254Gamma14, rPrefix+"_a_2")

	// a_b part: conj(b0)*γ_11, conj(b1)*γ_13, conj(b2)*γ_15
	bn254Fp2Conjugate(t,
		aPrefix+"_b_0_0", aPrefix+"_b_0_1",
		"_frob_cb0_0", "_frob_cb0_1")
	bn254Fp2MulByFrobCoeff(t, "_frob_cb0", bn254Gamma11, rPrefix+"_b_0")

	bn254Fp2Conjugate(t,
		aPrefix+"_b_1_0", aPrefix+"_b_1_1",
		"_frob_cb1_0", "_frob_cb1_1")
	bn254Fp2MulByFrobCoeff(t, "_frob_cb1", bn254Gamma13, rPrefix+"_b_1")

	bn254Fp2Conjugate(t,
		aPrefix+"_b_2_0", aPrefix+"_b_2_1",
		"_frob_cb2_0", "_frob_cb2_1")
	bn254Fp2MulByFrobCoeff(t, "_frob_cb2", bn254Gamma15, rPrefix+"_b_2")
}

// bn254Fp12FrobeniusP2 computes the p^2-power Frobenius endomorphism on Fp12.
// For p^2 Frobenius, conjugation is identity on Fp2, so we only multiply
// by the squared Frobenius coefficients.
func bn254Fp12FrobeniusP2(t *BN254Tracker, aPrefix, rPrefix string) {
	// Component 0 of each Fp6 part is unchanged
	t.toTop(aPrefix + "_a_0_0")
	t.rename(rPrefix + "_a_0_0")
	t.toTop(aPrefix + "_a_0_1")
	t.rename(rPrefix + "_a_0_1")

	// a_a component 1: multiply by γ_12^2
	bn254Fp2MulByFrobCoeff(t, aPrefix+"_a_1", bn254Gamma12Sq, rPrefix+"_a_1")
	// a_a component 2: multiply by γ_14^2
	bn254Fp2MulByFrobCoeff(t, aPrefix+"_a_2", bn254Gamma14Sq, rPrefix+"_a_2")

	// a_b component 0: multiply by γ_11^2
	bn254Fp2MulByFrobCoeff(t, aPrefix+"_b_0", bn254Gamma11Sq, rPrefix+"_b_0")
	// a_b component 1: multiply by γ_13^2
	bn254Fp2MulByFrobCoeff(t, aPrefix+"_b_1", bn254Gamma13Sq, rPrefix+"_b_1")
	// a_b component 2: multiply by γ_15^2
	bn254Fp2MulByFrobCoeff(t, aPrefix+"_b_2", bn254Gamma15Sq, rPrefix+"_b_2")
}

// bn254Fp2MulByFrobCoeff multiplies Fp2 element by a constant Fp2 element (Frobenius coefficient).
// When the coefficient has c1=0 (an Fp element embedded in Fp2), uses the cheaper
// scalar multiply path (2 FieldMul vs 3 FieldMulUnreduced + 2 FieldMod).
// Consumes aPrefix_0, aPrefix_1; produces rPrefix_0, rPrefix_1.
func bn254Fp2MulByFrobCoeff(t *BN254Tracker, aPrefix string, coeff [2]*big.Int, rPrefix string) {
	if t.qAtBottom {
		bn254Fp2MulByFrobCoeffFlat(t, aPrefix, coeff, rPrefix)
		return
	}
	// Original tracker-based implementation
	if coeff[1].Sign() == 0 {
		t.pushBigInt("_fcoeff_0", coeff[0])
		t.copyToTop(aPrefix+"_0", "_fcoeff_a0")
		t.copyToTop("_fcoeff_0", "_fcoeff_0c")
		bn254FieldMul(t, "_fcoeff_a0", "_fcoeff_0c", rPrefix+"_0")
		bn254FieldMul(t, aPrefix+"_1", "_fcoeff_0", rPrefix+"_1")
		return
	}
	t.pushBigInt("_fcoeff_0", coeff[0])
	t.pushBigInt("_fcoeff_1", coeff[1])
	bn254Fp2Mul(t,
		aPrefix+"_0", aPrefix+"_1",
		"_fcoeff_0", "_fcoeff_1",
		rPrefix+"_0", rPrefix+"_1")
}

// ===========================================================================
// Frobenius coefficients for BN254
// ===========================================================================
//
// These are the standard Frobenius coefficients γ_{i,j} for BN254 (alt_bn128).
// γ_{1,1} through γ_{1,5} are for Frobenius π_p.
// The squared versions are for π_{p^2}.
//
// Computed as: γ_{1,k} = ξ^((p^k - 1) / d) where d depends on the tower level.

var (
	// Frobenius π_p coefficients (Fp2 elements)
	bn254Gamma11 [2]*big.Int // γ_{1,1}: coeff for w term, Fp6 component 0
	bn254Gamma12 [2]*big.Int // γ_{1,2}: coeff for v term, Fp6 component 1
	bn254Gamma13 [2]*big.Int // γ_{1,3}: coeff for w*v term
	bn254Gamma14 [2]*big.Int // γ_{1,4}: coeff for v^2 term
	bn254Gamma15 [2]*big.Int // γ_{1,5}: coeff for w*v^2 term

	// Frobenius π_{p^2} coefficients (Fp elements embedded as Fp2 with c1=0)
	bn254Gamma11Sq [2]*big.Int
	bn254Gamma12Sq [2]*big.Int
	bn254Gamma13Sq [2]*big.Int
	bn254Gamma14Sq [2]*big.Int
	bn254Gamma15Sq [2]*big.Int
)

// mustParseBig parses a decimal big.Int string, panicking on failure.
func mustParseBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bn254_ext: failed to parse constant: " + s[:min(len(s), 20)])
	}
	return n
}

func init() {
	// BN254 Frobenius coefficients.
	// These are the standard values for the alt_bn128/BN254 curve.
	// Reference: https://eprint.iacr.org/2010/354, gnark-crypto, py_ecc

	// γ_{1,1} = ξ^((p-1)/6) where ξ = 9+u
	// γ_{1,k} = ξ^(k*(p-1)/6), for k = 1..5. These are E2 (Fp2) elements.
	// Values verified against gnark-crypto's MulByNonResidue1PowerK (k=1..5)
	// by emitting (1, 0) through each function — they match exactly.
	//
	// γ_{1,1} = ξ^((p-1)/6)
	bn254Gamma11[0] = mustParseBig("8376118865763821496583973867626364092589906065868298776909617916018768340080")
	bn254Gamma11[1] = mustParseBig("16469823323077808223889137241176536799009286646108169935659301613961712198316")

	// γ_{1,2} = ξ^((p-1)/3)
	bn254Gamma12[0] = mustParseBig("21575463638280843010398324269430826099269044274347216827212613867836435027261")
	bn254Gamma12[1] = mustParseBig("10307601595873709700152284273816112264069230130616436755625194854815875713954")

	// γ_{1,3} = ξ^((p-1)/2)
	bn254Gamma13[0] = mustParseBig("2821565182194536844548159561693502659359617185244120367078079554186484126554")
	bn254Gamma13[1] = mustParseBig("3505843767911556378687030309984248845540243509899259641013678093033130930403")

	// γ_{1,4} = ξ^(2*(p-1)/3)
	bn254Gamma14[0] = mustParseBig("2581911344467009335267311115468803099551665605076196740867805258568234346338")
	bn254Gamma14[1] = mustParseBig("19937756971775647987995932169929341994314640652964949448313374472400716661030")

	// γ_{1,5} = ξ^(5*(p-1)/6)
	bn254Gamma15[0] = mustParseBig("685108087231508774477564247770172212460312782337200605669322048753928464687")
	bn254Gamma15[1] = mustParseBig("8447204650696766136447902020341177575205426561248465145919723016860428151883")

	// π_{p^2} coefficients: these are Fp elements (c1 = 0).
	// These values are verified against gnark-crypto's
	// ecc/bn254/internal/fptower/frobenius.go:MulByNonResidue2PowerK (k=1..5)
	// — gnark's Power_k constant equals ξ^(k·(p²-1)/6), the formal definition
	// of γ_{2,k}. Both are pure Fp (c1 = 0).
	//
	// γ_{2,1} = ξ^((p^2-1)/6)  — gnark's MulByNonResidue2Power1 constant.
	bn254Gamma11Sq[0] = mustParseBig("21888242871839275220042445260109153167277707414472061641714758635765020556617")
	bn254Gamma11Sq[1] = big.NewInt(0)

	// γ_{2,2} = ξ^((p^2-1)/3)  — gnark's MulByNonResidue2Power2 constant.
	bn254Gamma12Sq[0] = mustParseBig("21888242871839275220042445260109153167277707414472061641714758635765020556616")
	bn254Gamma12Sq[1] = big.NewInt(0)

	// γ_{2,3} = ξ^((p^2-1)/2) = p - 1
	bn254Gamma13Sq[0] = mustParseBig("21888242871839275222246405745257275088696311157297823662689037894645226208582")
	bn254Gamma13Sq[1] = big.NewInt(0)

	// γ_{2,4} = ξ^(2*(p^2-1)/3)
	bn254Gamma14Sq[0] = mustParseBig("2203960485148121921418603742825762020974279258880205651966")
	bn254Gamma14Sq[1] = big.NewInt(0)

	// γ_{2,5} = ξ^(5*(p^2-1)/6)
	bn254Gamma15Sq[0] = mustParseBig("2203960485148121921418603742825762020974279258880205651967")
	bn254Gamma15Sq[1] = big.NewInt(0)
}

// ===========================================================================
// Helper functions for Fp6/Fp12 operations
// ===========================================================================

// bn254Fp6RenamePrefix renames all 6 Fp slots of an Fp6 element in-place.
// No stack operations are emitted — this is a pure tracker rename.
func bn254Fp6RenamePrefix(t *BN254Tracker, srcPrefix, dstPrefix string) {
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		for j := len(t.nm) - 1; j >= 0; j-- {
			if t.nm[j] == srcPrefix+"_"+sfx+"_0" {
				t.nm[j] = dstPrefix + "_" + sfx + "_0"
				break
			}
		}
		for j := len(t.nm) - 1; j >= 0; j-- {
			if t.nm[j] == srcPrefix+"_"+sfx+"_1" {
				t.nm[j] = dstPrefix + "_" + sfx + "_1"
				break
			}
		}
	}
}

// bn254Fp6CopyPrefix copies all 6 Fp slots of an Fp6 element to new names.
func bn254Fp6CopyPrefix(t *BN254Tracker, srcPrefix, dstPrefix string) {
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.copyToTop(srcPrefix+"_"+sfx+"_0", dstPrefix+"_"+sfx+"_0")
		t.copyToTop(srcPrefix+"_"+sfx+"_1", dstPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6DropPrefix drops all 6 Fp slots of an Fp6 element.
func bn254Fp6DropPrefix(t *BN254Tracker, prefix string) {
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.toTop(prefix + "_" + sfx + "_0")
		t.drop()
		t.toTop(prefix + "_" + sfx + "_1")
		t.drop()
	}
}

// bn254Fp12DropInputs drops all 12 Fp slots of an Fp12 element.
func bn254Fp12DropInputs(t *BN254Tracker, prefix string) {
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop(prefix + part + "_" + sfx + "_0")
			t.drop()
			t.toTop(prefix + part + "_" + sfx + "_1")
			t.drop()
		}
	}
}

// bn254Fp6MulCopy performs Fp6 multiplication preserving the original operands.
// It copies both operands before multiplying.
func bn254Fp6MulCopy(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	bn254Fp6CopyPrefix(t, aPrefix, "_f6mc_a")
	bn254Fp6CopyPrefix(t, bPrefix, "_f6mc_b")
	bn254Fp6Mul(t, "_f6mc_a", "_f6mc_b", rPrefix)
}

// ===========================================================================
// Fp12 exponentiation by BN254 parameter x
// ===========================================================================
//
// BN254 parameter: x = 4965661367192848881 (0x44E992B44A6909F1)
// Used in final exponentiation hard part.

// bn254Fp12ExpByX computes f^x using square-and-multiply over Fp12.
// x = 4965661367192848881, which is 63 bits.
// Consumes 12 Fp slots; produces 12 Fp slots.
func bn254Fp12ExpByX(t *BN254Tracker, aPrefix, rPrefix string) {
	// Compute xBits from bn254X (MSB first) for square-and-multiply.
	xBits := make([]int, bn254X.BitLen())
	for i := 0; i < bn254X.BitLen(); i++ {
		xBits[bn254X.BitLen()-1-i] = int(bn254X.Bit(i))
	}

	// Find first set bit
	startIdx := -1
	for i, b := range xBits {
		if b == 1 {
			startIdx = i
			break
		}
	}

	// Init: result = a (copy)
	bn254Fp12CopyPrefix(t, aPrefix, "_expx_r")

	// Process remaining bits
	for i := startIdx + 1; i < len(xBits); i++ {
		// Square
		bn254Fp12Sqr(t, "_expx_r", "_expx_sq")
		bn254Fp12RenamePrefix(t, "_expx_sq", "_expx_r")

		if xBits[i] == 1 {
			// Multiply by a
			bn254Fp12CopyPrefix(t, aPrefix, "_expx_ac")
			bn254Fp12Mul(t, "_expx_r", "_expx_ac", "_expx_mr")
			bn254Fp12RenamePrefix(t, "_expx_mr", "_expx_r")
		}
	}

	// Rename result
	bn254Fp12RenamePrefix(t, "_expx_r", rPrefix)

	// Clean up input
	bn254Fp12DropInputs(t, aPrefix)
}

// ===========================================================================
// More Fp12 helpers
// ===========================================================================

// bn254Fp12CopyPrefix copies all 12 Fp slots.
func bn254Fp12CopyPrefix(t *BN254Tracker, srcPrefix, dstPrefix string) {
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.copyToTop(srcPrefix+part+"_"+sfx+"_0", dstPrefix+part+"_"+sfx+"_0")
			t.copyToTop(srcPrefix+part+"_"+sfx+"_1", dstPrefix+part+"_"+sfx+"_1")
		}
	}
}

// bn254Fp12RenamePrefix renames all 12 Fp slots from one prefix to another.
func bn254Fp12RenamePrefix(t *BN254Tracker, srcPrefix, dstPrefix string) {
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop(srcPrefix + part + "_" + sfx + "_0")
			t.rename(dstPrefix + part + "_" + sfx + "_0")
			t.toTop(srcPrefix + part + "_" + sfx + "_1")
			t.rename(dstPrefix + part + "_" + sfx + "_1")
		}
	}
}

// bn254Fp12SetOne sets an Fp12 element to 1 (= (1,0,0,0,0,0,0,0,0,0,0,0)).
// Produces 12 Fp slots.
func bn254Fp12SetOne(t *BN254Tracker, prefix string) {
	// a_0_0 = 1, everything else = 0
	t.pushInt(prefix+"_a_0_0", 1)
	t.pushInt(prefix+"_a_0_1", 0)
	t.pushInt(prefix+"_a_1_0", 0)
	t.pushInt(prefix+"_a_1_1", 0)
	t.pushInt(prefix+"_a_2_0", 0)
	t.pushInt(prefix+"_a_2_1", 0)
	t.pushInt(prefix+"_b_0_0", 0)
	t.pushInt(prefix+"_b_0_1", 0)
	t.pushInt(prefix+"_b_1_0", 0)
	t.pushInt(prefix+"_b_1_1", 0)
	t.pushInt(prefix+"_b_2_0", 0)
	t.pushInt(prefix+"_b_2_1", 0)
}
