// Ext4 macro layer for the SP1 FRI verifier codegen.
//
// Each macro operates on a parent KBTracker by reading 4 named base-field
// coefficients (`aPrefix_0`..`aPrefix_3`) and producing 4 named output
// coefficients (`outPrefix_0`..`outPrefix_3`). The original input slots are
// preserved (the macros use `copyToTop` rather than `toTop`) so the same
// inputs can be reused across multiple Ext4 ops without re-staging.
//
// Composition pattern mirrors the existing kbField{Add,Sub,Mul,Inv} ladder
// in `koalabear.go`: every intermediate is a uniquely-named slot that the
// tracker walks via `findDepth`/`roll`. The macros never assume any
// particular runtime stack position for their inputs — they look them up
// by name. This is essential because the FRI per-query loop interleaves
// many Ext4 ops with sibling-digest pushes, and the runtime stack shape is
// deeply nested.
//
// Reference algebra (binomial extension F_p[X]/(X^4 - W) with W = 3):
//
//   add: r_i = a_i + b_i
//   sub: r_i = a_i - b_i
//   mul: r0 = a0 b0 + W (a1 b3 + a2 b2 + a3 b1)
//        r1 = a0 b1 + a1 b0 + W (a2 b3 + a3 b2)
//        r2 = a0 b2 + a1 b1 + a2 b0 + W a3 b3
//        r3 = a0 b3 + a1 b2 + a2 b1 + a3 b0
//   inv: see kbExt4InvComponent in koalabear.go (tower of quadratic extensions).
//
// Mirrors `packages/runar-go/sp1fri/koalabear.go::Ext4{Add,Sub,Mul,Inv}`.
package codegen

import "fmt"

// kbExt4Add computes c = a + b over Ext4 by component-wise base-field add.
//
// Reads `aPrefix_0..3` and `bPrefix_0..3`, writes `outPrefix_0..3`. Inputs
// are preserved on the stack (copied not consumed).
func kbExt4Add(t *KBTracker, aPrefix, bPrefix, outPrefix string) {
	for i := 0; i < 4; i++ {
		aName := fmt.Sprintf("%s_%d", aPrefix, i)
		bName := fmt.Sprintf("%s_%d", bPrefix, i)
		// Copy both onto the top so kbFieldAdd's toTop calls don't disturb the originals.
		t.copyToTop(aName, "_e4add_a")
		t.copyToTop(bName, "_e4add_b")
		kbFieldAdd(t, "_e4add_a", "_e4add_b", fmt.Sprintf("%s_%d", outPrefix, i))
	}
}

// kbExt4Sub computes c = a - b over Ext4 by component-wise base-field sub.
func kbExt4Sub(t *KBTracker, aPrefix, bPrefix, outPrefix string) {
	for i := 0; i < 4; i++ {
		aName := fmt.Sprintf("%s_%d", aPrefix, i)
		bName := fmt.Sprintf("%s_%d", bPrefix, i)
		t.copyToTop(aName, "_e4sub_a")
		t.copyToTop(bName, "_e4sub_b")
		kbFieldSub(t, "_e4sub_a", "_e4sub_b", fmt.Sprintf("%s_%d", outPrefix, i))
	}
}

// kbExt4Mul computes c = a * b over Ext4 = F[X]/(X^4 - W), W = 3.
//
// Reads `aPrefix_0..3` and `bPrefix_0..3`, writes `outPrefix_0..3`. Inputs
// are preserved.
//
// Each component uses base-field muls + adds composed via the existing
// kbFieldMul/Add helpers — no calls into kbExt4MulComponent (which expects
// a fresh isolated tracker).
func kbExt4Mul(t *KBTracker, aPrefix, bPrefix, outPrefix string) {
	an := func(i int) string { return fmt.Sprintf("%s_%d", aPrefix, i) }
	bn := func(i int) string { return fmt.Sprintf("%s_%d", bPrefix, i) }

	mulCopy := func(aIdx, bIdx int, outName string) {
		t.copyToTop(an(aIdx), "_e4m_a")
		t.copyToTop(bn(bIdx), "_e4m_b")
		kbFieldMul(t, "_e4m_a", "_e4m_b", outName)
	}

	// r0 = a0 b0 + W (a1 b3 + a2 b2 + a3 b1)
	mulCopy(0, 0, "_e4m_t00")
	mulCopy(1, 3, "_e4m_t13")
	mulCopy(2, 2, "_e4m_t22")
	mulCopy(3, 1, "_e4m_t31")
	kbFieldAdd(t, "_e4m_t13", "_e4m_t22", "_e4m_s12")
	kbFieldAdd(t, "_e4m_s12", "_e4m_t31", "_e4m_cross0")
	kbFieldMulConst(t, "_e4m_cross0", kbFieldW, "_e4m_wcross0")
	kbFieldAdd(t, "_e4m_t00", "_e4m_wcross0", fmt.Sprintf("%s_0", outPrefix))

	// r1 = a0 b1 + a1 b0 + W (a2 b3 + a3 b2)
	mulCopy(0, 1, "_e4m_t01")
	mulCopy(1, 0, "_e4m_t10")
	kbFieldAdd(t, "_e4m_t01", "_e4m_t10", "_e4m_d1")
	mulCopy(2, 3, "_e4m_t23")
	mulCopy(3, 2, "_e4m_t32")
	kbFieldAdd(t, "_e4m_t23", "_e4m_t32", "_e4m_cross1")
	kbFieldMulConst(t, "_e4m_cross1", kbFieldW, "_e4m_wcross1")
	kbFieldAdd(t, "_e4m_d1", "_e4m_wcross1", fmt.Sprintf("%s_1", outPrefix))

	// r2 = a0 b2 + a1 b1 + a2 b0 + W a3 b3
	mulCopy(0, 2, "_e4m_t02")
	mulCopy(1, 1, "_e4m_t11")
	kbFieldAdd(t, "_e4m_t02", "_e4m_t11", "_e4m_s01_2")
	mulCopy(2, 0, "_e4m_t20")
	kbFieldAdd(t, "_e4m_s01_2", "_e4m_t20", "_e4m_d2")
	mulCopy(3, 3, "_e4m_t33")
	kbFieldMulConst(t, "_e4m_t33", kbFieldW, "_e4m_wcross2")
	kbFieldAdd(t, "_e4m_d2", "_e4m_wcross2", fmt.Sprintf("%s_2", outPrefix))

	// r3 = a0 b3 + a1 b2 + a2 b1 + a3 b0
	mulCopy(0, 3, "_e4m_t03")
	mulCopy(1, 2, "_e4m_t12")
	kbFieldAdd(t, "_e4m_t03", "_e4m_t12", "_e4m_s01_3")
	mulCopy(2, 1, "_e4m_t21")
	kbFieldAdd(t, "_e4m_s01_3", "_e4m_t21", "_e4m_s012_3")
	mulCopy(3, 0, "_e4m_t30")
	kbFieldAdd(t, "_e4m_s012_3", "_e4m_t30", fmt.Sprintf("%s_3", outPrefix))
}

// kbExt4ScalarMul computes c = a * s where s is a base-field scalar (named
// `sName`). Reads `aPrefix_0..3` + `sName`, writes `outPrefix_0..3`. Inputs
// preserved.
func kbExt4ScalarMul(t *KBTracker, aPrefix, sName, outPrefix string) {
	for i := 0; i < 4; i++ {
		t.copyToTop(fmt.Sprintf("%s_%d", aPrefix, i), "_e4s_a")
		t.copyToTop(sName, "_e4s_s")
		kbFieldMul(t, "_e4s_a", "_e4s_s", fmt.Sprintf("%s_%d", outPrefix, i))
	}
}

// kbExt4Inv computes c = a^{-1} over Ext4. Reads `aPrefix_0..3`, writes
// `outPrefix_0..3`. Inputs preserved.
//
// Mirrors the algebra in koalabear.go::kbExt4InvComponent but composes
// macros directly so the parent tracker stays consistent. Algorithm
// (tower of quadratic extensions, F[X]/(X^4 - W)):
//
//	norm0 = a0^2 + W a2^2 - 2 W a1 a3
//	norm1 = 2 a0 a2 - a1^2 - W a3^2
//	det   = norm0^2 - W norm1^2
//	scalar = det^{-1}
//	invN0  = norm0 * scalar
//	invN1  = -norm1 * scalar
//	r0 =  a0 invN0 + W a2 invN1
//	r1 = -(a1 invN0 + W a3 invN1)
//	r2 =  a0 invN1 + a2 invN0
//	r3 = -(a1 invN1 + a3 invN0)
func kbExt4Inv(t *KBTracker, aPrefix, outPrefix string) {
	an := func(i int) string { return fmt.Sprintf("%s_%d", aPrefix, i) }

	// norm0 = a0^2 + W a2^2 - 2 W a1 a3
	t.copyToTop(an(0), "_e4i_a0c")
	kbFieldSqr(t, "_e4i_a0c", "_e4i_a0sq")
	t.copyToTop(an(2), "_e4i_a2c")
	kbFieldSqr(t, "_e4i_a2c", "_e4i_a2sq")
	kbFieldMulConst(t, "_e4i_a2sq", kbFieldW, "_e4i_wa2sq")
	kbFieldAdd(t, "_e4i_a0sq", "_e4i_wa2sq", "_e4i_n0a")
	t.copyToTop(an(1), "_e4i_a1c")
	t.copyToTop(an(3), "_e4i_a3c")
	kbFieldMul(t, "_e4i_a1c", "_e4i_a3c", "_e4i_a1a3")
	kbFieldMulConst(t, "_e4i_a1a3", 2*kbFieldW, "_e4i_2wa1a3")
	kbFieldSub(t, "_e4i_n0a", "_e4i_2wa1a3", "_e4i_norm0")

	// norm1 = 2 a0 a2 - a1^2 - W a3^2
	t.copyToTop(an(0), "_e4i_a0d")
	t.copyToTop(an(2), "_e4i_a2d")
	kbFieldMul(t, "_e4i_a0d", "_e4i_a2d", "_e4i_a0a2")
	kbFieldMulConst(t, "_e4i_a0a2", 2, "_e4i_2a0a2")
	t.copyToTop(an(1), "_e4i_a1d")
	kbFieldSqr(t, "_e4i_a1d", "_e4i_a1sq")
	kbFieldSub(t, "_e4i_2a0a2", "_e4i_a1sq", "_e4i_n1a")
	t.copyToTop(an(3), "_e4i_a3d")
	kbFieldSqr(t, "_e4i_a3d", "_e4i_a3sq")
	kbFieldMulConst(t, "_e4i_a3sq", kbFieldW, "_e4i_wa3sq")
	kbFieldSub(t, "_e4i_n1a", "_e4i_wa3sq", "_e4i_norm1")

	// det = norm0^2 - W norm1^2 ; scalar = det^{-1}
	t.copyToTop("_e4i_norm0", "_e4i_n0c")
	kbFieldSqr(t, "_e4i_n0c", "_e4i_n0sq")
	t.copyToTop("_e4i_norm1", "_e4i_n1c")
	kbFieldSqr(t, "_e4i_n1c", "_e4i_n1sq")
	kbFieldMulConst(t, "_e4i_n1sq", kbFieldW, "_e4i_wn1sq")
	kbFieldSub(t, "_e4i_n0sq", "_e4i_wn1sq", "_e4i_det")
	kbFieldInv(t, "_e4i_det", "_e4i_scalar")

	// invN0 = norm0 * scalar
	t.copyToTop("_e4i_scalar", "_e4i_sc0")
	t.copyToTop("_e4i_norm0", "_e4i_n0v")
	kbFieldMul(t, "_e4i_n0v", "_e4i_sc0", "_e4i_invN0")

	// invN1 = -norm1 * scalar
	t.copyToTop("_e4i_norm1", "_e4i_n1v")
	t.pushInt("_e4i_zero", 0)
	kbFieldSub(t, "_e4i_zero", "_e4i_n1v", "_e4i_neg_n1")
	t.copyToTop("_e4i_scalar", "_e4i_sc1")
	kbFieldMul(t, "_e4i_neg_n1", "_e4i_sc1", "_e4i_invN1")

	// r0 = a0 invN0 + W a2 invN1
	t.copyToTop(an(0), "_e4i_ra0")
	t.copyToTop("_e4i_invN0", "_e4i_riN0a")
	kbFieldMul(t, "_e4i_ra0", "_e4i_riN0a", "_e4i_p0")
	t.copyToTop(an(2), "_e4i_ra2")
	t.copyToTop("_e4i_invN1", "_e4i_riN1a")
	kbFieldMul(t, "_e4i_ra2", "_e4i_riN1a", "_e4i_p1")
	kbFieldMulConst(t, "_e4i_p1", kbFieldW, "_e4i_wp1")
	kbFieldAdd(t, "_e4i_p0", "_e4i_wp1", fmt.Sprintf("%s_0", outPrefix))

	// r1 = -(a1 invN0 + W a3 invN1)
	t.copyToTop(an(1), "_e4i_ra1")
	t.copyToTop("_e4i_invN0", "_e4i_riN0b")
	kbFieldMul(t, "_e4i_ra1", "_e4i_riN0b", "_e4i_q0")
	t.copyToTop(an(3), "_e4i_ra3")
	t.copyToTop("_e4i_invN1", "_e4i_riN1b")
	kbFieldMul(t, "_e4i_ra3", "_e4i_riN1b", "_e4i_q1")
	kbFieldMulConst(t, "_e4i_q1", kbFieldW, "_e4i_wq1")
	kbFieldAdd(t, "_e4i_q0", "_e4i_wq1", "_e4i_odd1")
	t.pushInt("_e4i_zero1", 0)
	kbFieldSub(t, "_e4i_zero1", "_e4i_odd1", fmt.Sprintf("%s_1", outPrefix))

	// r2 = a0 invN1 + a2 invN0
	t.copyToTop(an(0), "_e4i_ua0")
	t.copyToTop("_e4i_invN1", "_e4i_uiN1a")
	kbFieldMul(t, "_e4i_ua0", "_e4i_uiN1a", "_e4i_u0")
	t.copyToTop(an(2), "_e4i_ua2")
	t.copyToTop("_e4i_invN0", "_e4i_uiN0a")
	kbFieldMul(t, "_e4i_ua2", "_e4i_uiN0a", "_e4i_u1")
	kbFieldAdd(t, "_e4i_u0", "_e4i_u1", fmt.Sprintf("%s_2", outPrefix))

	// r3 = -(a1 invN1 + a3 invN0)
	t.copyToTop(an(1), "_e4i_va1")
	t.copyToTop("_e4i_invN1", "_e4i_viN1b")
	kbFieldMul(t, "_e4i_va1", "_e4i_viN1b", "_e4i_v0")
	t.copyToTop(an(3), "_e4i_va3")
	t.copyToTop("_e4i_invN0", "_e4i_viN0b")
	kbFieldMul(t, "_e4i_va3", "_e4i_viN0b", "_e4i_v1")
	kbFieldAdd(t, "_e4i_v0", "_e4i_v1", "_e4i_odd3")
	t.pushInt("_e4i_zero3", 0)
	kbFieldSub(t, "_e4i_zero3", "_e4i_odd3", fmt.Sprintf("%s_3", outPrefix))
}

// kbExt4DropAllByPrefix walks the tracker name table and drops every slot
// whose name starts with `prefix`. Used for cleanup after macros that have
// produced many intermediates the caller no longer cares about.
func kbExt4DropAllByPrefix(t *KBTracker, prefix string) {
	// Iterate in reverse so toTop+drop doesn't shift unaffected slots beneath us.
	for {
		idx := -1
		for i := len(t.nm) - 1; i >= 0; i-- {
			if len(t.nm[i]) >= len(prefix) && t.nm[i][:len(prefix)] == prefix {
				idx = i
				break
			}
		}
		if idx == -1 {
			return
		}
		name := t.nm[idx]
		t.toTop(name)
		t.drop()
	}
}

// kbExt4DropByPrefixes drops slots whose names match any of the given prefixes.
func kbExt4DropByPrefixes(t *KBTracker, prefixes ...string) {
	for _, p := range prefixes {
		kbExt4DropAllByPrefix(t, p)
	}
}

// kbExt4Equal4VerifyByName asserts that the four named coefficients of an
// Ext4 slot match a target value. The named coefficients are CONSUMED by
// the equality check (a OP_NUMEQUALVERIFY pops both operands).
//
// Reads `slotPrefix_0..3` and the target Ext4 (pushed at runtime by the
// caller as `targetPrefix_0..3`). Drops both. Used at the end of the
// per-query final-poly check.
func kbExt4Equal4VerifyByName(t *KBTracker, slotPrefix, targetPrefix string) {
	for i := 0; i < 4; i++ {
		t.toTop(fmt.Sprintf("%s_%d", slotPrefix, i))
		t.toTop(fmt.Sprintf("%s_%d", targetPrefix, i))
		t.rawBlock(
			[]string{fmt.Sprintf("%s_%d", slotPrefix, i), fmt.Sprintf("%s_%d", targetPrefix, i)},
			"",
			func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_NUMEQUALVERIFY"})
			},
		)
	}
}
