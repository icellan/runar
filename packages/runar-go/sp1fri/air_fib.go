package sp1fri

// Fibonacci AIR constraint evaluator.
//
// Mirrors the AIR in `tests/vectors/sp1/fri/minimal-guest/regen/src/main.rs`
// (a port of Plonky3's `uni-stark/tests/fib_air.rs`):
//
//   2 columns: left, right.
//   3 public values: a, b, x.
//   Constraints (in evaluation order):
//     wf := when_first_row():  assert_eq(local.left,  a)
//                              assert_eq(local.right, b)
//     wt := when_transition(): assert_eq(local.right,             next.left)
//                              assert_eq(local.left + local.right, next.right)
//     when_last_row():         assert_eq(local.right, x)
//
// The verifier folds these via the random-linear combination scalar `alpha`:
//   accumulator = 0
//   for each constraint c (in order): accumulator = accumulator * alpha + c
// (See `uni-stark/src/folder.rs::VerifierConstraintFolder::assert_zero`,
// lines 217-220.)
//
// Each `when_S().assert_eq(L, R)` desugars to `assert_zero(S * (L - R))`
// (see `air/src/filtered.rs::FilteredAirBuilder::assert_zero`, lines 61-63).

// EvalFibonacciConstraints evaluates the Fibonacci AIR constraints at the
// out-of-domain point `zeta`, returning the alpha-folded accumulator.
//
// Inputs:
//   - local[0]  = trace_local[0]  (== column "left"  at  zeta)
//   - local[1]  = trace_local[1]  (== column "right" at  zeta)
//   - next[0]   = trace_next[0]   (== column "left"  at  zeta * g_trace)
//   - next[1]   = trace_next[1]   (== column "right" at  zeta * g_trace)
//   - pis[0..3] = canonical KoalaBear public values [a, b, x]
//   - sels      = Lagrange selectors at zeta from the trace domain
//                 (is_first_row, is_last_row, is_transition).
//   - alpha     = Fiat-Shamir random scalar.
//
// Returns the accumulator value `folded_constraints` such that the OOD
// equation is `folded_constraints * sels.inv_vanishing == quotient`.
func EvalFibonacciConstraints(
	local [2]Ext4,
	next [2]Ext4,
	pis [3]uint32,
	sels LagrangeSelectors,
	alpha Ext4,
) Ext4 {
	// Lift public values into Ext4.
	a := Ext4FromBase(pis[0])
	b := Ext4FromBase(pis[1])
	x := Ext4FromBase(pis[2])

	left := local[0]
	right := local[1]
	nLeft := next[0]
	nRight := next[1]

	// Fold helper: accumulator = accumulator * alpha + constraint.
	acc := Ext4Zero()
	fold := func(c Ext4) {
		acc = Ext4Add(Ext4Mul(acc, alpha), c)
	}

	// 1. when_first_row().assert_eq(local.left,  a)  → is_first_row * (left  - a)
	fold(Ext4Mul(sels.IsFirstRow, Ext4Sub(left, a)))

	// 2. when_first_row().assert_eq(local.right, b)  → is_first_row * (right - b)
	fold(Ext4Mul(sels.IsFirstRow, Ext4Sub(right, b)))

	// 3. when_transition().assert_eq(local.right, next.left)
	//    → is_transition * (right - nLeft)
	fold(Ext4Mul(sels.IsTransition, Ext4Sub(right, nLeft)))

	// 4. when_transition().assert_eq(local.left + local.right, next.right)
	//    → is_transition * ((left + right) - nRight)
	fold(Ext4Mul(sels.IsTransition, Ext4Sub(Ext4Add(left, right), nRight)))

	// 5. when_last_row().assert_eq(local.right, x)  → is_last_row * (right - x)
	fold(Ext4Mul(sels.IsLastRow, Ext4Sub(right, x)))

	return acc
}

// LagrangeSelectors is the runtime form of `commit/src/domain.rs::LagrangeSelectors`
// at a single Ext4 point, computed for the trace domain (shift = 1).
type LagrangeSelectors struct {
	IsFirstRow   Ext4
	IsLastRow    Ext4
	IsTransition Ext4
	InvVanishing Ext4
}

// SelectorsAtPoint computes the Lagrange selectors at `point` for the trace
// domain `H` of size `2^logSize`, with shift = 1.
//
// Mirrors `TwoAdicMultiplicativeCoset::selectors_at_point` (lines 262-271):
//
//	unshifted_point  = point * shift_inverse              (= point since shift=1)
//	z_h              = unshifted_point^|H|  - 1
//	is_first_row     = z_h / (unshifted_point - 1)
//	is_last_row      = z_h / (unshifted_point - h_inv)
//	is_transition    = unshifted_point - h_inv
//	inv_vanishing    = 1 / z_h
//
// where h is the subgroup generator of order |H| (= 2-adic generator at
// `logSize`).
func SelectorsAtPoint(logSize int, point Ext4) LagrangeSelectors {
	// Subgroup generator of order |H|.
	h := KbTwoAdicGenerator(logSize)
	hInv := KbInv(h)
	hInvExt := Ext4FromBase(hInv)

	zH := Ext4Sub(Ext4PowPow2(point, uint32(logSize)), Ext4One())
	pmO := Ext4Sub(point, Ext4One())
	pmHinv := Ext4Sub(point, hInvExt)

	return LagrangeSelectors{
		IsFirstRow:   Ext4Div(zH, pmO),
		IsLastRow:    Ext4Div(zH, pmHinv),
		IsTransition: pmHinv,
		InvVanishing: Ext4Inv(zH),
	}
}
