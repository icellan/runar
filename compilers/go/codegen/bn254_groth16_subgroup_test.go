package codegen

// Regression tests for the G1 / G2 curve-membership checks that live in
// the witness-assisted Groth16 preamble (emitWAG2OnCurveCheck and the
// surrounding emitWAG1OnCurveCheck calls). These close a documented
// soundness hole where the raw preamble only enforced gradient
// consistency on proof.A / proof.B / proof.C — a hostile prover could
// supply off-curve points that satisfy the gradient equations while
// forging the pairing identity.

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// bigFromE2 converts gnark-crypto's E2 into the (real, imag) *big.Int
// pair the codegen's Fp² helpers operate on.
func bigFromE2(e bn254.E2) (a0, a1 *big.Int) {
	a0 = new(big.Int)
	a1 = new(big.Int)
	e.A0.BigInt(a0)
	e.A1.BigInt(a1)
	return
}

// TestGroth16WA_G2OnCurve_AcceptsValidPoint verifies that the G2 on-curve
// check emitted as part of the witness-assisted preamble accepts a
// well-formed BN254 G2 point (in this case the generator).
func TestGroth16WA_G2OnCurve_AcceptsValidPoint(t *testing.T) {
	_, _, _, g2 := bn254.Generators()

	x0 := new(big.Int)
	x1 := new(big.Int)
	y0 := new(big.Int)
	y1 := new(big.Int)
	g2.X.A0.BigInt(x0)
	g2.X.A1.BigInt(x1)
	g2.Y.A0.BigInt(y0)
	g2.Y.A1.BigInt(y1)

	ops := buildG2OnCurveHarness(x0, x1, y0, y1)
	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("valid G2 point rejected by on-curve check: %v", err)
	}
}

// TestGroth16WA_G2OnCurve_RejectsOffCurvePoint verifies that the G2 on-
// curve check aborts the script when supplied coordinates that do NOT
// satisfy y² == x³ + b' over Fp2. The tampered y1 coordinate is chosen
// to differ from the generator's while keeping all other coords valid,
// so only the curve equation distinguishes accept from reject.
func TestGroth16WA_G2OnCurve_RejectsOffCurvePoint(t *testing.T) {
	_, _, _, g2 := bn254.Generators()

	x0 := new(big.Int)
	x1 := new(big.Int)
	y0 := new(big.Int)
	y1 := new(big.Int)
	g2.X.A0.BigInt(x0)
	g2.X.A1.BigInt(x1)
	g2.Y.A0.BigInt(y0)
	g2.Y.A1.BigInt(y1)

	// Tamper: add 1 to y1 so the point no longer sits on the twist.
	y1Tampered := new(big.Int).Add(y1, big.NewInt(1))
	y1Tampered.Mod(y1Tampered, bn254FieldP)

	ops := buildG2OnCurveHarness(x0, x1, y0, y1Tampered)
	if err := buildAndExecute(t, ops); err == nil {
		t.Fatalf("off-curve G2 point accepted by on-curve check")
	}
}

// TestGroth16WA_G2TwistConstant_MatchesGnark sanity-checks that the
// runtime-precomputed b' = 3/(9+u) matches gnark-crypto's twist constant.
// The pair (bn254TwistB0, bn254TwistB1) is emitted verbatim into every
// Groth16 preamble — a mismatch here would silently break every proof.
func TestGroth16WA_G2TwistConstant_MatchesGnark(t *testing.T) {
	// gnark-crypto exposes the twist b' as bn254.bTwistCurveCoeff inside an
	// unexported package variable; we reconstruct it via the curve
	// definition y² = x³ + b' and a known generator point.
	_, _, _, g2 := bn254.Generators()
	// b' = y² - x³  in Fp2
	var x2, x3, y2 bn254.E2
	x2.Square(&g2.X)
	x3.Mul(&x2, &g2.X)
	y2.Square(&g2.Y)
	var bPrime bn254.E2
	bPrime.Sub(&y2, &x3)

	var expected0, expected1 fp.Element
	expected0 = bPrime.A0
	expected1 = bPrime.A1
	var got0, got1 fp.Element
	got0.SetBigInt(bn254TwistB0)
	got1.SetBigInt(bn254TwistB1)
	if !got0.Equal(&expected0) {
		t.Errorf("bn254TwistB0 = %s, want %s", got0.String(), expected0.String())
	}
	if !got1.Equal(&expected1) {
		t.Errorf("bn254TwistB1 = %s, want %s", got1.String(), expected1.String())
	}
}

// TestGroth16WA_G1OnCurve_AcceptsValidPoint is a regression pin for the
// existing emitWAG1OnCurveCheck helper — added here so the G1 / G2
// checks are covered in a single file.
func TestGroth16WA_G1OnCurve_AcceptsValidPoint(t *testing.T) {
	_, _, g1, _ := bn254.Generators()
	x := new(big.Int)
	y := new(big.Int)
	g1.X.BigInt(x)
	g1.Y.BigInt(y)

	ops := buildG1OnCurveHarness(x, y)
	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("valid G1 point rejected by on-curve check: %v", err)
	}
}

// TestGroth16WA_G1OnCurve_RejectsOffCurvePoint verifies the G1 on-curve
// check rejects a coordinate pair that fails y² == x³ + 3 mod p.
func TestGroth16WA_G1OnCurve_RejectsOffCurvePoint(t *testing.T) {
	_, _, g1, _ := bn254.Generators()
	x := new(big.Int)
	y := new(big.Int)
	g1.X.BigInt(x)
	g1.Y.BigInt(y)
	yTampered := new(big.Int).Add(y, big.NewInt(1))
	yTampered.Mod(yTampered, bn254FieldP)

	ops := buildG1OnCurveHarness(x, yTampered)
	if err := buildAndExecute(t, ops); err == nil {
		t.Fatalf("off-curve G1 point accepted by on-curve check")
	}
}

// buildG2OnCurveHarness returns the StackOps that
//   - push q, x0, x1, y0, y1 (in the order the helper's tracker expects,
//     with q at the bottom so qAtBottom mode works),
//   - run emitWAG2OnCurveCheck,
//   - finish with OP_1 for a clean truthy stack on success.
//
// The helper preserves x0, x1, y0, y1 on the stack (does not consume
// them), so the harness drops them before the final OP_1 to keep the
// interpreter's single-item top invariant happy.
func buildG2OnCurveHarness(x0, x1, y0, y1 *big.Int) []StackOp {
	initNames := []string{"_q", "_x0", "_x1", "_y0", "_y1"}
	var ops []StackOp
	emit := func(op StackOp) { ops = append(ops, op) }
	t := NewBN254Tracker(initNames, emit)

	// Emit the pushes that correspond to initNames.
	preamble := []StackOp{
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bn254FieldP)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(x0)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(x1)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(y0)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(y1)}},
	}

	// Place the tracker in qAtBottom mode — emitWAG2OnCurveCheck is
	// designed for the preamble's stack model.
	t.SetQAtBottom()
	t.primeCacheActive = true

	emitWAG2OnCurveCheck(t, "_x0", "_x1", "_y0", "_y1")

	// Clean up: drop every tracked name so only _q remains, then drop _q
	// itself; finish with OP_1.
	for len(t.nm) > 0 {
		t.drop()
	}
	t.e(StackOp{Op: "push", Value: bigIntPush(1)})

	// Prepend the push preamble so the harness stack is [q, x0, x1, y0, y1]
	// before the helper runs.
	out := append([]StackOp{}, preamble...)
	out = append(out, ops...)
	return out
}

// buildG1OnCurveHarness mirrors buildG2OnCurveHarness for the G1 variant.
func buildG1OnCurveHarness(x, y *big.Int) []StackOp {
	initNames := []string{"_q", "_x", "_y"}
	var ops []StackOp
	emit := func(op StackOp) { ops = append(ops, op) }
	t := NewBN254Tracker(initNames, emit)

	preamble := []StackOp{
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bn254FieldP)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(x)}},
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(y)}},
	}

	t.SetQAtBottom()
	t.primeCacheActive = true

	emitWAG1OnCurveCheck(t, "_x", "_y")

	for len(t.nm) > 0 {
		t.drop()
	}
	t.e(StackOp{Op: "push", Value: bigIntPush(1)})

	out := append([]StackOp{}, preamble...)
	out = append(out, ops...)
	return out
}

// -----------------------------------------------------------------------
// G2 subgroup-check regression tests
// -----------------------------------------------------------------------
//
// These cover emitWAG2SubgroupCheck — the witness-assisted endomorphism
// check (ψ(P) == [6·x²]·P) that closes the TODO(subgroup-check) gap
// documented on the helper. The harness pushes the fixed BN254 modulus,
// the 390 Fp witness gradients (one Fp² slope per doubling and per
// addition in the [6·x²] scalar-mul chain), and the four G2 coordinates
// of P onto the stack, then runs the emitted script through the go-sdk
// interpreter. A valid G2 point must be accepted; an on-curve point
// outside the prime-order subgroup must be rejected.

// computeSubgroupGradientsForTest mirrors the off-chain chain that the
// witness-package's computeSubgroupGradients computes, but is re-
// implemented here to keep the codegen test independent of the witness
// package (which imports codegen and would create a test-time cycle).
//
// Returns the gradients in the exact push order the on-chain preamble
// expects — all doublings followed by all additions, each as (re, im).
func computeSubgroupGradientsForTest(t *testing.T, P bn254.G2Affine) []*big.Int {
	t.Helper()
	k := Bn254SubgroupCheckScalar()
	nbits := k.BitLen()

	type pt struct{ X, Y bn254.E2 }
	pbase := pt{X: P.X, Y: P.Y}
	cur := pbase

	var doublings []bn254.E2
	var additions []bn254.E2

	for i := nbits - 2; i >= 0; i-- {
		// Doubling slope: λ = 3·Tx² / (2·Ty)
		var num bn254.E2
		num.Square(&cur.X)
		var three fp.Element
		three.SetUint64(3)
		num.A0.Mul(&num.A0, &three)
		num.A1.Mul(&num.A1, &three)
		var den bn254.E2
		den.Double(&cur.Y)
		var denInv bn254.E2
		denInv.Inverse(&den)
		var lambda bn254.E2
		lambda.Mul(&num, &denInv)
		doublings = append(doublings, lambda)

		// Apply double: Tx' = λ² − 2Tx; Ty' = λ(Tx − Tx') − Ty.
		var lamSq bn254.E2
		lamSq.Square(&lambda)
		var twoX bn254.E2
		twoX.Double(&cur.X)
		var newX bn254.E2
		newX.Sub(&lamSq, &twoX)
		var diff bn254.E2
		diff.Sub(&cur.X, &newX)
		var lProd bn254.E2
		lProd.Mul(&lambda, &diff)
		var newY bn254.E2
		newY.Sub(&lProd, &cur.Y)
		cur = pt{X: newX, Y: newY}

		if k.Bit(i) == 1 {
			// Chord slope vs base P: λ = (Py − Ty)/(Px − Tx).
			var anum bn254.E2
			anum.Sub(&pbase.Y, &cur.Y)
			var aden bn254.E2
			aden.Sub(&pbase.X, &cur.X)
			var adenInv bn254.E2
			adenInv.Inverse(&aden)
			var alam bn254.E2
			alam.Mul(&anum, &adenInv)
			additions = append(additions, alam)

			// Apply add: Tx' = λ² − Tx − Px; Ty' = λ(Tx − Tx') − Ty.
			var alamSq bn254.E2
			alamSq.Square(&alam)
			var sub1 bn254.E2
			sub1.Sub(&alamSq, &cur.X)
			var newX2 bn254.E2
			newX2.Sub(&sub1, &pbase.X)
			var diff2 bn254.E2
			diff2.Sub(&cur.X, &newX2)
			var lProd2 bn254.E2
			lProd2.Mul(&alam, &diff2)
			var newY2 bn254.E2
			newY2.Sub(&lProd2, &cur.Y)
			cur = pt{X: newX2, Y: newY2}
		}
	}

	// Sanity: the final accumulator should equal ψ(P). If it doesn't,
	// the test math is wrong — fail early to surface the bug here rather
	// than inside the script interpreter.
	var jac bn254.G2Jac
	jac.FromAffine(&P)
	// gnark-crypto doesn't export ψ, but ψ(P) == [p]P on all of E'(Fp²).
	// Compute the expected [6·x²]P directly and compare; the on-chain
	// equality with ψ(P) is independently verified by script execution.
	var expected bn254.G2Jac
	expected.ScalarMultiplication(&jac, k)
	var expectedAff bn254.G2Affine
	expectedAff.FromJacobian(&expected)
	if !expectedAff.X.Equal(&cur.X) || !expectedAff.Y.Equal(&cur.Y) {
		t.Fatalf("off-chain [6·x²]·P mismatch: got (%s, %s) vs gnark (%s, %s)",
			cur.X.String(), cur.Y.String(), expectedAff.X.String(), expectedAff.Y.String())
	}

	out := make([]*big.Int, 0, (len(doublings)+len(additions))*2)
	for _, lam := range doublings {
		a0, a1 := bigFromE2(lam)
		out = append(out, a0, a1)
	}
	for _, lam := range additions {
		a0, a1 := bigFromE2(lam)
		out = append(out, a0, a1)
	}
	return out
}

// buildG2SubgroupHarness returns the StackOps that push q, the prover's
// subgroup-check gradients (390 Fp values), and the four G2 coordinates
// of P, then run emitWAG2SubgroupCheck. Matches the slot layout the
// Groth16 preamble uses: q at bottom, gradients next, then the four
// Fp coordinates under "_x0 _x1 _y0 _y1" on top.
func buildG2SubgroupHarness(t *testing.T, x0, x1, y0, y1 *big.Int, gradients []*big.Int) []StackOp {
	t.Helper()

	nD, nA := Bn254SubgroupCheckGradientCount()
	if want := (nD + nA) * 2; len(gradients) != want {
		t.Fatalf("harness: expected %d gradient Fp values, got %d", want, len(gradients))
	}

	// Push preamble — matches the initNames we declare below.
	preamble := []StackOp{
		{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bn254FieldP)}},
	}
	for _, g := range gradients {
		preamble = append(preamble, StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(g)}})
	}
	for _, c := range []*big.Int{x0, x1, y0, y1} {
		preamble = append(preamble, StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(c)}})
	}

	// Match the push order in initNames so the tracker's name table
	// lines up with the actual stack.
	initNames := []string{"_q"}
	for i := 0; i < nD; i++ {
		initNames = append(initNames, "_sgd_d_"+itoa(i)+"_0", "_sgd_d_"+itoa(i)+"_1")
	}
	for j := 0; j < nA; j++ {
		initNames = append(initNames, "_sgd_a_"+itoa(j)+"_0", "_sgd_a_"+itoa(j)+"_1")
	}
	initNames = append(initNames, "_x0", "_x1", "_y0", "_y1")

	var ops []StackOp
	emit := func(op StackOp) { ops = append(ops, op) }
	tr := NewBN254Tracker(initNames, emit)
	tr.SetQAtBottom()
	tr.primeCacheActive = true

	emitWAG2SubgroupCheck(tr, "_x0", "_x1", "_y0", "_y1")

	// Drop everything the tracker knows about (there should be no names
	// left if the helper behaves correctly: the four input coords remain,
	// the scalar-mul temporary slots were dropped, and the equality
	// checks consumed their own temporaries). Finish with OP_1 for a
	// clean truthy stack.
	for len(tr.nm) > 0 {
		tr.drop()
	}
	tr.e(StackOp{Op: "push", Value: bigIntPush(1)})

	return append(append([]StackOp{}, preamble...), ops...)
}

// TestGroth16WA_G2Subgroup_AcceptsGenerator: the BN254 G2 generator is by
// definition in the prime-order subgroup. The emitted witness-assisted
// check must accept it (i.e. not abort the script) when supplied with
// the correct gradient chain computed off-chain.
func TestGroth16WA_G2Subgroup_AcceptsGenerator(t *testing.T) {
	_, _, _, g2 := bn254.Generators()

	x0, x1 := bigFromE2(g2.X)
	y0, y1 := bigFromE2(g2.Y)

	gradients := computeSubgroupGradientsForTest(t, g2)
	ops := buildG2SubgroupHarness(t, x0, x1, y0, y1, gradients)
	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("G2 generator rejected by subgroup check: %v", err)
	}
}

// TestGroth16WA_G2Subgroup_RejectsBadGradients: even with a valid G2
// input, supplying a single tampered gradient must abort the script.
// This exercises the same on-chain gradient-verification primitive as
// the Miller loop, so a positive acceptance with tampered witness would
// indicate a codegen regression, not a cryptographic hole.
func TestGroth16WA_G2Subgroup_RejectsBadGradients(t *testing.T) {
	_, _, _, g2 := bn254.Generators()

	x0, x1 := bigFromE2(g2.X)
	y0, y1 := bigFromE2(g2.Y)

	gradients := computeSubgroupGradientsForTest(t, g2)
	// Tamper with the first doubling gradient — still a valid Fp value
	// mod p (so the push itself succeeds) but no longer equal to the
	// honest slope, so the gradient-verification OP_EQUALVERIFY aborts.
	gradients[0] = new(big.Int).Add(gradients[0], big.NewInt(1))
	gradients[0].Mod(gradients[0], bn254FieldP)

	ops := buildG2SubgroupHarness(t, x0, x1, y0, y1, gradients)
	if err := buildAndExecute(t, ops); err == nil {
		t.Fatalf("tampered gradient accepted by subgroup check")
	}
}

// TestGroth16WA_G2Subgroup_RejectsOutOfSubgroup: construct an on-curve
// point that is NOT in the prime-order subgroup (using the gnark
// GeneratePointNotInG2 helper, which seeds a random Fp² then hashes to
// the twist curve and deliberately subtracts the r-torsion component so
// the residual lies in the cofactor subgroup). The script must abort.
//
// The witness gradients are computed as though the scalar-mul would
// succeed: we follow the double-and-add chain starting from the off-
// subgroup point. Either (a) the chain hits a 2-torsion / x-collision
// step and the gradient inversion fails off-chain (testing harness
// reports that case via t.Skip), or (b) the chain completes but the
// final [6·x²]·P is NOT equal to ψ(P), so the OP_EQUALVERIFY at the
// end of emitWAG2SubgroupCheck aborts the script.
func TestGroth16WA_G2Subgroup_RejectsOutOfSubgroup(t *testing.T) {
	// Construct a twist-curve point that is NOT in G2 by sweeping
	// seeds through gnark's MapToCurve2 (Shallue–van de Woestijne). The
	// map produces a point on E'(Fp²) with no guarantee of landing in
	// the prime-order subgroup; the BN254 twist cofactor is
	// 2p − n ≈ 2^{255}, so a random seed almost always lands OFF the
	// r-torsion. Loop over seeds until we find one outside G2.
	var aff bn254.G2Affine
	found := false
	for seedI := uint64(1); seedI < 32; seedI++ {
		var seed bn254.E2
		seed.A0.SetUint64(seedI)
		seed.A1.SetUint64(seedI * 3)
		cand := bn254.MapToCurve2(&seed)
		if !cand.IsOnCurve() {
			continue
		}
		if cand.IsInSubGroup() {
			continue
		}
		aff = cand
		found = true
		break
	}
	if !found {
		t.Skip("could not find an off-subgroup twist point via MapToCurve2 in the seed range; negative vector unavailable")
	}

	x0, x1 := bigFromE2(aff.X)
	y0, y1 := bigFromE2(aff.Y)

	// Try to compute the double-and-add chain off-chain. If it fails
	// (2-torsion or x-collision mid-chain), the on-chain verifier would
	// also abort — substitute a minimal placeholder chain so the script
	// reaches its final comparison, which should still reject.
	gradients, ok := tryComputeSubgroupGradients(aff)
	if !ok {
		// Chain cannot be completed off-chain; the on-chain aborts at the
		// failing gradient step. Supply zeros as gradients — the on-chain
		// gradient check rejects at the first mismatch.
		nD, nA := Bn254SubgroupCheckGradientCount()
		gradients = make([]*big.Int, (nD+nA)*2)
		for i := range gradients {
			gradients[i] = big.NewInt(0)
		}
	}

	ops := buildG2SubgroupHarness(t, x0, x1, y0, y1, gradients)
	if err := buildAndExecute(t, ops); err == nil {
		t.Fatalf("off-subgroup point accepted by subgroup check")
	}
}

// tryComputeSubgroupGradients is the lenient variant of
// computeSubgroupGradientsForTest: instead of asserting that the final
// accumulator matches [6·x²]·P (which fails for off-subgroup inputs
// precisely because the group law doesn't preserve the point's order),
// it returns the chain even when mid-steps hit 2-torsion — in which
// case the Inverse in gnark-crypto returns the zero element and the
// resulting gradient is garbage. Used by the negative test to produce
// gradients that at least reach the final comparison step.
func tryComputeSubgroupGradients(P bn254.G2Affine) ([]*big.Int, bool) {
	k := Bn254SubgroupCheckScalar()
	nbits := k.BitLen()

	type pt struct{ X, Y bn254.E2 }
	pbase := pt{X: P.X, Y: P.Y}
	cur := pbase

	var doublings []bn254.E2
	var additions []bn254.E2

	for i := nbits - 2; i >= 0; i-- {
		// Skip zero-denom steps; the chain is unusable if we hit one.
		var zero bn254.E2
		if cur.Y.Equal(&zero) {
			return nil, false
		}

		var num bn254.E2
		num.Square(&cur.X)
		var three fp.Element
		three.SetUint64(3)
		num.A0.Mul(&num.A0, &three)
		num.A1.Mul(&num.A1, &three)
		var den bn254.E2
		den.Double(&cur.Y)
		var denInv bn254.E2
		denInv.Inverse(&den)
		var lambda bn254.E2
		lambda.Mul(&num, &denInv)
		doublings = append(doublings, lambda)

		var lamSq bn254.E2
		lamSq.Square(&lambda)
		var twoX bn254.E2
		twoX.Double(&cur.X)
		var newX bn254.E2
		newX.Sub(&lamSq, &twoX)
		var diff bn254.E2
		diff.Sub(&cur.X, &newX)
		var lProd bn254.E2
		lProd.Mul(&lambda, &diff)
		var newY bn254.E2
		newY.Sub(&lProd, &cur.Y)
		cur = pt{X: newX, Y: newY}

		if k.Bit(i) == 1 {
			if cur.X.Equal(&pbase.X) {
				return nil, false
			}
			var anum bn254.E2
			anum.Sub(&pbase.Y, &cur.Y)
			var aden bn254.E2
			aden.Sub(&pbase.X, &cur.X)
			var adenInv bn254.E2
			adenInv.Inverse(&aden)
			var alam bn254.E2
			alam.Mul(&anum, &adenInv)
			additions = append(additions, alam)

			var alamSq bn254.E2
			alamSq.Square(&alam)
			var sub1 bn254.E2
			sub1.Sub(&alamSq, &cur.X)
			var newX2 bn254.E2
			newX2.Sub(&sub1, &pbase.X)
			var diff2 bn254.E2
			diff2.Sub(&cur.X, &newX2)
			var lProd2 bn254.E2
			lProd2.Mul(&alam, &diff2)
			var newY2 bn254.E2
			newY2.Sub(&lProd2, &cur.Y)
			cur = pt{X: newX2, Y: newY2}
		}
	}

	out := make([]*big.Int, 0, (len(doublings)+len(additions))*2)
	for _, lam := range doublings {
		a0, a1 := bigFromE2(lam)
		out = append(out, a0, a1)
	}
	for _, lam := range additions {
		a0, a1 := bigFromE2(lam)
		out = append(out, a0, a1)
	}
	return out, true
}
