package codegen

// Adversarial-input tests for the general-purpose BN254 pairing builtins
// (`bn254Pairing`, `bn254MultiPairing4`, `bn254MultiPairing3`).
//
// CL-BUG-103 / CL-BUG-034: the five pairing emitters fed caller-supplied
// G1/G2 coordinates straight into the Miller loop with no on-curve check
// and no G2 subgroup check, while the witness-assisted Groth16 preamble in
// the SAME package performed exactly those checks. EIP-197 (the canonical
// reference for this primitive) mandates that a pairing whose inputs are
// off-curve or outside the prime-order subgroup MUST fail.
//
// Every negative below is paired with a positive control that runs the
// SAME harness on valid points, so a rejection can never be attributed to
// a broken harness.

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// ---------------------------------------------------------------------------
// Adversarial vectors
// ---------------------------------------------------------------------------

// advOffCurveG1 returns a well-formed, canonically encoded G1 coordinate
// pair (both < p) that does NOT satisfy y² == x³ + 3. Derived from the
// generator by incrementing y, and asserted off-curve via gnark-crypto so
// the vector can never silently become valid.
func advOffCurveG1(t *testing.T) (x, y *big.Int) {
	t.Helper()
	_, _, g1, _ := bn254.Generators()

	x = new(big.Int)
	y = new(big.Int)
	g1.X.BigInt(x)
	g1.Y.BigInt(y)
	y.Add(y, big.NewInt(1))
	y.Mod(y, bn254FieldP)

	if x.Cmp(bn254FieldP) >= 0 || y.Cmp(bn254FieldP) >= 0 {
		t.Fatalf("adversarial G1 vector is not canonically encoded")
	}
	// y² - (x³ + 3) must be nonzero mod p.
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, bn254FieldP)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, big.NewInt(3))
	rhs.Mod(rhs, bn254FieldP)
	if lhs.Cmp(rhs) == 0 {
		t.Fatalf("adversarial G1 vector is ON the curve; pick another")
	}

	// Cross-check with gnark-crypto.
	var probe bn254.G1Affine
	probe.X.SetBigInt(x)
	probe.Y.SetBigInt(y)
	if probe.IsOnCurve() {
		t.Fatalf("gnark says the adversarial G1 vector is on curve")
	}
	return x, y
}

// advOffCurveG2 returns a well-formed G2 coordinate 4-tuple that is NOT on
// the twist E'(Fp²): y² != x³ + b'. Derived from the G2 generator by
// incrementing the imaginary part of y.
func advOffCurveG2(t *testing.T) (x0, x1, y0, y1 *big.Int) {
	t.Helper()
	_, _, _, g2 := bn254.Generators()
	x0, x1 = bigFromE2(g2.X)
	y0, y1 = bigFromE2(g2.Y)

	y1 = new(big.Int).Add(y1, big.NewInt(1))
	y1.Mod(y1, bn254FieldP)

	var probe bn254.G2Affine
	probe.X.A0.SetBigInt(x0)
	probe.X.A1.SetBigInt(x1)
	probe.Y.A0.SetBigInt(y0)
	probe.Y.A1.SetBigInt(y1)
	if probe.IsOnCurve() {
		t.Fatalf("adversarial off-twist G2 vector is actually on the twist")
	}
	return x0, x1, y0, y1
}

// advOffSubgroupG2 returns a G2 coordinate 4-tuple that IS on the twist
// E'(Fp²) but is NOT in the prime-order subgroup G2. BN254's twist has
// cofactor 2p − n ≈ 2^255, so the SvdW map's output (which is never
// cofactor-cleared) lands off the r-torsion with overwhelming probability.
// The fixed seed (A0=1, A1=3) is deterministic; both properties are
// ASSERTED, never skipped, so this security-load-bearing vector can never
// silently degrade into a trivial off-curve vector.
func advOffSubgroupG2(t *testing.T) (x0, x1, y0, y1 *big.Int) {
	t.Helper()
	var seed bn254.E2
	seed.A0.SetUint64(1)
	seed.A1.SetUint64(3)
	aff := bn254.MapToCurve2(&seed)
	if !aff.IsOnCurve() {
		t.Fatalf("adversarial G2 seed (1,3) is not on the twist curve")
	}
	if aff.IsInSubGroup() {
		t.Fatalf("adversarial G2 seed (1,3) landed IN the prime-order subgroup")
	}
	x0, x1 = bigFromE2(aff.X)
	y0, y1 = bigFromE2(aff.Y)
	return
}

// ---------------------------------------------------------------------------
// Harnesses — identical push layout for positive and negative runs
// ---------------------------------------------------------------------------

// runSinglePairing pushes [P(64B), qx0, qx1, qy0, qy1], runs
// EmitBN254Pairing, and executes the resulting script. No trailing ops are
// appended: the emitter's own 12-slot Fp12 result is left on the stack and
// the interpreter's truthiness rule decides. A valid pair therefore
// succeeds (positive control below) and any aborting validation check
// makes the script fail.
func runSinglePairing(px, py, qx0, qx1, qy0, qy1 *big.Int) error {
	var ops []StackOp
	ops = append(ops, pushPoint(px, py))
	ops = append(ops, pushBigInt(qx0), pushBigInt(qx1), pushBigInt(qy0), pushBigInt(qy1))
	EmitBN254Pairing(func(op StackOp) { ops = append(ops, op) })
	return BuildAndExecuteOps(ops)
}

type g1Coords struct{ x, y *big.Int }
type g2Coords struct{ x0, x1, y0, y1 *big.Int }

// runMultiPairing4 pushes four (G1, G2) pairs, runs EmitBN254MultiPairing4
// and OP_VERIFYs its boolean result.
func runMultiPairing4(pairs mp4Config) error {
	var ops []StackOp
	for _, pr := range pairs {
		ops = append(ops, pushPoint(pr.p.x, pr.p.y))
		ops = append(ops, pushBigInt(pr.q.x0), pushBigInt(pr.q.x1), pushBigInt(pr.q.y0), pushBigInt(pr.q.y1))
	}
	EmitBN254MultiPairing4(func(op StackOp) { ops = append(ops, op) })
	ops = append(ops, opcode("OP_VERIFY"), opcode("OP_1"))
	return BuildAndExecuteOps(ops)
}

// validG1 / validG2 return the BN254 generators as plain coordinates.
func validG1() g1Coords {
	_, _, g1, _ := bn254.Generators()
	x := new(big.Int)
	y := new(big.Int)
	g1.X.BigInt(x)
	g1.Y.BigInt(y)
	return g1Coords{x, y}
}

func negValidG1() g1Coords {
	c := validG1()
	return g1Coords{c.x, new(big.Int).Sub(bn254FieldP, c.y)}
}

func validG2() g2Coords {
	_, _, _, g2 := bn254.Generators()
	x0, x1 := bigFromE2(g2.X)
	y0, y1 := bigFromE2(g2.Y)
	return g2Coords{x0, x1, y0, y1}
}

// ---------------------------------------------------------------------------
// bn254Pairing
// ---------------------------------------------------------------------------

// TestBN254Pairing_AcceptsValidPoints is the positive control for every
// negative below: the exact same harness, with the BN254 generators, must
// run to completion. Without it a rejection could be an artefact of the
// harness rather than of the validation checks.
func TestBN254Pairing_AcceptsValidPoints(t *testing.T) {
	p := validG1()
	q := validG2()
	if err := runSinglePairing(p.x, p.y, q.x0, q.x1, q.y0, q.y1); err != nil {
		t.Fatalf("e(G1, G2) with valid generators was rejected: %v", err)
	}
}

// TestBN254Pairing_RejectsOffCurveG1 — CL-BUG-103 attack (1) on the G1 side.
func TestBN254Pairing_RejectsOffCurveG1(t *testing.T) {
	x, y := advOffCurveG1(t)
	q := validG2()
	if err := runSinglePairing(x, y, q.x0, q.x1, q.y0, q.y1); err == nil {
		t.Fatal("bn254Pairing accepted an off-curve G1 point")
	}
}

// TestBN254Pairing_RejectsOffCurveG2 — CL-BUG-103 attack (1) on the G2 side.
func TestBN254Pairing_RejectsOffCurveG2(t *testing.T) {
	p := validG1()
	x0, x1, y0, y1 := advOffCurveG2(t)
	if err := runSinglePairing(p.x, p.y, x0, x1, y0, y1); err == nil {
		t.Fatal("bn254Pairing accepted an off-twist G2 point")
	}
}

// TestBN254Pairing_RejectsOffSubgroupG2 — CL-BUG-103 attack (2): a point
// that IS on the twist but lies in the cofactor torsion. Only a genuine
// subgroup check rejects this; an on-curve check alone lets it through.
func TestBN254Pairing_RejectsOffSubgroupG2(t *testing.T) {
	p := validG1()
	x0, x1, y0, y1 := advOffSubgroupG2(t)
	if err := runSinglePairing(p.x, p.y, x0, x1, y0, y1); err == nil {
		t.Fatal("bn254Pairing accepted an on-twist but off-subgroup G2 point")
	}
}

// TestBN254Pairing_RejectsIdentityG2 — CL-BUG-103 attack (3): the all-zero
// G2 encoding has no affine representation on the twist (b' != 0), so the
// on-curve check must reject it rather than letting the Miller loop run on
// degenerate values with bn254FieldInv(0) = 0.
//
// NOTE ON STRENGTH: unlike the three negatives above, this vector was
// already rejected before the fix — the degenerate Miller loop produces an
// all-zero Fp12 whose top slot is falsy. It is kept as a regression guard,
// not as evidence that the fix works.
func TestBN254Pairing_RejectsIdentityG2(t *testing.T) {
	p := validG1()
	z := func() *big.Int { return big.NewInt(0) }
	if err := runSinglePairing(p.x, p.y, z(), z(), z(), z()); err == nil {
		t.Fatal("bn254Pairing accepted the all-zero (identity) G2 encoding")
	}
}

// ---------------------------------------------------------------------------
// bn254MultiPairing4
//
// A multi-pairing returns "product == 1 in GT". Feeding it a single bad
// point and observing a FALSE result proves nothing: almost any wrong
// input makes the product differ from 1. The negatives below therefore use
// CANCELLING configurations — the bad point appears in two pairs whose G1
// arguments are P and -P, so bilinearity in the G1 argument makes its
// contribution cancel and the product is 1 REGARDLESS of whether the point
// is on the curve or in the subgroup. Each configuration is asserted to
// yield 1 under gnark-crypto's reference pairing before it is fed to the
// script, so a pre-fix "accept" is the real forgery and a post-fix
// "reject" can only come from the new validation checks.
// ---------------------------------------------------------------------------

type mp4Config [4]struct {
	p g1Coords
	q g2Coords
}

// mp4Identity builds the algebraically-guaranteed identity configuration
// e(G,G2)·e(-G,G2)·e(G,G2)·e(-G,G2) == 1 used as the positive control.
func mp4Identity() mp4Config {
	g := validG1()
	ng := negValidG1()
	q := validG2()
	return mp4Config{{g, q}, {ng, q}, {g, q}, {ng, q}}
}

// assertGnarkProductIsOne fails the test unless gnark-crypto's reference
// pairing agrees that the configuration's GT product is exactly 1. This is
// what makes the negatives below forgeries rather than noise.
func assertGnarkProductIsOne(t *testing.T, cfg mp4Config) {
	t.Helper()
	var g1s []bn254.G1Affine
	var g2s []bn254.G2Affine
	for _, pr := range cfg {
		var p bn254.G1Affine
		p.X.SetBigInt(pr.p.x)
		p.Y.SetBigInt(pr.p.y)
		var q bn254.G2Affine
		q.X.A0.SetBigInt(pr.q.x0)
		q.X.A1.SetBigInt(pr.q.x1)
		q.Y.A0.SetBigInt(pr.q.y0)
		q.Y.A1.SetBigInt(pr.q.y1)
		g1s = append(g1s, p)
		g2s = append(g2s, q)
	}
	gt, err := bn254.Pair(g1s, g2s)
	if err != nil {
		t.Fatalf("gnark reference pairing failed: %v", err)
	}
	var one bn254.E12
	one.SetOne()
	if !gt.Equal(&one) {
		t.Fatalf("configuration does not forge product == 1 under gnark; "+
			"the negative would be vacuous. got %s", gt.String())
	}
}

func TestBN254MultiPairing4_AcceptsValidPoints(t *testing.T) {
	cfg := mp4Identity()
	assertGnarkProductIsOne(t, cfg)
	if err := runMultiPairing4(cfg); err != nil {
		t.Fatalf("valid 4-pair identity configuration was rejected: %v", err)
	}
}

// TestBN254MultiPairing4_RejectsOffCurveG1: pairs 1 and 2 both use the
// SAME off-curve G1 point, negated in pair 2, so its contribution cancels
// and the product is 1. Pre-fix the script returns TRUE — a forged
// "pairing check passed" with an off-curve input.
func TestBN254MultiPairing4_RejectsOffCurveG1(t *testing.T) {
	x, y := advOffCurveG1(t)
	negY := new(big.Int).Sub(bn254FieldP, y)
	g := validG1()
	ng := negValidG1()
	q := validG2()
	cfg := mp4Config{
		{g1Coords{x, y}, q},
		{g1Coords{x, negY}, q},
		{g, q},
		{ng, q},
	}
	assertGnarkProductIsOne(t, cfg)
	if err := runMultiPairing4(cfg); err == nil {
		t.Fatal("bn254MultiPairing4 returned TRUE for a product containing an off-curve G1 point")
	}
}

// TestBN254MultiPairing4_RejectsOffCurveG2: the off-twist G2 point appears
// in pairs 1 and 2 against G and -G, so it cancels and the product is 1.
func TestBN254MultiPairing4_RejectsOffCurveG2(t *testing.T) {
	x0, x1, y0, y1 := advOffCurveG2(t)
	bad := g2Coords{x0, x1, y0, y1}
	g := validG1()
	ng := negValidG1()
	q := validG2()
	cfg := mp4Config{{g, bad}, {ng, bad}, {g, q}, {ng, q}}
	assertGnarkProductIsOne(t, cfg)
	if err := runMultiPairing4(cfg); err == nil {
		t.Fatal("bn254MultiPairing4 returned TRUE for a product containing an off-twist G2 point")
	}
}

// TestBN254MultiPairing4_RejectsOffSubgroupG2 is the headline vector for
// CL-BUG-103: an ON-CURVE G2 point in the twist's cofactor torsion. Only a
// genuine subgroup check rejects it; on-curve validation alone does not.
func TestBN254MultiPairing4_RejectsOffSubgroupG2(t *testing.T) {
	x0, x1, y0, y1 := advOffSubgroupG2(t)
	bad := g2Coords{x0, x1, y0, y1}
	g := validG1()
	ng := negValidG1()
	q := validG2()
	cfg := mp4Config{{g, bad}, {ng, bad}, {g, q}, {ng, q}}
	assertGnarkProductIsOne(t, cfg)
	if err := runMultiPairing4(cfg); err == nil {
		t.Fatal("bn254MultiPairing4 returned TRUE for a product containing an on-twist but off-subgroup G2 point")
	}
}

// ---------------------------------------------------------------------------
// Attribution: the off-subgroup rejection must come from the SUBGROUP check
// ---------------------------------------------------------------------------

// buildG2OnCurveOnlyHarness runs ONLY bn254AssertG2OnCurve on the supplied
// coordinates — no subgroup check — and finishes with a clean OP_1.
func buildG2OnCurveOnlyHarness(x0, x1, y0, y1 *big.Int) []StackOp {
	initNames := []string{"_q", "_x0", "_x1", "_y0", "_y1"}
	var ops []StackOp
	emit := func(op StackOp) { ops = append(ops, op) }
	tr := NewBN254Tracker(initNames, emit)

	preamble := []StackOp{
		pushBigInt(bn254FieldP),
		pushBigInt(x0), pushBigInt(x1), pushBigInt(y0), pushBigInt(y1),
	}

	tr.SetQAtBottom()
	tr.primeCacheActive = true

	bn254AssertG2OnCurve(tr, "_x0", "_x1", "_y0", "_y1", "attr")

	for len(tr.nm) > 0 {
		tr.drop()
	}
	tr.e(StackOp{Op: "push", Value: bigIntPush(1)})

	return append(append([]StackOp{}, preamble...), ops...)
}

// TestBN254OffSubgroupVector_PassesOnCurveCheck pins down WHY
// TestBN254Pairing_RejectsOffSubgroupG2 rejects. The adversarial vector is
// on the twist, so the on-curve assertion alone ACCEPTS it — the rejection
// in the pairing tests can therefore only come from the new subgroup check.
// Without this, an on-curve-only fix would look like a complete fix.
func TestBN254OffSubgroupVector_PassesOnCurveCheck(t *testing.T) {
	x0, x1, y0, y1 := advOffSubgroupG2(t)
	if err := buildAndExecute(t, buildG2OnCurveOnlyHarness(x0, x1, y0, y1)); err != nil {
		t.Fatalf("off-subgroup vector was rejected by the ON-CURVE check alone (%v); "+
			"the pairing rejection would not prove the subgroup check works", err)
	}

	// Control: an off-twist vector must fail the same harness.
	ox0, ox1, oy0, oy1 := advOffCurveG2(t)
	if err := buildAndExecute(t, buildG2OnCurveOnlyHarness(ox0, ox1, oy0, oy1)); err == nil {
		t.Fatal("on-curve-only harness accepted an off-twist point")
	}
}

// TestBN254OffSubgroupVector_FailsSubgroupCheck is the direct converse: the
// unassisted subgroup assertion on its own rejects the vector, and accepts
// the G2 generator.
func TestBN254OffSubgroupVector_FailsSubgroupCheck(t *testing.T) {
	build := func(x0, x1, y0, y1 *big.Int) []StackOp {
		initNames := []string{"_q", "_x0", "_x1", "_y0", "_y1"}
		var ops []StackOp
		emit := func(op StackOp) { ops = append(ops, op) }
		tr := NewBN254Tracker(initNames, emit)
		preamble := []StackOp{
			pushBigInt(bn254FieldP),
			pushBigInt(x0), pushBigInt(x1), pushBigInt(y0), pushBigInt(y1),
		}
		tr.SetQAtBottom()
		tr.primeCacheActive = true
		bn254AssertG2InSubgroup(tr, "_x0", "_x1", "_y0", "_y1", "attr")
		for len(tr.nm) > 0 {
			tr.drop()
		}
		tr.e(StackOp{Op: "push", Value: bigIntPush(1)})
		return append(append([]StackOp{}, preamble...), ops...)
	}

	g := validG2()
	if err := buildAndExecute(t, build(g.x0, g.x1, g.y0, g.y1)); err != nil {
		t.Fatalf("G2 generator rejected by the unassisted subgroup check: %v", err)
	}

	x0, x1, y0, y1 := advOffSubgroupG2(t)
	if err := buildAndExecute(t, build(x0, x1, y0, y1)); err == nil {
		t.Fatal("unassisted subgroup check accepted an off-subgroup point")
	}
}

// ---------------------------------------------------------------------------
// bn254MultiPairing3 (precomputed Fp12 variant)
//
// No execution test existed for this emitter before CL-BUG-103 remediation,
// so the positive control below is also the first regression guard that the
// inserted validation does not disturb the 3-pair stack layout.
// ---------------------------------------------------------------------------

// flatMillerLoop returns gnark's MillerLoop(P, Q) flattened into the 12-slot
// Fp12 order the emitter's `pre_*` tracker slots use (C0.B0.A0 .. C1.B2.A1).
// `pre` is multiplied into the Miller-loop accumulator BEFORE the single
// final exponentiation, so it must be a MillerLoop output, not a GT element.
func flatMillerLoop(t *testing.T, ps []bn254.G1Affine, qs []bn254.G2Affine) []*big.Int {
	t.Helper()
	e, err := bn254.MillerLoop(ps, qs)
	if err != nil {
		t.Fatalf("gnark MillerLoop: %v", err)
	}
	limbs := []*fp.Element{
		&e.C0.B0.A0, &e.C0.B0.A1,
		&e.C0.B1.A0, &e.C0.B1.A1,
		&e.C0.B2.A0, &e.C0.B2.A1,
		&e.C1.B0.A0, &e.C1.B0.A1,
		&e.C1.B1.A0, &e.C1.B1.A1,
		&e.C1.B2.A0, &e.C1.B2.A1,
	}
	out := make([]*big.Int, len(limbs))
	for i, l := range limbs {
		out[i] = new(big.Int)
		l.BigInt(out[i])
	}
	return out
}

// runMultiPairing3 pushes three (G1, G2) pairs plus the 12 precomputed Fp12
// slots, runs EmitBN254MultiPairing3WithPrecomputed and OP_VERIFYs the
// boolean result.
func runMultiPairing3(pairs [3]struct {
	p g1Coords
	q g2Coords
}, pre []*big.Int) error {
	var ops []StackOp
	for _, pr := range pairs {
		ops = append(ops, pushPoint(pr.p.x, pr.p.y))
		ops = append(ops, pushBigInt(pr.q.x0), pushBigInt(pr.q.x1), pushBigInt(pr.q.y0), pushBigInt(pr.q.y1))
	}
	for _, v := range pre {
		ops = append(ops, pushBigInt(v))
	}
	EmitBN254MultiPairing3WithPrecomputed(func(op StackOp) { ops = append(ops, op) })
	ops = append(ops, opcode("OP_VERIFY"), opcode("OP_1"))
	return BuildAndExecuteOps(ops)
}

func gnarkG1(c g1Coords) bn254.G1Affine {
	var p bn254.G1Affine
	p.X.SetBigInt(c.x)
	p.Y.SetBigInt(c.y)
	return p
}

func gnarkG2(c g2Coords) bn254.G2Affine {
	var q bn254.G2Affine
	q.X.A0.SetBigInt(c.x0)
	q.X.A1.SetBigInt(c.x1)
	q.Y.A0.SetBigInt(c.y0)
	q.Y.A1.SetBigInt(c.y1)
	return q
}

// assertFourTermProductIsOne asserts under gnark-crypto that
// e(p1,q1)·e(p2,q2)·e(p3,q3)·e(p4,q4) == 1. The 3-pair-plus-precomputed
// emitter computes exactly this product (the 4th term arriving as the
// precomputed MillerLoop constant), so this is what makes its negative a
// forgery rather than noise.
func assertFourTermProductIsOne(t *testing.T, ps []bn254.G1Affine, qs []bn254.G2Affine) {
	t.Helper()
	gt, err := bn254.Pair(ps, qs)
	if err != nil {
		t.Fatalf("gnark reference pairing failed: %v", err)
	}
	var one bn254.E12
	one.SetOne()
	if !gt.Equal(&one) {
		t.Fatalf("configuration does not forge product == 1 under gnark; "+
			"the test would be vacuous. got %s", gt.String())
	}
}

func TestBN254MultiPairing3_AcceptsValidPoints(t *testing.T) {
	g := validG1()
	ng := negValidG1()
	q := validG2()
	pairs := [3]struct {
		p g1Coords
		q g2Coords
	}{{g, q}, {ng, q}, {g, q}}
	// pre = MillerLoop(-G, G2) makes the full product collapse to 1.
	assertFourTermProductIsOne(t,
		[]bn254.G1Affine{gnarkG1(g), gnarkG1(ng), gnarkG1(g), gnarkG1(ng)},
		[]bn254.G2Affine{gnarkG2(q), gnarkG2(q), gnarkG2(q), gnarkG2(q)})
	pre := flatMillerLoop(t, []bn254.G1Affine{gnarkG1(ng)}, []bn254.G2Affine{gnarkG2(q)})
	if err := runMultiPairing3(pairs, pre); err != nil {
		t.Fatalf("valid 3-pair + precomputed configuration was rejected: %v", err)
	}
}

func TestBN254MultiPairing3_RejectsOffSubgroupG2(t *testing.T) {
	g := validG1()
	ng := negValidG1()
	q := validG2()
	x0, x1, y0, y1 := advOffSubgroupG2(t)
	bad := g2Coords{x0, x1, y0, y1}
	pairs := [3]struct {
		p g1Coords
		q g2Coords
	}{{g, bad}, {ng, bad}, {g, q}}
	// The bad point cancels between pairs 1 and 2, so the four-term
	// product is 1 and a pre-fix script returns TRUE.
	assertFourTermProductIsOne(t,
		[]bn254.G1Affine{gnarkG1(g), gnarkG1(ng), gnarkG1(g), gnarkG1(ng)},
		[]bn254.G2Affine{gnarkG2(bad), gnarkG2(bad), gnarkG2(q), gnarkG2(q)})
	pre := flatMillerLoop(t, []bn254.G1Affine{gnarkG1(ng)}, []bn254.G2Affine{gnarkG2(q)})
	if err := runMultiPairing3(pairs, pre); err == nil {
		t.Fatal("bn254MultiPairing3 returned TRUE for a product containing an on-twist but off-subgroup G2 point")
	}
}
