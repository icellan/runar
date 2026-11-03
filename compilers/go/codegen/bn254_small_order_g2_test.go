package codegen

// F-150 / GK-GAP-004: constructed small-order and cofactor-torsion G2
// vectors against the GENERIC BN254 pairing builtins (EmitBN254Pairing,
// EmitBN254MultiPairing4, EmitBN254MultiPairing3WithPrecomputed) and the
// unassisted subgroup assertion they share (bn254AssertG2InSubgroup), plus
// the witness-assisted emitWAG2SubgroupCheck for comparison.
//
// The pre-existing off-subgroup vector (bn254_pairing_validation_test.go
// advOffSubgroupG2) is a raw MapToCurve2 output: on the twist, but with a
// component in every prime-power part of the group, so its order is ~2^509.
// It is NOT a small-subgroup-confinement vector. The vectors here are:
//
//   - order exactly 10069  (the SMALLEST prime dividing the twist cofactor;
//     the test proves no smaller prime divides it, so no G2-input point of
//     smaller nontrivial order exists on E'(Fp²) at all)
//   - order exactly 5864401 (the next prime factor)
//   - a pure cofactor-torsion point [r]·P (order divides h, no G2 component)
//   - G2 generator + order-10069 point: the classic "valid-looking point
//     with a small-torsion tail" (order 10069·r)
//
// 2-TORSION (Y = 0) DOES NOT EXIST ON THE TWIST, so it cannot be a vector.
// #E'(Fp²) = r·h with h = 2p − r; p and r are odd primes, so h and r·h are
// odd and Lagrange rules out a point of order 2. The test also shows it
// directly: a Y = 0 point needs a root of x³ + b' in Fp², i.e. −b' must be a
// cube in Fp², and (−b')^((p²−1)/3) ≠ 1 proves it is not. More generally no
// prime below 10069 divides #E'(Fp²), so there is no 3-, 5-, 7-, … torsion
// either.
//
// All vector properties (on-curve, exact order, not in G2) are proved with
// plain Jacobian double-and-add, NOT gnark's IsInSubGroup — that helper uses
// the same ψ(P) == [6x²]P characterisation as the code under test, so it
// would not be an independent witness. gnark's GLV ScalarMultiplication is
// likewise avoided off G2 (it assumes r-torsion).
//
// Every script is executed by the go-sdk script interpreter (the engine
// packages/runar-go's ScriptVM wraps) through BuildAndExecuteOps. The
// honest controls for these exact harnesses are
// TestBN254Pairing_AcceptsValidPoints, TestBN254MultiPairing4_AcceptsValidPoints,
// TestBN254MultiPairing3_AcceptsValidPoints and
// TestGroth16WA_G2Subgroup_AcceptsGenerator; the subgroup-only harness
// below carries its own G2-generator control.

import (
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// bn254 curve parameter x (the BN "u"), from which p, r and 6x² derive.
var f150X, _ = new(big.Int).SetString("4965661367192848881", 10)

func f150R() *big.Int { return fr.Modulus() }

// f150TwistCofactor returns h = 2p − r, so that #E'(Fp²) = r·h.
func f150TwistCofactor() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(bn254FieldP, 1), f150R())
}

// f150Mul is plain left-to-right double-and-add over Jacobian coordinates.
// Valid for every point on the twist (gnark's AddAssign handles P == Q and
// P == −Q), unlike the GLV path.
func f150Mul(base bn254.G2Jac, k *big.Int) bn254.G2Jac {
	var acc bn254.G2Jac
	acc.Set(&base)
	acc.Z.SetZero() // infinity
	acc.X.SetOne()
	acc.Y.SetOne()
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc.DoubleAssign()
		if k.Bit(i) == 1 {
			acc.AddAssign(&base)
		}
	}
	return acc
}

func f150Jac(a bn254.G2Affine) bn254.G2Jac {
	var j bn254.G2Jac
	j.FromAffine(&a)
	return j
}

func f150Affine(j bn254.G2Jac) bn254.G2Affine {
	var a bn254.G2Affine
	a.FromJacobian(&j)
	return a
}

func f150Coords(a bn254.G2Affine) g2Coords {
	x0, x1 := bigFromE2(a.X)
	y0, y1 := bigFromE2(a.Y)
	return g2Coords{x0, x1, y0, y1}
}

// f150Psi is the untwist-Frobenius-twist endomorphism on the D-type twist,
// derived independently of the codegen's constants:
//
//	ψ(x, y) = (conj(x)·ξ^((p−1)/3), conj(y)·ξ^((p−1)/2)),  ξ = 9 + u.
func f150Psi(a bn254.G2Affine) bn254.G2Affine {
	var xi bn254.E2
	xi.A0.SetUint64(9)
	xi.A1.SetUint64(1)
	pm1 := new(big.Int).Sub(bn254FieldP, big.NewInt(1))
	var cx, cy bn254.E2
	cx.Exp(xi, new(big.Int).Div(pm1, big.NewInt(3)))
	cy.Exp(xi, new(big.Int).Div(pm1, big.NewInt(2)))
	var out bn254.G2Affine
	out.X.Conjugate(&a.X)
	out.X.Mul(&out.X, &cx)
	out.Y.Conjugate(&a.Y)
	out.Y.Mul(&out.Y, &cy)
	return out
}

// f150SixX2 is the Scott subgroup-test scalar 6x², recomputed from x.
func f150SixX2() *big.Int {
	k := new(big.Int).Mul(f150X, f150X)
	return k.Mul(k, big.NewInt(6))
}

type f150Vector struct {
	name string
	pt   bn254.G2Affine
}

var (
	f150Once    sync.Once
	f150Vectors []f150Vector
	f150Err     error
)

// f150TorsionPoint returns a point of order exactly q (q prime, q | h):
// [r·h/q]·P for the first MapToCurve2 seed that does not land on O.
func f150TorsionPoint(q int64) (bn254.G2Affine, error) {
	qq := big.NewInt(q)
	h := f150TwistCofactor()
	if new(big.Int).Mod(h, qq).Sign() != 0 {
		return bn254.G2Affine{}, fmt.Errorf("%d does not divide the twist cofactor", q)
	}
	cof := new(big.Int).Div(new(big.Int).Mul(h, f150R()), qq)
	for seed := uint64(1); seed < 64; seed++ {
		var e bn254.E2
		e.A0.SetUint64(seed)
		e.A1.SetUint64(5)
		p := bn254.MapToCurve2(&e)
		tj := f150Mul(f150Jac(p), cof)
		if tj.Z.IsZero() {
			continue
		}
		if chk := f150Mul(tj, qq); !chk.Z.IsZero() {
			return bn254.G2Affine{}, fmt.Errorf("[%d]T != O", q)
		}
		return f150Affine(tj), nil
	}
	return bn254.G2Affine{}, fmt.Errorf("no order-%d point found", q)
}

// f150BuildVectors constructs and independently checks every vector. Any
// failed property is an error: these vectors are security-load-bearing and
// must never silently degrade.
func f150BuildVectors() ([]f150Vector, error) {
	r := f150R()
	h := f150TwistCofactor()

	t10069, err := f150TorsionPoint(10069)
	if err != nil {
		return nil, err
	}
	t5864401, err := f150TorsionPoint(5864401)
	if err != nil {
		return nil, err
	}

	var seed bn254.E2
	seed.A0.SetUint64(11)
	seed.A1.SetUint64(13)
	cofTors := f150Affine(f150Mul(f150Jac(bn254.MapToCurve2(&seed)), r))

	_, _, _, g2 := bn254.Generators()
	mixedJ := f150Jac(g2)
	tj := f150Jac(t10069)
	mixedJ.AddAssign(&tj)
	mixed := f150Affine(mixedJ)

	vecs := []f150Vector{
		{"order-10069", t10069},
		{"order-5864401", t5864401},
		{"cofactor-torsion-[r]P", cofTors},
		{"G2gen+order-10069", mixed},
	}
	for _, v := range vecs {
		if !v.pt.IsOnCurve() {
			return nil, fmt.Errorf("%s: not on the twist", v.name)
		}
		j := f150Jac(v.pt)
		if j.Z.IsZero() {
			return nil, fmt.Errorf("%s: is the point at infinity", v.name)
		}
		// Not in G2 ⇔ [r]·P ≠ O (G2 is exactly the r-torsion of E'(Fp²)).
		if rp := f150Mul(j, r); rp.Z.IsZero() {
			return nil, fmt.Errorf("%s: [r]P == O, point is IN G2", v.name)
		}
		// The whole group has exponent dividing r·h.
		if o := f150Mul(j, new(big.Int).Mul(r, h)); !o.Z.IsZero() {
			return nil, fmt.Errorf("%s: [r·h]P != O; #E'(Fp²) != r·h", v.name)
		}
		// Off-chain prediction of the on-chain verdict: the Scott identity
		// ψ(P) == [6x²]P must FAIL. If it held, the generic path would
		// accept this vector — a security finding, not a test bug.
		psi := f150Psi(v.pt)
		kp := f150Affine(f150Mul(j, f150SixX2()))
		if psi.Equal(&kp) {
			return nil, fmt.Errorf("SECURITY: %s satisfies ψ(P) == [6x²]P off-chain; "+
				"the Scott subgroup test would ACCEPT it", v.name)
		}
	}
	return vecs, nil
}

func f150Setup(t *testing.T) []f150Vector {
	t.Helper()
	f150Once.Do(func() { f150Vectors, f150Err = f150BuildVectors() })
	if f150Err != nil {
		t.Fatal(f150Err)
	}
	return f150Vectors
}

func f150Vec(t *testing.T, name string) bn254.G2Affine {
	t.Helper()
	for _, v := range f150Setup(t) {
		if v.name == name {
			return v.pt
		}
	}
	t.Fatalf("no vector %q", name)
	return bn254.G2Affine{}
}

// f150IsInputAssertion reports whether a script failure is an aborted
// input assertion (OP_EQUALVERIFY inside the on-curve / subgroup checks)
// rather than a false pairing result. The multi-pairing harnesses finish
// with OP_VERIFY, so a pairing-product mismatch fails with that opcode
// instead.
func f150IsInputAssertion(err error) bool {
	return err != nil && strings.Contains(err.Error(), "OP_EQUALVERIFY")
}

// ---------------------------------------------------------------------------
// Vector construction and the 2-torsion impossibility proof
// ---------------------------------------------------------------------------

// TestF150_TwistHasNoTwoTorsion documents why no Y = 0 vector exists.
func TestF150_TwistHasNoTwoTorsion(t *testing.T) {
	r := f150R()
	h := f150TwistCofactor()

	// (1) Parity: #E'(Fp²) = r·h is odd.
	if r.Bit(0) != 1 || h.Bit(0) != 1 {
		t.Fatalf("twist order r·h is even; a 2-torsion vector may exist")
	}

	// (2) Direct: Y = 0 needs x³ = −b' in Fp². Fp²* is cyclic of order
	// p²−1 and 3 | p²−1, so −b' is a cube iff (−b')^((p²−1)/3) == 1.
	var xi, three, bTwist, negB bn254.E2
	xi.A0.SetUint64(9)
	xi.A1.SetUint64(1)
	three.A0.SetUint64(3)
	bTwist.Inverse(&xi)
	bTwist.Mul(&bTwist, &three)
	// Pin b' to the codegen's constant so this is the same twist.
	b0, b1 := bigFromE2(bTwist)
	if b0.Cmp(bn254TwistB0) != 0 || b1.Cmp(bn254TwistB1) != 0 {
		t.Fatalf("b' = 3/(9+u) disagrees with the codegen twist constant")
	}
	negB.Neg(&bTwist)
	p2m1 := new(big.Int).Sub(new(big.Int).Mul(bn254FieldP, bn254FieldP), big.NewInt(1))
	if new(big.Int).Mod(p2m1, big.NewInt(3)).Sign() != 0 {
		t.Fatal("3 does not divide p²−1")
	}
	var chi, one bn254.E2
	chi.Exp(negB, new(big.Int).Div(p2m1, big.NewInt(3)))
	one.SetOne()
	if chi.Equal(&one) {
		t.Fatal("−b' IS a cube in Fp²: a Y = 0 (2-torsion) twist point exists and must be added as a vector")
	}

	// (3) No prime below 10069 divides h, so 10069 is the smallest
	// nontrivial order any non-G2 twist point can have.
	for d := int64(2); d < 10069; d++ {
		if new(big.Int).Mod(h, big.NewInt(d)).Sign() == 0 {
			t.Fatalf("%d divides the twist cofactor; a smaller-order vector exists", d)
		}
	}
	for _, q := range []int64{10069, 5864401} {
		if !big.NewInt(q).ProbablyPrime(20) || new(big.Int).Mod(h, big.NewInt(q)).Sign() != 0 {
			t.Fatalf("%d is not a prime factor of the twist cofactor", q)
		}
	}
}

// TestF150_VectorsAreSmallOrderOffG2 builds the vectors (asserting their
// order, curve membership and non-membership in G2 inside f150BuildVectors)
// and cross-checks the independent ψ on the G2 generator, where the Scott
// identity must hold.
func TestF150_VectorsAreSmallOrderOffG2(t *testing.T) {
	if f150SixX2().Cmp(Bn254SubgroupCheckScalar()) != 0 {
		t.Fatal("6x² recomputed from x disagrees with the codegen scalar")
	}
	_, _, _, g2 := bn254.Generators()
	psi := f150Psi(g2)
	kg := f150Affine(f150Mul(f150Jac(g2), f150SixX2()))
	if !psi.Equal(&kg) {
		t.Fatal("independent ψ does not satisfy ψ(G) == [6x²]G on the G2 generator; ψ constants wrong")
	}
	for _, v := range f150Setup(t) {
		t.Logf("%s: x0=%s", v.name, f150Coords(v.pt).x0.Text(16))
	}
}

// ---------------------------------------------------------------------------
// Script execution
// ---------------------------------------------------------------------------

// TestF150_SmallOrderG2_PassesOnCurveCheck: every vector is on the twist,
// so the on-curve assertion alone ACCEPTS it. The rejections below can
// therefore only come from the subgroup check.
func TestF150_SmallOrderG2_PassesOnCurveCheck(t *testing.T) {
	for _, v := range f150Setup(t) {
		c := f150Coords(v.pt)
		if err := buildAndExecute(t, buildG2OnCurveOnlyHarness(c.x0, c.x1, c.y0, c.y1)); err != nil {
			t.Errorf("%s: rejected by the ON-CURVE check alone: %v", v.name, err)
		}
	}
}

func f150SubgroupOnlyHarness(c g2Coords) []StackOp {
	initNames := []string{"_q", "_x0", "_x1", "_y0", "_y1"}
	var ops []StackOp
	tr := NewBN254Tracker(initNames, func(op StackOp) { ops = append(ops, op) })
	preamble := []StackOp{
		pushBigInt(bn254FieldP),
		pushBigInt(c.x0), pushBigInt(c.x1), pushBigInt(c.y0), pushBigInt(c.y1),
	}
	tr.SetQAtBottom()
	tr.primeCacheActive = true
	bn254AssertG2InSubgroup(tr, "_x0", "_x1", "_y0", "_y1", "f150")
	for len(tr.nm) > 0 {
		tr.drop()
	}
	tr.e(StackOp{Op: "push", Value: bigIntPush(1)})
	return append(append([]StackOp{}, preamble...), ops...)
}

// TestF150_UnassistedSubgroupCheck_RejectsSmallOrderG2 runs the subgroup
// assertion that every generic pairing builtin emits, on each vector, with
// the G2 generator as the in-harness honest control.
func TestF150_UnassistedSubgroupCheck_RejectsSmallOrderG2(t *testing.T) {
	_, _, _, g2 := bn254.Generators()
	if err := buildAndExecute(t, f150SubgroupOnlyHarness(f150Coords(g2))); err != nil {
		t.Fatalf("control: G2 generator rejected by the unassisted subgroup check: %v", err)
	}
	for _, v := range f150Setup(t) {
		v := v
		t.Run(v.name, func(t *testing.T) {
			err := buildAndExecute(t, f150SubgroupOnlyHarness(f150Coords(v.pt)))
			if err == nil {
				t.Fatalf("SECURITY: unassisted G2 subgroup check ACCEPTED %s", v.name)
			}
			if !f150IsInputAssertion(err) {
				t.Fatalf("%s rejected, but not by an OP_EQUALVERIFY assertion: %v", v.name, err)
			}
		})
	}
}

// TestF150_BN254Pairing_RejectsSmallOrderG2: e(G1, T) with T of order
// 10069. The harness leaves the Fp12 result on the stack, so acceptance is
// truthiness; the rejection must be an input assertion.
func TestF150_BN254Pairing_RejectsSmallOrderG2(t *testing.T) {
	p := validG1()
	q := f150Coords(f150Vec(t, "order-10069"))
	err := runSinglePairing(p.x, p.y, q.x0, q.x1, q.y0, q.y1)
	if err == nil {
		t.Fatal("SECURITY: bn254Pairing ACCEPTED an order-10069 G2 point")
	}
	if !f150IsInputAssertion(err) {
		t.Fatalf("order-10069 G2 not rejected by an input assertion: %v", err)
	}
}

// TestF150_BN254MultiPairing4_RejectsSmallOrderG2 uses the cancelling
// configuration e(G,T)·e(−G,T)·e(G,Q)·e(−G,Q), asserted == 1 under gnark,
// so a script that skipped validation would return TRUE: a forgery. The
// rejection must therefore be an input assertion, not the final OP_VERIFY.
func TestF150_BN254MultiPairing4_RejectsSmallOrderG2(t *testing.T) {
	g := validG1()
	ng := negValidG1()
	q := validG2()
	for _, name := range []string{"order-10069", "G2gen+order-10069"} {
		name := name
		t.Run(name, func(t *testing.T) {
			bad := f150Coords(f150Vec(t, name))
			cfg := mp4Config{{g, bad}, {ng, bad}, {g, q}, {ng, q}}
			assertGnarkProductIsOne(t, cfg)
			err := runMultiPairing4(cfg)
			if err == nil {
				t.Fatalf("SECURITY: bn254MultiPairing4 returned TRUE for a product containing %s", name)
			}
			if !f150IsInputAssertion(err) {
				t.Fatalf("%s not rejected by an input assertion: %v", name, err)
			}
		})
	}
}

// TestF150_BN254MultiPairing3_RejectsSmallOrderG2: same cancelling forgery
// against the 3-pair + precomputed-Miller-loop emitter.
func TestF150_BN254MultiPairing3_RejectsSmallOrderG2(t *testing.T) {
	g := validG1()
	ng := negValidG1()
	q := validG2()
	bad := f150Coords(f150Vec(t, "order-10069"))
	pairs := [3]struct {
		p g1Coords
		q g2Coords
	}{{g, bad}, {ng, bad}, {g, q}}
	assertFourTermProductIsOne(t,
		[]bn254.G1Affine{gnarkG1(g), gnarkG1(ng), gnarkG1(g), gnarkG1(ng)},
		[]bn254.G2Affine{gnarkG2(bad), gnarkG2(bad), gnarkG2(q), gnarkG2(q)})
	pre := flatMillerLoop(t, []bn254.G1Affine{gnarkG1(ng)}, []bn254.G2Affine{gnarkG2(q)})
	err := runMultiPairing3(pairs, pre)
	if err == nil {
		t.Fatal("SECURITY: bn254MultiPairing3 returned TRUE for a product containing an order-10069 G2 point")
	}
	if !f150IsInputAssertion(err) {
		t.Fatalf("order-10069 G2 not rejected by an input assertion: %v", err)
	}
}

// TestF150_WAG2SubgroupCheck_RejectsSmallOrderG2: the witness-assisted
// subgroup check with HONEST gradients for the vector's own [6x²] chain
// (the chain is well-defined for an order-10069 point unless a prefix of
// 6x² hits 0 or ±1 mod 10069, which tryComputeSubgroupGradients reports).
// The prover cannot do better than honest gradients, so the abort must
// come from the final ψ(P) == [6x²]P comparison.
func TestF150_WAG2SubgroupCheck_RejectsSmallOrderG2(t *testing.T) {
	for _, name := range []string{"order-10069", "G2gen+order-10069"} {
		name := name
		t.Run(name, func(t *testing.T) {
			pt := f150Vec(t, name)
			gradients, ok := tryComputeSubgroupGradients(pt)
			if !ok {
				t.Fatalf("%s: [6x²] chain degenerates off-chain; vector does not exercise the final comparison", name)
			}
			c := f150Coords(pt)
			err := buildAndExecute(t, buildG2SubgroupHarness(t, c.x0, c.x1, c.y0, c.y1, gradients))
			if err == nil {
				t.Fatalf("SECURITY: witness-assisted G2 subgroup check ACCEPTED %s with honest gradients", name)
			}
		})
	}
}
