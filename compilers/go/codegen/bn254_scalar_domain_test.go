package codegen

import (
	"math/big"
	"testing"
)

// Scalar-domain tests for the two BN254 G1 double-and-add ladders,
// EmitBN254G1ScalarMul and emitG1ScalarMulNamed (the Groth16 one).
//
// Both build k' = k + 3r and then run 255 iterations from bit 254 down to 0,
// with the accumulator seeded at bit 255 rather than stepped. That is sound
// ONLY for k in [0, r-1], and nothing reduced k. The scalars are Groth16
// PUBLIC INPUTS -- caller-supplied -- so the domain is attacker-chosen.
//
// The interval argument, redone for BN254 rather than assumed from
// secp256k1 (the numbers are NOT the same -- see EmitBN254G1ScalarMul):
//
//	r.bit_length   = 254        (secp256k1: n is 256 bits)
//	3r.bit_length  = 256        (secp256k1: 3n is 258 bits)
//	3r    >= 2^255              so bit 255 is set for every k in [0, r-1]
//	4r-1   < 2^256              so no bit above 255 is ever set
//
// Hence: seed at bit 255, iterate 254..0. That is exactly what both ladders
// already do -- the offset and the iteration count were right. What was
// missing is the precondition they rest on.
//
// Out of domain, both halves of the bound break:
//
//	k >= 2^256 - 3r  (~2.2902 r)   k' sets bit 256, which the loop never
//	                               reads, so the ladder returns a DIFFERENT
//	                               multiple of P instead of failing.
//	k <= -r                        k' drops below 2^255, so the seeded bit
//	                               255 is a lie and the result is garbage.
//
// Separately, sweeping c_i = k' >> i over the whole domain shows the
// Jacobian mixed-add's exceptional cases (c_i = 0, 1, 2 mod r) are reachable
// at i = 0 ONLY, at k = 0 (accumulator = -P) and k = 2 (accumulator = P).
// k = 2 was already handled -- bn254BuildJacobianAddAffineInline branches on
// H == 0 at every step -- but k = 0 was not: H == 0 with R != 0 also took
// the doubling branch, returning -2P where the answer is the point at
// infinity. A public input of 0 is entirely ordinary in Groth16.

// bn254AllZeroPoint is this codegen's encoding of the point at infinity: the
// affine x||y blob cannot represent O, so the Jacobian-to-affine conversion's
// Fermat inverse turns Z = 0 into 64 zero bytes. Same convention as
// secp256k1 / P-256 / P-384. It is not on the curve (0 != 0 + 3), so
// EmitBN254G1OnCurve rejects it.
func bn254AllZeroPoint() (x, y *big.Int) {
	return big.NewInt(0), big.NewInt(0)
}

// TestBN254G1ScalarMul_ScalarDomain exercises EmitBN254G1ScalarMul outside
// [0, r-1] and at the two reachable degenerate steps.
func TestBN254G1ScalarMul_ScalarDomain(t *testing.T) {
	gx := big.NewInt(1)
	gy := big.NewInt(2)
	r := new(big.Int).Set(bn254CurveR)
	p := new(big.Int).Set(bn254FieldP)
	zx, zy := bn254AllZeroPoint()

	x3, y3 := bn254ComputeKG(t, 3)
	x5, y5 := bn254ComputeKG(t, 5)
	x7, y7 := bn254ComputeKG(t, 7)

	// -G = (gx, p - gy)
	negGy := new(big.Int).Sub(p, gy)

	mul := func(a int64, b *big.Int) *big.Int { return new(big.Int).Mul(big.NewInt(a), b) }
	add := func(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }
	sub := func(a, b *big.Int) *big.Int { return new(big.Int).Sub(a, b) }

	cases := []struct {
		name       string
		k          *big.Int
		expX, expY *big.Int
		why        string
	}{
		{"k=0", big.NewInt(0), zx, zy,
			"0*G is O; the last step adds P to -P, which is H == 0 with R != 0"},
		{"k=r", r, zx, zy,
			"r = 0 mod r, so also O -- needs the reduce, k' = 4r would otherwise be in range and give -2G"},
		{"k=3r", mul(3, r), zx, zy,
			"k' = 6r sets bit 256, above the loop's top bit"},
		{"k=r+5", add(r, big.NewInt(5)), x5, y5,
			"in-range residue, out-of-range scalar"},
		{"k=3r+7", add(mul(3, r), big.NewInt(7)), x7, y7,
			"bit-256 overflow with a non-identity answer"},
		{"k=-1", big.NewInt(-1), gx, negGy,
			"(r-1)*G = -G; OP_MOD takes the sign of the dividend, so the reduce must normalise"},
		{"k=-2r", mul(-2, r), zx, zy,
			"k' = r has bit 255 CLEAR, so the seeded accumulator bit is wrong"},
		{"k=-r+3", add(sub(big.NewInt(0), r), big.NewInt(3)), x3, y3,
			"k' = 2r+3 is also below 2^255"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mulOps := gatherOps(EmitBN254G1ScalarMul)

			var ops []StackOp
			ops = append(ops, pushPoint(gx, gy))
			ops = append(ops, pushBigInt(tc.k))
			ops = append(ops, mulOps...)
			ops = append(ops, pushPoint(tc.expX, tc.expY))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Fatalf("EmitBN254G1ScalarMul(G, %s): %s: %v", tc.k, tc.why, err)
			}
		})
	}
}

// TestBN254G1ScalarMul_AllZeroPointIsNotOnCurve pins the O encoding: the
// scalar-mul tests above assert 64 zero bytes for k = 0 mod r, and that is
// only a safe answer because the documented on-curve gate rejects it.
func TestBN254G1ScalarMul_AllZeroPointIsNotOnCurve(t *testing.T) {
	zx, zy := bn254AllZeroPoint()

	var ops []StackOp
	ops = append(ops, pushPoint(zx, zy))
	ops = append(ops, gatherOps(EmitBN254G1OnCurve)...)
	ops = append(ops, opcode("OP_NOT"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("bn254G1OnCurve(all-zero point) should be false: %v", err)
	}
}

// TestBN254G1AffineAdd_ZeroDenominatorIsNotMaskedToInfinity guards the
// PRECISION of the infinity mask added for P + (-P)
// (TestBN254G1Add_PointAtInfinity): it must key on px == qx AND py != qy, and
// must NOT key on a zero slope denominator.
//
// bn254G1AffineAdd uses the unified slope
//
//	s = (px^2 + px*qx + qx^2) / (py + qy)
//
// whose denominator is py + qy, and BN254 has j-invariant 0 with p = 1 mod 3,
// so F_p contains a primitive cube root of unity w. For any curve point (x, y)
// the point (w*x, y) is also on the curve, hence Q = (w*x, -y) has py + qy == 0
// while Q != -P -- and the true sum P + Q is an ORDINARY point, not O. Masking
// a zero denominator to the all-zero blob would answer "point at infinity"
// there: plausible and wrong, the exact failure mode 03f50d48 introduced on the
// NIST curves and f16790a9 had to undo.
//
// SEPARATE, PRE-EXISTING DEFECT, deliberately NOT asserted here: this input
// does not merely fail closed. Both the numerator and the denominator vanish
// (w^2 + w + 1 == 0 makes px^2 + px*qx + qx^2 == 0), Fermat gives inv(0) = 0,
// so s = 0 and the result is (-(px + qx), -py) -- which satisfies
// y^2 = x^3 + 3, because (1 + w)^3 == -1. bn254G1Add answers the zero
// denominator with a WRONG but ON-CURVE point, so assert(bn254G1OnCurve(r))
// does not catch it. Fixing that means replacing the unified slope with the
// chord/tangent selection secp256k1 and the NIST curves use, which also moves
// the shared Groth16 MSM path; it is out of scope for the P == -Q mask.
func TestBN254G1AffineAdd_ZeroDenominatorIsNotMaskedToInfinity(t *testing.T) {
	p := new(big.Int).Set(bn254FieldP)
	gx := big.NewInt(1)
	gy := big.NewInt(2)
	negGy := new(big.Int).Sub(p, gy)

	// w = primitive cube root of unity mod p: b^((p-1)/3) for the first small
	// b that does not land on 1.
	exp := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(3))
	var w *big.Int
	for b := int64(2); b < 100; b++ {
		cand := new(big.Int).Exp(big.NewInt(b), exp, p)
		if cand.Cmp(big.NewInt(1)) != 0 {
			w = cand
			break
		}
	}
	if w == nil {
		t.Fatal("no primitive cube root of unity found mod p")
	}
	if new(big.Int).Exp(w, big.NewInt(3), p).Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("w is not a cube root of unity: %s", w)
	}

	// Q = (w*gx, -gy): on the curve, distinct from -G, zero denominator.
	qx := new(big.Int).Mul(w, gx)
	qx.Mod(qx, p)
	if qx.Cmp(gx) == 0 {
		t.Fatal("w*gx == gx: the endomorphism image is not a distinct point")
	}
	if new(big.Int).Mod(new(big.Int).Add(gy, negGy), p).Sign() != 0 {
		t.Fatal("py + qy is not zero: the input does not exercise the denominator")
	}

	zx, zy := bn254AllZeroPoint()

	var ops []StackOp
	ops = append(ops, pushPoint(gx, gy))
	ops = append(ops, pushPoint(qx, negGy))
	ops = append(ops, gatherOps(EmitBN254G1Add)...)
	ops = append(ops, pushPoint(zx, zy))
	ops = append(ops, opcode("OP_EQUAL"))
	ops = append(ops, opcode("OP_NOT"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("bn254G1Add(G, (w*gx, -gy)) must NOT be masked to the all-zero point: %v", err)
	}
}
