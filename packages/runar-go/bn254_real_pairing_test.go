package runar

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// g1AffineToPoint encodes a gnark bn254.G1Affine as a Rúnar 64-byte Point
// (x[32] || y[32], big-endian).
func g1AffineToPoint(p bn254.G1Affine) Point {
	buf := make([]byte, 64)
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	copy(buf[:32], xBytes[:])
	copy(buf[32:], yBytes[:])
	return Point(buf)
}

// g2AffineToRunarCoords returns (x0, x1, y0, y1) as Rúnar-ordered *big.Int
// coordinates, matching the G2 convention Bn254CoordsToG2Affine expects.
// gnark E2 is {A0 = real, A1 = imag}, so no swap.
func g2AffineToRunarCoords(q bn254.G2Affine) (x0, x1, y0, y1 *big.Int) {
	x0 = new(big.Int)
	x1 = new(big.Int)
	y0 = new(big.Int)
	y1 = new(big.Int)
	qx0 := q.X.A0.BigInt(new(big.Int))
	qx1 := q.X.A1.BigInt(new(big.Int))
	qy0 := q.Y.A0.BigInt(new(big.Int))
	qy1 := q.Y.A1.BigInt(new(big.Int))
	return qx0, qx1, qy0, qy1
}

// trivialPairingInstance constructs a tiny but valid SP1-style Groth16
// pairing instance where:
//
//	α = G1, β = G2, γ = 2·G2, δ = 3·G2
//	IC[0] = G1, IC[1] = 2·G1
//	publicInput = 1, so prepared = G1 + 1·(2·G1) = 3·G1
//	A = 13·G1, B = G2, C = 2·G1
//
// Exponent check: 13·1 - 3·2 - 2·3 - 1·1 = 0  ✓
//
// Returns the 4 (G1, G2) pairs with γ, δ, β pre-negated on the G2 side
// (SP1 convention) — ready for Bn254MultiPairing4Big.
func trivialPairingInstance() (
	p1 bn254.G1Affine, q1 bn254.G2Affine, // (A, B)
	p2 bn254.G1Affine, q2 bn254.G2Affine, // (prepared, -γ)
	p3 bn254.G1Affine, q3 bn254.G2Affine, // (C, -δ)
	p4 bn254.G1Affine, q4 bn254.G2Affine, // (α, -β)
) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	scaleG1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return p
	}
	scaleG2 := func(k int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2Aff, big.NewInt(k))
		return p
	}

	alpha := scaleG1(1)
	beta := scaleG2(1)
	gamma := scaleG2(2)
	delta := scaleG2(3)
	prepared := scaleG1(3)
	a := scaleG1(13)
	b := scaleG2(1)
	c := scaleG1(2)

	var negBeta, negGamma, negDelta bn254.G2Affine
	negBeta.Neg(&beta)
	negGamma.Neg(&gamma)
	negDelta.Neg(&delta)

	return a, b, prepared, negGamma, c, negDelta, alpha, negBeta
}

// TestBn254MultiPairing4Big_AcceptsValidInstance verifies a trivial but
// cryptographically valid 4-pairing product equals the identity in GT.
func TestBn254MultiPairing4Big_AcceptsValidInstance(t *testing.T) {
	p1, q1, p2, q2, p3, q3, p4, q4 := trivialPairingInstance()

	q1x0, q1x1, q1y0, q1y1 := g2AffineToRunarCoords(q1)
	q2x0, q2x1, q2y0, q2y1 := g2AffineToRunarCoords(q2)
	q3x0, q3x1, q3y0, q3y1 := g2AffineToRunarCoords(q3)
	q4x0, q4x1, q4y0, q4y1 := g2AffineToRunarCoords(q4)

	ok := Bn254MultiPairing4Big(
		g1AffineToPoint(p1), q1x0, q1x1, q1y0, q1y1,
		g1AffineToPoint(p2), q2x0, q2x1, q2y0, q2y1,
		g1AffineToPoint(p3), q3x0, q3x1, q3y0, q3y1,
		g1AffineToPoint(p4), q4x0, q4x1, q4y0, q4y1,
	)
	if !ok {
		t.Fatal("Bn254MultiPairing4Big rejected a valid synthetic Groth16 instance")
	}
}

// TestBn254MultiPairing4Big_RejectsCorruptedProof flips a byte in proof.A
// and confirms the pairing check fails. Without this test the mock's
// return-true sloppiness would mask genuine proof corruption.
func TestBn254MultiPairing4Big_RejectsCorruptedProof(t *testing.T) {
	p1, q1, p2, q2, p3, q3, p4, q4 := trivialPairingInstance()

	// Corrupt proof A (p1): use α=G1 instead of the valid 13·G1. The resulting
	// pairing product is no longer 1 in GT.
	_, _, g1Aff, _ := bn254.Generators()
	p1 = g1Aff

	q1x0, q1x1, q1y0, q1y1 := g2AffineToRunarCoords(q1)
	q2x0, q2x1, q2y0, q2y1 := g2AffineToRunarCoords(q2)
	q3x0, q3x1, q3y0, q3y1 := g2AffineToRunarCoords(q3)
	q4x0, q4x1, q4y0, q4y1 := g2AffineToRunarCoords(q4)

	ok := Bn254MultiPairing4Big(
		g1AffineToPoint(p1), q1x0, q1x1, q1y0, q1y1,
		g1AffineToPoint(p2), q2x0, q2x1, q2y0, q2y1,
		g1AffineToPoint(p3), q3x0, q3x1, q3y0, q3y1,
		g1AffineToPoint(p4), q4x0, q4x1, q4y0, q4y1,
	)
	if ok {
		t.Fatal("Bn254MultiPairing4Big accepted a corrupted proof — real pairing failed to reject")
	}
}

// TestBn254G1ScalarMulBigP_WideScalar scalar-multiplies G1 by a 254-bit
// value and cross-checks the result against gnark. The legacy int64 variant
// would truncate at 2^63.
func TestBn254G1ScalarMulBigP_WideScalar(t *testing.T) {
	_, _, g1Aff, _ := bn254.Generators()

	// A scalar that doesn't fit in int64: 2^80 + 7.
	k := new(big.Int).Lsh(big.NewInt(1), 80)
	k.Add(k, big.NewInt(7))

	var expected bn254.G1Affine
	expected.ScalarMultiplication(&g1Aff, k)

	gotPoint := Bn254G1ScalarMulBigP(g1AffineToPoint(g1Aff), k)

	expectedPoint := g1AffineToPoint(expected)
	if string(gotPoint) != string(expectedPoint) {
		t.Fatalf("wide-scalar scalar-mul mismatch: got %x, want %x",
			[]byte(gotPoint), []byte(expectedPoint))
	}

	// Cross-check: the legacy int64 variant truncates k to int64 and
	// therefore produces a DIFFERENT (incorrect) point — confirming the
	// caveat in the int64 variant's doc.
	legacyPoint := Bn254G1ScalarMulP(g1AffineToPoint(g1Aff), k.Int64())
	if string(legacyPoint) == string(expectedPoint) {
		t.Fatal("legacy Bn254G1ScalarMulP unexpectedly matched wide-scalar result")
	}
}

// TestBn254MultiPairing3Big_AcceptsValidInstance consumes only 3 on-chain
// pairs and a pre-computed MillerLoop(α, -β) Fp12. This matches the
// optimisation in Groth16Config.AlphaNegBetaFp12 used by the compiled
// witness-assisted verifier.
func TestBn254MultiPairing3Big_AcceptsValidInstance(t *testing.T) {
	p1, q1, p2, q2, p3, q3, alpha, negBeta := trivialPairingInstance()

	// Pre-compute MillerLoop(α, -β) as 12 flat Fp coefficients.
	ml, err := bn254.MillerLoop([]bn254.G1Affine{alpha}, []bn254.G2Affine{negBeta})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	fp12 := [12]*big.Int{
		ml.C0.B0.A0.BigInt(new(big.Int)), ml.C0.B0.A1.BigInt(new(big.Int)),
		ml.C0.B1.A0.BigInt(new(big.Int)), ml.C0.B1.A1.BigInt(new(big.Int)),
		ml.C0.B2.A0.BigInt(new(big.Int)), ml.C0.B2.A1.BigInt(new(big.Int)),
		ml.C1.B0.A0.BigInt(new(big.Int)), ml.C1.B0.A1.BigInt(new(big.Int)),
		ml.C1.B1.A0.BigInt(new(big.Int)), ml.C1.B1.A1.BigInt(new(big.Int)),
		ml.C1.B2.A0.BigInt(new(big.Int)), ml.C1.B2.A1.BigInt(new(big.Int)),
	}

	q1x0, q1x1, q1y0, q1y1 := g2AffineToRunarCoords(q1)
	q2x0, q2x1, q2y0, q2y1 := g2AffineToRunarCoords(q2)
	q3x0, q3x1, q3y0, q3y1 := g2AffineToRunarCoords(q3)

	ok := Bn254MultiPairing3Big(
		g1AffineToPoint(p1), q1x0, q1x1, q1y0, q1y1,
		g1AffineToPoint(p2), q2x0, q2x1, q2y0, q2y1,
		g1AffineToPoint(p3), q3x0, q3x1, q3y0, q3y1,
		fp12[0], fp12[1], fp12[2], fp12[3], fp12[4], fp12[5],
		fp12[6], fp12[7], fp12[8], fp12[9], fp12[10], fp12[11],
	)
	if !ok {
		t.Fatal("Bn254MultiPairing3Big rejected a valid synthetic instance with precomputed α·-β")
	}
}

// ---------------------------------------------------------------------------
// F-127: off-chain / on-chain input-validation parity
//
// The compiled bn254MultiPairing4 / bn254MultiPairing3 scripts validate every
// input point before the Miller loop (compilers/go/codegen/
// bn254_point_validation.go). Executing EmitBN254MultiPairing4 on the
// cancelling configurations below gives (see the F-127 remediation log):
//
//	G1 = 64 zero bytes          -> rejected (y^2 == x^3 + 3 fails)
//	G2 = (0, 0, 0, 0)           -> rejected (twist equation fails)
//	G1 x or y coordinate + p    -> rejected (0 <= coord < p, R-141)
//	G2 on twist, off subgroup   -> rejected (psi(P) == [6x^2]P fails)
//	G2 coordinate +p or -p      -> ACCEPTED (arithmetic is mod p)
//
// Each negative is a forgery: under gnark's reference pairing, with the
// coordinates reduced mod p and (0,0) read as infinity, the product is 1.
// So a FALSE from the wrapper can only come from input validation.
// ---------------------------------------------------------------------------

type bigPair struct {
	p Point
	q [4]*big.Int
}

func mp4Big(pairs [4]bigPair) bool {
	return Bn254MultiPairing4Big(
		pairs[0].p, pairs[0].q[0], pairs[0].q[1], pairs[0].q[2], pairs[0].q[3],
		pairs[1].p, pairs[1].q[0], pairs[1].q[1], pairs[1].q[2], pairs[1].q[3],
		pairs[2].p, pairs[2].q[0], pairs[2].q[1], pairs[2].q[2], pairs[2].q[3],
		pairs[3].p, pairs[3].q[0], pairs[3].q[1], pairs[3].q[2], pairs[3].q[3],
	)
}

// assertGnarkForgery fails unless gnark-crypto, decoding the inputs the
// lenient way (SetBigInt reduces mod p, (0,0) is infinity, no subgroup
// check), says the product is 1. That is what makes each negative non-vacuous.
func assertGnarkForgery(t *testing.T, pairs []bigPair) {
	t.Helper()
	var g1s []bn254.G1Affine
	var g2s []bn254.G2Affine
	for _, pr := range pairs {
		b := []byte(pr.p)
		var p bn254.G1Affine
		p.X.SetBigInt(new(big.Int).SetBytes(b[:32]))
		p.Y.SetBigInt(new(big.Int).SetBytes(b[32:]))
		var q bn254.G2Affine
		q.X.A0.SetBigInt(pr.q[0])
		q.X.A1.SetBigInt(pr.q[1])
		q.Y.A0.SetBigInt(pr.q[2])
		q.Y.A1.SetBigInt(pr.q[3])
		g1s = append(g1s, p)
		g2s = append(g2s, q)
	}
	ok, err := bn254.PairingCheck(g1s, g2s)
	if err != nil || !ok {
		t.Fatalf("configuration is not a forgery under gnark (ok=%v err=%v); the negative would be vacuous", ok, err)
	}
}

func f127Fixtures() (g, ng Point, q [4]*big.Int, fieldP *big.Int) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	var neg bn254.G1Affine
	neg.Neg(&g1Aff)
	x0, x1, y0, y1 := g2AffineToRunarCoords(g2Aff)
	return g1AffineToPoint(g1Aff), g1AffineToPoint(neg), [4]*big.Int{x0, x1, y0, y1}, fp.Modulus()
}

// TestBn254MultiPairing4Big_RejectsG1Identity is the F-127 repro: the 64-zero
// Point used to pass gnark's IsOnCurve (gnark encodes infinity as (0,0)) and
// drop out of the product, so this returned true. The script rejects it.
func TestBn254MultiPairing4Big_RejectsG1Identity(t *testing.T) {
	g, ng, q, _ := f127Fixtures()
	zero := Point(make([]byte, 64))
	pairs := [4]bigPair{{zero, q}, {g, q}, {ng, q}, {zero, q}}
	assertGnarkForgery(t, pairs[:])
	if mp4Big(pairs) {
		t.Fatal("Bn254MultiPairing4Big accepted the G1 identity (64 zero bytes); the compiled script rejects it")
	}
}

// TestBn254MultiPairing4Big_RejectsG2Identity: the all-zero G2 encoding is
// gnark's infinity too. The script's twist-equation check rejects it.
func TestBn254MultiPairing4Big_RejectsG2Identity(t *testing.T) {
	g, ng, q, _ := f127Fixtures()
	z := [4]*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	pairs := [4]bigPair{{g, z}, {ng, z}, {g, q}, {ng, q}}
	assertGnarkForgery(t, pairs[:])
	if mp4Big(pairs) {
		t.Fatal("Bn254MultiPairing4Big accepted the all-zero G2 identity; the compiled script rejects it")
	}
}

// TestBn254MultiPairing4Big_RejectsNonCanonicalG1: (x+p, y) and (x, y+p)
// alias the generator once reduced. The script requires 0 <= coord < p.
func TestBn254MultiPairing4Big_RejectsNonCanonicalG1(t *testing.T) {
	g, ng, q, fieldP := f127Fixtures()
	for _, half := range []int{0, 1} {
		b := []byte(g)
		c := new(big.Int).SetBytes(b[half*32 : half*32+32])
		c.Add(c, fieldP)
		alias := make([]byte, 64)
		copy(alias, b)
		c.FillBytes(alias[half*32 : half*32+32])
		pairs := [4]bigPair{{Point(alias), q}, {ng, q}, {g, q}, {ng, q}}
		assertGnarkForgery(t, pairs[:])
		if mp4Big(pairs) {
			t.Fatalf("Bn254MultiPairing4Big accepted a non-canonical G1 coordinate (half %d = coord+p); the compiled script rejects it", half)
		}
	}
}

// TestBn254MultiPairing4Big_RejectsOffSubgroupG2: a point on the twist but in
// the cofactor torsion (same MapToCurve2 seed the codegen tests use). The
// script's subgroup check rejects it; IsOnCurve alone does not.
func TestBn254MultiPairing4Big_RejectsOffSubgroupG2(t *testing.T) {
	g, ng, q, _ := f127Fixtures()
	var seed bn254.E2
	seed.A0.SetUint64(1)
	seed.A1.SetUint64(3)
	aff := bn254.MapToCurve2(&seed)
	if !aff.IsOnCurve() || aff.IsInSubGroup() {
		t.Fatal("adversarial G2 seed (1,3) must be on the twist and outside the subgroup")
	}
	bx0, bx1, by0, by1 := g2AffineToRunarCoords(aff)
	bad := [4]*big.Int{bx0, bx1, by0, by1}
	pairs := [4]bigPair{{g, bad}, {ng, bad}, {g, q}, {ng, q}}
	assertGnarkForgery(t, pairs[:])
	if mp4Big(pairs) {
		t.Fatal("Bn254MultiPairing4Big accepted an on-twist but off-subgroup G2 point; the compiled script rejects it")
	}
}

// TestBn254MultiPairing4Big_AcceptsNonCanonicalG2: the other side of parity.
// The script reduces G2 coordinates mod p and accepts x0+p and x0-p, so the
// wrapper must too. Guards against over-tightening the G2 decoder.
func TestBn254MultiPairing4Big_AcceptsNonCanonicalG2(t *testing.T) {
	g, ng, q, fieldP := f127Fixtures()
	for _, delta := range []*big.Int{fieldP, new(big.Int).Neg(fieldP)} {
		alias := [4]*big.Int{new(big.Int).Add(q[0], delta), q[1], q[2], q[3]}
		pairs := [4]bigPair{{g, alias}, {ng, alias}, {g, q}, {ng, q}}
		if !mp4Big(pairs) {
			t.Fatalf("Bn254MultiPairing4Big rejected G2 x0%+v·p; the compiled script accepts it", delta.Sign())
		}
	}
}

// TestBn254MultiPairing3Big_RejectsG1Identity: same decoder, other entry
// point. With precomputed = 1 in Fp12, e(0,Q)·e(G,Q)·e(-G,Q) is 1 under
// gnark's lenient decoding; the script rejects the identity.
func TestBn254MultiPairing3Big_RejectsG1Identity(t *testing.T) {
	g, ng, q, _ := f127Fixtures()
	zero := Point(make([]byte, 64))
	one, z := big.NewInt(1), big.NewInt(0)
	if Bn254MultiPairing3Big(
		zero, q[0], q[1], q[2], q[3],
		g, q[0], q[1], q[2], q[3],
		ng, q[0], q[1], q[2], q[3],
		one, z, z, z, z, z, z, z, z, z, z, z,
	) {
		t.Fatal("Bn254MultiPairing3Big accepted the G1 identity (64 zero bytes); the compiled script rejects it")
	}
}
