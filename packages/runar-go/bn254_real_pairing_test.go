package runar

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
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
