package runar

// Real BN254 pairing implementations for Go-mock tests.
//
// The int64-typed Bn254MultiPairing3/Bn254MultiPairing4 in bn254.go are
// deliberate mocks that return true — BN254 field elements are 254 bits
// and cannot fit in int64, so any "real" pairing that accepts Bigint
// (int64) coords would truncate every real-world coordinate and always
// fail. The Big variants below accept *big.Int coords directly and run a
// real gnark-crypto pairing check, matching the compiled Bitcoin Script
// semantics.
//
// Use the Big variants in Go-level unit tests that consume gnark-generated
// proofs and VKs. The compiled Script is unaffected by this file — it is
// produced by compilers/go/codegen/bn254*.go.

import (
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// bn254PointToG1Affine decodes a 64-byte Rúnar Point (x[32] || y[32],
// big-endian) into a gnark bn254.G1Affine. Identity (0,0) is rejected
// (matching the compiled-Script on-curve check). The returned point is
// NOT subgroup-checked — callers that need full validation should call
// `pt.IsInSubGroup()` themselves.
func bn254PointToG1Affine(p Point) (bn254.G1Affine, error) {
	var out bn254.G1Affine
	b := []byte(p)
	if len(b) != 64 {
		return out, fmt.Errorf("bn254 point: expected 64 bytes, got %d", len(b))
	}
	xBig := new(big.Int).SetBytes(b[:32])
	yBig := new(big.Int).SetBytes(b[32:])
	out.X.SetBigInt(xBig)
	out.Y.SetBigInt(yBig)
	if !out.IsOnCurve() {
		return out, fmt.Errorf("bn254 point not on curve")
	}
	return out, nil
}

// bn254CoordsToG2Affine constructs a bn254.G2Affine from four Rúnar G2
// coordinates (x0, x1, y0, y1) where x = x0 + x1*u, y = y0 + y1*u. gnark
// E2 is {A0 = real, A1 = imaginary}, so Rúnar order maps one-to-one with
// no swap.
func bn254CoordsToG2Affine(x0, x1, y0, y1 BigintBig) (bn254.G2Affine, error) {
	var out bn254.G2Affine
	if x0 == nil || x1 == nil || y0 == nil || y1 == nil {
		return out, fmt.Errorf("nil G2 coordinate")
	}
	var ex0, ex1, ey0, ey1 fp.Element
	ex0.SetBigInt(x0)
	ex1.SetBigInt(x1)
	ey0.SetBigInt(y0)
	ey1.SetBigInt(y1)
	out.X.A0 = ex0
	out.X.A1 = ex1
	out.Y.A0 = ey0
	out.Y.A1 = ey1
	if !out.IsOnCurve() {
		return out, fmt.Errorf("bn254 G2 point not on twist curve")
	}
	return out, nil
}

// Bn254G1ScalarMulBigP performs BN254 G1 scalar multiplication with a
// full 254-bit scalar, unlike the int64 Bn254G1ScalarMulP variant which
// silently truncates k to int64.
func Bn254G1ScalarMulBigP(p Point, k BigintBig) Point {
	if k == nil {
		return bn254BytesToPoint(make([]byte, 64))
	}
	return bn254BytesToPoint(Bn254G1ScalarMul(bn254PointToBytes(p), k))
}

// Bn254MultiPairing4Big computes the product of 4 pairings
//
//	e(p1,q1) * e(p2,q2) * e(p3,q3) * e(p4,q4)
//
// and returns true iff the product equals the identity in GT. Uses
// gnark-crypto's bn254.PairingCheck. Unlike the int64 Bn254MultiPairing4
// mock, this runs the full pairing and rejects invalid fixtures.
func Bn254MultiPairing4Big(
	p1 Point, q1x0, q1x1, q1y0, q1y1 BigintBig,
	p2 Point, q2x0, q2x1, q2y0, q2y1 BigintBig,
	p3 Point, q3x0, q3x1, q3y0, q3y1 BigintBig,
	p4 Point, q4x0, q4x1, q4y0, q4y1 BigintBig,
) bool {
	g1s := make([]bn254.G1Affine, 4)
	g2s := make([]bn254.G2Affine, 4)
	var err error
	if g1s[0], err = bn254PointToG1Affine(p1); err != nil {
		return false
	}
	if g1s[1], err = bn254PointToG1Affine(p2); err != nil {
		return false
	}
	if g1s[2], err = bn254PointToG1Affine(p3); err != nil {
		return false
	}
	if g1s[3], err = bn254PointToG1Affine(p4); err != nil {
		return false
	}
	if g2s[0], err = bn254CoordsToG2Affine(q1x0, q1x1, q1y0, q1y1); err != nil {
		return false
	}
	if g2s[1], err = bn254CoordsToG2Affine(q2x0, q2x1, q2y0, q2y1); err != nil {
		return false
	}
	if g2s[2], err = bn254CoordsToG2Affine(q3x0, q3x1, q3y0, q3y1); err != nil {
		return false
	}
	if g2s[3], err = bn254CoordsToG2Affine(q4x0, q4x1, q4y0, q4y1); err != nil {
		return false
	}
	ok, err := bn254.PairingCheck(g1s, g2s)
	if err != nil {
		return false
	}
	return ok
}

// Bn254MultiPairing3Big checks whether the product of 3 pairings multiplied
// by a pre-computed MillerLoop(α, -β) Fp12 constant equals the identity in
// GT after final exponentiation:
//
//	final_exp( MillerLoop(p1..p3, q1..q3) * alphaBeta_fp12 ) == 1 in Fp12
//
// The alphaBeta Fp12 arguments are passed in gnark flat coefficient order
// (same as compilers/go/codegen/bn254_groth16.go:Groth16Config.AlphaNegBetaFp12).
func Bn254MultiPairing3Big(
	p1 Point, q1x0, q1x1, q1y0, q1y1 BigintBig,
	p2 Point, q2x0, q2x1, q2y0, q2y1 BigintBig,
	p3 Point, q3x0, q3x1, q3y0, q3y1 BigintBig,
	alphaBeta0, alphaBeta1, alphaBeta2, alphaBeta3, alphaBeta4, alphaBeta5 BigintBig,
	alphaBeta6, alphaBeta7, alphaBeta8, alphaBeta9, alphaBeta10, alphaBeta11 BigintBig,
) bool {
	g1s := make([]bn254.G1Affine, 3)
	g2s := make([]bn254.G2Affine, 3)
	var err error
	if g1s[0], err = bn254PointToG1Affine(p1); err != nil {
		return false
	}
	if g1s[1], err = bn254PointToG1Affine(p2); err != nil {
		return false
	}
	if g1s[2], err = bn254PointToG1Affine(p3); err != nil {
		return false
	}
	if g2s[0], err = bn254CoordsToG2Affine(q1x0, q1x1, q1y0, q1y1); err != nil {
		return false
	}
	if g2s[1], err = bn254CoordsToG2Affine(q2x0, q2x1, q2y0, q2y1); err != nil {
		return false
	}
	if g2s[2], err = bn254CoordsToG2Affine(q3x0, q3x1, q3y0, q3y1); err != nil {
		return false
	}

	// Build the supplied Fp12 constant from 12 flat coefficients.
	var precomputed bn254.E12
	fp12Ptrs := [12]*fp.Element{
		&precomputed.C0.B0.A0, &precomputed.C0.B0.A1,
		&precomputed.C0.B1.A0, &precomputed.C0.B1.A1,
		&precomputed.C0.B2.A0, &precomputed.C0.B2.A1,
		&precomputed.C1.B0.A0, &precomputed.C1.B0.A1,
		&precomputed.C1.B1.A0, &precomputed.C1.B1.A1,
		&precomputed.C1.B2.A0, &precomputed.C1.B2.A1,
	}
	fp12Args := [12]BigintBig{
		alphaBeta0, alphaBeta1, alphaBeta2, alphaBeta3, alphaBeta4, alphaBeta5,
		alphaBeta6, alphaBeta7, alphaBeta8, alphaBeta9, alphaBeta10, alphaBeta11,
	}
	for i, ptr := range fp12Ptrs {
		if fp12Args[i] == nil {
			return false
		}
		ptr.SetBigInt(fp12Args[i])
	}

	// MillerLoop of the 3 pairs, multiply by the precomputed constant, then
	// one FinalExponentiation. gnark-crypto's MillerLoop API takes slices.
	ml, err := bn254.MillerLoop(g1s, g2s)
	if err != nil {
		return false
	}
	var combined bn254.E12
	combined.Mul(&ml, &precomputed)
	result := bn254.FinalExponentiation(&combined)
	var one bn254.E12
	one.SetOne()
	return result.Equal(&one)
}
