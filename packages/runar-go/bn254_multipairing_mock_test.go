package runar

import (
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

// F-358: Bn254MultiPairing4 and Bn254MultiPairing3 (the int64/Bigint-typed
// Go mocks in bn254.go) unconditionally returned true, so a native Go test
// that calls them with a forged proof could never detect the forgery.
//
// The forgery here supplies the G2 point-at-infinity encoding (0,0,0,0) —
// Fp2 coordinates small enough to fit in the int64 Bigint parameter type —
// for every pair, with proof.A deliberately swapped to the negated
// generator instead of the honest witness.
//
// What this proves: at HEAD, Bn254MultiPairing4/3 ignore every argument
// and return true for this forged/degenerate configuration — a false
// accept. After the fix (delegating to the real gnark-crypto pairing via
// Bn254MultiPairing4Big/Bn254MultiPairing3Big), the same call returns
// false, so the always-true oracle is gone.
//
// What this does NOT prove: that the fix detects A-tampering specifically,
// or that Bn254MultiPairing4/3 can accept a genuine, non-degenerate Groth16
// proof through their int64 G2-coordinate parameters. Through this int64
// entry point every call's G2 side decodes to the point at infinity or
// something off-curve/off-subgroup — no valid, non-identity BN254 G2 point
// has all four Fp2 coordinates small enough to fit in int64 — so
// bn254CoordsToG2Affine's identity/curve/subgroup check rejects before the
// Miller loop ever runs, independent of A. The swap is kept only for
// traceability to the brief's "swapped A" wording; the real pairing
// arithmetic (and genuine A-tampering detection) is exercised by the *Big
// variants in bn254_real_pairing_test.go, whose BigintBig parameters can
// carry actual 254-bit coordinates.
func TestBn254MultiPairing4_RejectsDegenerateProof(t *testing.T) {
	_, _, g1Aff, _ := bn254.Generators()
	honestA := g1AffineToPoint(g1Aff)
	var wrong bn254.G1Affine
	wrong.Neg(&g1Aff)
	swappedA := g1AffineToPoint(wrong) // deliberately wrong proof.A

	ok := Bn254MultiPairing4(
		swappedA, 0, 0, 0, 0,
		honestA, 0, 0, 0, 0,
		honestA, 0, 0, 0, 0,
		honestA, 0, 0, 0, 0,
	)
	if ok {
		t.Fatal("Bn254MultiPairing4 accepted a forged/degenerate proof (G2 identity encoding) — the mock always returns true regardless of input")
	}
}

// Bn254MultiPairing3 variant of the same forgery (3 pairs + a precomputed
// Fp12 constant, all zero so the "constant" is Fp12 one). See the
// Bn254MultiPairing4 test above for what this does and does not prove.
func TestBn254MultiPairing3_RejectsDegenerateProof(t *testing.T) {
	_, _, g1Aff, _ := bn254.Generators()
	var wrong bn254.G1Affine
	wrong.Neg(&g1Aff)
	swappedA := g1AffineToPoint(wrong)
	honest := g1AffineToPoint(g1Aff)

	ok := Bn254MultiPairing3(
		swappedA, 0, 0, 0, 0,
		honest, 0, 0, 0, 0,
		honest, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0,
	)
	if ok {
		t.Fatal("Bn254MultiPairing3 accepted a forged/degenerate proof (G2 identity encoding) — the mock always returns true regardless of input")
	}
}
