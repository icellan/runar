package runar

import (
	"bytes"
	"testing"
)

// TestBn254G1OnCurve_RejectsIdentity asserts that the Go mock matches the
// compiled Script codegen in compilers/go/codegen/bn254.go (EmitBN254G1OnCurve)
// which evaluates y² == x³ + 3 directly and therefore rejects (0, 0).
func TestBn254G1OnCurve_RejectsIdentity(t *testing.T) {
	identity := make([]byte, 64) // all zeros → (x=0, y=0)
	if Bn254G1OnCurve(identity) {
		t.Fatal("Bn254G1OnCurve((0,0)) returned true; Script codegen rejects this point")
	}
}

// TestBn254G1Add_IdentityDoesNotAliasP2 ensures the returned slice is a fresh
// allocation when the left operand is identity. Returning the input slice
// directly causes surprise mutation bugs for callers that later mutate the
// result expecting independent storage.
func TestBn254G1Add_IdentityDoesNotAliasP2(t *testing.T) {
	identity := make([]byte, 64)
	// Generator G1 = (1, 2) as a 64-byte big-endian point.
	g1 := make([]byte, 64)
	g1[31] = 1 // x = 1
	g1[63] = 2 // y = 2
	original := append([]byte(nil), g1...)

	result := Bn254G1Add(identity, g1)
	if !bytes.Equal(result, g1) {
		t.Fatalf("Bn254G1Add(identity, g1) should equal g1")
	}

	// Mutate the result; the caller's operand must remain unchanged.
	result[0] = 0xFF
	if !bytes.Equal(g1, original) {
		t.Fatal("Bn254G1Add aliased p2: mutating result changed the input slice")
	}
}

// TestBn254G1Add_IdentityDoesNotAliasP1 — mirror of the above with identity
// as the right operand.
func TestBn254G1Add_IdentityDoesNotAliasP1(t *testing.T) {
	identity := make([]byte, 64)
	g1 := make([]byte, 64)
	g1[31] = 1
	g1[63] = 2
	original := append([]byte(nil), g1...)

	result := Bn254G1Add(g1, identity)
	result[0] = 0xFF
	if !bytes.Equal(g1, original) {
		t.Fatal("Bn254G1Add aliased p1: mutating result changed the input slice")
	}
}

// TestBn254G1Negate_ZeroYDoesNotAlias — when y == 0, Bn254G1Negate must still
// return a fresh allocation rather than aliasing the input slice.
func TestBn254G1Negate_ZeroYDoesNotAlias(t *testing.T) {
	// A point with y == 0: not on curve (y² = 0 ≠ x³+3 unless x³ = -3 mod p)
	// but Bn254G1Negate doesn't check on-curve-ness — it just flips y.
	// Use x = 0, y = 0 (the identity) for the aliasing test; y.Sign()==0 path.
	p := make([]byte, 64)
	original := append([]byte(nil), p...)

	result := Bn254G1Negate(p)
	result[0] = 0xFF
	if !bytes.Equal(p, original) {
		t.Fatal("Bn254G1Negate aliased input when y == 0: mutating result changed the input slice")
	}
}
