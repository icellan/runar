package codegen

import (
	"math/big"
	"testing"
)

// bn254AssertG1OnCurve is the Groth16-WA / pairing-input assertion, not the
// total predicate EmitBN254G1OnCurve. It must OP_VERIFY-fail a non-canonical
// encoding of G=(1,2). R-141 covered the predicate; this covers the assert,
// in both range-check modes: unsigned (pairing builtins, coordinates
// decomposed from bytes) and signed (Groth16-WA witness numbers, GK-GAP-009).

// r141RunAssertG1 executes bn254AssertG1OnCurve on (x, y) in the given mode.
func r141RunAssertG1(x, y *big.Int, sfx string, signedInputs bool) error {
	ops := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker(nil, emit)
		tr.PushPrimeCache()
		tr.pushBigInt("x", x)
		tr.pushBigInt("y", y)
		bn254AssertG1OnCurve(tr, "x", "y", sfx, signedInputs)
	})
	return BuildAndExecuteOps(ops)
}

func TestBn254AssertG1OnCurve_CanonicalGeneratorSucceeds(t *testing.T) {
	for _, signed := range []bool{false, true} {
		if err := r141RunAssertG1(big.NewInt(1), big.NewInt(2), "ok", signed); err != nil {
			t.Fatalf("canonical G=(1,2) must succeed (signedInputs=%v): %v", signed, err)
		}
	}
}

func TestBn254AssertG1OnCurve_XPlusPAborts(t *testing.T) {
	x := new(big.Int).Add(big.NewInt(1), bn254FieldP)
	for _, signed := range []bool{false, true} {
		if err := r141RunAssertG1(x, big.NewInt(2), "xp", signed); err == nil {
			t.Fatalf("bn254AssertG1OnCurve((1+p), 2) must abort (signedInputs=%v); non-canonical x is not a point", signed)
		}
	}
}

func TestBn254AssertG1OnCurve_YPlusPAborts(t *testing.T) {
	y := new(big.Int).Add(big.NewInt(2), bn254FieldP)
	for _, signed := range []bool{false, true} {
		if err := r141RunAssertG1(big.NewInt(1), y, "yp", signed); err == nil {
			t.Fatalf("bn254AssertG1OnCurve(1, (2+p)) must abort (signedInputs=%v); non-canonical y is not a point", signed)
		}
	}
}

// GK-GAP-009: a witness number can be negative. y - p squares to the same
// residue as y, so only the lower bound of the signed range check stops it.
func TestBn254AssertG1OnCurve_SignedRejectsNegativeAlias(t *testing.T) {
	y := new(big.Int).Sub(big.NewInt(2), bn254FieldP)
	if err := r141RunAssertG1(big.NewInt(1), y, "yn", true); err == nil {
		t.Fatal("bn254AssertG1OnCurve(1, 2-p) must abort in signed mode; a negative alias is not a canonical coordinate")
	}
	x := new(big.Int).Sub(big.NewInt(1), bn254FieldP)
	if err := r141RunAssertG1(x, big.NewInt(2), "xn", true); err == nil {
		t.Fatal("bn254AssertG1OnCurve(1-p, 2) must abort in signed mode")
	}
}
