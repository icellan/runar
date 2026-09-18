package codegen

import (
	"math/big"
	"testing"
)

// bn254AssertG1OnCurve is the Groth16-WA / pairing-input assertion, not the
// total predicate EmitBN254G1OnCurve. It must OP_VERIFY-fail a non-canonical
// encoding of G=(1,2). R-141 covered the predicate; this covers the assert.

func TestBn254AssertG1OnCurve_CanonicalGeneratorSucceeds(t *testing.T) {
	ops := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker(nil, emit)
		tr.PushPrimeCache()
		tr.pushBigInt("x", big.NewInt(1))
		tr.pushBigInt("y", big.NewInt(2))
		bn254AssertG1OnCurve(tr, "x", "y", "ok")
	})
	if err := BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("canonical G=(1,2) must succeed: %v", err)
	}
}

func TestBn254AssertG1OnCurve_XPlusPAborts(t *testing.T) {
	x := new(big.Int).Add(big.NewInt(1), bn254FieldP)
	ops := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker(nil, emit)
		tr.PushPrimeCache()
		tr.pushBigInt("x", x)
		tr.pushBigInt("y", big.NewInt(2))
		bn254AssertG1OnCurve(tr, "x", "y", "xp")
	})
	if err := BuildAndExecuteOps(ops); err == nil {
		t.Fatal("bn254AssertG1OnCurve((1+p), 2) must abort; non-canonical x is not a point")
	}
}

func TestBn254AssertG1OnCurve_YPlusPAborts(t *testing.T) {
	y := new(big.Int).Add(big.NewInt(2), bn254FieldP)
	ops := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker(nil, emit)
		tr.PushPrimeCache()
		tr.pushBigInt("x", big.NewInt(1))
		tr.pushBigInt("y", y)
		bn254AssertG1OnCurve(tr, "x", "y", "yp")
	})
	if err := BuildAndExecuteOps(ops); err == nil {
		t.Fatal("bn254AssertG1OnCurve(1, (2+p)) must abort; non-canonical y is not a point")
	}
}
