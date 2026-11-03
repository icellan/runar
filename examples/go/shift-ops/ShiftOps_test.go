package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// The caller supplies the expected shift results and the contract checks them
// (F-167: it used to assert only tautologies, so no input could fail). With
// a = 12 the native Go shifts agree with the on-chain OP_LSHIFT / OP_RSHIFT;
// the on-chain verdict is pinned by
// conformance/witnesses/real-crypto/shift-ops.json.

// expectPanic invokes fn and reports a failure if it does NOT panic — a wrong
// expected value must trip a Rúnar Assert.
func expectPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s: expected panic, got none", name)
		}
	}()
	fn()
}

func TestShiftOps_TestShift(t *testing.T) {
	c := &ShiftOps{A: 12}
	c.TestShift(96, 3) // should not panic
}

func TestShiftOps_TestShift_WrongResultRejected(t *testing.T) {
	c := &ShiftOps{A: 12}
	expectPanic(t, "wrong left shift", func() { c.TestShift(97, 3) })
	expectPanic(t, "wrong right shift", func() { c.TestShift(96, 2) })
}

func TestShiftOps_Compile(t *testing.T) {
	if err := runar.CompileCheck("ShiftOps.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
