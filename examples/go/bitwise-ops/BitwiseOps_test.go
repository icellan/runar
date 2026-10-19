package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// The caller supplies the expected results and the contract checks them
// (F-167: it used to assert only tautologies, so no input could fail). a = 12,
// b = 10 are 1-byte operands whose results stay below 0x80, so the native Go
// operators here agree with the on-chain byte-array opcodes; the on-chain
// verdict for the same values is pinned by
// conformance/witnesses/real-crypto/bitwise-ops.json.

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

func TestBitwiseOps_TestShift(t *testing.T) {
	c := &BitwiseOps{A: 12, B: 10}
	c.TestShift(48, 6) // should not panic
}

func TestBitwiseOps_TestShift_WrongResultRejected(t *testing.T) {
	c := &BitwiseOps{A: 12, B: 10}
	expectPanic(t, "wrong left shift", func() { c.TestShift(49, 6) })
	expectPanic(t, "wrong right shift", func() { c.TestShift(48, 7) })
}

func TestBitwiseOps_TestBitwise(t *testing.T) {
	c := &BitwiseOps{A: 12, B: 10}
	c.TestBitwise(8, 14, 6) // should not panic
}

func TestBitwiseOps_TestBitwise_WrongResultRejected(t *testing.T) {
	c := &BitwiseOps{A: 12, B: 10}
	expectPanic(t, "AND/OR swapped", func() { c.TestBitwise(14, 8, 6) })
	expectPanic(t, "wrong XOR", func() { c.TestBitwise(8, 14, 7) })
}

func TestBitwiseOps_Compile(t *testing.T) {
	if err := runar.CompileCheck("BitwiseOps.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
