package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestBitwiseOps_TestShift(t *testing.T) {
	c := &BitwiseOps{A: 8, B: 3}
	c.TestShift() // should not panic
}

func TestBitwiseOps_TestBitwise(t *testing.T) {
	c := &BitwiseOps{A: 12, B: 10}
	c.TestBitwise() // should not panic
}

func TestBitwiseOps_Compile(t *testing.T) {
	if err := runar.CompileCheck("BitwiseOps.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
