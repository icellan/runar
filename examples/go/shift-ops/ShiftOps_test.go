package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestShiftOps_TestShift(t *testing.T) {
	c := &ShiftOps{A: 16}
	c.TestShift() // should not panic
}

func TestShiftOps_Compile(t *testing.T) {
	if err := runar.CompileCheck("ShiftOps.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
