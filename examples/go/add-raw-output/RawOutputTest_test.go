package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// RawOutputTest.runar.go uses self.AddRawOutput and self.AddOutput — Rúnar
// intrinsics the compiler materialises into emitted Bitcoin Script. The
// cross-compiler conformance boundary we care about is the Rúnar frontend
// (parse → validate → typecheck), so we exercise that directly via
// CompileCheck.

func TestRawOutputTest_Compile(t *testing.T) {
	if err := runar.CompileCheck("RawOutputTest.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
