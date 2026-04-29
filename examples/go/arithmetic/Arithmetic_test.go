package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Arithmetic.runar.go uses //go:build ignore so the contract source is a
// parser-only fixture (it imports the unreal "runar" import path that the
// Rúnar Go frontend rewrites). We can't construct it natively from the test
// binary, so this suite covers the Rúnar frontend (parse → validate →
// typecheck) only.

func TestArithmetic_Compile(t *testing.T) {
	if err := runar.CompileCheck("Arithmetic.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
