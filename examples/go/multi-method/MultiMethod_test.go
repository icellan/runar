package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// MultiMethod.runar.go uses //go:build ignore so the contract source is a
// parser-only fixture. We cover the Rúnar frontend (parse → validate →
// typecheck) only.

func TestMultiMethod_Compile(t *testing.T) {
	if err := runar.CompileCheck("MultiMethod.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
