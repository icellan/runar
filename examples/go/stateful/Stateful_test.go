package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Stateful.runar.go uses //go:build ignore so the contract source is a
// parser-only fixture. We cover the Rúnar frontend (parse → validate →
// typecheck) only.

func TestStateful_Compile(t *testing.T) {
	if err := runar.CompileCheck("Stateful.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
