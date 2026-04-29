package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ECPrimitives.runar.go uses //go:build ignore so the contract source is a
// parser-only fixture. The EC primitives themselves are exercised by the
// ec-demo example's native tests; this suite covers the Rúnar frontend
// (parse → validate → typecheck) for the ec-primitives surface.

func TestECPrimitives_Compile(t *testing.T) {
	if err := runar.CompileCheck("ECPrimitives.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
