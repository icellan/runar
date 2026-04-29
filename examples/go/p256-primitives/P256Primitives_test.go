package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// P256Primitives.runar.go uses //go:build ignore so the contract source is a
// parser-only fixture. The NIST P-256 primitives themselves are exercised
// natively by the p256-wallet example tests; this suite covers the Rúnar
// frontend (parse → validate → typecheck) for the p256-primitives surface.

func TestP256Primitives_Compile(t *testing.T) {
	if err := runar.CompileCheck("P256Primitives.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
