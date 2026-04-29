package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// P384Primitives.runar.go uses //go:build ignore so the contract source is a
// parser-only fixture. The NIST P-384 primitives themselves are exercised
// natively by the p384-wallet example tests; this suite covers the Rúnar
// frontend (parse → validate → typecheck) for the p384-primitives surface.

func TestP384Primitives_Compile(t *testing.T) {
	if err := runar.CompileCheck("P384Primitives.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
