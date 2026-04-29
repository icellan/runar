package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// IfWithoutElse.runar.go uses //go:build ignore so the contract source is a
// parser-only fixture. We can't construct it natively from the test binary,
// so this suite covers the Rúnar frontend (parse → validate → typecheck) only.

func TestIfWithoutElse_Compile(t *testing.T) {
	if err := runar.CompileCheck("IfWithoutElse.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
