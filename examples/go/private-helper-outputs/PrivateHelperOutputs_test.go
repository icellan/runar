package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// PrivateHelperOutputs.runar.go uses unexported helpers that wrap the
// AddOutput / AddDataOutput intrinsics. The cross-compiler conformance
// boundary we care about is the Rúnar frontend (parse → validate →
// typecheck) — exercised here via CompileCheck.

func TestPrivateHelperOutputs_Compile(t *testing.T) {
	if err := runar.CompileCheck("PrivateHelperOutputs.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestPrivateHelperOutputs_Commit(t *testing.T) {
	c := &PrivateHelperOutputs{Counter: 5}
	c.Commit()
	if c.Counter != 6 {
		t.Fatalf("commit: expected counter=6, got %d", c.Counter)
	}
}
