package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// DataOutputTest.runar.go uses self.AddDataOutput, a Rúnar intrinsic the
// compiler materialises into emitted Bitcoin Script. Although the Go SDK's
// StatefulSmartContract base struct does provide an AddDataOutput method we
// could call natively, the cross-compiler conformance boundary we care about
// is the Rúnar frontend: parse → validate → typecheck. We exercise that
// directly via CompileCheck.

func TestDataOutputTest_Compile(t *testing.T) {
	if err := runar.CompileCheck("DataOutputTest.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
