package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ECUnit.TestOps round-trips a secp256k1 point through EcPointX / EcPointY /
// EcMakePoint. Inside emitted Bitcoin Script the coordinates are
// arbitrary-precision bigints, but the Go SDK's EcPointX / EcPointY return
// Bigint (int64) and truncate the high bits of any real curve point — so the
// rebuilt point is never on the curve when invoked natively. The cross-
// compiler conformance boundary we care about is the Rúnar frontend, so this
// suite covers parse → validate → typecheck. The EC primitives themselves are
// exercised end-to-end by the ec-demo native tests.

func TestECUnit_Compile(t *testing.T) {
	if err := runar.CompileCheck("ECUnit.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
