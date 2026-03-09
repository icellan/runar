package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Native execution tests are omitted because the Fiat-Shamir challenge
// e = Bin2Num(Hash256(R || P)) produces a 256-bit value that overflows
// Go's int64 Bigint type. The contract logic is verified by the TS test
// suite and conformance golden files (which use arbitrary-precision
// arithmetic via BigInt / Bitcoin Script numbers).

func TestSchnorrZKP_Compile(t *testing.T) {
	if err := runar.CompileCheck("SchnorrZKP.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
