package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Native execution tests are omitted because:
//
//  1. The Fiat-Shamir challenge e = Bin2Num(Hash256(R || P)) produces a
//     256-bit value that overflows Go's int64 Bigint type.
//
//  2. BUG-001 added the malleability gate assert(within(s, 1, <secp256k1-n>))
//     where the upper bound is the secp256k1 group order (256 bits). That
//     literal does not fit in an int64, so a native-Go inclusion of the
//     contract source would fail to compile.
//
// The cross-tier conformance suite (conformance/tests/schnorr-zkp) consumes
// this file as text via the Rúnar frontend, not as a Go-buildable module,
// so this test only exercises the frontend's parse / validate / typecheck
// pipeline. Adversarial s-bound tests with full algebraic semantics live in
// examples/ts, examples/sol, examples/move, and examples/python (where
// bigint arithmetic is native).

func TestSchnorrZKP_Compile(t *testing.T) {
	if err := runar.CompileCheck("SchnorrZKP.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
