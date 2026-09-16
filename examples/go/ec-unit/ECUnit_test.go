package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ECUnit.TestOps round-trips a secp256k1 point through EcPointX / EcPointY /
// EcMakePoint and asserts the rebuilt point is on the curve. That assertion
// was unrunnable: EcPointX / EcPointY returned Bigint (int64) and kept the low
// 8 bytes of a 256-bit coordinate, so the rebuilt point was 48 bytes of zeroes
// and could not be on the curve. This file said so in a comment and ran only
// the compile check — the contract body was never executed, which is the shape
// of gap that lets a mock drift from the emitter unseen.
//
// The three coordinate functions take and return BigintBig now, so TestOps
// runs. It is the boundary test for this fixture: every coordinate it moves is
// 256 bits, so no narrowing implementation can satisfy it.

func TestECUnit_Compile(t *testing.T) {
	if err := runar.CompileCheck("ECUnit.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestECUnit_TestOps(t *testing.T) {
	c := &ECUnit{PubKey: runar.EcEncodeCompressed(runar.EcMulGen(1))}
	c.TestOps()
}

// The round trip inside TestOps has to be checked against a point whose
// coordinates do not fit in 64 bits, or a truncating accessor passes it.
func TestECUnit_RoundTripIsPastTheInt64Boundary(t *testing.T) {
	g := runar.EcMulGen(1)
	x, y := runar.EcPointX(g), runar.EcPointY(g)
	if x.BitLen() <= 64 || y.BitLen() <= 64 {
		t.Fatalf("G came back narrow (x %d bits, y %d bits) — TestOps would "+
			"pass against a truncating accessor", x.BitLen(), y.BitLen())
	}
	if rebuilt := runar.EcMakePoint(x, y); rebuilt != g {
		t.Fatalf("EcMakePoint(EcPointX(G), EcPointY(G)) = %x, want %x", rebuilt, g)
	}
}
