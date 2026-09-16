package runar

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// ecG builds the secp256k1 generator point as a 64-byte Point.
func ecG() Point {
	xHex := "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	yHex := "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
	xBytes, _ := hex.DecodeString(xHex)
	yBytes, _ := hex.DecodeString(yHex)
	buf := make([]byte, 64)
	copy(buf[:32], xBytes)
	copy(buf[32:], yBytes)
	return Point(buf)
}

func TestECG_Is64Bytes(t *testing.T) {
	g := ecG()
	if len(g) != 64 {
		t.Fatalf("expected ECG to be 64 bytes, got %d", len(g))
	}
}

func TestEcOnCurve_Generator(t *testing.T) {
	if !EcOnCurve(ecG()) {
		t.Fatal("generator point should be on the curve")
	}
}

func TestEcOnCurve_BadPoint(t *testing.T) {
	bad := make([]byte, 64)
	bad[0] = 0x01 // x=1, y=0 — not on curve
	if EcOnCurve(Point(bad)) {
		t.Fatal("arbitrary point (1, 0) should not be on curve")
	}
}

func TestEcAdd_G_Plus_G_Equals_EcMul_G_2(t *testing.T) {
	g := ecG()
	sum := EcAdd(g, g)
	product := EcMul(g, 2)

	if sum != product {
		t.Fatalf("EcAdd(G, G) != EcMul(G, 2)")
	}
}

func TestEcMul_G_2_Equals_EcMulGen_2(t *testing.T) {
	g := ecG()
	fromMul := EcMul(g, 2)
	fromMulGen := EcMulGen(2)

	if fromMul != fromMulGen {
		t.Fatalf("EcMul(G, 2) != EcMulGen(2)")
	}
}

func TestEcMulGen_1_Equals_G(t *testing.T) {
	g := ecG()
	result := EcMulGen(1)

	if result != g {
		t.Fatalf("EcMulGen(1) != G")
	}
}

func TestEcAdd_G_Plus_G_OnCurve(t *testing.T) {
	g := ecG()
	twoG := EcAdd(g, g)
	if !EcOnCurve(twoG) {
		t.Fatal("2G should be on the curve")
	}
}

func TestEcNegate_OnCurve(t *testing.T) {
	g := ecG()
	neg := EcNegate(g)
	if !EcOnCurve(neg) {
		t.Fatal("negated generator should be on the curve")
	}
}

func TestEcNegate_DifferentFromOriginal(t *testing.T) {
	g := ecG()
	neg := EcNegate(g)
	if neg == g {
		t.Fatal("negated point should differ from original")
	}
}

func TestEcNegate_DoubleNegateIsIdentity(t *testing.T) {
	g := ecG()
	neg := EcNegate(g)
	doubleNeg := EcNegate(neg)
	if doubleNeg != g {
		t.Fatal("double negation should return original point")
	}
}

func TestEcMakePoint_RoundTrip(t *testing.T) {
	// Use small coordinates that fit in int64 for the round-trip test.
	// We can't use the generator's actual coordinates since they exceed int64.
	// Instead, verify the structural round-trip with the generator via pointToCoords.
	g := ecG()
	x, y := pointToCoords(g)
	reconstructed := coordsToPoint(x, y)
	if Point(reconstructed) != g {
		t.Fatal("coordsToPoint(pointToCoords(G)) should round-trip to G")
	}
}

func TestEcMakePoint_SmallValues(t *testing.T) {
	// Coordinates that fit in a byte still have to round-trip; the wide-value
	// case lives in ec_coordinate_width_test.go.
	p := EcMakePoint(big.NewInt(100), big.NewInt(200))
	gotX := EcPointX(p)
	gotY := EcPointY(p)
	if gotX.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("expected x=100, got %s", gotX)
	}
	if gotY.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("expected y=200, got %s", gotY)
	}
}

func TestEcEncodeCompressed_33Bytes(t *testing.T) {
	g := ecG()
	compressed := EcEncodeCompressed(g)
	if len(compressed) != 33 {
		t.Fatalf("expected 33 bytes, got %d", len(compressed))
	}
}

func TestEcEncodeCompressed_Prefix(t *testing.T) {
	g := ecG()
	compressed := EcEncodeCompressed(g)
	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		t.Fatalf("expected prefix 0x02 or 0x03, got 0x%02x", prefix)
	}
}

func TestEcModReduce_Positive(t *testing.T) {
	result := EcModReduce(17, 5)
	if result != 2 {
		t.Fatalf("expected 17 %% 5 = 2, got %d", result)
	}
}

func TestEcModReduce_Negative(t *testing.T) {
	result := EcModReduce(-3, 5)
	if result != 2 {
		t.Fatalf("expected (-3) mod 5 = 2, got %d", result)
	}
}

func TestEcModReduce_Zero(t *testing.T) {
	result := EcModReduce(0, 7)
	if result != 0 {
		t.Fatalf("expected 0 mod 7 = 0, got %d", result)
	}
}

func TestEcMulGen_Associativity(t *testing.T) {
	// 3G computed two ways: EcMulGen(3) vs EcAdd(EcMulGen(2), G)
	threeG := EcMulGen(3)
	twoGplusG := EcAdd(EcMulGen(2), ecG())
	if threeG != twoGplusG {
		t.Fatal("EcMulGen(3) != EcAdd(EcMulGen(2), G)")
	}
}

func TestEcMulGen_ResultOnCurve(t *testing.T) {
	for _, k := range []Bigint{1, 2, 3, 5, 10, 100} {
		p := EcMulGen(k)
		if !EcOnCurve(p) {
			t.Fatalf("EcMulGen(%d) not on curve", k)
		}
	}
}
