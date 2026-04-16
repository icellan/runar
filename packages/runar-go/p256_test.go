package runar

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestP256Keygen(t *testing.T) {
	kp := P256Keygen()
	if kp.SK == nil {
		t.Fatal("P256Keygen: SK is nil")
	}
	if len(kp.PK) != 64 {
		t.Fatalf("P256Keygen: PK length = %d, want 64", len(kp.PK))
	}
	if len(kp.PKCompressed) != 33 {
		t.Fatalf("P256Keygen: PKCompressed length = %d, want 33", len(kp.PKCompressed))
	}
	// Compressed key must start with 02 or 03.
	prefix := kp.PKCompressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		t.Fatalf("P256Keygen: PKCompressed[0] = 0x%02x, want 0x02 or 0x03", prefix)
	}
	// The public key point must be on P-256.
	if !P256OnCurve(kp.PK) {
		t.Fatal("P256Keygen: generated public key is not on P-256 curve")
	}
}

func TestP256SignVerify(t *testing.T) {
	kp := P256Keygen()
	msg := []byte("hello runar p256")

	sig := P256Sign(msg, kp.SK)
	// Raw format: exactly 64 bytes (r[32] || s[32]).
	if len(sig) != 64 {
		t.Fatalf("P256Sign: signature length = %d, want 64 (raw r||s)", len(sig))
	}

	ok := VerifyECDSAP256(ByteString(msg), ByteString(sig), ByteString(kp.PKCompressed))
	if !ok {
		t.Fatal("VerifyECDSAP256: valid signature failed verification")
	}
}

func TestP256SignVerify_RawFormat(t *testing.T) {
	// Verify that P256Sign produces exactly 64 bytes (not DER which is variable length).
	kp := P256Keygen()
	for i := 0; i < 10; i++ {
		sig := P256Sign([]byte("test message for raw format check"), kp.SK)
		if len(sig) != 64 {
			t.Fatalf("P256Sign iteration %d: length = %d, want 64", i, len(sig))
		}
	}
}

func TestP256SignVerify_WrongMsg(t *testing.T) {
	kp := P256Keygen()
	sig := P256Sign([]byte("correct message"), kp.SK)

	ok := VerifyECDSAP256(ByteString("wrong message"), ByteString(sig), ByteString(kp.PKCompressed))
	if ok {
		t.Fatal("VerifyECDSAP256: signature verified against wrong message (should fail)")
	}
}

func TestP256SignVerify_WrongKey(t *testing.T) {
	kp1 := P256Keygen()
	kp2 := P256Keygen()
	msg := []byte("test message")

	sig := P256Sign(msg, kp1.SK)
	ok := VerifyECDSAP256(ByteString(msg), ByteString(sig), ByteString(kp2.PKCompressed))
	if ok {
		t.Fatal("VerifyECDSAP256: signature verified with wrong public key (should fail)")
	}
}

func TestP256MulGen(t *testing.T) {
	// k * G should equal the standard Go P-256 base point multiplication result.
	k := big.NewInt(42)
	got := P256MulGen(k)

	curve := elliptic.P256()
	wantX, wantY := curve.ScalarBaseMult(k.Bytes())
	want := p256PointFromXY(wantX, wantY)

	if got != want {
		t.Fatalf("P256MulGen(42): got %x, want %x", []byte(got), []byte(want))
	}
}

func TestP256MulGen_Generator(t *testing.T) {
	// 1 * G should equal the curve generator.
	one := big.NewInt(1)
	g := P256MulGen(one)
	gx, gy := p256XYFromPoint(g)

	params := elliptic.P256().Params()
	if gx.Cmp(params.Gx) != 0 {
		t.Fatalf("P256MulGen(1): Gx mismatch: got %x, want %x", gx, params.Gx)
	}
	if gy.Cmp(params.Gy) != 0 {
		t.Fatalf("P256MulGen(1): Gy mismatch: got %x, want %x", gy, params.Gy)
	}
}

func TestP256Add(t *testing.T) {
	// G + G should equal 2*G.
	one := big.NewInt(1)
	two := big.NewInt(2)

	g := P256MulGen(one)
	twoG := P256MulGen(two)
	gPlusG := P256Add(g, g)

	if gPlusG != twoG {
		t.Fatalf("P256Add(G, G): got %x, want 2G = %x", []byte(gPlusG), []byte(twoG))
	}
}

func TestP256Add_CommutativityAndAssociativity(t *testing.T) {
	// Verify A + B == B + A, and (A + B) + C == A + (B + C).
	a := P256MulGen(big.NewInt(3))
	b := P256MulGen(big.NewInt(7))
	c := P256MulGen(big.NewInt(11))

	if P256Add(a, b) != P256Add(b, a) {
		t.Fatal("P256Add: not commutative")
	}

	lhs := P256Add(P256Add(a, b), c)
	rhs := P256Add(a, P256Add(b, c))
	if lhs != rhs {
		t.Fatal("P256Add: not associative")
	}
}

func TestP256OnCurve_Generator(t *testing.T) {
	g := P256MulGen(big.NewInt(1))
	if !P256OnCurve(g) {
		t.Fatal("P256OnCurve: generator should be on curve")
	}
}

func TestP256OnCurve_ZeroPoint(t *testing.T) {
	zero := P256Point(make([]byte, 64))
	if P256OnCurve(zero) {
		t.Fatal("P256OnCurve: zero point (point at infinity) should not be on curve")
	}
}

func TestP256OnCurve_RandomPoint(t *testing.T) {
	kp := P256Keygen()
	if !P256OnCurve(kp.PK) {
		t.Fatal("P256OnCurve: freshly generated key pair should be on curve")
	}
}

func TestP256EncodeCompressed(t *testing.T) {
	kp := P256Keygen()
	compressed := P256EncodeCompressed(kp.PK)

	if len(compressed) != 33 {
		t.Fatalf("P256EncodeCompressed: length = %d, want 33", len(compressed))
	}
	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		t.Fatalf("P256EncodeCompressed: prefix = 0x%02x, want 0x02 or 0x03", prefix)
	}
	// The x-coordinate in compressed form must match the x-coordinate from the 64-byte point.
	x := []byte(kp.PK)[:32]
	compX := []byte(compressed)[1:]
	for i := range x {
		if x[i] != compX[i] {
			t.Fatalf("P256EncodeCompressed: x coordinate mismatch at byte %d", i)
		}
	}
}

func TestP256EncodeCompressed_Generator(t *testing.T) {
	g := P256MulGen(big.NewInt(1))
	compressed := P256EncodeCompressed(g)

	// Round-trip: decode the compressed key and verify coordinates match.
	cx, cy := elliptic.UnmarshalCompressed(elliptic.P256(), []byte(compressed))
	if cx == nil {
		t.Fatal("P256EncodeCompressed: failed to unmarshal compressed generator")
	}
	params := elliptic.P256().Params()
	if cx.Cmp(params.Gx) != 0 || cy.Cmp(params.Gy) != 0 {
		t.Fatal("P256EncodeCompressed: generator round-trip failed")
	}
}

func TestP256Negate(t *testing.T) {
	// P + (-P) should give the point at infinity (0, 0).
	g := P256MulGen(big.NewInt(5))
	negG := P256Negate(g)
	sum := P256Add(g, negG)

	sx, sy := p256XYFromPoint(sum)
	if sx.Sign() != 0 || sy.Sign() != 0 {
		t.Fatalf("P256Negate: P + (-P) = (%x, %x), want (0, 0)", sx, sy)
	}
}

func TestP256Mul(t *testing.T) {
	// 5 * G via P256Mul should equal P256MulGen(5).
	g := P256MulGen(big.NewInt(1))
	k := big.NewInt(5)

	via_mul := P256Mul(g, k)
	via_gen := P256MulGen(k)

	if via_mul != via_gen {
		t.Fatalf("P256Mul(G, 5) = %x, want %x", []byte(via_mul), []byte(via_gen))
	}
}
