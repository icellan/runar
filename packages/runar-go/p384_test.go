package runar

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestP384Keygen(t *testing.T) {
	kp := P384Keygen()
	if kp.SK == nil {
		t.Fatal("P384Keygen: SK is nil")
	}
	if len(kp.PK) != 96 {
		t.Fatalf("P384Keygen: PK length = %d, want 96", len(kp.PK))
	}
	if len(kp.PKCompressed) != 49 {
		t.Fatalf("P384Keygen: PKCompressed length = %d, want 49", len(kp.PKCompressed))
	}
	prefix := kp.PKCompressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		t.Fatalf("P384Keygen: PKCompressed[0] = 0x%02x, want 0x02 or 0x03", prefix)
	}
	if !P384OnCurve(kp.PK) {
		t.Fatal("P384Keygen: generated public key is not on P-384 curve")
	}
}

func TestP384SignVerify(t *testing.T) {
	kp := P384Keygen()
	msg := []byte("hello runar p384")

	sig := P384Sign(msg, kp.SK)
	// Raw format: exactly 96 bytes (r[48] || s[48]).
	if len(sig) != 96 {
		t.Fatalf("P384Sign: signature length = %d, want 96 (raw r||s)", len(sig))
	}

	ok := VerifyECDSAP384(ByteString(msg), ByteString(sig), ByteString(kp.PKCompressed))
	if !ok {
		t.Fatal("VerifyECDSAP384: valid signature failed verification")
	}
}

func TestP384SignVerify_RawFormat(t *testing.T) {
	// Verify that P384Sign produces exactly 96 bytes (not DER which is variable length).
	kp := P384Keygen()
	for i := 0; i < 10; i++ {
		sig := P384Sign([]byte("test message for raw format check"), kp.SK)
		if len(sig) != 96 {
			t.Fatalf("P384Sign iteration %d: length = %d, want 96", i, len(sig))
		}
	}
}

func TestP384SignVerify_WrongMsg(t *testing.T) {
	kp := P384Keygen()
	sig := P384Sign([]byte("correct message"), kp.SK)

	ok := VerifyECDSAP384(ByteString("wrong message"), ByteString(sig), ByteString(kp.PKCompressed))
	if ok {
		t.Fatal("VerifyECDSAP384: signature verified against wrong message (should fail)")
	}
}

func TestP384SignVerify_WrongKey(t *testing.T) {
	kp1 := P384Keygen()
	kp2 := P384Keygen()
	msg := []byte("test message")

	sig := P384Sign(msg, kp1.SK)
	ok := VerifyECDSAP384(ByteString(msg), ByteString(sig), ByteString(kp2.PKCompressed))
	if ok {
		t.Fatal("VerifyECDSAP384: signature verified with wrong public key (should fail)")
	}
}

func TestP384MulGen(t *testing.T) {
	// k * G should equal the standard Go P-384 base point multiplication result.
	k := big.NewInt(42)
	got := P384MulGen(k)

	curve := elliptic.P384()
	wantX, wantY := curve.ScalarBaseMult(k.Bytes())
	want := p384PointFromXY(wantX, wantY)

	if got != want {
		t.Fatalf("P384MulGen(42): got %x, want %x", []byte(got), []byte(want))
	}
}

func TestP384MulGen_Generator(t *testing.T) {
	one := big.NewInt(1)
	g := P384MulGen(one)
	gx, gy := p384XYFromPoint(g)

	params := elliptic.P384().Params()
	if gx.Cmp(params.Gx) != 0 {
		t.Fatalf("P384MulGen(1): Gx mismatch: got %x, want %x", gx, params.Gx)
	}
	if gy.Cmp(params.Gy) != 0 {
		t.Fatalf("P384MulGen(1): Gy mismatch: got %x, want %x", gy, params.Gy)
	}
}

func TestP384Add(t *testing.T) {
	// G + G should equal 2*G.
	one := big.NewInt(1)
	two := big.NewInt(2)

	g := P384MulGen(one)
	twoG := P384MulGen(two)
	gPlusG := P384Add(g, g)

	if gPlusG != twoG {
		t.Fatalf("P384Add(G, G): got %x, want 2G = %x", []byte(gPlusG), []byte(twoG))
	}
}

func TestP384Add_CommutativityAndAssociativity(t *testing.T) {
	a := P384MulGen(big.NewInt(3))
	b := P384MulGen(big.NewInt(7))
	c := P384MulGen(big.NewInt(11))

	if P384Add(a, b) != P384Add(b, a) {
		t.Fatal("P384Add: not commutative")
	}

	lhs := P384Add(P384Add(a, b), c)
	rhs := P384Add(a, P384Add(b, c))
	if lhs != rhs {
		t.Fatal("P384Add: not associative")
	}
}

func TestP384OnCurve_Generator(t *testing.T) {
	g := P384MulGen(big.NewInt(1))
	if !P384OnCurve(g) {
		t.Fatal("P384OnCurve: generator should be on curve")
	}
}

func TestP384OnCurve_ZeroPoint(t *testing.T) {
	zero := P384Point(make([]byte, 96))
	if P384OnCurve(zero) {
		t.Fatal("P384OnCurve: zero point (point at infinity) should not be on curve")
	}
}

func TestP384OnCurve_RandomPoint(t *testing.T) {
	kp := P384Keygen()
	if !P384OnCurve(kp.PK) {
		t.Fatal("P384OnCurve: freshly generated key pair should be on curve")
	}
}

func TestP384EncodeCompressed(t *testing.T) {
	kp := P384Keygen()
	compressed := P384EncodeCompressed(kp.PK)

	if len(compressed) != 49 {
		t.Fatalf("P384EncodeCompressed: length = %d, want 49", len(compressed))
	}
	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		t.Fatalf("P384EncodeCompressed: prefix = 0x%02x, want 0x02 or 0x03", prefix)
	}
	// The x-coordinate in compressed form must match the x-coordinate from the 96-byte point.
	x := []byte(kp.PK)[:48]
	compX := []byte(compressed)[1:]
	for i := range x {
		if x[i] != compX[i] {
			t.Fatalf("P384EncodeCompressed: x coordinate mismatch at byte %d", i)
		}
	}
}

func TestP384EncodeCompressed_Generator(t *testing.T) {
	g := P384MulGen(big.NewInt(1))
	compressed := P384EncodeCompressed(g)

	cx, cy := elliptic.UnmarshalCompressed(elliptic.P384(), []byte(compressed))
	if cx == nil {
		t.Fatal("P384EncodeCompressed: failed to unmarshal compressed generator")
	}
	params := elliptic.P384().Params()
	if cx.Cmp(params.Gx) != 0 || cy.Cmp(params.Gy) != 0 {
		t.Fatal("P384EncodeCompressed: generator round-trip failed")
	}
}

func TestP384Negate(t *testing.T) {
	// P + (-P) should give the point at infinity (0, 0).
	g := P384MulGen(big.NewInt(5))
	negG := P384Negate(g)
	sum := P384Add(g, negG)

	sx, sy := p384XYFromPoint(sum)
	if sx.Sign() != 0 || sy.Sign() != 0 {
		t.Fatalf("P384Negate: P + (-P) = (%x, %x), want (0, 0)", sx, sy)
	}
}

func TestP384Mul(t *testing.T) {
	// 5 * G via P384Mul should equal P384MulGen(5).
	g := P384MulGen(big.NewInt(1))
	k := big.NewInt(5)

	via_mul := P384Mul(g, k)
	via_gen := P384MulGen(k)

	if via_mul != via_gen {
		t.Fatalf("P384Mul(G, 5) = %x, want %x", []byte(via_mul), []byte(via_gen))
	}
}
