package sp1fri

import "testing"

func TestKbInvRoundtrip(t *testing.T) {
	for _, x := range []uint32{1, 2, 3, 7, 1234567, KbPrime - 1} {
		inv := KbInv(x)
		if KbMul(x, inv) != 1 {
			t.Errorf("KbInv(%d) failed: %d * %d = %d, want 1", x, x, inv, KbMul(x, inv))
		}
	}
}

func TestExt4MulIdentity(t *testing.T) {
	a := Ext4{17, 9, 4, 21}
	one := Ext4One()
	got := Ext4Mul(a, one)
	if got != a {
		t.Errorf("a * 1 != a: got %v want %v", got, a)
	}
}

func TestExt4Inv(t *testing.T) {
	a := Ext4{17, 9, 4, 21}
	inv := Ext4Inv(a)
	prod := Ext4Mul(a, inv)
	if prod != Ext4One() {
		t.Errorf("a * a^-1 != 1: got %v", prod)
	}
}

func TestKbTwoAdicGenerator(t *testing.T) {
	// g_24 must be a primitive 2^24-th root of unity:
	//   g_24^(2^24) = 1, but g_24^(2^23) != 1.
	g24 := KbTwoAdicGenerator(KbTwoAdicity)
	x := g24
	for i := 0; i < KbTwoAdicity-1; i++ {
		x = KbMul(x, x)
	}
	// x = g_24^(2^23). Squaring once more should give 1; x itself should not be 1.
	if x == 1 {
		t.Errorf("g_24^(2^23) = 1 — generator order too small")
	}
	if KbMul(x, x) != 1 {
		t.Errorf("g_24^(2^24) != 1 (got %d)", KbMul(x, x))
	}
}
