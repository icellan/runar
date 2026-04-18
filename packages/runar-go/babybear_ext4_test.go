package runar

import "testing"

// TestBbExt4Inv_MulGivesIdentity verifies that BbExt4Inv is a true multiplicative
// inverse in the quartic extension field: a * inv(a) == (1, 0, 0, 0).
func TestBbExt4Inv_MulGivesIdentity(t *testing.T) {
	cases := [][4]int64{
		{1, 2, 3, 4},
		{7, 0, 11, 0},
		{1234567, 77, 55, 99},
		{bbP - 1, bbP - 2, bbP - 3, bbP - 4},
	}
	for _, a := range cases {
		inv := [4]int64{
			BbExt4Inv0(a[0], a[1], a[2], a[3]),
			BbExt4Inv1(a[0], a[1], a[2], a[3]),
			BbExt4Inv2(a[0], a[1], a[2], a[3]),
			BbExt4Inv3(a[0], a[1], a[2], a[3]),
		}
		p := [4]int64{
			BbExt4Mul0(a[0], a[1], a[2], a[3], inv[0], inv[1], inv[2], inv[3]),
			BbExt4Mul1(a[0], a[1], a[2], a[3], inv[0], inv[1], inv[2], inv[3]),
			BbExt4Mul2(a[0], a[1], a[2], a[3], inv[0], inv[1], inv[2], inv[3]),
			BbExt4Mul3(a[0], a[1], a[2], a[3], inv[0], inv[1], inv[2], inv[3]),
		}
		if p != [4]int64{1, 0, 0, 0} {
			t.Errorf("a=%v * inv(a)=%v = %v, want (1,0,0,0)", a, inv, p)
		}
	}
}
