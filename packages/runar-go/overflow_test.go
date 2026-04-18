package runar

import (
	"math"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// checkedMul / checkedAdd unit tests
// ---------------------------------------------------------------------------

func TestCheckedMul_SmallValues(t *testing.T) {
	if got := checkedMul(6, 7); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
	if got := checkedMul(-3, 4); got != -12 {
		t.Fatalf("expected -12, got %d", got)
	}
	if got := checkedMul(0, math.MaxInt64); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestCheckedMul_Overflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on int64 overflow")
		}
	}()
	checkedMul(math.MaxInt64, 2)
}

func TestCheckedAdd_SmallValues(t *testing.T) {
	if got := checkedAdd(40, 2); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
}

func TestCheckedAdd_Overflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on int64 overflow")
		}
	}()
	checkedAdd(math.MaxInt64, 1)
}

func TestCheckedAdd_NegativeOverflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on int64 negative overflow")
		}
	}()
	checkedAdd(math.MinInt64, -1)
}

// ---------------------------------------------------------------------------
// Math function boundary tests (post Fix GO-1)
//
// Historically these functions panicked for a wide range of valid inputs
// simply because |MinInt64| isn't representable as int64. Fix GO-1 routes
// them through big.Int internally so only _output_ overflow triggers
// surfaces a panic; the *Big siblings never overflow.
// ---------------------------------------------------------------------------

func TestAbs_MinInt64_DoesNotPanic(t *testing.T) {
	// Abs(MinInt64) now wraps to MinInt64 itself (int64 cannot hold 2^63).
	// Previously it panicked.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Abs(MinInt64) should not panic anymore; got: %v", r)
		}
	}()
	got := Abs(math.MinInt64)
	// The wrapped return is MinInt64 because 2^63 is not representable.
	// Users who need the true magnitude must use AbsBig.
	if got != math.MinInt64 {
		t.Fatalf("Abs(MinInt64) expected wrap to MinInt64, got %d", got)
	}
}

func TestAbsBig_MinInt64(t *testing.T) {
	// AbsBig returns the mathematically correct |MinInt64| = 2^63.
	got := AbsBig(big.NewInt(math.MinInt64))
	want := new(big.Int).Lsh(big.NewInt(1), 63) // 2^63
	if got.Cmp(want) != 0 {
		t.Fatalf("AbsBig(MinInt64): want %s, got %s", want.String(), got.String())
	}
}

func TestPow_Overflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected Pow overflow panic when result doesn't fit int64")
		}
	}()
	Pow(math.MaxInt64, 2)
}

func TestPow_SmallValues(t *testing.T) {
	if got := Pow(2, 10); got != 1024 {
		t.Fatalf("expected 1024, got %d", got)
	}
	if got := Pow(3, 0); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
}

func TestPowBig_LargeResult(t *testing.T) {
	// 2^128 — overflows int64 by a wide margin but PowBig handles it fine.
	r := PowBig(big.NewInt(2), big.NewInt(128))
	want := new(big.Int).Lsh(big.NewInt(1), 128)
	if r.Cmp(want) != 0 {
		t.Fatalf("PowBig(2, 128): want %s, got %s", want.String(), r.String())
	}
}

func TestMulDiv_Overflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected MulDiv overflow panic")
		}
	}()
	MulDiv(math.MaxInt64, 2, 1)
}

func TestMulDiv_NoFalseOverflow(t *testing.T) {
	// (MaxInt64 * 2) / 2 == MaxInt64 — the intermediate product overflows
	// int64, but the final quotient fits. The old code panicked here; the
	// new code routes through big.Int and returns the correct answer.
	got := MulDiv(math.MaxInt64, 2, 2)
	if got != math.MaxInt64 {
		t.Fatalf("MulDiv(MaxInt64, 2, 2): want MaxInt64, got %d", got)
	}
}

func TestMulDiv_SmallValues(t *testing.T) {
	if got := MulDiv(100, 3, 2); got != 150 {
		t.Fatalf("expected 150, got %d", got)
	}
}

func TestMulDivBig_LargeValues(t *testing.T) {
	// 2^80 * 2^80 / 2^80 = 2^80 — well outside int64 but fine in big.Int.
	p := new(big.Int).Lsh(big.NewInt(1), 80)
	r := MulDivBig(p, p, p)
	if r.Cmp(p) != 0 {
		t.Fatalf("MulDivBig(2^80, 2^80, 2^80): want %s, got %s", p.String(), r.String())
	}
}

func TestPercentOf_Overflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected PercentOf overflow panic when result doesn't fit int64")
		}
	}()
	// The final result MaxInt64 * 5000 / 10000 = MaxInt64/2 still fits;
	// pick a larger bps that genuinely overflows the output.
	PercentOf(math.MaxInt64, math.MaxInt64)
}

func TestPercentOf_SmallValues(t *testing.T) {
	if got := PercentOf(10000, 2500); got != 2500 {
		t.Fatalf("expected 2500, got %d", got)
	}
}

func TestPercentOf_NoFalseOverflow(t *testing.T) {
	// MaxInt64 * 5000 overflows int64 but the final /10000 fits. The old
	// code panicked; the new code returns the correct answer.
	got := PercentOf(math.MaxInt64, 5000)
	// 9223372036854775807 * 5000 / 10000 = 4611686018427387903 (MaxInt64 / 2, truncated)
	want := int64(4611686018427387903)
	if got != want {
		t.Fatalf("PercentOf(MaxInt64, 5000): want %d, got %d", want, got)
	}
}

func TestGcd_MinInt64_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Gcd(MinInt64, 1) should not panic anymore; got: %v", r)
		}
	}()
	// gcd(2^63, 1) = 1 — fits in int64 cleanly.
	if got := Gcd(math.MinInt64, 1); got != 1 {
		t.Fatalf("Gcd(MinInt64, 1): want 1, got %d", got)
	}
}

func TestGcdBig_MinInt64(t *testing.T) {
	// gcd(2^63, 2^63) = 2^63 — doesn't fit in int64 but fine in big.Int.
	a := big.NewInt(math.MinInt64) // -2^63
	r := GcdBig(a, a)
	want := new(big.Int).Lsh(big.NewInt(1), 63) // 2^63
	if r.Cmp(want) != 0 {
		t.Fatalf("GcdBig(MinInt64, MinInt64): want %s, got %s", want.String(), r.String())
	}
}

func TestGcd_SmallValues(t *testing.T) {
	if got := Gcd(12, 8); got != 4 {
		t.Fatalf("expected 4, got %d", got)
	}
}

func TestNum2Bin_MinInt64_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Num2Bin(MinInt64, 8) should not panic anymore; got: %v", r)
		}
	}()
	// The encoding is 8 bytes LE sign-magnitude; |MinInt64| magnitude is 2^63
	// which is the byte sequence 00 00 00 00 00 00 00 80 in LE — the final
	// 0x80 overlaps with the sign bit. With length=8 the encoding is
	// 0000000000000080 and the sign bit happens to be set.
	got := Num2Bin(math.MinInt64, 8)
	want := ByteString([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80})
	if string(got) != string(want) {
		t.Fatalf("Num2Bin(MinInt64, 8): want %x, got %x", want, got)
	}
}

func TestNum2BinBig_LargeValue(t *testing.T) {
	// Encode 2^72 in 10 bytes: LE bytes 00 00 00 00 00 00 00 00 00 01 (positive)
	v := new(big.Int).Lsh(big.NewInt(1), 72)
	got := Num2BinBig(v, 10)
	want := ByteString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if string(got) != string(want) {
		t.Fatalf("Num2BinBig(2^72, 10): want %x, got %x", want, got)
	}
	// And decode it back via Bin2NumBig
	back := Bin2NumBig(got)
	if back.Cmp(v) != 0 {
		t.Fatalf("Bin2NumBig round-trip: want %s, got %s", v.String(), back.String())
	}
}

func TestBin2Num_RoundTrip_Positive(t *testing.T) {
	// 0xDEADBEEF (positive, fits in int64 easily)
	raw := ByteString([]byte{0xef, 0xbe, 0xad, 0x5e}) // bytes in LE; high nibble 0x5 keeps sign bit clear
	got := Bin2Num(raw)
	want := int64(0x5eadbeef)
	if got != want {
		t.Fatalf("Bin2Num positive: want %d, got %d", want, got)
	}
}

func TestBin2Num_RoundTrip_Negative(t *testing.T) {
	// -0x5eadbeef is 0xef 0xbe 0xad 0xde (sign bit set on 0xde = 0x5e | 0x80)
	raw := ByteString([]byte{0xef, 0xbe, 0xad, 0xde})
	got := Bin2Num(raw)
	want := int64(-0x5eadbeef)
	if got != want {
		t.Fatalf("Bin2Num negative: want %d, got %d", want, got)
	}
}
