package runar

import (
	"math"
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
// Math function overflow boundary tests
// ---------------------------------------------------------------------------

func TestAbs_MinInt64_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Abs(MinInt64) should panic — |MinInt64| overflows int64")
		}
	}()
	Abs(math.MinInt64)
}

func TestPow_Overflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected Pow overflow panic")
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

func TestMulDiv_Overflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected MulDiv overflow panic")
		}
	}()
	MulDiv(math.MaxInt64, 2, 1)
}

func TestMulDiv_SmallValues(t *testing.T) {
	if got := MulDiv(100, 3, 2); got != 150 {
		t.Fatalf("expected 150, got %d", got)
	}
}

func TestPercentOf_Overflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected PercentOf overflow panic")
		}
	}()
	PercentOf(math.MaxInt64, 5000)
}

func TestPercentOf_SmallValues(t *testing.T) {
	if got := PercentOf(10000, 2500); got != 2500 {
		t.Fatalf("expected 2500, got %d", got)
	}
}

func TestGcd_MinInt64_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Gcd(MinInt64, 1) should panic — |MinInt64| overflows int64")
		}
	}()
	Gcd(math.MinInt64, 1)
}

func TestGcd_SmallValues(t *testing.T) {
	if got := Gcd(12, 8); got != 4 {
		t.Fatalf("expected 4, got %d", got)
	}
}

func TestNum2Bin_MinInt64_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Num2Bin(MinInt64, 8) should panic — |MinInt64| overflows int64")
		}
	}()
	Num2Bin(math.MinInt64, 8)
}
