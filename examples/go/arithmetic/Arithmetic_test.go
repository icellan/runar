package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestArithmetic_Compile(t *testing.T) {
	if err := runar.CompileCheck("Arithmetic.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Verify computes (a+b) + (a-b) + (a*b) + (a/b). The interesting half is the
// DIVISION: Rúnar's `/` and Go's int64 `/` both truncate toward zero, which
// only becomes visible once an operand is negative. -7/2 is -3 under
// truncation and -4 under floor, so the negative rows below are what
// distinguish the two -- a port that silently floored would pass every
// positive row.
//
// The compiled script is held to the same answers by
// conformance/arithmetic_division_execution_test.go, which spends these exact
// operands on the go-sdk consensus interpreter.
func TestArithmetic_MatchesTruncatingDivision(t *testing.T) {
	for _, c := range []struct{ a, b runar.Int }{
		{10, 3}, {7, 2}, {1, 1}, {100, 7},
		{-7, 2}, {7, -2}, {-7, -2}, {-1, 2}, {1, -2},
	} {
		want := (c.a + c.b) + (c.a - c.b) + (c.a * c.b) + (c.a / c.b)
		a, b, target := c.a, c.b, want
		mustAccept(t, "Verify on its own arithmetic", func() {
			(&Arithmetic{Target: target}).Verify(a, b)
		})
		mustRefuse(t, "Verify against a neighbouring target", func() {
			(&Arithmetic{Target: target + 1}).Verify(a, b)
		})
	}
}

// Pin the sign rule itself, so the table above cannot pass by computing the
// same wrong thing on both sides.
func TestArithmetic_DivisionTruncatesTowardZero(t *testing.T) {
	for _, c := range []struct {
		a, b, want runar.Int
	}{
		{-7, 2, -3}, // floor would give -4
		{7, -2, -3},
		{-7, -2, 3},
		{-1, 2, 0}, // floor would give -1
	} {
		if got := c.a / c.b; got != c.want {
			t.Fatalf("%d / %d = %d, want %d (truncation toward zero)", c.a, c.b, got, c.want)
		}
	}
}

func mustAccept(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: the contract REFUSED (%v)", what, r)
		}
	}()
	fn()
}

func mustRefuse(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: the contract ACCEPTED where it must refuse", what)
		}
	}()
	fn()
}
