package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestBoundedLoop_Compile(t *testing.T) {
	if err := runar.CompileCheck("BoundedLoop.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// `for i := 0; i < 5; i++ { sum += start + i }` accumulates 5*start + 10.
// The two terms fail differently: a wrong trip count moves the 5*start
// coefficient, a dropped iterator moves the +10. Varying start separates them.
func TestBoundedLoop_AccumulatesStartPlusIterator(t *testing.T) {
	for _, start := range []runar.Int{0, 1, 3, -2} {
		start := start
		want := 5*start + 10
		mustAccept(t, "5*start+10", func() {
			(&BoundedLoop{ExpectedSum: want}).Verify(start)
		})
		mustRefuse(t, "iterator dropped (5*start)", func() {
			(&BoundedLoop{ExpectedSum: 5 * start}).Verify(start)
		})
		mustRefuse(t, "four iterations (4*start+6)", func() {
			(&BoundedLoop{ExpectedSum: 4*start + 6}).Verify(start)
		})
		mustRefuse(t, "six iterations (6*start+15)", func() {
			(&BoundedLoop{ExpectedSum: 6*start + 15}).Verify(start)
		})
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
