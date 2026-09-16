package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// runar.Assert panics on a false condition, mirroring OP_VERIFY aborting the
// script, so "the contract refuses" and "fn panics" are the same event.
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

func TestLoopShapes_Compile(t *testing.T) {
	if err := runar.CompileCheck("LoopShapes.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// `for i := 3; i < 7; i++` visits 3, 4, 5, 6 and sums to 18. The non-zero
// START is what this fixture exists for: a lowering that resets the iterator
// to 0 sums 0+1+2+3 == 6 over the same trip count, and a trip count read off
// the bound rather than the range runs 7 times.
func TestLoopShapes_SumsFromNonZeroStart(t *testing.T) {
	for _, seed := range []runar.Int{0, 5, -2} {
		seed := seed
		mustAccept(t, "seed+18", func() {
			(&LoopShapes{Target: seed + 18}).Verify(seed)
		})
	}
}

func TestLoopShapes_RejectsWrongIteratorRange(t *testing.T) {
	mustRefuse(t, "iterator reset to 0 (sum 6)", func() {
		(&LoopShapes{Target: 6}).Verify(0)
	})
	mustRefuse(t, "body dropped (acc stays at seed)", func() {
		(&LoopShapes{Target: 0}).Verify(0)
	})
	mustRefuse(t, "iterated 0..6 instead of 3..6 (sum 21)", func() {
		(&LoopShapes{Target: 21}).Verify(0)
	})
}
