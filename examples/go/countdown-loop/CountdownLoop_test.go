package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// mustAccept runs fn and fails if the contract refuses. runar.Assert panics on
// a false condition, mirroring OP_VERIFY aborting the script, so "the contract
// refuses" and "fn panics" are the same event; recovering here turns a raw
// panic trace into a message that names the case.
func mustAccept(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: the contract REFUSED (%v)", what, r)
		}
	}()
	fn()
}

// mustRefuse is the other half: without it every row above would pass on a
// contract whose assertion was deleted.
func mustRefuse(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: the contract ACCEPTED where it must refuse", what)
		}
	}()
	fn()
}

func TestCountdownLoop_Compile(t *testing.T) {
	if err := runar.CompileCheck("CountdownLoop.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// `for i := 5; i > 1; i--` visits 5, 4, 3, 2 and sums its iterator to 14.
//
// The numbers are not decoration. A descending loop whose BODY is dropped
// leaves acc == seed; one that silently runs ASCENDING over the same trip
// count sums 0+1+2+3 == 6. Both have been real defects in this repo. The
// COMPILED script is pinned to the same 14 by
// conformance/move_countdown_loop_execution_test.go, spent on the go-sdk
// consensus interpreter, so these rows are the native half of a native-vs-
// script agreement rather than a restatement of the loop.
func TestCountdownLoop_SumsIteratorDescending(t *testing.T) {
	for _, seed := range []runar.Int{0, 1, -7, 1000} {
		seed := seed
		mustAccept(t, "seed+14 for seed", func() {
			(&CountdownLoop{Target: seed + 14}).Verify(seed)
		})
	}
}

func TestCountdownLoop_RejectsWrongTripCount(t *testing.T) {
	mustRefuse(t, "body dropped (acc stays at seed)", func() {
		(&CountdownLoop{Target: 0}).Verify(0)
	})
	mustRefuse(t, "ascending iterator over the same trip count (sum 6)", func() {
		(&CountdownLoop{Target: 6}).Verify(0)
	})
	mustRefuse(t, "one iteration short (sum 12)", func() {
		(&CountdownLoop{Target: 12}).Verify(0)
	})
	mustRefuse(t, "one iteration long (sum 15)", func() {
		(&CountdownLoop{Target: 15}).Verify(0)
	})
}
