package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestIfWithoutElse_Compile(t *testing.T) {
	if err := runar.CompileCheck("IfWithoutElse.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Two independent else-less `if`s each add 1 to a counter, and the method
// asserts the counter is non-zero. The both-below row is the only refusal, and
// it is what proves the counter starts at 0 rather than at 1 -- an else-less
// `if` whose merge point picks up the wrong value would make every row accept.
func TestIfWithoutElse_CountsEachBranchIndependently(t *testing.T) {
	c := &IfWithoutElse{Threshold: 10}
	mustAccept(t, "both above", func() { c.Check(11, 11) })
	mustAccept(t, "only a above", func() { c.Check(11, 9) })
	mustAccept(t, "only b above", func() { c.Check(9, 11) })
	mustRefuse(t, "neither above", func() { c.Check(9, 9) })
	mustRefuse(t, "both exactly at the threshold (strict >)", func() { c.Check(10, 10) })
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
