package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestIfElse_Compile(t *testing.T) {
	if err := runar.CompileCheck("IfElse.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Check takes `value + Limit` on the true arm and `value - Limit` on the false
// arm, then asserts the result is positive. The inputs are chosen so the two
// arms disagree: with value=5, Limit=10 the true arm gives 15 (accept) and the
// false arm -5 (refuse). A lowering that ran the wrong arm, or ran both and
// kept the last, flips both rows.
func TestIfElse_SelectsTheRightArm(t *testing.T) {
	c := &IfElse{Limit: 10}
	mustAccept(t, "mode=true takes value+Limit", func() { c.Check(5, true) })
	mustRefuse(t, "mode=false takes value-Limit", func() { c.Check(5, false) })

	// And the mirror image, so neither row can pass on an arm that ignores
	// `mode` and always adds (or always subtracts).
	mustRefuse(t, "mode=true on a value that makes the sum non-positive", func() {
		c.Check(-20, true)
	})
	mustAccept(t, "mode=false on a value that makes the difference positive", func() {
		c.Check(20, false)
	})
}

// The assertion is `> 0`, not `>= 0`.
func TestIfElse_ZeroIsNotPositive(t *testing.T) {
	mustRefuse(t, "result exactly 0", func() { (&IfElse{Limit: 10}).Check(10, false) })
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
