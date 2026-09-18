package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestBooleanLogic_Compile(t *testing.T) {
	if err := runar.CompileCheck("BooleanLogic.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Verify asserts `(a>T && b>T) || ((a>T || b>T) && !flag)`. The truth table is
// enumerated exhaustively rather than sampled: && / || / ! are exactly the
// operators a lowering can swap for one another, and any single swap changes
// at least one of these eight rows.
func TestBooleanLogic_TruthTable(t *testing.T) {
	const threshold runar.Int = 10
	above, below := runar.Int(11), runar.Int(9)

	for _, c := range []struct {
		a, b runar.Bool // a>T, b>T
		flag runar.Bool
		want bool
	}{
		{true, true, true, true},   // both above -- flag irrelevant
		{true, true, false, true},
		{true, false, true, false}, // one above, flag set -- refused
		{true, false, false, true}, // one above, flag clear -- allowed
		{false, true, true, false},
		{false, true, false, true},
		{false, false, true, false}, // neither above -- always refused
		{false, false, false, false},
	} {
		a, b := below, below
		if c.a {
			a = above
		}
		if c.b {
			b = above
		}
		flag, want := c.flag, c.want
		run := func() { (&BooleanLogic{Threshold: threshold}).Verify(a, b, flag) }
		if want {
			mustAccept(t, "a>T && b>T truth row", run)
		} else {
			mustRefuse(t, "a>T && b>T truth row", run)
		}
	}
}

// The comparison is strict: a value EQUAL to the threshold is not above it.
func TestBooleanLogic_ThresholdIsStrict(t *testing.T) {
	mustRefuse(t, "a == threshold counted as above", func() {
		(&BooleanLogic{Threshold: 10}).Verify(10, 10, false)
	})
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
