package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestStateful_Compile(t *testing.T) {
	if err := runar.CompileCheck("Stateful.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestStateful_IncrementAccumulates(t *testing.T) {
	c := &Stateful{Count: 0, MaxCount: 10}
	c.Increment(3)
	c.Increment(4)
	if c.Count != 7 {
		t.Fatalf("Count = %d after +3 +4, want 7", c.Count)
	}
}

// The bound is `<=`, so MaxCount itself is reachable and one past it is not.
// Both rows are needed: an off-by-one in either direction moves exactly one of
// them.
func TestStateful_BoundIsInclusive(t *testing.T) {
	mustAccept(t, "Count reaches MaxCount exactly", func() {
		(&Stateful{Count: 0, MaxCount: 10}).Increment(10)
	})
	mustRefuse(t, "Count exceeds MaxCount by one", func() {
		(&Stateful{Count: 0, MaxCount: 10}).Increment(11)
	})
}

func TestStateful_Reset(t *testing.T) {
	c := &Stateful{Count: 9, MaxCount: 10}
	c.Reset()
	if c.Count != 0 {
		t.Fatalf("Count = %d after Reset, want 0", c.Count)
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
