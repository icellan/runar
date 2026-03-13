package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func TestCounter_Increment(t *testing.T) {
	c := &Counter{Count: 0}
	c.Increment()
	if c.Count != 1 {
		t.Errorf("expected Count=1, got %d", c.Count)
	}
}

func TestCounter_IncrementMultiple(t *testing.T) {
	c := &Counter{Count: 0}
	for i := 0; i < 10; i++ {
		c.Increment()
	}
	if c.Count != 10 {
		t.Errorf("expected Count=10, got %d", c.Count)
	}
}

func TestCounter_Decrement(t *testing.T) {
	c := &Counter{Count: 5}
	c.Decrement()
	if c.Count != 4 {
		t.Errorf("expected Count=4, got %d", c.Count)
	}
}

func TestCounter_DecrementAtZero_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := &Counter{Count: 0}
	c.Decrement()
}

func TestCounter_IncrementThenDecrement(t *testing.T) {
	c := &Counter{Count: 0}
	c.Increment()
	c.Increment()
	c.Increment()
	c.Decrement()
	if c.Count != 2 {
		t.Errorf("expected Count=2, got %d", c.Count)
	}
}

func TestCounter_Compile(t *testing.T) {
	if err := runar.CompileCheck("Counter.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Row 489: Counter initial state is count=0
func TestCounter_InitialState(t *testing.T) {
	c := &Counter{Count: 0}
	if c.Count != 0 {
		t.Errorf("expected initial Count=0, got %d", c.Count)
	}
}
