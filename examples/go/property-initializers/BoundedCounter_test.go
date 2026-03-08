package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// NOTE: Contracts with property initializers define an init() method that sets
// default values (e.g., Count = 0, Active = true). In native Go tests, you must
// call init() after constructing the struct to apply these defaults. At compile
// time, the Rúnar compiler bakes these defaults directly into the Bitcoin Script.

func TestBoundedCounter_DefaultInitializers(t *testing.T) {
	c := &BoundedCounter{MaxCount: 10}
	// Call init() to apply property initializer defaults
	c.init()
	if c.Count != 0 {
		t.Errorf("expected Count=0, got %d", c.Count)
	}
	if c.Active != true {
		t.Errorf("expected Active=true, got %v", c.Active)
	}
	c.Increment(1)
	if c.Count != 1 {
		t.Errorf("expected Count=1 after increment, got %d", c.Count)
	}
}

func TestBoundedCounter_Increment(t *testing.T) {
	c := &BoundedCounter{MaxCount: 10}
	c.init()
	c.Increment(3)
	if c.Count != 3 {
		t.Errorf("expected Count=3, got %d", c.Count)
	}
}

func TestBoundedCounter_RejectsIncrementBeyondMax(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := &BoundedCounter{MaxCount: 5}
	c.init()
	c.Increment(6)
}

func TestBoundedCounter_Reset(t *testing.T) {
	c := &BoundedCounter{MaxCount: 10}
	c.init()
	c.Increment(7)
	if c.Count != 7 {
		t.Errorf("expected Count=7, got %d", c.Count)
	}
	c.Reset()
	if c.Count != 0 {
		t.Errorf("expected Count=0, got %d", c.Count)
	}
}

func TestBoundedCounter_Compile(t *testing.T) {
	if err := runar.CompileCheck("BoundedCounter.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
