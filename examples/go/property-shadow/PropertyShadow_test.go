package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// N-016: the locals `Target` / `Count` shadow the fields only as bare names;
// `c.Target` / `c.Count` still read the fields. These native rows are the
// source-semantics half; the compiled script is spent on the @bsv/sdk engine
// by conformance/witnesses/real-crypto/property-shadow.json.

func TestPropertyShadow_Compile(t *testing.T) {
	if err := runar.CompileCheck("PropertyShadow.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestPropertyShadow_BumpReadsTheFields(t *testing.T) {
	c := &PropertyShadow{Target: 10, Count: 4}
	c.Bump(9)
	if c.Count != 13 {
		t.Fatalf("count = %d, want 4 + 9 = 13", c.Count)
	}
}

func TestPropertyShadow_WrongNRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("bump(5) with target 10 must refuse (5 + 1 != 10)")
		}
	}()
	(&PropertyShadow{Target: 10, Count: 4}).Bump(5)
}
