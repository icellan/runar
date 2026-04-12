package contract

import (
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// Compile-check for Grid2x2: runs parse → validate → typecheck.
func TestGrid2x2_Compile(t *testing.T) {
	if err := runar.CompileCheck("Grid2x2.v2.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// TestGrid2x2_FullCompile runs the complete Go compiler pipeline on the
// nested-FixedArray contract and asserts that the output is a valid,
// non-empty Rúnar artifact. This is the nested-array acceptance test.
func TestGrid2x2_FullCompile(t *testing.T) {
	a, err := compiler.CompileFromSource("Grid2x2.v2.runar.go")
	if err != nil {
		t.Fatalf("Grid2x2 compile failed: %v", err)
	}
	if a.Script == "" {
		t.Fatal("empty script")
	}
	if a.ContractName != "Grid2x2" {
		t.Errorf("contract name = %q, want Grid2x2", a.ContractName)
	}

	// The assembler must have regrouped the 4 expanded scalar siblings
	// back into a single nested FixedArray<FixedArray<bigint, 2>, 2>
	// state field named "grid" (not 4 independent scalar fields).
	if len(a.StateFields) != 1 {
		t.Fatalf("expected 1 state field after regroup, got %d", len(a.StateFields))
	}
	sf := a.StateFields[0]
	if sf.Name != "grid" {
		t.Errorf("state field name = %q, want grid", sf.Name)
	}
	if sf.Type != "FixedArray<FixedArray<bigint, 2>, 2>" {
		t.Errorf("state field type = %q, want FixedArray<FixedArray<bigint, 2>, 2>", sf.Type)
	}
	if sf.FixedArray == nil {
		t.Fatal("expected FixedArray metadata on regrouped state field")
	}
	if sf.FixedArray.Length != 2 {
		t.Errorf("outer length = %d, want 2", sf.FixedArray.Length)
	}
	if sf.FixedArray.ElementType != "FixedArray<bigint, 2>" {
		t.Errorf("element type = %q, want FixedArray<bigint, 2>", sf.FixedArray.ElementType)
	}
	wantLeaves := []string{"grid__0__0", "grid__0__1", "grid__1__0", "grid__1__1"}
	if len(sf.FixedArray.SyntheticNames) != len(wantLeaves) {
		t.Fatalf("synthetic names %v, want %v", sf.FixedArray.SyntheticNames, wantLeaves)
	}
	for i, n := range wantLeaves {
		if sf.FixedArray.SyntheticNames[i] != n {
			t.Errorf("synthetic[%d] = %q, want %q", i, sf.FixedArray.SyntheticNames[i], n)
		}
	}
}
