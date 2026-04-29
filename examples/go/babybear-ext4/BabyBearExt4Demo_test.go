package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// BabyBearExt4Demo exercises the Baby Bear Ext4 (quartic extension field)
// built-ins. The arithmetic relations are validated end-to-end by the
// repo-root vector tests; here we cover the cross-compiler frontend
// boundary (parse → validate → typecheck).

func TestBabyBearExt4Demo_Compile(t *testing.T) {
	if err := runar.CompileCheck("BabyBearExt4Demo.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
