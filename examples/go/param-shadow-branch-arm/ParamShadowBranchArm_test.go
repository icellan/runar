package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// N-007: the parameter `Count` shadows the field only as a bare name; inside
// the `if` arm it is still the caller's argument. These native rows are the
// source-semantics half; the compiled script is spent on the @bsv/sdk engine
// by conformance/witnesses/real-crypto/param-shadow-branch-arm.json.

func TestParamShadowBranchArm_Compile(t *testing.T) {
	if err := runar.CompileCheck("ParamShadowBranchArm.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestParamShadowBranchArm_HonestSet(t *testing.T) {
	c := &ParamShadowBranchArm{Count: 5}
	c.Set(5, true)
	if c.Count != 5 {
		t.Fatalf("count = %d, want 5", c.Count)
	}
}

func TestParamShadowBranchArm_SkipArm(t *testing.T) {
	c := &ParamShadowBranchArm{Count: 5}
	c.Set(7, false)
	if c.Count != 7 {
		t.Fatalf("count = %d, want 7", c.Count)
	}
}

func TestParamShadowBranchArm_GuardReadsTheArgument(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("set(7, true) with state count 5 must refuse (argument 7 != 5)")
		}
	}()
	(&ParamShadowBranchArm{Count: 5}).Set(7, true)
}
