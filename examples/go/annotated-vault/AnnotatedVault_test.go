package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// N-044: memo (a variable-length ByteString) precedes owner in the state
// section. These native rows are the source-semantics half; the compiled
// script is spent on the @bsv/sdk engine by
// conformance/witnesses/real-crypto/annotated-vault.json and, per tier, by
// packages/runar-testing/src/__tests__/n044-state-length-sign-spend.test.ts.

func TestAnnotatedVault_Compile(t *testing.T) {
	if err := runar.CompileCheck("AnnotatedVault.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestAnnotatedVault_AnnotateKeepsOwner(t *testing.T) {
	owner := runar.PubKey("02" + string(make([]byte, 32)))
	c := &AnnotatedVault{Memo: "", Owner: owner, Balance: 1000}
	memo := runar.ByteString(make([]byte, 128))
	c.Annotate(memo)
	if c.Memo != memo || c.Owner != owner || c.Balance != 1000 {
		t.Fatalf("annotate must replace only the memo")
	}
}
