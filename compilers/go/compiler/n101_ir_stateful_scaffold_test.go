package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// N-101 — CompileFromIRBytes refuses a StatefulSmartContract program (declared,
// or inferred per N-087) any of whose public methods lacks, reorders or alters
// the scaffolding ANF lowering injects (auto-injected parameters, the
// checkPreimage / sighash / deserialize_state prologue, the state
// continuation), with the diagnostics shared by all seven tiers
// (conformance/negatives/ir-stateful-scaffold-cases.json).
//
// Before: F-107's attack body relabelled StatefulSmartContract compiled to
// 76767b8777, which an attacker's key spends under strict @bsv/sdk Spend, and
// so did the parentClass-less variant carrying a dead add_data_output.
//
// Proves: every corpus case is refused with its exact diagnostic and the
// accepted programs (incl. unmodified stateful goldens) compile. Does not
// prove cross-tier agreement (conformance/negatives/ir-stateful-scaffold.test.ts
// does) or anything about the free user code between prologue and continuation.
func TestN101_IRStatefulScaffolding(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", "ir-stateful-scaffold-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Accept []struct {
			Name string          `json:"name"`
			IR   json.RawMessage `json:"ir"`
		} `json:"accept"`
		Cases []struct {
			Name  string          `json:"name"`
			IR    json.RawMessage `json:"ir"`
			Error string          `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) < 10 || len(corpus.Accept) < 3 {
		t.Fatalf("corpus has %d cases, %d accepts", len(corpus.Cases), len(corpus.Accept))
	}
	for _, a := range corpus.Accept {
		if _, err := CompileFromIRBytes(a.IR); err != nil {
			t.Errorf("%s must compile: %v", a.Name, err)
		}
	}
	for _, c := range corpus.Cases {
		_, err := CompileFromIRBytes(c.IR)
		if err == nil {
			t.Errorf("%s: accepted; want %q", c.Name, c.Error)
		} else if err.Error() != c.Error {
			t.Errorf("%s: got %q; want %q", c.Name, err.Error(), c.Error)
		}
	}
}
