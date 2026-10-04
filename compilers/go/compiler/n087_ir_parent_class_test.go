package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// N-087 — CompileFromIRBytes enforces the source validator's parentClass rules
// on IR, with the diagnostics shared by all seven tiers
// (conformance/negatives/ir-parent-class-cases.json).
//
// Before: a SmartContract declaring `owner` with readonly:false (F-107's
// v2-mut-stateless) compiled to 76767b8777, which an attacker's key spends
// under strict @bsv/sdk Spend; stateful-only nodes in a non-stateful contract
// and raw_script outside UnsafeSmartContract compiled too.
//
// Proves: every corpus case is refused with its exact diagnostic and the
// accepted programs (incl. parentClass-less IR) compile. Does not prove that a
// declared StatefulSmartContract body enforces its state continuation.
func TestN087_IRParentClassRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", "ir-parent-class-cases.json"))
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
			Match string          `json:"match"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) < 10 {
		t.Fatalf("corpus has %d cases", len(corpus.Cases))
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
		} else if got := err.Error(); (c.Match == "prefix" && !strings.HasPrefix(got, c.Error)) || (c.Match != "prefix" && got != c.Error) {
			t.Errorf("%s: got %q; want %q", c.Name, err.Error(), c.Error)
		}
	}
}
