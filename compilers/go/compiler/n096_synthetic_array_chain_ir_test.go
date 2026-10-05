package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// N-096 — an over-deep `syntheticArrayChain` must be refused, never panic.
//
// regroupSyntheticRuns ended its 1024-pass cap with panic(), so the F-105
// probe (basic-p2pkh plus a property whose chain is 1100 levels deep) made the
// --ir CLI exit 2 with a goroutine dump. The loader now refuses such a chain
// up front with the shared diagnostic (conformance/negatives/
// ir-synthetic-array-chain.test.ts holds the 7-tier corpus); the regrouper
// itself also returns an error, because the SOURCE path reaches it too.
//
// Proves: neither the IR entry point nor the regrouper panics on a chain past
// the cap, and the IR entry point gives the shared diagnostic. Does not prove:
// the rest of the rule (sibling/naming checks), which the conformance corpus
// covers in every tier.
// ---------------------------------------------------------------------------

func n096DeepChain(depth int) []ir.ANFSyntheticArrayLevel {
	chain := make([]ir.ANFSyntheticArrayLevel, depth)
	for k := range chain {
		chain[k] = ir.ANFSyntheticArrayLevel{Base: "deep", Index: 0, Length: 1}
	}
	return chain
}

func TestN096_RegroupCapReturnsErrorInsteadOfPanicking(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("regroupSyntheticRuns panicked: %v", r)
		}
	}()
	_, err := regroupSyntheticRuns([]regroupEntry{{name: "deep", typ: "bigint", chain: n096DeepChain(1100)}})
	if err == nil {
		t.Fatal("expected an error for a chain deeper than the regroup cap")
	}
}

func TestN096_IRProbeRefusedWithSharedDiagnostic(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "tests", "basic-p2pkh", "expected-ir.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	props := doc["properties"].([]interface{})
	deep := map[string]interface{}{"name": "deep", "type": "bigint", "readonly": true, "syntheticArrayChain": n096DeepChain(1100)}
	doc["properties"] = append([]interface{}{props[0], deep}, props[1:]...)
	probe, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CompileFromIRBytes panicked: %v", r)
		}
	}()
	_, err = CompileFromIRBytes(probe)
	want := "IR validation: malformed syntheticArrayChain on property 'deep': 1100 levels exceed the limit of 1023"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want error containing %q, got %v", want, err)
	}
}
