package ir

// N-205 (b): the --ir loader re-asserts verifyRabinSig key provenance.
//
// What this proves: LoadIRFromBytes refuses the oracle-price golden with its
// modulus rebound to a load_param, with the shared diagnostic, and still loads
// the unmodified golden. What it does NOT prove: the helper / alias / write
// shapes and cross-tier agreement — conformance/negatives/
// ir-rabin-key-provenance.test.ts runs those against this tier's binary.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestN205_IRRabinKeyProvenance(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "tests", "oracle-price", "expected-ir.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIRFromBytes(data); err != nil {
		t.Fatalf("golden refused: %v", err)
	}
	// settle's t5 (`load_prop oraclePubKey`) becomes `load_param price`.
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	applied := false
	for _, m := range doc["methods"].([]any) {
		method := m.(map[string]any)
		if method["name"] != "settle" {
			continue
		}
		for _, b := range method["body"].([]any) {
			binding := b.(map[string]any)
			if binding["name"] == "t5" {
				binding["value"] = map[string]any{"kind": "load_param", "name": "price"}
				applied = true
			}
		}
	}
	if !applied {
		t.Fatal("mutation did not apply; golden layout changed")
	}
	hostile, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadIRFromBytes(hostile)
	want := "IR validation: method 'settle': verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}
