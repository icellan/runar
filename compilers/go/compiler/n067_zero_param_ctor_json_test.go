package compiler

import (
	"encoding/json"
	"strings"
	"testing"
)

// N-067 — a zero-parameter constructor must serialize abi.constructor.params
// as `[]`, not `null`.
//
// `constructorParams` in buildArtifact (compiler.go) was declared with
// `var constructorParams []ABIParam` and never appended to when the contract
// has no constructor properties, leaving it a nil slice. Go's encoding/json
// marshals a nil slice as the JSON literal `null` (it only marshals `[]` for
// a non-nil, zero-length slice), while every other tier's constructor-params
// list is built by map/list-comprehension/append idioms that always produce
// an empty collection, never a null. The TS SDK's `new RunarContract`
// (packages/runar-sdk/src/contract.ts) reads `artifact.abi.constructor.params.length`
// unconditionally, so a Go-compiled zero-arg-constructor artifact loaded there
// crashed with "Cannot read properties of null (reading 'length')" instead of
// working like the TS-compiled equivalent.
//
// What this test proves: compiling a zero-parameter-constructor contract with
// the Go compiler and marshaling the resulting *Artifact to JSON (the exact
// path the CLI's `--source` mode uses, ArtifactToJSON) yields
// `"params":[]` for the constructor, matching the TS emitter's shape.
// What it does NOT prove: anything about the TS SDK's handling of a
// (now impossible for a fresh Go artifact) null value — that is covered
// separately in packages/runar-sdk's test suite.
func TestZeroParamConstructor_ABIParamsSerializesAsEmptyArray_NotNull(t *testing.T) {
	src := `import { SmartContract, assert } from 'runar-lang';

class NoArgs extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint) {
    assert(p > 0n);
  }
}
`
	r := CompileFromSourceStrWithResult(src, "NoArgs.runar.ts", CompileOptions{})
	if !r.Success || r.Artifact == nil {
		t.Fatalf("compile failed: %v", diagMessages(r))
	}

	if len(r.Artifact.ABI.Constructor.Params) != 0 {
		t.Fatalf("expected 0 constructor params, got %d", len(r.Artifact.ABI.Constructor.Params))
	}

	raw, err := ArtifactToJSON(r.Artifact)
	if err != nil {
		t.Fatalf("ArtifactToJSON failed: %v", err)
	}

	// Confirm the JSON actually round-trips a real `[]`, not a JSON `null`
	// that happens to unmarshal into a nil/zero-length Go slice.
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("failed to unmarshal artifact JSON: %v", err)
	}
	abi, ok := parsed["abi"].(map[string]interface{})
	if !ok {
		t.Fatalf("artifact JSON missing abi object: %s", raw)
	}
	ctor, ok := abi["constructor"].(map[string]interface{})
	if !ok {
		t.Fatalf("artifact JSON missing abi.constructor object: %s", raw)
	}
	params, present := ctor["params"]
	if !present {
		t.Fatalf("artifact JSON missing abi.constructor.params: %s", raw)
	}
	if params == nil {
		t.Fatalf("abi.constructor.params serialized as JSON null, want []; full JSON:\n%s", raw)
	}
	arr, ok := params.([]interface{})
	if !ok || len(arr) != 0 {
		t.Fatalf("abi.constructor.params did not deserialize as an empty array: %#v", params)
	}

	// Belt-and-suspenders: assert directly on the serialized bytes that the
	// substring is `"params":[]` (compact form is not what MarshalIndent
	// produces, so check the indented form instead) and that `"params": null`
	// never appears anywhere in the artifact.
	if strings.Contains(string(raw), `"params": null`) {
		t.Fatalf("artifact JSON contains \"params\": null:\n%s", raw)
	}
}
