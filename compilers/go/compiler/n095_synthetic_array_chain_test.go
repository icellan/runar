package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// N-095 — `syntheticArrayChain` on ANFProperty is wire data, and the wire is
// governed by packages/runar-ir-schema/src/schemas/anf-ir.schema.json.
//
// The expand-fixed-arrays pass desugars a `FixedArray` property into scalar
// siblings and hangs a chain of `{base, index, length}` levels off each leaf.
// The artifact assembler regroups those siblings back into a single FixedArray
// state/ABI entry by reading that chain off the *ANF program*, not off the AST
// -- so an ANF that loses the field still compiles to identical script bytes
// but degrades the SDK's `state.grid` accessor into N raw scalars. That is why
// the field must be BOTH emitted and declared in the shared schema: `$defs.
// ANFProperty` is `additionalProperties: false`, so an undeclared field makes
// Go's own ANF fail `validateANF`.
//
// Go is the tier whose spelling won (`syntheticArrayChain`); these tests pin
// it against the schema so a future rename in either place fails here.
// ---------------------------------------------------------------------------

const n095NestedFixedArraySource = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class Grid2x2 extends StatefulSmartContract {
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public set00(v: bigint) {
    this.grid[0][0] = v;
    assert(true);
  }

  public set11(v: bigint) {
    this.grid[1][1] = v;
    assert(true);
  }
}
`

// n095AnfSchemaProperties returns the key set `$defs.ANFProperty` accepts.
func n095AnfSchemaProperties(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "..", "packages", "runar-ir-schema", "src", "schemas", "anf-ir.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ANF schema: %v", err)
	}
	var schema struct {
		Defs map[string]struct {
			AdditionalProperties *bool                      `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse ANF schema: %v", err)
	}
	def, ok := schema.Defs["ANFProperty"]
	if !ok {
		t.Fatal("$defs.ANFProperty missing from the ANF schema")
	}
	if def.AdditionalProperties == nil || *def.AdditionalProperties {
		t.Fatal("$defs.ANFProperty is no longer additionalProperties:false — " +
			"this test's premise (an undeclared key is a schema violation) no longer holds")
	}
	keys := make(map[string]bool, len(def.Properties))
	for k := range def.Properties {
		keys[k] = true
	}
	return keys
}

// n095EmitIR compiles the source to ANF and returns the same JSON shape
// `--emit-ir` prints (marshalled through the ir package's json tags).
func n095EmitIR(t *testing.T, source string) []map[string]json.RawMessage {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Grid2x2.runar.ts")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	program, err := CompileSourceToIR(path)
	if err != nil {
		t.Fatalf("CompileSourceToIR: %v", err)
	}
	raw, err := json.Marshal(program)
	if err != nil {
		t.Fatalf("marshal ANF: %v", err)
	}
	var doc struct {
		Properties []map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal ANF: %v", err)
	}
	return doc.Properties
}

// TestN095_EmittedPropertyKeysAreAllDeclaredInTheSchema is the schema-
// conformance guard: every key Go writes on an ANFProperty must be a key the
// cross-tier schema declares. Before N-095 this failed on
// `syntheticArrayChain`.
func TestN095_EmittedPropertyKeysAreAllDeclaredInTheSchema(t *testing.T) {
	allowed := n095AnfSchemaProperties(t)
	for _, prop := range n095EmitIR(t, n095NestedFixedArraySource) {
		for key := range prop {
			if !allowed[key] {
				t.Errorf("emitted ANFProperty key %q is not declared in $defs.ANFProperty "+
					"(additionalProperties:false) — Go's own ANF fails validateANF", key)
			}
		}
	}
}

// TestN095_ExpandedLeavesCarryTheCamelCaseChain pins the spelling AND the
// shape. A tier that renames the key, or drops it, silently loses the ABI
// regrouping without moving a single script byte.
func TestN095_ExpandedLeavesCarryTheCamelCaseChain(t *testing.T) {
	props := n095EmitIR(t, n095NestedFixedArraySource)
	if len(props) != 4 {
		t.Fatalf("expected 4 expanded leaves, got %d", len(props))
	}
	want := [][2]int{{0, 0}, {0, 1}, {1, 0}, {1, 1}}
	for i, prop := range props {
		rawChain, ok := prop["syntheticArrayChain"]
		if !ok {
			t.Fatalf("leaf %d has no \"syntheticArrayChain\" key (keys: %v)", i, keysOf(prop))
		}
		if _, bad := prop["__syntheticArrayChain"]; bad {
			t.Errorf("leaf %d still carries the Rust AST-marker spelling", i)
		}
		if _, bad := prop["synthetic_array_chain"]; bad {
			t.Errorf("leaf %d still carries the Ruby snake spelling", i)
		}
		var chain []struct {
			Base   string `json:"base"`
			Index  int    `json:"index"`
			Length int    `json:"length"`
		}
		if err := json.Unmarshal(rawChain, &chain); err != nil {
			t.Fatalf("leaf %d chain does not match {base,index,length}: %v", i, err)
		}
		if len(chain) != 2 {
			t.Fatalf("leaf %d: chain length %d, want 2 (a 2x2 grid nests twice)", i, len(chain))
		}
		if chain[0].Base != "grid" || chain[0].Length != 2 || chain[0].Index != want[i][0] {
			t.Errorf("leaf %d outer level = %+v, want base=grid index=%d length=2", i, chain[0], want[i][0])
		}
		if chain[1].Length != 2 || chain[1].Index != want[i][1] {
			t.Errorf("leaf %d inner level = %+v, want index=%d length=2", i, chain[1], want[i][1])
		}
	}
}

// TestN095_ScalarPropertyCarriesNoChain is the byte-neutrality control: a
// contract with no FixedArray must not grow the key.
func TestN095_ScalarPropertyCarriesNoChain(t *testing.T) {
	const src = `import { StatefulSmartContract, assert } from 'runar-lang';

export class Counter extends StatefulSmartContract {
  count: bigint = 0n;

  constructor() {
    super();
  }

  public increment() {
    this.count = this.count + 1n;
    assert(true);
  }
}
`
	for i, prop := range n095EmitIR(t, src) {
		for key := range prop {
			if key == "syntheticArrayChain" {
				t.Errorf("property %d on a FixedArray-free contract grew a syntheticArrayChain key", i)
			}
		}
	}
}

// TestN095_SelfIRRoundTripStillRegroups is the acceptance test: Go's own ANF,
// fed back through `--ir`, must still produce the regrouped `grid` state field
// rather than four raw scalars.
func TestN095_SelfIRRoundTripStillRegroups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Grid2x2.runar.ts")
	if err := os.WriteFile(path, []byte(n095NestedFixedArraySource), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	program, err := CompileSourceToIR(path)
	if err != nil {
		t.Fatalf("CompileSourceToIR: %v", err)
	}
	irJSON, err := json.Marshal(program)
	if err != nil {
		t.Fatalf("marshal ANF: %v", err)
	}

	fromSource, err := CompileFromSource(path)
	if err != nil {
		t.Fatalf("CompileFromSource: %v", err)
	}
	fromIR, err := CompileFromIRBytes(irJSON)
	if err != nil {
		t.Fatalf("CompileFromIRBytes: %v", err)
	}

	assertRegrouped(t, "source", fromSource)
	assertRegrouped(t, "ir", fromIR)

	if fromSource.Script != fromIR.Script {
		t.Errorf("script hex diverged between source mode and IR mode")
	}
}

func assertRegrouped(t *testing.T, label string, artifact *Artifact) {
	t.Helper()
	if len(artifact.StateFields) != 1 {
		names := make([]string, 0, len(artifact.StateFields))
		for _, sf := range artifact.StateFields {
			names = append(names, sf.Name)
		}
		t.Fatalf("%s: expected 1 regrouped state field, got %d %v", label, len(artifact.StateFields), names)
	}
	sf := artifact.StateFields[0]
	if sf.Name != "grid" {
		t.Errorf("%s: state field name = %q, want \"grid\"", label, sf.Name)
	}
	if sf.FixedArray == nil {
		t.Fatalf("%s: state field carries no fixedArray metadata — the SDK accessor is broken", label)
	}
	want := []string{"grid__0__0", "grid__0__1", "grid__1__0", "grid__1__1"}
	if len(sf.FixedArray.SyntheticNames) != len(want) {
		t.Fatalf("%s: syntheticNames = %v, want %v", label, sf.FixedArray.SyntheticNames, want)
	}
	for i, n := range want {
		if sf.FixedArray.SyntheticNames[i] != n {
			t.Errorf("%s: syntheticNames[%d] = %q, want %q", label, i, sf.FixedArray.SyntheticNames[i], n)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
