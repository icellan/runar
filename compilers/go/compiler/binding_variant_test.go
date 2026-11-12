package compiler

import (
	"encoding/json"
	"strings"
	"testing"
)

// Ports #170 (original design: brendan-elas, #167): the C=1 Any-S binding and
// the @bindingVariant directive. The two blobs are pinned here as literals,
// not read from codegen, so a Go-only drift fails this file. Execution of the
// same bytes through @bsv/sdk Spend lives in
// packages/runar-testing/src/__tests__/binding-variant.test.ts.

// 422 bytes: s = lowS((z+1) mod n), C=1 key 038ff83d...
const bindingLowSHex = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

// 376 bytes: s = z+1, no mod-n, no low-S (nVersion > 1 only).
const bindingAllHex = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

func bindingCounter(directive string) string {
	return `
class C extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  ` + directive + `
  public bump() { this.count++; }
}
`
}

func TestBindingVariant_PinnedSizes(t *testing.T) {
	if len(bindingLowSHex)/2 != 422 || len(bindingAllHex)/2 != 376 {
		t.Fatalf("pins are %d / %d bytes, want 422 / 376", len(bindingLowSHex)/2, len(bindingAllHex)/2)
	}
}

func TestBindingVariant_DefaultIsC1LowS(t *testing.T) {
	for _, d := range []string{"", "/** @bindingVariant lowS */"} {
		r := compileOK(t, bindingCounter(d), "C.runar.ts")
		if strings.Count(r.Artifact.Script, bindingLowSHex) != 1 {
			t.Fatalf("%q: script does not contain the 422-byte lowS blob exactly once", d)
		}
		if strings.Contains(r.Artifact.Script, "02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0") {
			t.Fatalf("%q: retired C=2^248 key still emitted", d)
		}
	}
}

func TestBindingVariant_AllEmitsCompactBlob(t *testing.T) {
	r := compileOK(t, bindingCounter("/** @bindingVariant all */"), "C.runar.ts")
	if strings.Count(r.Artifact.Script, bindingAllHex) != 1 || strings.Contains(r.Artifact.Script, bindingLowSHex) {
		t.Fatal("@bindingVariant all must emit the 376-byte blob and not the default")
	}
}

func TestBindingVariant_NestedArmInherits(t *testing.T) {
	src := `
class G extends SmartContract {
  constructor() { super(); }
  /** @bindingVariant all */
  public unlock(a: SigHashPreimage, b: SigHashPreimage, c: boolean) {
    if (c) { assert(checkPreimage(a)); } else { assert(checkPreimage(b)); }
  }
}
`
	r := compileOK(t, src, "G.runar.ts")
	if strings.Count(r.Artifact.Script, bindingAllHex) != 2 || strings.Contains(r.Artifact.Script, bindingLowSHex) {
		t.Fatal("both if-arm checkPreimage calls must inherit @bindingVariant all")
	}
}

func TestBindingVariant_DirectiveErrors(t *testing.T) {
	cases := map[string]string{
		"/** @bindingVariant: all */":                       "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`",
		"/** @bindingVariant high */":                       `@bindingVariant: unknown variant "high" (valid: lowS, all)`,
		"/** @bindingVariant all */\n  // @bindingVariant lowS": "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one",
	}
	for d, want := range cases {
		r := CompileFromSourceStrWithResult(bindingCounter(d), "C.runar.ts")
		if r.Success || !strings.Contains(strings.Join(diagMessages(r), "\n"), want) {
			t.Fatalf("%q: want error %q, got %v", d, want, diagMessages(r))
		}
	}
	priv := strings.Replace(bindingCounter("/** @bindingVariant all */"), "public bump", "private bump", 1)
	r := CompileFromSourceStrWithResult(priv, "C.runar.ts")
	if r.Success || !strings.Contains(strings.Join(diagMessages(r), "\n"), "@bindingVariant directive on non-public method 'bump' has no effect") {
		t.Fatalf("private method: got %v", diagMessages(r))
	}
}

func TestBindingVariant_NonTSSurfacesRefuse(t *testing.T) {
	surfaces := map[string]string{
		"C.runar.sol": "Solidity", "C.runar.move": "Move", "C.runar.py": "Python", "C.runar.go": "Go DSL",
		"C.runar.rs": "Rust", "C.runar.rb": "Ruby", "C.runar.zig": "Zig", "C.runar.java": "Java",
	}
	for file, name := range surfaces {
		r := CompileFromSourceStrWithResult("// @bindingVariant all\n", file)
		want := "@bindingVariant directive is not supported by the " + name + " surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured"
		if r.Success || !strings.Contains(strings.Join(diagMessages(r), "\n"), want) {
			t.Fatalf("%s: want %q, got %v", file, want, diagMessages(r))
		}
	}
}

func TestBindingVariant_IRLoaderRefusesUnknown(t *testing.T) {
	prog, err := CompileSourceStrToIRForTest(bindingCounter("/** @bindingVariant all */"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prog, `"bindingVariant":"all"`) {
		t.Fatalf("--emit-ir must carry bindingVariant all")
	}
	if _, err := CompileFromIRBytes([]byte(prog)); err != nil {
		t.Fatalf("valid all IR refused: %v", err)
	}
	bad := strings.Replace(prog, `"bindingVariant":"all"`, `"bindingVariant":"high"`, 1)
	if _, err := CompileFromIRBytes([]byte(bad)); err == nil || !strings.Contains(err.Error(), `bindingVariant must be "lowS" or "all"`) {
		t.Fatalf("invalid bindingVariant accepted or wrong error: %v", err)
	}
}

// CompileSourceStrToIRForTest lowers a .runar.ts source and returns its ANF JSON.
func CompileSourceStrToIRForTest(src string) (string, error) {
	r := CompileFromSourceStrWithResult(src, "C.runar.ts", CompileOptions{DisableConstantFolding: true})
	if !r.Success {
		return "", &irTestErr{strings.Join(diagMessages(r), "; ")}
	}
	b, err := json.Marshal(r.ANF)
	return string(b), err
}

type irTestErr struct{ s string }

func (e *irTestErr) Error() string { return e.s }
