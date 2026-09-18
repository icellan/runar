package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// R-214 (CL-GAP-055) — the playground computed the ANF IR and threw it away.
//
// `compileSource` calls the same library entry point the CLI uses, and that
// entry point returns a `*CompileResult` carrying `ANF` — the A-Normal Form IR
// from pass 4. The playground handler kept `ScriptHex` and `ScriptAsm` and
// dropped everything else, so the one artifact that explains WHY a contract
// compiles to the bytes it does never reached the browser.
//
// The IR is the part a playground is for. Hex and ASM show the result;
// the ANF shows the lowering — which binding became which push, where the
// constant folder fired, what the fixed-array expansion produced.
//
// Stack IR is deliberately NOT added here: no tier serialises it (see
// CLAUDE.md, invariant 2 — the claim that it is compared was removed under
// R-096), so there is no canonical form to hand out. The finding named both;
// only one of them exists to return.

const irProbeSource = `import { SmartContract, assert } from 'runar-lang';

export class IrProbe extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  public verify(x: bigint) { assert(x === this.target); }
}`

func postCompile(t *testing.T, body map[string]string) (int, map[string]any) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/compile", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handleCompile(rec, req)

	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response (%d): %v\nbody: %s", rec.Code, err, rec.Body.String())
	}
	return rec.Code, decoded
}

func TestPlayground_ReturnsAnfIr(t *testing.T) {
	code, resp := postCompile(t, map[string]string{
		"source":   irProbeSource,
		"filename": "IrProbe.runar.ts",
	})
	if code != http.StatusOK {
		t.Fatalf("compile failed (%d): %v", code, resp)
	}

	// The pre-existing fields must survive.
	if _, ok := resp["scriptHex"].(string); !ok {
		t.Fatalf("scriptHex missing or not a string: %v", resp["scriptHex"])
	}
	if _, ok := resp["scriptAsm"].(string); !ok {
		t.Fatalf("scriptAsm missing or not a string: %v", resp["scriptAsm"])
	}

	anf, ok := resp["anfIr"].(map[string]any)
	if !ok {
		t.Fatalf("anfIr missing or not an object: %#v", resp["anfIr"])
	}

	// Anti-vacuity: an empty object would satisfy the type assertion above.
	if name, _ := anf["contractName"].(string); name != "IrProbe" {
		t.Fatalf("anfIr.contractName = %q, want %q", name, "IrProbe")
	}
	methods, ok := anf["methods"].([]any)
	if !ok || len(methods) == 0 {
		t.Fatalf("anfIr.methods is empty or not an array: %#v", anf["methods"])
	}

	// The IR must be the real lowering, not a stub: `verify` has to carry the
	// bindings that produce the comparison.
	raw, err := json.Marshal(anf)
	if err != nil {
		t.Fatalf("re-marshal anf: %v", err)
	}
	for _, want := range []string{"load_param", "load_prop", "bin_op", "assert"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("anfIr does not mention %q — this is not a real lowering:\n%s", want, raw)
		}
	}
}

func TestPlayground_AnfIrTracksTheSource(t *testing.T) {
	// A different contract must yield a different IR, or the handler could be
	// returning a cached or hard-coded blob and the test above would not care.
	_, first := postCompile(t, map[string]string{
		"source":   irProbeSource,
		"filename": "IrProbe.runar.ts",
	})
	_, second := postCompile(t, map[string]string{
		"source": strings.Replace(irProbeSource,
			"class IrProbe", "class IrProbeTwo", 1),
		"filename": "IrProbeTwo.runar.ts",
	})

	nameOf := func(resp map[string]any) string {
		anf, ok := resp["anfIr"].(map[string]any)
		if !ok {
			t.Fatalf("response carries no anfIr object: %#v", resp["anfIr"])
		}
		name, _ := anf["contractName"].(string)
		return name
	}
	firstName, secondName := nameOf(first), nameOf(second)
	if firstName == secondName {
		t.Fatalf("both compiles reported contractName %q — the IR does not track the source", firstName)
	}
}

func TestPlayground_FailedCompileCarriesNoIr(t *testing.T) {
	// A rejected source must not ship a half-built IR the browser would render
	// as if it were the lowering of valid code.
	code, resp := postCompile(t, map[string]string{
		"source":   "this is not a contract",
		"filename": "Broken.runar.ts",
	})
	if code == http.StatusOK {
		t.Fatalf("expected a rejection, got 200: %v", resp)
	}
	if _, present := resp["anfIr"]; present {
		t.Fatalf("error response carries anfIr: %v", resp)
	}
}
