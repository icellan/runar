package compiler

// N-151 — the artifact carries rawScriptSpans exactly as the TS reference does.
//
// The emitter always recorded a span per asm() raw-bytes op, but
// assembleArtifact never copied them into the Artifact, so the serialized
// artifact had no rawScriptSpans key even for real asm() contracts. The
// expected values below are the ones pinned by the TS reference test
// packages/runar-compiler/src/__tests__/raw-script-spans.test.ts.
//
// Proves: this tier's serialized artifact JSON carries the same
// rawScriptSpans array (offset, length, inArity, outArity) as TS for the
// single-span, consecutive-span, non-default-arity and multi-byte-body
// shapes, and omits the key for a contract with no asm(). Does NOT prove
// anything about how an SDK or analyzer consumes the spans; cross-tier value
// parity is conformance/negatives/artifact-flag-parity.test.ts.

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func n151Spans(t *testing.T, source string) (interface{}, bool) {
	t.Helper()
	r := CompileFromSourceStrWithResult(source, "WithAsm.runar.ts")
	if !r.Success || r.Artifact == nil {
		var msgs []string
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "; "))
	}
	raw, err := json.Marshal(r.Artifact)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	v, ok := m["rawScriptSpans"]
	return v, ok
}

func n151Span(offset, length, in, out float64) map[string]interface{} {
	return map[string]interface{}{"offset": offset, "length": length, "inArity": in, "outArity": out}
}

func n151Asm(params, body string) string {
	return `import { UnsafeSmartContract, asm } from 'runar-lang';

class WithAsm extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(` + params + `) {
` + body + `
  }
}
`
}

func TestN151_RawScriptSpansInArtifact(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   []interface{}
	}{
		{
			"single span",
			n151Asm("", `    asm({ body: '51', in_arity: 0, out_arity: 1 });`),
			[]interface{}{n151Span(0, 1, 0, 1)},
		},
		{
			"consecutive spans",
			n151Asm("", "    asm({ body: '51', in_arity: 0, out_arity: 1 });\n    asm({ body: '6151', in_arity: 1, out_arity: 1 });"),
			[]interface{}{n151Span(0, 1, 0, 1), n151Span(1, 2, 1, 1)},
		},
		{
			"non-default arities",
			n151Asm("a: bigint, b: bigint", `    asm({ body: '87', in_arity: 2, out_arity: 1 });`),
			[]interface{}{n151Span(0, 1, 2, 1)},
		},
		{
			"multi-byte body",
			n151Asm("", `    asm({ body: '76a90051', in_arity: 0, out_arity: 1 });`),
			[]interface{}{n151Span(0, 4, 0, 1)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := n151Spans(t, c.source)
			if !ok {
				t.Fatalf("artifact has no rawScriptSpans key; want %v", c.want)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("rawScriptSpans = %v, want %v", got, c.want)
			}
		})
	}
}

func TestN151_RawScriptSpansOmittedWithoutAsm(t *testing.T) {
	src := `import { SmartContract, assert } from 'runar-lang';

class Always extends SmartContract {
  constructor() { super(); }
  public unlock(): void {
    assert(1n === 1n);
  }
}
`
	if v, ok := n151Spans(t, src); ok {
		t.Fatalf("rawScriptSpans must be omitted for a contract with no asm(), got %v", v)
	}
}
