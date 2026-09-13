package compiler

import (
	"strings"
	"testing"
)

// R-122 / CL-BUG-130 — codegen's unknown-function fallback emitted a silent
// OP_0.
//
//	"lowerCall's unknown-function fallback emits OP_0 with no diagnostic, and it
//	 is reachable… The same file elsewhere explicitly refuses exactly this —
//	 'Refusing to emit a silent OP_0 placeholder' at :1273-1279 and :1395-1400.
//	 The discipline was not applied here."
//
// On the SOURCE path the typechecker rejects an unknown function first. The
// `--ir` entry points do not run the frontend at all (R-012 is the same shape),
// so ANF IR naming a function this tier has never heard of used to compile
// clean — and the value the contract asserts on became a hardcoded 0, i.e. an
// always-false spend rather than a refusal.
const unknownCallIR = `{
	"contractName": "UnknownCall",
	"properties": [
		{"name": "threshold", "type": "bigint", "readonly": true}
	],
	"methods": [{
		"name": "go",
		"isPublic": true,
		"params": [{"name": "x", "type": "bigint"}],
		"body": [
			{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t1", "value": {"kind": "call", "func": "definitelyNotARunarBuiltin", "args": ["t0"]}},
			{"name": "t2", "value": {"kind": "assert", "value": "t1"}}
		]
	}]
}`

func TestCompileFromIR_RefusesUnknownFunctionInsteadOfSilentOP0(t *testing.T) {
	artifact, err := CompileFromIRBytes([]byte(unknownCallIR))
	if err == nil {
		t.Fatalf("the --ir path ACCEPTED a call to an unknown function and emitted "+
			"a %d-hexchar script; the value the contract asserts on is a hardcoded 0",
			len(artifact.Script))
	}
	msg := err.Error()
	if !strings.Contains(msg, "definitelyNotARunarBuiltin") {
		t.Errorf("the error must name the function; got: %v", err)
	}
	if !strings.Contains(msg, "OP_0") {
		t.Errorf("the error must say what it refused to emit; got: %v", err)
	}
}

// The control: an ordinary IR program still compiles. A refusal added to a path
// that previously accepted bad input must not change what good input does.
func TestCompileFromIR_KnownBuiltinsStillCompile(t *testing.T) {
	artifact, err := CompileFromIRBytes([]byte(controlIR))
	if err != nil {
		t.Fatalf("ordinary IR must still compile: %v", err)
	}
	if artifact.Script == "" {
		t.Fatal("ordinary IR produced an empty script")
	}
}
