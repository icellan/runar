package compiler

import (
	"strings"
	"testing"
)

// F-258 / CL-BUG-151 — codegen's non-literal property-initializer fallback
// emitted a silent OP_0.
//
// The language only allows literal property initializers (BigIntLiteral /
// BoolLiteral / ByteStringLiteral -- see CLAUDE.md "Property initializers").
// The frontend enforces that, but the `--ir` entry point skips the frontend
// entirely (same shape as R-012 / R-122), so a hand-written IR file can give
// a property a non-literal (array/object) `initialValue`. `pushPropertyValue`'s
// default case used to silently push 0 for any value it did not recognize --
// compiling cleanly to a script that always reads the property as 0, with no
// diagnostic.
const hostilePropertyInitializerIR = `{
	"contractName": "HostilePropInit",
	"properties": [
		{"name": "secret", "type": "bigint", "readonly": true, "initialValue": [1, 2, 3]}
	],
	"methods": [{
		"name": "reveal",
		"isPublic": true,
		"params": [],
		"body": [
			{"name": "t0", "value": {"kind": "load_prop", "name": "secret"}},
			{"name": "t1", "value": {"kind": "assert", "value": "t0"}}
		]
	}]
}`

func TestCompileFromIR_RefusesNonLiteralPropertyInitializerInsteadOfSilentOP0(t *testing.T) {
	artifact, err := CompileFromIRBytes([]byte(hostilePropertyInitializerIR))
	if err == nil {
		t.Fatalf("the --ir path ACCEPTED a non-literal (array) property initializer and "+
			"emitted a %d-hexchar script; the property it is spliced into always reads as 0",
			len(artifact.Script))
	}
	msg := err.Error()
	if !strings.Contains(msg, "secret") {
		t.Errorf("the error must name the property; got: %v", err)
	}
	if !strings.Contains(msg, "OP_0") {
		t.Errorf("the error must say what it refused to emit; got: %v", err)
	}
}

// The control: a property with a REAL literal initializer (the only shape
// the frontend ever produces) still compiles through pushPropertyValue's
// non-default arms. A refusal added to the fallback must not change what
// good input does.
const literalPropertyInitializerIR = `{
	"contractName": "LiteralPropInit",
	"properties": [
		{"name": "threshold", "type": "bigint", "readonly": true, "initialValue": 42}
	],
	"methods": [{
		"name": "check",
		"isPublic": true,
		"params": [],
		"body": [
			{"name": "t0", "value": {"kind": "load_prop", "name": "threshold"}},
			{"name": "t1", "value": {"kind": "assert", "value": "t0"}}
		]
	}]
}`

func TestCompileFromIR_LiteralPropertyInitializerStillCompiles(t *testing.T) {
	artifact, err := CompileFromIRBytes([]byte(literalPropertyInitializerIR))
	if err != nil {
		t.Fatalf("a literal property initializer must still compile: %v", err)
	}
	if artifact.Script == "" {
		t.Fatal("ordinary IR produced an empty script")
	}
}
