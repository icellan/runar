package compiler

import (
	"reflect"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// R-012 / CL-BUG-093 — the `--ir` entry point bypassed the entire frontend,
// and with it the `verifySP1FRI` soundness refusal.
//
// The refusal lives in `frontend.Validate`, which only ever runs on a
// `CompileFromSource*` path. `CompileFromIR`, `CompileFromIRBytes` and
// `CompileFromProgram` never call it, so ANF IR that reaches the known-unsound
// SP1 FRI verifier compiled clean — no error, no warning, exit 0 — producing
// byte-for-byte the same 248,560-byte locking script the source path refuses to
// emit without an explicit acknowledgement.
//
// The acknowledgement CANNOT be carried in the IR. Two independent reasons:
//
//  1. `ir.ANFProgram` has exactly three JSON fields (contractName, properties,
//     methods) and the emitted ANF IR JSON is compared BYTE-FOR-BYTE across all
//     seven tiers by the conformance suite. The tier-local metadata that does
//     exist (`ParentClass`, `ANFMethod.SigHashType`) is deliberately tagged
//     `json:"-"` precisely so it never reaches that JSON — an in-memory carrier
//     cannot survive the `--ir` round trip by construction.
//  2. More fundamentally: IR handed to `--ir` is UNTRUSTED INPUT. A flag inside
//     it would be written by whoever wrote the IR, so it would authorise
//     nothing. The acknowledgement has to come from the invoker
//     (`CompileOptions.AcknowledgeUnsoundSP1Fri`, surfaced as the CLI's
//     `--acknowledge-unsound-sp1-fri`), not from the artifact under inspection.
//
// So the guard consults the OBSERVABLE instead: a `call` binding naming
// `verifySP1FRI` is exactly what `codegen/stack.go` dispatches on to emit the
// unsound verifier, and it is present in the IR whether or not the source that
// produced it carried the directive.

const sp1FriIRCall = `{
	"contractName": "Sp1Guard",
	"properties": [
		{"name": "sp1VKeyHash", "type": "ByteString", "readonly": true}
	],
	"methods": [{
		"name": "verify",
		"isPublic": true,
		"params": [
			{"name": "proofBlob", "type": "ByteString"},
			{"name": "publicValues", "type": "ByteString"}
		],
		"body": [
			{"name": "t0", "value": {"kind": "load_param", "name": "proofBlob"}},
			{"name": "t1", "value": {"kind": "load_param", "name": "publicValues"}},
			{"name": "t2", "value": {"kind": "load_prop", "name": "sp1VKeyHash"}},
			{"name": "t3", "value": {"kind": "call", "func": "verifySP1FRI", "args": ["t0", "t1", "t2"]}},
			{"name": "t4", "value": {"kind": "assert", "value": "t3"}}
		]
	}]
}`

// sp1FriIRNested hides the call one level down, inside an `if` arm that itself
// contains a `loop` whose body holds the call. A guard that only scans the
// top-level binding list of each method walks straight past this.
const sp1FriIRNested = `{
	"contractName": "Sp1GuardNested",
	"properties": [
		{"name": "sp1VKeyHash", "type": "ByteString", "readonly": true}
	],
	"methods": [{
		"name": "verify",
		"isPublic": true,
		"params": [
			{"name": "proofBlob", "type": "ByteString"},
			{"name": "publicValues", "type": "ByteString"}
		],
		"body": [
			{"name": "t0", "value": {"kind": "load_const", "value": true}},
			{"name": "t1", "value": {
				"kind": "if",
				"cond": "t0",
				"then": [
					{"name": "t2", "value": {
						"kind": "loop",
						"count": 1,
						"iterVar": "i",
						"body": [
							{"name": "t3", "value": {"kind": "load_param", "name": "proofBlob"}},
							{"name": "t4", "value": {"kind": "load_param", "name": "publicValues"}},
							{"name": "t5", "value": {"kind": "load_prop", "name": "sp1VKeyHash"}},
							{"name": "t6", "value": {"kind": "call", "func": "verifySP1FRI", "args": ["t3", "t4", "t5"]}},
							{"name": "t7", "value": {"kind": "assert", "value": "t6"}}
						]
					}}
				],
				"else": []
			}}
		]
	}]
}`

// controlIR is the negative control: ordinary IR with nothing to do with SP1.
// It must compile through `--ir` unchanged, before and after the fix.
const controlIR = `{
	"contractName": "P2PKH",
	"properties": [
		{"name": "pubKeyHash", "type": "Addr", "readonly": true}
	],
	"methods": [{
		"name": "unlock",
		"isPublic": true,
		"params": [
			{"name": "sig", "type": "Sig"},
			{"name": "pubKey", "type": "PubKey"}
		],
		"body": [
			{"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
			{"name": "t1", "value": {"kind": "load_param", "name": "pubKey"}},
			{"name": "t2", "value": {"kind": "load_prop", "name": "pubKeyHash"}},
			{"name": "t3", "value": {"kind": "call", "func": "hash160", "args": ["t1"]}},
			{"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t3", "right": "t2"}},
			{"name": "t5", "value": {"kind": "assert", "value": "t4"}},
			{"name": "t6", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
			{"name": "t7", "value": {"kind": "assert", "value": "t6"}}
		]
	}]
}`

// TestCompileFromIRBytes_RefusesUnsoundSP1FriVerifier is the exact testable
// assertion for R-012: ANF JSON containing {"kind":"call","func":"verifySP1FRI"}
// must be refused with an error mentioning REFUSING.
func TestCompileFromIRBytes_RefusesUnsoundSP1FriVerifier(t *testing.T) {
	for _, tc := range []struct {
		name   string
		irJSON string
	}{
		{"top-level call", sp1FriIRCall},
		{"nested in if/loop", sp1FriIRNested},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact, err := CompileFromIRBytes([]byte(tc.irJSON))
			if err == nil {
				t.Fatalf("--ir path ACCEPTED the known-unsound SP1 FRI verifier "+
					"(script %d hex chars); it must refuse", len(artifact.Script))
			}
			if !strings.Contains(err.Error(), "REFUSING") {
				t.Errorf("error must name the refusal; got: %v", err)
			}
			if !strings.Contains(err.Error(), "verifySP1FRI") {
				t.Errorf("error must name the builtin; got: %v", err)
			}
			// The IR path has no source to put a comment directive in, so the
			// message must point at the invoker-side acknowledgement instead.
			if !strings.Contains(err.Error(), "--acknowledge-unsound-sp1-fri") {
				t.Errorf("error must name the IR-path acknowledgement flag; got: %v", err)
			}
		})
	}
}

// TestCompileFromIR_AcknowledgedByInvokerStillCompiles pins the escape hatch:
// the acknowledgement comes from the caller, never from the IR.
func TestCompileFromIR_AcknowledgedByInvokerStillCompiles(t *testing.T) {
	artifact, err := CompileFromIRBytes([]byte(sp1FriIRCall), CompileOptions{
		AcknowledgeUnsoundSP1Fri: true,
	})
	if err != nil {
		t.Fatalf("acknowledged --ir compile must succeed: %v", err)
	}
	if len(artifact.Script) == 0 {
		t.Fatal("acknowledged --ir compile produced an empty script")
	}
}

// TestCompileFromIRBytes_ControlIRUnaffected is the control. It must pass both
// before and after the fix: a refusal added to a path that previously accepted
// bad input must not change what legitimate input does.
func TestCompileFromIRBytes_ControlIRUnaffected(t *testing.T) {
	artifact, err := CompileFromIRBytes([]byte(controlIR))
	if err != nil {
		t.Fatalf("ordinary IR must still compile through --ir: %v", err)
	}
	if len(artifact.Script) == 0 {
		t.Fatal("ordinary IR produced an empty script")
	}
}

// TestCompileFromProgram_RefusesUnsoundSP1FriVerifier covers the third bypassing
// entry point named in the finding. CompileFromProgram is exported, so a
// downstream Go caller can hand it a loaded ANF program directly and skip
// CompileFromIR entirely.
func TestCompileFromProgram_RefusesUnsoundSP1FriVerifier(t *testing.T) {
	prog := mustLoadIR(t, sp1FriIRCall)
	if _, err := CompileFromProgram(prog); err == nil {
		t.Fatal("CompileFromProgram ACCEPTED the known-unsound SP1 FRI verifier")
	} else if !strings.Contains(err.Error(), "REFUSING") {
		t.Errorf("error must name the refusal; got: %v", err)
	}
}

// TestSP1FriIRWalker_WalksEveryNestedBindingList is the exhaustiveness pin,
// mirroring frontend.TestSP1FriWalker_HandlesEveryDeclaredExpressionType on the
// source side. `ir.ANFValue` is a flat struct with a Kind discriminator; every
// field of type []ANFBinding is a place a `call` binding can hide. If a future
// ANF kind adds a new nested binding list and the walker is not taught about
// it, the refusal becomes a silent bypass again — so fail the build here rather
// than in production.
func TestSP1FriIRWalker_WalksEveryNestedBindingList(t *testing.T) {
	// Fields the walker descends into. Keep in sync with
	// walkBindingsForSP1Fri in sp1_fri_ir_guard.go.
	walked := map[string]bool{
		"Then": true,
		"Else": true,
		"Body": true,
	}

	bindingSliceType := reflect.TypeOf([]ir.ANFBinding(nil))
	vt := reflect.TypeOf(ir.ANFValue{})
	for i := 0; i < vt.NumField(); i++ {
		f := vt.Field(i)
		if f.Type != bindingSliceType {
			continue
		}
		if !walked[f.Name] {
			t.Errorf("ir.ANFValue.%s is a nested []ANFBinding that the SP1 FRI IR "+
				"walker does not descend into — a verifySP1FRI call placed there "+
				"would bypass the refusal. Add it to walkBindingsForSP1Fri and to "+
				"the `walked` set in this test.", f.Name)
		}
		delete(walked, f.Name)
	}
	for name := range walked {
		t.Errorf("walker descends into ir.ANFValue.%s, which no longer exists "+
			"(or is no longer []ANFBinding)", name)
	}
}
