package ir

import (
	"strings"
	"testing"
)

// R-079: a raw_script span with an EMPTY body but a non-trivial declared arity
// is a miscompile, not a cosmetic annotation mismatch.
//
// `raw_script` is the one ANF node the compiler treats as opaque: stack
// lowering does not read the bytes, it trusts the declared `in_arity` /
// `out_arity` to model the span's stack effect (see
// codegen.loweringContext.lowerRawScript, which pops in_arity and pushes
// out_arity). Emission, by contrast, short-circuits on a zero-length span
// (codegen.emitContext.emitRawBytes returns before writing anything). The two
// halves then disagree: the stack model believes operands were consumed and a
// result produced, while the script does nothing at all. Every downstream
// PICK/ROLL depth computed off that model addresses the wrong slot.
//
// Observed on the `--ir` path before this guard, with in_arity 1 / out_arity 1
// and a body that should have been OP_NEGATE:
//
//	bytes="8f" -> 8f01859c   assert(NEGATE(x) === -5)  spends with x = 5
//	bytes=""   ->   01859c   assert(       x  === -5)  spends with x = -5
//
// Both scripts validate on the real @bsv/sdk `Spend` engine; they just accept
// different witnesses. The span silently degrades to the identity function and
// the declared contract semantics are not what gets locked on chain.
//
// The source path never reaches this shape — the validator already rejects it
// with "asm() body must be a non-empty hex string literal"
// (frontend/validator.go). `--ir` takes externally supplied IR and so needs
// the same rule enforced at its own trust boundary.

func TestValidateIR_RejectsEmptyRawScriptBody(t *testing.T) {
	cases := []struct {
		name     string
		inArity  int
		outArity int
	}{
		{"net stack effect -1", 2, 1},
		{"identity arity", 1, 1},
		{"pure producer", 0, 1},
		{"pure consumer", 1, 0},
		{"declares nothing", 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			program := &ANFProgram{
				ContractName: "RawSpan",
				Properties:   []ANFProperty{},
				Methods: []ANFMethod{
					{
						Name:     "unlock",
						IsPublic: true,
						Params: []ANFParam{
							{Name: "x", Type: "bigint"},
							{Name: "y", Type: "bigint"},
						},
						Body: []ANFBinding{
							{Name: "t0", Value: ANFValue{Kind: "load_param", Name: "x"}},
							{Name: "t1", Value: ANFValue{Kind: "load_param", Name: "y"}},
							{Name: "t2", Value: ANFValue{
								Kind:     "raw_script",
								Bytes:    "",
								InArity:  tc.inArity,
								OutArity: tc.outArity,
							}},
							{Name: "t3", Value: ANFValue{Kind: "assert", ValueRef: "t2"}},
						},
					},
				},
			}

			err := ValidateIR(program)
			if err == nil {
				t.Fatalf("expected ValidateIR to reject an empty raw_script body (in_arity=%d, out_arity=%d), got nil",
					tc.inArity, tc.outArity)
			}
			if !strings.Contains(err.Error(), "raw_script") {
				t.Errorf("error should name raw_script, got: %v", err)
			}
			if !strings.Contains(err.Error(), "empty") {
				t.Errorf("error should say the body is empty, got: %v", err)
			}
		})
	}
}

// The guard must fire on the real external-input entry point, not just on the
// exported validator: `--ir` reaches ValidateIR through LoadIRFromBytes.
func TestLoadIRFromBytes_RejectsEmptyRawScriptBody(t *testing.T) {
	irJSON := `{
		"contractName": "RawSpan",
		"properties": [],
		"methods": [
			{
				"name": "unlock",
				"isPublic": true,
				"params": [
					{"name": "x", "type": "bigint"},
					{"name": "y", "type": "bigint"}
				],
				"body": [
					{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
					{"name": "t1", "value": {"kind": "load_param", "name": "y"}},
					{"name": "t2", "value": {"kind": "raw_script", "bytes": "", "in_arity": 2, "out_arity": 1}},
					{"name": "t3", "value": {"kind": "assert", "value": "t2"}}
				]
			}
		]
	}`

	if _, err := LoadIRFromBytes([]byte(irJSON)); err == nil {
		t.Fatal("expected LoadIRFromBytes to reject IR carrying an empty raw_script body, got nil")
	}
}

// A raw_script node that omits "bytes" entirely decodes to the same empty
// string and must be rejected on the same grounds — an absent body is not a
// weaker claim than an explicitly empty one.
func TestLoadIRFromBytes_RejectsMissingRawScriptBody(t *testing.T) {
	irJSON := `{
		"contractName": "RawSpan",
		"properties": [],
		"methods": [
			{
				"name": "unlock",
				"isPublic": true,
				"params": [{"name": "x", "type": "bigint"}],
				"body": [
					{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
					{"name": "t1", "value": {"kind": "raw_script", "in_arity": 1, "out_arity": 1}},
					{"name": "t2", "value": {"kind": "assert", "value": "t1"}}
				]
			}
		]
	}`

	if _, err := LoadIRFromBytes([]byte(irJSON)); err == nil {
		t.Fatal("expected LoadIRFromBytes to reject IR whose raw_script omits \"bytes\", got nil")
	}
}

// Control: a raw_script span that actually carries bytes stays accepted, and
// so does one nested inside an `if` arm — the guard must not over-reach.
func TestValidateIR_AcceptsNonEmptyRawScriptBody(t *testing.T) {
	program := &ANFProgram{
		ContractName: "RawSpan",
		Properties:   []ANFProperty{},
		Methods: []ANFMethod{
			{
				Name:     "unlock",
				IsPublic: true,
				Params: []ANFParam{
					{Name: "x", Type: "bigint"},
					{Name: "y", Type: "bigint"},
				},
				Body: []ANFBinding{
					{Name: "t0", Value: ANFValue{Kind: "load_param", Name: "x"}},
					{Name: "t1", Value: ANFValue{Kind: "load_param", Name: "y"}},
					{Name: "t2", Value: ANFValue{
						Kind:     "raw_script",
						Bytes:    "93", // OP_ADD
						InArity:  2,
						OutArity: 1,
					}},
					{Name: "t3", Value: ANFValue{Kind: "assert", ValueRef: "t2"}},
				},
			},
		},
	}

	if err := ValidateIR(program); err != nil {
		t.Fatalf("non-empty raw_script body must stay accepted, got: %v", err)
	}
}

// Nested bindings are validated recursively, so an empty span hidden in an
// `if` arm or a `loop` body must be caught too.
func TestValidateIR_RejectsEmptyRawScriptBodyInNestedArms(t *testing.T) {
	empty := ANFBinding{Name: "n0", Value: ANFValue{
		Kind: "raw_script", Bytes: "", InArity: 1, OutArity: 1,
	}}

	nested := map[string]ANFValue{
		"if-then": {Kind: "if", Cond: "c", Then: []ANFBinding{empty}},
		"if-else": {Kind: "if", Cond: "c", Else: []ANFBinding{empty}},
		"loop":    {Kind: "loop", Count: 2, Body: []ANFBinding{empty}},
	}

	for name, value := range nested {
		t.Run(name, func(t *testing.T) {
			program := &ANFProgram{
				ContractName: "RawSpan",
				Properties:   []ANFProperty{},
				Methods: []ANFMethod{
					{
						Name:     "unlock",
						IsPublic: true,
						Body:     []ANFBinding{{Name: "t0", Value: value}},
					},
				},
			}
			if err := ValidateIR(program); err == nil {
				t.Fatalf("expected an empty raw_script body nested in %s to be rejected, got nil", name)
			}
		})
	}
}
