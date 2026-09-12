package ir

import (
	"strings"
	"testing"
)

// R-081: IR with no public method compiles to an EMPTY locking script, and an
// empty locking script is anyone-can-spend.
//
// This is not a validation nit. Measured against the real @bsv/sdk `Spend`
// engine with full consensus wrappers (push-only unlocking script, clean
// stack, minimal push):
//
//	lockingScript = ""   unlockingScript = 51 (OP_1)   -> validate() == true
//	lockingScript = ""   unlockingScript = 0101        -> validate() == true
//
// A one-byte witness any observer can construct spends the output. Before this
// guard, `runar-compiler-go --ir <no-public-methods>.json` exited 0 and emitted
// a complete, well-formed artifact whose `"script"` field was the empty string
// — directly loadable by all seven deployment SDKs.
//
// The source path already rejects this shape ("Contract 'X' has no public
// methods — no spending entry points; add 'public' to at least one method",
// frontend/validator.go). ValidateIR is only reachable from LoadIRFromBytes,
// i.e. exactly the `--ir` external-input path, so this is the same rule
// enforced at the trust boundary the source validator does not cover.

func TestValidateIR_RejectsNoPublicMethods(t *testing.T) {
	cases := []struct {
		name    string
		methods []ANFMethod
	}{
		{
			name:    "no methods at all",
			methods: []ANFMethod{},
		},
		{
			name:    "nil methods",
			methods: nil,
		},
		{
			name: "private methods only",
			methods: []ANFMethod{
				{Name: "helper", IsPublic: false, Body: []ANFBinding{
					{Name: "t0", Value: ANFValue{Kind: "load_const"}},
				}},
			},
		},
		{
			name: "constructor only",
			methods: []ANFMethod{
				{Name: "constructor", IsPublic: false, Params: []ANFParam{
					{Name: "a", Type: "bigint"},
				}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			program := &ANFProgram{
				ContractName: "NoEntryPoint",
				Properties:   []ANFProperty{},
				Methods:      tc.methods,
			}

			err := ValidateIR(program)
			if err == nil {
				t.Fatal("expected ValidateIR to reject IR with no public method, got nil")
			}
			if !strings.Contains(err.Error(), "NoEntryPoint") {
				t.Errorf("error should name the contract, got: %v", err)
			}
			if !strings.Contains(err.Error(), "public") {
				t.Errorf("error should point at the missing public method, got: %v", err)
			}
		})
	}
}

// The guard must fire on the real external-input entry point. This is the exact
// IR that produced `{"script": "", "asm": ""}` with exit code 0.
func TestLoadIRFromBytes_RejectsNoPublicMethods(t *testing.T) {
	for name, irJSON := range map[string]string{
		"empty methods array": `{
			"contractName": "Empty",
			"properties": [],
			"methods": []
		}`,
		"private only": `{
			"contractName": "PrivOnly",
			"properties": [],
			"methods": [
				{
					"name": "helper",
					"isPublic": false,
					"params": [],
					"body": [
						{"name": "t0", "value": {"kind": "load_const", "value": true}}
					]
				}
			]
		}`,
		"isPublic omitted defaults to private": `{
			"contractName": "DefaultPrivate",
			"properties": [],
			"methods": [
				{
					"name": "helper",
					"params": [],
					"body": [
						{"name": "t0", "value": {"kind": "load_const", "value": true}}
					]
				}
			]
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadIRFromBytes([]byte(irJSON)); err == nil {
				t.Fatal("expected LoadIRFromBytes to reject IR with no spending entry point, got nil")
			}
		})
	}
}

// Control: a single public method alongside any number of private ones is a
// real contract and must stay accepted.
func TestValidateIR_AcceptsAtLeastOnePublicMethod(t *testing.T) {
	program := &ANFProgram{
		ContractName: "HasEntryPoint",
		Properties:   []ANFProperty{},
		Methods: []ANFMethod{
			{Name: "constructor", IsPublic: false},
			{Name: "helper", IsPublic: false},
			{Name: "unlock", IsPublic: true, Body: []ANFBinding{
				{Name: "t0", Value: ANFValue{Kind: "load_const"}},
				{Name: "t1", Value: ANFValue{Kind: "assert", ValueRef: "t0"}},
			}},
		},
	}

	if err := ValidateIR(program); err != nil {
		t.Fatalf("IR carrying a public method must stay accepted, got: %v", err)
	}
}

// The new check must not mask the pre-existing structural diagnostics: a
// program that is both entry-point-less AND structurally broken should still
// report the structural fault, because that is the more actionable error.
func TestValidateIR_StructuralErrorsStillReportedFirst(t *testing.T) {
	program := &ANFProgram{
		ContractName: "Broken",
		Properties:   []ANFProperty{{Name: "x", Type: ""}},
		Methods:      []ANFMethod{},
	}

	err := ValidateIR(program)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "property") {
		t.Errorf("the empty-property-type diagnostic must survive, got: %v", err)
	}
}
