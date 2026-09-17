package codegen

import (
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// R-158 / CL-BUG-113: Groth16-WA preamble selection used to scan only
// TOP-LEVEL ANF bindings. A marker inside an `if` arm or loop body silently
// selected the unsound (no-preamble) variant — the same class as
// methodUsesCheckPreimageRec before it started walking branches.
//
// These tests drive the shipped scanner, not a copy.

func markerCall(name, fn string) ir.ANFBinding {
	return ir.ANFBinding{
		Name:  name,
		Value: ir.ANFValue{Kind: "call", Func: fn, Args: []string{}},
	}
}

func TestMethodUsesGroth16WAPreamble_TopLevel(t *testing.T) {
	body := []ir.ANFBinding{
		markerCall("t0", "assertGroth16WitnessAssisted"),
	}
	if !methodUsesGroth16WAPreamble(body) {
		t.Fatal("top-level assertGroth16WitnessAssisted must select the preamble")
	}
}

func TestMethodUsesGroth16WAPreamble_InsideIfThen(t *testing.T) {
	body := []ir.ANFBinding{
		{
			Name: "t0",
			Value: ir.ANFValue{
				Kind: "if",
				Cond: "flag",
				Then: []ir.ANFBinding{markerCall("t1", "assertGroth16WitnessAssisted")},
			},
		},
	}
	if !methodUsesGroth16WAPreamble(body) {
		t.Fatal("marker inside if-then must select the preamble; top-level-only scan is R-158")
	}
}

func TestMethodUsesGroth16WAPreamble_InsideLoop(t *testing.T) {
	body := []ir.ANFBinding{
		{
			Name: "t0",
			Value: ir.ANFValue{
				Kind:  "loop",
				Count: 1,
				Body:  []ir.ANFBinding{markerCall("t1", "assertGroth16WitnessAssistedWithMSM")},
			},
		},
	}
	if !methodUsesGroth16WAPreamble(body) {
		t.Fatal("marker inside loop body must select the preamble")
	}
	if !methodUsesGroth16WAPreambleWithMSM(body) {
		t.Fatal("MSM marker inside loop body must select the MSM preamble")
	}
}

func TestMethodUsesGroth16WAPreamble_Absent(t *testing.T) {
	body := []ir.ANFBinding{
		{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "x"}},
	}
	if methodUsesGroth16WAPreamble(body) {
		t.Fatal("no marker must not select the preamble")
	}
}
