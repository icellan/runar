package frontend

import (
	"strings"
	"testing"
)

// R-246 (CL-GAP-084), the Go half.
//
// validatePropertyType refuses any CustomType and accepts a PrimitiveType whose
// name is not in validPropTypes — unless it is spelled "void":
//
//	case PrimitiveType:
//		if !validPropTypes[t.Name] {
//			if t.Name == "void" { ...error... }   // and nothing else
//		}
//
// One property, two spellings of the same unknown name, two answers. The finding
// was filed against the Python tier; ts, ruby and this one share it verbatim,
// while rust, java and zig already refuse both.
//
// No parser produces a PrimitiveType with an unknown name today — they all map
// an unrecognised name to CustomType — but Validate takes an AST, and the
// frontend is not the only thing that builds one.

func r246Contract(t TypeNode) *ContractNode {
	loc := SourceLocation{File: "Probe.runar.ts", Line: 1, Column: 1}
	return &ContractNode{
		Name:        "Probe",
		ParentClass: "SmartContract",
		Properties: []PropertyNode{
			{Name: "p", Type: t, Readonly: true, SourceLocation: loc},
		},
		Constructor: MethodNode{Name: "constructor", SourceLocation: loc},
		SourceFile:  "Probe.runar.ts",
	}
}

// Only the diagnostics about the property's TYPE: a minimal hand-built contract
// trips other rules, and filtering keeps this about the branch it is named for.
func r246TypeErrors(t TypeNode) []string {
	res := Validate(r246Contract(t))
	var out []string
	for _, e := range res.Errors {
		if strings.Contains(strings.ToLower(e.Message), "type") {
			out = append(out, e.Message)
		}
	}
	return out
}

func TestR246_ValidPrimitiveIsAccepted(t *testing.T) {
	// Control: without it, "refuse everything" passes every case below.
	if errs := r246TypeErrors(PrimitiveType{Name: "bigint"}); len(errs) != 0 {
		t.Fatalf("a valid primitive was refused: %v", errs)
	}
}

func TestR246_UnknownCustomTypeIsRefused(t *testing.T) {
	errs := r246TypeErrors(CustomType{Name: "Foobarium"})
	if !strings.Contains(strings.Join(errs, "\n"), "Foobarium") {
		t.Fatalf("the half that already worked no longer does: %v", errs)
	}
}

func TestR246_VoidIsRefused(t *testing.T) {
	errs := r246TypeErrors(PrimitiveType{Name: "void"})
	if !strings.Contains(strings.Join(errs, "\n"), "void") {
		t.Fatalf("void was accepted: %v", errs)
	}
}

func TestR246_UnknownPrimitiveIsRefusedToo(t *testing.T) {
	errs := r246TypeErrors(PrimitiveType{Name: "Foobarium"})
	if !strings.Contains(strings.Join(errs, "\n"), "Foobarium") {
		t.Fatalf("an unknown PrimitiveType passed validation while the identical "+
			"name as a CustomType is refused: %v", errs)
	}
}

func TestR246_ReachesFixedArrayElementType(t *testing.T) {
	errs := r246TypeErrors(FixedArrayType{Element: PrimitiveType{Name: "Foobarium"}, Length: 3})
	if !strings.Contains(strings.Join(errs, "\n"), "Foobarium") {
		t.Fatalf("FixedArray<Foobarium, 3> was accepted: %v", errs)
	}
}

func TestR246_ValidFixedArrayStillAccepted(t *testing.T) {
	errs := r246TypeErrors(FixedArrayType{Element: PrimitiveType{Name: "bigint"}, Length: 3})
	if len(errs) != 0 {
		t.Fatalf("a valid FixedArray was refused: %v", errs)
	}
}
