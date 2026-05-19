// Package frontend — regression test for F-003: every ANF-kind dispatch
// in the Go ANF-lowering / constant-fold / DCE passes must reject an
// unknown kind with a typed *ir.UnknownANFKindError, instead of
// silently returning the value unchanged / dropping refs / defaulting
// to "no side effect".
//
// Each test drives one dispatch site with a synthetic ANFValue whose
// `Kind` does not appear in the ANFValue schema, then asserts the
// resulting panic carries the typed error with the synthetic kind name.
package frontend

import (
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

const syntheticFrontendKind = "synthetic_test_kind_for_regression_only"

func syntheticFrontendValue() ir.ANFValue {
	return ir.ANFValue{Kind: syntheticFrontendKind}
}

// recoverFrontendUnknownKind runs fn and recovers a panic. It fails the
// test if the panic value was not *ir.UnknownANFKindError.
func recoverFrontendUnknownKind(t *testing.T, fn func()) *ir.UnknownANFKindError {
	t.Helper()
	var caught *ir.UnknownANFKindError
	func() {
		defer func() {
			if r := recover(); r != nil {
				if e, ok := r.(*ir.UnknownANFKindError); ok {
					caught = e
					return
				}
				t.Fatalf("expected *ir.UnknownANFKindError panic, got %T: %v", r, r)
			}
		}()
		fn()
	}()
	return caught
}

func TestUnknownANFKind_ConstantFold_FoldValue(t *testing.T) {
	v := syntheticFrontendValue()
	env := newConstEnv()
	err := recoverFrontendUnknownKind(t, func() {
		_ = foldValue(&v, env)
	})
	if err == nil {
		t.Fatal("expected foldValue panic for unknown kind")
	}
	if err.Kind != syntheticFrontendKind {
		t.Errorf("expected kind %q, got %q", syntheticFrontendKind, err.Kind)
	}
	if err.Location != "constant-fold.foldValue" {
		t.Errorf("expected location constant-fold.foldValue, got %q", err.Location)
	}
}

func TestUnknownANFKind_AnfLower_RemapValueRefs(t *testing.T) {
	v := syntheticFrontendValue()
	err := recoverFrontendUnknownKind(t, func() {
		_ = remapValueRefs(v, map[string]string{})
	})
	if err == nil {
		t.Fatal("expected remapValueRefs panic for unknown kind")
	}
	if err.Kind != syntheticFrontendKind {
		t.Errorf("expected kind %q, got %q", syntheticFrontendKind, err.Kind)
	}
	if err.Location != "anf-lower.remapValueRefs" {
		t.Errorf("expected location anf-lower.remapValueRefs, got %q", err.Location)
	}
}

func TestUnknownANFKind_AnfLower_IsSideEffectFree(t *testing.T) {
	v := syntheticFrontendValue()
	err := recoverFrontendUnknownKind(t, func() {
		_ = isSideEffectFree(&v)
	})
	if err == nil {
		t.Fatal("expected isSideEffectFree panic for unknown kind")
	}
	if err.Kind != syntheticFrontendKind {
		t.Errorf("expected kind %q, got %q", syntheticFrontendKind, err.Kind)
	}
	if err.Location != "anf-lower.isSideEffectFree" {
		t.Errorf("expected location anf-lower.isSideEffectFree, got %q", err.Location)
	}
}

func TestUnknownANFKind_AnfOptimize_CollectValueRefs(t *testing.T) {
	v := syntheticFrontendValue()
	refs := map[string]bool{}
	err := recoverFrontendUnknownKind(t, func() {
		collectValueRefs(&v, refs)
	})
	if err == nil {
		t.Fatal("expected collectValueRefs panic for unknown kind")
	}
	if err.Kind != syntheticFrontendKind {
		t.Errorf("expected kind %q, got %q", syntheticFrontendKind, err.Kind)
	}
	if err.Location != "anf-optimize.collectValueRefs" {
		t.Errorf("expected location anf-optimize.collectValueRefs, got %q", err.Location)
	}
}

func TestUnknownANFKind_AnfOptimize_HasSideEffect(t *testing.T) {
	v := syntheticFrontendValue()
	err := recoverFrontendUnknownKind(t, func() {
		_ = hasSideEffect(&v)
	})
	if err == nil {
		t.Fatal("expected hasSideEffect panic for unknown kind")
	}
	if err.Kind != syntheticFrontendKind {
		t.Errorf("expected kind %q, got %q", syntheticFrontendKind, err.Kind)
	}
	if err.Location != "anf-optimize.hasSideEffect" {
		t.Errorf("expected location anf-optimize.hasSideEffect, got %q", err.Location)
	}
}

func TestUnknownANFKind_AnfOptimize_EliminateDeadBindings(t *testing.T) {
	// Drive DCE end-to-end with a synthetic-kind binding in the body.
	// The first dispatch in eliminateDeadBindings is collectAllRefs ->
	// collectValueRefs, so we expect that location to fire first.
	method := &ir.ANFMethod{
		Name:     "m",
		Params:   nil,
		IsPublic: true,
		Body: []ir.ANFBinding{
			{Name: "t0", Value: syntheticFrontendValue()},
		},
	}
	err := recoverFrontendUnknownKind(t, func() {
		eliminateDeadBindings(method)
	})
	if err == nil {
		t.Fatal("expected eliminateDeadBindings panic for unknown kind")
	}
	if err.Kind != syntheticFrontendKind {
		t.Errorf("expected kind %q, got %q", syntheticFrontendKind, err.Kind)
	}
	// Either collectValueRefs or hasSideEffect can be the first to fire.
	switch err.Location {
	case "anf-optimize.collectValueRefs", "anf-optimize.hasSideEffect":
	default:
		t.Errorf("expected anf-optimize.{collectValueRefs,hasSideEffect}, got %q", err.Location)
	}
}

func TestUnknownANFKind_FoldConstants_TopLevel(t *testing.T) {
	// Drive constant-fold end-to-end. foldValue is called per binding,
	// so the synthetic kind should reach the default branch.
	program := &ir.ANFProgram{
		ContractName: "T",
		Methods: []ir.ANFMethod{
			{
				Name:     "m",
				Params:   nil,
				IsPublic: true,
				Body: []ir.ANFBinding{
					{Name: "t0", Value: syntheticFrontendValue()},
				},
			},
		},
	}
	err := recoverFrontendUnknownKind(t, func() {
		_ = FoldConstants(program)
	})
	if err == nil {
		t.Fatal("expected FoldConstants panic for unknown kind")
	}
	if err.Kind != syntheticFrontendKind {
		t.Errorf("expected kind %q, got %q", syntheticFrontendKind, err.Kind)
	}
	if !strings.Contains(err.Location, "constant-fold") {
		t.Errorf("expected constant-fold location, got %q", err.Location)
	}
}
