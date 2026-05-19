// Package codegen — regression test for F-003: every ANF-kind dispatch
// in the Go stack-lowering codegen must reject an unknown kind with a
// typed *ir.UnknownANFKindError, instead of silently returning empty
// refs / emitting no stack ops.
//
// Each test drives one dispatch site with a synthetic ANFValue whose
// `Kind` does not appear in the ANFValue schema, then asserts the
// resulting panic carries the typed error with the synthetic kind name.
//
// If a new ANFValue variant is added in the future, the dispatch sites
// below must be updated; this test guards against silently shipping an
// unhandled variant.
package codegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

const syntheticKind = "synthetic_test_kind_for_regression_only"

func syntheticANFValue() *ir.ANFValue {
	return &ir.ANFValue{Kind: syntheticKind}
}

// recoverUnknownKind runs fn and recovers a panic. It returns the typed
// error if the panic value was *ir.UnknownANFKindError, otherwise nil.
func recoverUnknownKind(t *testing.T, fn func()) *ir.UnknownANFKindError {
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

func TestUnknownANFKind_Stack_CollectRefs(t *testing.T) {
	err := recoverUnknownKind(t, func() {
		_ = collectRefs(syntheticANFValue())
	})
	if err == nil {
		t.Fatal("expected panic with *ir.UnknownANFKindError, got none")
	}
	if err.Kind != syntheticKind {
		t.Errorf("expected kind %q, got %q", syntheticKind, err.Kind)
	}
	if err.Location != "stack.collectRefs" {
		t.Errorf("expected location stack.collectRefs, got %q", err.Location)
	}
}

func TestUnknownANFKind_Stack_LowerBinding_ViaLowerToStack(t *testing.T) {
	// LowerToStack wraps panics in a returned error via fmt.Errorf("...: %v", r),
	// so the typed error surfaces through its Error() method on the wrapped value.
	program := &ir.ANFProgram{
		ContractName: "T",
		Methods: []ir.ANFMethod{
			{
				Name:     "m",
				Params:   nil,
				IsPublic: true,
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: syntheticKind}},
				},
			},
		},
	}
	_, err := LowerToStack(program)
	if err == nil {
		t.Fatal("expected LowerToStack to return an error for an unknown kind")
	}
	if !strings.Contains(err.Error(), syntheticKind) {
		t.Errorf("expected error to contain synthetic kind %q, got %q", syntheticKind, err.Error())
	}
	// Either collectRefs (computeLastUses runs first) or lowerBinding can fire.
	if !strings.Contains(err.Error(), "stack.collectRefs") &&
		!strings.Contains(err.Error(), "stack.lowerBinding") {
		t.Errorf("expected stack.collectRefs or stack.lowerBinding in error, got %q", err.Error())
	}
}

func TestUnknownANFKindError_MessageMentionsRecipe(t *testing.T) {
	e := &ir.UnknownANFKindError{Kind: syntheticKind, Location: "unit-test.location"}
	msg := e.Error()
	if !strings.Contains(msg, syntheticKind) {
		t.Errorf("expected message to contain kind, got %q", msg)
	}
	if !strings.Contains(msg, "unit-test.location") {
		t.Errorf("expected message to contain location, got %q", msg)
	}
	if !strings.Contains(msg, "Adding a New ANF Value Kind") {
		t.Errorf("expected message to point at CLAUDE.md recipe, got %q", msg)
	}
	// The type should be usable as a standard error.
	var target *ir.UnknownANFKindError
	if !errors.As(error(e), &target) {
		t.Errorf("errors.As did not match *ir.UnknownANFKindError")
	}
}
