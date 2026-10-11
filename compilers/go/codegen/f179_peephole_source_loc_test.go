package codegen

// F-179 — Go peephole rewrites and the rebuilt nested `if` must keep a
// SourceLoc on the ops they emit.
//
// Before the fix every replacement op built by matchWindow2/3/4
// (PUSH 1 + OP_ADD -> OP_1ADD, OP_EQUAL + OP_VERIFY -> OP_EQUALVERIFY, the
// constant folds, ...) was a fresh StackOp literal with a nil SourceLoc, and
// optimizeNestedIf rebuilt each `if` op from Op/Then/Else only. The emitter
// only records a mapping for an op that still has a SourceLoc, so those
// opcodes got no source-map entry.
//
// Convention (same as the TS tier after F-224, and the Python / Rust tiers):
// a replacement op with no location of its own inherits the location of the
// FIRST op of the matched window.
//
// What this proves: fused / rewritten ops (including both ops of a 2-op
// replacement and a rebuilt `if`) carry the head op's location through
// OptimizeStackOps, and ops that had no location stay without one.
//
// What this does not prove: anything about the emitted source map (see
// compiler/f179_source_map_optimized_ops_test.go), nor that the head
// location is the most precise choice, nor the other tiers' optimizers.

import (
	"reflect"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

var (
	f179LocA = &ir.SourceLocation{File: "C.runar.ts", Line: 10, Column: 4}
	f179LocB = &ir.SourceLocation{File: "C.runar.ts", Line: 20, Column: 8}
)

func f179At(op StackOp, loc *ir.SourceLocation) StackOp {
	op.SourceLoc = loc
	return op
}

func TestF179_Push1Add_Fused_KeepsHeadSourceLoc(t *testing.T) {
	ops := []StackOp{
		f179At(pushBigIntOp(1), f179LocA),
		f179At(opcodeOp("OP_ADD"), f179LocB),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 || result[0].Code != "OP_1ADD" {
		t.Fatalf("expected a single OP_1ADD, got %+v", result)
	}
	if !reflect.DeepEqual(result[0].SourceLoc, f179LocA) {
		t.Errorf("OP_1ADD SourceLoc = %+v, want head location %+v", result[0].SourceLoc, f179LocA)
	}
}

func TestF179_EqualVerify_Fused_KeepsHeadSourceLoc(t *testing.T) {
	ops := []StackOp{
		f179At(opcodeOp("OP_EQUAL"), f179LocA),
		f179At(opcodeOp("OP_VERIFY"), f179LocB),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 || result[0].Code != "OP_EQUALVERIFY" {
		t.Fatalf("expected a single OP_EQUALVERIFY, got %+v", result)
	}
	if !reflect.DeepEqual(result[0].SourceLoc, f179LocA) {
		t.Errorf("OP_EQUALVERIFY SourceLoc = %+v, want %+v", result[0].SourceLoc, f179LocA)
	}
}

func TestF179_ChainFold_TwoOpReplacement_BothKeepHeadSourceLoc(t *testing.T) {
	ops := []StackOp{
		f179At(pushBigIntOp(3), f179LocA),
		f179At(opcodeOp("OP_ADD"), f179LocA),
		f179At(pushBigIntOp(4), f179LocB),
		f179At(opcodeOp("OP_ADD"), f179LocB),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 || result[0].Op != "push" || result[0].Value.BigInt.Int64() != 7 || result[1].Code != "OP_ADD" {
		t.Fatalf("expected [PUSH 7, OP_ADD], got %+v", result)
	}
	for i, op := range result {
		if !reflect.DeepEqual(op.SourceLoc, f179LocA) {
			t.Errorf("result[%d] SourceLoc = %+v, want %+v", i, op.SourceLoc, f179LocA)
		}
	}
}

func TestF179_NestedIf_Rebuilt_KeepsOwnSourceLoc(t *testing.T) {
	ops := []StackOp{{
		Op: "if",
		Then: []StackOp{
			f179At(opcodeOp("OP_EQUAL"), f179LocB),
			f179At(opcodeOp("OP_VERIFY"), f179LocB),
		},
		SourceLoc: f179LocA,
	}}
	result := OptimizeStackOps(ops)
	if len(result) != 1 || result[0].Op != "if" {
		t.Fatalf("expected a single if op, got %+v", result)
	}
	if !reflect.DeepEqual(result[0].SourceLoc, f179LocA) {
		t.Errorf("rebuilt if SourceLoc = %+v, want %+v", result[0].SourceLoc, f179LocA)
	}
	if len(result[0].Then) != 1 || result[0].Then[0].Code != "OP_EQUALVERIFY" ||
		!reflect.DeepEqual(result[0].Then[0].SourceLoc, f179LocB) {
		t.Errorf("then branch = %+v, want [OP_EQUALVERIFY @ %+v]", result[0].Then, f179LocB)
	}
}

func TestF179_NoSourceLoc_StaysNil(t *testing.T) {
	result := OptimizeStackOps([]StackOp{opcodeOp("OP_EQUAL"), opcodeOp("OP_VERIFY")})
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %+v", result)
	}
	if result[0].SourceLoc != nil {
		t.Errorf("SourceLoc = %+v, want nil", result[0].SourceLoc)
	}
}
