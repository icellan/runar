// Package codegen — regression tests for CL-BUG-127 / R-013.
//
// Two stack-lowering sites resolved a compile-time constant by narrowing
// a *big.Int to int with `int(v.Int64())` and only THEN range-checking
// the result. Because big.Int.Int64() truncates modulo 2^64 rather than
// failing, every one of those range checks was bypassable: a caller who
// wrote depth = 2^64+8 got the 8-level Merkle codegen, and a caller who
// wrote index = 2^64+2 got public input slot 2 — silently, with the
// range check reporting "in range" on a value the source never named.
//
// These tests drive both sites with synthetic ANF and assert a
// diagnostic. The controls prove the in-range values still lower.
package codegen

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// constBinding builds a load_const ANF binding carrying an arbitrary
// *big.Int — the shape stack lowering records in ctx.constValues.
func constBinding(name string, v *big.Int) ir.ANFBinding {
	raw, _ := json.Marshal(v.String() + "n")
	return ir.ANFBinding{
		Name:  name,
		Value: ir.ANFValue{Kind: "load_const", RawValue: raw, ConstBigInt: new(big.Int).Set(v)},
	}
}

// merkleProgram builds a one-method contract that calls
// merkleRootSha256(leaf, proof, index, depth) with the given depth
// constant. The proof/leaf/index operands are method params so only the
// depth constant is under test.
func merkleProgram(depth *big.Int) *ir.ANFProgram {
	body := []ir.ANFBinding{
		{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "leaf"}},
		{Name: "t1", Value: ir.ANFValue{Kind: "load_param", Name: "proof"}},
		{Name: "t2", Value: ir.ANFValue{Kind: "load_param", Name: "idx"}},
		constBinding("t3", depth),
		{Name: "t4", Value: ir.ANFValue{Kind: "call", Func: "merkleRootSha256", Args: []string{"t0", "t1", "t2", "t3"}}},
		{Name: "t5", Value: ir.ANFValue{Kind: "load_param", Name: "root"}},
		{Name: "t6", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t4", Right: "t5", ResultType: "bytes"}},
		{Name: "t7", Value: ir.ANFValue{Kind: "assert", ValueRef: "t6"}},
	}
	return &ir.ANFProgram{
		ContractName: "MerkleDepth",
		Methods: []ir.ANFMethod{{
			Name:     "unlock",
			IsPublic: true,
			Params: []ir.ANFParam{
				{Name: "leaf", Type: "ByteString"},
				{Name: "proof", Type: "ByteString"},
				{Name: "idx", Type: "bigint"},
				{Name: "root", Type: "ByteString"},
			},
			Body: body,
		}},
	}
}

func TestMerkleDepth_InRangeControl_StillLowers(t *testing.T) {
	if _, err := LowerToStack(merkleProgram(big.NewInt(8))); err != nil {
		t.Fatalf("depth 8 must still lower, got %v", err)
	}
}

// TestMerkleDepth_ModularWrapIsRejected: 2^64+8 truncates to 8, so the
// `depth < 1 || depth > 64` guard passed and the compiler emitted the
// 8-level codegen for a depth the contract never asked for.
func TestMerkleDepth_ModularWrapIsRejected(t *testing.T) {
	depth := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(8))
	_, err := LowerToStack(merkleProgram(depth))
	if err == nil {
		t.Fatal("expected a diagnostic for a Merkle depth of 2^64+8, got a clean lowering")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "depth") {
		t.Errorf("expected the diagnostic to name the depth argument, got %v", err)
	}
}

// TestMerkleDepth_SignFlipIsRejected: 2^63 truncates to MinInt64, which
// the `< 1` guard does catch — but only by luck of the wrap landing
// negative. Assert it is rejected with a range diagnostic either way.
func TestMerkleDepth_SignFlipIsRejected(t *testing.T) {
	depth := new(big.Int).Lsh(big.NewInt(1), 63)
	if _, err := LowerToStack(merkleProgram(depth)); err == nil {
		t.Fatal("expected a diagnostic for a Merkle depth of 2^63, got a clean lowering")
	}
}

// groth16Program builds a method calling groth16PublicInput(idx). The
// call is expected to fail before it needs the _pub_<n> stack slots when
// the index is out of range; the in-range control therefore asserts on
// WHICH error is reported, not on success.
func groth16Program(idx *big.Int) *ir.ANFProgram {
	body := []ir.ANFBinding{
		constBinding("t0", idx),
		{Name: "t1", Value: ir.ANFValue{Kind: "call", Func: "groth16PublicInput", Args: []string{"t0"}}},
		{Name: "t2", Value: ir.ANFValue{Kind: "load_param", Name: "expected"}},
		{Name: "t3", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t1", Right: "t2"}},
		{Name: "t4", Value: ir.ANFValue{Kind: "assert", ValueRef: "t3"}},
	}
	return &ir.ANFProgram{
		ContractName: "Groth16Index",
		Methods: []ir.ANFMethod{{
			Name:     "unlock",
			IsPublic: true,
			Params:   []ir.ANFParam{{Name: "expected", Type: "bigint"}},
			Body:     body,
		}},
	}
}

// TestGroth16PublicInput_InRangeControl: index 2 is in [0, 4], so the
// range check must pass and lowering must get as far as looking for the
// _pub_2 stack slot (absent in this synthetic program). Any *range*
// complaint here would mean the new guard rejects a legal index.
func TestGroth16PublicInput_InRangeControl(t *testing.T) {
	_, err := LowerToStack(groth16Program(big.NewInt(2)))
	if err == nil {
		t.Fatal("synthetic program has no _pub_2 slot; expected the slot diagnostic")
	}
	if !strings.Contains(err.Error(), "_pub_2") {
		t.Fatalf("index 2 must pass the range check and fail on the missing slot, got %v", err)
	}
}

// TestGroth16PublicInput_ModularWrapIsRejected: 2^64+2 truncates to 2,
// so `idx < 0 || idx > 4` passed and the compiler picked public-input
// slot 2 for an index the contract never named.
func TestGroth16PublicInput_ModularWrapIsRejected(t *testing.T) {
	idx := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(2))
	_, err := LowerToStack(groth16Program(idx))
	if err == nil {
		t.Fatal("expected a diagnostic for a groth16PublicInput index of 2^64+2, got a clean lowering")
	}
	if strings.Contains(err.Error(), "_pub_2") {
		t.Fatalf("index 2^64+2 was silently narrowed to slot 2: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "index") {
		t.Errorf("expected the diagnostic to name the index argument, got %v", err)
	}
}
