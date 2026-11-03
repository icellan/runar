package runar

// N-223 — out-of-range constructorSlots paramIndex.
//
// The constructor only checks len(constructorArgs) == len(abi.constructor.params)
// (see NewRunarContract) -- it never cross-checks that every ConstructorSlot's
// ParamIndex actually falls within that range. Before this fix, every
// `c.constructorArgs[slot.ParamIndex]` read in sdk_contract.go (buildCodeScript,
// adjustCodeSepOffset, resolvedCodeSepSlotValues) indexed the slice directly: a
// malformed or hostile artifact's out-of-range ParamIndex crashed GetLockingScript
// with a raw Go "index out of range" panic instead of a named error (this item's
// brief: "Go/Rust/Zig/Python crash with a raw index error").
//
// Parity target: TS N-081 / N-223 (packages/runar-sdk/src/__tests__/constructor-slots.test.ts).

import (
	"strings"
	"testing"
)

func panicMessage(t *testing.T, f func()) string {
	t.Helper()
	r := recoverFrom(f)
	if r == nil {
		t.Fatal("expected a panic, got none")
	}
	switch v := r.(type) {
	case error:
		return v.Error()
	case string:
		return v
	default:
		return ""
	}
}

func recoverFrom(f func()) (result interface{}) {
	defer func() {
		result = recover()
	}()
	f()
	return nil
}

func TestN223_BuildCodeScriptRefusesOutOfRangeParamIndex(t *testing.T) {
	// Exactly 1 constructor arg below (matching the 1 ABI param), but the
	// slot references ParamIndex 1 -- out of range.
	art := &RunarArtifact{
		Version:      "runar-v0.1.0",
		ContractName: "Test",
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{{Name: "threshold", Type: "bigint"}}},
			Methods:     []ABIMethod{{Name: "check", Params: []ABIParam{}, IsPublic: true}},
		},
		Script:           "009c69", // OP_0(slot) OP_NUMEQUAL OP_VERIFY
		ConstructorSlots: []ConstructorSlot{{ParamIndex: 1, ByteOffset: 0}},
	}
	c := NewRunarContract(art, []interface{}{int64(1000)})

	msg := panicMessage(t, func() { _ = c.GetLockingScript() })
	if !strings.Contains(strings.ToLower(msg), "paramindex") {
		t.Fatalf("panic must name paramIndex, got: %q", msg)
	}
}

func TestN223_AdjustCodeSepOffsetRefusesOutOfRangeParamIndex_WithoutBuildCodeScript(t *testing.T) {
	// getCodeSepIndex falls straight to adjustCodeSepOffset when codeScript is
	// unset -- this never calls buildCodeScript at all, proving the gap the
	// primary-site fix alone does not cover.
	art := &RunarArtifact{
		Version:      "runar-v0.1.0",
		ContractName: "CodeSep",
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{{Name: "threshold", Type: "bigint"}}},
			Methods:     []ABIMethod{{Name: "check", Params: []ABIParam{}, IsPublic: true}},
		},
		Script:               "00ab9c69", // OP_0(slot) OP_CODESEPARATOR OP_NUMEQUAL OP_VERIFY
		ConstructorSlots:     []ConstructorSlot{{ParamIndex: 1, ByteOffset: 0}},
		CodeSeparatorIndex:   intPtr(2),
		CodeSeparatorIndices: []int{2},
	}
	c := NewRunarContract(art, []interface{}{int64(1000)})

	msg := panicMessage(t, func() { _ = c.getCodeSepIndex(0) })
	if !strings.Contains(strings.ToLower(msg), "paramindex") {
		t.Fatalf("panic must name paramIndex, got: %q", msg)
	}
}

func intPtr(n int) *int { return &n }
