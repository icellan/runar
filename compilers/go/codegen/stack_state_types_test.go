package codegen

// Regression coverage for the Go codegen's `deserialize_state` allowlist.
//
// The validator at `compilers/go/frontend/validator.go` permits 14 property
// types (bigint, boolean, ByteString, PubKey, Sig, Sha256, Ripemd160, Addr,
// SigHashPreimage, RabinSig, RabinPubKey, Point, P256Point, P384Point). The
// stack-lowering pass historically only covered 7 of those (bigint, boolean,
// PubKey, Addr, Sha256, Point, ByteString) and would panic — surfaced via
// `LowerToStack`'s deferred recover as `stack lowering failed:
// deserialize_state: unsupported type: ...` — for any stateful contract whose
// mutable property used one of the remaining seven.
//
// This file mirrors the Rust fix in commit e879e58
// (`compilers/rust/tests/compiler_tests.rs::test_deserialize_state_ripemd160_
// codegens_cleanly`) but exercises every type family that previously fell
// through:
//
//   * Fixed-length byte types: Ripemd160 (20), P256Point (64), P384Point (96)
//   * Numeric bigint-aliases:  RabinSig, RabinPubKey (both 8 bytes via BIN2NUM)
//   * Variable-length types:   Sig, SigHashPreimage (push-data-prefix decoded
//                              exactly like ByteString)
//
// Each subtest builds a minimal stateful ANF program in-place (one mutable
// property of the type under test plus a single public `update` method whose
// body consists of just the compiler-injected
// `load_param(txPreimage) -> check_preimage -> deserialize_state` prelude)
// and runs it through `LowerToStack`. A clean error return asserts the
// type is now handled; failure surfaces the captured panic message.

import (
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// buildStatefulDeserializeProgram constructs the smallest ANF program that
// drives `lowerDeserializeState` for the given state-property type. The
// method body mirrors what `frontend/anf_lower.go` injects at the top of
// every public method of a StatefulSmartContract.
func buildStatefulDeserializeProgram(propType string) *ir.ANFProgram {
	assertT1, _ := marshalString("t1")
	return &ir.ANFProgram{
		ContractName: "StateTypeProbe",
		Properties: []ir.ANFProperty{
			{Name: "value", Type: propType, Readonly: false},
		},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{{Name: "value", Type: propType}},
				Body:     nil,
				IsPublic: false,
			},
			{
				Name: "update",
				Params: []ir.ANFParam{
					{Name: "txPreimage", Type: "SigHashPreimage"},
				},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "txPreimage"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "check_preimage", Preimage: "t0"}},
					{Name: "t2", Value: ir.ANFValue{Kind: "assert", RawValue: assertT1, ValueRef: "t1"}},
					{Name: "t3", Value: ir.ANFValue{Kind: "load_param", Name: "txPreimage"}},
					{Name: "t4", Value: ir.ANFValue{Kind: "deserialize_state", Preimage: "t3"}},
				},
				IsPublic: true,
			},
		},
	}
}

// TestLowerToStack_DeserializeState_AllStateTypes asserts every validator-
// permitted state-property type survives stack lowering without panicking.
// Pre-fix this file failed for all subtests except bigint / boolean / PubKey
// / Addr / Sha256 / Point / ByteString (the 7 legacy entries).
func TestLowerToStack_DeserializeState_AllStateTypes(t *testing.T) {
	cases := []struct {
		name     string
		propType string
	}{
		// Fixed-length byte buffers — newly covered in this fix.
		{name: "Ripemd160", propType: "Ripemd160"},
		{name: "P256Point", propType: "P256Point"},
		{name: "P384Point", propType: "P384Point"},

		// Numeric bigint aliases — newly covered in this fix.
		{name: "RabinSig", propType: "RabinSig"},
		{name: "RabinPubKey", propType: "RabinPubKey"},

		// Variable-length byte buffers — newly covered in this fix.
		{name: "Sig", propType: "Sig"},
		{name: "SigHashPreimage", propType: "SigHashPreimage"},

		// Already-supported types pinned here so the allowlist can't
		// narrow in a future refactor without tripping this test.
		{name: "bigint", propType: "bigint"},
		{name: "boolean", propType: "boolean"},
		{name: "PubKey", propType: "PubKey"},
		{name: "Addr", propType: "Addr"},
		{name: "Sha256", propType: "Sha256"},
		{name: "Point", propType: "Point"},
		{name: "ByteString", propType: "ByteString"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			program := buildStatefulDeserializeProgram(tc.propType)

			methods, err := LowerToStack(program)
			if err != nil {
				// Surface the specific codegen message so regressions
				// point at the deserialize_state switch rather than
				// generic "stack lowering failed".
				if strings.Contains(err.Error(), "deserialize_state: unsupported type") {
					t.Fatalf("deserialize_state allowlist missing %q: %v", tc.propType, err)
				}
				t.Fatalf("LowerToStack(%q) failed: %v", tc.propType, err)
			}

			// Sanity: the update method should have lowered.
			var found bool
			for _, m := range methods {
				if m.Name == "update" {
					found = true
					if len(m.Ops) == 0 {
						t.Fatalf("update method for %q produced no stack ops", tc.propType)
					}
					break
				}
			}
			if !found {
				t.Fatalf("update method missing from lowered program for %q", tc.propType)
			}
		})
	}
}
