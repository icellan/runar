package frontend

import (
	"testing"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/ir"
)

// Regression tests for CL-BUG-015 / R-030 (residual N-014).
//
// `collectValueRefs` in dce.go carried two deliberate silent fall-throughs:
//
//	case "deserialize_state":  // preimage ref NOT collected
//	case "array_literal":      // element refs NOT collected
//
// The TypeScript reference (packages/runar-compiler/src/optimizer/dce.ts,
// collectRefsFromValue) collects both, and codegen/stack.go reads both
// (lowerDeserializeState(value.Preimage), lowerArrayLiteral(value.Elements),
// and collectRefs' `refs = append(refs, value.Elements...)`).
//
// Consequence — the identical dangling-SSA-reference shape R-004 hit:
//   - `deserialize_state` is retained by HasSideEffect, but the binding that
//     produces its preimage is pure, so DCE deletes the producer out from
//     under a surviving consumer.
//   - `array_literal` is pure, but survives whenever a consumer (checkMultiSig)
//     references it; its element producers are then deleted while the consumer
//     still pulls each element to TOS.
//
// Both end the same way: `stack lowering failed: value %q not found on stack`.
//
// These tests drive the real DCE pass (EliminateDeadCode) and the real
// production DCE driver (OptimizeEC -> optimizeMethodEC -> EliminateDeadBindings
// — DCE only runs after an EC rule fires), and assert the surviving operands
// reach emitted Stack IR rather than only checking the predicate. Every test
// carries a negative control: a genuinely pure unreferenced binding must still
// be eliminated, so the fix cannot be satisfied by retaining everything.

// ---------------------------------------------------------------------------
// Local builders
// ---------------------------------------------------------------------------

func deserializeStateBinding(name, preimage string) ir.ANFBinding {
	return ir.ANFBinding{
		Name:  name,
		Value: ir.ANFValue{Kind: "deserialize_state", Preimage: preimage},
	}
}

func arrayLiteralBinding(name string, elements []string) ir.ANFBinding {
	return ir.ANFBinding{
		Name:  name,
		Value: ir.ANFValue{Kind: "array_literal", Elements: elements},
	}
}

// withParams declares the method parameters that the body's load_param
// bindings name. Required only by the tests that call LowerToStack: an
// undeclared parameter is not on the stack map, which the lowering pass
// rejects for its own (unrelated) reason.
func withParams(prog *ir.ANFProgram, params ...ir.ANFParam) *ir.ANFProgram {
	prog.Methods[0].Params = params
	return prog
}

// makeStatefulTestProgram is makeTestProgram plus one mutable property, which
// lowerDeserializeState requires — with zero non-readonly properties it returns
// before it ever touches the preimage ref, making the test vacuous.
func makeStatefulTestProgram(bindings []ir.ANFBinding) *ir.ANFProgram {
	prog := makeTestProgram(bindings)
	prog.Properties = []ir.ANFProperty{
		{Name: "count", Type: "bigint", Readonly: false},
	}
	return prog
}

// ecTrigger returns the two bindings that arm the EC optimizer. `ecMul(p, 1)`
// fires the ec-mul-one rule, which is what makes optimizeMethodEC call
// EliminateDeadBindings at all.
func ecTrigger(pointRef string) []ir.ANFBinding {
	return []ir.ANFBinding{
		loadConstBigInt("one", 1),
		callBinding("q", "ecMul", []string{pointRef, "one"}),
	}
}

func assertECRuleFired(t *testing.T, body []ir.ANFBinding) {
	t.Helper()
	for _, b := range body {
		if b.Name == "q" && b.Value.Kind == "call" {
			t.Fatal("ec-mul-one did not fire — OptimizeEC never invoked DCE, test is vacuous")
		}
	}
}

// ---------------------------------------------------------------------------
// 1. deserialize_state — the preimage producer must survive DCE.
// ---------------------------------------------------------------------------

// deserializeStateBody: "pre" is read ONLY by the deserialize_state binding.
// "ds" itself is retained by HasSideEffect, so if the preimage ref goes
// uncollected the consumer outlives its producer.
func deserializeStateBody(extra ...ir.ANFBinding) []ir.ANFBinding {
	body := append([]ir.ANFBinding{}, extra...)
	return append(body,
		loadParamBinding("pre", "txPreimage"),
		deserializeStateBinding("ds", "pre"),
		// Negative control: pure, unreferenced — MUST be eliminated.
		binOpBinding("pureDead", "+", "point", "point"),
	)
}

func assertDeserializeStateOperandSurvives(t *testing.T, body []ir.ANFBinding) {
	t.Helper()
	names := dceBindingNameSet(body)

	if !names["ds"] {
		t.Fatal("DCE deleted the deserialize_state binding \"ds\" — HasSideEffect regression")
	}
	if !names["pre"] {
		t.Error("DCE deleted \"pre\", the preimage producer of a surviving " +
			"deserialize_state — stack lowering resolves a binding that no longer exists")
	}
	if names["pureDead"] {
		t.Error("negative control failed: pure unreferenced bin_op \"pureDead\" survived " +
			"DCE — the fix must not retain everything")
	}
}

func TestEliminateDeadCode_RetainsDeserializeStatePreimage(t *testing.T) {
	prog := makeStatefulTestProgram(append(
		[]ir.ANFBinding{loadParamBinding("point", "point")},
		deserializeStateBody()...,
	))
	EliminateDeadCode(prog)
	assertDeserializeStateOperandSurvives(t, prog.Methods[0].Body)
}

// The production driver: DCE runs only from optimizeMethodEC, after an EC rule
// fires. This is the exact path a real compile takes.
func TestOptimizeEC_RetainsDeserializeStatePreimage(t *testing.T) {
	body := []ir.ANFBinding{loadParamBinding("point", "point")}
	body = append(body, ecTrigger("point")...)
	body = append(body, deserializeStateBody()...)

	prog := makeStatefulTestProgram(body)
	OptimizeEC(prog)

	assertECRuleFired(t, prog.Methods[0].Body)
	assertDeserializeStateOperandSurvives(t, prog.Methods[0].Body)
}

// The surviving deserialize_state must still lower. lowerDeserializeState
// bringToTop's the preimage ref; a deleted producer panics with
// `value "pre" not found on stack`, surfaced as a LowerToStack error.
func TestOptimizeEC_DeserializeStateReachesEmittedScript(t *testing.T) {
	body := []ir.ANFBinding{loadParamBinding("point", "point")}
	body = append(body, ecTrigger("point")...)
	body = append(body,
		loadParamBinding("pre", "txPreimage"),
		deserializeStateBinding("ds", "pre"),
	)

	prog := withParams(makeStatefulTestProgram(body),
		ir.ANFParam{Name: "point", Type: "Point"},
		ir.ANFParam{Name: "txPreimage", Type: "SigHashPreimage"},
	)
	OptimizeEC(prog)
	assertECRuleFired(t, prog.Methods[0].Body)

	if _, err := codegen.LowerToStack(prog); err != nil {
		t.Fatalf("LowerToStack: %v — the deserialize_state preimage producer was "+
			"eliminated by DCE, leaving a dangling SSA reference", err)
	}
}

// ---------------------------------------------------------------------------
// 2. array_literal — the element producers must survive DCE.
// ---------------------------------------------------------------------------

// arrayLiteralBody: "sig0" / "pk0" are read ONLY through the array_literal
// bindings. The arrays themselves are pure but survive because the
// checkMultiSig call (effectful, and it references them) keeps them live.
func arrayLiteralBody(extra ...ir.ANFBinding) []ir.ANFBinding {
	body := append([]ir.ANFBinding{}, extra...)
	return append(body,
		loadParamBinding("sig0", "sig0"),
		loadParamBinding("pk0", "pk0"),
		arrayLiteralBinding("sigs", []string{"sig0"}),
		arrayLiteralBinding("pks", []string{"pk0"}),
		callBinding("ms", "checkMultiSig", []string{"sigs", "pks"}),
		// Negative control: pure, unreferenced — MUST be eliminated.
		binOpBinding("pureDead", "+", "point", "point"),
	)
}

func assertArrayLiteralElementsSurvive(t *testing.T, body []ir.ANFBinding) {
	t.Helper()
	names := dceBindingNameSet(body)

	for _, arr := range []string{"sigs", "pks"} {
		if !names[arr] {
			t.Fatalf("DCE deleted array_literal %q even though checkMultiSig references it", arr)
		}
	}
	for _, elem := range []string{"sig0", "pk0"} {
		if !names[elem] {
			t.Errorf("DCE deleted %q, an element producer of a surviving array_literal — "+
				"lowerCheckMultiSig pulls each element to TOS and would dangle", elem)
		}
	}
	if names["pureDead"] {
		t.Error("negative control failed: pure unreferenced bin_op \"pureDead\" survived " +
			"DCE — the fix must not retain everything")
	}
}

func TestEliminateDeadCode_RetainsArrayLiteralElements(t *testing.T) {
	prog := makeTestProgram(append(
		[]ir.ANFBinding{loadParamBinding("point", "point")},
		arrayLiteralBody()...,
	))
	EliminateDeadCode(prog)
	assertArrayLiteralElementsSurvive(t, prog.Methods[0].Body)
}

func TestOptimizeEC_RetainsArrayLiteralElements(t *testing.T) {
	body := []ir.ANFBinding{loadParamBinding("point", "point")}
	body = append(body, ecTrigger("point")...)
	body = append(body, arrayLiteralBody()...)

	prog := makeTestProgram(body)
	OptimizeEC(prog)

	assertECRuleFired(t, prog.Methods[0].Body)
	assertArrayLiteralElementsSurvive(t, prog.Methods[0].Body)
}

// The surviving checkMultiSig must still lower: lowerCheckMultiSig bringToTop's
// every element, so a deleted element producer panics with
// `value "sig0" not found on stack`.
func TestOptimizeEC_ArrayLiteralElementsReachEmittedScript(t *testing.T) {
	body := []ir.ANFBinding{loadParamBinding("point", "point")}
	body = append(body, ecTrigger("point")...)
	// The elements are load_const bindings, NOT load_param: a parameter
	// occupies a stack slot under its own name whether or not its load_param
	// binding survives, so bringToTop would resolve it anyway and the test
	// would pass vacuously. A const has no slot but its own binding.
	body = append(body,
		loadConstHex("sig0", "3044022000000000000000000000000000000000000000000000000000000000000000"),
		loadConstHex("pk0", "02000000000000000000000000000000000000000000000000000000000000000000"),
		arrayLiteralBinding("sigs", []string{"sig0"}),
		arrayLiteralBinding("pks", []string{"pk0"}),
		callBinding("ms", "checkMultiSig", []string{"sigs", "pks"}),
	)

	prog := withParams(makeTestProgram(body),
		ir.ANFParam{Name: "point", Type: "Point"},
	)
	OptimizeEC(prog)
	assertECRuleFired(t, prog.Methods[0].Body)

	methods, err := codegen.LowerToStack(prog)
	if err != nil {
		t.Fatalf("LowerToStack: %v — an array_literal element producer was eliminated "+
			"by DCE, leaving a dangling SSA reference", err)
	}
	found := false
	for _, m := range methods {
		for _, op := range m.Ops {
			if op.Code == "OP_CHECKMULTISIG" {
				found = true
			}
		}
	}
	if !found {
		t.Error("emitted Stack IR contains no OP_CHECKMULTISIG")
	}
}

// ---------------------------------------------------------------------------
// 3. Operand-ref parity with the TypeScript reference
//    (packages/runar-compiler/src/optimizer/dce.ts::collectRefsFromValue).
// ---------------------------------------------------------------------------

func TestCollectValueRefs_MatchesTypeScriptReference(t *testing.T) {
	cases := []struct {
		name  string
		value ir.ANFValue
		want  []string
	}{
		{
			name:  "deserialize_state collects preimage",
			value: ir.ANFValue{Kind: "deserialize_state", Preimage: "pre"},
			want:  []string{"pre"},
		},
		{
			name:  "array_literal collects elements",
			value: ir.ANFValue{Kind: "array_literal", Elements: []string{"e0", "e1"}},
			want:  []string{"e0", "e1"},
		},
		{
			// Latent: both frontends emit add_output with preimage="", but
			// the --ir path deserializes the field and codegen reads it.
			name: "add_output collects preimage",
			value: ir.ANFValue{
				Kind: "add_output", Satoshis: "sats",
				StateValues: []string{"sv0"}, Preimage: "pre",
			},
			want: []string{"sats", "sv0", "pre"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refs := make(map[string]bool)
			collectValueRefs(&tc.value, refs)
			for _, w := range tc.want {
				if !refs[w] {
					t.Errorf("collectValueRefs did not collect %q; got %v", w, refs)
				}
			}
			if len(refs) != len(tc.want) {
				t.Errorf("collectValueRefs collected %v, want exactly %v", refs, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scope of these tests
//
// PROVES:
//   - collectValueRefs collects deserialize_state's preimage ref and
//     array_literal's element refs, matching the TypeScript reference.
//   - Those operand producers survive both EliminateDeadCode and the
//     production OptimizeEC -> EliminateDeadBindings driver.
//   - The surviving consumers still lower to Stack IR, so no dangling SSA
//     reference reaches codegen.
//   - DCE still deletes genuinely pure unreferenced bindings.
//
// DOES NOT PROVE:
//   - Cross-tier byte parity. That is the conformance suite's job; the native
//     Go golden harness (compilers/go/conformance_goldens_test.go) covers the
//     Go half and passes unchanged.
//   - Anything about the Rust / Python / Zig / Ruby / Java DCE passes.
// ---------------------------------------------------------------------------
