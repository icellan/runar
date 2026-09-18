package frontend

import (
	"testing"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/ir"
)

// Regression tests for CL-BUG-013 / R-004.
//
// The Go DCE pass classified `add_raw_output`, `add_data_output`, `call` and
// `method_call` as effect-free, so an unreferenced binding of any of those
// kinds was silently deleted. The TypeScript reference
// (packages/runar-compiler/src/optimizer/dce.ts, hasSideEffect) puts all four
// in the side-effecting arm. Consequences: an author-written output can be
// dropped from the emitted script (fund-loss class defect for a covenant) and
// Go diverges from every other tier.
//
// These tests drive the real DCE pass (EliminateDeadCode) and the real
// production DCE driver (OptimizeEC -> optimizeMethodEC -> EliminateDeadBindings),
// not the HasSideEffect predicate in isolation. Every test carries a negative
// control: a genuinely pure unreferenced binding must still be eliminated, so
// the fix cannot be satisfied by making HasSideEffect return true always.

// ---------------------------------------------------------------------------
// Local builders (the shared helpers live in anf_ec_optimizer_test.go)
// ---------------------------------------------------------------------------

func addRawOutputBinding(name, satoshis, scriptBytes string) ir.ANFBinding {
	return ir.ANFBinding{
		Name:  name,
		Value: ir.ANFValue{Kind: "add_raw_output", Satoshis: satoshis, ScriptBytes: scriptBytes},
	}
}

func addDataOutputBinding(name, satoshis, scriptBytes string) ir.ANFBinding {
	return ir.ANFBinding{
		Name:  name,
		Value: ir.ANFValue{Kind: "add_data_output", Satoshis: satoshis, ScriptBytes: scriptBytes},
	}
}

func methodCallBinding(name, object, method string, args []string) ir.ANFBinding {
	return ir.ANFBinding{
		Name:  name,
		Value: ir.ANFValue{Kind: "method_call", Object: object, Method: method, Args: args},
	}
}

func binOpBinding(name, op, left, right string) ir.ANFBinding {
	return ir.ANFBinding{
		Name:  name,
		Value: ir.ANFValue{Kind: "bin_op", Op: op, Left: left, Right: right},
	}
}

func dceBindingNameSet(body []ir.ANFBinding) map[string]bool {
	out := make(map[string]bool, len(body))
	for i := range body {
		out[body[i].Name] = true
	}
	return out
}

// effectfulKindsBody builds a method body in which every one of the four
// disputed kinds produces a binding that nothing downstream reads, plus a
// genuinely pure unreferenced binding as the negative control.
//
// `sats` / `script` are read ONLY by the add_raw_output / add_data_output
// bindings, so they also pin the operand-reference half of the contract: once
// those two kinds survive DCE, stack lowering (codegen/stack.go collectRefs)
// needs their operand producers, and dropping them would leave a dangling ref.
func effectfulKindsBody(extra ...ir.ANFBinding) []ir.ANFBinding {
	body := append([]ir.ANFBinding{}, extra...)
	return append(body,
		loadParamBinding("p", "p"),
		loadConstBigInt("sats", 1000),
		loadConstHex("script", "76a914000000000000000000000000000000000000000088ac"),
		addRawOutputBinding("raw", "sats", "script"),
		addDataOutputBinding("dat", "sats", "script"),
		callBinding("hcall", "myHelper", []string{"p"}),
		methodCallBinding("mcall", "p", "helper", []string{}),
		// Negative control: pure, unreferenced — MUST be eliminated.
		binOpBinding("pureDead", "+", "p", "p"),
	)
}

func assertEffectfulKindsSurvive(t *testing.T, body []ir.ANFBinding) {
	t.Helper()
	names := dceBindingNameSet(body)

	for _, want := range []struct{ name, kind string }{
		{"raw", "add_raw_output"},
		{"dat", "add_data_output"},
		{"hcall", "call"},
		{"mcall", "method_call"},
	} {
		if !names[want.name] {
			t.Errorf("DCE deleted unreferenced %s binding %q — the author-written "+
				"effect is silently dropped from the emitted script", want.kind, want.name)
		}
	}

	// Operand producers of the surviving outputs must stay live, otherwise
	// codegen/stack.go collectRefs resolves a deleted binding.
	for _, operand := range []string{"sats", "script"} {
		if !names[operand] {
			t.Errorf("DCE deleted %q, the operand producer of a surviving "+
				"add_raw_output/add_data_output — stack lowering would dangle", operand)
		}
	}

	// Negative control.
	if names["pureDead"] {
		t.Error("negative control failed: pure unreferenced bin_op \"pureDead\" survived " +
			"DCE — HasSideEffect must not be true unconditionally")
	}
}

// ---------------------------------------------------------------------------
// 1. Whole-program DCE pass
// ---------------------------------------------------------------------------

func TestEliminateDeadCode_RetainsEffectfulKinds(t *testing.T) {
	prog := makeTestProgram(effectfulKindsBody())
	EliminateDeadCode(prog)
	assertEffectfulKindsSurvive(t, prog.Methods[0].Body)
}

// ---------------------------------------------------------------------------
// 2. The production DCE driver: OptimizeEC runs EliminateDeadBindings on any
//    method in which an EC rule fired. `ecMul(p, 1)` fires ec-mul-one, so this
//    exercises the exact path a real compile takes.
// ---------------------------------------------------------------------------

func TestOptimizeEC_RetainsEffectfulKindsAfterECRewrite(t *testing.T) {
	prog := makeTestProgram(effectfulKindsBody(
		loadConstBigInt("one", 1),
		callBinding("q", "ecMul", []string{"p", "one"}),
	))
	// Note: "p" is declared after "q" in the body order produced by
	// effectfulKindsBody(extra...); reorder so the EC rule can resolve it.
	body := prog.Methods[0].Body
	reordered := []ir.ANFBinding{}
	for _, b := range body {
		if b.Name == "p" {
			reordered = append(reordered, b)
		}
	}
	for _, b := range body {
		if b.Name != "p" {
			reordered = append(reordered, b)
		}
	}
	prog.Methods[0].Body = reordered

	OptimizeEC(prog)

	if dceBindingNameSet(prog.Methods[0].Body)["q"] {
		// ec-mul-one rewrites q into an unreferenced @ref alias; if q is still
		// a live ecMul call the rule never fired and DCE never ran, which would
		// make this test vacuous.
		for _, b := range prog.Methods[0].Body {
			if b.Name == "q" && b.Value.Kind == "call" {
				t.Fatal("ec-mul-one did not fire — OptimizeEC never invoked DCE, test is vacuous")
			}
		}
	}
	assertEffectfulKindsSurvive(t, prog.Methods[0].Body)
}

// ---------------------------------------------------------------------------
// 3. The surviving add_raw_output must still reach the emitted script.
//    lowerAddRawOutput is the only thing in this program that emits
//    OP_NUM2BIN (it encodes the satoshi amount as 8-byte LE), so its presence
//    in the lowered Stack IR is a direct witness that the output survived all
//    the way to codegen.
// ---------------------------------------------------------------------------

func TestOptimizeEC_RawOutputReachesEmittedScript(t *testing.T) {
	prog := makeTestProgram([]ir.ANFBinding{
		loadParamBinding("p", "p"),
		loadConstBigInt("one", 1),
		callBinding("q", "ecMul", []string{"p", "one"}),
		loadConstBigInt("sats", 1000),
		loadConstHex("script", "76a914000000000000000000000000000000000000000088ac"),
		addRawOutputBinding("raw", "sats", "script"),
	})
	OptimizeEC(prog)

	methods, err := codegen.LowerToStack(prog)
	if err != nil {
		t.Fatalf("LowerToStack: %v", err)
	}
	found := false
	for _, m := range methods {
		for _, op := range m.Ops {
			if op.Code == "OP_NUM2BIN" {
				found = true
			}
		}
	}
	if !found {
		t.Error("emitted Stack IR contains no OP_NUM2BIN: the addRawOutput the " +
			"author wrote was dropped from the script by DCE")
	}
}

// ---------------------------------------------------------------------------
// 4. Standalone negative control: DCE must still delete pure dead code.
// ---------------------------------------------------------------------------

func TestEliminateDeadCode_StillEliminatesPureDeadCode(t *testing.T) {
	prog := makeTestProgram([]ir.ANFBinding{
		loadParamBinding("p", "p"),
		loadConstBigInt("k", 7),
		binOpBinding("deadA", "+", "p", "k"),
		binOpBinding("deadB", "*", "p", "p"),
		assertBinding("a", "p"),
	})
	EliminateDeadCode(prog)
	names := dceBindingNameSet(prog.Methods[0].Body)
	for _, dead := range []string{"deadA", "deadB", "k"} {
		if names[dead] {
			t.Errorf("pure unreferenced binding %q survived DCE", dead)
		}
	}
	if !names["a"] {
		t.Error("assert binding was eliminated")
	}
}

// ---------------------------------------------------------------------------
// 5. Predicate parity with the TypeScript reference
//    (packages/runar-compiler/src/optimizer/dce.ts::hasSideEffect).
// ---------------------------------------------------------------------------

func TestHasSideEffect_MatchesTypeScriptReference(t *testing.T) {
	effectful := []string{
		"assert", "update_prop", "check_preimage", "deserialize_state",
		"add_output", "add_raw_output", "add_data_output", "call",
		"method_call", "raw_script",
	}
	pure := []string{
		"load_param", "load_prop", "load_const", "get_state_script",
		"bin_op", "unary_op", "if", "loop", "array_literal",
	}
	for _, kind := range effectful {
		if !HasSideEffect(&ir.ANFValue{Kind: kind}) {
			t.Errorf("HasSideEffect(%q) = false, TypeScript reference says true", kind)
		}
	}
	for _, kind := range pure {
		if HasSideEffect(&ir.ANFValue{Kind: kind}) {
			t.Errorf("HasSideEffect(%q) = true, TypeScript reference says false", kind)
		}
	}
}

// ---------------------------------------------------------------------------
// Scope of these tests
//
// PROVES:
//   - The Go DCE pass (EliminateDeadCode, and EliminateDeadBindings as driven
//     by the production OptimizeEC path) no longer deletes an unreferenced
//     add_raw_output / add_data_output / call / method_call binding.
//   - The operand producers of a surviving add_raw_output / add_data_output
//     stay live, so codegen/stack.go collectRefs cannot resolve a deleted
//     binding.
//   - A surviving add_raw_output still reaches the emitted Stack IR.
//   - DCE still deletes genuinely pure unreferenced bindings, so the fix is
//     not "HasSideEffect always returns true".
//   - HasSideEffect's classification now matches the TypeScript reference
//     in packages/runar-compiler/src/optimizer/dce.ts.
//
// DOES NOT PROVE:
//   - Cross-tier byte parity. That is the conformance suite's job; the native
//     Go golden harness (compilers/go/conformance_goldens_test.go) covers the
//     Go half and passes unchanged.
//   - That every OTHER pre-existing fall-through in collectValueRefs is
//     correct. `deserialize_state` (preimage ref) and `array_literal`
//     (element refs) are still silently uncollected in Go while the TS
//     reference collects both — untouched here, reported separately.
//   - Anything about the Rust / Python / Zig / Ruby / Java DCE passes.
