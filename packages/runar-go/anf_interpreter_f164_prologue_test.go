package runar

// ---------------------------------------------------------------------------
// F-164 (round 2): ExecuteStrict must mock the WHOLE auto-injected stateful
// prologue (checkPreimage's assert AND the sighash-type assert), not just
// developer asserts. See packages/runar-sdk/src/anf-interpreter.ts for the
// TS reference this ports (anfDetectAutoInjectedPrologueAsserts mirrors
// detectAutoInjectedPrologueAsserts there).
//
// Round 1 of F-164 fixed the `check_preimage` ANF-node kind to mock-return
// true in strict mode. That alone is NOT enough: the compiler's prologue
// also emits a SECOND, un-marked assert right after — the sighash-type
// check (`assert(extractSigHashType(txPreimage) === <mode>)`) — and
// `extractSigHashType` has no real/mock value off-chain (a separate,
// pre-existing, documented gap: anf_interpreter.go's "A-3" equivalent).
// Before round 2, a strict-mode call against a REAL compiled stateful
// method would get past checkPreimage only to throw at the sighash-type
// assert instead — never reaching the method's actual body.
// ---------------------------------------------------------------------------

import "testing"

// f164LoadTxPreimage builds the `load_param txPreimage` binding the
// prologue reads twice (once for checkPreimage, once for extractSigHashType).
func f164LoadTxPreimage(name string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "load_param", "name": "txPreimage",
	}}
}

func f164CheckPreimage(name, preimageRef string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "check_preimage", "preimage": preimageRef,
	}}
}

func f164ExtractSigHashCall(name, preimageRef string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "call", "func": "extractSigHashType", "args": []interface{}{preimageRef},
	}}
}

func f164BinOpEq(name, left, right string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "bin_op", "op": "===", "left": left, "right": right,
	}}
}

// f164FullPrologueProgram builds the exact 8-binding prologue
// `compilers/go/frontend/anf_lower.go` emits at the start of every public
// stateful method (mirrors compiled conformance/tests/stateful-counter
// expected-ir.json: t0-t7), followed by whatever userBody bindings the
// caller supplies.
func f164FullPrologueProgram(userBody []ANFBinding) *ANFProgram {
	body := []ANFBinding{
		f164LoadTxPreimage("t0"),
		f164CheckPreimage("t1", "t0"),
		sbAssert("t2", "t1"),
		f164LoadTxPreimage("t3"),
		f164ExtractSigHashCall("t4", "t3"),
		sbConst("t5", "65"),
		f164BinOpEq("t6", "t4", "t5"),
		sbAssert("t7", "t6"),
	}
	body = append(body, userBody...)
	return &ANFProgram{
		ContractName: "Counter",
		Properties:   []ANFProperty{{Name: "count", Type: "bigint", Readonly: false}},
		Methods: []ANFMethod{{
			Name:     "increment",
			IsPublic: true,
			Params:   []ANFParam{{Name: "txPreimage", Type: "SigHashPreimage"}},
			Body:     body,
		}},
	}
}

// TestExecuteStrict_MocksWholeAutoInjectedPrologue is the failing-test-first
// proof for F-164 round 2: a real compiled stateful method's prologue
// (checkPreimage assert + sighash-type assert) must not abort strict mode;
// the method's real body result must come through.
func TestExecuteStrict_MocksWholeAutoInjectedPrologue(t *testing.T) {
	anf := f164FullPrologueProgram([]ANFBinding{
		{Name: "t8", Value: map[string]interface{}{"kind": "load_prop", "name": "count"}},
		sbConst("t9", "1"),
		sbBin("t10", "+", "t8", "t9"),
		sbUpd("t11", "count", "t10"),
	})

	state, _, _, err := ExecuteStrict(anf, "increment", map[string]interface{}{"count": int64(0)}, map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("ExecuteStrict returned error, want success: %v", err)
	}
	got := anfToBigInt(state["count"]).Int64()
	if got != 1 {
		t.Errorf("state[count] = %d, want 1", got)
	}
}

// TestExecuteStrict_UserAssertAfterPrologueStillEnforced proves the
// structural detector is anchored to the FIXED prologue position
// (indices 0-7) — a user-written assert that ALSO calls
// extractSigHashType, placed AFTER the prologue, remains fully enforced.
func TestExecuteStrict_UserAssertAfterPrologueStillEnforced(t *testing.T) {
	anf := f164FullPrologueProgram([]ANFBinding{
		f164LoadTxPreimage("u0"),
		f164ExtractSigHashCall("u1", "u0"),
		sbConst("u2", "1"), // wrong expected mode (real mode is 65)
		f164BinOpEq("u3", "u1", "u2"),
		sbAssert("userAssert", "u3"),
		{Name: "t8", Value: map[string]interface{}{"kind": "load_prop", "name": "count"}},
		sbConst("t9", "1"),
		sbBin("t10", "+", "t8", "t9"),
		sbUpd("t11", "count", "t10"),
	})

	_, _, _, err := ExecuteStrict(anf, "increment", map[string]interface{}{"count": int64(0)}, map[string]interface{}{}, nil)
	af, ok := err.(*AssertionFailureError)
	if !ok {
		t.Fatalf("err = %v (%T), want *AssertionFailureError", err, err)
	}
	if af.BindingName != "userAssert" {
		t.Errorf("BindingName = %q, want %q (mocking must not reach past the prologue)", af.BindingName, "userAssert")
	}
}
