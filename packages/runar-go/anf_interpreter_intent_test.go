package runar

// ---------------------------------------------------------------------------
// anf_interpreter_intent_test.go
//
// Go-tier port of the TS reference's intent-intrinsics interpreter coverage
// (`packages/runar-testing/src/__tests__/intent-intrinsics-interpreter.test.ts`).
//
// The TS test suite exercises the four shipping fixtures end-to-end through
// the AST interpreter, using TestContract.setPrevOutScript /
// setSerialisedOutputs / setMockPreimage / setMockPreimageBytes to feed
// witness bytes. The Go tier doesn't reuse the TS source files (no Go-side
// source-to-ANF lowering pass is wired in here); instead we hand-build
// minimal ANF programs that mirror each contract's body and prove the three
// new intrinsic handlers — extractPrevOutputScript, requireOutputP2PKH,
// currentBlockHeight — replay the same desugared semantics under the
// new InterpreterFixture API.
//
// 10 tests, one per TS `it(...)` block:
//   - intent-prev-output-script:    1 success + 2 failure (wrong hash, missing witness)
//   - intent-output-p2pkh:          1 success + 2 failure (wrong PKH bytes, wrong hashOutputs)
//   - intent-current-block-height:  1 success + 1 failure (locktime > deadline)
//   - branched-readonly-len:        1 then-branch + 1 else-branch
// ---------------------------------------------------------------------------

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func intentHash256(bytes []byte) []byte {
	a := sha256.Sum256(bytes)
	b := sha256.Sum256(a[:])
	out := make([]byte, 32)
	copy(out, b[:])
	return out
}

func intentFromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("intentFromHex: " + err.Error())
	}
	return b
}

// intentP2PKHOutput builds a canonical 34-byte P2PKH output:
// 8 LE amount ‖ 1976a914 ‖ pkh ‖ 88ac.
func intentP2PKHOutput(amount int64, pkh []byte) []byte {
	if len(pkh) != 20 {
		panic("pkh must be 20 bytes")
	}
	out := make([]byte, 34)
	a := amount
	for i := 0; i < 8; i++ {
		out[i] = byte(a & 0xff)
		a >>= 8
	}
	out[8], out[9], out[10], out[11] = 0x19, 0x76, 0xa9, 0x14
	copy(out[12:32], pkh)
	out[32], out[33] = 0x88, 0xac
	return out
}

// ---------------------------------------------------------------------------
// ANF program builders — one per TS contract.
//
// Each ANF program is hand-built to mirror the semantic body of the TS
// source, with implicit stateful params (txPreimage, _changePKH,
// _changeAmount) declared so the existing implicit-param filter in
// runMethod skips them.
// ---------------------------------------------------------------------------

func anfIntentPrevOutputScript() *ANFProgram {
	// public bind() {
	//   const s = extractPrevOutputScript(0n, this.expectedHash);
	//   assert(len(s) > 0n);
	//   this.count = this.count + 1n;
	// }
	return &ANFProgram{
		ContractName: "IntentPrevOutputScript",
		Properties: []ANFProperty{
			{Name: "expectedHash", Type: "ByteString", Readonly: true},
			{Name: "count", Type: "bigint", Readonly: false},
		},
		Methods: []ANFMethod{
			{Name: "constructor", IsPublic: false, Body: []ANFBinding{}},
			{
				Name:     "bind",
				IsPublic: true,
				Params: []ANFParam{
					{Name: "txPreimage", Type: "SigHashPreimage"},
					{Name: "_changePKH", Type: "Addr"},
					{Name: "_changeAmount", Type: "bigint"},
				},
				Body: []ANFBinding{
					// const s = extractPrevOutputScript(0n, this.expectedHash);
					{Name: "t_idx", Value: map[string]interface{}{"kind": "load_const", "value": float64(0)}},
					{Name: "t_exp", Value: map[string]interface{}{"kind": "load_prop", "name": "expectedHash"}},
					{Name: "t_s", Value: map[string]interface{}{
						"kind": "call",
						"func": "extractPrevOutputScript",
						"args": []interface{}{"t_idx", "t_exp"},
					}},
					// assert(len(s) > 0n);
					{Name: "t_len", Value: map[string]interface{}{
						"kind": "call",
						"func": "len",
						"args": []interface{}{"t_s"},
					}},
					{Name: "t_zero", Value: map[string]interface{}{"kind": "load_const", "value": float64(0)}},
					{Name: "t_gt", Value: map[string]interface{}{
						"kind": "bin_op", "op": ">", "left": "t_len", "right": "t_zero",
					}},
					{Name: "t_assert", Value: map[string]interface{}{"kind": "assert", "value": "t_gt"}},
					// this.count = this.count + 1n;
					{Name: "t_c", Value: map[string]interface{}{"kind": "load_prop", "name": "count"}},
					{Name: "t_one", Value: map[string]interface{}{"kind": "load_const", "value": float64(1)}},
					{Name: "t_sum", Value: map[string]interface{}{
						"kind": "bin_op", "op": "+", "left": "t_c", "right": "t_one", "resultType": "bigint",
					}},
					{Name: "t_upd", Value: map[string]interface{}{
						"kind": "update_prop", "name": "count", "value": "t_sum",
					}},
				},
			},
		},
	}
}

func anfIntentOutputP2PKH() *ANFProgram {
	// public payBond() {
	//   requireOutputP2PKH(0n, this.bondPKH, this.bondAmount);
	//   this.count = this.count + 1n;
	// }
	return &ANFProgram{
		ContractName: "IntentOutputP2PKH",
		Properties: []ANFProperty{
			{Name: "bondPKH", Type: "ByteString", Readonly: true},
			{Name: "bondAmount", Type: "bigint", Readonly: true},
			{Name: "count", Type: "bigint", Readonly: false},
		},
		Methods: []ANFMethod{
			{Name: "constructor", IsPublic: false, Body: []ANFBinding{}},
			{
				Name:     "payBond",
				IsPublic: true,
				Params: []ANFParam{
					{Name: "txPreimage", Type: "SigHashPreimage"},
					{Name: "_changePKH", Type: "Addr"},
					{Name: "_changeAmount", Type: "bigint"},
				},
				Body: []ANFBinding{
					{Name: "t_idx", Value: map[string]interface{}{"kind": "load_const", "value": float64(0)}},
					{Name: "t_pkh", Value: map[string]interface{}{"kind": "load_prop", "name": "bondPKH"}},
					{Name: "t_amt", Value: map[string]interface{}{"kind": "load_prop", "name": "bondAmount"}},
					{Name: "t_req", Value: map[string]interface{}{
						"kind": "call",
						"func": "requireOutputP2PKH",
						"args": []interface{}{"t_idx", "t_pkh", "t_amt"},
					}},
					// this.count = this.count + 1n;
					{Name: "t_c", Value: map[string]interface{}{"kind": "load_prop", "name": "count"}},
					{Name: "t_one", Value: map[string]interface{}{"kind": "load_const", "value": float64(1)}},
					{Name: "t_sum", Value: map[string]interface{}{
						"kind": "bin_op", "op": "+", "left": "t_c", "right": "t_one", "resultType": "bigint",
					}},
					{Name: "t_upd", Value: map[string]interface{}{
						"kind": "update_prop", "name": "count", "value": "t_sum",
					}},
				},
			},
		},
	}
}

func anfIntentCurrentBlockHeight() *ANFProgram {
	// public spend() {
	//   const h = currentBlockHeight();
	//   assert(h <= this.deadline);
	//   this.count = this.count + 1n;
	// }
	return &ANFProgram{
		ContractName: "IntentCurrentBlockHeight",
		Properties: []ANFProperty{
			{Name: "deadline", Type: "bigint", Readonly: true},
			{Name: "count", Type: "bigint", Readonly: false},
		},
		Methods: []ANFMethod{
			{Name: "constructor", IsPublic: false, Body: []ANFBinding{}},
			{
				Name:     "spend",
				IsPublic: true,
				Params: []ANFParam{
					{Name: "txPreimage", Type: "SigHashPreimage"},
					{Name: "_changePKH", Type: "Addr"},
					{Name: "_changeAmount", Type: "bigint"},
				},
				Body: []ANFBinding{
					{Name: "t_h", Value: map[string]interface{}{
						"kind": "call",
						"func": "currentBlockHeight",
						"args": []interface{}{},
					}},
					{Name: "t_d", Value: map[string]interface{}{"kind": "load_prop", "name": "deadline"}},
					{Name: "t_cmp", Value: map[string]interface{}{
						"kind": "bin_op", "op": "<=", "left": "t_h", "right": "t_d",
					}},
					{Name: "t_assert", Value: map[string]interface{}{"kind": "assert", "value": "t_cmp"}},
					{Name: "t_c", Value: map[string]interface{}{"kind": "load_prop", "name": "count"}},
					{Name: "t_one", Value: map[string]interface{}{"kind": "load_const", "value": float64(1)}},
					{Name: "t_sum", Value: map[string]interface{}{
						"kind": "bin_op", "op": "+", "left": "t_c", "right": "t_one", "resultType": "bigint",
					}},
					{Name: "t_upd", Value: map[string]interface{}{
						"kind": "update_prop", "name": "count", "value": "t_sum",
					}},
				},
			},
		},
	}
}

// bindingsToJSON converts a slice of ANFBindings into the []interface{}
// JSON shape that anfGetBindings (the interpreter's branch decoder) expects.
// Inline `then` / `else` / `body` arrays in hand-built ANF programs must use
// this shape, otherwise the decoder returns nil and the branch body is
// silently dropped.
func bindingsToJSON(bs []ANFBinding) []interface{} {
	out := make([]interface{}, len(bs))
	for i, b := range bs {
		out[i] = map[string]interface{}{
			"name":  b.Name,
			"value": b.Value,
		}
	}
	return out
}

func anfBranchedReadonlyLen() *ANFProgram {
	// public spend(scratch: ByteString) {
	//   if (len(scratch) > 0n) {
	//     this.count = this.count + 1n;
	//     this.tag = scratch;
	//   } else {
	//     this.count = this.count - 1n;
	//     this.tag = '3030';
	//   }
	//   this.addOutput(1000n, this.count, this.tag);
	// }
	thenBranch := []ANFBinding{
		{Name: "u_c", Value: map[string]interface{}{"kind": "load_prop", "name": "count"}},
		{Name: "u_one", Value: map[string]interface{}{"kind": "load_const", "value": float64(1)}},
		{Name: "u_sum", Value: map[string]interface{}{
			"kind": "bin_op", "op": "+", "left": "u_c", "right": "u_one", "resultType": "bigint",
		}},
		{Name: "u_upd_c", Value: map[string]interface{}{
			"kind": "update_prop", "name": "count", "value": "u_sum",
		}},
		{Name: "u_scratch_t", Value: map[string]interface{}{"kind": "load_param", "name": "scratch"}},
		{Name: "u_upd_tag", Value: map[string]interface{}{
			"kind": "update_prop", "name": "tag", "value": "u_scratch_t",
		}},
	}
	elseBranch := []ANFBinding{
		{Name: "e_c", Value: map[string]interface{}{"kind": "load_prop", "name": "count"}},
		{Name: "e_one", Value: map[string]interface{}{"kind": "load_const", "value": float64(1)}},
		{Name: "e_diff", Value: map[string]interface{}{
			"kind": "bin_op", "op": "-", "left": "e_c", "right": "e_one", "resultType": "bigint",
		}},
		{Name: "e_upd_c", Value: map[string]interface{}{
			"kind": "update_prop", "name": "count", "value": "e_diff",
		}},
		{Name: "e_tag_lit", Value: map[string]interface{}{"kind": "load_const", "value": "3030"}},
		{Name: "e_upd_tag", Value: map[string]interface{}{
			"kind": "update_prop", "name": "tag", "value": "e_tag_lit",
		}},
	}
	return &ANFProgram{
		ContractName: "BranchedReadonlyLen",
		Properties: []ANFProperty{
			{Name: "count", Type: "bigint", Readonly: false},
			{Name: "tag", Type: "ByteString", Readonly: false},
		},
		Methods: []ANFMethod{
			{Name: "constructor", IsPublic: false, Body: []ANFBinding{}},
			{
				Name:     "spend",
				IsPublic: true,
				Params: []ANFParam{
					{Name: "scratch", Type: "ByteString"},
					{Name: "txPreimage", Type: "SigHashPreimage"},
					{Name: "_changePKH", Type: "Addr"},
					{Name: "_changeAmount", Type: "bigint"},
				},
				Body: []ANFBinding{
					// len(scratch) > 0n
					{Name: "t_scratch", Value: map[string]interface{}{"kind": "load_param", "name": "scratch"}},
					{Name: "t_len", Value: map[string]interface{}{
						"kind": "call", "func": "len", "args": []interface{}{"t_scratch"},
					}},
					{Name: "t_zero", Value: map[string]interface{}{"kind": "load_const", "value": float64(0)}},
					{Name: "t_cond", Value: map[string]interface{}{
						"kind": "bin_op", "op": ">", "left": "t_len", "right": "t_zero",
					}},
					{Name: "t_if", Value: map[string]interface{}{
						"kind": "if", "cond": "t_cond",
						"then": bindingsToJSON(thenBranch),
						"else": bindingsToJSON(elseBranch),
					}},
					// this.addOutput(1000n, this.count, this.tag);
					//
					// We omit `stateValues` here: the state mutations already
					// happened inside the if/else branches via `update_prop`.
					// Passing valid binding refs would simply re-emit the same
					// values; the Go test verifies state, not output emission.
					{Name: "t_sats", Value: map[string]interface{}{"kind": "load_const", "value": float64(1000)}},
					{Name: "t_out", Value: map[string]interface{}{
						"kind": "add_output",
					}},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// intent-prev-output-script
// ---------------------------------------------------------------------------

func TestIntentInterpreter_PrevOutputScript_Success(t *testing.T) {
	prevOutScript := intentFromHex("76a91400112233445566778899aabbccddeeff0011223388ac")
	expectedHash := intentHash256(prevOutScript)

	anf := anfIntentPrevOutputScript()
	fix := NewInterpreterFixture()
	fix.SetPrevOutScript(0, prevOutScript)

	state, _, _, err := ExecuteStrictWithFixture(anf, "bind",
		map[string]interface{}{
			"expectedHash": hex.EncodeToString(expectedHash),
			"count":        big.NewInt(0),
		},
		nil, nil, fix)
	if err != nil {
		t.Fatalf("ExecuteStrictWithFixture: %v", err)
	}
	c, ok := state["count"].(*big.Int)
	if !ok || c.Int64() != 1 {
		t.Fatalf("expected count=1, got %v", state["count"])
	}
}

func TestIntentInterpreter_PrevOutputScript_WrongHash(t *testing.T) {
	prevOutScript := intentFromHex("76a91400112233445566778899aabbccddeeff0011223388ac")
	expectedHash := intentHash256(prevOutScript)

	anf := anfIntentPrevOutputScript()
	fix := NewInterpreterFixture()
	// Different bytes → different hash256.
	fix.SetPrevOutScript(0, intentFromHex("deadbeef"))

	_, _, _, err := ExecuteStrictWithFixture(anf, "bind",
		map[string]interface{}{
			"expectedHash": hex.EncodeToString(expectedHash),
			"count":        big.NewInt(0),
		},
		nil, nil, fix)
	if err == nil {
		t.Fatal("expected IntentIntrinsicError, got nil")
	}
	ie, ok := err.(*IntentIntrinsicError)
	if !ok {
		t.Fatalf("expected *IntentIntrinsicError, got %T: %v", err, err)
	}
	if ie.Intrinsic != "extractPrevOutputScript" {
		t.Errorf("Intrinsic: got %q", ie.Intrinsic)
	}
	if !strings.Contains(ie.Error(), "hash256") {
		t.Errorf("error must mention hash256, got %q", ie.Error())
	}
}

func TestIntentInterpreter_PrevOutputScript_MissingWitness(t *testing.T) {
	prevOutScript := intentFromHex("76a91400112233445566778899aabbccddeeff0011223388ac")
	expectedHash := intentHash256(prevOutScript)

	anf := anfIntentPrevOutputScript()
	// Intentionally do not call SetPrevOutScript.
	fix := NewInterpreterFixture()

	_, _, _, err := ExecuteStrictWithFixture(anf, "bind",
		map[string]interface{}{
			"expectedHash": hex.EncodeToString(expectedHash),
			"count":        big.NewInt(0),
		},
		nil, nil, fix)
	if err == nil {
		t.Fatal("expected missing-witness error, got nil")
	}
	ie, ok := err.(*IntentIntrinsicError)
	if !ok {
		t.Fatalf("expected *IntentIntrinsicError, got %T: %v", err, err)
	}
	if !ie.MissingWitness {
		t.Errorf("expected MissingWitness=true, got false")
	}
	if !strings.Contains(ie.Error(), "requires witness bytes") {
		t.Errorf("expected 'requires witness bytes' in error, got %q", ie.Error())
	}
}

// ---------------------------------------------------------------------------
// intent-output-p2pkh
// ---------------------------------------------------------------------------

func TestIntentInterpreter_OutputP2PKH_Success(t *testing.T) {
	bondPKH := intentFromHex("00112233445566778899aabbccddeeff00112233")
	bondAmount := int64(5000)
	serialised := intentP2PKHOutput(bondAmount, bondPKH)
	outputHash := intentHash256(serialised)

	anf := anfIntentOutputP2PKH()
	fix := NewInterpreterFixture()
	fix.SetSerialisedOutputs(serialised)
	fix.SetMockPreimageOutputHash(outputHash)

	state, _, _, err := ExecuteStrictWithFixture(anf, "payBond",
		map[string]interface{}{
			"bondPKH":    hex.EncodeToString(bondPKH),
			"bondAmount": big.NewInt(bondAmount),
			"count":      big.NewInt(0),
		},
		nil, nil, fix)
	if err != nil {
		t.Fatalf("ExecuteStrictWithFixture: %v", err)
	}
	c, ok := state["count"].(*big.Int)
	if !ok || c.Int64() != 1 {
		t.Fatalf("expected count=1, got %v", state["count"])
	}
}

func TestIntentInterpreter_OutputP2PKH_WrongPKHBytes(t *testing.T) {
	bondPKH := intentFromHex("00112233445566778899aabbccddeeff00112233")
	bondAmount := int64(5000)
	// Build serialised outputs with a DIFFERENT pkh; hashOutputs must still
	// match this wrong-serialised witness, otherwise the outer hash assertion
	// trips first. We want the per-output substr comparison to fail.
	wrongPKH := intentFromHex("ffffffffffffffffffffffffffffffffffffffff")
	wrongSerialised := intentP2PKHOutput(bondAmount, wrongPKH)
	wrongOutputHash := intentHash256(wrongSerialised)

	anf := anfIntentOutputP2PKH()
	fix := NewInterpreterFixture()
	fix.SetSerialisedOutputs(wrongSerialised)
	fix.SetMockPreimageOutputHash(wrongOutputHash)

	_, _, _, err := ExecuteStrictWithFixture(anf, "payBond",
		map[string]interface{}{
			"bondPKH":    hex.EncodeToString(bondPKH),
			"bondAmount": big.NewInt(bondAmount),
			"count":      big.NewInt(0),
		},
		nil, nil, fix)
	if err == nil {
		t.Fatal("expected IntentIntrinsicError, got nil")
	}
	ie, ok := err.(*IntentIntrinsicError)
	if !ok {
		t.Fatalf("expected *IntentIntrinsicError, got %T: %v", err, err)
	}
	if !strings.Contains(ie.Error(), "mismatch") {
		t.Errorf("expected 'mismatch' in error, got %q", ie.Error())
	}
}

func TestIntentInterpreter_OutputP2PKH_WrongHashOutputs(t *testing.T) {
	bondPKH := intentFromHex("00112233445566778899aabbccddeeff00112233")
	bondAmount := int64(5000)
	serialised := intentP2PKHOutput(bondAmount, bondPKH)

	anf := anfIntentOutputP2PKH()
	fix := NewInterpreterFixture()
	fix.SetSerialisedOutputs(serialised)
	// Wrong outputHash on the preimage — the outer hash check fires first.
	fix.SetMockPreimageOutputHash(make([]byte, 32))

	_, _, _, err := ExecuteStrictWithFixture(anf, "payBond",
		map[string]interface{}{
			"bondPKH":    hex.EncodeToString(bondPKH),
			"bondAmount": big.NewInt(bondAmount),
			"count":      big.NewInt(0),
		},
		nil, nil, fix)
	if err == nil {
		t.Fatal("expected IntentIntrinsicError, got nil")
	}
	ie, ok := err.(*IntentIntrinsicError)
	if !ok {
		t.Fatalf("expected *IntentIntrinsicError, got %T: %v", err, err)
	}
	if !strings.Contains(ie.Error(), "hash256(serialisedOutputs)") {
		t.Errorf("expected 'hash256(serialisedOutputs)' in error, got %q", ie.Error())
	}
}

// ---------------------------------------------------------------------------
// intent-current-block-height
// ---------------------------------------------------------------------------

func TestIntentInterpreter_CurrentBlockHeight_Success(t *testing.T) {
	anf := anfIntentCurrentBlockHeight()
	fix := NewInterpreterFixture()
	fix.SetMockPreimageLocktime(big.NewInt(500_000))

	state, _, _, err := ExecuteStrictWithFixture(anf, "spend",
		map[string]interface{}{
			"deadline": big.NewInt(1_000_000),
			"count":    big.NewInt(0),
		},
		nil, nil, fix)
	if err != nil {
		t.Fatalf("ExecuteStrictWithFixture: %v", err)
	}
	c, ok := state["count"].(*big.Int)
	if !ok || c.Int64() != 1 {
		t.Fatalf("expected count=1, got %v", state["count"])
	}
}

func TestIntentInterpreter_CurrentBlockHeight_Failure(t *testing.T) {
	anf := anfIntentCurrentBlockHeight()
	fix := NewInterpreterFixture()
	fix.SetMockPreimageLocktime(big.NewInt(999_999))

	_, _, _, err := ExecuteStrictWithFixture(anf, "spend",
		map[string]interface{}{
			"deadline": big.NewInt(100),
			"count":    big.NewInt(0),
		},
		nil, nil, fix)
	if err == nil {
		t.Fatal("expected AssertionFailureError, got nil")
	}
	if _, ok := err.(*AssertionFailureError); !ok {
		t.Fatalf("expected *AssertionFailureError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// branched-readonly-len — both arms succeed.
//
// This case doesn't exercise any of the three new intrinsics but is part of
// the TS test suite (regression coverage for state mutation under a
// `len(...)`-driven branch); we port it for parity.
// ---------------------------------------------------------------------------

func TestIntentInterpreter_BranchedReadonlyLen_ThenBranch(t *testing.T) {
	anf := anfBranchedReadonlyLen()

	state, _, _, err := ExecuteStrictWithFixture(anf, "spend",
		map[string]interface{}{
			"count": big.NewInt(10),
			"tag":   "00",
		},
		map[string]interface{}{"scratch": "aabbcc"},
		nil, nil)
	if err != nil {
		t.Fatalf("ExecuteStrictWithFixture: %v", err)
	}
	c, ok := state["count"].(*big.Int)
	if !ok || c.Int64() != 11 {
		t.Fatalf("expected count=11, got %v", state["count"])
	}
	tag, _ := state["tag"].(string)
	if tag != "aabbcc" {
		t.Fatalf("expected tag=aabbcc, got %v", state["tag"])
	}
}

func TestIntentInterpreter_BranchedReadonlyLen_ElseBranch(t *testing.T) {
	anf := anfBranchedReadonlyLen()

	state, _, _, err := ExecuteStrictWithFixture(anf, "spend",
		map[string]interface{}{
			"count": big.NewInt(10),
			"tag":   "aa",
		},
		map[string]interface{}{"scratch": ""},
		nil, nil)
	if err != nil {
		t.Fatalf("ExecuteStrictWithFixture: %v", err)
	}
	c, ok := state["count"].(*big.Int)
	if !ok || c.Int64() != 9 {
		t.Fatalf("expected count=9, got %v", state["count"])
	}
	tag, _ := state["tag"].(string)
	if tag != "3030" {
		t.Fatalf("expected tag=3030, got %v", state["tag"])
	}
}
