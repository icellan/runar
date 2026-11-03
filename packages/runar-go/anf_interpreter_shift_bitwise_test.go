package runar

// ---------------------------------------------------------------------------
// anf_interpreter_shift_bitwise_test.go
//
// Pins the ANF interpreter's `& | ^ ~ << >>` evaluation to Bitcoin Script's
// byte-array script-number semantics: OP_AND/OP_OR/OP_XOR/OP_INVERT/
// OP_LSHIFT/OP_RSHIFT operate on the operands' minimal script-number BYTES,
// not their bigint value. Truth table mirrors the TS reference
// (packages/runar-testing/src/__tests__/script-number-bitwise.test.ts and
// vm/utils.ts scriptNumberBitwise / scriptNumberInvert / scriptNumberShift).
// ---------------------------------------------------------------------------

import (
	"math/big"
	"strings"
	"testing"
)

func bi(n int64) *big.Int { return big.NewInt(n) }

func TestAnfEvalBinOp_ShiftBitwise_TruthTable(t *testing.T) {
	cases := []struct {
		name string
		op   string
		l, r int64
		want int64
	}{
		{"255<<1==254 not 510", "<<", 255, 1, 254},
		{"256<<1==512", "<<", 256, 1, 512},
		{"5<<3==40", "<<", 5, 3, 40},
		{"32>>3==4", ">>", 32, 3, 4},
		{"255>>1==-127 not 127", ">>", 255, 1, -127},
		{"5&3==1", "&", 5, 3, 1},
		{"-1&5==1 not 5", "&", -1, 5, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := anfEvalBinOp(c.op, bi(c.l), bi(c.r), "")
			gotBig, ok := got.(*big.Int)
			if !ok {
				t.Fatalf("expected *big.Int result, got %T (%v)", got, got)
			}
			if gotBig.Cmp(bi(c.want)) != 0 {
				t.Errorf("%d %s %d = %s, want %d", c.l, c.op, c.r, gotBig, c.want)
			}
		})
	}
}

func TestAnfEvalUnaryOp_Invert_TruthTable(t *testing.T) {
	cases := []struct {
		name string
		val  int64
		want int64
	}{
		{"~5==-122 not -6", 5, -122},
		{"~255==-32512", 255, -32512},
		{"~0==0", 0, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := anfEvalUnaryOp("~", bi(c.val), "")
			gotBig, ok := got.(*big.Int)
			if !ok {
				t.Fatalf("expected *big.Int result, got %T (%v)", got, got)
			}
			if gotBig.Cmp(bi(c.want)) != 0 {
				t.Errorf("~%d = %s, want %d", c.val, gotBig, c.want)
			}
		})
	}
}

func TestAnfEvalBinOp_ShiftBitwise_Aborts(t *testing.T) {
	cases := []struct {
		name string
		op   string
		l, r int64
	}{
		{"255&1 -> ABORT (len mismatch)", "&", 255, 1},
		{"7|0 -> ABORT (len mismatch)", "|", 7, 0},
		{"5<<(-1) -> ABORT (negative shift)", "<<", 5, -1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("expected panic (ABORT), got none")
				}
				if _, ok := r.(*ScriptOpcodeError); !ok {
					t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", r, r)
				}
			}()
			anfEvalBinOp(c.op, bi(c.l), bi(c.r), "")
		})
	}
}

// TestExecuteStrict_ShiftBitwise_AbortSurfacesAsError confirms the panic
// unwinds through runMethod's recover and surfaces as a plain Go error from
// the public entry points (ExecuteStrict / ComputeNewState), not a raw
// runtime panic — mirroring the TS reference where scriptNumberBitwise /
// scriptNumberShift throw a catchable Error rather than crashing the
// process.
func TestExecuteStrict_ShiftBitwise_AbortSurfacesAsError(t *testing.T) {
	anf := &ANFProgram{
		ContractName: "ShiftAbort",
		Properties:   []ANFProperty{},
		Methods: []ANFMethod{
			{
				Name:     "run",
				IsPublic: true,
				Params:   []ANFParam{},
				Body: []ANFBinding{
					{
						Name: "t0",
						Value: map[string]interface{}{
							"kind":  "load_const",
							"value": "255",
						},
					},
					{
						Name: "t1",
						Value: map[string]interface{}{
							"kind":  "load_const",
							"value": "1",
						},
					},
					{
						Name: "t2",
						Value: map[string]interface{}{
							"kind":        "bin_op",
							"op":          "&",
							"left":        "t0",
							"right":       "t1",
							"result_type": "bigint",
						},
					},
				},
			},
		},
	}

	_, _, _, err := ExecuteStrict(anf, "run", map[string]interface{}{}, map[string]interface{}{}, nil)
	if err == nil {
		t.Fatalf("expected an error from ExecuteStrict on OP_AND length mismatch, got nil")
	}
	if _, ok := err.(*ScriptOpcodeError); !ok {
		t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// CHAINED byte-op semantics (issue: shift/bitwise results are fixed-length,
// possibly NON-minimal byte arrays on-chain; a chained length-sensitive op
// must see that real length, not the re-minimised numeric value).
//
// A single op on minimal operands was already correct (truth-table tests
// above). These pin the interpreter's per-binding side-map threading so a
// shift/bitwise RESULT feeding another `& | ^ << >> ~` matches the deployed
// script. Mirrors the TS reference (packages/runar-sdk/src/anf-interpreter.ts
// `scriptBytes` side map + packages/runar-testing/src/vm/utils.ts
// scriptNumber*Bytes helpers).
// ---------------------------------------------------------------------------

// sbConst builds a load_const binding whose value is the decimal string `val`.
func sbConst(name, val string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{"kind": "load_const", "value": val}}
}

// sbBin builds a numeric bin_op binding (result_type "bigint").
func sbBin(name, op, left, right string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "bin_op", "op": op, "left": left, "right": right, "result_type": "bigint",
	}}
}

// sbUn builds a numeric unary_op binding (result_type "bigint").
func sbUn(name, op, operand string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "unary_op", "op": op, "operand": operand, "result_type": "bigint",
	}}
}

// sbUpd builds an update_prop binding writing binding `val` to property `prop`.
func sbUpd(name, prop, val string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "update_prop", "name": prop, "value": val,
	}}
}

// sbProgram wraps a method body around a single mutable property "out".
func sbProgram(body []ANFBinding) *ANFProgram {
	return &ANFProgram{
		ContractName: "Chained",
		Properties:   []ANFProperty{{Name: "out", Type: "bigint", Readonly: false}},
		Methods: []ANFMethod{{
			Name: "run", IsPublic: true, Params: []ANFParam{}, Body: body,
		}},
	}
}

// TestAnfInterpreter_ChainedByteOps_Values pins the value results of chained
// shift/bitwise expressions where an intermediate is a non-minimal byte array.
func TestAnfInterpreter_ChainedByteOps_Values(t *testing.T) {
	cases := []struct {
		name string
		body []ANFBinding
		want int64
	}{
		{
			// (2<<8)|5: 2<<8 leaves the 1-byte [0x00]; OP_OR([0x00],[0x05])=
			// [0x05] => 5. A re-minimising interpreter would OR empty|[0x05]
			// and abort on the length mismatch.
			name: "(2<<8)|5 == 5",
			body: []ANFBinding{
				sbConst("t0", "2"),
				sbConst("t1", "8"),
				sbBin("t2", "<<", "t0", "t1"),
				sbConst("t3", "5"),
				sbBin("t4", "|", "t2", "t3"),
				sbUpd("t5", "out", "t4"),
			},
			want: 5,
		},
		{
			// ~(2<<8): invert the 1-byte [0x00] -> [0xff] => -127 decoded.
			name: "~(2<<8) == -127",
			body: []ANFBinding{
				sbConst("t0", "2"),
				sbConst("t1", "8"),
				sbBin("t2", "<<", "t0", "t1"),
				sbUn("t3", "~", "t2"),
				sbUpd("t4", "out", "t3"),
			},
			want: -127,
		},
		{
			// (256<<8)&256: 256<<8 within 2 bytes = [0x01,0x00] (=1); AND with
			// encode(256)=[0x00,0x01] => [0x00,0x00] => 0. Both 2 bytes, so no
			// abort — but the numeric values (1 & 256) would give 0 too here;
			// the point is the byte path agrees and does NOT abort.
			name: "(256<<8)&256 == 0",
			body: []ANFBinding{
				sbConst("t0", "256"),
				sbConst("t1", "8"),
				sbBin("t2", "<<", "t0", "t1"),
				sbConst("t3", "256"),
				sbBin("t4", "&", "t2", "t3"),
				sbUpd("t5", "out", "t4"),
			},
			want: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, err := ComputeNewState(
				sbProgram(c.body), "run",
				map[string]interface{}{"out": big.NewInt(0)},
				map[string]interface{}{}, nil,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, ok := state["out"].(*big.Int)
			if !ok {
				t.Fatalf("expected *big.Int state[out], got %T (%v)", state["out"], state["out"])
			}
			if got.Cmp(bi(c.want)) != 0 {
				t.Errorf("%s = %s, want %d", c.name, got, c.want)
			}
		})
	}
}

// TestAnfInterpreter_ChainedByteOps_Abort pins the funds-loss case: on-chain
// `(1<<8)&0` is OP_AND([0x00], []) — a length mismatch that ABORTS. A buggy
// interpreter that re-minimises the shift result to 0 would compute `0 & 0 =
// 0` and report the spend as valid off-chain while the chain rejects it.
func TestAnfInterpreter_ChainedByteOps_Abort(t *testing.T) {
	body := []ANFBinding{
		sbConst("t0", "1"),
		sbConst("t1", "8"),
		sbBin("t2", "<<", "t0", "t1"),
		sbConst("t3", "0"),
		sbBin("t4", "&", "t2", "t3"),
		sbUpd("t5", "out", "t4"),
	}
	_, err := ComputeNewState(
		sbProgram(body), "run",
		map[string]interface{}{"out": big.NewInt(0)},
		map[string]interface{}{}, nil,
	)
	if err == nil {
		t.Fatalf("expected an ABORT error for (1<<8)&0 length mismatch, got nil")
	}
	se, ok := err.(*ScriptOpcodeError)
	if !ok {
		t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", err, err)
	}
	if se.Opcode != "OP_AND" || !strings.Contains(se.Message, "same length") {
		t.Errorf("expected OP_AND same-length abort, got %q: %q", se.Opcode, se.Message)
	}
}

// ---------------------------------------------------------------------------
// NON-MINIMAL numeric operands (funds-locking).
//
// A shift PRESERVES its operand's byte length, so `1 >> 1` leaves the 1-byte
// array [0x00] — a NON-minimal zero (minimal zero is the empty array). Every
// NUMERIC consumer on-chain (OP_ADD/OP_SUB/OP_MUL/OP_DIV/OP_MOD, OP_NUMEQUAL/
// OP_NOT and the relational ops, and a shift's COUNT operand) decodes with
// fRequireMinimal=true and ABORTS on a non-minimal encoding.
//
// The interpreter threads the real stack bytes through the byte ops but the
// NUMERIC path used to read only the decoded value, re-minimising [0x00] to 0
// and reporting the spend VALID. A developer testing off-chain saw green and
// deployed a UTXO the chain will never let them spend.
//
// The byte-array ops OP_AND/OP_OR/OP_XOR and a shift's VALUE operand are NOT
// covered by fRequireMinimal — they legitimately take non-minimal bytes and
// only require equal length. Those must stay accepted (see the controls
// below and conformance/fuzz-regressions/entries/
// 2026-07-14-chained-shift-or-nonminimal).
// ---------------------------------------------------------------------------

// sbAlias builds the `@ref:` alias binding the ANF lowering emits for a named
// local (`const left: bigint = a << 3n` becomes t2 = a << 3n followed by
// left = @ref:t2). Real compiler output routes almost every byte-op result
// through one of these before it reaches a consumer.
func sbAlias(name, target string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "load_const", "value": "@ref:" + target,
	}}
}

// sbAssert builds an `assert` binding over the predicate binding `pred`.
func sbAssert(name, pred string) ANFBinding {
	return ANFBinding{Name: name, Value: map[string]interface{}{
		"kind": "assert", "value": pred,
	}}
}

// TestAnfInterpreter_NonMinimalNumericOperand_Aborts pins that feeding a
// non-minimally-encoded shift result to a numeric consumer ABORTS, matching
// the deployed script's fRequireMinimal decode.
func TestAnfInterpreter_NonMinimalNumericOperand_Aborts(t *testing.T) {
	// Prefix shared by every case: t2 = 1 >> 1 -> raw stack bytes [0x00].
	prefix := []ANFBinding{
		sbConst("t0", "1"),
		sbConst("t1", "1"),
		sbBin("t2", ">>", "t0", "t1"),
		sbConst("t3", "0"),
		sbConst("t4", "1"),
	}

	cases := []struct {
		name   string
		tail   []ANFBinding
		opcode string
	}{
		{
			// OP_NUMEQUAL on [0x00] — the canonical funds-locking guard:
			// `(n >> 1) === 0` reports VALID off-chain, aborts on-chain.
			name:   "(1>>1)===0 -> ABORT (OP_NUMEQUAL)",
			tail:   []ANFBinding{sbBin("t5", "===", "t2", "t3")},
			opcode: "OP_NUMEQUAL",
		},
		{
			name:   "0===(1>>1) -> ABORT (right operand too)",
			tail:   []ANFBinding{sbBin("t5", "===", "t3", "t2")},
			opcode: "OP_NUMEQUAL",
		},
		{
			name:   "(1>>1)+1 -> ABORT (OP_ADD)",
			tail:   []ANFBinding{sbBin("t5", "+", "t2", "t4")},
			opcode: "OP_ADD",
		},
		{
			name:   "(1>>1)-1 -> ABORT (OP_SUB)",
			tail:   []ANFBinding{sbBin("t5", "-", "t2", "t4")},
			opcode: "OP_SUB",
		},
		{
			name:   "(1>>1)*1 -> ABORT (OP_MUL)",
			tail:   []ANFBinding{sbBin("t5", "*", "t2", "t4")},
			opcode: "OP_MUL",
		},
		{
			name:   "(1>>1)/1 -> ABORT (OP_DIV)",
			tail:   []ANFBinding{sbBin("t5", "/", "t2", "t4")},
			opcode: "OP_DIV",
		},
		{
			name:   "(1>>1)%1 -> ABORT (OP_MOD)",
			tail:   []ANFBinding{sbBin("t5", "%", "t2", "t4")},
			opcode: "OP_MOD",
		},
		{
			name:   "(1>>1)!==1 -> ABORT (OP_NUMNOTEQUAL)",
			tail:   []ANFBinding{sbBin("t5", "!==", "t2", "t4")},
			opcode: "OP_NUMNOTEQUAL",
		},
		{
			name:   "(1>>1)<1 -> ABORT (OP_LESSTHAN)",
			tail:   []ANFBinding{sbBin("t5", "<", "t2", "t4")},
			opcode: "OP_LESSTHAN",
		},
		{
			name:   "(1>>1)<=1 -> ABORT (OP_LESSTHANOREQUAL)",
			tail:   []ANFBinding{sbBin("t5", "<=", "t2", "t4")},
			opcode: "OP_LESSTHANOREQUAL",
		},
		{
			name:   "(1>>1)>1 -> ABORT (OP_GREATERTHAN)",
			tail:   []ANFBinding{sbBin("t5", ">", "t2", "t4")},
			opcode: "OP_GREATERTHAN",
		},
		{
			name:   "(1>>1)>=1 -> ABORT (OP_GREATERTHANOREQUAL)",
			tail:   []ANFBinding{sbBin("t5", ">=", "t2", "t4")},
			opcode: "OP_GREATERTHANOREQUAL",
		},
		{
			// A shift's COUNT operand IS read as a number -> fRequireMinimal.
			name:   "1<<(1>>1) -> ABORT (OP_LSHIFT count operand)",
			tail:   []ANFBinding{sbBin("t5", "<<", "t4", "t2")},
			opcode: "OP_LSHIFT",
		},
		{
			name:   "1>>(1>>1) -> ABORT (OP_RSHIFT count operand)",
			tail:   []ANFBinding{sbBin("t5", ">>", "t4", "t2")},
			opcode: "OP_RSHIFT",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := append(append([]ANFBinding{}, prefix...), c.tail...)
			body = append(body, sbUpd("t6", "out", "t3"))
			_, err := ComputeNewState(
				sbProgram(body), "run",
				map[string]interface{}{"out": big.NewInt(0)},
				map[string]interface{}{}, nil,
			)
			if err == nil {
				t.Fatalf("expected a non-minimal-operand ABORT, got nil (spend wrongly reported valid)")
			}
			se, ok := err.(*ScriptOpcodeError)
			if !ok {
				t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", err, err)
			}
			if se.Opcode != c.opcode {
				t.Errorf("expected opcode %s, got %s", c.opcode, se.Opcode)
			}
			if !strings.Contains(se.Message, "non-minimally encoded") {
				t.Errorf("expected a non-minimal-encoding message, got %q", se.Message)
			}
		})
	}
}

// TestExecuteStrict_NonMinimalNumericOperand_GuardDoesNotSilentlyPass is the
// funds-locking scenario end to end: `assert((n >> 1) === 0)` with n = 1. The
// deployed script aborts at OP_NUMEQUAL, so strict mode must report a failure
// rather than a clean spend.
func TestExecuteStrict_NonMinimalNumericOperand_GuardDoesNotSilentlyPass(t *testing.T) {
	body := []ANFBinding{
		sbConst("t0", "1"),
		sbConst("t1", "1"),
		sbBin("t2", ">>", "t0", "t1"),
		sbConst("t3", "0"),
		sbBin("t4", "===", "t2", "t3"),
		sbAssert("t5", "t4"),
		sbUpd("t6", "out", "t3"),
	}
	_, _, _, err := ExecuteStrict(
		sbProgram(body), "run",
		map[string]interface{}{"out": big.NewInt(0)},
		map[string]interface{}{}, nil,
	)
	if err == nil {
		t.Fatalf("assert((1>>1)===0) was accepted off-chain; the deployed script aborts at OP_NUMEQUAL (funds locked)")
	}
	if _, ok := err.(*ScriptOpcodeError); !ok {
		t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", err, err)
	}
}

// TestAnfInterpreter_MinimalOperands_StillAccepted are the CONTROLS. None of
// these carry a non-minimal encoding into a numeric consumer, so all must
// keep spending exactly as before.
func TestAnfInterpreter_MinimalOperands_StillAccepted(t *testing.T) {
	cases := []struct {
		name string
		body []ANFBinding
		want int64
	}{
		{
			// 2>>1 leaves [0x01] — that IS the minimal encoding of 1, so the
			// numeric compare is legal on-chain and must still accept.
			name: "(2>>1)===1 accepts",
			body: []ANFBinding{
				sbConst("t0", "2"),
				sbConst("t1", "1"),
				sbBin("t2", ">>", "t0", "t1"),
				sbConst("t3", "1"),
				sbBin("t4", "===", "t2", "t3"),
				sbAssert("t5", "t4"),
				sbUpd("t6", "out", "t3"),
			},
			want: 1,
		},
		{
			// `& | ^` are NOT fRequireMinimal — they take non-minimal bytes and
			// only require equal length. (2<<8) is the 1-byte [0x00]; OR with
			// [0x05] gives [0x05], which is minimal, so the `=== 5` is legal.
			// Pinned by conformance/fuzz-regressions/entries/
			// 2026-07-14-chained-shift-or-nonminimal — rejecting this is WRONG.
			name: "(2<<8)|5 === 5 accepts",
			body: []ANFBinding{
				sbConst("t0", "2"),
				sbConst("t1", "8"),
				sbBin("t2", "<<", "t0", "t1"),
				sbConst("t3", "5"),
				sbBin("t4", "|", "t2", "t3"),
				sbBin("t5", "===", "t4", "t3"),
				sbAssert("t6", "t5"),
				sbUpd("t7", "out", "t3"),
			},
			want: 5,
		},
		{
			// A shift's VALUE operand is not fRequireMinimal either: (2<<8) is
			// [0x00], shifting it again is legal and stays 1 byte.
			name: "((2<<8)<<1)|5 === 5 accepts",
			body: []ANFBinding{
				sbConst("t0", "2"),
				sbConst("t1", "8"),
				sbBin("t2", "<<", "t0", "t1"),
				sbConst("t3", "1"),
				sbBin("t4", "<<", "t2", "t3"),
				sbConst("t5", "5"),
				sbBin("t6", "|", "t4", "t5"),
				sbBin("t7", "===", "t6", "t5"),
				sbAssert("t8", "t7"),
				sbUpd("t9", "out", "t5"),
			},
			want: 5,
		},
		{
			// ~(2<<8) = [0xff] = -127, which IS minimal for -127.
			name: "~(2<<8) === -127 accepts",
			body: []ANFBinding{
				sbConst("t0", "2"),
				sbConst("t1", "8"),
				sbBin("t2", "<<", "t0", "t1"),
				sbUn("t3", "~", "t2"),
				sbConst("t4", "-127"),
				sbBin("t5", "===", "t3", "t4"),
				sbAssert("t6", "t5"),
				sbUpd("t7", "out", "t4"),
			},
			want: -127,
		},
		{
			// Plain arithmetic on values that never touched a byte op.
			name: "1+1===2 accepts",
			body: []ANFBinding{
				sbConst("t0", "1"),
				sbConst("t1", "1"),
				sbBin("t2", "+", "t0", "t1"),
				sbConst("t3", "2"),
				sbBin("t4", "===", "t2", "t3"),
				sbAssert("t5", "t4"),
				sbUpd("t6", "out", "t2"),
			},
			want: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, _, _, err := ExecuteStrict(
				sbProgram(c.body), "run",
				map[string]interface{}{"out": big.NewInt(0)},
				map[string]interface{}{}, nil,
			)
			if err != nil {
				t.Fatalf("control regressed — expected a clean spend, got %v", err)
			}
			// `out` is whatever the written binding held: a *big.Int from an
			// arithmetic/byte op, or the decimal string a load_const carries.
			if got := anfToBigInt(state["out"]); got.Cmp(bi(c.want)) != 0 {
				t.Errorf("out = %s, want %d", got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// `@ref:` ALIAS bindings must carry the threaded stack bytes.
//
// The lowering turns every named local into an alias: `const left: bigint =
// this.a << 3n` becomes `t2 = a << 3n` followed by `left = @ref:t2`, and the
// consumer reads `left`. The side map is keyed by binding name, so an alias
// that does not copy the entry drops the real stack bytes — which silently
// disables BOTH the non-minimal numeric check above AND the chained byte-op
// threading, on exactly the shape the compiler actually emits.
//
// conformance/tests/shift-ops is a live example: `left = this.a << 3n;
// assert(left === expectedLeft)`. With a = 32 the shift leaves the 1-byte
// [0x00] and OP_NUMEQUALVERIFY (the left check; the final assert is OP_NUMEQUAL) aborts on chain.
// ---------------------------------------------------------------------------

func TestAnfInterpreter_AliasCarriesScriptBytes(t *testing.T) {
	t.Run("aliased non-minimal shift result aborts a numeric consumer", func(t *testing.T) {
		body := []ANFBinding{
			sbConst("t0", "1"),
			sbConst("t1", "1"),
			sbBin("t2", ">>", "t0", "t1"), // raw [0x00]
			sbAlias("s", "t2"),            // const s = a >> 1
			sbConst("t3", "0"),
			sbBin("t4", "===", "s", "t3"),
			sbAssert("t5", "t4"),
			sbUpd("t6", "out", "t3"),
		}
		_, _, _, err := ExecuteStrict(
			sbProgram(body), "run",
			map[string]interface{}{"out": big.NewInt(0)},
			map[string]interface{}{}, nil,
		)
		if err == nil {
			t.Fatalf("aliased [0x00] was accepted; the deployed script aborts at OP_NUMEQUAL (funds locked)")
		}
		se, ok := err.(*ScriptOpcodeError)
		if !ok {
			t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", err, err)
		}
		if se.Opcode != "OP_NUMEQUAL" || !strings.Contains(se.Message, "non-minimally encoded") {
			t.Errorf("expected an OP_NUMEQUAL non-minimal abort, got %q: %q", se.Opcode, se.Message)
		}
	})

	t.Run("aliased non-minimal bytes still feed a byte op (no false abort)", func(t *testing.T) {
		// CONTROL, and a regression for the byte-op threading itself: an alias
		// that drops the entry makes OP_OR re-derive 0's EMPTY encoding and
		// abort on a length mismatch the chain never sees.
		body := []ANFBinding{
			sbConst("t0", "2"),
			sbConst("t1", "8"),
			sbBin("t2", "<<", "t0", "t1"), // raw [0x00]
			sbAlias("s", "t2"),            // const s = a << 8
			sbConst("t3", "5"),
			sbBin("t4", "|", "s", "t3"),
			sbBin("t5", "===", "t4", "t3"),
			sbAssert("t6", "t5"),
			sbUpd("t7", "out", "t4"),
		}
		state, _, _, err := ExecuteStrict(
			sbProgram(body), "run",
			map[string]interface{}{"out": big.NewInt(0)},
			map[string]interface{}{}, nil,
		)
		if err != nil {
			t.Fatalf("(2<<8)|5 through an alias must spend to 5, got %v", err)
		}
		if got := anfToBigInt(state["out"]); got.Cmp(bi(5)) != 0 {
			t.Errorf("out = %s, want 5", got)
		}
	})

	t.Run("aliased MINIMAL shift result still accepted", func(t *testing.T) {
		body := []ANFBinding{
			sbConst("t0", "2"),
			sbConst("t1", "1"),
			sbBin("t2", ">>", "t0", "t1"), // raw [0x01] — minimal
			sbAlias("s", "t2"),
			sbConst("t3", "1"),
			sbBin("t4", "===", "s", "t3"),
			sbAssert("t5", "t4"),
			sbUpd("t6", "out", "t3"),
		}
		state, _, _, err := ExecuteStrict(
			sbProgram(body), "run",
			map[string]interface{}{"out": big.NewInt(0)},
			map[string]interface{}{}, nil,
		)
		if err != nil {
			t.Fatalf("control regressed — expected a clean spend, got %v", err)
		}
		if got := anfToBigInt(state["out"]); got.Cmp(bi(1)) != 0 {
			t.Errorf("out = %s, want 1", got)
		}
	})
}
