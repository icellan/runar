package compiler

import (
	"strings"
	"testing"
)

// F-072 (CL-BUG-042) — lowerCall's exit / assert branches recorded a stack
// slot no opcode produces.
//
// `exit(cond)` lowers as `call exit` (it has no dedicated ANF node) and
// codegen/stack.go lowerCall ran `cond OP_VERIFY` and then pushed a slot for
// the void result. OP_VERIFY leaves nothing behind, so every later PICK/ROLL
// addressed the item one below the one it meant. For
//
//	check(b, a, x, y) { exit(x > 0n); assert(y === 1n); assert(a > 5n); assert(b === 0n); }
//
// every tier emitted 7c00a0697c519d7c55a0697c9177, which a five-push witness
// (0, b=6, a=1, x=1, y=999) spends. The `call assert` spelling (reachable only
// through --ir; frontends emit the dedicated `assert` node) hit the same bug.
// The `super` branch had the same push but is dead: constructors are never
// stack-lowered and the loader refuses `super` elsewhere (negative I14).
//
// What this proves: the Go tier, on the source path in both fold modes and on
// the --ir path for `call exit` and `call assert`, emits the hand-derived
// 7c00a069519d55a06991 (SWAP 0 GT VERIFY 1 NUMEQUALVERIFY 5 GT VERIFY NOT).
// What this does NOT prove: that the script spends correctly — that is
// executed on the @bsv/sdk engine, for all seven tiers, in
// packages/runar-testing/src/__tests__/f072-exit-phantom-slot-spend.test.ts.

const f072Expected = "7c00a069519d55a06991"
const f072PreFix = "7c00a0697c519d7c55a0697c9177"

const f072Source = `import { SmartContract, assert } from 'runar-lang';

class ExitAssert4 extends SmartContract {
  constructor() {
    super();
  }

  public check(b: bigint, a: bigint, x: bigint, y: bigint) {
    exit(x > 0n);
    assert(y === 1n);
    assert(a > 5n);
    assert(b === 0n);
  }
}
`

func f072IR(guard string) string {
	return strings.ReplaceAll(`{"contractName": "ExitAssert4", "properties": [], "methods": [
		{"name": "constructor", "isPublic": false, "params": [], "body": [
			{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
		{"name": "check", "isPublic": true, "params": [
			{"name": "b", "type": "bigint"}, {"name": "a", "type": "bigint"},
			{"name": "x", "type": "bigint"}, {"name": "y", "type": "bigint"}], "body": [
			{"name": "t0", "value": {"kind": "load_param", "name": "x"}},
			{"name": "t1", "value": {"kind": "load_const", "value": 0}},
			{"name": "t2", "value": {"kind": "bin_op", "op": ">", "left": "t0", "right": "t1"}},
			{"name": "t3", "value": {"kind": "call", "func": "GUARD", "args": ["t2"]}},
			{"name": "t4", "value": {"kind": "load_param", "name": "y"}},
			{"name": "t5", "value": {"kind": "load_const", "value": 1}},
			{"name": "t6", "value": {"kind": "bin_op", "op": "===", "left": "t4", "right": "t5"}},
			{"name": "t7", "value": {"kind": "assert", "value": "t6"}},
			{"name": "t8", "value": {"kind": "load_param", "name": "a"}},
			{"name": "t9", "value": {"kind": "load_const", "value": 5}},
			{"name": "t10", "value": {"kind": "bin_op", "op": ">", "left": "t8", "right": "t9"}},
			{"name": "t11", "value": {"kind": "assert", "value": "t10"}},
			{"name": "t12", "value": {"kind": "load_param", "name": "b"}},
			{"name": "t13", "value": {"kind": "load_const", "value": 0}},
			{"name": "t14", "value": {"kind": "bin_op", "op": "===", "left": "t12", "right": "t13"}},
			{"name": "t15", "value": {"kind": "assert", "value": "t14"}}]}]}`, "GUARD", guard)
}

func TestF072_ExitThenAssert_Source(t *testing.T) {
	for _, fold := range []bool{false, true} {
		r := CompileFromSourceStrWithResult(f072Source, "ExitAssert4.runar.ts", CompileOptions{DisableConstantFolding: !fold})
		if !r.Success {
			t.Fatalf("fold=%v: compile failed: %v", fold, r.Diagnostics)
		}
		if r.ScriptHex == f072PreFix {
			t.Fatalf("fold=%v: phantom slot after exit(): got the pre-fix bytes %s (%s)", fold, r.ScriptHex, r.ScriptAsm)
		}
		if r.ScriptHex != f072Expected {
			t.Fatalf("fold=%v: got %s (%s), want %s", fold, r.ScriptHex, r.ScriptAsm, f072Expected)
		}
	}
}

func TestF072_CallExitAndCallAssert_IR(t *testing.T) {
	for _, guard := range []string{"exit", "assert"} {
		art, err := CompileFromIRBytes([]byte(f072IR(guard)))
		if err != nil {
			t.Fatalf("call %s: %v", guard, err)
		}
		if art.Script != f072Expected {
			t.Fatalf("call %s: got %s (%s), want %s", guard, art.Script, art.ASM, f072Expected)
		}
	}
}
