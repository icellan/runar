//! F-072 — lowerCall's `exit` / `assert` branches recorded a stack slot no
//! opcode produces.
//!
//! `exit(cond)` lowers as `call exit` (no dedicated ANF node); the stack
//! lowering ran `cond OP_VERIFY` and then pushed a slot for the void result.
//! OP_VERIFY leaves nothing behind, so every later PICK/ROLL addressed the item
//! one below the one it meant. For
//! `check(b, a, x, y) { exit(x > 0n); assert(y === 1n); assert(a > 5n); assert(b === 0n); }`
//! every tier emitted 7c00a0697c519d7c55a0697c9177, which the five-push
//! witness (0, b=6, a=1, x=1, y=999) spends. `call assert` (reachable only
//! through --ir) hit the same bug; the `super` branch is dead (constructors are
//! never stack-lowered and the loader refuses `super` elsewhere).
//!
//! Proves: the Rust tier emits the hand-derived 7c00a069519d55a06991 on the
//! source path (both fold modes) and on the --ir path for `call exit` and
//! `call assert`.
//! Does not prove: that the script spends correctly — executed on the
//! @bsv/sdk engine for all seven tiers in
//! packages/runar-testing/src/__tests__/f072-exit-phantom-slot-spend.test.ts.

use runar_compiler_rust::{compile_from_ir_str, compile_from_source_str_with_options, CompileOptions};

const EXPECTED: &str = "7c00a069519d55a06991";
const PRE_FIX: &str = "7c00a0697c519d7c55a0697c9177";

const SOURCE: &str = r#"import { SmartContract, assert } from 'runar-lang';

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
"#;

fn ir(guard: &str) -> String {
    r#"{"contractName": "ExitAssert4", "properties": [], "methods": [
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
            {"name": "t15", "value": {"kind": "assert", "value": "t14"}}]}]}"#
        .replace("GUARD", guard)
}

#[test]
fn f072_exit_then_assert_source_reads_right_slots() {
    for fold in [false, true] {
        let opts = CompileOptions { disable_constant_folding: !fold, ..Default::default() };
        let art = compile_from_source_str_with_options(SOURCE, Some("ExitAssert4.runar.ts"), &opts)
            .expect("ExitAssert4 should compile");
        assert_ne!(art.script, PRE_FIX, "fold={fold}: phantom slot after exit(): {}", art.asm);
        assert_eq!(art.script, EXPECTED, "fold={fold}: {}", art.asm);
    }
}

#[test]
fn f072_call_exit_and_call_assert_ir_read_right_slots() {
    for guard in ["exit", "assert"] {
        let art = compile_from_ir_str(&ir(guard)).expect("IR should compile");
        assert_eq!(art.script, EXPECTED, "call {guard}: {}", art.asm);
    }
}
