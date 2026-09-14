//! Stack lowering across unrolled for-loops — outer-scope refs (method
//! params, pre-loop consts) must survive loop unrolling. Port of the
//! TypeScript `loop-outer-refs.test.ts` (PR #113, fix 5).
//!
//!  (a) a const defined before a loop and referenced inside it (including
//!      only inside a nested if-branch) failed compilation with
//!      "value 'X' not found on stack" — the first iteration consumed it;
//!  (b) worse, a method PARAM referenced after an unrolled loop whose body
//!      also references it was silently lowered to an empty push (OP_0):
//!      compilation succeeded, the env-based interpreter passed, but the
//!      emitted Script failed at runtime (silent interpreter<->Script
//!      divergence).
//!
//! The fix: lower_loop collects outer refs deeply (nested branches included)
//! and protects them in non-final iterations, and in the final iteration
//! whenever the enclosing scope still references them after the loop. The
//! old silent OP_0 fallbacks are now hard errors.

use runar_compiler_rust::{
    compile_from_ir_str, compile_from_source_str_with_result, CompileOptions,
};

/// V003 repro: multi-input tx walk — param `data` used inside AND after the loop.
const LOOP_WALK_SOURCE: &str = r#"
import { SmartContract, assert, substr, cat, bin2num } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class LoopWalk extends SmartContract {
  readonly pad00: ByteString = "00" as ByteString;

  constructor() {
    super();
  }

  public walk(data: ByteString) {
    let off = 5n;
    for (let i = 0n; i < 3n; i++) {
      if (i < bin2num(cat(substr(data, 4n, 1n), this.pad00))) {
        const sl = bin2num(cat(substr(data, off + 36n, 1n), this.pad00));
        assert(sl < 253n);
        off = off + 36n + 1n + sl + 4n;
      }
    }
    const tail = bin2num(cat(substr(data, off, 1n), this.pad00));
    assert(tail === 7n);
  }
}
"#;

/// Symptom (a): const defined before the loop, referenced inside it.
const CONST_BEFORE_LOOP_SOURCE: &str = r#"
import { SmartContract, assert, substr, cat, bin2num } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class ConstLoop extends SmartContract {
  readonly pad00: ByteString = "00" as ByteString;

  constructor() {
    super();
  }

  public probe(data: ByteString) {
    const base = 5n;
    let acc = 0n;
    for (let i = 0n; i < 3n; i++) {
      const b = bin2num(cat(substr(data, base + i, 1n), this.pad00));
      acc = acc + b;
    }
    assert(acc === 6n);
  }
}
"#;

/// A loop-carried local REASSIGNED and then READ AGAIN in the same iteration.
/// The rebinding shadows the incoming slot under the same name; the later read
/// was its last body use, so it consumed the UPDATED value and left the dead
/// incoming one for the next iteration to resolve. `wacc` came out as `step*N`
/// instead of `step*N*(N+1)/2` — silently in a stateless contract, and as a
/// permanently unspendable UTXO in a stateful one. Real-VM proof:
/// packages/runar-testing/src/__tests__/loop-carried-local-read-after-reassign-vm.test.ts
const CARRIED_REBIND_SOURCE: &str = r#"import { SmartContract, assert } from 'runar-lang';

class LoopCarriedRebind extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    let wacc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + step;
      wacc = wacc + acc;
    }
    assert(wacc === this.expected);
  }
}
"#;

/// Control: the same loop with a single self-accumulating carrier — no read
/// after the rebinding. Its bytes must NOT move, or the carried-rebind fix has
/// been written too wide and every shipped `BoundedLoop`-shaped contract pays.
/// R-186 / R-292 re-stamped this pin on 2026-09-14: the accumulator body leaves
/// the carried local on top, so the iteration variable sat one slot down and
/// `lowerLoop`'s `depth == 0` cleanup never fired. The control still says what it
/// was written to say about the carried-rebind fix; it no longer pins the bytes
/// that predate it.
const PLAIN_ACCUMULATOR_SOURCE: &str = r#"import { SmartContract, assert } from 'runar-lang';

class LoopPlainAccumulator extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + step;
    }
    assert(acc === this.expected);
  }
}
"#;

/// The same cross-read one loop deeper. The predicate keys on the body's
/// TOP-LEVEL binding names, and at the OUTER level `acc` is bound only inside
/// the nested loop — so it was neither an outer ref nor a carried rebind, and
/// every outer iteration restarted from the slot the previous one left behind.
/// `wacc` came out 24 where the source says 30 (step = 3). Real-VM proof:
/// packages/runar-testing/src/__tests__/nested-loop-carried-local-vm.test.ts
const NESTED_CARRIED_REBIND_SOURCE: &str = r#"import { SmartContract, assert } from 'runar-lang';

class LoopNestedCarriedRebind extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    let wacc = 0n;
    for (let i = 0n; i < 2n; i++) {
      for (let j = 0n; j < 2n; j++) {
        acc = acc + step;
        wacc = wacc + acc;
      }
    }
    assert(wacc === this.expected);
  }
}
"#;

/// Control: NESTED loops with a single self-accumulating carrier. The flatten
/// step fires here (the body does contain a nested loop) but the predicate
/// still says "not carried", so the bytes must NOT move — that is what keeps
/// nesting itself from costing anything.
/// R-186 / R-292 re-stamped this pin on 2026-09-14 as well. Nesting still costs
/// nothing — the single-level accumulator moved by exactly the same change.
const NESTED_PLAIN_ACCUMULATOR_SOURCE: &str = r#"import { SmartContract, assert } from 'runar-lang';

class LoopNestedPlainAccumulator extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      for (let j = 0n; j < 2n; j++) {
        acc = acc + step;
      }
    }
    assert(acc === this.expected);
  }
}
"#;

/// Byte-identical across all seven compiler tiers (fold-OFF).
const CARRIED_REBIND_HEX: &str = "000000537953797c937b78937b7551547a53797c937b7c9377009c7777";
const PLAIN_ACCUMULATOR_HEX: &str = "000052797b7c9377517b7b7c9377009c";
const NESTED_CARRIED_REBIND_HEX: &str = "00000000547954797c93537a78937b7551557953797c937b78937b75537a755100567954797c93537a78937b7551577a53797c937b7c93777b75009c77777777";
const NESTED_PLAIN_ACCUMULATOR_HEX: &str =
    "0000005379537a7c93775153797b7c93777751005379537a7c937751537a7b7c937777009c";

fn compile_hex(source: &str, file_name: &str) -> String {
    let opts = CompileOptions {
        disable_constant_folding: true,
        ..CompileOptions::default()
    };
    let result = compile_from_source_str_with_result(source, Some(file_name), &opts);
    assert!(
        result.success,
        "{} should compile; diagnostics: {:?}",
        file_name,
        result
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
    );
    result.script_hex.expect("compiled script hex")
}

#[test]
fn a_local_reassigned_then_read_again_in_the_same_iteration_survives_it() {
    assert_eq!(
        compile_hex(CARRIED_REBIND_SOURCE, "LoopCarriedRebind.runar.ts"),
        CARRIED_REBIND_HEX
    );
}

#[test]
fn a_plain_accumulator_loop_is_untouched_by_the_carried_rebind_fix() {
    assert_eq!(
        compile_hex(PLAIN_ACCUMULATOR_SOURCE, "LoopPlainAccumulator.runar.ts"),
        PLAIN_ACCUMULATOR_HEX
    );
}

#[test]
fn the_same_cross_read_inside_a_nested_loop_survives_it_too() {
    assert_eq!(
        compile_hex(
            NESTED_CARRIED_REBIND_SOURCE,
            "LoopNestedCarriedRebind.runar.ts"
        ),
        NESTED_CARRIED_REBIND_HEX
    );
}

#[test]
fn a_nested_plain_accumulator_is_untouched_by_the_nested_fix() {
    assert_eq!(
        compile_hex(
            NESTED_PLAIN_ACCUMULATOR_SOURCE,
            "LoopNestedPlainAccumulator.runar.ts"
        ),
        NESTED_PLAIN_ACCUMULATOR_HEX
    );
}

#[test]
fn param_referenced_after_a_loop_is_not_lowered_to_an_empty_push() {
    let opts = CompileOptions::default();
    let result = compile_from_source_str_with_result(
        LOOP_WALK_SOURCE,
        Some("LoopWalk.runar.ts"),
        &opts,
    );
    assert!(
        result.success,
        "LoopWalk should compile; diagnostics: {:?}",
        result
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
    );

    // The post-loop code (after the last OP_ENDIF) reads `data` via
    // substr(data, off, 1n). With the bug, `data` was emitted as OP_0
    // right after the final OP_ENDIF; fixed code brings the real param up.
    let asm = result.script_asm.expect("compiled asm");
    let last_endif = asm.rfind("OP_ENDIF").expect("loop emits at least one OP_ENDIF");
    let post_loop = &asm[last_endif..];
    assert!(
        !post_loop.contains("OP_0"),
        "post-loop region must not contain a silent OP_0 placeholder; post-loop asm: {}",
        post_loop
    );
}

#[test]
fn const_defined_before_a_loop_and_referenced_inside_compiles() {
    let opts = CompileOptions::default();
    let result = compile_from_source_str_with_result(
        CONST_BEFORE_LOOP_SOURCE,
        Some("ConstLoop.runar.ts"),
        &opts,
    );
    // Previously: "value 'base' not found on stack (...)"
    assert!(
        result.success,
        "ConstLoop should compile; diagnostics: {:?}",
        result
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
    );
    assert!(result.script_hex.is_some(), "script hex should be present");
}

#[test]
fn a_load_param_that_cannot_be_satisfied_is_a_loud_error_not_op0() {
    // Hand-written ANF referencing a parameter the method does not have —
    // the old code silently emitted OP_0 here.
    let ir_json = r#"{
        "contractName": "Broken",
        "properties": [],
        "methods": [{
            "name": "run",
            "params": [{"name": "x", "type": "bigint"}],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "ghost"}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;

    // The hard error is raised inside stack lowering; lower_to_stack's
    // catch_unwind boundary converts it into a Result::Err (rather than
    // unwinding the whole process), so it surfaces here as an Err message.
    let err = compile_from_ir_str(ir_json).expect_err("unsatisfiable load_param must be rejected");
    assert!(
        err.contains("Refusing to emit a silent OP_0"),
        "error should be the loud stack-lowering diagnostic, got: {}",
        err
    );
}
