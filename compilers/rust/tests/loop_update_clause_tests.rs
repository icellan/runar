//! R-029 / CL-BUG-008 regression guard for the Rust tier: the for-loop
//! `update` clause was parsed, carried through the whole AST, and then
//! **never type-checked and never lowered**.
//!
//! `typecheck.rs`'s `Statement::ForStatement` arm destructured
//! `{ init, condition, body, .. }` — the `update` field fell into the rest
//! pattern and no pass ever looked at the expression inside it. `validator.rs`
//! did the same. So the clause was a hole in the language's central invariant
//! (CLAUDE.md: "the type checker rejects calls to unknown functions like
//! `Math.floor()` or `console.log()`"): anything at all could be written
//! there and the contract compiled clean with exit status 0.
//!
//! Three observed shapes, all against the `bounded-loop` contract whose
//! correct script is 42 bytes:
//!
//!   * `for (let i = 0n; i < 5n; undefinedFn())` — compiled to **byte-identical
//!     output**. A typo'd or nonexistent function name produced no diagnostic.
//!   * `for (let i = 0n; i < 5n; this.count++)` — a write to contract state
//!     written in the update clause is silently DROPPED from the emitted
//!     script. The ANF carries no `update_prop` for it.
//!   * `for (int i = 0; i < 6; i += 2)` (Solidity frontend) — a non-unit step
//!     is silently coerced to `i++`, so the loop unrolled 6 times over
//!     i = 0,1,2,3,4,5 instead of 3 times over i = 0,2,4. The same family as
//!     the Go tier's CL-BUG-128.
//!
//! **Why the fix rejects rather than lowers.** The ANF `loop` node can express
//! exactly `{ count, iter_var, start, step, body }`: the iterator is
//! synthesized on each unrolled iteration as `start + i * step`. There is no
//! slot for an arbitrary update statement, and appending the update's lowering
//! to the tail of the body would re-emit `i++` as a dead binding for every
//! loop that already compiles correctly — moving bytes for the whole corpus to
//! express nothing. The loop model only ever supported a unit step; the defect
//! was that everything else was *accepted* instead of *refused*. So the fix
//! makes the accepted set explicit and rejects the rest with a diagnostic.
//!
//! The accepted set is every shape the seven frontends in this tier actually
//! synthesize for a bounded loop:
//!   * `i++` / `i--` / `++i` / `--i`            (ts, sol, move-fold, go, java,
//!                                               python, ruby, rust-macro)
//!   * `i = i + 1` / `i = i - 1` / `i = 1 + i`  (sol `i += 1`, zig
//!                                               `while (c) : (i += 1)`, java)
//!   * an effect-free literal or bare identifier — the no-op sentinel that the
//!     zig / move / go while-shaped parsers synthesize when the source has no
//!     continue expression at all.
//!
//! What these tests do NOT prove: nothing here says the update clause is
//! *lowered*; the contract is precisely that a non-representable update is a
//! compile error instead of silent output. And the controls pin only the
//! `bounded-loop` shape — they show the fix refuses nothing that compiled
//! before, not that every loop in the corpus is unaffected (the conformance
//! goldens cover that).

use std::path::PathBuf;

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

/// The one correct answer. `bounded-loop` sums `start + i` for i in 0..5 and
/// asserts the total; all nine frontends lower to these exact 42 bytes.
const BOUNDED_LOOP_HEX: &str =
    "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c";

fn example(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("failed to read {:?}: {}", p, e))
}

fn compile(source: &str, file_name: &str) -> Result<String, String> {
    compile_from_source_str_with_options(source, Some(file_name), &CompileOptions::default())
        .map(|artifact| artifact.script)
}

/// A stateful contract with one mutable property, parameterised on the
/// for-loop update clause.
fn ts_with_update(update: &str) -> String {
    format!(
        r#"import {{ StatefulSmartContract, assert }} from 'runar-lang';

export class UpdateProbe extends StatefulSmartContract {{
  count: bigint;

  constructor(count: bigint) {{ super(count); this.count = count; }}

  public unlock(expected: bigint): void {{
    let acc: bigint = 0n;
    for (let i = 0n; i < 3n; {update}) {{
      acc = acc + i;
    }}
    assert(acc === expected);
  }}
}}
"#
    )
}

fn sol_with_update(bound: &str, update: &str) -> String {
    example("examples/sol/bounded-loop/BoundedLoop.runar.sol")
        .replace("i < 5", bound)
        .replace("i++", update)
}

// ---------------------------------------------------------------------------
// The defect: the update clause accepts anything
// ---------------------------------------------------------------------------

/// The sharpest form. `undefinedFn` does not exist — not a Rúnar builtin, not
/// a contract method — and the update clause let it through.
#[test]
fn update_calling_an_undefined_function_is_rejected() {
    let err = compile(&ts_with_update("undefinedFn()"), "UpdateProbe.runar.ts").expect_err(
        "a for-loop update clause calling an undefined function must not compile: \
         the type checker's unknown-function rule has to reach inside the update",
    );
    assert!(
        !err.trim().is_empty(),
        "rejection must carry a diagnostic, got an empty message"
    );
}

/// CLAUDE.md names `console.log` explicitly as a call the type checker rejects.
/// It did — everywhere except the update clause.
#[test]
fn update_calling_console_log_is_rejected() {
    compile(&ts_with_update("console.log(i)"), "UpdateProbe.runar.ts").expect_err(
        "`console.log` in a for-loop update clause must be rejected like it is anywhere else",
    );
}

/// The silent-drop half. `this.count++` in the update position is a write to
/// contract state that never reaches the emitted script.
#[test]
fn update_with_a_state_side_effect_is_rejected_not_dropped() {
    compile(&ts_with_update("this.count++"), "UpdateProbe.runar.ts").expect_err(
        "a state mutation in the update clause is not representable in the ANF loop node, \
         so it must be a compile error — silently dropping it is what this test forbids",
    );
}

/// Same family as the Go tier's CL-BUG-128: a non-unit step is coerced to
/// `i++`. Reached through the Solidity frontend because this tier's TypeScript
/// parser rejects `i += 2n` in expression position for unrelated reasons.
#[test]
fn non_unit_step_update_is_rejected_not_coerced() {
    let coerced = compile(&sol_with_update("i < 6", "i += 2"), "BoundedLoop.runar.sol");
    match coerced {
        Err(_) => {}
        Ok(hex) => panic!(
            "`i += 2` must not compile: it silently unrolled with step 1 \
             ({} iterations' worth of script, {} hex chars)",
            6,
            hex.len()
        ),
    }
}

// ---------------------------------------------------------------------------
// Controls: every shape that compiles today must still compile, byte-identical
// ---------------------------------------------------------------------------

/// `i++` — the canonical form, and the one both for-loops in the whole corpus
/// use.
#[test]
fn control_ts_increment_is_byte_identical() {
    let hex = compile(
        &example("examples/ts/bounded-loop/BoundedLoop.runar.ts"),
        "BoundedLoop.runar.ts",
    )
    .expect("the plain `i++` bounded loop must compile");
    assert_eq!(hex, BOUNDED_LOOP_HEX, "`i++` lowering must not move bytes");
}

/// `i += 1` through the Solidity frontend lands as
/// `Assignment { target: i, value: i + 1 }` — a different AST shape than `i++`
/// that the accepted set has to keep.
#[test]
fn control_sol_compound_assign_unit_step_is_byte_identical() {
    let hex = compile(&sol_with_update("i < 5", "i += 1"), "BoundedLoop.runar.sol")
        .expect("`i += 1` is a unit step and must still compile");
    assert_eq!(hex, BOUNDED_LOOP_HEX);
}

/// Zig has no C-style `for`; `while (i < 5) : (i += 1)` is folded into a
/// ForStatement whose update is the assignment form.
#[test]
fn control_zig_while_continue_expression_is_byte_identical() {
    let hex = compile(
        &example("examples/zig/bounded-loop/BoundedLoop.runar.zig"),
        "BoundedLoop.runar.zig",
    )
    .expect("the zig while-with-continue-expression bounded loop must compile");
    assert_eq!(hex, BOUNDED_LOOP_HEX);
}

/// Move folds a trailing `i = i + 1` out of the while body into the update
/// slot as an `IncrementExpr`.
#[test]
fn control_move_while_fold_is_byte_identical() {
    let hex = compile(
        &example("examples/move/bounded-loop/BoundedLoop.runar.move"),
        "BoundedLoop.runar.move",
    )
    .expect("the move while-fold bounded loop must compile");
    assert_eq!(hex, BOUNDED_LOOP_HEX);
}

/// A countdown loop: `i--` with `>`. Guards against an accepted-set that only
/// understands counting up.
#[test]
fn control_ts_countdown_still_compiles() {
    let source = r#"import { SmartContract, assert } from 'runar-lang';

export class Countdown extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) { super(expected); this.expected = expected; }

  public verify(start: bigint): void {
    let sum: bigint = 0n;
    for (let i = 3n; i > 0n; i--) {
      sum = sum + start + i;
    }
    assert(sum === this.expected);
  }
}
"#;
    compile(source, "Countdown.runar.ts").expect("a countdown loop must still compile");
}
