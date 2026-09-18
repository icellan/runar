//! Regression tests for CL-BUG-088 / R-009: the unrolled loop iteration count is
//! computed as an arbitrary-precision integer and then narrowed to a machine
//! integer, with nothing bounding the magnitude first.
//!
//! In this tier the narrowing was `count.to_i64().unwrap_or(0).max(0) as usize`.
//! `to_i64()` returns `None` for anything outside the i64 range, so
//! `unwrap_or(0)` turned an astronomically large bound into **zero iterations**:
//! the loop body — which may carry the contract's `assert(checkSig(..))` —
//! vanished from the emitted script, with no diagnostic and an exit status of 0.
//! That is also the mechanism behind CL-BUG-151.
//!
//! The second half of the contract is the ceiling. `MaxLoopCount` (10000)
//! existed only in the Go tier's `--ir` loader; nothing bounded a loop written
//! in source, so a bound of 10001 — or 10^18, which `to_i64()` happily
//! accepts — unrolled without complaint.
//!
//! What these tests pin: an out-of-range or over-ceiling loop bound is a
//! compile-time diagnostic, and a valid loop still compiles to the exact bytes
//! it produced before the guard existed.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

/// Watchdog for a single compile. A bound that `to_i64()` accepts (10^6 here,
/// but nothing stopped 10^18) drives unbounded unrolling, which no assertion
/// can interrupt from the test thread —
/// so the compile runs on its own thread and a regression fails fast instead of
/// wedging CI. Mirrors the Go tier's goroutine-behind-a-watchdog.
const WATCHDOG: Duration = Duration::from_secs(30);

fn loop_bound_source(bound: &str) -> String {
    format!(
        r#"import {{ SmartContract, assert }} from 'runar-lang';

export class LoopBound extends SmartContract {{
  constructor() {{ super(); }}

  public unlock(x: bigint): void {{
    let acc: bigint = 0n;
    for (let i = 0n; i < {bound}n; i++) {{
      acc = acc + i;
    }}
    assert(acc === x);
  }}
}}
"#
    )
}

fn compile_bound(bound: &str, disable_constant_folding: bool) -> Result<String, String> {
    let source = loop_bound_source(bound);
    let opts = CompileOptions {
        disable_constant_folding,
        ..Default::default()
    };
    compile_from_source_str_with_options(&source, Some("LoopBound.runar.ts"), &opts)
        .map(|artifact| artifact.script)
}

/// Run one compile behind the watchdog.
fn compile_bound_guarded(bound: &str) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    let owned = bound.to_string();
    thread::spawn(move || {
        let _ = tx.send(compile_bound(&owned, false));
    });
    match rx.recv_timeout(WATCHDOG) {
        Ok(outcome) => outcome,
        Err(_) => panic!(
            "bound {bound} did not produce a result within {WATCHDOG:?} — the narrowed count is still driving loop unrolling"
        ),
    }
}

fn assert_rejected(outcome: Result<String, String>, label: &str) {
    match outcome {
        Ok(script) => panic!(
            "bound {label}: expected a compile diagnostic, got a successful compile (script {script})"
        ),
        Err(msg) => assert!(
            msg.to_lowercase().contains("loop"),
            "bound {label}: expected a diagnostic mentioning the loop bound, got: {msg}"
        ),
    }
}

/// Control: a normal small bound must keep compiling, and to the exact bytes it
/// produced before the range guard was added. If a guard moves these, the guard
/// is not byte-neutral and the change is a codegen regression, not a fix.
#[test]
fn loop_bound_control_still_compiles_byte_identically() {
    for (bound, hex) in [("3", "537c9c"), ("10", "012d7c9c")] {
        for disable_folding in [false, true] {
            let script = compile_bound(bound, disable_folding)
                .unwrap_or_else(|e| panic!("bound={bound} foldOff={disable_folding}: {e}"));
            assert_eq!(
                script, hex,
                "bound={bound} foldOff={disable_folding}: script hex changed"
            );
        }
    }
}

/// 2^63 — the first value outside i64. `to_i64()` returns `None`, `unwrap_or(0)`
/// makes it zero iterations, and the loop body disappears.
#[test]
fn loop_bound_2_pow_63_is_rejected() {
    assert_rejected(compile_bound_guarded("9223372036854775808"), "2^63");
}

/// 2^64 + 10 — same silent-drop mechanism, and it must not be mistaken for the
/// modular-wrap outcome the Go tier had at the same magnitude.
#[test]
fn loop_bound_2_pow_64_plus_10_is_rejected() {
    let outcome = compile_bound_guarded("18446744073709551626");
    if let Ok(script) = &outcome {
        assert_ne!(
            script, "012d7c9c",
            "bound 2^64+10 compiled to the same bytes as bound 10"
        );
    }
    assert_rejected(outcome, "2^64+10");
}

/// 10^20 — still outside i64, still silently zero before the fix.
#[test]
fn loop_bound_10_pow_20_is_rejected_without_hanging() {
    assert_rejected(compile_bound_guarded("100000000000000000000"), "10^20");
}

/// The ceiling half of the fix. 10001 fits every machine integer there is, so no
/// amount of narrowing care stops it — only MAX_LOOP_COUNT on the SOURCE path
/// does. Same for 10^6, which `to_i64()` accepts and which — like the 10^18 the
/// old code also accepted — would otherwise unroll for as long as it took; the
/// watchdog above is what makes that case safe to run.
#[test]
fn loop_bound_exceeding_max_loop_count_is_rejected_on_source_path() {
    for bound in ["10001", "1000000"] {
        let outcome = compile_bound_guarded(bound);
        assert_rejected(outcome.clone(), bound);
        let msg = outcome.unwrap_err();
        assert!(
            msg.contains("10000"),
            "bound {bound}: expected the diagnostic to name the maximum loop count, got: {msg}"
        );
    }
}
