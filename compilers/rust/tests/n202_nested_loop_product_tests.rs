//! N-202: the source path bounds the PRODUCT of nested loop counts, not just
//! each loop's own count.
//!
//! `extract_loop_shape` caps one for-loop at MAX_LOOP_COUNT (10,000). Two loops
//! of 9,000, one inside the other, each passed that cap while the unrolled work
//! was 81,000,000 iterations. F-283 refuses the same nest on the --ir path, so a
//! source contract compiled while its own emitted IR was refused on replay.
//!
//! Proves: on the Rust source path a 101 x 100 nest is refused with the shared
//! product diagnostic, also when the inner loop sits in an if arm, and a nest of
//! exactly 10,000 still compiles. Each compile runs behind a watchdog thread, so
//! a regression fails instead of hanging.
//! Does not prove: the other tiers (conformance/negatives/n202-nested-loop-
//! product-parity.test.ts), or loops reached through a private method call that
//! stack lowering inlines later — the bound is per-method nesting in ANF, the
//! same rule the --ir loader applies.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const WATCHDOG: Duration = Duration::from_secs(60);

const PRODUCT_DIAG: &str = "For loop unrolls to 100 iterations nested inside an enclosing loop of total count 101, producing 10100 total iterations, exceeding the maximum loop count of 10000.";

fn nested_loop_source(outer: u32, inner: u32, in_if_arm: bool) -> String {
    let mut inner_loop = format!("for (let j = 0n; j < {inner}n; j++) {{ acc = acc + x; }}");
    if in_if_arm {
        inner_loop = format!("if (x > 0n) {{ {inner_loop} }}");
    }
    format!(
        r#"import {{ SmartContract, assert }} from 'runar-lang';

export class NestedLoops extends SmartContract {{
  constructor() {{ super(); }}

  public unlock(x: bigint): void {{
    let acc: bigint = 0n;
    for (let i = 0n; i < {outer}n; i++) {{ {inner_loop} }}
    assert(acc > x);
  }}
}}
"#
    )
}

fn compile_guarded(source: String) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let opts = CompileOptions::default();
        let _ = tx.send(
            compile_from_source_str_with_options(&source, Some("NestedLoops.runar.ts"), &opts)
                .map(|artifact| artifact.script),
        );
    });
    match rx.recv_timeout(WATCHDOG) {
        Ok(outcome) => outcome,
        Err(_) => panic!("compile did not finish within {WATCHDOG:?} — nested loops are being unrolled unbounded"),
    }
}

#[test]
fn n202_nested_loop_product_over_max_is_rejected() {
    for in_if_arm in [false, true] {
        match compile_guarded(nested_loop_source(101, 100, in_if_arm)) {
            Ok(_) => panic!("in_if_arm={in_if_arm}: expected the 101 x 100 nest to be refused, got a successful compile"),
            Err(msg) => assert!(
                msg.contains(PRODUCT_DIAG),
                "in_if_arm={in_if_arm}: expected diagnostic {PRODUCT_DIAG:?}, got: {msg}"
            ),
        }
    }
}

#[test]
fn n202_nested_loop_product_at_max_still_compiles() {
    if let Err(msg) = compile_guarded(nested_loop_source(100, 100, false)) {
        panic!("expected the 100 x 100 nest to compile, got: {msg}");
    }
}
