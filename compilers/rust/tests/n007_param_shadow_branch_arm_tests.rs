//! Port of packages/runar-compiler/src/__tests__/n007-param-shadow-branch-arm.test.ts.
//!
//! N-007 — a method parameter that shadows a MUTABLE property must stay the
//! parameter inside an `if` / ternary arm.
//!
//! Issue #130 (stack layer): `deserialize_state` pushes each mutable property
//! under its own name, so `LoweringContext::new` renames a same-named method
//! parameter's slot to `__param_<name>` and records it in `renamed_params`;
//! `lower_load_param` resolves through that map.
//!
//! The defect: `lower_if` built `then_ctx` / `else_ctx` with
//! `LoweringContext::new`, whose `renamed_params` starts EMPTY. The arm's
//! cloned stack still carries the `__param_<name>` slot, so a `load_param`
//! inside the arm resolved the bare name to the deserialized PROPERTY slot —
//! the stale on-chain state — instead of the caller's witness argument:
//!
//! ```text
//! public set(count: bigint, flag: boolean) {
//!   if (flag) { assert(count == 5n); }     // arm read this.count (stale)
//!   this.count = count;
//! }
//! ```
//!
//! With on-chain count = 5, `set(7n, true)` passed a guard the source says
//! must fail. Real-engine proof:
//! packages/runar-testing/src/__tests__/n007-param-shadow-branch-arm-vm.test.ts.
//!
//! Oracle (needs no reference tier): a parameter's NAME is not part of the
//! program, so alpha-renaming `count` -> `newCount` must give byte-identical
//! script.
//!
//! Proves: Rust resolves a shadowing parameter to the same slot inside an
//! if-then arm, an if-else arm and a ternary arm as for a non-colliding name,
//! in both fold modes. Does NOT prove: that the renamed program is itself
//! correct on-chain (the VM test), or anything about other tiers.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const PRELUDE: &str = "import { StatefulSmartContract, assert } from 'runar-lang';

class Probe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

";

const THEN_ARM: &str = "  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(count == 5n);
    }
    this.count = count;
  }
}
";

const ELSE_ARM: &str = "  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(flag);
    } else {
      assert(count > 10n);
    }
    this.count = count;
  }
}
";

const TERNARY_ARM: &str = "  public set(count: bigint, flag: boolean) {
    const v: bigint = flag ? count + 1n : 0n;
    assert(v != 3n);
    this.count = count;
  }
}
";

/// Control: the parameter is read only OUTSIDE any arm (already correct before
/// the fix; pins that the oracle is not vacuous).
const NO_ARM: &str = "  public set(count: bigint, flag: boolean) {
    assert(count != 3n);
    assert(flag);
    this.count = count;
  }
}
";

fn alpha_rename(body: &str) -> String {
    body.replacen("set(count: bigint", "set(newCount: bigint", 1)
        .replacen("this.count = count;", "this.count = newCount;", 1)
        .replacen("(count ", "(newCount ", 1)
        .replacen("? count ", "? newCount ", 1)
}

fn compile_hex(body: &str, disable_constant_folding: bool) -> String {
    let opts = CompileOptions {
        disable_constant_folding,
        ..CompileOptions::default()
    };
    let source = format!("{}{}", PRELUDE, body);
    match compile_from_source_str_with_options(&source, Some("Probe.runar.ts"), &opts) {
        Ok(artifact) => artifact.script,
        Err(e) => panic!("compilation failed: {}", e),
    }
}

#[test]
fn shadowing_param_is_alpha_equivalent_in_branch_arm() {
    let cases: &[(&str, &str)] = &[
        ("then-arm", THEN_ARM),
        ("else-arm", ELSE_ARM),
        ("ternary-arm", TERNARY_ARM),
        ("control/no-arm", NO_ARM),
    ];
    let mut failures = Vec::new();
    for (label, body) in cases {
        let renamed = alpha_rename(body);
        // The rename must have removed every read of the shadowing name: the
        // only `count` left is the property access `this.count`.
        for (i, _) in renamed.match_indices("count") {
            assert!(
                i > 0 && renamed.as_bytes()[i - 1] == b'.',
                "alpha-rename left a read of the shadowing name:\n{}",
                renamed
            );
        }
        for disable in [true, false] {
            let got = compile_hex(body, disable);
            let want = compile_hex(&renamed, disable);
            if got != want {
                failures.push(format!(
                    "{} (fold-{}): a parameter that shadows mutable property 'count' compiled \
                     differently from the renamed program — the arm read the deserialized state \
                     slot, not the witness argument",
                    label,
                    if disable { "off" } else { "on" }
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
