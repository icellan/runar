//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n051-branch-arm-private-helper.test.ts`.
//!
//! N-051 — a private-helper call inside a BRANCH ARM must inline the callee.
//!
//! `spec/semantics.md` §6.3 defines a private method as source-level
//! substitution at every call site, and its canonical example is a helper call
//! in EXPRESSION position:
//!
//! ```text
//!   private square(x: bigint): bigint { return x * x; }
//!   public verify(n: bigint): void { assert(this.square(n) < 100n); }
//!   // After inlining:
//!   public verify(n: bigint): void { assert(n * n < 100n); }
//! ```
//!
//! `spec/ir-format.md` §4.7 keeps `method_call` in the canonical ANF ("Inlining
//! happens in a later compiler phase"), so the substitution is stack lowering's
//! job — and stack lowering lowers an `if`'s arms in a FRESH context.
//!
//! The defect: `codegen/stack.rs`'s `lower_if` built `then_ctx` / `else_ctx`
//! with `LoweringContext::new`, which initialises `private_methods` to an EMPTY
//! map, and never copied `self.private_methods` into them. Inside an arm the
//! callee was therefore unknown and Rust REJECTED the program:
//!
//! ```text
//!   const v: bigint = p > 0n ? this.bump(p) : 0n;   // bump(x) = x + 1n
//!
//!   ts / zig / ruby / java   7600a0638b6700776800a2         (correct)
//!   go                       7600a063006700776800a2         (silently wrong)
//!   python                   7600a063007c00776700776800a2   (silently wrong)
//!   rust                     rejected: "unknown function 'bump'"
//! ```
//!
//! Rust's rejection was the harmless end of the same bug. Go and Python
//! ACCEPTED and emitted a script that never evaluates the helper — `OP_0` where
//! the source says `OP_1ADD` — so the covenant deploys and the arm computes a
//! value the contract never asked for.
//!
//! This is the branch-lowering arm contract (NEW-014 / NEW-018) again: an arm
//! context is constructed fresh, so every field it needs has to be re-plumbed
//! by hand. `script_level_code_separator` was re-plumbed by R-010 and
//! `renamed_params` by issue #130 — both with a comment at the copy site.
//! `private_methods` was missed. TS, Ruby and Java already copied it, which is
//! exactly why those tiers were correct.
//!
//! The hexes are the SEVEN-TIER agreed output. Every tier pins the same
//! strings, which is what makes this a parity gate: a tier that lowers the fix
//! differently fails its own test.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const PRELUDE: &str = r#"import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }
"#;

/// Helper called from a ternary arm.
const TERNARY_ARM_BODY_PLUS_1: &str = r#"  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    const v: bigint = p > 0n ? this.bump(p) : 0n;
    assert(v >= this.s);
  }
}
"#;

/// Same shape, different callee body — the body-independence probe.
const TERNARY_ARM_BODY_PLUS_2: &str = r#"  private bump(x: bigint): bigint { return x + 2n; }

  public m(p: bigint): void {
    const v: bigint = p > 0n ? this.bump(p) : 0n;
    assert(v >= this.s);
  }
}
"#;

/// Control: the same program with the helper inlined by hand.
const TERNARY_ARM_MANUAL_INLINE_BODY: &str = r#"  public m(p: bigint): void {
    const v: bigint = p > 0n ? p + 1n : 0n;
    assert(v >= this.s);
  }
}
"#;

/// Helper called from an `if` STATEMENT arm.
const IF_STATEMENT_ARM_BODY: &str = r#"  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    let v: bigint = 0n;
    if (p > 0n) {
      v = this.bump(p);
    } else {
      v = 0n;
    }
    assert(v >= this.s);
  }
}
"#;

/// Control: the same `if` with no helper call in either arm.
const IF_STATEMENT_ARM_NO_HELPER_BODY: &str = r#"  public m(p: bigint): void {
    let v: bigint = 0n;
    if (p > 0n) {
      v = p + 1n;
    } else {
      v = 0n;
    }
    assert(v >= this.s);
  }
}
"#;

/// Control: a helper call in ordinary statement position, outside any arm.
const STATEMENT_POSITION_BODY: &str = r#"  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    const v: bigint = this.bump(p);
    assert(v >= this.s);
  }
}
"#;

fn contract(body: &str) -> String {
    format!("{}{}", PRELUDE, body)
}

fn compile_script_hex(source: &str, disable_constant_folding: bool) -> String {
    let opts = CompileOptions {
        disable_constant_folding,
        ..CompileOptions::default()
    };
    match compile_from_source_str_with_options(source, Some("C.runar.ts"), &opts) {
        Ok(artifact) => artifact.script,
        Err(e) => panic!("compilation failed: {}", e),
    }
}

#[test]
fn seven_tier_script_for_branch_arm_private_helper() {
    let cases: &[(&str, &str, &str)] = &[
        ("ternary-arm/+1", TERNARY_ARM_BODY_PLUS_1, "7600a0638b6700776800a2"),
        ("ternary-arm/+2", TERNARY_ARM_BODY_PLUS_2, "7600a06352936700776800a2"),
        (
            "ternary-arm-manual-inline",
            TERNARY_ARM_MANUAL_INLINE_BODY,
            "7600a0638b6700776800a2",
        ),
        (
            "if-statement-arm",
            IF_STATEMENT_ARM_BODY,
            "007800a0637c8b767676537a757777670076537a7577687c7500a2",
        ),
        (
            "if-statement-arm-no-helper",
            IF_STATEMENT_ARM_NO_HELPER_BODY,
            "007800a0637c8b7677670076537a7577687c7500a2",
        ),
        ("statement-position", STATEMENT_POSITION_BODY, "8b00a2"),
    ];

    for (label, body, want) in cases {
        let source = contract(body);
        for disable in [true, false] {
            let got = compile_script_hex(&source, disable);
            assert_eq!(
                &got, want,
                "{} (disable_constant_folding={}): script hex diverged from the seven-tier agreed output",
                label, disable
            );
        }
    }
}

/// `spec/semantics.md` §6.3: inlining IS substitution, so a helper call in a
/// ternary arm and the hand-substituted program are the same program.
#[test]
fn ternary_arm_matches_manual_inline() {
    let with_helper = contract(TERNARY_ARM_BODY_PLUS_1);
    let manual = contract(TERNARY_ARM_MANUAL_INLINE_BODY);
    for disable in [true, false] {
        assert_eq!(
            compile_script_hex(&with_helper, disable),
            compile_script_hex(&manual, disable),
            "helper-in-arm and hand-inlined source differ (disable_constant_folding={})",
            disable
        );
    }
}

/// The tier-independent oracle. No reference tier is consulted: a compiler that
/// emits the same bytes for `x + 1n` and `x + 2n` has dropped the callee body,
/// whatever its peers do.
#[test]
fn callee_body_reaches_the_arm() {
    let plus1 = contract(TERNARY_ARM_BODY_PLUS_1);
    let plus2 = contract(TERNARY_ARM_BODY_PLUS_2);
    for disable in [true, false] {
        assert_ne!(
            compile_script_hex(&plus1, disable),
            compile_script_hex(&plus2, disable),
            "two different helper bodies compiled to the same script (disable_constant_folding={})",
            disable
        );
    }
}
