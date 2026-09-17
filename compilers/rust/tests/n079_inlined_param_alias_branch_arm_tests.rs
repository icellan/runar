//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n079-inlined-param-alias-branch-arm.test.ts`.
//!
//! N-079 — the inlined argument alias must survive into a branch arm.
//!
//! `spec/semantics.md` §6.3 defines a private method as source-level
//! substitution at every call site. So this:
//!
//! ```text
//! private pay(v: bigint): void { ...uses v... }
//! public  go(v: bigint) { this.pay(v * 2n); }
//! ```
//!
//! and the hand-substituted program (`const a = v * 2n;` then the body with `a`
//! in place of `v`) are the SAME program and must compile to the same script.
//! That is an oracle needing no reference tier.
//!
//! The defect, in the five tiers that had it: `inline_private_method_call`
//! pushes the caller's argument refs onto the CURRENT lowering context and then
//! lowers the private method's body into it. When that body contains an `if` /
//! `for` / ternary, the arm is built by a FRESH sub-context. TS, Python, Zig,
//! Ruby and Java did not copy the alias stack into it, so a read of the
//! private's parameter inside the arm found no alias and fell through to
//! `load_param`, resolving to the CALLER's same-named parameter instead of the
//! argument that was passed in. The covenant's output amount became `v + 100`
//! where the source says `(v * 2) + 100`.
//!
//! RUST IS A REFERENCE HERE and needed no change. This test pins Rust to the
//! seven-tier table so that a future edit to its sub-context construction is
//! caught here rather than by a cross-tier divergence.
//!
//! Measured on the pre-fix HEAD, `--disable-constant-folding`:
//!
//! ```text
//!                go   rust  python  zig  ruby  java  ts
//! hand-inlined   705   705    705   705   705   705  705
//! via helper     705   705    703   703   703   703  703
//! ```
//!
//! The (byte length, sha256-of-hex) pairs below are the SEVEN-TIER agreed
//! output; every tier pins the same table. The scripts are ~700 B (a stateful
//! covenant — the ANF-level inliner only fires for a helper that emits
//! outputs), so they are pinned by digest rather than inline.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};
use sha2::{Digest, Sha256};

const PRELUDE: &str = r#"import { StatefulSmartContract, assert } from "runar-lang";

class C extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

"#;

fn contract(body: &str) -> String {
    format!("{}{}", PRELUDE, body)
}

/// The item's probe: a helper containing an `if`, called with `v * 2n`.
const IF_ARM_BODY: &str = r#"  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 100n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
"#;

/// §6.3 control: the same program with the helper substituted by hand.
const IF_ARM_MANUAL_BODY: &str = r#"  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    let extra: bigint = 0n;
    if (a > 5n) {
      extra = a + 100n;
    } else {
      extra = a + 1n;
    }
    this.addOutput(extra, this.count);
    assert(v >= 0n);
  }
}
"#;

/// N-051 oracle: differs from `IF_ARM_BODY` ONLY inside the then-arm.
const IF_ARM_200_BODY: &str = r#"  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 200n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
"#;

/// Same hazard through a ternary arm.
const TERNARY_ARM_BODY: &str = r#"  private pay(v: bigint): void {
    const extra: bigint = v > 5n ? v + 100n : v + 1n;
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
"#;

const TERNARY_ARM_MANUAL_BODY: &str = r#"  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    const extra: bigint = a > 5n ? a + 100n : a + 1n;
    this.addOutput(extra, this.count);
    assert(v >= 0n);
  }
}
"#;

/// Same hazard through a `for` body — a sub-context builds that too.
const LOOP_BODY_BODY: &str = r#"  private pay(v: bigint): void {
    let acc: bigint = 0n;
    for (let i = 0; i < 3; i++) {
      acc = acc + v;
    }
    this.addOutput(acc, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
"#;

const LOOP_BODY_MANUAL_BODY: &str = r#"  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    let acc: bigint = 0n;
    for (let i = 0; i < 3; i++) {
      acc = acc + a;
    }
    this.addOutput(acc, this.count);
    assert(v >= 0n);
  }
}
"#;

/// Control: a helper with NO nested block at all. Must be byte-unchanged.
const NO_IF_BODY: &str = r#"  private pay(v: bigint): void {
    const extra: bigint = v + 100n;
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
"#;

/// Control: the parameter is read at STATEMENT level inside the helper, and the
/// `if` in the helper does not read it. Must be byte-unchanged.
const STMT_LEVEL_BODY: &str = r#"  private pay(v: bigint): void {
    const extra: bigint = v + 100n;
    let bump: bigint = 0n;
    if (this.count > 5n) {
      bump = 1n;
    } else {
      bump = 2n;
    }
    this.addOutput(extra + bump, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
"#;

/// Control: the argument IS the caller's own parameter (`this.pay(v)`), so
/// caller-param and argument coincide and the WRONG lowering computed the right
/// VALUE. It was still a different script — 701 B in the five broken tiers
/// where Go/Rust emitted 703 — because the arm re-issued `load_param` instead
/// of reading the alias slot.
const PASSTHROUGH_BODY: &str = r#"  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 100n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v);
    assert(v >= 0n);
  }
}
"#;

fn compile_script_hex(source: &str, disable_constant_folding: bool) -> String {
    let opts = CompileOptions {
        disable_constant_folding,
        ..CompileOptions::default()
    };
    match compile_from_source_str_with_options(source, Some("C.runar.ts"), &opts) {
        Ok(artifact) => artifact.script.to_lowercase(),
        Err(e) => panic!("compilation failed: {}", e),
    }
}

fn digest(script_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(script_hex.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[test]
fn seven_tier_script_for_inlined_param_alias() {
    let cases: &[(&str, &str, usize, &str)] = &[
        (
            "if-arm",
            IF_ARM_BODY,
            708,
            "d0499caa79ff3d89a84a9830ab35dec5822ef4f8bdb613f190bad0f9cb9a8470",
        ),
        (
            "if-arm-manual",
            IF_ARM_MANUAL_BODY,
            708,
            "d0499caa79ff3d89a84a9830ab35dec5822ef4f8bdb613f190bad0f9cb9a8470",
        ),
        (
            "if-arm-200",
            IF_ARM_200_BODY,
            709,
            "76b75efe60492121334561aa1f44639aa538efac39f0c8c078a68b7ecccc935e",
        ),
        (
            "ternary-arm",
            TERNARY_ARM_BODY,
            694,
            "697a10519f0ac738ff497312c9b2ca5e601d135a793e5f22b21e4501a1931cde",
        ),
        (
            "ternary-arm-manual",
            TERNARY_ARM_MANUAL_BODY,
            694,
            "697a10519f0ac738ff497312c9b2ca5e601d135a793e5f22b21e4501a1931cde",
        ),
        (
            "loop-body",
            LOOP_BODY_BODY,
            701,
            "7ca33e902cbc9ccb0431b2c29d66c0db63856619579ae5f2661202f635dc5f6a",
        ),
        (
            "loop-body-manual",
            LOOP_BODY_MANUAL_BODY,
            701,
            "7ca33e902cbc9ccb0431b2c29d66c0db63856619579ae5f2661202f635dc5f6a",
        ),
        (
            "no-if",
            NO_IF_BODY,
            686,
            "7ac476f9ac2eaac74d9b7d6ec51483a1ef7fe8f267998ff371728b5408511300",
        ),
        (
            "stmt-level",
            STMT_LEVEL_BODY,
            704,
            "c7df31bb403a85a97117ba27f16da98b58068b9ffc5be12dbd3d76d0a5ae0c79",
        ),
        (
            "passthrough",
            PASSTHROUGH_BODY,
            706,
            "8826b46db122ecd01f584ff3148ef7f24d9dd948088bd97cee4c086235efdd56",
        ),
    ];

    for (label, body, want_len, want_sha) in cases {
        let source = contract(body);
        for disable in [true, false] {
            let got = compile_script_hex(&source, disable);
            assert_eq!(
                got.len() / 2,
                *want_len,
                "{} (disable_constant_folding={}): script length diverged from the seven-tier agreed output",
                label,
                disable
            );
            assert_eq!(
                &digest(&got),
                want_sha,
                "{} (disable_constant_folding={}): script bytes diverged from the seven-tier agreed output",
                label,
                disable
            );
        }
    }
}

/// `spec/semantics.md` §6.3: inlining IS substitution, so the helper form and
/// the hand-substituted program are the same program.
#[test]
fn helper_matches_manual_inline() {
    let cases: &[(&str, &str, &str)] = &[
        ("if", IF_ARM_BODY, IF_ARM_MANUAL_BODY),
        ("ternary", TERNARY_ARM_BODY, TERNARY_ARM_MANUAL_BODY),
        ("for", LOOP_BODY_BODY, LOOP_BODY_MANUAL_BODY),
    ];
    for (kind, helper_body, manual_body) in cases {
        let helper = contract(helper_body);
        let manual = contract(manual_body);
        for disable in [true, false] {
            assert_eq!(
                compile_script_hex(&helper, disable),
                compile_script_hex(&manual, disable),
                "helper with a nested {} diverged from the hand-inlined source (disable_constant_folding={})",
                kind,
                disable
            );
        }
    }
}

/// The N-051 oracle, consulting no reference tier: two helper bodies that
/// differ ONLY inside the arm must not compile to the same script.
#[test]
fn arm_reads_the_argument() {
    let plus100 = contract(IF_ARM_BODY);
    let plus200 = contract(IF_ARM_200_BODY);
    for disable in [true, false] {
        assert_ne!(
            compile_script_hex(&plus100, disable),
            compile_script_hex(&plus200, disable),
            "two helper bodies differing only inside the arm compiled to the same script (disable_constant_folding={})",
            disable
        );
    }
}
