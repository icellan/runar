//! N-046 (ScopeSnatcher) + N-047 (ShadowGoblin) — a block-scoped declaration,
//! or a local of an inlined private helper, that reuses a name already bound in
//! an enclosing scope gets its own ANF identity (user decision R24:
//! alpha-rename, `<name>@<n>`). Port of
//! packages/runar-compiler/src/__tests__/n046-block-scope-alpha-rename.test.ts.
//!
//! `let authorized = checkSig(sig, this.owner); if (trigger) { let authorized
//! = true; } assert(authorized);` bound the inner `let` as `authorized`, the
//! if-arm reconciliation took it for a reassignment of the outer local, and any
//! signature unlocked the coins. An inlined output-emitting helper's local
//! overwrote the caller's the same way.
//!
//! Oracle: alpha-equivalence, from the source language rather than compiler
//! output. Renaming the inner declaration cannot change the program's meaning,
//! so each template compiled with `$L` = the outer name must produce exactly the
//! bytes of `$L` = `fresh`, in both constant-folding modes.
//!
//! Proves: in the Rust tier, an inner `let` in a no-else if-arm, in both arms
//! of an if/else, in a nested if (reassigned there), in a loop body, a loop
//! variable reusing an outer local, an inner `let` reusing a parameter, and an
//! inlined helper local reusing a caller local or parameter all compile like
//! their renamed spellings. Does NOT prove: on-chain behaviour or cross-tier
//! ANF naming (both in
//! packages/runar-testing/src/__tests__/n046-block-scope-spend.test.ts).

use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

fn vault(body: &str) -> String {
    String::from(
        r#"
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class ShadowVault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

"#,
    ) + body
        + "\n}\n"
}

fn payout(body: &str) -> String {
    String::from(
        r#"
import { StatefulSmartContract, ByteString, PubKey, Sig, assert, checkSig, len } from 'runar-lang';

class OwnerPayout extends StatefulSmartContract {
  nonce: bigint;
  readonly owner: PubKey;

  constructor(nonce: bigint, owner: PubKey) {
    super(nonce, owner);
    this.nonce = nonce;
    this.owner = owner;
  }

"#,
    ) + body
        + "\n}\n"
}

fn shapes() -> Vec<(&'static str, &'static str, String)> {
    vec![
        (
            "ScopeSnatcher: inner let in a no-else if-arm",
            "authorized",
            vault(
                r#"  public spend(sig: Sig, trigger: boolean) {
    let authorized = checkSig(sig, this.owner);
    if (trigger) {
      let $L = true;
    }
    assert(authorized);
  }"#,
            ),
        ),
        (
            "ScopeSnatcher: inner const in both arms of an if/else",
            "ok",
            vault(
                r#"  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      const $L = true;
      assert($L);
    } else {
      const $L = x < 0n;
      assert(!$L);
    }
    assert(ok);
  }"#,
            ),
        ),
        (
            "inner let in a nested if, read and reassigned inside its scope",
            "ok",
            vault(
                r#"  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      if (x > 1n) {
        let $L = x > 5n;
        $L = !$L;
        assert($L || x == 7n);
      }
    }
    assert(ok);
  }"#,
            ),
        ),
        (
            "inner let in a loop body",
            "ok",
            vault(
                r#"  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    for (let i = 0n; i < 2n; i++) {
      let $L = x > i;
      assert($L);
    }
    assert(ok);
  }"#,
            ),
        ),
        (
            "loop variable reusing an outer local name",
            "i",
            vault(
                r#"  public spend(sig: Sig, x: bigint) {
    let i = x;
    let acc = 0n;
    for (let $L = 0n; $L < 3n; $L++) {
      acc = acc + $L;
    }
    assert(i == acc);
    assert(checkSig(sig, this.owner));
  }"#,
            ),
        ),
        (
            "inner let reusing a parameter name",
            "x",
            vault(
                r#"  public spend(sig: Sig, x: bigint) {
    if (x > 0n) {
      let $L = 5n;
      assert($L == 5n);
    }
    assert(x == 7n);
    assert(checkSig(sig, this.owner));
  }"#,
            ),
        ),
        (
            "ShadowGoblin: inlined helper local reusing a caller local name",
            "valid",
            payout(
                r#"  public withdraw(sig: Sig, destination: ByteString) {
    const valid = checkSig(sig, this.owner);
    this.pay(destination);
    assert(valid);
  }

  private pay(destination: ByteString) {
    const $L = len(destination) > 0n;
    assert($L);
    this.addRawOutput(50000n, destination);
  }"#,
            ),
        ),
        (
            "inlined helper local reusing a caller parameter name",
            "sig",
            payout(
                r#"  public withdraw(sig: Sig, destination: ByteString) {
    this.pay(destination);
    assert(checkSig(sig, this.owner));
  }

  private pay(destination: ByteString) {
    const $L = len(destination);
    assert($L > 0n);
    this.addRawOutput(50000n, destination);
  }"#,
            ),
        ),
    ]
}

fn hex_of(source: &str, disable_fold: bool) -> Result<String, String> {
    let opts = CompileOptions {
        disable_constant_folding: disable_fold,
        ..CompileOptions::default()
    };
    let r = compile_from_source_str_with_result(source, Some("Shadow.runar.ts"), &opts);
    if !r.success {
        return Err(format!(
            "compile failed: {:?}",
            r.diagnostics
                .iter()
                .map(|d| d.message.clone())
                .collect::<Vec<_>>()
        ));
    }
    Ok(r.script_hex.expect("compiled script hex"))
}

#[test]
fn n046_shadowing_declaration_compiles_like_renamed_spelling() {
    let mut failures = Vec::new();
    for (name, outer, template) in shapes() {
        for disable_fold in [true, false] {
            let shadow = hex_of(&template.replace("$L", outer), disable_fold);
            let control = hex_of(&template.replace("$L", "fresh"), disable_fold);
            if shadow != control {
                failures.push(format!(
                    "{} (disable_fold={}): shadowing {:?} != renamed {:?}",
                    name, disable_fold, shadow, control
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
