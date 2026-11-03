//! N-016 — a local that shares a contract property's name must never capture a
//! later `this.<prop>` read or write (user decision R8: correct scoping). Port
//! of packages/runar-compiler/src/__tests__/n016-property-shadow-scoping.test.ts.
//!
//! `const target = n + 1n; assert(target == this.target);` compiled to 8b769c
//! (OP_1ADD OP_DUP OP_NUMEQUAL): the property read resolved by name to the
//! local's stack slot, an always-true self-comparison.
//!
//! Oracle: alpha-equivalence, from the source language rather than compiler
//! output. Renaming a local / private-helper param / public param to a fresh
//! name cannot change the program's meaning, so each template compiled with
//! `$L` = the property's name must produce exactly the bytes of `$L` = `lcl`,
//! in both constant-folding modes.
//!
//! Proves: in the Rust tier, property-named locals (top level, if-arm, nested
//! block, loop variable, ++, byte-typed, inside a private helper), a private
//! helper's param and a public param never capture `this.<prop>`; stateful
//! property reads/writes and the continuation are unaffected by a same-named
//! local, including an if whose arms rebind the local and write the property.
//! Does NOT prove: on-chain behaviour (see
//! packages/runar-testing/src/__tests__/n016-property-shadow-spend.test.ts) or
//! local-vs-compiler-temp collisions (a local literally named `t3`).

use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

fn stateless(body: &str, prop_type: &str) -> String {
    format!(
        "import {{ SmartContract, assert, cat, ByteString }} from 'runar-lang';

class Shadow extends SmartContract {{
  readonly target: {t};
  constructor(target: {t}) {{
    super(target);
    this.target = target;
  }}

{body}
}}
",
        t = prop_type,
        body = body
    )
}

fn stateful(body: &str) -> String {
    format!(
        "import {{ StatefulSmartContract, assert }} from 'runar-lang';

class Shadow extends StatefulSmartContract {{
  count: bigint;

  constructor(count: bigint) {{
    super(count);
    this.count = count;
  }}

{body}
}}
",
        body = body
    )
}

fn shapes() -> Vec<(&'static str, &'static str, String)> {
    vec![
        ("local at method top level", "target", stateless("  public unlock(n: bigint) {
    const $L = n + 1n;
    assert($L == this.target);
  }", "bigint")),
        ("local inside an if-arm", "target", stateless("  public unlock(n: bigint) {
    if (n > 0n) {
      const $L = n + 1n;
      assert($L == this.target);
    } else {
      assert(n == this.target);
    }
  }", "bigint")),
        ("local inside a nested block", "target", stateless("  public unlock(n: bigint) {
    if (n > 0n) {
      if (n > 1n) {
        const $L = n + 1n;
        assert($L == this.target);
      } else {
        assert(n + 2n == this.target);
      }
    } else {
      assert(false);
    }
  }", "bigint")),
        ("loop variable", "target", stateless("  public unlock(n: bigint) {
    let acc = 0n;
    for (let $L = 0n; $L < 2n; $L++) {
      acc = acc + this.target - $L;
    }
    assert(acc == n);
  }", "bigint")),
        ("local mutated with ++", "target", stateless("  public unlock(n: bigint) {
    let $L = n;
    $L++;
    assert($L == this.target);
  }", "bigint")),
        ("byte-typed local", "target", stateless("  public unlock(a: ByteString) {
    const $L = cat(a, a);
    assert($L == this.target);
  }", "ByteString")),
        ("local inside a private helper", "target", stateless("  private chk(n: bigint): boolean {
    const $L = n + 1n;
    return $L == this.target;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }", "bigint")),
        ("private helper parameter", "target", stateless("  private chk($L: bigint): boolean {
    return this.target == $L + 1n;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }", "bigint")),
        ("public parameter, property read first", "target", stateless("  public unlock($L: bigint) {
    assert(this.target == $L + 1n);
  }", "bigint")),
        ("stateful: local, then property read + write", "count", stateful("  public bump(n: bigint) {
    const $L = n * 2n;
    this.count = this.count + $L;
    assert($L > 0n);
  }")),
        ("stateful: local live across a property write", "count", stateful("  public bump(n: bigint) {
    let $L = n;
    this.count = this.count + 1n;
    assert(this.count > $L);
  }")),
        ("stateful: if-arms rebind the local and write the property", "count", stateful("  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      $L = $L + 1n;
      this.count = this.count + $L;
    } else {
      this.count = this.count + 1n;
    }
  }")),
        ("stateful: an if-arm writes the property, then rebinds the local read after the if", "count", stateful("  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      this.count = this.count + $L;
      $L = $L + 1n;
    } else {
      this.count = this.count + 1n;
    }
    assert($L > 0n);
  }")),
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
            r.diagnostics.iter().map(|d| d.message.clone()).collect::<Vec<_>>()
        ));
    }
    Ok(r.script_hex.expect("compiled script hex"))
}

#[test]
fn n016_probe_no_longer_self_compares() {
    let src = shapes()[0].2.replace("$L", "target");
    assert_eq!(hex_of(&src, true).unwrap(), "8b009c");
}

#[test]
fn n016_shadowing_compiles_like_renamed_spelling() {
    let mut failures = Vec::new();
    for (name, prop, template) in shapes() {
        for disable_fold in [true, false] {
            let shadow = hex_of(&template.replace("$L", prop), disable_fold);
            let control = hex_of(&template.replace("$L", "lcl"), disable_fold);
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
