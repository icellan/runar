//! constructorArgs shape/key validation — port of the TypeScript
//! `constructor-args-validation.test.ts` (PR #113, fix 1).
//!
//! `compile*_with_options(opts.constructor_args)` must reject inputs that
//! would silently bake nothing and emit placeholder scripts that fail
//! opaquely at runtime:
//!
//!  (a) positional arrays — N/A for the Rust tier (constructor_args is a
//!      typed `HashMap<String, Value>`, so no positional array can reach it);
//!  (b) keys that don't match any contract property (typos);
//!  (c) referenced readonly properties left unbaked after applying the args.

use std::collections::HashMap;

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const HASH_LOCK_SOURCE: &str = r#"
class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
"#;

const TWO_PROP_SOURCE: &str = r#"
class TwoProp extends SmartContract {
  readonly target: bigint;
  readonly unused: bigint;

  constructor(target: bigint, unused: bigint) {
    super(target, unused);
    this.target = target;
    this.unused = unused;
  }

  public check(x: bigint) {
    assert(x === this.target);
  }
}
"#;

fn hash() -> String {
    "aa".repeat(32)
}

fn opts_with(args: HashMap<String, serde_json::Value>) -> CompileOptions {
    CompileOptions {
        constructor_args: args,
        ..Default::default()
    }
}

#[test]
fn rejects_keys_that_match_no_contract_property() {
    let mut args = HashMap::new();
    // typo: hashVal instead of hashValue
    args.insert("hashVal".to_string(), serde_json::Value::String(hash()));

    let result = compile_from_source_str_with_options(
        HASH_LOCK_SOURCE,
        Some("HashLock.runar.ts"),
        &opts_with(args),
    );

    let err = result.expect_err("typo key must be rejected");
    assert!(err.contains("hashVal"), "error should name the offending key: {}", err);
    assert!(
        err.contains("hashValue"),
        "error should list valid property names: {}",
        err
    );
}

#[test]
fn rejects_when_a_referenced_readonly_property_remains_unbaked() {
    let mut args = HashMap::new();
    // 'target' is referenced by check() but not provided.
    args.insert("unused".to_string(), serde_json::Value::from(1));

    let result = compile_from_source_str_with_options(
        TWO_PROP_SOURCE,
        Some("TwoProp.runar.ts"),
        &opts_with(args),
    );

    let err = result.expect_err("unbaked referenced readonly must be rejected");
    assert!(err.contains("target"), "error should name 'target': {}", err);
    assert!(
        err.contains("placeholder"),
        "error should mention the placeholder hazard: {}",
        err
    );
}

#[test]
fn accepts_an_unreferenced_readonly_property_left_unbaked() {
    let mut args = HashMap::new();
    // 'unused' is never referenced by a method — DCE eliminates it, so
    // leaving it unbaked is fine.
    args.insert("target".to_string(), serde_json::Value::from(42));

    let result = compile_from_source_str_with_options(
        TWO_PROP_SOURCE,
        Some("TwoProp.runar.ts"),
        &opts_with(args),
    );

    let artifact = result.expect("unreferenced unbaked readonly should be allowed");
    assert!(!artifact.script.is_empty(), "script hex should be present");
}

#[test]
fn accepts_a_complete_named_record() {
    let mut args = HashMap::new();
    args.insert("hashValue".to_string(), serde_json::Value::String(hash()));

    let result = compile_from_source_str_with_options(
        HASH_LOCK_SOURCE,
        Some("HashLock.runar.ts"),
        &opts_with(args),
    );

    let artifact = result.expect("complete record should compile");
    assert!(
        artifact.script.contains(&hash()),
        "baked script should contain the hash bytes"
    );
}

#[test]
fn still_compiles_placeholder_artifacts_when_no_constructor_args_given() {
    let result = compile_from_source_str_with_options(
        HASH_LOCK_SOURCE,
        Some("HashLock.runar.ts"),
        &CompileOptions::default(),
    );

    let artifact = result.expect("no-args placeholder compile should succeed");
    assert!(
        !artifact.constructor_slots.is_empty(),
        "placeholder artifact should carry constructor slots"
    );
}

// ---------------------------------------------------------------------------
// F-101 — (d) value kind / byte-width check.
//
// Before the fix `apply_constructor_args` baked any serde_json::Value into the
// property: `true` against a 20-byte hash pushed OP_1 (`76a95188ac`), `42`
// pushed a 1-byte number (`76a9012a88ac`), a 6-byte hex string a 6-byte push —
// every one exit 0 and unspendable. Proves: each mismatch is refused with the
// diagnostic the TypeScript reference emits, naming the property, its declared
// type and the expected shape. Does NOT prove anything about the SDK's
// deploy-time constructorSlots path, which never goes through constructor_args.
// ---------------------------------------------------------------------------

fn p2pkh_source(t: &str) -> String {
    format!(
        r#"
class P2PKH extends SmartContract {{
  readonly pubKeyHash: {t};
  constructor(pubKeyHash: {t}) {{ super(pubKeyHash); this.pubKeyHash = pubKeyHash; }}
  public unlock(sig: Sig, pubKey: PubKey) {{
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }}
}}
"#
    )
}

fn compile_p2pkh(t: &str, v: serde_json::Value) -> Result<String, String> {
    let mut args = HashMap::new();
    args.insert("pubKeyHash".to_string(), v);
    compile_from_source_str_with_options(&p2pkh_source(t), Some("P2PKH.runar.ts"), &opts_with(args))
        .map(|a| a.script)
}

#[test]
fn f101_rejects_a_value_that_does_not_match_the_property_type() {
    use serde_json::json;
    let cases: Vec<(&str, serde_json::Value, &str)> = vec![
        ("ByteString", json!(true), "must be a hex string, got a boolean"),
        ("Addr", json!(true), "must be exactly 20 bytes of hex, got a boolean"),
        ("Addr", json!(42), "must be exactly 20 bytes of hex, got an integer"),
        ("Addr", json!("aabbccddeeff"), "must be exactly 20 bytes of hex, got 6 bytes of hex"),
        ("Addr", json!("zzzz-not-hex"), "must be exactly 20 bytes of hex, got a non-hex string"),
        ("ByteString", json!("abc"), "must be a hex string, got a non-hex string"),
        ("ByteString", json!(null), "must be a hex string, got an unsupported value"),
    ];
    for (t, v, want) in cases {
        let shown = v.to_string();
        let err = compile_p2pkh(t, v).expect_err(&format!("{t} <- {shown} must be rejected"));
        assert!(
            err.contains(&format!("property 'pubKeyHash' ({t})")) && err.contains(want),
            "{t} <- {shown}: expected '{want}', got: {err}"
        );
    }
}

#[test]
fn f101_rejects_bigint_and_boolean_mismatches() {
    use serde_json::json;
    let src = r#"
class Flagged extends SmartContract {
  readonly target: bigint;
  readonly on: boolean;
  constructor(target: bigint, on: boolean) { super(target, on); this.target = target; this.on = on; }
  public check(x: bigint) { assert(this.on); assert(x === this.target); }
}
"#;
    let mut args = HashMap::new();
    args.insert("target".to_string(), json!("2a"));
    args.insert("on".to_string(), json!(1));
    let err = compile_from_source_str_with_options(src, Some("Flagged.runar.ts"), &opts_with(args))
        .expect_err("wrong-typed bigint / boolean must be rejected");
    assert!(
        err.contains("property 'target' (bigint) must be an integer, got 1 bytes of hex"),
        "{err}"
    );
    assert!(err.contains("property 'on' (boolean) must be a boolean, got an integer"), "{err}");
}

#[test]
fn f101_accepts_correctly_typed_values() {
    use serde_json::json;
    let script = compile_p2pkh("Addr", json!("AB".repeat(20))).expect("20-byte hex Addr");
    assert!(script.to_lowercase().contains(&"ab".repeat(20)));
    compile_p2pkh("ByteString", json!("")).expect("empty ByteString is a valid value");
    // The "<digits>n" decimal-bigint string form the ANF JSON loader accepts.
    let mut args = HashMap::new();
    args.insert("target".to_string(), json!("42n"));
    compile_from_source_str_with_options(TWO_PROP_SOURCE, Some("TwoProp.runar.ts"), &opts_with(args))
        .expect("'42n' is an integer");
}
