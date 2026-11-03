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

// ---------------------------------------------------------------------------
// F-103 — the ANF-IR (`compile_from_ir_str_with_options`) and direct-program
// (`compile_from_program_with_options`) entry points must honour
// `constructor_args` exactly like the source pipeline, matching the TS
// reference `compileFromANF`, which validates and bakes them.
//
// Before the fix both entry points ignored the field: the caller got exit 0
// and an artifact whose script still carried the OP_0 placeholder plus a live
// constructor slot. Proves: the named value is baked (script byte-identical to
// the source-pipeline bake, no constructor slot left), and the same F-101 /
// unknown-key / unbaked-readonly checks refuse bad args on these paths. Does
// NOT prove anything about the IR loader's own validation or the SDK's
// deploy-time constructorSlots splice.
// ---------------------------------------------------------------------------

fn hash_lock_ir() -> runar_compiler_rust::ir::ANFProgram {
    runar_compiler_rust::compile_source_str_to_ir(HASH_LOCK_SOURCE, Some("HashLock.runar.ts"))
        .expect("HashLock lowers to ANF")
}

fn hash_args(v: serde_json::Value) -> HashMap<String, serde_json::Value> {
    let mut args = HashMap::new();
    args.insert("hashValue".to_string(), v);
    args
}

#[test]
fn f103_ir_entry_point_bakes_constructor_args_like_the_source_pipeline() {
    let opts = opts_with(hash_args(serde_json::Value::String(hash())));
    let from_source =
        compile_from_source_str_with_options(HASH_LOCK_SOURCE, Some("HashLock.runar.ts"), &opts)
            .expect("source bake");
    let ir_json = serde_json::to_string(&hash_lock_ir()).unwrap();

    let from_ir = runar_compiler_rust::compile_from_ir_str_with_options(&ir_json, &opts)
        .expect("IR compile with constructor_args");
    assert!(from_ir.script.contains(&hash()), "IR path must embed the value: {}", from_ir.script);
    assert!(
        from_ir.constructor_slots.is_empty(),
        "IR path must not leave a constructor slot for a baked property: {:?}",
        from_ir.constructor_slots
    );
    assert_eq!(from_ir.script, from_source.script, "IR bake must match source bake");

    let from_program =
        runar_compiler_rust::compile_from_program_with_options(&hash_lock_ir(), &opts)
            .expect("direct-program compile with constructor_args");
    assert!(from_program.constructor_slots.is_empty());
    assert_eq!(from_program.script, from_source.script, "program bake must match source bake");
}

#[test]
fn f103_ir_entry_points_validate_constructor_args() {
    let ir_json = serde_json::to_string(&hash_lock_ir()).unwrap();
    let cases: Vec<(HashMap<String, serde_json::Value>, &str)> = vec![
        (
            {
                let mut a = HashMap::new();
                a.insert("hashVal".to_string(), serde_json::Value::String(hash()));
                a
            },
            "constructorArgs key 'hashVal' does not match any property",
        ),
        (
            hash_args(serde_json::json!("aabb")),
            "property 'hashValue' (Sha256) must be exactly 32 bytes of hex, got 2 bytes of hex",
        ),
    ];
    for (args, want) in cases {
        let opts = opts_with(args);
        let err = runar_compiler_rust::compile_from_ir_str_with_options(&ir_json, &opts)
            .expect_err("bad constructor_args on the IR path must be refused");
        assert!(err.contains(want), "IR path: expected '{want}', got: {err}");
        let err = runar_compiler_rust::compile_from_program_with_options(&hash_lock_ir(), &opts)
            .expect_err("bad constructor_args on the program path must be refused");
        assert!(err.contains(want), "program path: expected '{want}', got: {err}");
    }

    // (c) A referenced readonly property left unbaked is refused too.
    let two_prop_ir = runar_compiler_rust::compile_source_str_to_ir(TWO_PROP_SOURCE, Some("TwoProp.runar.ts"))
        .expect("TwoProp lowers");
    let mut args = HashMap::new();
    args.insert("unused".to_string(), serde_json::json!(7));
    let err = runar_compiler_rust::compile_from_ir_str_with_options(
        &serde_json::to_string(&two_prop_ir).unwrap(),
        &opts_with(args),
    )
    .expect_err("unbaked referenced readonly must be refused");
    assert!(err.contains("readonly property 'target'"), "{err}");

    // No args: still the placeholder artifact (unchanged behaviour).
    let plain = runar_compiler_rust::compile_from_ir_str_with_options(&ir_json, &CompileOptions::default())
        .expect("no-args IR compile");
    assert!(!plain.constructor_slots.is_empty());
}

/// F-266: with several unrecognised constructor_args keys, the refusal text
/// must be the same on every compile. `constructor_args` is a `HashMap`, and
/// each fresh `HashMap` gets its own `RandomState` seed, so iterating its keys
/// directly reorders the per-key diagnostics from one compile to the next.
/// The keys are reported in sorted order — the TypeScript reference reports
/// them in insertion order, which a `HashMap` does not keep, so sorted order is
/// the deterministic order that equals TS whenever the caller inserts keys in
/// sorted order (as here).
///
/// Proves: the joined error string is identical across 64 compiles with
/// independently seeded maps, and lists the keys in sorted order.
/// Does not prove: anything about script bytes (baking walks
/// `program.properties` in declaration order and never iterated the map), or
/// cross-process stability beyond what independent per-map seeds exercise.
#[test]
fn f266_unknown_key_diagnostics_are_deterministic() {
    let keys = ["zeta", "alpha", "mu", "beta", "omega", "kappa", "delta", "gamma"];
    let mut seen = std::collections::HashSet::new();
    for _ in 0..64 {
        let mut args = HashMap::new();
        for k in keys {
            args.insert(k.to_string(), serde_json::json!(1));
        }
        let err = compile_from_source_str_with_options(
            HASH_LOCK_SOURCE,
            Some("HashLock.runar.ts"),
            &opts_with(args),
        )
        .expect_err("unknown keys must be refused");
        seen.insert(err);
    }
    assert_eq!(
        seen.len(),
        1,
        "diagnostic text varied across compiles ({} variants):\n{:#?}",
        seen.len(),
        seen
    );
    let err = seen.into_iter().next().unwrap();
    let mut sorted = keys.to_vec();
    sorted.sort();
    let positions: Vec<usize> = sorted
        .iter()
        .map(|k| err.find(&format!("key '{k}'")).expect("every unknown key is reported"))
        .collect();
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "unknown keys must be reported in sorted order, got: {err}"
    );
}
