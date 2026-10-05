//! N-096: the loader refuses a `syntheticArrayChain` the expand-fixed-arrays
//! pass could not have written, with the diagnostic shared by all 7 tiers
//! (`conformance/negatives/ir-synthetic-array-chain.test.ts` holds the corpus).
//!
//! Proves: the F-105 probe (basic-p2pkh plus a property whose chain is 1100
//! levels of `{base: deep, index: 0, length: 1}`) is refused at load time with
//! the shared words, and the FixedArray goldens still load. Does not prove the
//! rest of the rule, which the conformance corpus covers in every tier.

use runar_compiler_rust::ir::loader::load_ir_from_str;
use serde_json::{json, Value};

fn golden(fixture: &str) -> Value {
    let path = format!(
        "{}/../../conformance/tests/{}/expected-ir.json",
        env!("CARGO_MANIFEST_DIR"),
        fixture
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read golden")).expect("parse golden")
}

#[test]
fn f105_probe_is_refused_with_the_shared_diagnostic() {
    let mut ir = golden("basic-p2pkh");
    let chain: Vec<Value> = (0..1100).map(|_| json!({"base": "deep", "index": 0, "length": 1})).collect();
    ir["properties"].as_array_mut().unwrap().insert(
        1,
        json!({"name": "deep", "type": "bigint", "readonly": true, "syntheticArrayChain": chain}),
    );
    let err = load_ir_from_str(&ir.to_string()).expect_err("the probe must be refused");
    assert_eq!(
        err,
        "IR validation: malformed syntheticArrayChain on property 'deep': 1100 levels exceed the limit of 1023"
    );
}

#[test]
fn fixed_array_goldens_still_load() {
    for f in ["fixed-array-index", "fixed-array-write"] {
        load_ir_from_str(&golden(f).to_string()).unwrap_or_else(|e| panic!("{f}: {e}"));
    }
}
