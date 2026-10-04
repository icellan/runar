//! N-087 — `compile_from_ir_str` enforces the source validator's parentClass
//! rules on IR, with the diagnostics shared by all seven tiers
//! (`conformance/negatives/ir-parent-class-cases.json`).
//!
//! Before: a SmartContract declaring `owner` with readonly:false (F-107's
//! v2-mut-stateless) compiled to 76767b8777, which an attacker's key spends
//! under strict @bsv/sdk Spend; stateful-only nodes in a non-stateful contract
//! and raw_script outside UnsafeSmartContract compiled too.
//!
//! Proves: every corpus case is refused with its exact diagnostic and the
//! accepted programs (incl. parentClass-less IR) compile. Does not prove that a
//! declared StatefulSmartContract body enforces its state continuation.

use runar_compiler_rust::compile_from_ir_str;

fn corpus() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/negatives/ir-parent-class-cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn n087_accepted_programs_compile() {
    let c = corpus();
    for a in c["accept"].as_array().unwrap() {
        compile_from_ir_str(&a["ir"].to_string())
            .unwrap_or_else(|e| panic!("{} must compile: {}", a["name"], e));
    }
}

#[test]
fn n087_every_case_refused_with_shared_diagnostic() {
    let c = corpus();
    let cases = c["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let want = case["error"].as_str().unwrap();
        let prefix = case["match"].as_str() == Some("prefix");
        match compile_from_ir_str(&case["ir"].to_string()) {
            Ok(_) => failures.push(format!("{}: accepted; want {:?}", name, want)),
            Err(got) if (prefix && !got.starts_with(want)) || (!prefix && got != want) => failures.push(format!("{}: got {:?}; want {:?}", name, got, want)),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{} case(s) wrong:\n{}", failures.len(), failures.join("\n"));
}
