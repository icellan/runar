//! N-101 — `compile_from_ir_str` refuses a StatefulSmartContract program
//! (declared, or inferred per N-087) any of whose public methods lacks,
//! reorders or alters the scaffolding ANF lowering injects (auto-injected
//! parameters, the checkPreimage / sighash / deserialize_state prologue, the
//! state continuation), with the diagnostics shared by all seven tiers
//! (`conformance/negatives/ir-stateful-scaffold-cases.json`).
//!
//! Before: F-107's attack body relabelled StatefulSmartContract compiled to
//! 76767b8777, which an attacker's key spends under strict @bsv/sdk Spend, and
//! so did the parentClass-less variant carrying a dead add_data_output.
//!
//! Proves: every corpus case is refused with its exact diagnostic and the
//! accepted programs (incl. unmodified stateful goldens) compile. Does not
//! prove cross-tier agreement (conformance/negatives/ir-stateful-scaffold.test.ts
//! does) or anything about the free user code between prologue and continuation.

use runar_compiler_rust::compile_from_ir_str;

fn corpus() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/negatives/ir-stateful-scaffold-cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn n101_accepted_programs_compile() {
    let c = corpus();
    let accept = c["accept"].as_array().unwrap();
    assert!(accept.len() >= 3);
    for a in accept {
        compile_from_ir_str(&a["ir"].to_string())
            .unwrap_or_else(|e| panic!("{} must compile: {}", a["name"], e));
    }
}

#[test]
fn n101_every_case_refused_with_shared_diagnostic() {
    let c = corpus();
    let cases = c["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let want = case["error"].as_str().unwrap();
        match compile_from_ir_str(&case["ir"].to_string()) {
            Ok(_) => failures.push(format!("{}: accepted; want {:?}", name, want)),
            Err(got) if got != want => failures.push(format!("{}: got {:?}; want {:?}", name, got, want)),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{} case(s) wrong:\n{}", failures.len(), failures.join("\n"));
}
