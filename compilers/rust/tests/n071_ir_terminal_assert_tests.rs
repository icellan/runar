//! N-071 — the `--ir` loader refuses a public method that does not END with an
//! assert, with the diagnostic shared verbatim by all seven tiers
//! (`conformance/negatives/ir-terminal-assert-cases.json`).
//!
//! Before: `"body": []` compiled to an EMPTY (anyone-can-spend) locking script
//! at exit 0, and an `if` whose else arm ended in `load_const true` compiled
//! to a script an empty signature spends.
//!
//! Proves: every case is refused with its exact diagnostic and the accepted
//! programs (a P2PK control, a both-arm `if`) load. Does not prove: that an
//! accepted program is secure — ending in an assert is necessary, not
//! sufficient.

use runar_compiler_rust::ir::loader::load_ir_from_str;

fn corpus() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/negatives/ir-terminal-assert-cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn n071_accepted_programs_load() {
    let c = corpus();
    for a in c["accept"].as_array().unwrap() {
        load_ir_from_str(&a["ir"].to_string())
            .unwrap_or_else(|e| panic!("{} must load: {}", a["name"], e));
    }
}

#[test]
fn n071_every_case_refused_with_shared_diagnostic() {
    let c = corpus();
    let cases = c["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let want = case["error"].as_str().unwrap();
        match load_ir_from_str(&case["ir"].to_string()) {
            Ok(_) => failures.push(format!("{}: accepted; want {:?}", name, want)),
            Err(got) if got != want => failures.push(format!("{}: got {:?}; want {:?}", name, got, want)),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{} case(s) wrong:\n{}", failures.len(), failures.join("\n"));
}
