//! N-069 — the `--ir` loader checks every required ANF field for presence and
//! JSON type, and names the field path in a diagnostic shared verbatim by all
//! seven tiers (`conformance/negatives/ir-required-fields-cases.json`).
//!
//! Before: serde refused most shapes with its own wording and a line/column
//! (`missing field `body` at line 1 column 182`) rather than the field's path.
//!
//! Proves: each single-field corruption of the control is refused with its
//! exact diagnostic and the control loads. Does not prove: full schema
//! conformance (deliberately defaulted optional fields are not required).

use runar_compiler_rust::ir::loader::load_ir_from_str;

fn corpus() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/negatives/ir-required-fields-cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn n069_control_loads() {
    let c = corpus();
    load_ir_from_str(&c["control"].to_string()).expect("control must load");
}

#[test]
fn n069_every_case_refused_with_shared_diagnostic() {
    let c = corpus();
    let cases = c["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
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
