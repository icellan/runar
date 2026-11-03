//! N-065 / N-060 — a user identifier spelled like a name the compiler mints is
//! refused, with the diagnostic shared verbatim by all seven tiers
//! (`conformance/negatives/reserved-names-cases.json`).
//!
//! Before: `let t2: bigint = p; assert(p > 0n); if (c) { t2 = p; }
//! assert(t2 + 1n === 1n);` compiled to a script that accepts p = 1, c = false
//! (the final guard read the ANF temp `t2`, not the local), and `--ir`
//! accepted parameters, properties, bindings and references named after stack
//! lowering's own slots (`_codePart`, `__param_*`, `__shadowed_*`, `_pub_<n>`).
//!
//! Proves: every source case is refused by this tier's frontend with the
//! shared sentence while its renamed twin compiles; a stateless contract's own
//! `txPreimage` parameter compiles; every `--ir` case is refused by the loader
//! and the accepted IR compiles to the P2PK script. Does not prove: the
//! on-chain effect (conformance/negatives/reserved-names.test.ts runs Spend).

use runar_compiler_rust::ir::loader::load_ir_from_str;
use runar_compiler_rust::{compile_from_ir_str, compile_from_source_str_with_result, CompileOptions};

fn corpus() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/negatives/reserved-names-cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn compile(src: &str, file: &str) -> (bool, Vec<String>) {
    let opts = CompileOptions { disable_constant_folding: true, ..CompileOptions::default() };
    let r = compile_from_source_str_with_result(src, Some(file), &opts);
    (r.success, r.diagnostics.iter().map(|d| d.message.clone()).collect())
}

#[test]
fn n065_source_cases_refused_with_shared_diagnostic() {
    let c = corpus();
    let cases = c["source"]["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let file = case["file"].as_str().unwrap();
        let want = case["error"].as_str().unwrap();
        let (ok, msgs) = compile(case["src"].as_str().unwrap(), file);
        if ok || !msgs.iter().any(|m| m == want) {
            failures.push(format!("{}: success={} diagnostics={:?}; want {:?}", name, ok, msgs, want));
        }
        let (twin_ok, twin_msgs) = compile(case["twin"].as_str().unwrap(), file);
        if !twin_ok {
            failures.push(format!("{} twin refused: {:?}", name, twin_msgs));
        }
    }
    assert!(failures.is_empty(), "{} failure(s):\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn n065_source_accepted_programs_compile() {
    let c = corpus();
    for a in c["source"]["accept"].as_array().unwrap() {
        let (ok, msgs) = compile(a["src"].as_str().unwrap(), a["file"].as_str().unwrap());
        assert!(ok, "{} refused: {:?}", a["name"], msgs);
    }
}

#[test]
fn n065_ir_cases_refused_with_shared_diagnostic() {
    let c = corpus();
    let cases = c["ir"]["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let want = case["error"].as_str().unwrap();
        match load_ir_from_str(&case["ir"].to_string()) {
            Ok(_) => failures.push(format!("{}: accepted; want {:?}", name, want)),
            Err(got) if !got.contains(want) => failures.push(format!("{}: got {:?}; want {:?}", name, got, want)),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{} case(s) wrong:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn n065_ir_accepted_programs_compile() {
    let c = corpus();
    for a in c["ir"]["accept"].as_array().unwrap() {
        let art = compile_from_ir_str(&a["ir"].to_string())
            .unwrap_or_else(|e| panic!("{} must compile: {}", a["name"], e));
        assert_eq!(art.script, "00ac", "{}", a["name"]);
    }
}
