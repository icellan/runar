//! Conformance-fixture parity tests. Loads each canonical fixture hex
//! under `conformance/tests/<name>/expected-script.hex`, runs the
//! analyzer, and byte-compares the serialized JSON report against the
//! golden under `conformance/analyzer/<name>/expected-analyzer-report.json`.

use std::fs;
use std::path::PathBuf;

use runar_lang::analyzer::{analyze_script, serialize_report};

fn repo_root() -> PathBuf {
    // tests run with cwd = packages/runar-rs/
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // pop runar-rs
    p.pop(); // pop packages
    p
}

fn run_fixture(name: &str) {
    let root = repo_root();
    let hex_path = root
        .join("conformance")
        .join("tests")
        .join(name)
        .join("expected-script.hex");
    let golden_path = root
        .join("conformance")
        .join("analyzer")
        .join(name)
        .join("expected-analyzer-report.json");

    let hex = fs::read_to_string(&hex_path)
        .unwrap_or_else(|e| panic!("read {}: {}", hex_path.display(), e));
    let golden = fs::read_to_string(&golden_path)
        .unwrap_or_else(|e| panic!("read {}: {}", golden_path.display(), e));

    let result = analyze_script(hex.trim()).expect("analyze");
    let actual = serialize_report(&result);
    if actual != golden {
        // Show the first divergent line for a useful failure.
        let a_lines: Vec<&str> = actual.split('\n').collect();
        let g_lines: Vec<&str> = golden.split('\n').collect();
        let n = a_lines.len().max(g_lines.len());
        for i in 0..n {
            let a = a_lines.get(i).copied().unwrap_or("");
            let g = g_lines.get(i).copied().unwrap_or("");
            if a != g {
                panic!(
                    "[{}] first divergence at line {}:\n  actual:   {}\n  expected: {}",
                    name,
                    i + 1,
                    a,
                    g
                );
            }
        }
        panic!("[{}] outputs differ but no line diverged", name);
    }
}

#[test]
fn basic_p2pkh() {
    run_fixture("basic-p2pkh");
}

#[test]
fn escrow() {
    run_fixture("escrow");
}

#[test]
fn stateful_counter() {
    run_fixture("stateful-counter");
}

#[test]
fn auction() {
    run_fixture("auction");
}

#[test]
fn covenant_vault() {
    run_fixture("covenant-vault");
}

#[test]
fn ec_demo() {
    run_fixture("ec-demo");
}

#[test]
fn schnorr_zkp() {
    run_fixture("schnorr-zkp");
}

#[test]
fn if_else() {
    run_fixture("if-else");
}
