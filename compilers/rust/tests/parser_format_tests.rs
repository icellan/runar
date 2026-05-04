//! Focused parser-format tests for the Rust compiler.
//!
//! `multiformat_tests.rs` covers dispatch and basic structure for several
//! formats; this file adds the focused per-format tests called out by the
//! 2026-05-01 compiler test gap audit (Java, Zig, Rust-macro). Each test
//! asserts the parser produces a valid `ContractNode` for a small,
//! representative source snippet drawn from the real conformance fixtures
//! when present, otherwise an inline minimal example.

use runar_compiler_rust::frontend::parser::parse_source;

/// Resolve a conformance fixture's source for the given extension via its
/// `source.json` manifest. Every conformance fixture has every
/// `.runar.{ts,sol,move,go,rs,py,zig,rb,java}` entry populated, so a missing
/// entry is a real failure and must FAIL LOUDLY rather than silently skip.
fn read_conformance_format(test_name: &str, ext: &str) -> String {
    let cfg_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("tests")
        .join(test_name)
        .join("source.json");
    let raw = std::fs::read_to_string(&cfg_path)
        .unwrap_or_else(|e| panic!("missing conformance source.json {:?}: {}", cfg_path, e));
    let cfg: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid JSON {:?}: {}", cfg_path, e));
    let rel = cfg
        .get("sources")
        .and_then(|s| s.get(ext))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("source.json {:?} missing sources[{}] entry", cfg_path, ext));
    let resolved = cfg_path.parent().unwrap().join(rel);
    std::fs::read_to_string(&resolved)
        .unwrap_or_else(|e| panic!("failed to read fixture {:?}: {}", resolved, e))
}

// ---------------------------------------------------------------------------
// Java parser dispatch
// ---------------------------------------------------------------------------

#[test]
fn test_parse_java_p2pkh_dispatch() {
    let source = read_conformance_format("basic-p2pkh", ".runar.java");
    let result = parse_source(&source, Some("P2PKH.runar.java"));
    // Java parser must dispatch and produce a P2PKH contract for the
    // conformance fixture. If a future surface-level change can no longer
    // produce a contract, the parser must at least surface diagnostics —
    // a contract-less, error-less result is a silent regression.
    let contract = result.contract.unwrap_or_else(|| {
        assert!(
            !result.errors.is_empty(),
            "Java parser produced no contract and no errors"
        );
        panic!(
            "Java parser produced no contract for basic-p2pkh.runar.java; errors: {:?}",
            result.errors
        )
    });
    assert_eq!(contract.name, "P2PKH");
}

// ---------------------------------------------------------------------------
// Zig parser dispatch
// ---------------------------------------------------------------------------

#[test]
fn test_parse_zig_p2pkh_dispatch() {
    let source = read_conformance_format("basic-p2pkh", ".runar.zig");
    let result = parse_source(&source, Some("P2PKH.runar.zig"));
    // Zig dispatch must produce a P2PKH contract for the conformance fixture.
    // The cross-compiler conformance suite is the byte-equality gate; this
    // test is the dispatch + structural sanity check.
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Zig parser produced no contract for basic-p2pkh.runar.zig; errors: {:?}",
            result.errors
        )
    });
    assert_eq!(contract.name, "P2PKH");
}

// ---------------------------------------------------------------------------
// Rust-macro parser
// ---------------------------------------------------------------------------

#[test]
fn test_parse_rs_arithmetic_structure() {
    let source = read_conformance_format("arithmetic", ".runar.rs");
    let result = parse_source(&source, Some("Arithmetic.runar.rs"));
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Rust-macro parser produced no contract for arithmetic.runar.rs; errors: {:?}",
            result.errors
        )
    });
    assert_eq!(contract.name, "Arithmetic");
    assert!(
        contract.methods.iter().any(|m| m.name == "verify"),
        "expected method 'verify'"
    );
}

#[test]
fn test_parse_rs_p2pkh_structure() {
    let source = read_conformance_format("basic-p2pkh", ".runar.rs");
    let result = parse_source(&source, Some("P2PKH.runar.rs"));
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Rust-macro parser produced no contract for basic-p2pkh.runar.rs; errors: {:?}",
            result.errors
        )
    });
    assert_eq!(contract.name, "P2PKH");
    assert_eq!(contract.parent_class, "SmartContract");
}

// ---------------------------------------------------------------------------
// Python parser (focused structure check beyond the dispatch test)
// ---------------------------------------------------------------------------

#[test]
fn test_parse_py_p2pkh_structure() {
    let source = read_conformance_format("basic-p2pkh", ".runar.py");
    let result = parse_source(&source, Some("P2PKH.runar.py"));
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Python parser produced no contract for basic-p2pkh.runar.py; errors: {:?}",
            result.errors
        )
    });
    assert_eq!(contract.name, "P2PKH");
    // Python uses snake_case which the parser converts to camelCase.
    assert!(
        contract.properties.iter().any(|p| p.name == "pubKeyHash"),
        "expected property 'pubKeyHash' (camelCase)"
    );
}

// ---------------------------------------------------------------------------
// Go DSL parser (focused structure check beyond the dispatch test)
// ---------------------------------------------------------------------------

#[test]
fn test_parse_go_p2pkh_structure_via_conformance() {
    let source = read_conformance_format("basic-p2pkh", ".runar.go");
    let result = parse_source(&source, Some("P2PKH.runar.go"));
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Go parser produced no contract for basic-p2pkh.runar.go; errors: {:?}",
            result.errors
        )
    });
    assert_eq!(contract.name, "P2PKH");
    assert!(
        contract.properties.iter().any(|p| p.name == "pubKeyHash"),
        "expected property 'pubKeyHash' (camelCase)"
    );
}
