//! Byte-identical golden diff harness for the Rust compiler.
//!
//! For every directory under `conformance/tests/`, this test:
//!   1. Locates the Rust-format source file (`*.runar.rs`)
//!   2. Compiles it via the Rust compiler (parse -> validate -> typecheck -> ANF -> stack -> emit)
//!   3. Canonicalizes the ANF IR JSON (sort keys, strip `sourceLoc`, 2-space indent)
//!   4. Asserts byte-for-byte equality against `expected-ir.json` and `expected-script.hex`
//!
//! The canonicalization strategy mirrors `conformance/runner/runner.ts::canonicalizeJson`.
//!
//! All failures are collected and reported at the end. A summary prints pass/fail counts
//! and shows concrete diffs for the first 5 failing fixtures (IR / script).

use runar_compiler_rust::{
    compile_from_source_str_with_options, compile_source_str_to_ir_with_options, CompileOptions,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn conformance_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("tests")
}

/// Resolve the Rust-format source file for a conformance fixture.
///
/// Mirrors the TS runner's logic in `conformance/runner/runner.ts`:
///   1. If `source.json` exists and has a `.runar.rs` entry in `sources`,
///      resolve it relative to the fixture directory. Use it if the path exists.
///   2. Otherwise fall back to the first `*.runar.rs` file in the fixture dir.
fn find_rust_source(test_dir: &Path) -> Option<PathBuf> {
    // (1) source.json lookup
    let config_path = test_dir.join("source.json");
    if config_path.exists() {
        if let Ok(raw) = fs::read_to_string(&config_path) {
            if let Ok(cfg) = serde_json::from_str::<Value>(&raw) {
                if let Some(rel) = cfg
                    .get("sources")
                    .and_then(|s| s.get(".runar.rs"))
                    .and_then(|v| v.as_str())
                {
                    let resolved = test_dir.join(rel);
                    // Canonicalize so the path is absolute and normalized;
                    // existence is implied by canonicalize() succeeding.
                    if let Ok(abs) = fs::canonicalize(&resolved) {
                        return Some(abs);
                    }
                }
            }
        }
    }

    // (2) glob fallback in fixture directory
    let entries = fs::read_dir(test_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".runar.rs") {
                return Some(path);
            }
        }
    }
    None
}

/// Recursively sort object keys and strip `sourceLoc`.
fn canonicalize_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if k == "sourceLoc" {
                    continue;
                }
                out.insert(k.clone(), canonicalize_value(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
        _ => v.clone(),
    }
}

/// Parse + canonicalize + serialize JSON with 2-space indent.
fn canonicalize_json_str(s: &str) -> Result<String, String> {
    let parsed: Value = serde_json::from_str(s).map_err(|e| format!("JSON parse error: {}", e))?;
    let canonical = canonicalize_value(&parsed);
    serde_json::to_string_pretty(&canonical).map_err(|e| format!("JSON serialize error: {}", e))
}

#[derive(Debug)]
enum FixtureOutcome {
    Pass,
    MissingSource,
    CompileError(String),
    IrMismatch { expected: String, actual: String },
    ScriptMismatch { expected: String, actual: String },
}

fn run_one_fixture(test_dir: &Path) -> FixtureOutcome {
    let source_path = match find_rust_source(test_dir) {
        Some(p) => p,
        None => return FixtureOutcome::MissingSource,
    };

    let source = match fs::read_to_string(&source_path) {
        Ok(s) => s,
        Err(e) => return FixtureOutcome::CompileError(format!("read source: {}", e)),
    };
    let file_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("contract.rs");

    let opts = CompileOptions {
        disable_constant_folding: true,
        ..Default::default()
    };

    // Step 1: compile to IR
    let anf = match compile_source_str_to_ir_with_options(&source, Some(file_name), &opts) {
        Ok(a) => a,
        Err(e) => return FixtureOutcome::CompileError(format!("source->IR: {}", e)),
    };
    let actual_ir_json = match serde_json::to_string(&anf) {
        Ok(s) => s,
        Err(e) => return FixtureOutcome::CompileError(format!("serialize IR: {}", e)),
    };
    let actual_ir_canonical = match canonicalize_json_str(&actual_ir_json) {
        Ok(s) => s,
        Err(e) => return FixtureOutcome::CompileError(format!("canonicalize actual IR: {}", e)),
    };

    // Step 2: compile to script hex
    let artifact = match compile_from_source_str_with_options(&source, Some(file_name), &opts) {
        Ok(a) => a,
        Err(e) => return FixtureOutcome::CompileError(format!("source->script: {}", e)),
    };
    let actual_script = artifact.script.to_lowercase();
    let actual_script: String = actual_script.chars().filter(|c| !c.is_whitespace()).collect();

    // Step 3: compare against goldens
    let expected_ir_path = test_dir.join("expected-ir.json");
    if expected_ir_path.exists() {
        let raw = match fs::read_to_string(&expected_ir_path) {
            Ok(s) => s,
            Err(e) => return FixtureOutcome::CompileError(format!("read golden IR: {}", e)),
        };
        let expected_canonical = match canonicalize_json_str(&raw) {
            Ok(s) => s,
            Err(e) => return FixtureOutcome::CompileError(format!("canonicalize golden IR: {}", e)),
        };
        if actual_ir_canonical != expected_canonical {
            return FixtureOutcome::IrMismatch {
                expected: expected_canonical,
                actual: actual_ir_canonical,
            };
        }
    }

    let expected_script_path = test_dir.join("expected-script.hex");
    if expected_script_path.exists() {
        let raw = match fs::read_to_string(&expected_script_path) {
            Ok(s) => s,
            Err(e) => return FixtureOutcome::CompileError(format!("read golden script: {}", e)),
        };
        let expected_script: String = raw.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
        if actual_script != expected_script {
            return FixtureOutcome::ScriptMismatch {
                expected: expected_script,
                actual: actual_script,
            };
        }
    }

    FixtureOutcome::Pass
}

/// Produce a compact unified-diff summary of two strings (first 40 differing lines).
fn short_diff(expected: &str, actual: &str) -> String {
    let exp_lines: Vec<&str> = expected.lines().collect();
    let act_lines: Vec<&str> = actual.lines().collect();
    let mut out = String::new();
    let max = exp_lines.len().max(act_lines.len());
    let mut shown = 0usize;
    for i in 0..max {
        let e = exp_lines.get(i).copied().unwrap_or("<EOF>");
        let a = act_lines.get(i).copied().unwrap_or("<EOF>");
        if e != a {
            out.push_str(&format!("    line {}:\n      - expected: {}\n      + actual:   {}\n", i + 1, e, a));
            shown += 1;
            if shown >= 12 {
                out.push_str("    ... (truncated)\n");
                break;
            }
        }
    }
    if out.is_empty() {
        out.push_str("    (strings differ but no line diff; likely trailing whitespace)\n");
    }
    out
}

#[test]
fn test_conformance_goldens_rust() {
    let tests_dir = conformance_tests_dir();
    assert!(
        tests_dir.is_dir(),
        "conformance tests directory not found: {}",
        tests_dir.display()
    );

    let mut dirs: Vec<PathBuf> = fs::read_dir(&tests_dir)
        .expect("readdir conformance/tests")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    dirs.sort();

    let mut pass: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut failures: Vec<(String, FixtureOutcome)> = Vec::new();

    for dir in &dirs {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let outcome = run_one_fixture(dir);
        match &outcome {
            FixtureOutcome::Pass => pass.push(name),
            FixtureOutcome::MissingSource => missing.push(name),
            _ => failures.push((name, outcome)),
        }
    }

    // Print summary
    let total = dirs.len();
    let pass_count = pass.len();
    let miss_count = missing.len();
    let fail_count = failures.len();
    println!(
        "\n=== Rust conformance-goldens summary: {} pass / {} fail / {} missing-source (of {} fixtures) ===",
        pass_count, fail_count, miss_count, total
    );
    if !missing.is_empty() {
        println!("Missing .runar.rs source files:");
        for n in &missing {
            println!("  - {}", n);
        }
    }
    // Show up to the first 5 failures with concrete diffs
    let shown_failures: Vec<&(String, FixtureOutcome)> = failures.iter().take(5).collect();
    for (name, outcome) in &shown_failures {
        println!("\n--- FAIL: {} ---", name);
        match outcome {
            FixtureOutcome::CompileError(msg) => {
                println!("  compile error: {}", msg);
            }
            FixtureOutcome::IrMismatch { expected, actual } => {
                println!("  IR mismatch (expected {} chars, actual {} chars):", expected.len(), actual.len());
                print!("{}", short_diff(expected, actual));
            }
            FixtureOutcome::ScriptMismatch { expected, actual } => {
                println!(
                    "  script mismatch: expected {} hex chars, actual {} hex chars",
                    expected.len(),
                    actual.len()
                );
                let min_len = expected.len().min(actual.len());
                let mut first_diff = min_len;
                for i in 0..min_len {
                    if expected.as_bytes()[i] != actual.as_bytes()[i] {
                        first_diff = i;
                        break;
                    }
                }
                let lo = first_diff.saturating_sub(20);
                let exp_hi = (first_diff + 20).min(expected.len());
                let act_hi = (first_diff + 20).min(actual.len());
                println!(
                    "  first diff at hex offset {} (byte {})",
                    first_diff,
                    first_diff / 2
                );
                println!("  expected: ...{}...", &expected[lo..exp_hi]);
                println!("  actual:   ...{}...", &actual[lo..act_hi]);
            }
            _ => {}
        }
    }
    if failures.len() > shown_failures.len() {
        println!("\n... and {} more failures:", failures.len() - shown_failures.len());
        for (name, _) in &failures[shown_failures.len()..] {
            println!("  - {}", name);
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} fixtures failed (see stdout for details)",
        failures.len(),
        total
    );
}
