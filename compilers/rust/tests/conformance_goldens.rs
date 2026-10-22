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

// N-389 (R145, "named set, keep coverage"): fixtures Rust is EXPECTED to
// refuse. Rust refuses the BN254 pairing family (bn254MultiPairing4) by
// policy. A fixture is skipped only when it is named here AND its
// source.json allowlist excludes rust. Every other fixture, including the
// Go-only ones Rust compiles byte-identically today (babybear,
// babybear-ext4, merkle-proof, state-covenant), is compiled and
// byte-checked, and a refusal there is a failure. Mirrors the Python
// harness's EXPECTED_NOT_PYTHON_COMPILABLE (N-387).
const EXPECTED_NOT_RUST_COMPILABLE: &[&str] = &["bn254-pairing"];

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
        // N-217: fail loud. A read or parse error here used to be
        // swallowed (`if let Ok(...)`) and treated as "source.json
        // doesn't exist", silently falling through to the glob fallback
        // as if the config had never existed. Let it panic instead --
        // the same fail-closed approach F-264 (Ruby) and F-323 (Python)
        // took for the identical pattern in their own harnesses.
        let raw = fs::read_to_string(&config_path)
            .unwrap_or_else(|e| panic!("read {}: {}", config_path.display(), e));
        let cfg: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse {}: {}", config_path.display(), e));
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
    OptedOut,
    CompileError(String),
    // F-285: a missing/unreadable `expected-ir.json` or `expected-script.hex`
    // is a failure, not a silent pass. See `compare_goldens` below.
    MissingGoldenIr,
    MissingGoldenHex,
    // N-389: a fixture named in EXPECTED_NOT_RUST_COMPILABLE whose
    // source.json allowlist does not exclude rust.
    StaleExpectedNotCompilable,
    IrMismatch { expected: String, actual: String },
    ScriptMismatch { expected: String, actual: String },
}

/// F-285: true for every `FixtureOutcome` that must fail the sweep.
///
/// Before this fix, `MissingSource` was routed into a separate `missing`
/// bucket that the final `assert!` never consulted, so a fixture whose
/// source resolution failed (e.g. every `.runar.rs` entry in `source.json`
/// repointed at a nonexistent file) reported `0 fail` instead of failing.
/// `Pass` and `OptedOut` are the only outcomes that do not fail the sweep.
fn is_fixture_failure(outcome: &FixtureOutcome) -> bool {
    !matches!(outcome, FixtureOutcome::Pass | FixtureOutcome::OptedOut)
}

/// Honor the per-fixture compiler allowlist in `source.json`. If `compilers`
/// is present and does not include "rust", the fixture is intentionally
/// opted out of Rust Stack-IR / hex parity (parser coverage is universal and
/// enforced elsewhere). See `conformance/README.md` ⇒ "Per-fixture compiler
/// allowlist".
fn fixture_allowlisted_for_rust(test_dir: &Path) -> bool {
    match read_compiler_allowlist(test_dir) {
        None => true,
        Some(list) => list.iter().any(|s| s == "rust"),
    }
}

/// Return the fixture's `source.json` `compilers` allowlist, or `None` when
/// absent (= all compilers). Mirrors
/// `conformance/runner/runner.ts::readFixtureCompilerAllowlist`.
///
/// N-217: a read or parse error panics (fail loud) rather than being
/// swallowed as "no allowlist declared". N-389: a `compilers` value that is
/// not a list of strings also panics -- it used to fall into `_ => true` and
/// silently admit the fixture.
fn read_compiler_allowlist(test_dir: &Path) -> Option<Vec<String>> {
    let config_path = test_dir.join("source.json");
    if !config_path.exists() {
        return None;
    }
    let raw = fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("read {}: {}", config_path.display(), e));
    let cfg: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse {}: {}", config_path.display(), e));
    match cfg.get("compilers") {
        None => None,
        Some(Value::Array(arr)) => Some(
            arr.iter()
                .map(|v| {
                    v.as_str().map(str::to_string).unwrap_or_else(|| {
                        panic!(
                            "{}: 'compilers' must be a list of strings, got {}",
                            config_path.display(),
                            cfg["compilers"]
                        )
                    })
                })
                .collect(),
        ),
        Some(other) => panic!(
            "{}: 'compilers' must be a list of strings, got {}",
            config_path.display(),
            other
        ),
    }
}

/// Independent (raw `source.json`) check that the allowlist excludes rust.
/// Deliberately does not go through `read_compiler_allowlist`.
fn excludes_rust_raw(test_dir: &Path) -> bool {
    let config_path = test_dir.join("source.json");
    if !config_path.exists() {
        return false;
    }
    let raw = fs::read_to_string(&config_path).expect("read source.json");
    let cfg: Value = serde_json::from_str(&raw).expect("parse source.json");
    match cfg.get("compilers").and_then(|v| v.as_array()) {
        Some(arr) => !arr.iter().any(|v| v.as_str() == Some("rust")),
        None => false,
    }
}

struct ScanResult {
    pass: Vec<String>,
    missing: Vec<String>,
    skipped: Vec<String>,
    failures: Vec<(String, FixtureOutcome)>,
}

/// Walk `dirs` and classify each fixture.
///
/// N-389 (R145): a fixture is skipped ONLY when it is named in
/// `not_compilable` AND its allowlist excludes rust. A named fixture whose
/// allowlist does not exclude rust is a `StaleExpectedNotCompilable`
/// failure. Every unnamed fixture is compiled and byte-checked, even when
/// its allowlist excludes rust.
fn scan_fixtures(dirs: &[PathBuf], not_compilable: &[&str]) -> ScanResult {
    let mut res = ScanResult {
        pass: Vec::new(),
        missing: Vec::new(),
        skipped: Vec::new(),
        failures: Vec::new(),
    };
    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        if not_compilable.contains(&name.as_str()) {
            if fixture_allowlisted_for_rust(dir) {
                res.failures.push((name, FixtureOutcome::StaleExpectedNotCompilable));
            } else {
                res.skipped.push(name);
            }
            continue;
        }
        let outcome = run_one_fixture(dir);
        // F-285: `MissingSource` used to go only into `missing`, a bucket
        // the final `assert!` never consulted. `missing` is kept for the
        // diagnostic listing; `is_fixture_failure` is what the sweep
        // asserts on.
        if let FixtureOutcome::MissingSource = &outcome {
            res.missing.push(name.clone());
        }
        if matches!(outcome, FixtureOutcome::Pass) {
            res.pass.push(name);
        } else if is_fixture_failure(&outcome) {
            res.failures.push((name, outcome));
        } else {
            res.skipped.push(name);
        }
    }
    res
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
    if let Some(outcome) = compare_goldens(test_dir, &actual_ir_canonical, &actual_script) {
        return outcome;
    }

    FixtureOutcome::Pass
}

/// Compare a fixture's actual (already-canonicalized) ANF IR / script hex
/// against its checked-in `expected-ir.json` / `expected-script.hex`.
///
/// F-285: this used to be inline, gated behind `if expected_ir_path.exists()`
/// / `if expected_script_path.exists()` -- a fixture whose golden file was
/// missing (deleted, renamed, ...) skipped the comparison entirely and fell
/// through to `Pass`, with zero bytes actually checked. A missing or
/// unreadable golden is now a failure (`MissingGoldenIr` / `MissingGoldenHex`),
/// mirroring the Go (`compareGoldens`, F-280) and Python (`_compare_goldens`,
/// F-323) harnesses' fix for the identical pattern.
///
/// Returns `None` when both goldens are present, readable, and byte-identical
/// to the actual output; otherwise `Some(failure outcome)`.
fn compare_goldens(test_dir: &Path, actual_ir_canonical: &str, actual_script: &str) -> Option<FixtureOutcome> {
    let expected_ir_path = test_dir.join("expected-ir.json");
    if !expected_ir_path.exists() {
        return Some(FixtureOutcome::MissingGoldenIr);
    }
    let raw = match fs::read_to_string(&expected_ir_path) {
        Ok(s) => s,
        Err(e) => return Some(FixtureOutcome::CompileError(format!("read golden IR: {}", e))),
    };
    let expected_canonical = match canonicalize_json_str(&raw) {
        Ok(s) => s,
        Err(e) => return Some(FixtureOutcome::CompileError(format!("canonicalize golden IR: {}", e))),
    };
    if actual_ir_canonical != expected_canonical {
        return Some(FixtureOutcome::IrMismatch {
            expected: expected_canonical,
            actual: actual_ir_canonical.to_string(),
        });
    }

    let expected_script_path = test_dir.join("expected-script.hex");
    if !expected_script_path.exists() {
        return Some(FixtureOutcome::MissingGoldenHex);
    }
    let raw = match fs::read_to_string(&expected_script_path) {
        Ok(s) => s,
        Err(e) => return Some(FixtureOutcome::CompileError(format!("read golden script: {}", e))),
    };
    let expected_script: String = raw.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
    if actual_script != expected_script {
        return Some(FixtureOutcome::ScriptMismatch {
            expected: expected_script,
            actual: actual_script.to_string(),
        });
    }

    None
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

    // F-285: a `DirEntry` read error or a failed `file_type()` call used to
    // be dropped silently (`filter_map(|e| e.ok())`, `.unwrap_or(false)`),
    // which would quietly shrink `dirs` below the real fixture count with
    // no failure anywhere in the sweep -- lost fixture coverage. Both now
    // panic (failing the test) instead of disappearing a fixture.
    let mut dirs: Vec<PathBuf> = fs::read_dir(&tests_dir)
        .expect("readdir conformance/tests")
        .map(|e| e.expect("readdir entry"))
        .filter(|e| e.file_type().expect("file_type").is_dir())
        .map(|e| e.path())
        .collect();
    dirs.sort();

    let ScanResult {
        pass,
        missing,
        skipped: opted_out,
        failures,
    } = scan_fixtures(&dirs, EXPECTED_NOT_RUST_COMPILABLE);

    // Print summary
    let total = dirs.len();
    let pass_count = pass.len();
    let miss_count = missing.len();
    let fail_count = failures.len();
    let opt_count = opted_out.len();
    println!(
        "\n=== Rust conformance-goldens summary: {} pass / {} fail / {} missing-source / {} skipped (named in EXPECTED_NOT_RUST_COMPILABLE, allowlist excludes rust) (of {} fixtures) ===",
        pass_count, fail_count, miss_count, opt_count, total
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
            FixtureOutcome::MissingSource => {
                println!("  missing source: no .runar.rs file found for fixture '{}'", name);
            }
            FixtureOutcome::MissingGoldenIr => {
                println!("  missing golden: expected-ir.json not found for fixture '{}'", name);
            }
            FixtureOutcome::MissingGoldenHex => {
                println!("  missing golden: expected-script.hex not found for fixture '{}'", name);
            }
            FixtureOutcome::StaleExpectedNotCompilable => {
                println!(
                    "  stale: '{}' is named in EXPECTED_NOT_RUST_COMPILABLE but its source.json allowlist does not exclude rust",
                    name
                );
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

    // N-389 (R145): the skipped set must be exactly the named set; every
    // named entry must exist and really exclude rust in its raw source.json.
    assert_eq!(opted_out, EXPECTED_NOT_RUST_COMPILABLE.to_vec());
    for n in EXPECTED_NOT_RUST_COMPILABLE {
        let d = tests_dir.join(n);
        assert!(d.is_dir(), "EXPECTED_NOT_RUST_COMPILABLE names unknown fixture {:?}", n);
        assert!(excludes_rust_raw(&d), "{:?} allowlist does not exclude rust", n);
    }
    assert_eq!(pass.len() + opted_out.len(), total);
}

// ----------------------------------------------------------------------
// F-285: `conformance_goldens.rs` had two ways to report a green sweep
// without actually checking a fixture:
//   (1) a missing `expected-ir.json` / `expected-script.hex` skipped the
//       comparison entirely (guarded by `if path.exists()`) and fell
//       through to `Pass`;
//   (2) a fixture whose source could not be resolved (`MissingSource`)
//       was counted only in the unasserted `missing` bucket, never in
//       `failures` -- "all source.json .runar.rs entries repointed at a
//       nonexistent file" reported 0 fail.
// Both are reproduced below against synthetic, throwaway fixture
// directories under the OS temp dir (never against the real conformance
// corpus) and proven fixed.
// ----------------------------------------------------------------------

/// Create (and clear) a throwaway scratch directory for one of the tests
/// below. Not a conformance fixture; never under `conformance/tests`.
fn f285_scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("runar-f285-{}-{}", label, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// What this proves: `compare_goldens` treats a missing `expected-ir.json`
/// as a failure (`MissingGoldenIr`), not as "nothing to compare against,
/// mark it passed" -- the behavior the old `if expected_ir_path.exists()`
/// guard produced.
///
/// What this does not prove: that the real conformance corpus contains a
/// fixture missing this golden today -- it does not; every fixture ships
/// both goldens. This is a synthetic, throwaway directory under the OS
/// temp dir, removed at the end of the test.
#[test]
fn test_compare_goldens_missing_golden_ir_is_failure() {
    let dir = f285_scratch_dir("missing-ir");
    fs::write(dir.join("expected-script.hex"), "deadbeef").expect("write expected-script.hex");
    // expected-ir.json deliberately absent.

    let outcome = compare_goldens(&dir, r#"{"anything":true}"#, "deadbeef");

    match outcome {
        Some(FixtureOutcome::MissingGoldenIr) => {}
        other => panic!(
            "compare_goldens did not report MissingGoldenIr for an absent expected-ir.json: {:?}",
            other
        ),
    }

    let _ = fs::remove_dir_all(&dir);
}

/// What this proves: `compare_goldens` treats a missing
/// `expected-script.hex` as a failure (`MissingGoldenHex`), isolated from
/// the IR-missing case above by giving it a matching IR golden so the IR
/// comparison passes first and the hex path is what's actually exercised.
///
/// What this does not prove: the hex comparison logic itself when the
/// golden IS present (covered by the real-corpus run in
/// `test_conformance_goldens_rust`).
#[test]
fn test_compare_goldens_missing_golden_hex_is_failure() {
    let dir = f285_scratch_dir("missing-hex");
    let ir_json = r#"{"anything":true}"#;
    fs::write(dir.join("expected-ir.json"), ir_json).expect("write expected-ir.json");
    let actual_ir = canonicalize_json_str(ir_json).expect("canonicalize synthetic IR");
    // expected-script.hex deliberately absent.

    let outcome = compare_goldens(&dir, &actual_ir, "deadbeef");

    match outcome {
        Some(FixtureOutcome::MissingGoldenHex) => {}
        other => panic!(
            "compare_goldens did not report MissingGoldenHex for an absent expected-script.hex: {:?}",
            other
        ),
    }

    let _ = fs::remove_dir_all(&dir);
}

/// What this proves: `is_fixture_failure` classifies `MissingSource` as a
/// failure. This is the regression guard for the "lost fixture coverage"
/// half of F-285: before the fix, `MissingSource` outcomes were routed
/// only into the `missing` bucket in `test_conformance_goldens_rust`,
/// which the final `assert!(failures.is_empty(), ...)` never consulted --
/// repointing every fixture's `.runar.rs` entry at a nonexistent file
/// reported "0 fail" instead of failing. `Pass` and `OptedOut` are the
/// only outcomes that must NOT fail the sweep.
///
/// What this does not prove: that `test_conformance_goldens_rust` itself
/// wires `is_fixture_failure` in correctly end-to-end for every outcome
/// variant -- that is covered by the real-corpus run passing (today, with
/// no missing sources or goldens) and by the two `compare_goldens` tests
/// above.
#[test]
fn test_is_fixture_failure_classifies_missing_source_as_failure() {
    assert!(
        is_fixture_failure(&FixtureOutcome::MissingSource),
        "MissingSource must be a failure (lost fixture coverage), not a silently-unasserted bucket"
    );
    assert!(
        is_fixture_failure(&FixtureOutcome::MissingGoldenIr),
        "MissingGoldenIr must be a failure"
    );
    assert!(
        is_fixture_failure(&FixtureOutcome::MissingGoldenHex),
        "MissingGoldenHex must be a failure"
    );
    assert!(!is_fixture_failure(&FixtureOutcome::Pass), "Pass must not be a failure");
    assert!(!is_fixture_failure(&FixtureOutcome::OptedOut), "OptedOut must not be a failure");
}

/// What this proves: `run_one_fixture` itself returns `MissingSource` (not
/// a silent pass) for a fixture directory whose `source.json` points its
/// `.runar.rs` entry at a nonexistent file and has no `*.runar.rs` glob
/// fallback either -- this is CL-GAP-154's literal mutation scenario ("all
/// source.json .runar.rs entries repointed at a nonexistent file"),
/// exercising `find_rust_source`'s route (1) failing to canonicalize the
/// dangling path, then falling through to the route (2) glob, which also
/// finds nothing. The outcome is confirmed to be an outcome
/// `is_fixture_failure` (and therefore `test_conformance_goldens_rust`'s
/// assert) now catches.
///
/// What this does not prove: that the real conformance corpus has such a
/// fixture today -- it does not; this is a synthetic, throwaway directory.
/// It also does not prove CL-GAP-033's distinct "glob fallback can
/// substitute a different contract" claim -- out of scope for this item
/// (see notes for dispatcher).
#[test]
fn test_run_one_fixture_reports_missing_source_for_unresolvable_fixture() {
    let dir = f285_scratch_dir("missing-source");
    fs::write(
        dir.join("source.json"),
        r#"{"sources":{".runar.rs":"nonexistent-file.runar.rs"}}"#,
    )
    .expect("write source.json");
    // No *.runar.rs file anywhere in the scratch dir, so the glob fallback
    // in find_rust_source's route (2) also comes up empty.

    let outcome = run_one_fixture(&dir);

    match outcome {
        FixtureOutcome::MissingSource => {}
        other => panic!("run_one_fixture did not report MissingSource: {:?}", other),
    }
    assert!(is_fixture_failure(&outcome), "MissingSource must be a failure");

    let _ = fs::remove_dir_all(&dir);
}

// ----------------------------------------------------------------------
// N-217: `find_rust_source` and `fixture_allowlisted_for_rust` each
// swallowed a `source.json` read/parse error (`if let Ok(...)` /
// `Err(_) => return true`) and treated it as "no config" or "no
// allowlist", silently falling through to the glob fallback or admitting
// the fixture instead of surfacing the real cause -- the identical
// pattern F-264 (Ruby) and F-323 (Python) closed in their own harnesses.
// Fixed below to panic (fail loud) on a read or parse error, matching
// those two tiers' fail-closed approach. Exercised against synthetic,
// throwaway fixture directories only; never against the real conformance
// corpus.
// ----------------------------------------------------------------------

/// What this proves: `find_rust_source` does not silently swallow a
/// malformed (non-JSON) `source.json` and fall through to the `*.runar.rs`
/// glob fallback as if no config existed -- it now panics, surfacing the
/// real cause instead of misreporting a broken config as a plain
/// "no source found" (or, worse here, a resolution via a glob fallback
/// that happens to find an unrelated file).
///
/// What this does not prove: that the real conformance corpus contains a
/// fixture with malformed JSON today -- it does not. Also does not
/// exercise the read-error (as opposed to parse-error) half of the same
/// swallow; both routes share the same fix, but only the parse-error
/// route is covered here to keep the fixture simple and portable.
#[test]
#[should_panic(expected = "parse ")]
fn test_find_rust_source_panics_on_malformed_source_json() {
    let dir = f285_scratch_dir("n217-find-malformed");
    fs::write(dir.join("source.json"), "{not valid json").expect("write source.json");
    // No *.runar.rs file anywhere in the scratch dir, so a swallow would
    // fall through route (2) and quietly return None instead of panicking.

    let _ = find_rust_source(&dir);

    let _ = fs::remove_dir_all(&dir);
}

/// What this proves: `fixture_allowlisted_for_rust` does not silently
/// swallow a malformed `source.json` and treat it as "no allowlist
/// declared" (`return true`) -- a broken config must surface, not
/// silently admit the fixture as if rust were unconditionally allowed.
///
/// What this does not prove: that the real conformance corpus contains a
/// fixture with malformed JSON today -- it does not.
#[test]
#[should_panic(expected = "parse ")]
fn test_fixture_allowlisted_for_rust_panics_on_malformed_source_json() {
    let dir = f285_scratch_dir("n217-allowlist-malformed");
    fs::write(dir.join("source.json"), "{not valid json").expect("write source.json");

    let _ = fixture_allowlisted_for_rust(&dir);

    let _ = fs::remove_dir_all(&dir);
}

// ----------------------------------------------------------------------
// N-389 (R145): the sweep used to skip every allowlist-excluded fixture,
// dropping the byte check on Go-only fixtures Rust compiles in agreement
// with Go, and treated a non-list `compilers` value as "no allowlist".
// Exercised against synthetic, throwaway fixture directories only.
// ----------------------------------------------------------------------

/// What this proves: a fixture whose allowlist excludes rust but which is
/// NOT named in the not-compilable set is attempted, not skipped: here it
/// has no source, so it surfaces as `MissingSource` in `failures` and not
/// in `skipped`.
///
/// What this does not prove: the byte comparison for such a fixture (the
/// real-corpus sweep covers babybear, babybear-ext4, merkle-proof and
/// state-covenant).
#[test]
fn test_scan_fixtures_compiles_excluded_but_unnamed_fixture() {
    let dir = f285_scratch_dir("n389-unnamed").join("go-only-unnamed");
    fs::create_dir_all(&dir).expect("create fixture dir");
    fs::write(dir.join("source.json"), r#"{"compilers":["go"]}"#).expect("write source.json");

    let res = scan_fixtures(&[dir.clone()], &[]);

    assert!(res.skipped.is_empty(), "unnamed fixture must not be skipped: {:?}", res.skipped);
    assert_eq!(res.failures.len(), 1);
    assert!(matches!(res.failures[0].1, FixtureOutcome::MissingSource));

    let _ = fs::remove_dir_all(dir.parent().unwrap());
}

/// What this proves: a named fixture whose allowlist excludes rust is
/// skipped, and one whose allowlist does not exclude rust (or has none) is
/// a `StaleExpectedNotCompilable` failure.
///
/// What this does not prove: that the named set matches what rust refuses
/// today (the real-corpus sweep asserts that).
#[test]
fn test_scan_fixtures_named_set_skips_and_flags_stale_entries() {
    let root = f285_scratch_dir("n389-named");
    let excluded = root.join("excluded");
    let included = root.join("included");
    fs::create_dir_all(&excluded).expect("create");
    fs::create_dir_all(&included).expect("create");
    fs::write(excluded.join("source.json"), r#"{"compilers":["go"]}"#).expect("write");
    fs::write(included.join("source.json"), r#"{"compilers":["go","rust"]}"#).expect("write");

    let res = scan_fixtures(&[excluded.clone(), included.clone()], &["excluded", "included"]);

    assert_eq!(res.skipped, vec!["excluded".to_string()]);
    assert_eq!(res.failures.len(), 1);
    assert_eq!(res.failures[0].0, "included");
    assert!(matches!(res.failures[0].1, FixtureOutcome::StaleExpectedNotCompilable));

    let _ = fs::remove_dir_all(&root);
}

/// What this proves: a non-list `compilers` value fails closed (panics)
/// instead of being treated as "no allowlist".
///
/// What this does not prove: that the real corpus has such a value (it
/// does not).
#[test]
#[should_panic(expected = "must be a list of strings")]
fn test_fixture_allowlisted_for_rust_panics_on_non_list_compilers() {
    let dir = f285_scratch_dir("n389-non-list");
    fs::write(dir.join("source.json"), r#"{"compilers":"go"}"#).expect("write source.json");

    let _ = fixture_allowlisted_for_rust(&dir);

    let _ = fs::remove_dir_all(&dir);
}
