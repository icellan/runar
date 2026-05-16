//! CLI smoke tests for the `debug` subcommand (G-6).
//!
//! Builds the `runar-compiler-rust` binary and exercises the `debug`
//! subcommand against trivial scripts. The Rust tier is execute-only by
//! design (upstream `Spend` state is `pub(crate)`); these tests verify the
//! wrapper parses its args, runs the script, and reports a final pass/fail
//! line.
//!
//! Cross-tier alignment with the Go `cli_debug_test.go` smoke tests so a
//! regression here trips before the cross-language audit's CLI checklist
//! re-opens.

use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    // Cargo sets CARGO_BIN_EXE_<name> for integration tests when the binary
    // belongs to the same package — this is the canonical way to find the
    // built binary without re-invoking cargo build.
    PathBuf::from(env!("CARGO_BIN_EXE_runar-compiler-rust"))
}

#[test]
fn debug_trivial_script_passes() {
    // OP_1 — pushes 1 onto the stack, which is truthy → final: pass.
    let out = Command::new(bin_path())
        .args(["debug", "--script", "51"])
        .output()
        .expect("spawn binary");
    assert!(
        out.status.success(),
        "debug on OP_1 must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("final: pass"),
        "expected 'final: pass', got:\n{}",
        stdout
    );
}

#[test]
fn debug_falsy_script_reports_fail() {
    // OP_0 — pushes empty bytes (falsy) → final: fail (wrapper still exits 0).
    let out = Command::new(bin_path())
        .args(["debug", "--script", "00"])
        .output()
        .expect("spawn binary");
    assert!(
        out.status.success(),
        "wrapper must exit 0 even for falsy scripts; got: {:?}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("final: fail"),
        "expected 'final: fail' for OP_0, got:\n{}",
        stdout
    );
}

#[test]
fn debug_missing_input_errors() {
    // No --script and no --artifact: must exit non-zero with a diagnostic.
    let out = Command::new(bin_path())
        .arg("debug")
        .output()
        .expect("spawn binary");
    assert!(
        !out.status.success(),
        "debug with no input must exit non-zero"
    );
}

#[test]
fn debug_artifact_loads_script_field() {
    let tmp = tempdir();
    let artifact_path = tmp.join("trivial.json");
    std::fs::write(&artifact_path, r#"{"script":"51"}"#).expect("write artifact");

    let out = Command::new(bin_path())
        .args([
            "debug",
            "--artifact",
            artifact_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn binary");
    assert!(
        out.status.success(),
        "debug --artifact must exit 0\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("final: pass"),
        "expected 'final: pass' from --artifact OP_1, got:\n{}",
        stdout
    );
}

// Minimal tempdir helper — these tests don't need the `tempfile` crate
// just for one path. Each test allocates its own subdir under target/.
fn tempdir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("runar-rust-cli-debug-{}", nanos));
    std::fs::create_dir_all(&path).expect("create tempdir");
    path
}
