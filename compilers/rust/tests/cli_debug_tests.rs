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
    // OP_0 — pushes empty bytes (falsy) → final: fail, and the process must
    // exit non-zero so CI / scripts can rely on the exit status (F-221).
    // Proves: a false-result script is reported on stdout AND as a failing
    // exit status. Does not prove anything about the interpreter itself.
    let out = Command::new(bin_path())
        .args(["debug", "--script", "00"])
        .output()
        .expect("spawn binary");
    assert!(
        !out.status.success(),
        "debug on a falsy script must exit non-zero; got: {:?}",
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
fn debug_interpreter_error_exits_nonzero() {
    // OP_VERIFY on an empty stack — an interpreter error, not a false
    // result. Must still print the final-fail diagnostic and exit non-zero
    // (F-221). Does not prove which error the interpreter raised.
    let out = Command::new(bin_path())
        .args(["debug", "--script", "69"])
        .output()
        .expect("spawn binary");
    assert!(
        !out.status.success(),
        "debug on an erroring script must exit non-zero; got: {:?}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("final: fail (interpreter error"),
        "expected 'final: fail (interpreter error' for OP_VERIFY on empty stack, got:\n{}",
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
    let artifact_path = tmp.path().join("trivial.json");
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

// F-386: `--script` and `--artifact` are meant to be alternatives (the
// usage string says `[--script <hex> | --artifact <path>]`), but the
// resolver in debug_subcommand.rs silently preferred `--script` and ran it
// without ever looking at `--artifact`, exiting 0. Proves: passing both
// flags together is now a diagnosed, non-zero-exit error naming both flags.
// Does not prove: which flag "should" win in any hypothetical future where
// the conflict is instead a documented precedence rather than a refusal —
// that design choice was reserved to the brief's testable assertion
// (explicit diagnostic + non-zero exit), not inferred here.
#[test]
fn debug_conflicting_flags_errors() {
    let tmp = tempdir();
    let artifact_path = tmp.path().join("other.json");
    std::fs::write(&artifact_path, r#"{"script":"52"}"#).expect("write artifact");

    let out = Command::new(bin_path())
        .args([
            "debug",
            "--script",
            "51",
            "--artifact",
            artifact_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn binary");
    assert!(
        !out.status.success(),
        "debug with both --script and --artifact must exit non-zero; got: {:?}\nstdout: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--script") && stderr.contains("--artifact"),
        "expected a diagnostic naming both --script and --artifact, got:\n{}",
        stderr
    );
}

// F-386: `--unlock` was never exercised by an existing test, so a
// regression that dropped the unlocking script on the floor before
// building `SpendParams` would not have been caught. OP_VERIFY (0x69)
// then OP_1 (0x51) as the locking script fails on an empty stack without
// an unlocking script, and passes once `--unlock 51` supplies the value
// OP_VERIFY consumes. Proves: `--unlock`'s hex reaches the interpreter as
// the unlocking script. Does not prove anything about multi-push unlocking
// scripts or script contexts beyond this single-push case.
#[test]
fn debug_unlock_flag_is_applied() {
    let without_unlock = Command::new(bin_path())
        .args(["debug", "--script", "6951"])
        .output()
        .expect("spawn binary");
    assert!(
        !without_unlock.status.success(),
        "OP_VERIFY OP_1 with no unlocking input must fail; got: {:?}",
        without_unlock.status
    );

    let with_unlock = Command::new(bin_path())
        .args(["debug", "--script", "6951", "--unlock", "51"])
        .output()
        .expect("spawn binary");
    assert!(
        with_unlock.status.success(),
        "OP_VERIFY OP_1 with --unlock 51 must pass\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&with_unlock.stdout),
        String::from_utf8_lossy(&with_unlock.stderr)
    );
    let stdout = String::from_utf8_lossy(&with_unlock.stdout);
    assert!(
        stdout.contains("final: pass"),
        "expected 'final: pass' once --unlock supplies the VERIFY input, got:\n{}",
        stdout
    );
}

// F-386: invalid hex in `--script` was never exercised by a test. Proves:
// a non-hex --script value is rejected with a diagnostic naming the
// locking hex, not a panic or a silent empty script.
#[test]
fn debug_invalid_script_hex_errors() {
    let out = Command::new(bin_path())
        .args(["debug", "--script", "zz"])
        .output()
        .expect("spawn binary");
    assert!(
        !out.status.success(),
        "debug with invalid --script hex must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("locking hex"),
        "expected a diagnostic naming the locking hex, got:\n{}",
        stderr
    );
}

// F-386: invalid hex in `--unlock` was never exercised by a test. Proves:
// a non-hex --unlock value is rejected with a diagnostic naming the unlock
// hex, independent of the --script path above.
#[test]
fn debug_invalid_unlock_hex_errors() {
    let out = Command::new(bin_path())
        .args(["debug", "--script", "51", "--unlock", "zz"])
        .output()
        .expect("spawn binary");
    assert!(
        !out.status.success(),
        "debug with invalid --unlock hex must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unlock hex"),
        "expected a diagnostic naming the unlock hex, got:\n{}",
        stderr
    );
}

// F-386: an artifact JSON lacking a `script` field was never exercised by
// a test. Proves: the CLI refuses with a diagnostic rather than running an
// empty/undefined locking script.
#[test]
fn debug_artifact_without_script_field_errors() {
    let tmp = tempdir();
    let artifact_path = tmp.path().join("no-script.json");
    std::fs::write(&artifact_path, r#"{}"#).expect("write artifact");

    let out = Command::new(bin_path())
        .args([
            "debug",
            "--artifact",
            artifact_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn binary");
    assert!(
        !out.status.success(),
        "debug --artifact with no 'script' field must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no 'script' field"),
        "expected a diagnostic about the missing 'script' field, got:\n{}",
        stderr
    );
}

// F-386: an unrecognized flag was never exercised by a test. Proves: an
// unknown flag is rejected with a diagnostic naming it, not silently
// ignored.
#[test]
fn debug_unrecognized_flag_errors() {
    let out = Command::new(bin_path())
        .args(["debug", "--script", "51", "--bogus", "x"])
        .output()
        .expect("spawn binary");
    assert!(
        !out.status.success(),
        "debug with an unrecognized flag must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--bogus"),
        "expected a diagnostic naming the unrecognized flag, got:\n{}",
        stderr
    );
}

// F-386: `-h`/`--help` were never exercised by a test. Proves: both spellings
// exit 0 and print the usage text (to stderr, via `print_usage`'s
// `eprintln!`), rather than falling through to "unrecognized flag" or some
// other error path.
#[test]
fn debug_help_flags_print_usage_and_exit_zero() {
    for flag in ["-h", "--help"] {
        let out = Command::new(bin_path())
            .args(["debug", flag])
            .output()
            .expect("spawn binary");
        assert!(
            out.status.success(),
            "debug {} must exit 0; got: {:?}",
            flag,
            out.status
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("Usage:"),
            "debug {} expected usage text on stderr, got:\n{}",
            flag,
            stderr
        );
    }
}

// Minimal tempdir helper — these tests don't need the `tempfile` crate
// just for one path. Each test allocates its own subdir under the system
// temp dir and the `TempDir` guard removes it on drop (R54 forbids `git
// stash`-adjacent sharing hazards here too: these dirs are process-local,
// but previously nothing ever removed them, leaking a nanosecond-named
// directory per test run under the shared system temp dir — matching the
// cleanup `t.TempDir()` gives the Go sibling suite for free).
struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> TempDir {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("runar-rust-cli-debug-{}", nanos));
    std::fs::create_dir_all(&path).expect("create tempdir");
    TempDir(path)
}
