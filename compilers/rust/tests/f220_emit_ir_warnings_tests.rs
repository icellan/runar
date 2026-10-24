//! F-220: `--emit-ir` discarded every compiler warning, including the H2
//! locktime-bypass advisory.
//!
//! The `--emit-ir` branch in `main.rs` called
//! `compile_source_to_ir_with_options`, which returns
//! `Result<ANFProgram, String>`, a type with no room for a warning. It printed
//! the IR and returned, so a contract that reads `extractLocktime` without an
//! `extractSequence` finality guard compiled in silence under `--emit-ir`,
//! while the same contract under `--hex` printed the warning. The issue-#109
//! `@embedAlways` DCE notice was dropped the same way.
//!
//! The TS CLI prints every warning-severity diagnostic to stderr as
//! `warning: <msg>` before any output mode, without changing the exit code or
//! stdout. These tests hold `--emit-ir` to the same rule by comparing it with
//! this binary's own `--hex` run.
//!
//! What this proves: for a contract carrying the H2 locktime warning and one
//! carrying the #109 DCE notice, the built `runar-compiler-rust` binary under
//! `--emit-ir` exits 0, prints exactly the stderr that `--hex` prints, and
//! keeps stdout to the IR JSON (no `"script"` key). With `--emit-source-map`
//! as well (the F-255 fall-through into the full compile), the warning is
//! printed exactly once, not twice.
//! What it does not prove: the `--ir` input path (it runs no validator and has
//! no source warnings), any other tier's CLI (each has its own test), or that
//! the warning text itself is right (the validator tests own that).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const LOCKTIME_SOURCE: &str = r#"import { StatefulSmartContract, assert, extractLocktime } from 'runar-lang';

class TimeLock extends StatefulSmartContract {
    count: bigint;
    readonly deadline: bigint;
    constructor(count: bigint, deadline: bigint) {
        super(count, deadline);
        this.count = count;
        this.deadline = deadline;
    }
    public unlock() {
        assert(extractLocktime(this.txPreimage) >= this.deadline);
        this.count++;
    }
}
"#;
const LOCKTIME_NEEDLE: &str = "does not assert extractSequence";

const DCE_SOURCE: &str = r#"import { SmartContract, assert, PubKey, Sig, Addr, checkSig, hash160 } from 'runar-lang';

class Unused extends SmartContract {
    readonly pubKeyHash: Addr;
    readonly memo: bigint;
    constructor(pubKeyHash: Addr, memo: bigint) {
        super(pubKeyHash, memo);
        this.pubKeyHash = pubKeyHash;
        this.memo = memo;
    }
    public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
    }
}
"#;
const DCE_NEEDLE: &str = "readonly field 'memo' is not referenced";

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_runar-compiler-rust"))
}

fn tempdir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("runar-rust-f220-{}-{}-{}", tag, std::process::id(), n));
    std::fs::create_dir_all(&path).expect("create tempdir");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(bin_path()).args(args).output().expect("spawn binary")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn assert_emit_ir_prints_the_hex_warnings(dir: &Path, file: &str, source: &str, needle: &str) {
    let src = dir.join(file);
    std::fs::write(&src, source).expect("write source");
    let src = src.to_str().expect("utf8 path");

    let hex = run(&["--source", src, "--hex"]);
    assert!(hex.status.success(), "--hex must exit 0; stderr: {}", stderr_of(&hex));
    assert!(
        stderr_of(&hex).contains(needle),
        "sanity: --hex must print the warning; stderr: {}",
        stderr_of(&hex)
    );

    let ir = run(&["--source", src, "--emit-ir"]);
    assert!(ir.status.success(), "--emit-ir must exit 0; stderr: {}", stderr_of(&ir));
    assert_eq!(
        stderr_of(&ir),
        stderr_of(&hex),
        "--emit-ir must print the same warnings as --hex (F-220)"
    );

    let stdout = String::from_utf8_lossy(&ir.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("--emit-ir stdout must be the IR JSON alone");
    assert!(json.get("contractName").is_some(), "stdout must be ANF IR: {}", stdout);
    assert!(json.get("script").is_none(), "stdout must carry only the IR: {}", stdout);
}

#[test]
fn emit_ir_prints_the_h2_locktime_warning() {
    let dir = tempdir("locktime");
    assert_emit_ir_prints_the_hex_warnings(&dir, "TimeLock.runar.ts", LOCKTIME_SOURCE, LOCKTIME_NEEDLE);
}

#[test]
fn emit_ir_prints_the_embed_always_dce_notice() {
    let dir = tempdir("dce");
    assert_emit_ir_prints_the_hex_warnings(&dir, "Unused.runar.ts", DCE_SOURCE, DCE_NEEDLE);
}

#[test]
fn emit_ir_with_emit_source_map_prints_the_warning_once() {
    let dir = tempdir("sourcemap");
    let src = dir.join("TimeLock.runar.ts");
    std::fs::write(&src, LOCKTIME_SOURCE).expect("write source");
    let sm = dir.join("source-map.json");

    let out = run(&[
        "--source",
        src.to_str().unwrap(),
        "--emit-ir",
        "--emit-source-map",
        sm.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "must exit 0; stderr: {}", stderr_of(&out));
    assert!(sm.exists(), "F-255: the source map must still be written");
    assert_eq!(
        stderr_of(&out).matches(LOCKTIME_NEEDLE).count(),
        1,
        "the warning must be printed exactly once; stderr: {}",
        stderr_of(&out)
    );
}

// N-377: proves tempdir(tag) never hands two callers the same path, even when
// called back to back with the same tag. Does not prove uniqueness across
// processes beyond the pid component.
#[test]
fn n377_tempdir_paths_are_unique() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                (0..200).map(|_| tempdir("uniq")).collect::<Vec<PathBuf>>()
            })
        })
        .collect();
    let dirs: Vec<PathBuf> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let set: std::collections::HashSet<&PathBuf> = dirs.iter().collect();
    for d in &dirs {
        let _ = std::fs::remove_dir_all(d);
    }
    assert_eq!(set.len(), dirs.len(), "tempdir() returned duplicate paths");
}
