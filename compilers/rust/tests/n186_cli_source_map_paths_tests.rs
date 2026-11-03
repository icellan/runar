//! N-186: `--emit-source-map` must never be silently dropped. The Zig and TS
//! CLIs dropped it under `--hex` and for an IR input (exit 0, nothing
//! written). The Rust CLI already writes it on those paths; these tests pin
//! that so it cannot regress into the same silent drop.
//!
//! What this proves: the built `runar-compiler-rust` binary, given
//! `--emit-source-map <path>` with `--source --hex`, `--ir`, `--ir --hex` or
//! `--ir --asm`, exits 0 and writes a `{"mappings": ...}` file. An ANF IR
//! carries no source locations, so for `--ir` the mappings array is empty
//! (the same file every other tier's CLI writes). It does not prove any other
//! tier's CLI.

use std::path::PathBuf;
use std::process::Command;

fn tempdir(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("runar-rust-n186-{}-{}", std::process::id(), tag));
    std::fs::create_dir_all(&path).expect("create tempdir");
    path
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn run_with_map(tag: &str, args: &[&str]) -> (std::process::Output, serde_json::Value) {
    let sm_path = tempdir(tag).join("source-map.json");
    let _ = std::fs::remove_file(&sm_path);
    let out = Command::new(env!("CARGO_BIN_EXE_runar-compiler-rust"))
        .args(args)
        .args(["--emit-source-map", sm_path.to_str().unwrap()])
        .output()
        .expect("spawn binary");
    assert!(
        out.status.success(),
        "must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        sm_path.exists(),
        "--emit-source-map file was never written (N-186); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&sm_path).expect("read source map");
    let json: serde_json::Value = serde_json::from_str(&text).expect("source map must be JSON");
    assert!(json.get("mappings").is_some(), "must carry a mappings key, got: {}", text);
    (out, json)
}

#[test]
fn hex_with_emit_source_map_writes_the_source_map() {
    let src = repo_root().join("examples/rust/p2pkh/P2PKH.runar.rs");
    let (out, json) = run_with_map("src-hex", &["--source", src.to_str().unwrap(), "--hex"]);
    assert!(!json["mappings"].as_array().unwrap().is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty() && stdout.trim().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn ir_input_with_emit_source_map_writes_the_empty_source_map() {
    let ir = repo_root().join("conformance/tests/basic-p2pkh/expected-ir.json");
    for (tag, extra) in [("ir-plain", None), ("ir-hex", Some("--hex")), ("ir-asm", Some("--asm"))] {
        let mut args = vec!["--ir", ir.to_str().unwrap()];
        if let Some(e) = extra {
            args.push(e);
        }
        let (_out, json) = run_with_map(tag, &args);
        assert!(json["mappings"].as_array().unwrap().is_empty(), "{}: IR has no source locations", tag);
    }
}
