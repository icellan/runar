//! F-255: `--emit-ir` silently dropped `--emit-source-map`, exiting 0
//! having written nothing.
//!
//! The `--emit-ir` branch in `main.rs` printed the ANF IR JSON and `return`ed
//! unconditionally, before the code further down that services
//! `--emit-source-map` ever ran. `--source X --emit-ir --emit-source-map Y`
//! exited 0 and Y was never created — the request was silently dropped, not
//! refused. Go had the identical bug (F-183) and Java was always correct
//! ("GAP-002: --emit-source-map ... runs INDEPENDENTLY of --emit-ir"); this
//! ports Go's fix (fall through into the full compile so SourceMapData gets
//! populated, write the source map, THEN stop before the hex/asm/artifact
//! output) to the Rust tier.
//!
//! What this test proves: the built `runar-compiler-rust` binary, given
//! `--emit-ir` together with `--emit-source-map <path>`, exits 0, writes a
//! `{"mappings": [...]}` file to `<path>`, and prints ONLY the IR JSON on
//! stdout (no `"script"` field — `--emit-ir`'s contract is "stdout carries
//! only the IR").
//! What it does not prove: the two flags combined with `--hex` or `--asm`;
//! any other tier's CLI (those are separate test files per tier).

use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    // Cargo sets CARGO_BIN_EXE_<name> for integration tests when the binary
    // belongs to the same package — the canonical way to find the built
    // binary without re-invoking cargo build.
    PathBuf::from(env!("CARGO_BIN_EXE_runar-compiler-rust"))
}

fn tempdir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("runar-rust-cli-emit-ir-source-map-{}", nanos));
    std::fs::create_dir_all(&path).expect("create tempdir");
    path
}

fn repo_root() -> PathBuf {
    // compilers/rust -> compilers -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn emit_ir_with_emit_source_map_writes_the_source_map_and_prints_only_ir() {
    let source = repo_root().join("examples/rust/p2pkh/P2PKH.runar.rs");
    assert!(source.exists(), "missing fixture: {:?}", source);

    let tmp = tempdir();
    let sm_path = tmp.join("source-map.json");
    assert!(
        !sm_path.exists(),
        "sanity: source map path must not pre-exist"
    );

    let out = Command::new(bin_path())
        .args([
            "--source",
            source.to_str().expect("utf8 path"),
            "--emit-ir",
            "--emit-source-map",
            sm_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("spawn binary");

    assert!(
        out.status.success(),
        "--emit-ir --emit-source-map must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // The finding itself: the file must actually be written.
    assert!(
        sm_path.exists(),
        "--emit-source-map file was never written (F-255 regression); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sm_contents = std::fs::read_to_string(&sm_path).expect("read source map");
    let sm_json: serde_json::Value =
        serde_json::from_str(&sm_contents).expect("source map must be valid JSON");
    assert!(
        sm_json.get("mappings").is_some(),
        "source map JSON must carry a \"mappings\" key, got: {}",
        sm_contents
    );

    // --emit-ir's contract: stdout carries only the IR, never the full
    // artifact (which would carry a "script" field).
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stdout_json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be the IR JSON");
    assert!(
        stdout_json.get("contractName").is_some(),
        "stdout must be ANF IR (expected a contractName field), got: {}",
        stdout
    );
    assert!(
        stdout_json.get("script").is_none(),
        "stdout must carry ONLY the IR, not the compiled artifact; got: {}",
        stdout
    );
}
