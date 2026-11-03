//! F-105: a hostile `--ir` program must not be able to panic the compiler in
//! artifact assembly.
//!
//! `assemble_artifact` regroups synthetic FixedArray leaves by popping one
//! `syntheticArrayChain` level per pass, under a 1024-pass cap. The cap used to
//! end in `panic!`, and `assemble_artifact` runs after the guarded `emit` pass,
//! outside every `catch_unwind` — so an IR whose chain is deeper than the cap
//! aborted the process (exit 101, "thread 'main' panicked") instead of being
//! refused with a diagnostic.
//!
//! What these tests prove: the crafted IR (basic-p2pkh plus one constructor
//! property carrying a 1100-level chain of `{index: 0, length: 1}`) is refused
//! with an ordinary `Err` through the library entry point, and with a nonzero,
//! non-panic exit plus a `Compilation error:` diagnostic through the CLI. The control
//! (same IR, 5 levels) still compiles, so the refusal is driven by the depth,
//! not by the shape.
//!
//! What they do not prove: which layer refuses. A loader-side chain check
//! (another item) may reject this IR before assembly; the tests accept any
//! diagnostic as long as nothing panics. They also do not prove that every
//! other post-emit code path is panic-free for arbitrary IR.

use std::path::PathBuf;
use std::process::Command;

use runar_compiler_rust::compile_from_ir_str;
use serde_json::{json, Value};

fn p2pkh_ir_with_chain_depth(depth: usize) -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/tests/basic-p2pkh/expected-ir.json"
    );
    let mut ir: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read p2pkh IR"))
            .expect("parse p2pkh IR");
    // N-096: the chain is the one expand-fixed-arrays writes for a
    // `FixedArray<...<bigint, 1>..., 1>` named `deep` (each level's base is
    // the previous `<base>__<index>`, the leaf is named after the innermost
    // level), so the loader's chain rule refuses it for its DEPTH alone.
    let mut base = "deep".to_string();
    let mut chain: Vec<Value> = Vec::with_capacity(depth);
    for _ in 0..depth {
        chain.push(json!({"base": base, "index": 0, "length": 1}));
        base.push_str("__0");
    }
    ir["properties"].as_array_mut().expect("properties").push(json!({
        "name": base,
        "type": "bigint",
        "readonly": true,
        "syntheticArrayChain": chain,
    }));
    serde_json::to_string(&ir).expect("serialize IR")
}

#[test]
fn chain_deeper_than_regroup_cap_is_a_diagnostic_not_a_panic() {
    let ir = p2pkh_ir_with_chain_depth(1100);
    let outcome = std::panic::catch_unwind(|| compile_from_ir_str(&ir));
    match outcome {
        Err(_) => panic!("compile_from_ir_str panicked on a 1100-level syntheticArrayChain"),
        Ok(Ok(_)) => panic!("a 1100-level syntheticArrayChain compiled; expected a refusal"),
        Ok(Err(msg)) => assert!(!msg.is_empty(), "refusal carried an empty diagnostic"),
    }
}

#[test]
fn chain_within_cap_still_compiles() {
    let ir = p2pkh_ir_with_chain_depth(5);
    compile_from_ir_str(&ir).expect("a 5-level chain of length-1 arrays must compile");
}

#[test]
fn cli_refuses_deep_chain_with_nonzero_exit_and_no_panic() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let ir_path = dir.join("f105_deep_chain.ir.json");
    std::fs::write(&ir_path, p2pkh_ir_with_chain_depth(1100)).expect("write IR");

    let out = Command::new(env!("CARGO_BIN_EXE_runar-compiler-rust"))
        .arg("--ir")
        .arg(&ir_path)
        .output()
        .expect("spawn binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "deep chain must exit nonzero; stderr: {stderr}");
    assert_ne!(out.status.code(), Some(101), "exit 101 is a Rust panic; stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "compiler panicked: {stderr}");
    assert!(
        stderr.contains("Compilation error:"),
        "expected a `Compilation error:` diagnostic, got: {stderr}"
    );
}
