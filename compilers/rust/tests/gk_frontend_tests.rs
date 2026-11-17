//! Grok v1 frontend findings, Rust tier. The corpora are the cross-tier ones
//! in conformance/negatives/, shared with the other six tiers' unit tests and
//! the conformance negatives gates.
//!
//! - GK-BUG-015: a repeated method name is a validate error with the shared
//!   message, and the compile finishes (two same-named privates with
//!   different Sig consumption could make the consumption fixpoint spin).
//! - GK-GAP-013: `lower_to_anf` refuses malformed intent-intrinsic calls
//!   instead of lowering them to `load_const ""`; typecheck refuses first.
//! - GK-GAP-010: a public method's SigHashPreimage parameter must reach
//!   checkPreimage on every path.
//! - GK-GAP-005/006: suffixes match ignoring ASCII case, an unknown suffix is
//!   refused with the shared message, and no file name means TypeScript.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use runar_compiler_rust::compile_from_source_str;
use runar_compiler_rust::frontend::anf_lower::lower_to_anf;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::frontend::typecheck::typecheck;
use serde_json::Value;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus(name: &str) -> Value {
    let raw = std::fs::read_to_string(repo().join("conformance/negatives").join(name)).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

/// Compile on a worker thread with a hard deadline, so a hang fails the test.
fn compile_with_deadline(src: &str, file: &str) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    let (src, file) = (src.to_string(), file.to_string());
    std::thread::spawn(move || {
        let r = compile_from_source_str(&src, Some(&file)).map(|a| a.script);
        let _ = tx.send(r);
    });
    rx.recv_timeout(Duration::from_secs(60))
        .unwrap_or_else(|_| Err("TIMEOUT: compile did not finish within 60s".to_string()))
}

#[test]
fn gk015_duplicate_method_is_refused() {
    let c = corpus("duplicate-method-cases.json");
    for case in c["cases"].as_array().unwrap() {
        let err = compile_with_deadline(s(case, "src"), s(case, "file"))
            .expect_err(&format!("{} accepted", s(case, "name")));
        assert!(err.contains(s(case, "error")), "{}: {err}", s(case, "name"));
        compile_with_deadline(s(case, "twin"), s(case, "file"))
            .unwrap_or_else(|e| panic!("{} twin refused: {e}", s(case, "name")));
    }
}

#[test]
fn gk013_lowerer_refuses_malformed_intent_shapes() {
    let c = corpus("intent-shape-cases.json");
    for case in c["cases"].as_array().unwrap() {
        let parsed = parse_source(s(case, "src"), Some("Bad.runar.ts"));
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        let contract = parsed.contract.unwrap();
        assert!(!typecheck(&contract).errors.is_empty(), "typecheck accepted {}", s(case, "name"));
        let msg = match std::panic::catch_unwind(|| lower_to_anf(&contract)) {
            Ok(_) => "LOWERED".to_string(),
            Err(e) => e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default(),
        };
        assert!(msg.contains(s(case, "lowerError")), "{}: {msg}", s(case, "name"));
    }
}

#[test]
fn gk010_preimage_checked_on_every_path() {
    let c = corpus("preimage-checked-cases.json");
    for case in c["refuse"].as_array().unwrap() {
        let err = compile_from_source_str(s(case, "src"), Some(s(case, "file")))
            .err()
            .unwrap_or_else(|| panic!("{} accepted", s(case, "name")));
        assert!(err.contains(s(case, "error")), "{}: {err}", s(case, "name"));
    }
    for case in c["accept"].as_array().unwrap() {
        compile_from_source_str(s(case, "src"), Some(s(case, "file")))
            .unwrap_or_else(|e| panic!("{} refused: {e}", s(case, "name")));
    }
}

#[test]
fn gk005_extension_dispatch() {
    let ts = std::fs::read_to_string(repo().join("examples/ts/p2pkh/P2PKH.runar.ts")).unwrap();
    let py = std::fs::read_to_string(repo().join("examples/python/p2pkh/P2PKH.runar.py")).unwrap();
    for (src, lower, upper) in [(&ts, "P2PKH.runar.ts", "P2PKH.RUNAR.TS"), (&py, "P2PKH.runar.py", "P2PKH.RUNAR.PY")] {
        let a = compile_from_source_str(src, Some(lower)).expect(lower).script;
        let b = compile_from_source_str(src, Some(upper)).expect(upper).script;
        assert_eq!(a, b, "{lower} vs {upper}");
    }
    let want = "unsupported file extension: P2PKH.runar.xyz (expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, .runar.py, .runar.rb, .runar.zig, or .runar.java)";
    let x = parse_source(&ts, Some("P2PKH.runar.xyz"));
    assert!(x.contract.is_none(), "unknown suffix parsed as TypeScript");
    assert_eq!(x.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>(), vec![want.to_string()]);
    for name in [None, Some("")] {
        let n = parse_source(&ts, name);
        assert!(n.contract.is_some() && n.errors.is_empty(), "{name:?}: {:?}", n.errors);
    }
}

