//! N-499 -- the artifact `anf` section's sourceLoc values equal the TS ones.
//!
//! The Rust frontend carries 1-based columns internally (diagnostics subtract
//! one when printing, N-078; the source map subtracts one at emission). The
//! TS reference artifact is 0-based, so a stateful artifact's embedded ANF
//! must report 0-based `sourceLoc.column` too. Each source below is compiled
//! with constant folding off and the (line, column) of every ANF binding,
//! walked depth-first in method order through `if` then/else and `loop`
//! bodies, is compared with the TS compiler's, pinned in the Zig tier's
//! n475/n487 reference JSON files (null = the binding carries no sourceLoc).
//!
//! What this proves: for those 30 files the Rust artifact's anf sourceLoc
//! line/column equals TS for every binding of every method, constructor
//! included, including which bindings carry none.
//! What this does not prove: fold-on artifacts; sources outside those files;
//! the TS values are pinned, not recomputed, so a TS-side change needs a
//! re-pin.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

const REFERENCES: [&str; 2] = [
    include_str!("../../zig/src/tests/n475_ts_anf_sourceloc_reference.json"),
    include_str!("../../zig/src/tests/n487_ts_anf_sourceloc_reference.json"),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn walk(bindings: &[Value], acc: &mut Vec<Option<(i64, i64)>>) {
    for b in bindings {
        acc.push(b.get("sourceLoc").map(|s| (s["line"].as_i64().unwrap(), s["column"].as_i64().unwrap())));
        let v = &b["value"];
        for k in ["then", "else", "body"] {
            if let Some(arr) = v.get(k).and_then(|x| x.as_array()) {
                walk(arr, acc);
            }
        }
    }
}

#[test]
fn artifact_anf_sourceloc_equals_the_pinned_ts_reference() {
    let mut failures = Vec::new();
    let mut checked = 0;
    for reference in REFERENCES {
        let refs: Value = serde_json::from_str(reference).unwrap();
        for (rel, want) in refs.as_object().unwrap() {
            let src = repo_root().join(rel);
            let out = Command::new(env!("CARGO_BIN_EXE_runar-compiler-rust"))
                .args(["--source", src.to_str().unwrap(), "--disable-constant-folding"])
                .output()
                .expect("run compiler");
            assert!(out.status.success(), "{rel}: {}", String::from_utf8_lossy(&out.stderr));
            let art: Value = serde_json::from_slice(&out.stdout).unwrap();
            let mut got = Vec::new();
            for m in art["anf"]["methods"].as_array().expect("artifact has anf") {
                walk(m["body"].as_array().unwrap(), &mut got);
            }
            let want: Vec<Option<(i64, i64)>> = want
                .as_array()
                .unwrap()
                .iter()
                .map(|w| w.as_array().map(|a| (a[0].as_i64().unwrap(), a[1].as_i64().unwrap())))
                .collect();
            checked += 1;
            if got != want {
                let i = (0..want.len().min(got.len())).find(|&i| got[i] != want[i]).unwrap_or(want.len().min(got.len()));
                failures.push(format!("{rel}: binding {i} differs (TS {} / Rust {} bindings) TS {:?} Rust {:?}", want.len(), got.len(), want.get(i), got.get(i)));
            }
        }
    }
    assert_eq!(checked, 30);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
