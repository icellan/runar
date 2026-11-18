//! #199 (release-trap warning) and D18 (dropped-continuation error), Rust
//! tier. Corpora are the cross-tier ones in conformance/negatives/, shared
//! with the other six tiers and the conformance gates
//! (gk-frontend-parity.test.ts, ir-release-trap.test.ts). Mirrors
//! packages/runar-compiler/src/passes/continuation-rules.ts.

use std::path::PathBuf;

use runar_compiler_rust::frontend::anf_lower::lower_to_anf;
use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::frontend::expand_fixed_arrays::expand_fixed_arrays;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::{compile_from_ir_str, compile_from_source_str_with_result, CompileOptions};
use serde_json::Value;

fn corpus(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/negatives").join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

fn cases<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}

fn opts() -> CompileOptions {
    CompileOptions { disable_constant_folding: true, ..CompileOptions::default() }
}

/// (errors, warnings) of a full source compile.
fn compile(src: &str, file: &str) -> (Vec<String>, Vec<String>) {
    let r = compile_from_source_str_with_result(src, Some(file), &opts());
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for d in r.diagnostics {
        match d.severity {
            Severity::Warning => warnings.push(d.message),
            _ => errors.push(d.message),
        }
    }
    (errors, warnings)
}

#[test]
fn release_trap_199_warns_on_every_warn_case_and_no_nowarn_case() {
    let c = corpus("release-trap-cases.json");
    assert!(cases(&c, "warn").len() >= 3 && cases(&c, "nowarn").len() >= 3);
    for case in cases(&c, "warn") {
        let (errors, warnings) = compile(s(case, "src"), s(case, "file"));
        assert!(errors.is_empty(), "{} refused: {errors:?}", s(case, "name"));
        assert!(
            warnings.iter().any(|w| w.contains(s(case, "warning"))),
            "{} missing warning; got {warnings:?}",
            s(case, "name")
        );
    }
    for case in cases(&c, "nowarn") {
        let (errors, warnings) = compile(s(case, "src"), s(case, "file"));
        assert!(errors.is_empty(), "{} refused: {errors:?}", s(case, "name"));
        assert!(
            !warnings.iter().any(|w| w.contains(s(case, "warning_absent"))),
            "{} carries the warning",
            s(case, "name")
        );
    }
}

#[test]
fn d18_source_refuses_every_refuse_case_and_accepts_every_accept_case() {
    let c = corpus("dropped-continuation-cases.json");
    assert!(cases(&c, "refuse").len() >= 5 && cases(&c, "accept").len() >= 3);
    for case in cases(&c, "refuse") {
        let (errors, _) = compile(s(case, "src"), s(case, "file"));
        assert!(
            errors.iter().any(|e| e.contains(s(case, "error"))),
            "{} not refused with the D18 text; got {errors:?}",
            s(case, "name")
        );
    }
    for case in cases(&c, "accept") {
        let (errors, _) = compile(s(case, "src"), s(case, "file"));
        assert!(errors.is_empty(), "{} refused: {errors:?}", s(case, "name"));
    }
}

/// D18 on the --ir path: each refuse source is lowered with validate /
/// typecheck skipped (the IR a pre-D18 frontend emitted); each accept source's
/// own ANF must still compile from IR.
#[test]
fn d18_ir_path_refuses_dropped_continuation() {
    let c = corpus("dropped-continuation-cases.json");
    for case in cases(&c, "refuse") {
        let parsed = parse_source(s(case, "src"), Some(s(case, "file")));
        let contract = parsed.contract.unwrap_or_else(|| panic!("{} parse failed", s(case, "name")));
        // Pass 3b, as the real pipeline runs it before ANF lowering.
        let expanded = expand_fixed_arrays(&contract);
        assert!(expanded.errors.is_empty(), "{} expand failed", s(case, "name"));
        let json = serde_json::to_string(&lower_to_anf(&expanded.contract)).unwrap();
        assert!(json.contains("\"update_prop\"") && json.contains("\"add_raw_output\""), "{}", s(case, "name"));
        assert!(!json.contains("\"add_output\""), "{}", s(case, "name"));
        let err = compile_from_ir_str(&json).err().unwrap_or_else(|| panic!("{} --ir accepted", s(case, "name")));
        assert!(err.contains(s(case, "error")), "{}: {err}", s(case, "name"));
    }
    for case in cases(&c, "accept") {
        let r = compile_from_source_str_with_result(s(case, "src"), Some(s(case, "file")), &opts());
        let anf = r.anf.unwrap_or_else(|| panic!("{} source refused", s(case, "name")));
        let json = serde_json::to_string(&anf).unwrap();
        compile_from_ir_str(&json).unwrap_or_else(|e| panic!("{} --ir refused: {e}", s(case, "name")));
    }
}
