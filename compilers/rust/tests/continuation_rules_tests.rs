//! #199 (release-trap warning) and D18 (dropped-continuation error), Rust
//! tier. Corpora are the cross-tier ones in conformance/negatives/, shared
//! with the other six tiers and the conformance gates
//! (gk-frontend-parity.test.ts, ir-release-trap.test.ts). Mirrors
//! packages/runar-compiler/src/passes/continuation-rules.ts.

use std::path::PathBuf;

use runar_compiler_rust::frontend::anf_lower::try_lower_to_anf;
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
        let program = match try_lower_to_anf(&expanded.contract) {
            Ok(p) => p,
            // The lowerer itself refuses a write inside an output-declaring
            // branch; that shape is hand-built below instead.
            Err(e) if e.message.contains("both declares outputs and assigns contract properties") => continue,
            Err(e) => panic!("{} lowering failed: {e}", s(case, "name")),
        };
        let json = serde_json::to_string(&program).unwrap();
        assert!(json.contains("\"update_prop\""), "{}", s(case, "name"));
        assert!(json.contains("\"add_raw_output\"") || json.contains("\"add_output\""), "{}", s(case, "name"));
        let err = compile_from_ir_str(&json).err().unwrap_or_else(|| panic!("{} --ir accepted", s(case, "name")));
        assert!(err.contains(s(case, "error")), "{}: {err}", s(case, "name"));
    }
    // The per-path shape only a hand-written IR can carry: the accepted
    // terminal-branch-writes-nothing program with an update_prop added to its
    // raw-output branch (mirrors writeOnRawBranchIr in ir-release-trap.test.ts).
    {
        let base = cases(&c, "accept").iter().find(|x| s(x, "name") == "terminal-branch-writes-nothing").unwrap();
        let want = cases(&c, "refuse").iter().find(|x| s(x, "name") == "write-on-raw-branch-sibling-add-output").unwrap();
        let r = compile_from_source_str_with_result(s(base, "src"), Some(s(base, "file")), &opts());
        let anf = r.anf.expect("terminal-branch-writes-nothing source refused");
        let mut ir: Value = serde_json::to_value(&anf).unwrap();
        let pay = ir["methods"].as_array_mut().unwrap().iter_mut().find(|m| m["name"] == "pay").unwrap();
        let has_raw = |bs: &Value| bs.as_array().is_some_and(|a| a.iter().any(|b| b["value"]["kind"] == "add_raw_output"));
        let ifb = pay["body"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|b| b["value"]["kind"] == "if" && has_raw(&b["value"]["then"]))
            .expect("no raw-output if arm to patch");
        let then = ifb["value"]["then"].as_array_mut().unwrap();
        then.insert(0, serde_json::json!({"name": "d18w1", "value": {"kind": "update_prop", "name": "count", "value": "d18w0"}}));
        then.insert(0, serde_json::json!({"name": "d18w0", "value": {"kind": "load_const", "value": 7}}));
        let err = compile_from_ir_str(&ir.to_string()).err().expect("ir-write-on-raw-branch-sibling-add-output --ir accepted");
        assert!(err.contains(s(want, "error")), "ir-write-on-raw-branch-sibling-add-output: {err}");
    }
    for case in cases(&c, "accept") {
        let r = compile_from_source_str_with_result(s(case, "src"), Some(s(case, "file")), &opts());
        let anf = r.anf.unwrap_or_else(|| panic!("{} source refused", s(case, "name")));
        let json = serde_json::to_string(&anf).unwrap();
        compile_from_ir_str(&json).unwrap_or_else(|e| panic!("{} --ir refused: {e}", s(case, "name")));
    }
}

/// The unchecked ANF of `src` (validate / typecheck skipped), as IR JSON, or
/// None when the lowerer itself refuses a write inside an output-declaring branch.
fn unchecked_ir(src: &str, file: &str, name: &str) -> Option<String> {
    let parsed = parse_source(src, Some(file));
    let contract = parsed.contract.unwrap_or_else(|| panic!("{name} parse failed"));
    let expanded = expand_fixed_arrays(&contract);
    assert!(expanded.errors.is_empty(), "{name} expand failed");
    match try_lower_to_anf(&expanded.contract) {
        Ok(p) => Some(serde_json::to_string(&p).unwrap()),
        Err(e) if e.message.contains("both declares outputs and assigns contract properties") => None,
        Err(e) => panic!("{name} lowering failed: {e}"),
    }
}

/// The shared refuse / accept matrix of one corpus, on the source path and
/// the --ir path.
fn refuse_and_accept(refuse: &[Value], accept: &[Value]) {
    for case in refuse {
        let name = s(case, "name");
        let (errors, _) = compile(s(case, "src"), s(case, "file"));
        assert!(errors.iter().any(|e| e.contains(s(case, "error"))), "{name} not refused; got {errors:?}");
        if let Some(json) = unchecked_ir(s(case, "src"), s(case, "file"), name) {
            let err = compile_from_ir_str(&json).err().unwrap_or_else(|| panic!("{name} --ir accepted"));
            assert!(err.contains(s(case, "error")), "{name}: {err}");
        }
    }
    for case in accept {
        let name = s(case, "name");
        let r = compile_from_source_str_with_result(s(case, "src"), Some(s(case, "file")), &opts());
        let anf = r.anf.unwrap_or_else(|| panic!("{name} source refused: {:?}", r.diagnostics));
        let json = serde_json::to_string(&anf).unwrap();
        compile_from_ir_str(&json).unwrap_or_else(|e| panic!("{name} --ir refused: {e}"));
    }
}

/// D27: a state write after a path's last addOutput is dead on chain.
#[test]
fn d27_refuses_a_write_after_the_last_add_output() {
    let c = corpus("dropped-continuation-cases.json");
    let refuse = cases(&c, "refuse_after_last");
    assert!(refuse.len() >= 5);
    for case in refuse {
        assert!(s(case, "error").contains("writes contract state after the last addOutput()"), "{}", s(case, "name"));
    }
    refuse_and_accept(refuse, cases(&c, "accept"));
}

/// D26: a lower-bound compare on extractLocktime needs an asserted locktime
/// domain pin on its path. Corpus: conformance/negatives/locktime-domain-cases.json.
#[test]
fn d26_refuses_an_unpinned_locktime_gate() {
    let c = corpus("locktime-domain-cases.json");
    assert!(cases(&c, "refuse").len() >= 10 && cases(&c, "accept").len() >= 10);
    refuse_and_accept(cases(&c, "refuse"), cases(&c, "accept"));
}
