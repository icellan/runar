//! F-219 (CL-BUG-115) — dead-binding elimination only runs behind the EC gate.
//!
//! `anf_optimize::optimize_ec` returns the program untouched when no EC rewrite
//! fired (`if !any_changed { return program; }`) and only calls
//! `dce::eliminate_dead_bindings_method` after that early exit. No other
//! production path DCEs the program (`lib.rs`'s `collect_referenced_props` runs
//! `eliminate_dead_code` on a throw-away probe copy for the issue-#109 warning
//! only). So a contract with no EC rewrite keeps its dead bindings in ANF.
//!
//! TS has the same gate (`optimizeEC` in `optimizer/anf-ec.ts`, pinned by
//! `r194-dce-invocation.test.ts`), and so do Go, Python and Java. Running DCE
//! unconditionally fails to compile 11 conformance fixtures until N-140's
//! liveness work lands (R-194), so the gate stays. What was wrong in this tier
//! was the documentation: `dce.rs` called itself "the canonical, standalone DCE
//! pass", `optimize_ec`'s doc said it "then eliminates dead bindings. Always-on",
//! and `lib.rs`'s IR-input path said it delegates to DCE unconditionally.
//!
//! What this proves: those overclaims are gone, the gate still precedes the DCE
//! call, and `optimize_ec` keeps an unreferenced, non-preserved `load_prop` in a
//! program with no EC rewrite and drops it once a rewrite fires.
//! What it does not prove: that skipping DCE for non-EC programs is desirable,
//! or anything about emitted bytes. Stack lowering drops the dead chain itself:
//! for a non-EC contract with a dead `const unused = this.b + 1n`, TS and Rust
//! both emit `008b7c009c77` in both fold modes.

use runar_compiler_rust::frontend::anf_optimize::optimize_ec;
use runar_compiler_rust::ir::{ANFBinding, ANFMethod, ANFProgram, ANFValue};

fn read_src(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Part A: the overclaiming comments are gone (red at the pre-fix HEAD).
// ---------------------------------------------------------------------------

#[test]
fn dce_header_no_longer_claims_to_be_a_standalone_pass() {
    let src = read_src("src/frontend/dce.rs");
    let header: String = src.lines().take_while(|l| l.starts_with("//!")).collect::<Vec<_>>().join("\n");
    assert!(
        !header.contains("standalone DCE pass"),
        "dce.rs calls itself a standalone DCE pass; its only production caller is \
         anf_optimize::optimize_ec, after the any_changed gate"
    );
    assert!(
        header.contains("optimize_ec"),
        "the dce.rs header should name optimize_ec as its production caller"
    );
}

#[test]
fn optimize_ec_doc_no_longer_claims_dce_always_runs() {
    let src = read_src("src/frontend/anf_optimize.rs");
    let fn_at = src.find("pub fn optimize_ec(").expect("optimize_ec not found");
    let doc_start = src[..fn_at].rfind("/// Optimize EC operations").expect("optimize_ec doc not found");
    let doc = &src[doc_start..fn_at];
    assert!(
        !doc.contains("then eliminates dead bindings. Always-on"),
        "optimize_ec's doc says it always eliminates dead bindings; it returns early \
         when no EC rewrite fired"
    );
    assert!(doc.contains("any_changed"), "optimize_ec's doc should name the any_changed gate");
}

#[test]
fn lib_ir_path_comment_no_longer_claims_unconditional_dce() {
    let src = read_src("src/lib.rs");
    assert!(
        !src.contains("Delegates internally to frontend::dce for dead-binding cleanup.\n"),
        "lib.rs still says the EC pass delegates to DCE unconditionally"
    );
}

// ---------------------------------------------------------------------------
// Part B: positional tripwire. Green before and after; it guards against
// someone moving the DCE call ahead of the gate before N-140 lands.
// ---------------------------------------------------------------------------

#[test]
fn ec_gate_still_precedes_the_dce_call() {
    let src = read_src("src/frontend/anf_optimize.rs");
    let fn_at = src.find("pub fn optimize_ec(").expect("optimize_ec not found");
    let body = &src[fn_at..];
    let gate = body.find("if !any_changed {").expect("the any_changed early exit is gone");
    let call = body
        .find(".map(eliminate_dead_bindings_method)")
        .expect("optimize_ec no longer calls eliminate_dead_bindings_method");
    assert!(
        call > gate,
        "the DCE call moved ahead of the EC gate. Per R-194 that breaks 11 conformance \
         fixtures until N-140's liveness work lands; fix DCE first, then update the docs \
         and this test"
    );
}

// ---------------------------------------------------------------------------
// Part C: behavioural pin of optimize_ec.
// ---------------------------------------------------------------------------

const INFINITY_HEX: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn b(name: &str, value: ANFValue) -> ANFBinding {
    ANFBinding { name: name.to_string(), value, source_loc: None }
}

fn dead_load_prop() -> ANFBinding {
    b("dead", ANFValue::LoadProp { name: "p".to_string(), preserve: false })
}

fn program(body: Vec<ANFBinding>) -> ANFProgram {
    ANFProgram {
        contract_name: "Test".to_string(),
        parent_class: String::new(),
        properties: vec![],
        methods: vec![ANFMethod {
            name: "m".to_string(),
            params: vec![],
            body,
            is_public: true,
            sighash_type: None,
        }],
    }
}

fn has(p: &ANFProgram, name: &str) -> bool {
    p.methods[0].body.iter().any(|x| x.name == name)
}

#[test]
fn non_ec_program_keeps_its_dead_binding() {
    let out = optimize_ec(program(vec![
        dead_load_prop(),
        b("t0", ANFValue::LoadConst { value: serde_json::Value::Bool(true) }),
        b("t1", ANFValue::Assert { value: "t0".to_string(), is_auto_injected_state_check: false }),
    ]));
    assert!(has(&out, "dead"), "optimize_ec DCE'd a program with no EC rewrite; update the docs");
}

#[test]
fn ec_rewrite_runs_dce_and_drops_the_dead_binding() {
    let out = optimize_ec(program(vec![
        dead_load_prop(),
        b("t0", ANFValue::LoadConst { value: serde_json::Value::String("ab".repeat(64)) }),
        b("t1", ANFValue::LoadConst { value: serde_json::Value::String(INFINITY_HEX.to_string()) }),
        b("t2", ANFValue::Call { func: "ecAdd".to_string(), args: vec!["t0".to_string(), "t1".to_string()] }),
        b("t3", ANFValue::Assert { value: "t2".to_string(), is_auto_injected_state_check: false }),
    ]));
    let t2 = out.methods[0].body.iter().find(|x| x.name == "t2").expect("t2 missing");
    assert!(
        !matches!(t2.value, ANFValue::Call { .. }),
        "the ecAdd(x, INFINITY) rewrite did not fire, so this test proves nothing"
    );
    assert!(!has(&out, "dead"), "an EC rewrite fired but the dead binding survived");
}
