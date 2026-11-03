//! F-086 — a name minted by the EC optimizer must never collide with a name
//! the method already uses.
//!
//! The scalar-fusing rules (9, 10, 11) bind the folded scalar under a
//! generated name (`<binding>_k` in this tier) just before the rewritten
//! binding. ANF is single-assignment and stack lowering resolves a name to its
//! shallowest slot, so when `<binding>_k` is already a body binding or a
//! method param the two values alias. Reachable from `--ir`, where names are
//! attacker-chosen. Pre-fix, `s_k = 999; s = ecAdd(ecMulGen(2), ecMulGen(3));
//! assert(k == s_k)` compiled to a script that accepts k = 5 and rejects the
//! honest k = 999 (@bsv/sdk Spend.validate, strict v1 — F-086 remediation log).
//!
//! Proves: the minted name is fresh w.r.t. every binding (at any depth), param
//! and property; colliding programs compile to exactly the script of their
//! renamed twins; the no-collision name is unchanged.
//! Does not prove: anything about names minted by stack lowering
//! (`_codePart`, `__param_*`, `__merge$*`).

use runar_compiler_rust::compile_from_ir_str;
use runar_compiler_rust::frontend::anf_optimize::optimize_ec;
use runar_compiler_rust::ir::loader::load_ir_from_str;
use runar_compiler_rust::ir::{ANFMethod, ANFValue};
use serde_json::json;

fn program_json(body_name: Option<&str>, k_param: &str) -> String {
    let mut body = vec![];
    if let Some(n) = body_name {
        body.push(json!({"name": n, "value": {"kind": "load_const", "value": 999}}));
    }
    body.extend([
        json!({"name": "t1", "value": {"kind": "load_const", "value": 2}}),
        json!({"name": "t2", "value": {"kind": "call", "func": "ecMulGen", "args": ["t1"]}}),
        json!({"name": "t3", "value": {"kind": "load_const", "value": 3}}),
        json!({"name": "t4", "value": {"kind": "call", "func": "ecMulGen", "args": ["t3"]}}),
        json!({"name": "s", "value": {"kind": "call", "func": "ecAdd", "args": ["t2", "t4"]}}),
        json!({"name": "t5", "value": {"kind": "load_param", "name": "p"}}),
        json!({"name": "t6", "value": {"kind": "bin_op", "op": "===", "left": "s", "right": "t5"}}),
        json!({"name": "t7", "value": {"kind": "assert", "value": "t6"}}),
        json!({"name": "t8", "value": {"kind": "load_param", "name": k_param}}),
    ]);
    let rhs = match body_name {
        Some(n) => n.to_string(),
        None => {
            body.push(json!({"name": "t9c", "value": {"kind": "load_const", "value": 999}}));
            "t9c".to_string()
        }
    };
    body.push(json!({"name": "t9", "value": {"kind": "bin_op", "op": "===", "left": "t8", "right": rhs}}));
    body.push(json!({"name": "t10", "value": {"kind": "assert", "value": "t9"}}));
    json!({
        "contractName": "EcOptCollide",
        "properties": [],
        "methods": [
            {"name": "constructor", "isPublic": false, "params": [],
             "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
            {"name": "unlock", "isPublic": true,
             "params": [{"name": "p", "type": "Point"}, {"name": k_param, "type": "bigint"}],
             "body": body}
        ]
    })
    .to_string()
}

fn optimized_unlock(json: &str) -> ANFMethod {
    let program = optimize_ec(load_ir_from_str(json).expect("load"));
    program.methods.into_iter().find(|m| m.name == "unlock").unwrap()
}

/// The scalar the rewritten `s` consumes: the (unique) prior binding of its arg.
fn fused_scalar(m: &ANFMethod) -> serde_json::Value {
    let i = m.body.iter().position(|b| b.name == "s").unwrap();
    let arg = match &m.body[i].value {
        ANFValue::Call { func, args } => {
            assert_eq!(func, "ecMulGen");
            args[0].clone()
        }
        other => panic!("s not rewritten: {:?}", other),
    };
    assert!(m.params.iter().all(|p| p.name != arg), "fused scalar {arg} is a param name");
    let prior: Vec<_> = m.body[..i].iter().filter(|b| b.name == arg).collect();
    assert_eq!(prior.len(), 1, "fused scalar name {arg} bound {} times", prior.len());
    match &prior[0].value {
        ANFValue::LoadConst { value } => value.clone(),
        other => panic!("fused scalar not a const: {:?}", other),
    }
}

fn assert_single_assignment(m: &ANFMethod) {
    let mut seen = std::collections::HashSet::new();
    for b in &m.body {
        assert!(seen.insert(b.name.clone()), "binding {} assigned twice", b.name);
        assert!(m.params.iter().all(|p| p.name != b.name), "binding {} shadows a param", b.name);
    }
}

fn as_int(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.trim_end_matches('n').to_string(),
        other => panic!("unexpected const {:?}", other),
    }
}

#[test]
fn f086_control_no_collision_keeps_historical_name() {
    let m = optimized_unlock(&program_json(None, "k"));
    assert!(m.body.iter().any(|b| b.name == "s_k"));
    assert_eq!(as_int(&fused_scalar(&m)), "5");
}

#[test]
fn f086_preexisting_body_binding_is_not_shadowed() {
    let m = optimized_unlock(&program_json(Some("s_k"), "k"));
    assert_single_assignment(&m);
    assert_eq!(as_int(&fused_scalar(&m)), "5");
}

#[test]
fn f086_param_is_not_shadowed() {
    let m = optimized_unlock(&program_json(None, "s_k"));
    assert_single_assignment(&m);
    assert_eq!(as_int(&fused_scalar(&m)), "5");
}

#[test]
fn f086_colliding_programs_compile_like_their_renamed_twins() {
    let hex = |j: String| compile_from_ir_str(&j).expect("compile").script;
    assert_eq!(hex(program_json(Some("s_k"), "k")), hex(program_json(Some("zz_unused"), "k")));
    assert_eq!(hex(program_json(None, "s_k")), hex(program_json(None, "zz")));
}
