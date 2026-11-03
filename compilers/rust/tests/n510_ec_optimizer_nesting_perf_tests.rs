//! N-510 — the EC ANF optimizer (pass 4.5) must be near-linear in `if`
//! nesting depth.
//!
//! `optimize_method_ec_once` used to clone, at every nesting level, the whole
//! binding-value map (`ValueMap::nested_scope`) -- and that map held a full
//! copy of every enclosing `if` binding, each with its entire nested subtree --
//! so the pass was cubic in depth. N-264's D=32 x 120 composite input (3,840
//! nested ifs after inlining) took ~30 s in the Rust tier against 0.7 s in Go,
//! which turned `conformance/negatives/n264-composite-nesting-parity.test.ts`
//! into a load-dependent flake (harness timeout 120 s).
//!
//! Proves: optimizing a 400-deep chain of nested ifs (the shape N-264's
//! input lowers to) finishes inside a bound that is generous for a debug
//! build yet far below the pre-fix cost, and leaves the program untouched
//! (no EC call to rewrite). Does not prove: byte-identical output of the full
//! pipeline (the N-264 parity test pins Go's digest for that), nor an exact
//! complexity class -- the bound is wall-clock.

use runar_compiler_rust::frontend::anf_optimize::optimize_ec;
use runar_compiler_rust::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFValue};
use std::time::{Duration, Instant};

const DEPTH: usize = 400;

fn b(name: String, value: ANFValue) -> ANFBinding {
    ANFBinding { name, value, source_loc: None }
}

/// `depth` nested ifs; each level binds a constant, a comparison and the `if`.
fn nested(depth: usize) -> Vec<ANFBinding> {
    let mut inner = vec![b(
        "leaf".to_string(),
        ANFValue::LoadConst { value: serde_json::Value::from(1) },
    )];
    for d in (0..depth).rev() {
        let k = format!("k{d}");
        let c = format!("c{d}");
        inner = vec![
            b(k.clone(), ANFValue::LoadConst { value: serde_json::Value::from(d as i64) }),
            b(c.clone(), ANFValue::BinOp {
                op: ">".to_string(),
                left: "x".to_string(),
                right: k,
                result_type: None,
            }),
            b(format!("i{d}"), ANFValue::If {
                cond: c,
                then: inner,
                else_branch: vec![],
                results: vec![],
            }),
        ];
    }
    inner
}

#[test]
fn ec_optimizer_is_not_superlinear_in_if_nesting() {
    let mut body = vec![b("x".to_string(), ANFValue::LoadParam { name: "x".to_string() })];
    body.extend(nested(DEPTH));
    let program = ANFProgram {
        contract_name: "P".to_string(),
        parent_class: String::new(),
        properties: vec![],
        methods: vec![ANFMethod {
            name: "verify".to_string(),
            params: vec![ANFParam { name: "x".to_string(), param_type: "bigint".to_string() }],
            body,
            is_public: true,
            sighash_type: None,
        }],
    };
    // The optimizer recurses once per nesting level; give it the stack the
    // CLI's worker thread has.
    let elapsed = std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(move || {
            let t = Instant::now();
            let out = optimize_ec(program);
            assert_eq!(out.methods[0].body.len(), 4, "no EC call: body untouched");
            t.elapsed()
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(
        elapsed < Duration::from_secs(3),
        "EC optimizer took {elapsed:?} on {DEPTH} nested ifs (cubic nested-scope cloning)"
    );
}
