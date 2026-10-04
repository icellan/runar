//! F-108 — DCE must treat a PRIVATE method's last binding as a liveness root.
//!
//! Stack lowering inlines a private helper at each `method_call` and takes the
//! helper's LAST binding as the call's result. Nothing inside the helper
//! references that binding, so a pure return expression (`return n + 1n`) was
//! deleted whenever DCE ran — which in this tier happens to every method once
//! any EC rewrite fires anywhere in the program. The helper was emptied and the
//! contract failed to compile ("value 't2' not found on stack").
//!
//! What this proves: `eliminate_dead_bindings_method` keeps a private method's
//! final binding and its inputs, still drops a genuinely dead binding ahead of
//! it, and still drops an unreferenced pure final binding of a PUBLIC method.
//! What it does not prove: spendability — `conformance/dce/private-return.test.ts`
//! executes the compiled script on all seven tiers.

use runar_compiler_rust::frontend::dce::eliminate_dead_bindings_method;
use runar_compiler_rust::ir::{ANFBinding, ANFMethod, ANFParam, ANFValue};

fn binding(name: &str, value: ANFValue) -> ANFBinding {
    ANFBinding { name: name.to_string(), value, source_loc: None }
}

fn add1(is_public: bool) -> ANFMethod {
    ANFMethod {
        name: if is_public { "pub_m" } else { "add1" }.to_string(),
        params: vec![ANFParam { name: "n".to_string(), param_type: "bigint".to_string() }],
        body: vec![
            binding("dead", ANFValue::LoadConst { value: serde_json::Value::from(7) }),
            binding("t0", ANFValue::LoadParam { name: "n".to_string() }),
            binding("t1", ANFValue::LoadConst { value: serde_json::Value::from(1) }),
            binding(
                "t2",
                ANFValue::BinOp {
                    op: "+".to_string(),
                    left: "t0".to_string(),
                    right: "t1".to_string(),
                    result_type: None,
                },
            ),
        ],
        is_public,
        sighash_type: None,
    }
}

fn names(m: &ANFMethod) -> Vec<&str> {
    m.body.iter().map(|b| b.name.as_str()).collect()
}

#[test]
fn dce_keeps_private_method_return_value() {
    let out = eliminate_dead_bindings_method(&add1(false));
    assert_eq!(
        names(&out),
        vec!["t0", "t1", "t2"],
        "DCE emptied a private helper's return value"
    );
}

#[test]
fn dce_still_drops_public_method_pure_last_binding() {
    let out = eliminate_dead_bindings_method(&add1(true));
    assert!(names(&out).is_empty(), "got {:?}", names(&out));
}
