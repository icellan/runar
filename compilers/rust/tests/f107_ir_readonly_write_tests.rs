//! F-107 (CL-BUG-263) — the `--ir` path must refuse an `update_prop` on a
//! readonly property, at every nesting depth, with the Go tier's F-004
//! diagnostic (`compilers/go/compiler/ir_frontend_rules.go`).
//!
//! Before: the source validator rejects `this.pubKeyHash = …` outside the
//! constructor ("cannot assign to readonly property"), but the same program
//! handed in as ANF IR compiled at exit 0 — the IR path never ran the rule.
//!
//! Proves: `compile_from_ir_str` refuses a readonly write at the top level of a
//! public method, inside an `if` arm, inside a `loop` body and inside a private
//! method; refuses a write to an undeclared property; and still compiles the
//! P2PKH and stateful-counter goldens to their golden hex (a constructor's
//! readonly write and a mutable-property write stay legal).
//!
//! Does not prove: that every validator rule is enforced on IR (only this one
//! and the existing terminal-assert rule are), nor that an accepted IR program
//! is secure — IR is still the developer's program, and it can say anything a
//! valid source program can.

use runar_compiler_rust::compile_from_ir_str;
use serde_json::{json, Value};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/tests");

fn golden(fixture: &str) -> (Value, String) {
    let ir = std::fs::read_to_string(format!("{ROOT}/{fixture}/expected-ir.json")).unwrap();
    let hex = std::fs::read_to_string(format!("{ROOT}/{fixture}/expected-script.hex")).unwrap();
    (serde_json::from_str(&ir).unwrap(), hex.trim().to_string())
}

fn readonly_msg(prop: &str, method: &str) -> String {
    format!(
        "IR validation: cannot assign to readonly property '{prop}' in method '{method}'. readonly properties may only be assigned in the constructor; a later load_prop would read the assigned value instead of the one baked into the locking script"
    )
}

fn method_mut<'a>(ir: &'a mut Value, name: &str) -> &'a mut Value {
    ir["methods"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["name"] == name)
        .unwrap()
}

fn update(name: &str, prop: &str, value: &str) -> Value {
    json!({ "name": name, "value": { "kind": "update_prop", "name": prop, "value": value } })
}

/// The sweep1 hijack: P2PKH with `pubKeyHash = hash160(pubKey)` written
/// before the `hash160(pubKey) === pubKeyHash` comparison.
fn p2pkh_with_unlock_insert(at: usize, binding: Value) -> Value {
    let (mut ir, _) = golden("basic-p2pkh");
    method_mut(&mut ir, "unlock")["body"].as_array_mut().unwrap().insert(at, binding);
    ir
}

fn refused(ir: &Value) -> String {
    match compile_from_ir_str(&ir.to_string()) {
        Ok(a) => panic!("compiled a readonly-write program to {}", a.script),
        Err(e) => e,
    }
}

#[test]
fn f107_top_level_readonly_write_refused() {
    let ir = p2pkh_with_unlock_insert(2, update("t_h", "pubKeyHash", "t1"));
    assert_eq!(refused(&ir), readonly_msg("pubKeyHash", "unlock"));
}

#[test]
fn f107_readonly_write_in_if_arm_refused() {
    let ir = p2pkh_with_unlock_insert(
        2,
        json!({ "name": "t_if", "value": {
            "kind": "if", "cond": "t1",
            "then": [ { "name": "t_c", "value": { "kind": "load_param", "name": "pubKey" } } ],
            "else": [ update("t_h", "pubKeyHash", "t1") ]
        }}),
    );
    assert_eq!(refused(&ir), readonly_msg("pubKeyHash", "unlock"));
}

#[test]
fn f107_readonly_write_in_loop_body_refused() {
    let ir = p2pkh_with_unlock_insert(
        2,
        json!({ "name": "t_loop", "value": {
            "kind": "loop", "count": 1, "iterVar": "i", "start": 0, "step": 1,
            "body": [ update("t_h", "pubKeyHash", "t1") ]
        }}),
    );
    assert_eq!(refused(&ir), readonly_msg("pubKeyHash", "unlock"));
}

#[test]
fn f107_readonly_write_in_private_method_refused() {
    let (mut ir, _) = golden("basic-p2pkh");
    ir["methods"].as_array_mut().unwrap().push(json!({
        "name": "steal", "isPublic": false,
        "params": [ { "name": "h", "type": "Addr" } ],
        "body": [
            { "name": "t0", "value": { "kind": "load_param", "name": "h" } },
            update("t1", "pubKeyHash", "t0")
        ]
    }));
    assert_eq!(refused(&ir), readonly_msg("pubKeyHash", "steal"));
}

#[test]
fn f107_undeclared_property_write_refused() {
    let ir = p2pkh_with_unlock_insert(2, update("t_h", "ghost", "t1"));
    assert_eq!(
        refused(&ir),
        "IR validation: method 'unlock' assigns to undeclared property 'ghost'"
    );
}

#[test]
fn f107_goldens_with_legal_writes_still_compile() {
    // basic-p2pkh: the constructor writes the readonly pubKeyHash (legal).
    // stateful-counter: a public method writes the mutable count (legal).
    for fixture in ["basic-p2pkh", "stateful-counter"] {
        let (ir, hex) = golden(fixture);
        let a = compile_from_ir_str(&ir.to_string())
            .unwrap_or_else(|e| panic!("{fixture} must compile: {e}"));
        assert_eq!(a.script, hex, "{fixture} golden hex moved");
    }
}
