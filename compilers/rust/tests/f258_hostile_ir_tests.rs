//! F-258 / CL-BUG-151 — two of codegen's silent-OP_0 fallbacks are reachable
//! via a hand-written `--ir` file (the frontend, which enforces that
//! property initializers and `load_const` values are literals, is skipped
//! entirely on this path):
//!
//!  1. `push_json_value`'s default arm, for a property `initialValue` that
//!     is not a bool/number/string (e.g. an array).
//!  2. `lower_load_const`'s `None` arm, for a `load_const.value` that does
//!     not decode to a bool/number/string. Unlike the Go/Python/Ruby
//!     tiers, this tier's IR loader does not eagerly validate `load_const`
//!     values at load time, so this one is a LIVE bug here (the equivalent
//!     site in Go/Python/Ruby is already dead code, guarded upstream).
//!
//! Both used to compile cleanly to a 1-byte `OP_0` script instead of being
//! refused.

use runar_compiler_rust::compile_from_ir_str;

#[test]
fn a_non_literal_property_initializer_is_a_loud_error_not_op0() {
    let ir_json = r#"{
        "contractName": "HostilePropInit",
        "properties": [
            {"name": "secret", "type": "bigint", "readonly": true, "initialValue": [1, 2, 3]}
        ],
        "methods": [{
            "name": "reveal",
            "params": [],
            "body": [
                {"name": "t0", "value": {"kind": "load_prop", "name": "secret"}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;

    let err = compile_from_ir_str(ir_json)
        .expect_err("a non-literal (array) property initializer must be rejected");
    assert!(
        err.contains("secret"),
        "error should name the property, got: {}",
        err
    );
    assert!(
        err.contains("Refusing to emit a silent OP_0"),
        "error should be the loud stack-lowering diagnostic, got: {}",
        err
    );
}

#[test]
fn an_undecodable_load_const_value_is_a_loud_error_not_op0() {
    let ir_json = r#"{
        "contractName": "HostileLoadConst",
        "properties": [],
        "methods": [{
            "name": "go",
            "params": [],
            "body": [
                {"name": "t1", "value": {"kind": "load_const", "value": [1, 2, 3]}},
                {"name": "t2", "value": {"kind": "assert", "value": "t1"}}
            ],
            "isPublic": true
        }]
    }"#;

    let err = compile_from_ir_str(ir_json)
        .expect_err("a load_const value that decodes to neither bool/number/string must be rejected");
    assert!(
        err.contains("Refusing to emit a silent OP_0"),
        "error should be the loud stack-lowering diagnostic, got: {}",
        err
    );
}

#[test]
fn a_literal_property_initializer_still_compiles() {
    // Control: an ordinary literal initializer must still compile through
    // push_json_value's non-default arms.
    let ir_json = r#"{
        "contractName": "LiteralPropInit",
        "properties": [
            {"name": "threshold", "type": "bigint", "readonly": true, "initialValue": 42}
        ],
        "methods": [{
            "name": "check",
            "params": [],
            "body": [
                {"name": "t0", "value": {"kind": "load_prop", "name": "threshold"}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact = compile_from_ir_str(ir_json).expect("a literal property initializer must compile");
    assert!(!artifact.script.is_empty());
}
