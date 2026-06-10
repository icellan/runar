//! BUG-008 follow-up: IR-loader size-guard regression tests for the
//! Rust tier. Mirrors `compilers/go/ir/loader_size_guard_test.go`.

use runar_compiler_rust::ir::input_limits::{
    IRNestingExceededError, IRSizeExceededError, MAX_IR_BYTES, MAX_IR_NESTING,
};
use runar_compiler_rust::ir::loader::{load_ir_from_str, load_ir_from_str_typed, IRLoaderError};

#[test]
fn load_ir_rejects_oversized_input() {
    let oversized: String = " ".repeat(MAX_IR_BYTES + 1);
    match load_ir_from_str_typed(&oversized) {
        Err(IRLoaderError::Size(IRSizeExceededError { limit, actual })) => {
            assert_eq!(limit, MAX_IR_BYTES);
            assert_eq!(actual, MAX_IR_BYTES + 1);
        }
        other => panic!("expected IRLoaderError::Size, got {:?}", other),
    }
    let plain = load_ir_from_str(&oversized);
    assert!(
        plain.as_ref().unwrap_err().contains("MAX_IR_BYTES"),
        "expected message to mention MAX_IR_BYTES, got: {:?}",
        plain
    );
}

#[test]
fn load_ir_rejects_deeply_nested_input() {
    // Build a JSON payload nested MAX_IR_NESTING+50 levels deep.
    let depth = MAX_IR_NESTING + 50;
    let mut body = String::from("1");
    for _ in 0..depth {
        body = format!("{{\"n\":{}}}", body);
    }
    match load_ir_from_str_typed(&body) {
        Err(IRLoaderError::Nesting(IRNestingExceededError { limit })) => {
            assert_eq!(limit, MAX_IR_NESTING);
        }
        other => panic!("expected IRLoaderError::Nesting, got {:?}", other),
    }
}

#[test]
fn load_ir_depth_walk_ignores_braces_inside_strings() {
    // 1000 `{` inside a JSON string MUST NOT count toward depth.
    let open_braces: String = "{".repeat(1000);
    let bad = format!(
        "{{\"contractName\":\"X\",\"properties\":[],\"methods\":[],\"_note\":\"{}\"}}",
        open_braces
    );
    let res = load_ir_from_str_typed(&bad);
    // The depth/size caps must NOT trip. Downstream parsing succeeds or
    // fails based on schema validation; we only care that neither typed
    // DoS-bound error fires.
    match res {
        Err(IRLoaderError::Size(_)) => panic!("size cap incorrectly tripped"),
        Err(IRLoaderError::Nesting(_)) => panic!("nesting cap incorrectly tripped"),
        _ => {}
    }
}

#[test]
fn load_ir_accepts_minimal_program() {
    let minimal =
        r#"{"contractName":"X","properties":[],"methods":[]}"#;
    let res = load_ir_from_str_typed(minimal);
    assert!(res.is_ok(), "expected ok, got {:?}", res);
}
