//! D12 bytes/math findings against the Rust SDK ANF interpreter
//! (`compute_new_state`, the path `prepare_call` derives the continuation
//! state from). Each expectation is what the compiled script computes or that
//! it aborts (D12 bytes-math report, executed on @bsv/sdk Spend):
//! - BM-F2: bin2num of more than 8 bytes is exact or refused, never wrapped.
//! - BM-F4: ByteString `& | ^` follow OP_AND/OP_OR/OP_XOR (length mismatch
//!   aborts); int2str is OP_NUM2BIN. Neither invents "" / Undefined.
//! - BM-F5: num2bin / int2str with a negative or too-narrow width abort.
//! - BM-F7: gcd(i64::MIN, x) neither panics nor returns a negative value.
//! - reverseBytes of more than 520 bytes is refused (the script reverses only
//!   the first 520).
//! - SECP-F1: native ec_mod_reduce = ((v tmod m) + m) tmod m.

use std::collections::HashMap;

use runar_lang::ec::ec_mod_reduce;
use runar_lang::sdk::anf_interpreter::{compute_new_state, ANFProgram};
use runar_lang::sdk::SdkValue;

/// `this.r = <value>` where `<value>` reads params `a` and `b`.
fn run(r_type: &str, value: serde_json::Value, a: SdkValue, b: SdkValue) -> Result<SdkValue, String> {
    let anf: ANFProgram = serde_json::from_value(serde_json::json!({
        "contractName": "D12Probe",
        "properties": [{"name": "r", "type": r_type, "readonly": false}],
        "methods": [{"name": "m", "isPublic": true,
            "params": [{"name": "a", "type": "ByteString"}, {"name": "b", "type": "ByteString"}],
            "body": [
                {"name": "a0", "value": {"kind": "load_param", "name": "a"}},
                {"name": "b0", "value": {"kind": "load_param", "name": "b"}},
                {"name": "v", "value": value},
                {"name": "u", "value": {"kind": "update_prop", "name": "r", "value": "v"}}
            ]}]
    }))
    .expect("probe ANF");
    let mut state = HashMap::new();
    state.insert("r".to_string(), if r_type == "bigint" { SdkValue::Int(0) } else { SdkValue::Bytes(String::new()) });
    let mut args = HashMap::new();
    args.insert("a".to_string(), a);
    args.insert("b".to_string(), b);
    compute_new_state(&anf, "m", &state, &args, &[]).map(|s| s.get("r").cloned().expect("r"))
}


fn call1(func: &str) -> serde_json::Value {
    serde_json::json!({"kind": "call", "func": func, "args": ["a0"]})
}

fn bytes(h: &str) -> SdkValue {
    SdkValue::Bytes(h.to_string())
}

#[test]
fn d12_bm_f2_bin2num_over_8_bytes_exact_or_refused() {
    // Fits i64 although 9 bytes long (non-minimal padding): exact.
    assert_eq!(run("bigint", call1("bin2num"), bytes("010000000000000000"), bytes("")), Ok(SdkValue::Int(1)));
    assert_eq!(run("bigint", call1("bin2num"), bytes("ff00"), bytes("")), Ok(SdkValue::Int(255)));
    // 2^63, 10-byte and 32-byte values: outside i64 -> refused, never wrapped.
    for h in ["000000000000008000", "0102030405060708090a", &"ff".repeat(32)] {
        let r = run("bigint", call1("bin2num"), bytes(h), bytes(""));
        assert!(r.is_err(), "bin2num({}) must be refused, got {:?}", h, r);
    }
}

#[test]
fn d12_bm_f4_bytes_bitwise_matches_script() {
    for (op, want) in [("&", "0f00"), ("|", "ffff"), ("^", "f0ff")] {
        let v = serde_json::json!({"kind": "bin_op", "op": op, "left": "a0", "right": "b0", "result_type": "bytes"});
        assert_eq!(run("ByteString", v, bytes("ff0f"), bytes("0ff0")), Ok(bytes(want)), "ff0f {} 0ff0", op);
    }
    let v = serde_json::json!({"kind": "bin_op", "op": "&", "left": "a0", "right": "b0", "result_type": "bytes"});
    assert!(run("ByteString", v, bytes("ff"), bytes("0f0f")).is_err(), "OP_AND length mismatch aborts");
}

fn num_call(func: &str, v: i64, w: i64) -> Result<SdkValue, String> {
    let anf_val = serde_json::json!({"kind": "call", "func": func, "args": ["x", "w"]});
    let anf: ANFProgram = serde_json::from_value(serde_json::json!({
        "contractName": "D12Num",
        "properties": [{"name": "r", "type": "ByteString", "readonly": false}],
        "methods": [{"name": "m", "isPublic": true,
            "params": [{"name": "a", "type": "bigint"}, {"name": "b", "type": "bigint"}],
            "body": [
                {"name": "x", "value": {"kind": "load_param", "name": "a"}},
                {"name": "w", "value": {"kind": "load_param", "name": "b"}},
                {"name": "v", "value": anf_val},
                {"name": "u", "value": {"kind": "update_prop", "name": "r", "value": "v"}}
            ]}]
    }))
    .unwrap();
    let mut state = HashMap::new();
    state.insert("r".to_string(), SdkValue::Bytes(String::new()));
    let mut args = HashMap::new();
    args.insert("a".to_string(), SdkValue::Int(v));
    args.insert("b".to_string(), SdkValue::Int(w));
    compute_new_state(&anf, "m", &state, &args, &[]).map(|s| s.get("r").cloned().unwrap())
}

#[test]
fn d12_bm_f4_int2str_is_num2bin() {
    assert_eq!(num_call("int2str", 5, 2), Ok(bytes("0500")));
}

#[test]
fn d12_bm_f5_num2bin_narrow_width_refused() {
    for f in ["num2bin", "int2str"] {
        for (v, w) in [(40000, 2), (128, 1), (1, 0), (5, -1), (-1, 0)] {
            let r = num_call(f, v, w);
            assert!(r.is_err(), "{}({}, {}) must be refused, got {:?}", f, v, w, r);
        }
        assert_eq!(num_call(f, 0, 0), Ok(bytes("")));
        assert_eq!(num_call(f, 255, 2), Ok(bytes("ff00")));
    }
}

fn gcd(a: i64, b: i64) -> Result<SdkValue, String> {
    let anf: ANFProgram = serde_json::from_value(serde_json::json!({
        "contractName": "D12Gcd",
        "properties": [{"name": "r", "type": "bigint", "readonly": false}],
        "methods": [{"name": "m", "isPublic": true,
            "params": [{"name": "a", "type": "bigint"}, {"name": "b", "type": "bigint"}],
            "body": [
                {"name": "x", "value": {"kind": "load_param", "name": "a"}},
                {"name": "y", "value": {"kind": "load_param", "name": "b"}},
                {"name": "v", "value": {"kind": "call", "func": "gcd", "args": ["x", "y"]}},
                {"name": "u", "value": {"kind": "update_prop", "name": "r", "value": "v"}}
            ]}]
    }))
    .unwrap();
    let mut state = HashMap::new();
    state.insert("r".to_string(), SdkValue::Int(0));
    let mut args = HashMap::new();
    args.insert("a".to_string(), SdkValue::Int(a));
    args.insert("b".to_string(), SdkValue::Int(b));
    compute_new_state(&anf, "m", &state, &args, &[]).map(|s| s.get("r").cloned().unwrap())
}

#[test]
fn d12_bm_f7_gcd_i64_min() {
    assert_eq!(gcd(i64::MIN, 6), Ok(SdkValue::Int(2)));
    assert_eq!(gcd(6, i64::MIN), Ok(SdkValue::Int(2)));
    // 2^63 is outside i64: refused, not returned as i64::MIN.
    assert!(gcd(i64::MIN, 0).is_err());
    assert!(gcd(i64::MIN, i64::MIN).is_err());
}

#[test]
fn d12_reverse_bytes_over_520_refused() {
    let ok = run("ByteString", call1("reverseBytes"), bytes(&format!("{}cd", "ab".repeat(519))), bytes(""));
    assert_eq!(ok, Ok(bytes(&format!("cd{}", "ab".repeat(519)))));
    let r = run("ByteString", call1("reverseBytes"), bytes(&"ab".repeat(521)), bytes(""));
    assert!(r.is_err(), "reverseBytes(521 B) must be refused, got {:?}", r.map(|_| ()));
}

#[test]
fn d12_secp_f1_ec_mod_reduce_matches_script() {
    for (v, m, want) in [(7, -3, -2), (-7, -3, -1), (-5, 3, 1), (17, 5, 2), (-3, 5, 2), (i64::MIN, -1, 0),
        (i64::MAX - 1, i64::MAX, i64::MAX - 1)] {
        assert_eq!(ec_mod_reduce(v, m), want, "ec_mod_reduce({}, {})", v, m);
    }
    assert!(std::panic::catch_unwind(|| ec_mod_reduce(5, 0)).is_err(), "m == 0 aborts like OP_MOD");
}

