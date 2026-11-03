//! N-102: the binary `/` and `%` operators lower to OP_DIV / OP_MOD, which
//! truncate toward zero and ABORT the script on a zero divisor. The SDK ANF
//! interpreter returned 0 for a zero divisor, deriving a post-state the
//! deployed script can never produce (and `i64::MIN / -1` panicked the host).
//!
//! Proves: `compute_new_state` refuses a zero divisor (and the i64 overflow
//! case) and truncates toward zero (-7/2 = -3, -7%2 = -1). Does not prove:
//! agreement with an executed script (the expected values are the
//! OP_DIV/OP_MOD semantics, not an execution), nor anything about Rust's
//! native `/` on contract fields.

use std::collections::HashMap;

use runar_lang::sdk::anf_interpreter::{compute_new_state, ANFProgram};
use runar_lang::sdk::SdkValue;

fn probe_anf(op: &str) -> ANFProgram {
    serde_json::from_value(serde_json::json!({
        "contractName": "DivProbe",
        "properties": [{"name": "result", "type": "bigint", "readonly": false}],
        "methods": [{
            "name": "probe",
            "params": [{"name": "a", "type": "bigint"}, {"name": "b", "type": "bigint"}],
            "isPublic": true,
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "b"}},
                {"name": "r", "value": {"kind": "bin_op", "op": op, "left": "t0", "right": "t1"}},
                {"name": "u", "value": {"kind": "update_prop", "name": "result", "value": "r"}},
            ],
        }],
    }))
    .expect("probe ANF")
}

fn run(op: &str, a: i64, b: i64) -> Result<i64, String> {
    let named: HashMap<String, SdkValue> = [("a", a), ("b", b)]
        .iter()
        .map(|(n, v)| (n.to_string(), SdkValue::Int(*v)))
        .collect();
    let mut state = HashMap::new();
    state.insert("result".to_string(), SdkValue::Int(0));
    let out = compute_new_state(&probe_anf(op), "probe", &state, &named, &[])?;
    match out.get("result") {
        Some(SdkValue::Int(v)) => Ok(*v),
        other => Err(format!("unexpected result {:?}", other)),
    }
}

#[test]
fn zero_divisor_is_refused() {
    for op in ["/", "%"] {
        assert!(run(op, 7, 0).is_err(), "{op} by zero must be refused, script aborts");
    }
}

#[test]
fn i64_min_over_minus_one_is_refused_not_a_panic() {
    for op in ["/", "%"] {
        // `/`: 2^63 is outside i64 (refuse). `%`: the script yields 0, and so must we.
        let r = run(op, i64::MIN, -1);
        if op == "/" {
            assert!(r.is_err(), "i64::MIN / -1 does not fit i64");
        } else {
            assert_eq!(r, Ok(0));
        }
    }
}

#[test]
fn truncates_toward_zero() {
    assert_eq!(run("/", -7, 2), Ok(-3));
    assert_eq!(run("%", -7, 2), Ok(-1));
    assert_eq!(run("/", 7, -2), Ok(-3));
    assert_eq!(run("%", 7, -2), Ok(1));
}
