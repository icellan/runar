//! F-134: the Rust mocks of the math builtins (`runar::prelude`, what a
//! `.runar.rs` contract calls under `cargo test`) and the SDK ANF interpreter
//! (what derives a call's post-state) must compute what the compiled script
//! computes.
//!
//! The expected column was established by EXECUTING the TS compiler's script
//! for each builtin in @bsv/sdk's Spend (fold ON and OFF, identical): OP_DIV /
//! OP_MOD truncate toward zero; a zero divisor aborts; `pow` aborts outside
//! `0 <= exp <= 32` (OP_WITHIN guard); `sqrt` aborts on `n < 0`. `None` means
//! the script fails, so the runtime must refuse (panic / `Err`) rather than
//! return a number. (`sqrt`'s `n >= 2^495` guard is unreachable from i64.)
//!
//! Proves: for each listed input the prelude mock and the interpreter return
//! the script's value or refuse where the script aborts. Does not prove:
//! agreement outside the table, or anything about the script itself (it is the
//! oracle here, not the subject).

use std::collections::HashMap;
use std::panic;

use runar_lang::prelude::{divmod, mul_div, percent_of, pow, safediv, safemod, sqrt};
use runar_lang::sdk::anf_interpreter::{compute_new_state, ANFProgram};
use runar_lang::sdk::SdkValue;

const VECTORS: &[(&str, &[i64], Option<i64>)] = &[
    ("divmod", &[-7, 2], Some(-3)),
    ("divmod", &[7, -2], Some(-3)),
    ("divmod", &[1, 0], None),
    ("mulDiv", &[-7, 1, 2], Some(-3)),
    ("mulDiv", &[1, 1, 0], None),
    ("percentOf", &[-1, 5000], Some(0)),
    ("percentOf", &[-15000, 1], Some(-1)),
    ("pow", &[2, -1], None),
    ("pow", &[2, 0], Some(1)),
    ("pow", &[-2, 3], Some(-8)),
    ("pow", &[2, 32], Some(4294967296)),
    ("pow", &[2, 33], None),
    ("pow", &[1, 40], None),
    ("sqrt", &[-1], None),
    ("sqrt", &[0], Some(0)),
    ("sqrt", &[8], Some(2)),
    ("safediv", &[-7, 2], Some(-3)),
    ("safediv", &[1, 0], None),
    ("safemod", &[-7, 2], Some(-1)),
    ("safemod", &[7, -2], Some(1)),
    ("safemod", &[1, 0], None),
];

fn probe_anf(func: &str, nargs: usize) -> ANFProgram {
    let names = ["a", "b", "c"];
    let mut body: Vec<serde_json::Value> = (0..nargs)
        .map(|i| serde_json::json!({"name": format!("t{}", i), "value": {"kind": "load_param", "name": names[i]}}))
        .collect();
    let refs: Vec<String> = (0..nargs).map(|i| format!("t{}", i)).collect();
    body.push(serde_json::json!({"name": "r", "value": {"kind": "call", "func": func, "args": refs}}));
    body.push(serde_json::json!({"name": "u", "value": {"kind": "update_prop", "name": "result", "value": "r"}}));
    let params: Vec<serde_json::Value> = names[..nargs]
        .iter()
        .map(|n| serde_json::json!({"name": n, "type": "bigint"}))
        .collect();
    serde_json::from_value(serde_json::json!({
        "contractName": "MathProbe",
        "properties": [{"name": "result", "type": "bigint", "readonly": false}],
        "methods": [{"name": "probe", "params": params, "body": body, "isPublic": true}],
    }))
    .expect("probe ANF")
}

fn run_anf(func: &str, args: &[i64]) -> Result<i64, String> {
    let anf = probe_anf(func, args.len());
    let names = ["a", "b", "c"];
    let named: HashMap<String, SdkValue> = args
        .iter()
        .enumerate()
        .map(|(i, v)| (names[i].to_string(), SdkValue::Int(*v)))
        .collect();
    let mut state = HashMap::new();
    state.insert("result".to_string(), SdkValue::Int(0));
    let out = compute_new_state(&anf, "probe", &state, &named, &[])?;
    match out.get("result") {
        Some(SdkValue::Int(v)) => Ok(*v),
        other => Err(format!("unexpected result {:?}", other)),
    }
}

fn run_native(func: &str, a: &[i64]) -> i64 {
    match func {
        "divmod" => divmod(a[0], a[1]),
        "mulDiv" => mul_div(a[0], a[1], a[2]),
        "percentOf" => percent_of(a[0], a[1]),
        "pow" => pow(a[0], a[1]),
        "sqrt" => sqrt(a[0]),
        "safediv" => safediv(a[0], a[1]),
        "safemod" => safemod(a[0], a[1]),
        _ => unreachable!(),
    }
}

#[test]
fn f134_anf_interpreter_math_matches_script() {
    let mut failures = Vec::new();
    for (func, args, want) in VECTORS {
        let got = run_anf(func, args);
        let ok = match (want, &got) {
            (None, Err(_)) => true,
            (Some(w), Ok(g)) => w == g,
            _ => false,
        };
        if !ok {
            failures.push(format!("{}{:?}: script {:?}, interpreter {:?}", func, args, want, got));
        }
    }
    assert!(failures.is_empty(), "interpreter diverges from the script:\n{}", failures.join("\n"));
}

#[test]
fn f134_prelude_mock_math_matches_script() {
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for (func, args, want) in VECTORS {
        let got = panic::catch_unwind(|| run_native(func, args)).ok();
        if got != *want {
            failures.push(format!("{}{:?}: script {:?}, mock {:?}", func, args, want, got));
        }
    }
    panic::set_hook(prev);
    assert!(failures.is_empty(), "prelude mock diverges from the script:\n{}", failures.join("\n"));
}
