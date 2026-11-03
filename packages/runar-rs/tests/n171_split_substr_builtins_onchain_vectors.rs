//! N-171 (sibling of F-274): the Rust `split`/`substr` prelude builtins
//! (`runar_lang::prelude`, what a `.runar.rs` contract calls under `cargo
//! test`) AND the SDK ANF interpreter (what derives a call's post-state)
//! must return what the COMPILED SCRIPT returns, for every vector in the
//! shared on-chain file
//! `packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json`.
//! The interpreter's `split` arm was newly modelled (the same bug shape
//! F-274 fixed for `left`/`right`: it fell through to `Val::Undefined`
//! before this); its `substr` arm used to clamp instead of aborting.
//!
//! R67: the interpreter's `substr` is now fully abort-faithful. Its one
//! caller via `extractScriptCode` (`FungibleToken::merge`) used to get an
//! empty dummy scriptCode, turning a realistic `substr(sc, ...)` call into
//! a POSITIVE overflow the old clamp had to swallow to avoid breaking
//! `compute_new_state`. `extractScriptCode` now returns the contract's own
//! REAL codePart (`contract.rs`'s `prepare_call`, via
//! `compute_new_state_and_data_outputs_with_script_code`), so `substr` can
//! be fully abort-faithful without starving `merge` of a realistic
//! scriptCode.
//!
//! That file is the oracle: every row is executed on @bsv/sdk Spend.validate
//! by `packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts`.
//!
//! Proves: the prelude builtins AND the SDK ANF interpreter return the
//! on-chain value, or panic where the script aborts (never a value), for
//! BOTH `split` and `substr` -- covering n=0, interior, n=len(data),
//! n>len(data), n<0, and an empty `data` input.
//! Does not prove: inputs outside the file, or the script itself (the
//! oracle).

use std::collections::HashMap;
use std::panic;

use runar_lang::prelude::{split, substr};
use runar_lang::sdk::anf_interpreter::{compute_new_state, ANFProgram};
use runar_lang::sdk::SdkValue;

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex digit"))
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for byte in b {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Script result: the hex string, or `None` when the script aborts.
type Want = Option<String>;

fn load_cases() -> Vec<(String, String, i64, i64, Want)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json"
    );
    let text = std::fs::read_to_string(path).expect("shared split/substr vectors");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("vectors JSON");
    doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|c| {
            let fn_name = c["fn"].as_str().expect("fn").to_string();
            let data = c["data"].as_str().expect("data").to_string();
            let a = c["a"].as_i64().expect("a");
            let b = c["b"].as_i64().expect("b");
            let want = match &c["expect"] {
                serde_json::Value::String(s) if s == "abort" => None,
                serde_json::Value::String(s) => Some(s.clone()),
                v => panic!("unexpected expect {:?}", v),
            };
            (fn_name, data, a, b, want)
        })
        .collect()
}

fn probe_anf(func: &str) -> ANFProgram {
    let (params, call_args, extra_binding): (serde_json::Value, serde_json::Value, Option<serde_json::Value>) = if func == "substr" {
        (
            serde_json::json!([
                {"name": "data", "type": "ByteString"},
                {"name": "a", "type": "bigint"},
                {"name": "b", "type": "bigint"},
            ]),
            serde_json::json!(["t0", "t1", "t2"]),
            Some(serde_json::json!({"name": "t2", "value": {"kind": "load_param", "name": "b"}})),
        )
    } else {
        (
            serde_json::json!([
                {"name": "data", "type": "ByteString"},
                {"name": "a", "type": "bigint"},
            ]),
            serde_json::json!(["t0", "t1"]),
            None,
        )
    };
    let mut body = vec![
        serde_json::json!({"name": "t0", "value": {"kind": "load_param", "name": "data"}}),
        serde_json::json!({"name": "t1", "value": {"kind": "load_param", "name": "a"}}),
    ];
    if let Some(b) = extra_binding {
        body.push(b);
    }
    body.push(serde_json::json!({"name": "r", "value": {"kind": "call", "func": func, "args": call_args}}));
    body.push(serde_json::json!({"name": "u", "value": {"kind": "update_prop", "name": "result", "value": "r"}}));
    serde_json::from_value(serde_json::json!({
        "contractName": "SplitSubstrProbe",
        "properties": [{"name": "result", "type": "ByteString", "readonly": false}],
        "methods": [{
            "name": "probe",
            "params": params,
            "body": body,
            "isPublic": true,
        }],
    }))
    .expect("probe ANF")
}

fn run_anf(func: &str, data: &str, a: i64, b: i64) -> Result<String, String> {
    let anf = probe_anf(func);
    let mut named: HashMap<String, SdkValue> = HashMap::new();
    named.insert("data".to_string(), SdkValue::Bytes(data.to_string()));
    named.insert("a".to_string(), SdkValue::Int(a));
    named.insert("b".to_string(), SdkValue::Int(b));
    let mut state = HashMap::new();
    state.insert("result".to_string(), SdkValue::Bytes(String::new()));
    let out = compute_new_state(&anf, "probe", &state, &named, &[])?;
    match out.get("result") {
        Some(SdkValue::Bytes(s)) => Ok(s.clone()),
        other => Err(format!("unexpected result {:?}", other)),
    }
}

#[test]
fn n171_anf_interpreter_split_substr_matches_onchain_vectors() {
    let cases = load_cases();
    assert!(!cases.is_empty());
    let mut failures = Vec::new();
    for (func, data, a, b, want) in &cases {
        let got = panic::catch_unwind(|| run_anf(func, data, *a, *b));
        let ok = match (want, &got) {
            (None, Ok(Err(_))) => true,
            (None, Err(_)) => true,
            (Some(w), Ok(Ok(g))) => w == g,
            _ => false,
        };
        if !ok {
            failures.push(format!(
                "{}({}, {}, {}): script {:?}, interpreter {:?}",
                func, data, a, b, want, got.map_err(|_| "panic")
            ));
        }
    }
    assert!(failures.is_empty(), "interpreter diverges from the script:\n{}", failures.join("\n"));
}

#[test]
fn n171_prelude_split_substr_matches_onchain_vectors() {
    let cases = load_cases();
    assert!(!cases.is_empty());
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for (func, data_hex, a, b, want) in &cases {
        let data = from_hex(data_hex);
        let got = panic::catch_unwind(|| {
            if func == "split" {
                split(&data, *a)
            } else {
                substr(&data, *a, *b)
            }
        })
        .ok()
        .map(|v| to_hex(&v));
        if got != *want {
            failures.push(format!(
                "{}({}, {}, {}): script {:?}, prelude {:?}",
                func, data_hex, a, b, want, got
            ));
        }
    }
    panic::set_hook(prev);
    assert!(failures.is_empty(), "prelude diverges from the script:\n{}", failures.join("\n"));
}
