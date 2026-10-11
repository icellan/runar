//! F-274 (CL-BUG-163): the Rust `left`/`right` prelude builtins (`runar::prelude`,
//! what a `.runar.rs` contract calls under `cargo test`) and the SDK ANF
//! interpreter (what derives a call's post-state) must return what the
//! COMPILED SCRIPT returns, for every vector in the shared on-chain file
//! `packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json`.
//!
//! That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
//! `packages/runar-testing/src/__tests__/f274-split-builtins-onchain.test.ts`.
//!
//! Proves: both the prelude builtin and the interpreter return the on-chain
//! value, or refuse (panic / `Err`) where the script aborts — never a value —
//! covering n=0, n=len(data), n>len(data), n<0, and an empty `data` input.
//! Does not prove: inputs outside the file, or the script itself (the oracle).

use std::collections::HashMap;
use std::panic;

use runar_lang::prelude::{left, right};
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

fn load_cases() -> Vec<(String, String, i64, Want)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../runar-zig/src/fixtures/f274-split-builtins-onchain.json"
    );
    let text = std::fs::read_to_string(path).expect("shared split vectors");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("vectors JSON");
    doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|c| {
            let fn_name = c["fn"].as_str().expect("fn").to_string();
            let data = c["data"].as_str().expect("data").to_string();
            let n = c["n"].as_i64().expect("n");
            let want = match &c["expect"] {
                serde_json::Value::String(s) if s == "abort" => None,
                serde_json::Value::String(s) => Some(s.clone()),
                v => panic!("unexpected expect {:?}", v),
            };
            (fn_name, data, n, want)
        })
        .collect()
}

fn probe_anf(func: &str) -> ANFProgram {
    serde_json::from_value(serde_json::json!({
        "contractName": "SplitProbe",
        "properties": [{"name": "result", "type": "ByteString", "readonly": false}],
        "methods": [{
            "name": "probe",
            "params": [{"name": "data", "type": "ByteString"}, {"name": "n", "type": "bigint"}],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "data"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "n"}},
                {"name": "r", "value": {"kind": "call", "func": func, "args": ["t0", "t1"]}},
                {"name": "u", "value": {"kind": "update_prop", "name": "result", "value": "r"}},
            ],
            "isPublic": true,
        }],
    }))
    .expect("probe ANF")
}

fn run_anf(func: &str, data: &str, n: i64) -> Result<String, String> {
    let anf = probe_anf(func);
    let mut named: HashMap<String, SdkValue> = HashMap::new();
    named.insert("data".to_string(), SdkValue::Bytes(data.to_string()));
    named.insert("n".to_string(), SdkValue::Int(n));
    let mut state = HashMap::new();
    state.insert("result".to_string(), SdkValue::Bytes(String::new()));
    let out = compute_new_state(&anf, "probe", &state, &named, &[])?;
    match out.get("result") {
        Some(SdkValue::Bytes(s)) => Ok(s.clone()),
        other => Err(format!("unexpected result {:?}", other)),
    }
}

fn run_native(func: &str, data: &[u8], n: i64) -> Vec<u8> {
    match func {
        "left" => left(data, n),
        "right" => right(data, n),
        other => panic!("vectors name a builtin this test does not map: {}", other),
    }
}

#[test]
fn f274_anf_interpreter_split_matches_onchain_vectors() {
    let cases = load_cases();
    assert!(!cases.is_empty());
    let mut failures = Vec::new();
    for (func, data, n, want) in &cases {
        let got = panic::catch_unwind(|| run_anf(func, data, *n));
        let ok = match (want, &got) {
            (None, Ok(Err(_))) => true,
            (None, Err(_)) => true,
            (Some(w), Ok(Ok(g))) => w == g,
            _ => false,
        };
        if !ok {
            failures.push(format!(
                "{}({}, {}): script {:?}, interpreter {:?}",
                func, data, n, want, got.map_err(|_| "panic")
            ));
        }
    }
    assert!(failures.is_empty(), "interpreter diverges from the script:\n{}", failures.join("\n"));
}

#[test]
fn f274_prelude_split_matches_onchain_vectors() {
    let cases = load_cases();
    assert!(!cases.is_empty());
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for (func, data_hex, n, want) in &cases {
        let data = from_hex(data_hex);
        let got = panic::catch_unwind(|| run_native(func, &data, *n))
            .ok()
            .map(|v| to_hex(&v));
        if got != *want {
            failures.push(format!("{}({}, {}): script {:?}, prelude {:?}", func, data_hex, n, want, got));
        }
    }
    panic::set_hook(prev);
    assert!(failures.is_empty(), "prelude diverges from the script:\n{}", failures.join("\n"));
}
