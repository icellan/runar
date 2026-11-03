//! N-030 (CL-BUG-104): the Rust math builtins (`runar::prelude`, what a
//! `.runar.rs` contract calls under `cargo test`) and the SDK ANF interpreter
//! (what derives a call's post-state) must return what the COMPILED SCRIPT
//! returns, for every vector in the shared on-chain file
//! `packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json`.
//!
//! That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
//! `packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts`
//! (accept at `expect`, reject at `expect + 1`; an `abort` row rejects both
//! `== 0` and `!= 0`). Every other tier replays the same file.
//!
//! Proves: for every `cases` row, the prelude builtin and the interpreter return
//! the on-chain value, or refuse (panic / `Err`) where the script aborts —
//! never a value — including clamp with lo > hi and log2 of n <= 0.
//! Does not prove: that the `wideCases` rows (operands beyond i64: log2
//! saturating at 64, gcd's 256-step partial remainder, sqrt's 2^495 guard) are
//! COMPUTED. Both the prelude `Int` and this interpreter's integer value are
//! i64; the prelude cannot express them at all, and the interpreter refuses
//! them (N-163, `n163_anf_interpreter_wide_cases_fail_closed`). Every
//! bigint-capable tier replays them. Nor inputs outside the file, or the
//! script itself (the oracle).

use std::collections::HashMap;
use std::panic;

use runar_lang::prelude::{
    abs, bool_cast, clamp, divmod, gcd, log2, max, min, mul_div, percent_of, pow, safediv,
    safemod, sign, sqrt, within,
};
use runar_lang::sdk::anf_interpreter::{compute_new_state, ANFProgram};
use runar_lang::sdk::SdkValue;

/// Script result: an integer (booleans as 0/1), or `None` when the script aborts.
type Want = Option<i64>;

fn load_cases() -> Vec<(String, Vec<i64>, Want)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../runar-zig/src/fixtures/f033-math-builtins-onchain.json"
    );
    let text = std::fs::read_to_string(path).expect("shared math vectors");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("vectors JSON");
    doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|c| {
            let fn_name = c["fn"].as_str().expect("fn").to_string();
            let args = c["args"]
                .as_array()
                .expect("args")
                .iter()
                .map(|a| a.as_i64().expect("`cases` args fit i64"))
                .collect();
            let want = match &c["expect"] {
                serde_json::Value::String(s) => {
                    assert_eq!(s, "abort");
                    None
                }
                serde_json::Value::Bool(b) => Some(*b as i64),
                v => Some(v.as_i64().expect("`cases` expect fits i64")),
            };
            (fn_name, args, want)
        })
        .collect()
}

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
        Some(SdkValue::Bool(b)) => Ok(*b as i64),
        other => Err(format!("unexpected result {:?}", other)),
    }
}

fn run_native(func: &str, a: &[i64]) -> i64 {
    match func {
        "percentOf" => percent_of(a[0], a[1]),
        "mulDiv" => mul_div(a[0], a[1], a[2]),
        "safediv" => safediv(a[0], a[1]),
        "safemod" => safemod(a[0], a[1]),
        "divmod" => divmod(a[0], a[1]),
        "sqrt" => sqrt(a[0]),
        "log2" => log2(a[0]),
        "pow" => pow(a[0], a[1]),
        "clamp" => clamp(a[0], a[1], a[2]),
        "within" => within(a[0], a[1], a[2]) as i64,
        "sign" => sign(a[0]),
        "gcd" => gcd(a[0], a[1]),
        "abs" => abs(a[0]),
        "min" => min(a[0], a[1]),
        "max" => max(a[0], a[1]),
        "bool" => bool_cast(a[0]) as i64,
        other => panic!("vectors name a builtin this test does not map: {}", other),
    }
}

#[test]
fn n030_anf_interpreter_math_matches_onchain_vectors() {
    let cases = load_cases();
    assert!(!cases.is_empty());
    let mut failures = Vec::new();
    for (func, args, want) in &cases {
        let got = panic::catch_unwind(|| run_anf(func, args));
        let ok = match (want, &got) {
            (None, Ok(Err(_))) => true,
            (Some(w), Ok(Ok(g))) => w == g,
            _ => false,
        };
        if !ok {
            failures.push(format!("{}{:?}: script {:?}, interpreter {:?}", func, args, want, got.map_err(|_| "panic")));
        }
    }
    assert!(failures.is_empty(), "interpreter diverges from the script:\n{}", failures.join("\n"));
}

#[test]
fn n030_prelude_math_matches_onchain_vectors() {
    let cases = load_cases();
    assert!(!cases.is_empty());
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for (func, args, want) in &cases {
        let got = panic::catch_unwind(|| run_native(func, args)).ok();
        if got != *want {
            failures.push(format!("{}{:?}: script {:?}, prelude {:?}", func, args, want, got));
        }
    }
    panic::set_hook(prev);
    assert!(failures.is_empty(), "prelude diverges from the script:\n{}", failures.join("\n"));
}

/// Run `result = func(args...)` with each operand passed as the caller would
/// pass a beyond-i64 value: `SdkValue::BigInt`.
fn run_anf_bigint(func: &str, args: &[num_bigint::BigInt]) -> Result<i64, String> {
    let anf = probe_anf(func, args.len());
    let names = ["a", "b", "c"];
    let named: HashMap<String, SdkValue> = args
        .iter()
        .enumerate()
        .map(|(i, v)| (names[i].to_string(), SdkValue::BigInt(v.clone())))
        .collect();
    let mut state = HashMap::new();
    state.insert("result".to_string(), SdkValue::Int(0));
    let out = compute_new_state(&anf, "probe", &state, &named, &[])?;
    match out.get("result") {
        Some(SdkValue::Int(v)) => Ok(*v),
        Some(SdkValue::Bool(b)) => Ok(*b as i64),
        other => Err(format!("unexpected result {:?}", other)),
    }
}

/// N-163: the `wideCases` rows (operands or results beyond i64). This
/// interpreter's integer value is i64, so it cannot compute most of them —
/// but it must fail closed: every row yields an error, or exactly the on-chain
/// value. It used to read a beyond-i64 `SdkValue::BigInt` as 0
/// (`unwrap_or(0)`) and wrap `pow(10, 32)` / `*` / `mulDiv` / `percentOf`
/// past i64, deriving a post-state the script never produces.
///
/// Proves: no `wideCases` row yields a value other than the on-chain one, and
/// a beyond-i64 operand or result is refused rather than zeroed or wrapped.
/// Does not prove: that the interpreter computes these rows (it refuses them;
/// bigint support would be a refactor), nor any input outside the file.
#[test]
fn n163_anf_interpreter_wide_cases_fail_closed() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../runar-zig/src/fixtures/f033-math-builtins-onchain.json"
    );
    let text = std::fs::read_to_string(path).expect("shared math vectors");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("vectors JSON");
    let wide = doc["wideCases"].as_array().expect("wideCases");
    assert!(!wide.is_empty());
    let mut failures = Vec::new();
    for c in wide {
        let func = c["fn"].as_str().expect("fn");
        let args: Vec<num_bigint::BigInt> = c["args"]
            .as_array()
            .expect("args")
            .iter()
            .map(|a| a.as_str().expect("wide args are decimal strings").parse().expect("decimal"))
            .collect();
        // On-chain value as a decimal string, or None where the script aborts.
        let want: Option<String> = match &c["expect"] {
            serde_json::Value::Bool(b) => Some(if *b { "1" } else { "0" }.to_string()),
            serde_json::Value::String(s) if s == "abort" => None,
            serde_json::Value::String(s) => Some(s.clone()),
            v => panic!("unexpected expect {:?}", v),
        };
        let got = panic::catch_unwind(|| run_anf_bigint(func, &args));
        let ok = match (&want, &got) {
            (_, Ok(Err(_))) => true,
            (Some(w), Ok(Ok(g))) => *w == g.to_string(),
            _ => false,
        };
        if !ok {
            failures.push(format!("{}{:?}: script {:?}, interpreter {:?}", func, args, want, got.map_err(|_| "panic")));
        }
    }
    assert!(failures.is_empty(), "interpreter returned a value the script does not:\n{}", failures.join("\n"));
}

/// N-163: `a * b` past i64 must be refused, not wrapped (`wrapping_mul`).
/// Proves: the binop `*` fails closed on i64 overflow and still multiplies
/// in range. Does not prove: `+` / `-` overflow (not covered by this item).
#[test]
fn n163_anf_interpreter_mul_overflow_fails_closed() {
    let run = |a: i64, b: i64| -> Result<HashMap<String, SdkValue>, String> {
        let anf: ANFProgram = serde_json::from_value(serde_json::json!({
            "contractName": "MulProbe",
            "properties": [{"name": "result", "type": "bigint", "readonly": false}],
            "methods": [{"name": "probe", "params": [
                {"name": "a", "type": "bigint"}, {"name": "b", "type": "bigint"}
            ], "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "b"}},
                {"name": "r", "value": {"kind": "bin_op", "op": "*", "left": "t0", "right": "t1"}},
                {"name": "u", "value": {"kind": "update_prop", "name": "result", "value": "r"}}
            ], "isPublic": true}],
        }))
        .expect("mul ANF");
        let mut named = HashMap::new();
        named.insert("a".to_string(), SdkValue::Int(a));
        named.insert("b".to_string(), SdkValue::Int(b));
        let mut state = HashMap::new();
        state.insert("result".to_string(), SdkValue::Int(0));
        compute_new_state(&anf, "probe", &state, &named, &[])
    };
    assert!(matches!(run(6, -7).unwrap().get("result"), Some(SdkValue::Int(-42))));
    let got = run(i64::MAX, 2);
    assert!(got.is_err(), "i64::MAX * 2 must be refused, got {:?}", got);
}
