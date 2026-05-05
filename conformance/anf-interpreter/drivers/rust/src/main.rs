//! ANF interpreter parity driver (Rust SDK).
//!
//! Implements the protocol described in `../PROTOCOL.md`:
//!   - reads a single JSON input file (path passed positionally)
//!   - decodes `"Xn"` bigint strings recursively
//!   - loads the ANF JSON from `anfPath` (or, as a convenience for the
//!     existing `inputs/*.json` fixtures, from `<repo>/conformance/tests/<case>/expected-ir.json`)
//!   - calls `compute_new_state_and_data_outputs(...)` (lenient),
//!     `execute_strict(...)` (strict), or `execute_on_chain_authoritative(...)`
//!     (on-chain) according to the `--mode=...` flag
//!   - prints `{ state, dataOutputs, rawOutputs }` JSON to stdout, with
//!     bigints re-encoded as `"Xn"` strings
//!
//! Invocation:
//!
//!     runar-anf-driver-rust <input.json>                  # lenient (default)
//!     runar-anf-driver-rust --mode=strict <input.json>    # strict
//!     runar-anf-driver-rust --mode=on-chain <input.json>  # real-crypto
//!
//! Strict and on-chain modes emit
//! `{error: "AssertionFailureError", methodName, bindingName}` on the first
//! falsy `assert(...)` predicate (including the implicit one wrapping a
//! failed crypto verification in on-chain mode); otherwise the same
//! `{state, dataOutputs, rawOutputs}` envelope as lenient. Order of args is
//! irrelevant (the input file may appear in any position).

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Map, Value};

use runar_lang::sdk::anf_interpreter::{
    compute_new_state_and_data_outputs, execute_on_chain_authoritative, execute_strict, ANFProgram,
    DataOutputEntry, OnChainCryptoContext, RawOutputEntry,
};
use runar_lang::sdk::types::SdkValue;

#[derive(Copy, Clone, Eq, PartialEq)]
enum Mode {
    Lenient,
    Strict,
    OnChain,
}

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    let (mode, input_path) = match parse_args(&argv[1..]) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("driver error: {}", e);
            return ExitCode::from(1);
        }
    };
    match run(&input_path, mode) {
        Ok(out) => {
            // Print full output only on success.
            print!("{}", out);
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("driver error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// Parse argv into `(mode, input_path)`. Accepts `--mode=strict`,
/// `--mode=lenient`, or `--mode=on-chain` in any position; the lone non-flag
/// positional argument is the input file path.
fn parse_args(args: &[String]) -> Result<(Mode, String), String> {
    let mut mode = Mode::Lenient;
    let mut input_path: Option<String> = None;
    for a in args {
        match a.as_str() {
            "--mode=strict" => mode = Mode::Strict,
            "--mode=lenient" => mode = Mode::Lenient,
            "--mode=on-chain" => mode = Mode::OnChain,
            s if s.starts_with("--") => return Err(format!("unknown flag: {}", s)),
            s => {
                if input_path.is_some() {
                    return Err(
                        "usage: driver [--mode=strict|on-chain] <input-json-file>".to_string(),
                    );
                }
                input_path = Some(s.to_string());
            }
        }
    }
    let input_path = input_path
        .ok_or_else(|| "usage: driver [--mode=strict|on-chain] <input-json-file>".to_string())?;
    Ok((mode, input_path))
}

fn run(input_path: &str, mode: Mode) -> Result<String, String> {
    let raw = fs::read_to_string(input_path)
        .map_err(|e| format!("failed to read input file {}: {}", input_path, e))?;
    let input: Value =
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse input JSON: {}", e))?;

    let method_name = input
        .get("methodName")
        .and_then(|v| v.as_str())
        .ok_or("input missing methodName")?
        .to_string();

    let anf_path = resolve_anf_path(&input, input_path)?;
    let anf_raw = fs::read_to_string(&anf_path)
        .map_err(|e| format!("failed to read ANF file {}: {}", anf_path.display(), e))?;
    let anf: ANFProgram =
        serde_json::from_str(&anf_raw).map_err(|e| format!("failed to parse ANF JSON: {}", e))?;

    let current_state = decode_state_map(input.get("currentState"))?;
    let args = decode_state_map(input.get("args"))?;
    let constructor_args = decode_arg_list(input.get("constructorArgs"))?;

    match mode {
        Mode::Strict => {
            let result =
                execute_strict(&anf, &method_name, &current_state, &args, &constructor_args);
            encode_strict_result(result)
        }
        Mode::OnChain => {
            let sighash = input
                .get("sighash")
                .and_then(|v| v.as_str())
                .ok_or("input missing sighash for --mode=on-chain")?;
            let ctx = OnChainCryptoContext::from_hex(sighash).map_err(|e| {
                format!("invalid sighash for --mode=on-chain: {}", e)
            })?;
            let result = execute_on_chain_authoritative(
                &anf,
                &method_name,
                &current_state,
                &args,
                &constructor_args,
                &ctx,
            );
            encode_strict_result(result)
        }
        Mode::Lenient => {
            let (new_state, data_outputs, raw_outputs) = compute_new_state_and_data_outputs(
                &anf,
                &method_name,
                &current_state,
                &args,
                &constructor_args,
            )
            .map_err(|e| format!("compute_new_state_and_data_outputs failed: {}", e))?;

            let out_value = encode_output(&new_state, &data_outputs, &raw_outputs);
            let mut out = serde_json::to_string_pretty(&out_value)
                .map_err(|e| format!("failed to serialize output: {}", e))?;
            out.push('\n');
            Ok(out)
        }
    }
}

/// Encode the result of `execute_strict` / `execute_on_chain_authoritative`
/// into the wire format. On `Ok`, emits the standard
/// `{state, dataOutputs, rawOutputs}` envelope; on assertion failure, emits
/// `{error: "AssertionFailureError", methodName, bindingName}`. Driver exit
/// status remains 0 in both cases — only real driver errors (missing IR,
/// malformed input, …) bubble up to the non-zero exit path.
fn encode_strict_result(
    result: Result<
        (
            HashMap<String, SdkValue>,
            Vec<DataOutputEntry>,
            Vec<RawOutputEntry>,
        ),
        runar_lang::sdk::anf_interpreter::AssertionFailureError,
    >,
) -> Result<String, String> {
    match result {
        Ok((new_state, data_outputs, raw_outputs)) => {
            let out_value = encode_output(&new_state, &data_outputs, &raw_outputs);
            let mut out = serde_json::to_string_pretty(&out_value)
                .map_err(|e| format!("failed to serialize output: {}", e))?;
            out.push('\n');
            Ok(out)
        }
        Err(af) => {
            let mut obj = Map::new();
            obj.insert(
                "error".to_string(),
                Value::String("AssertionFailureError".to_string()),
            );
            obj.insert("methodName".to_string(), Value::String(af.method_name));
            obj.insert("bindingName".to_string(), Value::String(af.binding_name));
            let mut out = serde_json::to_string_pretty(&Value::Object(obj))
                .map_err(|e| format!("failed to serialize output: {}", e))?;
            out.push('\n');
            Ok(out)
        }
    }
}

/// Resolve `anfPath`. Prefer the spec field; fall back to `case` for the
/// in-tree fixtures under `inputs/*.json`.
fn resolve_anf_path(input: &Value, input_path: &str) -> Result<PathBuf, String> {
    if let Some(p) = input.get("anfPath").and_then(|v| v.as_str()) {
        return Ok(PathBuf::from(p));
    }
    if let Some(case) = input.get("case").and_then(|v| v.as_str()) {
        // <repo>/conformance/anf-interpreter/inputs/<file>.json
        // → <repo>/conformance/tests/<case>/expected-ir.json
        let input_abs = fs::canonicalize(input_path)
            .map_err(|e| format!("failed to canonicalize input path: {}", e))?;
        // Walk up looking for a sibling `tests` dir under `conformance`.
        let mut cur: Option<&Path> = Some(input_abs.as_path());
        while let Some(p) = cur {
            if let Some(parent) = p.parent() {
                let candidate = parent.join("tests").join(case).join("expected-ir.json");
                if candidate.exists() {
                    return Ok(candidate);
                }
                cur = Some(parent);
            } else {
                break;
            }
        }
        return Err(format!(
            "could not locate expected-ir.json for case '{}' starting from {}",
            case, input_path
        ));
    }
    Err("input missing both anfPath and case".to_string())
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

fn decode_state_map(v: Option<&Value>) -> Result<HashMap<String, SdkValue>, String> {
    let mut out = HashMap::new();
    let Some(v) = v else { return Ok(out); };
    let obj = match v {
        Value::Null => return Ok(out),
        Value::Object(o) => o,
        _ => return Err(format!("expected object, got {:?}", v)),
    };
    for (k, val) in obj {
        out.insert(k.clone(), decode_value(val)?);
    }
    Ok(out)
}

fn decode_arg_list(v: Option<&Value>) -> Result<Vec<SdkValue>, String> {
    let Some(v) = v else { return Ok(Vec::new()); };
    let arr = match v {
        Value::Null => return Ok(Vec::new()),
        Value::Array(a) => a,
        _ => return Err(format!("expected array, got {:?}", v)),
    };
    arr.iter().map(decode_value).collect()
}

/// Decode a single JSON value into an `SdkValue`, honoring the `"Xn"`
/// bigint convention.
fn decode_value(v: &Value) -> Result<SdkValue, String> {
    match v {
        Value::Bool(b) => Ok(SdkValue::Bool(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(SdkValue::Int(i))
            } else if let Some(f) = n.as_f64() {
                // JSON number that doesn't fit i64 — treat as i64 best-effort.
                Ok(SdkValue::Int(f as i64))
            } else {
                Err(format!("unsupported numeric value: {}", n))
            }
        }
        Value::String(s) => {
            if is_bigint_literal(s) {
                let body = &s[..s.len() - 1];
                if let Ok(i) = body.parse::<i64>() {
                    Ok(SdkValue::Int(i))
                } else {
                    let bn: num_bigint::BigInt =
                        body.parse().map_err(|e| format!("invalid bigint '{}': {}", body, e))?;
                    Ok(SdkValue::BigInt(bn))
                }
            } else {
                // Plain strings are treated as hex byte data.
                Ok(SdkValue::Bytes(s.clone()))
            }
        }
        Value::Null => Ok(SdkValue::Auto),
        Value::Array(arr) => {
            let inner: Result<Vec<SdkValue>, String> = arr.iter().map(decode_value).collect();
            Ok(SdkValue::Array(inner?))
        }
        Value::Object(_) => Err("nested object values are not supported in state/args".into()),
    }
}

fn is_bigint_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || *bytes.last().unwrap() != b'n' {
        return false;
    }
    let body = &s[..s.len() - 1];
    let body = body.strip_prefix('-').unwrap_or(body);
    !body.is_empty() && body.bytes().all(|c| c.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn encode_output(
    state: &HashMap<String, SdkValue>,
    data_outputs: &[DataOutputEntry],
    raw_outputs: &[RawOutputEntry],
) -> Value {
    let mut state_obj = Map::new();
    // Sort keys for stable output.
    let mut keys: Vec<&String> = state.keys().collect();
    keys.sort();
    for k in keys {
        state_obj.insert(k.clone(), encode_sdk_value(&state[k]));
    }

    let mut outs = Vec::with_capacity(data_outputs.len());
    for d in data_outputs {
        let mut obj = Map::new();
        obj.insert(
            "satoshis".to_string(),
            Value::String(format!("{}n", d.satoshis)),
        );
        obj.insert("script".to_string(), Value::String(d.script.clone()));
        outs.push(Value::Object(obj));
    }

    let mut raws = Vec::with_capacity(raw_outputs.len());
    for r in raw_outputs {
        let mut obj = Map::new();
        obj.insert(
            "satoshis".to_string(),
            Value::String(format!("{}n", r.satoshis)),
        );
        obj.insert("script".to_string(), Value::String(r.script.clone()));
        raws.push(Value::Object(obj));
    }

    let mut top = Map::new();
    top.insert("state".to_string(), Value::Object(state_obj));
    top.insert("dataOutputs".to_string(), Value::Array(outs));
    top.insert("rawOutputs".to_string(), Value::Array(raws));
    Value::Object(top)
}

/// Encode an SdkValue back into the wire format. Numeric values become
/// `"Xn"` bigint strings (matching the TS reference's `bigint` round-trip);
/// bytes stay as hex strings; bools stay as bools.
fn encode_sdk_value(v: &SdkValue) -> Value {
    match v {
        SdkValue::Int(n) => Value::String(format!("{}n", n)),
        SdkValue::BigInt(n) => Value::String(format!("{}n", n)),
        SdkValue::Bool(b) => Value::Bool(*b),
        SdkValue::Bytes(s) => Value::String(s.clone()),
        SdkValue::Auto => Value::Null,
        SdkValue::Array(arr) => Value::Array(arr.iter().map(encode_sdk_value).collect()),
    }
}
