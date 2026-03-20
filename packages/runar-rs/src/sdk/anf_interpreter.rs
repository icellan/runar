//! Lightweight ANF interpreter for auto-computing state transitions.
//!
//! Given a compiled artifact's ANF IR, the current contract state, and
//! method arguments, this interpreter walks the ANF bindings and computes
//! the new state.  It handles `update_prop` nodes to track state mutations,
//! while skipping on-chain-only operations like `check_preimage`,
//! `deserialize_state`, `get_state_script`, `add_output`, and `add_raw_output`.
//!
//! This enables the SDK to auto-compute `newState` for stateful contract
//! calls, so callers don't need to duplicate contract logic.

use std::collections::HashMap;
use serde::Deserialize;
use sha2::{Sha256, Digest as Sha256Digest};
use ripemd::Ripemd160;
use super::types::SdkValue;

// ---------------------------------------------------------------------------
// ANF types (deserialized from artifact JSON)
// ---------------------------------------------------------------------------

/// The top-level ANF program attached to a compiled artifact.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ANFProgram {
    pub contract_name: String,
    pub properties: Vec<ANFProperty>,
    pub methods: Vec<ANFMethod>,
}

/// A contract property in the ANF IR.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ANFProperty {
    pub name: String,
    #[serde(rename = "type")]
    pub prop_type: String,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub initial_value: Option<serde_json::Value>,
}

/// A method in the ANF IR.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ANFMethod {
    pub name: String,
    pub params: Vec<ANFParam>,
    pub body: Vec<ANFBinding>,
    #[serde(default)]
    pub is_public: bool,
}

/// A method parameter.
#[derive(Debug, Clone, Deserialize)]
pub struct ANFParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
}

/// A single let-binding in the ANF body.
#[derive(Debug, Clone, Deserialize)]
pub struct ANFBinding {
    pub name: String,
    pub value: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Internal value representation
// ---------------------------------------------------------------------------

/// Internal interpreter value — richer than SdkValue to handle booleans
/// and undefined results from skipped operations.
#[derive(Debug, Clone)]
enum Val {
    Int(i64),
    Bool(bool),
    Bytes(String),
    Undefined,
}

impl Val {
    fn from_sdk(v: &SdkValue) -> Self {
        match v {
            SdkValue::Int(n) => Val::Int(*n),
            SdkValue::BigInt(n) => Val::Int(n.to_string().parse::<i64>().unwrap_or(0)),
            SdkValue::Bool(b) => Val::Bool(*b),
            SdkValue::Bytes(s) => Val::Bytes(s.clone()),
            SdkValue::Auto => Val::Undefined,
        }
    }

    fn to_sdk(&self) -> SdkValue {
        match self {
            Val::Int(n) => SdkValue::Int(*n),
            Val::Bool(b) => SdkValue::Bool(*b),
            Val::Bytes(s) => SdkValue::Bytes(s.clone()),
            Val::Undefined => SdkValue::Int(0),
        }
    }

    fn to_i64(&self) -> i64 {
        match self {
            Val::Int(n) => *n,
            Val::Bool(b) => if *b { 1 } else { 0 },
            Val::Bytes(_) => 0,
            Val::Undefined => 0,
        }
    }

    fn is_truthy(&self) -> bool {
        match self {
            Val::Int(n) => *n != 0,
            Val::Bool(b) => *b,
            Val::Bytes(s) => !s.is_empty() && s != "0" && s != "false",
            Val::Undefined => false,
        }
    }

    fn as_hex(&self) -> String {
        match self {
            Val::Bytes(s) => s.clone(),
            Val::Int(_) | Val::Bool(_) | Val::Undefined => String::new(),
        }
    }

    fn is_bytes(&self) -> bool {
        matches!(self, Val::Bytes(_))
    }
}

/// Parse a serde_json::Value into a Val.
fn json_to_val(v: &serde_json::Value) -> Val {
    match v {
        serde_json::Value::Number(n) => {
            Val::Int(n.as_i64().unwrap_or(0))
        }
        serde_json::Value::Bool(b) => Val::Bool(*b),
        serde_json::Value::String(s) => {
            // Handle BigInt strings like "42n"
            if let Some(stripped) = s.strip_suffix('n') {
                if let Ok(n) = stripped.parse::<i64>() {
                    return Val::Int(n);
                }
            }
            // Plain numeric string
            if let Ok(n) = s.parse::<i64>() {
                return Val::Int(n);
            }
            Val::Bytes(s.clone())
        }
        serde_json::Value::Null => Val::Undefined,
        _ => Val::Undefined,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the new state after executing a contract method.
///
/// Returns the updated state (merged with `current_state`).
pub fn compute_new_state(
    anf: &ANFProgram,
    method_name: &str,
    current_state: &HashMap<String, SdkValue>,
    args: &HashMap<String, SdkValue>,
) -> Result<HashMap<String, SdkValue>, String> {
    // Find the public method
    let method = anf.methods.iter().find(|m| m.name == method_name && m.is_public)
        .ok_or_else(|| format!("compute_new_state: method '{}' not found in ANF IR", method_name))?;

    let mut env: HashMap<String, Val> = HashMap::new();

    // Load properties
    for prop in &anf.properties {
        if let Some(sv) = current_state.get(&prop.name) {
            env.insert(prop.name.clone(), Val::from_sdk(sv));
        } else if let Some(ref init) = prop.initial_value {
            env.insert(prop.name.clone(), json_to_val(init));
        }
    }

    // Load method params (skip implicit ones)
    let implicit: &[&str] = &["_changePKH", "_changeAmount", "_newAmount", "txPreimage"];
    for param in &method.params {
        if implicit.contains(&param.name.as_str()) {
            continue;
        }
        if let Some(sv) = args.get(&param.name) {
            env.insert(param.name.clone(), Val::from_sdk(sv));
        }
    }

    // Track state mutations
    let mut state_delta: HashMap<String, Val> = HashMap::new();

    // Walk bindings
    eval_bindings(&method.body, &mut env, &mut state_delta, anf);

    // Merge delta into current_state
    let mut result = current_state.clone();
    for (k, v) in state_delta {
        result.insert(k, v.to_sdk());
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Binding evaluation
// ---------------------------------------------------------------------------

fn eval_bindings(
    bindings: &[ANFBinding],
    env: &mut HashMap<String, Val>,
    state_delta: &mut HashMap<String, Val>,
    anf: &ANFProgram,
) {
    for binding in bindings {
        let val = eval_value(&binding.value, env, state_delta, anf);
        env.insert(binding.name.clone(), val);
    }
}

fn eval_value(
    value: &serde_json::Value,
    env: &mut HashMap<String, Val>,
    state_delta: &mut HashMap<String, Val>,
    anf: &ANFProgram,
) -> Val {
    let kind = match value.get("kind").and_then(|k| k.as_str()) {
        Some(k) => k,
        None => return Val::Undefined,
    };

    match kind {
        "load_param" => {
            let name = str_field(value, "name");
            env.get(&name).cloned().unwrap_or(Val::Undefined)
        }

        "load_prop" => {
            let name = str_field(value, "name");
            env.get(&name).cloned().unwrap_or(Val::Undefined)
        }

        "load_const" => {
            let raw = &value["value"];
            if let Some(s) = raw.as_str() {
                // Handle @ref: aliases
                if let Some(target) = s.strip_prefix("@ref:") {
                    return env.get(target).cloned().unwrap_or(Val::Undefined);
                }
            }
            json_to_val(raw)
        }

        "bin_op" => {
            let op = str_field(value, "op");
            let left_name = str_field(value, "left");
            let right_name = str_field(value, "right");
            let result_type = value.get("resultType").and_then(|v| v.as_str()).unwrap_or("");
            let left = env.get(&left_name).cloned().unwrap_or(Val::Undefined);
            let right = env.get(&right_name).cloned().unwrap_or(Val::Undefined);
            eval_bin_op(&op, &left, &right, result_type)
        }

        "unary_op" => {
            let op = str_field(value, "op");
            let operand_name = str_field(value, "operand");
            let result_type = value.get("resultType").and_then(|v| v.as_str()).unwrap_or("");
            let operand = env.get(&operand_name).cloned().unwrap_or(Val::Undefined);
            eval_unary_op(&op, &operand, result_type)
        }

        "call" => {
            let func = str_field(value, "func");
            let arg_names = str_array_field(value, "args");
            let args: Vec<Val> = arg_names.iter()
                .map(|n| env.get(n).cloned().unwrap_or(Val::Undefined))
                .collect();
            eval_call(&func, &args)
        }

        "method_call" => {
            let method_name = str_field(value, "method");
            let arg_names = str_array_field(value, "args");
            let call_args: Vec<Val> = arg_names.iter()
                .map(|n| env.get(n).cloned().unwrap_or(Val::Undefined))
                .collect();
            // Look up private method in ANF program
            if let Some(method) = anf.methods.iter().find(|m| m.name == method_name && !m.is_public) {
                let mut child_env: HashMap<String, Val> = HashMap::new();
                // Copy property values from caller env
                for prop in &anf.properties {
                    if let Some(v) = env.get(&prop.name) {
                        child_env.insert(prop.name.clone(), v.clone());
                    }
                }
                // Map params to args
                for (i, param) in method.params.iter().enumerate() {
                    if let Some(arg_val) = call_args.get(i) {
                        child_env.insert(param.name.clone(), arg_val.clone());
                    }
                }
                eval_bindings(&method.body, &mut child_env, state_delta, anf);
                // Copy property updates back to caller env
                for prop in &anf.properties {
                    if let Some(v) = child_env.get(&prop.name) {
                        env.insert(prop.name.clone(), v.clone());
                    }
                }
                // Return last binding's value
                if let Some(last) = method.body.last() {
                    child_env.get(&last.name).cloned().unwrap_or(Val::Undefined)
                } else {
                    Val::Undefined
                }
            } else {
                Val::Undefined
            }
        }

        "if" => {
            let cond_name = str_field(value, "cond");
            let cond = env.get(&cond_name).cloned().unwrap_or(Val::Undefined);
            let branch_key = if cond.is_truthy() { "then" } else { "else" };
            if let Some(branch_json) = value.get(branch_key).and_then(|v| v.as_array()) {
                let bindings: Vec<ANFBinding> = branch_json.iter()
                    .filter_map(|b| serde_json::from_value(b.clone()).ok())
                    .collect();
                // Create child env for the branch
                let mut child_env = env.clone();
                eval_bindings(&bindings, &mut child_env, state_delta, anf);
                // Copy new bindings back
                for (k, v) in &child_env {
                    env.insert(k.clone(), v.clone());
                }
                // Return last binding's value
                if let Some(last) = bindings.last() {
                    child_env.get(&last.name).cloned().unwrap_or(Val::Undefined)
                } else {
                    Val::Undefined
                }
            } else {
                Val::Undefined
            }
        }

        "loop" => {
            let count = value.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let iter_var = str_field(value, "iterVar");
            let body_json = value.get("body").and_then(|v| v.as_array());
            let mut last_val = Val::Undefined;
            if let Some(body_arr) = body_json {
                let bindings: Vec<ANFBinding> = body_arr.iter()
                    .filter_map(|b| serde_json::from_value(b.clone()).ok())
                    .collect();
                for i in 0..count {
                    env.insert(iter_var.clone(), Val::Int(i));
                    let mut loop_env = env.clone();
                    eval_bindings(&bindings, &mut loop_env, state_delta, anf);
                    // Copy loop bindings back
                    for (k, v) in &loop_env {
                        env.insert(k.clone(), v.clone());
                    }
                    if let Some(last) = bindings.last() {
                        last_val = loop_env.get(&last.name).cloned().unwrap_or(Val::Undefined);
                    }
                }
            }
            last_val
        }

        "assert" => Val::Undefined,

        "update_prop" => {
            let name = str_field(value, "name");
            let val_name = str_field(value, "value");
            let new_val = env.get(&val_name).cloned().unwrap_or(Val::Undefined);
            env.insert(name.clone(), new_val.clone());
            state_delta.insert(name, new_val);
            Val::Undefined
        }

        "add_output" => {
            // Map stateValues to mutable properties (declaration order)
            let state_values = str_array_field(value, "stateValues");
            if !state_values.is_empty() {
                let mutable_props: Vec<&ANFProperty> = anf.properties.iter()
                    .filter(|p| !p.readonly)
                    .collect();
                for (i, sv_name) in state_values.iter().enumerate() {
                    if let Some(prop) = mutable_props.get(i) {
                        let val = env.get(sv_name).cloned().unwrap_or(Val::Undefined);
                        env.insert(prop.name.clone(), val.clone());
                        state_delta.insert(prop.name.clone(), val);
                    }
                }
            }
            Val::Undefined
        }

        // On-chain-only operations — skip in simulation
        "check_preimage" | "deserialize_state" | "get_state_script"
        | "add_raw_output" => Val::Undefined,

        _ => Val::Undefined,
    }
}

// ---------------------------------------------------------------------------
// Binary operations
// ---------------------------------------------------------------------------

fn eval_bin_op(op: &str, left: &Val, right: &Val, result_type: &str) -> Val {
    // Bytes mode
    if result_type == "bytes" || (left.is_bytes() && right.is_bytes()) {
        let lh = left.as_hex();
        let rh = right.as_hex();
        return match op {
            "+" => Val::Bytes(format!("{}{}", lh, rh)),
            "==" | "===" => Val::Bool(lh == rh),
            "!=" | "!==" => Val::Bool(lh != rh),
            _ => Val::Bytes(String::new()),
        };
    }

    let l = left.to_i64();
    let r = right.to_i64();

    match op {
        "+" => Val::Int(l.wrapping_add(r)),
        "-" => Val::Int(l.wrapping_sub(r)),
        "*" => Val::Int(l.wrapping_mul(r)),
        "/" => Val::Int(if r == 0 { 0 } else { l / r }),
        "%" => Val::Int(if r == 0 { 0 } else { l % r }),
        "==" | "===" => Val::Bool(l == r),
        "!=" | "!==" => Val::Bool(l != r),
        "<" => Val::Bool(l < r),
        "<=" => Val::Bool(l <= r),
        ">" => Val::Bool(l > r),
        ">=" => Val::Bool(l >= r),
        "&&" => Val::Bool(left.is_truthy() && right.is_truthy()),
        "||" => Val::Bool(left.is_truthy() || right.is_truthy()),
        "&" => Val::Int(l & r),
        "|" => Val::Int(l | r),
        "^" => Val::Int(l ^ r),
        "<<" => Val::Int(l.wrapping_shl(r as u32)),
        ">>" => Val::Int(l.wrapping_shr(r as u32)),
        _ => Val::Int(0),
    }
}

// ---------------------------------------------------------------------------
// Unary operations
// ---------------------------------------------------------------------------

fn eval_unary_op(op: &str, operand: &Val, result_type: &str) -> Val {
    if result_type == "bytes" {
        if op == "~" {
            let hex = operand.as_hex();
            let inverted: String = (0..hex.len() / 2)
                .map(|i| {
                    let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
                    format!("{:02x}", !byte)
                })
                .collect();
            return Val::Bytes(inverted);
        }
        return operand.clone();
    }

    let v = operand.to_i64();
    match op {
        "-" => Val::Int(-v),
        "!" => Val::Bool(!operand.is_truthy()),
        "~" => Val::Int(!v),
        _ => Val::Int(v),
    }
}

// ---------------------------------------------------------------------------
// Built-in function calls
// ---------------------------------------------------------------------------

fn eval_call(func: &str, args: &[Val]) -> Val {
    match func {
        // Crypto — mock
        "checkSig" | "checkMultiSig" | "checkPreimage" => Val::Bool(true),

        // Crypto — real hashes
        "sha256" => hash_fn_sha256(&args.first().map(|a| a.as_hex()).unwrap_or_default()),
        "hash256" => hash_fn_hash256(&args.first().map(|a| a.as_hex()).unwrap_or_default()),
        "hash160" => hash_fn_hash160(&args.first().map(|a| a.as_hex()).unwrap_or_default()),
        "ripemd160" => hash_fn_ripemd160(&args.first().map(|a| a.as_hex()).unwrap_or_default()),

        // Assert — skip
        "assert" => Val::Undefined,

        // Byte operations
        "num2bin" => {
            let n = args.first().map(|a| a.to_i64()).unwrap_or(0);
            let len = args.get(1).map(|a| a.to_i64()).unwrap_or(0) as usize;
            Val::Bytes(num2bin_hex(n, len))
        }
        "bin2num" => {
            let hex = args.first().map(|a| a.as_hex()).unwrap_or_default();
            Val::Int(bin2num_i64(&hex))
        }
        "cat" => {
            let a = args.first().map(|v| v.as_hex()).unwrap_or_default();
            let b = args.get(1).map(|v| v.as_hex()).unwrap_or_default();
            Val::Bytes(format!("{}{}", a, b))
        }
        "substr" => {
            let hex = args.first().map(|v| v.as_hex()).unwrap_or_default();
            let start = args.get(1).map(|v| v.to_i64()).unwrap_or(0) as usize;
            let len = args.get(2).map(|v| v.to_i64()).unwrap_or(0) as usize;
            let from = start * 2;
            let to = (start + len) * 2;
            let to = to.min(hex.len());
            let from = from.min(hex.len());
            Val::Bytes(hex[from..to].to_string())
        }
        "reverseBytes" => {
            let hex = args.first().map(|v| v.as_hex()).unwrap_or_default();
            let mut pairs: Vec<&str> = Vec::new();
            let mut i = 0;
            while i + 2 <= hex.len() {
                pairs.push(&hex[i..i + 2]);
                i += 2;
            }
            pairs.reverse();
            Val::Bytes(pairs.join(""))
        }
        "len" => {
            let hex = args.first().map(|v| v.as_hex()).unwrap_or_default();
            Val::Int((hex.len() / 2) as i64)
        }

        // Math builtins
        "abs" => {
            let v = args.first().map(|a| a.to_i64()).unwrap_or(0);
            Val::Int(v.abs())
        }
        "min" => {
            let a = args.first().map(|v| v.to_i64()).unwrap_or(0);
            let b = args.get(1).map(|v| v.to_i64()).unwrap_or(0);
            Val::Int(a.min(b))
        }
        "max" => {
            let a = args.first().map(|v| v.to_i64()).unwrap_or(0);
            let b = args.get(1).map(|v| v.to_i64()).unwrap_or(0);
            Val::Int(a.max(b))
        }
        "within" => {
            let x = args.first().map(|v| v.to_i64()).unwrap_or(0);
            let lo = args.get(1).map(|v| v.to_i64()).unwrap_or(0);
            let hi = args.get(2).map(|v| v.to_i64()).unwrap_or(0);
            Val::Bool(x >= lo && x < hi)
        }
        "safediv" => {
            let a = args.first().map(|v| v.to_i64()).unwrap_or(0);
            let b = args.get(1).map(|v| v.to_i64()).unwrap_or(0);
            Val::Int(if b == 0 { 0 } else { a / b })
        }
        "safemod" => {
            let a = args.first().map(|v| v.to_i64()).unwrap_or(0);
            let b = args.get(1).map(|v| v.to_i64()).unwrap_or(0);
            Val::Int(if b == 0 { 0 } else { a % b })
        }
        "clamp" => {
            let v = args.first().map(|a| a.to_i64()).unwrap_or(0);
            let lo = args.get(1).map(|a| a.to_i64()).unwrap_or(0);
            let hi = args.get(2).map(|a| a.to_i64()).unwrap_or(0);
            Val::Int(v.max(lo).min(hi))
        }
        "sign" => {
            let v = args.first().map(|a| a.to_i64()).unwrap_or(0);
            Val::Int(if v > 0 { 1 } else if v < 0 { -1 } else { 0 })
        }
        "pow" => {
            let base = args.first().map(|a| a.to_i64()).unwrap_or(0);
            let exp = args.get(1).map(|a| a.to_i64()).unwrap_or(0);
            if exp < 0 {
                Val::Int(0)
            } else {
                let mut result: i64 = 1;
                for _ in 0..exp {
                    result = result.wrapping_mul(base);
                }
                Val::Int(result)
            }
        }
        "sqrt" => {
            let v = args.first().map(|a| a.to_i64()).unwrap_or(0);
            if v <= 0 {
                Val::Int(0)
            } else {
                // Integer square root via Newton's method
                let mut x = v;
                let mut y = (x + 1) / 2;
                while y < x {
                    x = y;
                    y = (x + v / x) / 2;
                }
                Val::Int(x)
            }
        }
        "gcd" => {
            let mut a = args.first().map(|v| v.to_i64()).unwrap_or(0).abs();
            let mut b = args.get(1).map(|v| v.to_i64()).unwrap_or(0).abs();
            while b != 0 {
                let t = b;
                b = a % b;
                a = t;
            }
            Val::Int(a)
        }
        "divmod" => {
            let a = args.first().map(|v| v.to_i64()).unwrap_or(0);
            let b = args.get(1).map(|v| v.to_i64()).unwrap_or(0);
            Val::Int(if b == 0 { 0 } else { a / b })
        }
        "log2" => {
            let v = args.first().map(|a| a.to_i64()).unwrap_or(0);
            if v <= 0 {
                Val::Int(0)
            } else {
                let mut bits: i64 = 0;
                let mut x = v;
                while x > 1 {
                    x >>= 1;
                    bits += 1;
                }
                Val::Int(bits)
            }
        }
        "bool" => {
            let truthy = args.first().map(|a| a.is_truthy()).unwrap_or(false);
            Val::Int(if truthy { 1 } else { 0 })
        }
        "mulDiv" => {
            let a = args.first().map(|v| v.to_i64()).unwrap_or(0) as i128;
            let b = args.get(1).map(|v| v.to_i64()).unwrap_or(0) as i128;
            let c = args.get(2).map(|v| v.to_i64()).unwrap_or(1) as i128;
            Val::Int(if c == 0 { 0 } else { ((a * b) / c) as i64 })
        }
        "percentOf" => {
            let a = args.first().map(|v| v.to_i64()).unwrap_or(0) as i128;
            let b = args.get(1).map(|v| v.to_i64()).unwrap_or(0) as i128;
            Val::Int(((a * b) / 10000) as i64)
        }

        // Preimage intrinsics — return dummy values in simulation
        "extractOutputHash" | "extractAmount" => {
            Val::Bytes("00".repeat(32))
        }

        _ => Val::Undefined,
    }
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i + 2 <= hex.len() {
        if let Ok(b) = u8::from_str_radix(&hex[i..i + 2], 16) {
            bytes.push(b);
        }
        i += 2;
    }
    bytes
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hash_fn_sha256(hex: &str) -> Val {
    let data = hex_to_bytes(hex);
    let result = Sha256::digest(&data);
    Val::Bytes(bytes_to_hex(&result))
}

fn hash_fn_hash256(hex: &str) -> Val {
    let data = hex_to_bytes(hex);
    let first = Sha256::digest(&data);
    let second = Sha256::digest(&first);
    Val::Bytes(bytes_to_hex(&second))
}

fn hash_fn_hash160(hex: &str) -> Val {
    let data = hex_to_bytes(hex);
    let sha = Sha256::digest(&data);
    let ripe = Ripemd160::digest(&sha);
    Val::Bytes(bytes_to_hex(&ripe))
}

fn hash_fn_ripemd160(hex: &str) -> Val {
    let data = hex_to_bytes(hex);
    let result = Ripemd160::digest(&data);
    Val::Bytes(bytes_to_hex(&result))
}

// ---------------------------------------------------------------------------
// Numeric encoding helpers
// ---------------------------------------------------------------------------

fn num2bin_hex(n: i64, byte_len: usize) -> String {
    if n == 0 {
        return "00".repeat(byte_len);
    }

    let negative = n < 0;
    let mut abs = if negative { (n as i128).unsigned_abs() } else { n as u128 };

    let mut bytes: Vec<u8> = Vec::new();
    while abs > 0 {
        bytes.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    // Sign bit handling
    if !bytes.is_empty() {
        if negative {
            if bytes[bytes.len() - 1] & 0x80 == 0 {
                let last = bytes.len() - 1;
                bytes[last] |= 0x80;
            } else {
                bytes.push(0x80);
            }
        } else if bytes[bytes.len() - 1] & 0x80 != 0 {
            bytes.push(0x00);
        }
    }

    // Pad or truncate
    while bytes.len() < byte_len {
        bytes.push(0x00);
    }
    bytes.truncate(byte_len);

    bytes_to_hex(&bytes)
}

fn bin2num_i64(hex: &str) -> i64 {
    if hex.is_empty() {
        return 0;
    }
    let mut bytes = hex_to_bytes(hex);
    if bytes.is_empty() {
        return 0;
    }

    let negative = bytes[bytes.len() - 1] & 0x80 != 0;
    if negative {
        let last = bytes.len() - 1;
        bytes[last] &= 0x7f;
    }

    let mut result: i64 = 0;
    for i in (0..bytes.len()).rev() {
        result = (result << 8) | bytes[i] as i64;
    }

    if negative { -result } else { result }
}

// ---------------------------------------------------------------------------
// JSON field helpers
// ---------------------------------------------------------------------------

fn str_field(value: &serde_json::Value, field: &str) -> String {
    value.get(field).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn str_array_field(value: &serde_json::Value, field: &str) -> Vec<String> {
    value.get(field)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_anf(methods: Vec<ANFMethod>) -> ANFProgram {
        ANFProgram {
            contract_name: "Test".to_string(),
            properties: vec![
                ANFProperty {
                    name: "count".to_string(),
                    prop_type: "bigint".to_string(),
                    readonly: false,
                    initial_value: None,
                },
            ],
            methods,
        }
    }

    fn make_increment_method() -> ANFMethod {
        // Simulates: this.count = this.count + 1
        ANFMethod {
            name: "increment".to_string(),
            params: vec![],
            is_public: true,
            body: vec![
                ANFBinding {
                    name: "_t0".to_string(),
                    value: serde_json::json!({ "kind": "load_prop", "name": "count" }),
                },
                ANFBinding {
                    name: "_t1".to_string(),
                    value: serde_json::json!({ "kind": "load_const", "value": 1 }),
                },
                ANFBinding {
                    name: "_t2".to_string(),
                    value: serde_json::json!({
                        "kind": "bin_op",
                        "op": "+",
                        "left": "_t0",
                        "right": "_t1",
                    }),
                },
                ANFBinding {
                    name: "_t3".to_string(),
                    value: serde_json::json!({
                        "kind": "update_prop",
                        "name": "count",
                        "value": "_t2",
                    }),
                },
            ],
        }
    }

    #[test]
    fn test_increment() {
        let anf = make_anf(vec![make_increment_method()]);
        let mut state = HashMap::new();
        state.insert("count".to_string(), SdkValue::Int(0));

        let result = compute_new_state(&anf, "increment", &state, &HashMap::new()).unwrap();
        assert_eq!(result.get("count"), Some(&SdkValue::Int(1)));
    }

    #[test]
    fn test_increment_twice() {
        let anf = make_anf(vec![make_increment_method()]);
        let mut state = HashMap::new();
        state.insert("count".to_string(), SdkValue::Int(5));

        let result = compute_new_state(&anf, "increment", &state, &HashMap::new()).unwrap();
        assert_eq!(result.get("count"), Some(&SdkValue::Int(6)));
    }

    #[test]
    fn test_method_not_found() {
        let anf = make_anf(vec![]);
        let result = compute_new_state(&anf, "nonexistent", &HashMap::new(), &HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_ref_alias() {
        // load_const with @ref: should resolve to the referenced binding
        let anf = make_anf(vec![ANFMethod {
            name: "test".to_string(),
            params: vec![],
            is_public: true,
            body: vec![
                ANFBinding {
                    name: "_t0".to_string(),
                    value: serde_json::json!({ "kind": "load_prop", "name": "count" }),
                },
                ANFBinding {
                    name: "_t1".to_string(),
                    value: serde_json::json!({ "kind": "load_const", "value": "@ref:_t0" }),
                },
                ANFBinding {
                    name: "_t2".to_string(),
                    value: serde_json::json!({ "kind": "load_const", "value": 10 }),
                },
                ANFBinding {
                    name: "_t3".to_string(),
                    value: serde_json::json!({
                        "kind": "bin_op", "op": "+",
                        "left": "_t1", "right": "_t2",
                    }),
                },
                ANFBinding {
                    name: "_t4".to_string(),
                    value: serde_json::json!({
                        "kind": "update_prop", "name": "count", "value": "_t3",
                    }),
                },
            ],
        }]);

        let mut state = HashMap::new();
        state.insert("count".to_string(), SdkValue::Int(7));

        let result = compute_new_state(&anf, "test", &state, &HashMap::new()).unwrap();
        assert_eq!(result.get("count"), Some(&SdkValue::Int(17)));
    }

    #[test]
    fn test_if_branch() {
        // if (count > 0) { count = count - 1 } else { count = count + 1 }
        let anf = make_anf(vec![ANFMethod {
            name: "test".to_string(),
            params: vec![],
            is_public: true,
            body: vec![
                ANFBinding {
                    name: "_t0".to_string(),
                    value: serde_json::json!({ "kind": "load_prop", "name": "count" }),
                },
                ANFBinding {
                    name: "_t1".to_string(),
                    value: serde_json::json!({ "kind": "load_const", "value": 0 }),
                },
                ANFBinding {
                    name: "_cond".to_string(),
                    value: serde_json::json!({
                        "kind": "bin_op", "op": ">",
                        "left": "_t0", "right": "_t1",
                    }),
                },
                ANFBinding {
                    name: "_if".to_string(),
                    value: serde_json::json!({
                        "kind": "if",
                        "cond": "_cond",
                        "then": [
                            { "name": "_a0", "value": { "kind": "load_prop", "name": "count" } },
                            { "name": "_a1", "value": { "kind": "load_const", "value": 1 } },
                            { "name": "_a2", "value": { "kind": "bin_op", "op": "-", "left": "_a0", "right": "_a1" } },
                            { "name": "_a3", "value": { "kind": "update_prop", "name": "count", "value": "_a2" } },
                        ],
                        "else": [
                            { "name": "_b0", "value": { "kind": "load_prop", "name": "count" } },
                            { "name": "_b1", "value": { "kind": "load_const", "value": 1 } },
                            { "name": "_b2", "value": { "kind": "bin_op", "op": "+", "left": "_b0", "right": "_b1" } },
                            { "name": "_b3", "value": { "kind": "update_prop", "name": "count", "value": "_b2" } },
                        ],
                    }),
                },
            ],
        }]);

        // count > 0: take then branch → decrement
        let mut state = HashMap::new();
        state.insert("count".to_string(), SdkValue::Int(5));
        let result = compute_new_state(&anf, "test", &state, &HashMap::new()).unwrap();
        assert_eq!(result.get("count"), Some(&SdkValue::Int(4)));

        // count == 0: take else branch → increment
        let mut state2 = HashMap::new();
        state2.insert("count".to_string(), SdkValue::Int(0));
        let result2 = compute_new_state(&anf, "test", &state2, &HashMap::new()).unwrap();
        assert_eq!(result2.get("count"), Some(&SdkValue::Int(1)));
    }

    #[test]
    fn test_hash_functions() {
        // sha256 of empty input
        let result = hash_fn_sha256("");
        assert!(matches!(result, Val::Bytes(ref s) if s.len() == 64));

        // hash256 of empty input
        let result = hash_fn_hash256("");
        assert!(matches!(result, Val::Bytes(ref s) if s.len() == 64));

        // hash160 of empty input
        let result = hash_fn_hash160("");
        assert!(matches!(result, Val::Bytes(ref s) if s.len() == 40));

        // ripemd160 of empty input
        let result = hash_fn_ripemd160("");
        assert!(matches!(result, Val::Bytes(ref s) if s.len() == 40));
    }

    #[test]
    fn test_num2bin_bin2num_roundtrip() {
        assert_eq!(num2bin_hex(42, 4), "2a000000");
        assert_eq!(bin2num_i64("2a000000"), 42);

        assert_eq!(num2bin_hex(-1, 1), "81");
        assert_eq!(bin2num_i64("81"), -1);

        assert_eq!(num2bin_hex(0, 4), "00000000");
        assert_eq!(bin2num_i64("00000000"), 0);
    }

    #[test]
    fn test_skips_implicit_params() {
        let anf = ANFProgram {
            contract_name: "Test".to_string(),
            properties: vec![ANFProperty {
                name: "count".to_string(),
                prop_type: "bigint".to_string(),
                readonly: false,
                initial_value: None,
            }],
            methods: vec![ANFMethod {
                name: "add".to_string(),
                params: vec![
                    ANFParam { name: "amount".to_string(), param_type: "bigint".to_string() },
                    ANFParam { name: "_changePKH".to_string(), param_type: "Ripemd160".to_string() },
                    ANFParam { name: "_changeAmount".to_string(), param_type: "bigint".to_string() },
                    ANFParam { name: "txPreimage".to_string(), param_type: "SigHashPreimage".to_string() },
                ],
                is_public: true,
                body: vec![
                    ANFBinding {
                        name: "_t0".to_string(),
                        value: serde_json::json!({ "kind": "load_prop", "name": "count" }),
                    },
                    ANFBinding {
                        name: "_t1".to_string(),
                        value: serde_json::json!({ "kind": "load_param", "name": "amount" }),
                    },
                    ANFBinding {
                        name: "_t2".to_string(),
                        value: serde_json::json!({
                            "kind": "bin_op", "op": "+",
                            "left": "_t0", "right": "_t1",
                        }),
                    },
                    ANFBinding {
                        name: "_t3".to_string(),
                        value: serde_json::json!({
                            "kind": "update_prop", "name": "count", "value": "_t2",
                        }),
                    },
                ],
            }],
        };

        let mut state = HashMap::new();
        state.insert("count".to_string(), SdkValue::Int(10));
        let mut args = HashMap::new();
        args.insert("amount".to_string(), SdkValue::Int(5));

        let result = compute_new_state(&anf, "add", &state, &args).unwrap();
        assert_eq!(result.get("count"), Some(&SdkValue::Int(15)));
    }

    #[test]
    fn test_deserialize_anf_program() {
        let json = r#"{
            "contractName": "Counter",
            "properties": [
                { "name": "count", "type": "bigint", "readonly": false }
            ],
            "methods": [
                {
                    "name": "increment",
                    "params": [],
                    "isPublic": true,
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_prop", "name": "count" } }
                    ]
                }
            ]
        }"#;
        let anf: ANFProgram = serde_json::from_str(json).unwrap();
        assert_eq!(anf.contract_name, "Counter");
        assert_eq!(anf.properties.len(), 1);
        assert_eq!(anf.methods.len(), 1);
        assert_eq!(anf.methods[0].body.len(), 1);
    }
}
