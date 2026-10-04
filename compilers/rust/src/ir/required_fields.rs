//! N-069 — presence and JSON type of the ANF IR's required fields.
//!
//! Checked on a generic `serde_json::Value` BEFORE the typed deserialize. serde
//! already refused most of these shapes, but with its own wording and a line /
//! column instead of the field (`missing field `body` at line 1 column 182`),
//! and it cannot tell which method or binding it was in. The required set is
//! `anf-ir.schema.json`'s `required` keys, minus the ones every loader defaults
//! for older payloads (loop start/step, add_output preimage).
//!
//! The diagnostics are shared verbatim with the other six tiers (Java's F-084
//! loader is the origin), pinned by
//! `conformance/negatives/ir-required-fields.test.ts`:
//!
//! ```text
//! IR validation: required field <path> is missing
//! IR validation: <path> must be <a type>, got <json type>
//! ```

use serde_json::{Map, Value};

type Obj = Map<String, Value>;
type R<T> = Result<T, String>;

fn json_type(v: Option<&Value>) -> &'static str {
    match v {
        None | Some(Value::Null) => "null",
        Some(Value::String(_)) => "string",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
        Some(Value::Number(_)) => "number",
    }
}

fn field_path(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{}.{}", path, key)
    }
}

fn malformed(path: &str, expected: &str, got: Option<&Value>) -> String {
    format!("IR validation: {} must be {}, got {}", path, expected, json_type(got))
}

/// Absence and a JSON null are both "missing".
fn req<'a>(obj: &'a Obj, key: &str, path: &str) -> R<&'a Value> {
    match obj.get(key) {
        None | Some(Value::Null) => Err(format!(
            "IR validation: required field {} is missing",
            field_path(path, key)
        )),
        Some(v) => Ok(v),
    }
}

fn req_str(obj: &Obj, path: &str, keys: &[&str]) -> R<()> {
    for key in keys {
        let v = req(obj, key, path)?;
        if !v.is_string() {
            return Err(malformed(&field_path(path, key), "a string", Some(v)));
        }
    }
    Ok(())
}

fn req_bool(obj: &Obj, key: &str, path: &str) -> R<()> {
    let v = req(obj, key, path)?;
    if !v.is_boolean() {
        return Err(malformed(&field_path(path, key), "a boolean", Some(v)));
    }
    Ok(())
}

fn req_list<'a>(obj: &'a Obj, key: &str, path: &str) -> R<&'a Vec<Value>> {
    let v = req(obj, key, path)?;
    v.as_array()
        .ok_or_else(|| malformed(&field_path(path, key), "an array", Some(v)))
}

fn as_obj<'a>(v: Option<&'a Value>, path: &str) -> R<&'a Obj> {
    match v {
        Some(Value::Object(o)) => Ok(o),
        other => Err(malformed(path, "an object", other)),
    }
}

fn req_str_list(obj: &Obj, key: &str, path: &str) -> R<()> {
    let lp = field_path(path, key);
    for (i, e) in req_list(obj, key, path)?.iter().enumerate() {
        if !e.is_string() {
            return Err(malformed(&format!("{}[{}]", lp, i), "a string", Some(e)));
        }
    }
    Ok(())
}

fn check_bindings(obj: &Obj, key: &str, path: &str) -> R<()> {
    let lp = field_path(path, key);
    for (i, b) in req_list(obj, key, path)?.iter().enumerate() {
        let bp = format!("{}[{}]", lp, i);
        let binding = as_obj(Some(b), &bp)?;
        req_str(binding, &bp, &["name"])?;
        let vp = format!("{}.value", bp);
        check_value(as_obj(binding.get("value"), &vp)?, &vp)?;
    }
    Ok(())
}

fn check_value(v: &Obj, path: &str) -> R<()> {
    req_str(v, path, &["kind"])?;
    match v.get("kind").and_then(Value::as_str).unwrap_or("") {
        "load_param" | "load_prop" => req_str(v, path, &["name"]),
        "bin_op" => req_str(v, path, &["op", "left", "right"]),
        "unary_op" => req_str(v, path, &["op", "operand"]),
        "call" => {
            req_str(v, path, &["func"])?;
            req_str_list(v, "args", path)
        }
        "method_call" => {
            req_str(v, path, &["object", "method"])?;
            req_str_list(v, "args", path)
        }
        "if" => {
            req_str(v, path, &["cond"])?;
            check_bindings(v, "then", path)?;
            check_bindings(v, "else", path)?;
            if v.contains_key("results") {
                req_str_list(v, "results", path)?;
            }
            Ok(())
        }
        "loop" => {
            check_bindings(v, "body", path)?;
            req_str(v, path, &["iterVar"])
        }
        "assert" => req_str(v, path, &["value"]),
        "update_prop" => req_str(v, path, &["name", "value"]),
        "check_preimage" | "deserialize_state" => req_str(v, path, &["preimage"]),
        "add_output" => {
            req_str(v, path, &["satoshis"])?;
            req_str_list(v, "stateValues", path)
        }
        "add_raw_output" | "add_data_output" => req_str(v, path, &["satoshis", "scriptBytes"]),
        "array_literal" => req_str_list(v, "elements", path),
        // load_const, get_state_script, raw_script: value-level rules check
        // their fields. Unknown kinds are refused by the typed deserialize.
        _ => Ok(()),
    }
}

/// F-038 / F-065: the two OPTIONAL keys the artifact copies into the fields
/// the SDK signs by. Absent (or null) is legal; a present value must be one the
/// source path can produce. Shared verbatim with the other six tiers.
const PARENT_CLASSES: [&str; 3] = ["SmartContract", "StatefulSmartContract", "UnsafeSmartContract"];
const SIGHASH_TYPES: [i64; 6] = [0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3];

fn opt_parent_class(obj: &Obj) -> R<()> {
    match obj.get("parentClass") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if PARENT_CLASSES.contains(&s.as_str()) => Ok(()),
        Some(Value::String(s)) => Err(format!(
            "IR validation: parentClass must be one of {}, got {}",
            PARENT_CLASSES.join(", "),
            s
        )),
        Some(v) => Err(malformed("parentClass", "a string", Some(v))),
    }
}

fn opt_sighash_type(obj: &Obj, path: &str) -> R<()> {
    let lp = field_path(path, "sigHashType");
    match obj.get("sigHashType") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Number(n)) => {
            if n.as_i64().map_or(false, |v| SIGHASH_TYPES.contains(&v)) {
                Ok(())
            } else {
                let list: Vec<String> = SIGHASH_TYPES.iter().map(|v| v.to_string()).collect();
                Err(format!("IR validation: {} must be one of {}, got {}", lp, list.join(", "), n))
            }
        }
        Some(v) => Err(malformed(&lp, "an integer", Some(v))),
    }
}

/// Return the first required field that is missing or of the wrong JSON type.
pub fn assert_required_ir_fields(json_str: &str) -> R<()> {
    // A syntax error is left to the typed parse, which reports it in the
    // shape the peer tiers already share.
    let root: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let program = as_obj(Some(&root), "the IR document")?;
    req_str(program, "", &["contractName"])?;
    opt_parent_class(program)?;
    for (i, p) in req_list(program, "properties", "")?.iter().enumerate() {
        let pp = format!("properties[{}]", i);
        let prop = as_obj(Some(p), &pp)?;
        req_str(prop, &pp, &["name", "type"])?;
        req_bool(prop, "readonly", &pp)?;
    }
    for (i, m) in req_list(program, "methods", "")?.iter().enumerate() {
        let mp = format!("methods[{}]", i);
        let method = as_obj(Some(m), &mp)?;
        req_str(method, &mp, &["name"])?;
        req_bool(method, "isPublic", &mp)?;
        opt_sighash_type(method, &mp)?;
        for (j, p) in req_list(method, "params", &mp)?.iter().enumerate() {
            let pp = format!("{}.params[{}]", mp, j);
            req_str(as_obj(Some(p), &pp)?, &pp, &["name", "type"])?;
        }
        check_bindings(method, "body", &mp)?;
    }
    Ok(())
}
