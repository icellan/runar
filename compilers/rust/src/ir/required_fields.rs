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

/// N-059 / F-102 (F-068 in Go): a `check_preimage` binding's optional
/// `sighashFlag`, at every nesting depth. Codegen appends `sighashFlag & 0xff`
/// to the OP_PUSH_TX binding, so an out-of-set value was truncated to a byte no
/// BSV spend can satisfy (999999 -> 0x3F, FORKID clear) and an explicit 0
/// emitted a 0x00 byte. Absent (or null) means the default ALL|FORKID. In a
/// public method the flag must also equal the method's `sigHashType` (default
/// 0x41): the artifact tells the SDK to sign under `sigHashType`, the script
/// derives its sighash under the flag, and a divergence is unspendable. Both
/// diagnostics are shared verbatim with the other six tiers.
const SIGHASH_DEFAULT: i64 = 0x41;

fn check_sighash_flags(
    obj: &Obj,
    key: &str,
    path: &str,
    method: &str,
    is_public: bool,
    declared: i64,
) -> R<()> {
    let lp = field_path(path, key);
    let list = match obj.get(key).and_then(Value::as_array) {
        Some(l) => l,
        None => return Ok(()),
    };
    for (i, b) in list.iter().enumerate() {
        let vp = format!("{}[{}].value", lp, i);
        let binding = match b.as_object() {
            Some(o) => o,
            None => continue,
        };
        let v = match binding.get("value").and_then(Value::as_object) {
            Some(o) => o,
            None => continue,
        };
        let name = binding.get("name").and_then(Value::as_str).unwrap_or("");
        match v.get("kind").and_then(Value::as_str).unwrap_or("") {
            "if" => {
                check_sighash_flags(v, "then", &vp, method, is_public, declared)?;
                check_sighash_flags(v, "else", &vp, method, is_public, declared)?;
            }
            "loop" => check_sighash_flags(v, "body", &vp, method, is_public, declared)?,
            "check_preimage" => {
                let mut flag = SIGHASH_DEFAULT;
                match v.get("sighashFlag") {
                    None | Some(Value::Null) => {}
                    Some(Value::Number(n)) => match n.as_i64().filter(|f| SIGHASH_TYPES.contains(f)) {
                        Some(f) => flag = f,
                        None => {
                            return Err(format!(
                                "IR validation: method {} binding {} check_preimage has sighashFlag {}; sighashFlag must be one of {{0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3}} (ALL/NONE/SINGLE with FORKID, optionally ANYONECANPAY). Any other value is truncated to a sighash byte no BSV spend can satisfy.",
                                method, name, n
                            ))
                        }
                    },
                    Some(other) => {
                        return Err(malformed(&field_path(&vp, "sighashFlag"), "an integer", Some(other)))
                    }
                }
                if is_public && flag != declared {
                    return Err(format!(
                        "IR validation: method {} binding {} check_preimage has sighashFlag {} but the method declares sigHashType {}; a public method's check_preimage must bind the sighash type its ABI declares, or the SDK signs a preimage the script rejects.",
                        method, name, flag, declared
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
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
        let declared = method.get("sigHashType").and_then(Value::as_i64).unwrap_or(SIGHASH_DEFAULT);
        let name = method.get("name").and_then(Value::as_str).unwrap_or("");
        let is_public = method.get("isPublic").and_then(Value::as_bool).unwrap_or(false);
        check_sighash_flags(method, "body", &mp, name, is_public, declared)?;
    }
    assert_ir_identifiers(program)?;
    assert_no_output_helper_calls(program)
}

/// N-207: the declared identifiers are non-empty, and a method's parameter
/// names are distinct. Runs after the type walk above, so every field read
/// here is a string. `""` is a string, so N-069 alone let an empty name
/// through; and duplicate param names alias ONE stack slot (every
/// `load_param` resolves to the last declared one, so `assert(p0 === p1)` over
/// two params of the same name compiled to an always-true script). Shared
/// verbatim with the other six tiers, pinned by
/// `conformance/negatives/ir-identifiers.test.ts`:
///
/// ```text
/// IR validation: <path> must be a non-empty string
/// IR validation: <path>.name '<name>' duplicates <earlier path>.name
/// ```
fn non_empty(obj: &Obj, path: &str, keys: &[&str]) -> R<()> {
    for key in keys {
        if obj.get(*key).and_then(Value::as_str) == Some("") {
            return Err(format!(
                "IR validation: {} must be a non-empty string",
                field_path(path, key)
            ));
        }
    }
    Ok(())
}

/// N-408: a binding's name is non-empty at every nesting level (a method
/// body, an `if` arm, a `loop` body), named by the path `check_bindings`
/// walks: `methods[0].body[1].value.then[0].name`.
fn non_empty_binding_names(obj: &Obj, key: &str, path: &str) -> R<()> {
    let lp = field_path(path, key);
    let bindings = obj.get(key).and_then(Value::as_array).cloned().unwrap_or_default();
    for (i, b) in bindings.iter().enumerate() {
        let Some(binding) = b.as_object() else { continue };
        let bp = format!("{}[{}]", lp, i);
        non_empty(binding, &bp, &["name"])?;
        let Some(value) = binding.get("value").and_then(Value::as_object) else { continue };
        let vp = format!("{}.value", bp);
        non_empty(value, &vp, &["kind"])?;
        match value.get("kind").and_then(Value::as_str).unwrap_or("") {
            "if" => {
                non_empty_binding_names(value, "then", &vp)?;
                non_empty_binding_names(value, "else", &vp)?;
            }
            "loop" => non_empty_binding_names(value, "body", &vp)?,
            _ => {}
        }
    }
    Ok(())
}

fn assert_ir_identifiers(program: &Obj) -> R<()> {
    let list = |obj: &Obj, key: &str| -> Vec<Obj> {
        obj.get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_object().cloned()).collect())
            .unwrap_or_default()
    };
    non_empty(program, "", &["contractName"])?;
    for (i, prop) in list(program, "properties").iter().enumerate() {
        non_empty(prop, &format!("properties[{}]", i), &["name", "type"])?;
    }
    for (i, method) in list(program, "methods").iter().enumerate() {
        let mp = format!("methods[{}]", i);
        non_empty(method, &mp, &["name"])?;
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (j, param) in list(method, "params").iter().enumerate() {
            let pp = format!("{}.params[{}]", mp, j);
            non_empty(param, &pp, &["name", "type"])?;
            let name = param.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            if let Some(first) = seen.get(&name) {
                return Err(format!(
                    "IR validation: {}.name '{}' duplicates {}.params[{}].name",
                    pp, name, mp, first
                ));
            }
            seen.insert(name, j);
        }
        non_empty_binding_names(method, "body", &mp)?;
    }
    Ok(())
}

/// N-094: a `method_call` to a PRIVATE method that emits outputs is refused at
/// load time. The frontends always inline an output-emitting private helper,
/// so such a call only arrives through hand-written `--ir`; stack lowering
/// cannot resolve the helper's `add_output` outside its caller's frame and used
/// to fail deep inside ("value '_codePart' not found on stack"). Shared
/// verbatim with the other six tiers, pinned by
/// `conformance/negatives/n094-ir-output-helper-call-parity.test.ts`:
///
/// ```text
/// IR validation: private method '<m>' emits outputs and must be inlined; --ir method_call to it is not supported
/// ```
fn value_of(binding: &Value) -> Option<&Obj> {
    binding.get("value").and_then(Value::as_object)
}

fn arm<'a>(v: &'a Obj, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn emits_outputs(bindings: &[Value]) -> bool {
    bindings.iter().filter_map(value_of).any(|v| {
        match v.get("kind").and_then(Value::as_str).unwrap_or("") {
            "add_output" | "add_raw_output" | "add_data_output" => true,
            "if" => emits_outputs(arm(v, "then")) || emits_outputs(arm(v, "else")),
            "loop" => emits_outputs(arm(v, "body")),
            _ => false,
        }
    })
}

fn refuse_output_helper_calls(bindings: &[Value], helpers: &[String]) -> R<()> {
    for v in bindings.iter().filter_map(value_of) {
        match v.get("kind").and_then(Value::as_str).unwrap_or("") {
            "method_call" => {
                let name = v.get("method").and_then(Value::as_str).unwrap_or("");
                if helpers.iter().any(|h| h == name) {
                    return Err(format!(
                        "IR validation: private method '{}' emits outputs and must be inlined; --ir method_call to it is not supported",
                        name
                    ));
                }
            }
            "if" => {
                refuse_output_helper_calls(arm(v, "then"), helpers)?;
                refuse_output_helper_calls(arm(v, "else"), helpers)?;
            }
            "loop" => refuse_output_helper_calls(arm(v, "body"), helpers)?,
            _ => {}
        }
    }
    Ok(())
}

fn assert_no_output_helper_calls(program: &Obj) -> R<()> {
    let methods = arm(program, "methods");
    let helpers: Vec<String> = methods
        .iter()
        .filter_map(Value::as_object)
        .filter(|m| m.get("isPublic").and_then(Value::as_bool) == Some(false))
        .filter(|m| emits_outputs(arm(m, "body")))
        .filter_map(|m| m.get("name").and_then(Value::as_str).map(String::from))
        .collect();
    if helpers.is_empty() {
        return Ok(());
    }
    for m in methods.iter().filter_map(Value::as_object) {
        refuse_output_helper_calls(arm(m, "body"), &helpers)?;
    }
    Ok(())
}
