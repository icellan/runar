//! ANF IR loader — reads and validates ANF IR from JSON.

use std::fs;
use std::path::Path;

use super::{ANFBinding, ANFProgram, ANFValue};

/// Load an ANF IR program from a JSON file on disk.
pub fn load_ir(path: &Path) -> Result<ANFProgram, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("reading IR file: {}", e))?;
    load_ir_from_str(&data)
}

/// Load an ANF IR program from a JSON string.
pub fn load_ir_from_str(json_str: &str) -> Result<ANFProgram, String> {
    let program: ANFProgram = serde_json::from_str(json_str)
        .map_err(|e| format!("invalid IR JSON: {}", e))?;
    validate_ir(&program)?;
    Ok(program)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Known ANF value kinds.
const KNOWN_KINDS: &[&str] = &[
    "load_param",
    "load_prop",
    "load_const",
    "bin_op",
    "unary_op",
    "call",
    "method_call",
    "if",
    "loop",
    "assert",
    "update_prop",
    "get_state_script",
    "check_preimage",
    "deserialize_state",
    "add_output",
    "add_raw_output",
];

fn kind_name(value: &ANFValue) -> &'static str {
    match value {
        ANFValue::LoadParam { .. } => "load_param",
        ANFValue::LoadProp { .. } => "load_prop",
        ANFValue::LoadConst { .. } => "load_const",
        ANFValue::BinOp { .. } => "bin_op",
        ANFValue::UnaryOp { .. } => "unary_op",
        ANFValue::Call { .. } => "call",
        ANFValue::MethodCall { .. } => "method_call",
        ANFValue::If { .. } => "if",
        ANFValue::Loop { .. } => "loop",
        ANFValue::Assert { .. } => "assert",
        ANFValue::UpdateProp { .. } => "update_prop",
        ANFValue::GetStateScript { .. } => "get_state_script",
        ANFValue::CheckPreimage { .. } => "check_preimage",
        ANFValue::DeserializeState { .. } => "deserialize_state",
        ANFValue::AddOutput { .. } => "add_output",
        ANFValue::AddRawOutput { .. } => "add_raw_output",
    }
}

fn validate_ir(program: &ANFProgram) -> Result<(), String> {
    if program.contract_name.is_empty() {
        return Err("IR validation: contractName is required".into());
    }

    for (i, prop) in program.properties.iter().enumerate() {
        if prop.name.is_empty() {
            return Err(format!("IR validation: property[{}] has empty name", i));
        }
        if prop.prop_type.is_empty() {
            return Err(format!(
                "IR validation: property {} has empty type",
                prop.name
            ));
        }
    }

    for (i, method) in program.methods.iter().enumerate() {
        if method.name.is_empty() {
            return Err(format!("IR validation: method[{}] has empty name", i));
        }
        for (j, param) in method.params.iter().enumerate() {
            if param.name.is_empty() {
                return Err(format!(
                    "IR validation: method {} param[{}] has empty name",
                    method.name, j
                ));
            }
            if param.param_type.is_empty() {
                return Err(format!(
                    "IR validation: method {} param {} has empty type",
                    method.name, param.name
                ));
            }
        }
        validate_bindings(&method.body, &method.name)?;
    }

    Ok(())
}

fn validate_bindings(bindings: &[ANFBinding], method_name: &str) -> Result<(), String> {
    for (i, binding) in bindings.iter().enumerate() {
        if binding.name.is_empty() {
            return Err(format!(
                "IR validation: method {} binding[{}] has empty name",
                method_name, i
            ));
        }

        let kind = kind_name(&binding.value);
        if !KNOWN_KINDS.contains(&kind) {
            return Err(format!(
                "IR validation: method {} binding {} has unknown kind {:?}",
                method_name, binding.name, kind
            ));
        }

        // Validate nested bindings
        match &binding.value {
            ANFValue::If {
                then, else_branch, ..
            } => {
                validate_bindings(then, method_name)?;
                validate_bindings(else_branch, method_name)?;
            }
            ANFValue::Loop { body, .. } => {
                validate_bindings(body, method_name)?;
            }
            _ => {}
        }
    }
    Ok(())
}
