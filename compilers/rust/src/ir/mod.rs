//! ANF IR types and loader.
//!
//! These types mirror the canonical Rúnar ANF IR JSON schema. Any conformant
//! Rúnar compiler produces byte-identical ANF IR (when serialised with canonical
//! JSON), so these types serve as the universal interchange format.

pub mod loader;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Program structure
// ---------------------------------------------------------------------------

/// Top-level ANF IR container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFProgram {
    #[serde(rename = "contractName")]
    pub contract_name: String,
    pub properties: Vec<ANFProperty>,
    pub methods: Vec<ANFMethod>,
}

/// A contract-level property (constructor parameter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFProperty {
    pub name: String,
    #[serde(rename = "type")]
    pub prop_type: String,
    pub readonly: bool,
    #[serde(rename = "initialValue", skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<serde_json::Value>,
}

/// A single contract method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFMethod {
    pub name: String,
    pub params: Vec<ANFParam>,
    pub body: Vec<ANFBinding>,
    #[serde(rename = "isPublic")]
    pub is_public: bool,
}

/// A method parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/// A single let-binding: `let <name> = <value>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFBinding {
    pub name: String,
    pub value: ANFValue,
}

// ---------------------------------------------------------------------------
// ANF value types (discriminated on `kind`)
// ---------------------------------------------------------------------------

/// Discriminated union of all ANF value types.
///
/// Uses `#[serde(tag = "kind")]` to match the JSON `"kind"` discriminator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum ANFValue {
    #[serde(rename = "load_param")]
    LoadParam { name: String },

    #[serde(rename = "load_prop")]
    LoadProp { name: String },

    #[serde(rename = "load_const")]
    LoadConst { value: serde_json::Value },

    #[serde(rename = "bin_op")]
    BinOp {
        op: String,
        left: String,
        right: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_type: Option<String>,
    },

    #[serde(rename = "unary_op")]
    UnaryOp {
        op: String,
        operand: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_type: Option<String>,
    },

    #[serde(rename = "call")]
    Call {
        func: String,
        args: Vec<String>,
    },

    #[serde(rename = "method_call")]
    MethodCall {
        object: String,
        method: String,
        args: Vec<String>,
    },

    #[serde(rename = "if")]
    If {
        cond: String,
        then: Vec<ANFBinding>,
        #[serde(rename = "else")]
        else_branch: Vec<ANFBinding>,
    },

    #[serde(rename = "loop")]
    Loop {
        count: usize,
        body: Vec<ANFBinding>,
        #[serde(rename = "iterVar")]
        iter_var: String,
    },

    #[serde(rename = "assert")]
    Assert { value: String },

    #[serde(rename = "update_prop")]
    UpdateProp { name: String, value: String },

    #[serde(rename = "get_state_script")]
    GetStateScript {},

    #[serde(rename = "check_preimage")]
    CheckPreimage { preimage: String },

    #[serde(rename = "deserialize_state")]
    DeserializeState { preimage: String },

    #[serde(rename = "add_output")]
    AddOutput {
        satoshis: String,
        #[serde(rename = "stateValues")]
        state_values: Vec<String>,
        #[serde(default)]
        preimage: String,
    },

    #[serde(rename = "add_raw_output")]
    AddRawOutput {
        satoshis: String,
        #[serde(rename = "scriptBytes")]
        script_bytes: String,
    },

    #[serde(rename = "array_literal")]
    ArrayLiteral {
        elements: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Constant value helpers
// ---------------------------------------------------------------------------

/// Typed constant value extracted from a `serde_json::Value`.
#[derive(Debug, Clone)]
pub enum ConstValue {
    Bool(bool),
    Int(i128),
    Str(String),
}

impl ANFValue {
    /// Extract the typed constant from a `LoadConst` value.
    pub fn const_value(&self) -> Option<ConstValue> {
        match self {
            ANFValue::LoadConst { value } => parse_const_value(value),
            _ => None,
        }
    }
}

/// Parse a `serde_json::Value` into a `ConstValue`.
pub fn parse_const_value(v: &serde_json::Value) -> Option<ConstValue> {
    match v {
        serde_json::Value::Bool(b) => Some(ConstValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            // Try i64 first (covers most values), then fall back to f64 for larger numbers
            if let Some(i) = n.as_i64() {
                Some(ConstValue::Int(i as i128))
            } else if let Some(f) = n.as_f64() {
                Some(ConstValue::Int(f as i128))
            } else {
                None
            }
        }
        serde_json::Value::String(s) => Some(ConstValue::Str(s.clone())),
        _ => None,
    }
}
