//! ANF IR types and loader.
//!
//! These types mirror the canonical Rúnar ANF IR JSON schema. Any conformant
//! Rúnar compiler produces byte-identical ANF IR (when serialised with canonical
//! JSON), so these types serve as the universal interchange format.

pub mod input_limits;
pub mod loader;
pub mod unknown_anf_kind_error;

pub use unknown_anf_kind_error::UnknownAnfKindError;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Source locations
// ---------------------------------------------------------------------------

/// Source location in the original file (used for debug source maps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

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
    /// Base class the source contract extends ("SmartContract" |
    /// "StatefulSmartContract" | "UnsafeSmartContract"). In-memory carrier
    /// ONLY (`#[serde(skip)]`) so it never appears in the emitted ANF IR JSON
    /// that the conformance suite compares cross-tier. The artifact assembler
    /// copies it to the top-level artifact field so SDKs can gate the
    /// issue-#42/#44 terminal sighash subscript trim on the authoritative
    /// parent class (a StatefulSmartContract with zero mutable fields still
    /// needs the trim even though state_fields is empty).
    #[serde(skip, default)]
    pub parent_class: String,
}

/// One level of a synthetic-array chain attached to expanded leaf
/// properties produced by the expand-fixed-arrays pass. Outermost
/// level first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ANFSyntheticArrayLevel {
    pub base: String,
    pub index: usize,
    pub length: usize,
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
    /// Non-empty for synthetic scalar leaves produced by the
    /// expand-fixed-arrays pass. Outermost level first. Used by the
    /// assembler to re-group these back into a single (possibly nested)
    /// FixedArray ABI/state entry.
    #[serde(rename = "__syntheticArrayChain", skip_serializing_if = "Option::is_none", default)]
    pub synthetic_array_chain: Option<Vec<ANFSyntheticArrayLevel>>,
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
    /// Debug-only: source location of the originating AST node. Not part of conformance.
    #[serde(rename = "sourceLoc", skip_serializing_if = "Option::is_none")]
    pub source_loc: Option<SourceLocation>,
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
    Assert {
        value: String,
        // Optional marker: set to `true` only on the auto-injected
        // `hash256(continuationOutputs) === extractOutputHash(txPreimage)`
        // assert emitted by the StatefulSmartContract lowering. Off-chain
        // SDK interpreters use this to skip the equality check without
        // resorting to positional or structural heuristics that misfire on
        // developer-written covenant asserts whose IR shape is identical.
        // Absent => developer code.
        #[serde(
            rename = "isAutoInjectedStateCheck",
            default,
            skip_serializing_if = "std::ops::Not::not"
        )]
        is_auto_injected_state_check: bool,
    },

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

    /// AddDataOutput — records an additional transaction output that is NOT a
    /// state continuation. The output is included in the auto-computed
    /// continuation hash in declaration order, after state outputs and before
    /// the change output. The emit shape is identical to `add_raw_output`:
    /// amount(8LE) + varint(scriptLen) + scriptBytes.
    #[serde(rename = "add_data_output")]
    AddDataOutput {
        satoshis: String,
        #[serde(rename = "scriptBytes")]
        script_bytes: String,
    },

    #[serde(rename = "array_literal")]
    ArrayLiteral {
        elements: Vec<String>,
    },

    /// RawScript — an opaque opcode-byte span emitted verbatim by the `asm`
    /// compiler intrinsic. `bytes` is an even-length hex string of raw Bitcoin
    /// Script opcode bytes; `in_arity` / `out_arity` declare the span's stack
    /// effect. The bytes are never inspected — the peephole optimizer treats
    /// the span as a hard barrier and constant folding never crosses it.
    #[serde(rename = "raw_script")]
    RawScript {
        bytes: String,
        #[serde(rename = "in_arity")]
        in_arity: usize,
        #[serde(rename = "out_arity")]
        out_arity: usize,
    },
}

// ---------------------------------------------------------------------------
// Constant value helpers
// ---------------------------------------------------------------------------

/// Typed constant value extracted from a `serde_json::Value`.
#[derive(Debug, Clone)]
pub enum ConstValue {
    Bool(bool),
    /// Arbitrary-precision integer constant.
    ///
    /// Widened from `i128` to `num_bigint::BigInt` so 256-bit constants
    /// (e.g. the secp256k1 group order in schnorr-zkp's s-bound assert)
    /// round-trip through the IR JSON ↔ stack-IR boundary without
    /// truncation. Mirrors Go's `ConstBigInt *big.Int` field on
    /// `ANFValue`.
    Int(num_bigint::BigInt),
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

/// Reports whether `s` is a JS-style decimal `BigInt` literal: an optional
/// leading `-`, one or more ASCII digits, and a required trailing `n`.
///
/// Mirrors:
///   - Go: `compilers/go/ir/types.go::isDecimalBigIntLiteral` — the
///     discriminator the Go IR decoder uses to distinguish a decimal
///     `BigInt` from a hex-encoded `ByteString` in `load_const` JSON
///     strings.
///   - Python: `_is_decimal_bigint_literal`
///   - TS: the conformance runner's BigInt canonicalisation
///
/// Without the `n` suffix the two cases are indistinguishable when the
/// literal is all-digit (e.g. `"3030"` is both a valid decimal integer
/// AND a valid hex bytestring).
pub fn is_decimal_bigint_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || *bytes.last().unwrap() != b'n' {
        return false;
    }
    let start = if bytes[0] == b'-' { 1 } else { 0 };
    let body = &bytes[start..bytes.len() - 1];
    if body.is_empty() {
        return false;
    }
    body.iter().all(|c| c.is_ascii_digit())
}

/// Parse a `serde_json::Value` into a `ConstValue`.
///
/// `load_const` values arrive in one of four shapes:
/// - `true` / `false`                       → `ConstValue::Bool`
/// - JSON number (any precision)            → `ConstValue::Int(BigInt)`
/// - JSON string with trailing `n` suffix   → `ConstValue::Int(BigInt)`
///   (JS-style decimal BigInt; cross-tier oversize-int encoding)
/// - JSON string otherwise                  → `ConstValue::Str` (hex bytes)
pub fn parse_const_value(v: &serde_json::Value) -> Option<ConstValue> {
    use num_bigint::BigInt;
    use std::str::FromStr;
    match v {
        serde_json::Value::Bool(b) => Some(ConstValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            // serde_json preserves integer JSON-number precision through
            // its string repr; parse via BigInt::from_str so 256-bit
            // values survive without truncation. JSON floats (e.g.
            // `1e20`) round-trip through a fractional string that
            // BigInt rejects; fall back to f64 → i128 in that case for
            // parity with the pre-widening behaviour.
            let s = n.to_string();
            if let Ok(bi) = BigInt::from_str(&s) {
                Some(ConstValue::Int(bi))
            } else if let Some(f) = n.as_f64() {
                Some(ConstValue::Int(BigInt::from(f as i128)))
            } else {
                None
            }
        }
        serde_json::Value::String(s) => {
            if is_decimal_bigint_literal(s) {
                // Strip the trailing 'n' and parse the digits as BigInt.
                let body = &s[..s.len() - 1];
                BigInt::from_str(body).ok().map(ConstValue::Int)
            } else {
                Some(ConstValue::Str(s.clone()))
            }
        }
        _ => None,
    }
}
