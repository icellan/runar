//! Core types for the Rúnar deployment SDK.

use serde::Deserialize;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Transaction types
// ---------------------------------------------------------------------------

/// A parsed Bitcoin transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub txid: String,
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
    pub raw: Option<String>,
}

/// A transaction input.
#[derive(Debug, Clone)]
pub struct TxInput {
    pub txid: String,
    pub output_index: u32,
    pub script: String,
    pub sequence: u32,
}

/// A transaction output.
#[derive(Debug, Clone)]
pub struct TxOutput {
    pub satoshis: i64,
    pub script: String,
}

/// An unspent transaction output.
#[derive(Debug, Clone)]
pub struct Utxo {
    pub txid: String,
    pub output_index: u32,
    pub satoshis: i64,
    pub script: String,
}

// ---------------------------------------------------------------------------
// Option types
// ---------------------------------------------------------------------------

/// Options for deploying a contract.
#[derive(Debug, Clone)]
pub struct DeployOptions {
    pub satoshis: i64,
    pub change_address: Option<String>,
}

/// Options for calling a contract method.
#[derive(Debug, Clone, Default)]
pub struct CallOptions {
    /// Satoshis for the next output (stateful contracts).
    pub satoshis: Option<i64>,
    pub change_address: Option<String>,
    /// New state values for the continuation output (stateful contracts).
    pub new_state: Option<HashMap<String, SdkValue>>,
    /// Multiple continuation outputs for multi-output methods (e.g., transfer).
    /// When provided, replaces the single continuation output from `new_state`.
    pub outputs: Option<Vec<OutputSpec>>,
    /// Additional contract UTXOs as inputs (e.g., merge, swap).
    /// Each input is signed with the same method and args as the primary call,
    /// with OP_PUSH_TX and Sig auto-computed per input.
    pub additional_contract_inputs: Option<Vec<Utxo>>,
    /// Per-input args for additional contract inputs. When provided,
    /// `additional_contract_input_args[i]` overrides args for
    /// `additional_contract_inputs[i]`. Sig params (Auto) are still auto-computed.
    pub additional_contract_input_args: Option<Vec<Vec<SdkValue>>>,
    /// Override the public key used for the change output (hex-encoded).
    /// Defaults to the signer's public key.
    pub change_pub_key: Option<String>,
}

/// Specification for a single continuation output in multi-output calls.
#[derive(Debug, Clone)]
pub struct OutputSpec {
    pub satoshis: i64,
    pub state: HashMap<String, SdkValue>,
}

// ---------------------------------------------------------------------------
// Artifact types (deserialized from JSON)
// ---------------------------------------------------------------------------

/// A compiled Rúnar contract artifact.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunarArtifact {
    pub version: String,
    pub contract_name: String,
    pub abi: Abi,
    pub script: String,
    #[serde(default)]
    pub state_fields: Option<Vec<StateField>>,
    #[serde(default)]
    pub constructor_slots: Option<Vec<ConstructorSlot>>,
}

/// The ABI (Application Binary Interface) of a contract.
#[derive(Debug, Clone, Deserialize)]
pub struct Abi {
    pub constructor: AbiConstructor,
    pub methods: Vec<AbiMethod>,
}

/// The constructor portion of an ABI.
#[derive(Debug, Clone, Deserialize)]
pub struct AbiConstructor {
    pub params: Vec<AbiParam>,
}

/// A method in the ABI.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbiMethod {
    pub name: String,
    pub params: Vec<AbiParam>,
    pub is_public: bool,
}

/// A parameter in the ABI.
#[derive(Debug, Clone, Deserialize)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
}

/// A state field definition.
#[derive(Debug, Clone, Deserialize)]
pub struct StateField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub index: usize,
}

/// A constructor slot mapping parameter index to byte offset in the script.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConstructorSlot {
    pub param_index: usize,
    pub byte_offset: usize,
}

// ---------------------------------------------------------------------------
// SDK value type
// ---------------------------------------------------------------------------

/// A value that can be passed to or read from the SDK.
#[derive(Debug, Clone, PartialEq)]
pub enum SdkValue {
    /// An integer (maps to Bitcoin Script numbers).
    Int(i64),
    /// A boolean value.
    Bool(bool),
    /// Hex-encoded byte data.
    Bytes(String),
    /// Placeholder for auto-computed Sig or PubKey params.
    /// Pass this as an arg to `call()` for params of type `Sig` or `PubKey` —
    /// the SDK will compute the real value from the signer.
    Auto,
}

impl SdkValue {
    /// Convert to i64, panicking if not an Int variant.
    pub fn as_int(&self) -> i64 {
        match self {
            SdkValue::Int(n) => *n,
            _ => panic!("SdkValue::as_int called on non-Int variant"),
        }
    }

    /// Convert to bool, panicking if not a Bool variant.
    pub fn as_bool(&self) -> bool {
        match self {
            SdkValue::Bool(b) => *b,
            _ => panic!("SdkValue::as_bool called on non-Bool variant"),
        }
    }

    /// Convert to hex string, panicking if not a Bytes variant.
    pub fn as_bytes(&self) -> &str {
        match self {
            SdkValue::Bytes(s) => s,
            _ => panic!("SdkValue::as_bytes called on non-Bytes variant"),
        }
    }
}
