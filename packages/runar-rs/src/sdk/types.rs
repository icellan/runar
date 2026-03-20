//! Core types for the Rúnar deployment SDK.

use serde::Deserialize;
use std::collections::HashMap;
use super::anf_interpreter::ANFProgram;

// ---------------------------------------------------------------------------
// Transaction types
// ---------------------------------------------------------------------------

/// A parsed Bitcoin transaction (data shape for get_transaction return).
#[derive(Debug, Clone)]
pub struct TransactionData {
    pub txid: String,
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
    pub raw: Option<String>,
}

/// Backward compatibility alias.
pub type Transaction = TransactionData;

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
    /// Terminal outputs for methods that verify exact output structure via
    /// extractOutputHash(). When set, the transaction is built with ONLY
    /// the contract UTXO as input (no funding inputs, no change output).
    /// The fee comes from the contract balance. The contract is considered
    /// fully spent after this call (currentUtxo becomes None).
    pub terminal_outputs: Option<Vec<TerminalOutput>>,
}

/// Specification for an exact output in a terminal method call.
#[derive(Debug, Clone)]
pub struct TerminalOutput {
    pub script_hex: String,
    pub satoshis: i64,
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
    #[serde(default, rename = "codeSeparatorIndex")]
    pub code_separator_index: Option<usize>,
    #[serde(default, rename = "codeSeparatorIndices")]
    pub code_separator_indices: Option<Vec<usize>>,
    #[serde(default)]
    pub anf: Option<ANFProgram>,
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
    #[serde(default)]
    pub is_terminal: Option<bool>,
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
#[serde(rename_all = "camelCase")]
pub struct StateField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub index: usize,
    /// Compile-time default value for properties with initializers.
    /// When artifacts are loaded via plain JSON.parse (without a BigInt
    /// reviver), BigInt values appear as strings with an "n" suffix
    /// (e.g. `"0n"`, `"1000n"`).
    #[serde(default)]
    pub initial_value: Option<serde_json::Value>,
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
    /// An arbitrary-precision integer for values that exceed i64 range.
    BigInt(num_bigint::BigInt),
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
    /// Convert to i64. Works for Int and BigInt (if within range).
    /// Panics if the value is not numeric or exceeds i64 range.
    pub fn as_int(&self) -> i64 {
        match self {
            SdkValue::Int(n) => *n,
            SdkValue::BigInt(n) => {
                use num_bigint::ToBigInt;
                let min = i64::MIN.to_bigint().unwrap();
                let max = i64::MAX.to_bigint().unwrap();
                if *n >= min && *n <= max {
                    // Safe to convert: value fits in i64
                    n.to_string().parse::<i64>().unwrap()
                } else {
                    panic!("SdkValue::as_int: BigInt value {} exceeds i64 range", n)
                }
            }
            _ => panic!("SdkValue::as_int called on non-numeric variant"),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Utxo
    // -----------------------------------------------------------------------

    #[test]
    fn utxo_creation_and_field_access() {
        let utxo = Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: "76a914".to_string(),
        };
        assert_eq!(utxo.txid, "aa".repeat(32));
        assert_eq!(utxo.output_index, 0);
        assert_eq!(utxo.satoshis, 100_000);
        assert_eq!(utxo.script, "76a914");
    }

    #[test]
    fn utxo_clone() {
        let utxo = Utxo {
            txid: "bb".repeat(32),
            output_index: 1,
            satoshis: 50_000,
            script: "51".to_string(),
        };
        let cloned = utxo.clone();
        assert_eq!(cloned.txid, utxo.txid);
        assert_eq!(cloned.output_index, utxo.output_index);
        assert_eq!(cloned.satoshis, utxo.satoshis);
        assert_eq!(cloned.script, utxo.script);
    }

    // -----------------------------------------------------------------------
    // TransactionData
    // -----------------------------------------------------------------------

    #[test]
    fn transaction_data_construction_defaults() {
        let tx = TransactionData {
            txid: "cc".repeat(32),
            version: 1,
            inputs: vec![],
            outputs: vec![],
            locktime: 0,
            raw: None,
        };
        assert_eq!(tx.txid, "cc".repeat(32));
        assert_eq!(tx.version, 1);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
        assert_eq!(tx.locktime, 0);
        assert!(tx.raw.is_none());
    }

    #[test]
    fn transaction_data_with_inputs_and_outputs() {
        let tx = TransactionData {
            txid: "dd".repeat(32),
            version: 1,
            inputs: vec![TxInput {
                txid: "ee".repeat(32),
                output_index: 0,
                script: "00".to_string(),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput {
                satoshis: 75_000,
                script: "76a914".to_string(),
            }],
            locktime: 500_000,
            raw: Some("0100000001...".to_string()),
        };
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].sequence, 0xffffffff);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].satoshis, 75_000);
        assert_eq!(tx.locktime, 500_000);
        assert!(tx.raw.is_some());
    }

    // -----------------------------------------------------------------------
    // RunarArtifact deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn runar_artifact_deserialize_minimal() {
        let json = r#"{
            "version": "0.1.0",
            "contractName": "TestContract",
            "abi": {
                "constructor": { "params": [] },
                "methods": []
            },
            "script": "5151"
        }"#;
        let artifact: RunarArtifact = serde_json::from_str(json).unwrap();
        assert_eq!(artifact.version, "0.1.0");
        assert_eq!(artifact.contract_name, "TestContract");
        assert_eq!(artifact.script, "5151");
        assert!(artifact.abi.constructor.params.is_empty());
        assert!(artifact.abi.methods.is_empty());
        assert!(artifact.state_fields.is_none());
        assert!(artifact.constructor_slots.is_none());
        assert!(artifact.code_separator_index.is_none());
    }

    #[test]
    fn runar_artifact_deserialize_with_methods() {
        let json = r#"{
            "version": "0.1.0",
            "contractName": "Counter",
            "abi": {
                "constructor": {
                    "params": [{ "name": "count", "type": "bigint" }]
                },
                "methods": [{
                    "name": "increment",
                    "params": [],
                    "isPublic": true
                }]
            },
            "script": "00ab"
        }"#;
        let artifact: RunarArtifact = serde_json::from_str(json).unwrap();
        assert_eq!(artifact.abi.constructor.params.len(), 1);
        assert_eq!(artifact.abi.constructor.params[0].name, "count");
        assert_eq!(artifact.abi.constructor.params[0].param_type, "bigint");
        assert_eq!(artifact.abi.methods.len(), 1);
        assert_eq!(artifact.abi.methods[0].name, "increment");
        assert!(artifact.abi.methods[0].is_public);
    }

    #[test]
    fn runar_artifact_deserialize_with_state_fields_and_slots() {
        let json = r#"{
            "version": "0.1.0",
            "contractName": "Stateful",
            "abi": {
                "constructor": { "params": [{ "name": "x", "type": "bigint" }] },
                "methods": [{ "name": "update", "params": [], "isPublic": true }]
            },
            "script": "aabb",
            "stateFields": [{ "name": "x", "type": "bigint", "index": 0 }],
            "constructorSlots": [{ "paramIndex": 0, "byteOffset": 5 }],
            "codeSeparatorIndex": 10,
            "codeSeparatorIndices": [10, 20]
        }"#;
        let artifact: RunarArtifact = serde_json::from_str(json).unwrap();
        let sf = artifact.state_fields.as_ref().unwrap();
        assert_eq!(sf.len(), 1);
        assert_eq!(sf[0].name, "x");
        assert_eq!(sf[0].index, 0);
        let cs = artifact.constructor_slots.as_ref().unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].param_index, 0);
        assert_eq!(cs[0].byte_offset, 5);
        assert_eq!(artifact.code_separator_index, Some(10));
        assert_eq!(artifact.code_separator_indices, Some(vec![10, 20]));
    }

    // -----------------------------------------------------------------------
    // SdkValue
    // -----------------------------------------------------------------------

    #[test]
    fn sdk_value_int() {
        let v = SdkValue::Int(42);
        assert_eq!(v.as_int(), 42);
    }

    #[test]
    fn sdk_value_bool() {
        let v = SdkValue::Bool(true);
        assert!(v.as_bool());
    }

    #[test]
    fn sdk_value_bytes() {
        let v = SdkValue::Bytes("deadbeef".to_string());
        assert_eq!(v.as_bytes(), "deadbeef");
    }

    #[test]
    fn sdk_value_auto() {
        let v = SdkValue::Auto;
        assert_eq!(v, SdkValue::Auto);
    }

    #[test]
    #[should_panic(expected = "non-numeric")]
    fn sdk_value_as_int_panics_on_bool() {
        SdkValue::Bool(true).as_int();
    }

    #[test]
    #[should_panic(expected = "non-Bool")]
    fn sdk_value_as_bool_panics_on_int() {
        SdkValue::Int(1).as_bool();
    }

    #[test]
    #[should_panic(expected = "non-Bytes")]
    fn sdk_value_as_bytes_panics_on_int() {
        SdkValue::Int(1).as_bytes();
    }

    #[test]
    fn sdk_value_equality() {
        assert_eq!(SdkValue::Int(5), SdkValue::Int(5));
        assert_ne!(SdkValue::Int(5), SdkValue::Int(6));
        assert_ne!(SdkValue::Int(1), SdkValue::Bool(true));
    }

    // -----------------------------------------------------------------------
    // DeployOptions / CallOptions
    // -----------------------------------------------------------------------

    #[test]
    fn deploy_options_construction() {
        let opts = DeployOptions {
            satoshis: 1000,
            change_address: Some("maddr".to_string()),
        };
        assert_eq!(opts.satoshis, 1000);
        assert_eq!(opts.change_address.as_deref(), Some("maddr"));
    }

    #[test]
    fn call_options_default() {
        let opts = CallOptions::default();
        assert!(opts.satoshis.is_none());
        assert!(opts.change_address.is_none());
        assert!(opts.new_state.is_none());
        assert!(opts.outputs.is_none());
        assert!(opts.terminal_outputs.is_none());
    }
}

// ---------------------------------------------------------------------------
// PreparedCall — result of prepare_call()
// ---------------------------------------------------------------------------

/// Result of `prepare_call()` — contains everything needed for external signing
/// and subsequent `finalize_call()`.
///
/// Public fields (`sighash`, `preimage`, `op_push_tx_sig`, `tx_hex`, `sig_indices`)
/// are for external signer coordination. Other fields are opaque
/// internals consumed by `finalize_call()`.
#[derive(Debug, Clone)]
pub struct PreparedCall {
    /// BIP-143 sighash (hex) — what external signers ECDSA-sign.
    pub sighash: String,
    /// Full BIP-143 preimage (hex).
    pub preimage: String,
    /// OP_PUSH_TX DER signature + sighash byte (hex). Empty if not needed.
    pub op_push_tx_sig: String,
    /// Built transaction hex (P2PKH funding signed, primary contract input uses placeholder sigs).
    pub tx_hex: String,
    /// User-visible arg positions that need external Sig values.
    pub sig_indices: Vec<usize>,

    // Internal fields — consumed by finalize_call()
    pub(crate) method_name: String,
    pub(crate) resolved_args: Vec<SdkValue>,
    pub(crate) method_selector_hex: String,
    pub(crate) is_stateful: bool,
    pub(crate) is_terminal: bool,
    pub(crate) needs_op_push_tx: bool,
    pub(crate) method_needs_change: bool,
    pub(crate) change_pkh_hex: String,
    pub(crate) change_amount: i64,
    pub(crate) method_needs_new_amount: bool,
    pub(crate) new_amount: i64,
    pub(crate) preimage_index: Option<usize>,
    pub(crate) contract_utxo: Utxo,
    pub(crate) new_locking_script: String,
    pub(crate) new_satoshis: i64,
    pub(crate) has_multi_output: bool,
    pub(crate) contract_outputs: Vec<ContractOutputEntry>,
    pub(crate) code_sep_idx: i64,
}

/// A contract output entry stored in PreparedCall (script + satoshis).
#[derive(Debug, Clone)]
pub struct ContractOutputEntry {
    pub script: String,
    pub satoshis: i64,
}
