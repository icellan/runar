//! Lightweight ANF interpreter for auto-computing state transitions.
//!
//! Given a compiled artifact's ANF IR, the current contract state, and
//! method arguments, this interpreter walks the ANF bindings and computes
//! the new state.  It handles `update_prop` nodes to track state mutations,
//! while skipping on-chain-only operations like `check_preimage`,
//! `deserialize_state`, and `get_state_script`. It also resolves
//! `add_data_output` and `add_raw_output` bindings into the result envelope
//! so callers building the broadcast transaction off-chain can splice them
//! in at the correct index.
//!
//! This enables the SDK to auto-compute `newState` for stateful contract
//! calls, so callers don't need to duplicate contract logic.

use std::collections::HashMap;
use serde::Deserialize;
use sha2::{Sha256, Digest as Sha256Digest};
use ripemd::Ripemd160;
use k256::ecdsa::{Signature as K256Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
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
            // Array values must be flattened into scalar slots by the
            // caller before reaching the ANF interpreter. Treat any
            // leaked Array as Undefined so downstream code fails loudly.
            SdkValue::Array(_) => Val::Undefined,
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
            // BigInt sigil: "42n" → Int(42). Matches the TS reference's
            // BigIntLiteral serialisation.
            if let Some(stripped) = s.strip_suffix('n') {
                if let Ok(n) = stripped.parse::<i64>() {
                    return Val::Int(n);
                }
            }
            // Any other JSON string is a ByteString literal. (The
            // upstream compiler always emits integers as JSON numbers
            // and ByteString hex literals as JSON strings; an earlier
            // `s.parse::<i64>()` fallback here mis-parsed all-digit hex
            // literals like "3030" as integers, breaking conformance
            // fixtures whose hex payload happens to contain only
            // digits.)
            Val::Bytes(s.clone())
        }
        serde_json::Value::Null => Val::Undefined,
        _ => Val::Undefined,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A data output resolved from `this.addDataOutput(...)` in the method body.
/// The SDK emits these between state outputs and the change output so the
/// tx's hashOutputs matches the compile-time continuation-hash constant.
#[derive(Debug, Clone)]
pub struct DataOutputEntry {
    pub satoshis: i64,
    pub script: String,
}

/// A raw output resolved from `this.addRawOutput(satoshis, scriptBytes)` in
/// the method body. `script` is the **caller-supplied** locking-script bytes
/// (hex-encoded), in contrast to `DataOutputEntry.script`, which is the hex
/// payload that becomes part of an `OP_RETURN` data output. The simulator
/// does not introspect these bytes — it surfaces them so a caller building
/// the broadcast transaction off-chain can splice them in at the correct
/// position. Entries appear in declaration order, after the state output
/// and after `data_outputs`.
#[derive(Debug, Clone)]
pub struct RawOutputEntry {
    pub satoshis: i64,
    pub script: String,
}

/// Returned by [`execute_strict`] when an `assert(...)` predicate evaluates
/// to a falsy value during strict-mode interpretation.
///
/// Carries the contract method name plus the ANF binding name (e.g. `t17`,
/// `t8`) so a developer can pinpoint the exact failing guard. The `Display`
/// impl renders the same string the TS / Go / Java / Zig SDKs produce so
/// cross-tier diffing on the wire is byte-stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionFailureError {
    pub method_name: String,
    pub binding_name: String,
}

impl std::fmt::Display for AssertionFailureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "assert failed in {}: binding '{}' evaluated to false",
            self.method_name, self.binding_name
        )
    }
}

impl std::error::Error for AssertionFailureError {}

/// Per-evaluation strict-mode handle. `None` (lenient) skips assert checks;
/// `Some` (strict) enforces them, returning [`AssertionFailureError`] on the
/// first falsy `assert(predicate)`.
///
/// When `real_crypto` is `Some`, the crypto built-ins (`checkSig`,
/// `checkMultiSig`, `checkPreimage`) verify against the supplied 32-byte
/// sighash instead of mock-returning `true`. Used by
/// [`execute_on_chain_authoritative`].
#[derive(Debug, Clone)]
pub(crate) struct StrictCtx {
    pub(crate) method_name: String,
    pub(crate) real_crypto: Option<OnChainCryptoContext>,
    /// When `Some`, intent-intrinsic witness bytes
    /// (`_prevOutScript_<i>` / `_serialisedOutputs`) and preimage-derived
    /// intrinsics (`extractLocktime`, `extractOutputHash`, etc.) consult
    /// this context instead of returning the bare zero-byte defaults.
    /// Used by [`execute_with_witness`] to port the TS
    /// AST-interpreter intent-intrinsic semantics into the Rust ANF
    /// interpreter.
    pub(crate) witness: Option<IntentWitnessContext>,
}

/// Per-method witness bytes + mock preimage fields consumed by the
/// intent-intrinsic ANF lowerings (`extractPrevOutputScript`,
/// `requireOutputP2PKH`, `currentBlockHeight`).
///
/// The TS reference interpreter exposes equivalent state via
/// `TestContract.setPrevOutScript`, `TestContract.setSerialisedOutputs`,
/// `TestContract.setMockPreimage`, and `TestContract.setMockPreimageBytes`.
/// This struct is the Rust-tier port of that channel — populate it before
/// calling [`execute_with_witness`].
#[derive(Debug, Clone, Default)]
pub struct IntentWitnessContext {
    /// Mock preimage integer fields (`locktime`, `amount`, `version`,
    /// `sequence`). Consulted by `extractLocktime` / `extractAmount` /
    /// `extractVersion` / `extractSequence` intrinsic calls.
    pub mock_preimage: HashMap<String, i64>,
    /// Mock preimage byte fields (`outputHash`, `hashPrevouts`,
    /// `hashSequence`, `outpoint`). Consulted by `extractOutputHash` /
    /// `extractOutputs` / `extractHashPrevouts` / `extractHashSequence` /
    /// `extractOutpoint`.
    pub mock_preimage_bytes: HashMap<String, Vec<u8>>,
    /// Witness bytes for the auto-injected `_prevOutScript_<input_index>`
    /// param (the desugar of `extractPrevOutputScript(inputIndex, ...)`).
    pub prev_out_scripts: HashMap<usize, Vec<u8>>,
    /// Witness bytes for the auto-injected `_serialisedOutputs` param
    /// (the desugar of `requireOutputP2PKH(...)`).
    pub serialised_outputs: Option<Vec<u8>>,
}

impl IntentWitnessContext {
    /// Construct a context pre-populated with the same defaults the TS
    /// reference uses (`locktime=0, amount=10000, version=1,
    /// sequence=0xfffffffe`).
    pub fn new() -> Self {
        let mut mock_preimage: HashMap<String, i64> = HashMap::new();
        mock_preimage.insert("locktime".to_string(), 0);
        mock_preimage.insert("amount".to_string(), 10000);
        mock_preimage.insert("version".to_string(), 1);
        mock_preimage.insert("sequence".to_string(), 0xfffffffei64);
        Self {
            mock_preimage,
            mock_preimage_bytes: HashMap::new(),
            prev_out_scripts: HashMap::new(),
            serialised_outputs: None,
        }
    }

    /// Set the previous-output-script witness bytes for `input_index`.
    /// Mirrors `TestContract.setPrevOutScript(inputIndex, bytes)` in the
    /// TS reference.
    pub fn set_prev_out_script(&mut self, input_index: usize, bytes: &[u8]) {
        self.prev_out_scripts.insert(input_index, bytes.to_vec());
    }

    /// Set the serialised-outputs witness bytes. Mirrors
    /// `TestContract.setSerialisedOutputs(bytes)` in the TS reference.
    pub fn set_serialised_outputs(&mut self, bytes: &[u8]) {
        self.serialised_outputs = Some(bytes.to_vec());
    }

    /// Set one preimage integer field (`locktime`, `amount`, `version`,
    /// `sequence`).
    pub fn set_mock_preimage_field(&mut self, key: &str, value: i64) {
        self.mock_preimage.insert(key.to_string(), value);
    }

    /// Set one preimage byte field (`outputHash`, `hashPrevouts`,
    /// `hashSequence`, `outpoint`).
    pub fn set_mock_preimage_bytes_field(&mut self, key: &str, value: &[u8]) {
        self.mock_preimage_bytes.insert(key.to_string(), value.to_vec());
    }
}

/// Failure mode for [`execute_with_witness`].
///
/// Carries either an `assert(...)` failure (with method + binding name) or a
/// missing-witness diagnostic produced when the contract's ANF references a
/// `_prevOutScript_<i>` / `_serialisedOutputs` synthetic param the caller
/// did not supply via [`IntentWitnessContext::set_prev_out_script`] /
/// [`IntentWitnessContext::set_serialised_outputs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentInterpreterError {
    Assertion(AssertionFailureError),
    MissingWitness(String),
    /// Driver-level error (method not found, etc.) — surfaced as a string
    /// to match the existing `compute_new_state` error shape.
    Driver(String),
}

impl std::fmt::Display for IntentInterpreterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentInterpreterError::Assertion(a) => write!(f, "{}", a),
            IntentInterpreterError::MissingWitness(m) => write!(f, "{}", m),
            IntentInterpreterError::Driver(d) => write!(f, "{}", d),
        }
    }
}

impl std::error::Error for IntentInterpreterError {}

/// Required cryptographic context for [`execute_on_chain_authoritative`].
///
/// `sighash` is the 32-byte BIP-143 sighash digest the on-chain VM would
/// verify signatures against (and that the caller would have signed with
/// `LocalSigner::sign(...)` before broadcasting). The interpreter:
///
///  - verifies `checkSig(sig, pk)` by parsing `pk` as a SEC1 secp256k1 point
///    (compressed 33 bytes or uncompressed 65 bytes), parsing `sig` as DER
///    (with optional trailing sighash type byte stripped), and running ECDSA
///    verification via `k256::ecdsa::VerifyingKey::verify_prehash`. Any
///    mismatch returns `false`, which then trips the enclosing `assert(...)`
///    and yields an [`AssertionFailureError`].
///  - verifies `checkMultiSig(sigs, pks)` by iterating signatures left-to-right
///    and consuming pubkeys greedily, mirroring Bitcoin's `OP_CHECKMULTISIG`.
///  - verifies `checkPreimage(preimage)` by computing
///    `SHA256(SHA256(preimage))` and comparing it to `sighash` byte-for-byte
///    — the on-chain `OP_PUSH_TX` semantic.
#[derive(Debug, Clone)]
pub struct OnChainCryptoContext {
    /// 32-byte BIP-143 sighash.
    pub sighash: [u8; 32],
}

impl OnChainCryptoContext {
    /// Construct a context from a hex-encoded 32-byte sighash. Returns
    /// `Err` if the hex is malformed or does not decode to exactly 32
    /// bytes.
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let bytes = hex_to_bytes_strict(hex)
            .ok_or_else(|| format!("OnChainCryptoContext::from_hex: invalid hex string"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "OnChainCryptoContext::from_hex: expected 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { sighash: arr })
    }
}

/// Compute the new state after executing a contract method.
///
/// Returns the updated state (merged with `current_state`).
///
/// `constructor_args` provides deploy-time values for readonly properties
/// that are not in `current_state` (which only contains mutable fields).
/// Without these, readonly fields used in method arithmetic evaluate to 0.
pub fn compute_new_state(
    anf: &ANFProgram,
    method_name: &str,
    current_state: &HashMap<String, SdkValue>,
    args: &HashMap<String, SdkValue>,
    constructor_args: &[SdkValue],
) -> Result<HashMap<String, SdkValue>, String> {
    compute_new_state_and_data_outputs(anf, method_name, current_state, args, constructor_args)
        .map(|(state, _, _)| state)
}

/// Compute the new state AND resolved data / raw outputs after executing a
/// contract method. See [`compute_new_state`] for state semantics; data
/// outputs come from `this.addDataOutput(...)` calls and raw outputs come
/// from `this.addRawOutput(...)` calls, both in declaration order.
pub fn compute_new_state_and_data_outputs(
    anf: &ANFProgram,
    method_name: &str,
    current_state: &HashMap<String, SdkValue>,
    args: &HashMap<String, SdkValue>,
    constructor_args: &[SdkValue],
) -> Result<(HashMap<String, SdkValue>, Vec<DataOutputEntry>, Vec<RawOutputEntry>), String> {
    // Lenient mode: any assert() in the body is skipped — the on-chain
    // script handles enforcement, and `run_method` cannot return an
    // AssertionFailureError when `strict = None`.
    match run_method(anf, method_name, current_state, args, constructor_args, None) {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(s)) => Err(s),
        // Unreachable: lenient mode never produces strict assertion failures.
        Err(af) => Err(format!("unexpected strict assertion in lenient mode: {}", af)),
    }
}

/// Strict-mode counterpart of [`compute_new_state_and_data_outputs`]: walks
/// the same ANF body but returns
/// `Err(AssertionFailureError)` on the first `assert(predicate)` whose
/// predicate is falsy. Crypto built-ins (`checkSig`, `checkMultiSig`,
/// `checkPreimage`) still mock-return `true`; only explicit `assert(...)`
/// predicates are enforced.
///
/// Non-assertion interpreter errors (e.g. `methodName` not present in the
/// ANF IR) panic in strict mode to keep the public signature the spec
/// requires (`Result<_, AssertionFailureError>`); driver-level validation
/// is expected to make those impossible. Real driver errors (missing IR,
/// malformed input) are surfaced by the conformance driver before this
/// function is ever called.
pub fn execute_strict(
    anf: &ANFProgram,
    method_name: &str,
    current_state: &HashMap<String, SdkValue>,
    args: &HashMap<String, SdkValue>,
    constructor_args: &[SdkValue],
) -> Result<(HashMap<String, SdkValue>, Vec<DataOutputEntry>, Vec<RawOutputEntry>), AssertionFailureError> {
    let strict = StrictCtx {
        method_name: method_name.to_string(),
        real_crypto: None,
        witness: None,
    };
    match run_method(
        anf,
        method_name,
        current_state,
        args,
        constructor_args,
        Some(&strict),
    ) {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(s)) => panic!("execute_strict: interpreter error: {}", s),
        Err(af) => Err(af),
    }
}

/// Like [`execute_strict`] but also performs real cryptographic verification
/// of `checkSig`, `checkMultiSig`, and `checkPreimage` against the supplied
/// `sighash`. Returns `Err(AssertionFailureError)` when any `assert(...)`
/// (including the implicit one wrapping a failed crypto built-in) fires.
///
/// The `ctx` parameter is mandatory and carries the sighash, so it is
/// impossible to call this entry point accidentally without supplying the
/// cryptographic inputs the verification needs.
///
/// Mirrors the TypeScript reference's `executeOnChainAuthoritative` and the
/// equivalent Java SDK `executeOnChainAuthoritative` / Zig SDK
/// `executeOnChainAuthoritative` entry points.
pub fn execute_on_chain_authoritative(
    anf: &ANFProgram,
    method_name: &str,
    current_state: &HashMap<String, SdkValue>,
    args: &HashMap<String, SdkValue>,
    constructor_args: &[SdkValue],
    ctx: &OnChainCryptoContext,
) -> Result<(HashMap<String, SdkValue>, Vec<DataOutputEntry>, Vec<RawOutputEntry>), AssertionFailureError> {
    let strict = StrictCtx {
        method_name: method_name.to_string(),
        real_crypto: Some(ctx.clone()),
        witness: None,
    };
    match run_method(
        anf,
        method_name,
        current_state,
        args,
        constructor_args,
        Some(&strict),
    ) {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(s)) => panic!("execute_on_chain_authoritative: interpreter error: {}", s),
        Err(af) => Err(af),
    }
}

/// Execute a contract method in strict mode with intent-intrinsic witness
/// support — the Rust-tier port of the TS reference's AST-interpreter
/// path for `extractPrevOutputScript` / `requireOutputP2PKH` /
/// `currentBlockHeight` (see
/// `packages/runar-testing/src/__tests__/intent-intrinsics-interpreter.test.ts`
/// for the canonical fixtures this entry point mirrors).
///
/// Concretely, before walking the ANF body:
///   - `witness.prev_out_scripts[i]` is injected into `args` under the
///     synthetic param name `_prevOutScript_<i>` (as a `Bytes` hex value).
///   - `witness.serialised_outputs` is injected as `_serialisedOutputs`.
///   - `extractLocktime`, `extractAmount`, `extractVersion`,
///     `extractSequence`, `extractOutputHash`, `extractOutputs`,
///     `extractHashPrevouts`, `extractHashSequence`, and `extractOutpoint`
///     consult [`IntentWitnessContext`] instead of returning the bare
///     zero-byte defaults.
///
/// Returns `Err(IntentInterpreterError::MissingWitness)` if the contract
/// ANF references a witness param the caller did not supply,
/// `Err(IntentInterpreterError::Assertion)` if any `assert(predicate)`
/// fires (e.g. `hash256(_prevOutScript_0) !== expectedHash`), and
/// `Err(IntentInterpreterError::Driver)` for genuine interpreter errors
/// (method not found, etc.).
pub fn execute_with_witness(
    anf: &ANFProgram,
    method_name: &str,
    current_state: &HashMap<String, SdkValue>,
    args: &HashMap<String, SdkValue>,
    constructor_args: &[SdkValue],
    witness: &IntentWitnessContext,
) -> Result<(HashMap<String, SdkValue>, Vec<DataOutputEntry>, Vec<RawOutputEntry>), IntentInterpreterError> {
    // Find the method first so we can scan its params for synthetic
    // witness names. Method-not-found surfaces as Driver(_).
    let method = anf
        .methods
        .iter()
        .find(|m| m.name == method_name && m.is_public)
        .ok_or_else(|| {
            IntentInterpreterError::Driver(format!(
                "execute_with_witness: method '{}' not found in ANF IR",
                method_name
            ))
        })?;

    // Merge witness bytes into args under the synthetic param names. If a
    // synthetic param is declared on the method but missing from the
    // witness context, surface MissingWitness with the same diagnostic
    // shape the TS reference produces.
    let mut merged_args = args.clone();
    for p in &method.params {
        if let Some(rest) = p.name.strip_prefix("_prevOutScript_") {
            if let Ok(idx) = rest.parse::<usize>() {
                match witness.prev_out_scripts.get(&idx) {
                    Some(bytes) => {
                        merged_args.insert(
                            p.name.clone(),
                            SdkValue::Bytes(bytes_to_hex(bytes)),
                        );
                    }
                    None => {
                        return Err(IntentInterpreterError::MissingWitness(format!(
                            "extractPrevOutputScript({}) requires witness bytes. \
                             Call IntentWitnessContext::set_prev_out_script({}, bytes) \
                             before invoking method '{}'.",
                            idx, idx, method_name
                        )));
                    }
                }
            }
        } else if p.name == "_serialisedOutputs" {
            match &witness.serialised_outputs {
                Some(bytes) => {
                    merged_args.insert(
                        p.name.clone(),
                        SdkValue::Bytes(bytes_to_hex(bytes)),
                    );
                }
                None => {
                    return Err(IntentInterpreterError::MissingWitness(format!(
                        "requireOutputP2PKH requires serialised-outputs witness bytes. \
                         Call IntentWitnessContext::set_serialised_outputs(bytes) \
                         before invoking method '{}'.",
                        method_name
                    )));
                }
            }
        }
    }

    // Strip the auto-injected stateful-continuation assert at the END of
    // the method body. The TS AST interpreter never sees this assertion
    // (it lives in ANF lowering, not in the AST), so porting the
    // intent-intrinsic tests requires us to skip it here as well —
    // otherwise the `hash256(cat(stateOutput, changeOutput)) ===
    // preimage.outputHash` check fires a spurious assertion failure (we
    // have no realistic continuation hash in simulation).
    //
    // The pattern is recognisable: the last top-level binding is
    // `assert(X)` where X is bound to a `bin_op {op:'===',result_type:
    // 'bytes'}` whose right operand traces back (one hop in env-order)
    // to a `call {func:'extractOutputHash'}`. Strip both the assert and
    // the bin_op + hash chain that feeds it isn't necessary — the
    // dependent bindings just become dead code and are evaluated harmlessly.
    let mut anf_clone = anf.clone();
    if let Some(m) = anf_clone
        .methods
        .iter_mut()
        .find(|mm| mm.name == method_name && mm.is_public)
    {
        if let Some(last) = m.body.last() {
            if last.value.get("kind").and_then(|k| k.as_str()) == Some("assert") {
                let pred_ref = last
                    .value
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let pred_binding = m.body.iter().find(|b| b.name == pred_ref);
                let is_continuation_pattern = pred_binding
                    .map(|b| {
                        if b.value.get("kind").and_then(|k| k.as_str()) != Some("bin_op") {
                            return false;
                        }
                        let op = b.value.get("op").and_then(|v| v.as_str()).unwrap_or("");
                        if op != "===" && op != "==" {
                            return false;
                        }
                        let result_type = b
                            .value
                            .get("result_type")
                            .or_else(|| b.value.get("resultType"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if result_type != "bytes" {
                            return false;
                        }
                        // Right operand should resolve to a call(extractOutputHash).
                        let right_ref = b
                            .value
                            .get("right")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        m.body
                            .iter()
                            .find(|bb| bb.name == right_ref)
                            .map(|bb| {
                                bb.value.get("kind").and_then(|k| k.as_str()) == Some("call")
                                    && bb
                                        .value
                                        .get("func")
                                        .and_then(|v| v.as_str())
                                        == Some("extractOutputHash")
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if is_continuation_pattern {
                    m.body.pop();
                }
            }
        }
    }

    let strict = StrictCtx {
        method_name: method_name.to_string(),
        real_crypto: None,
        witness: Some(witness.clone()),
    };
    match run_method(
        &anf_clone,
        method_name,
        current_state,
        &merged_args,
        constructor_args,
        Some(&strict),
    ) {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(s)) => Err(IntentInterpreterError::Driver(s)),
        Err(af) => Err(IntentInterpreterError::Assertion(af)),
    }
}

/// Shared entry-point for both lenient and strict modes.
///
/// Outer `Result`: strict-mode assertion failure (`Err`) vs successful
/// strict / any lenient walk (`Ok`).
/// Inner `Result`: real interpreter errors (e.g. method not found).
fn run_method(
    anf: &ANFProgram,
    method_name: &str,
    current_state: &HashMap<String, SdkValue>,
    args: &HashMap<String, SdkValue>,
    constructor_args: &[SdkValue],
    strict: Option<&StrictCtx>,
) -> Result<
    Result<(HashMap<String, SdkValue>, Vec<DataOutputEntry>, Vec<RawOutputEntry>), String>,
    AssertionFailureError,
> {
    // Find the public method
    let method = match anf
        .methods
        .iter()
        .find(|m| m.name == method_name && m.is_public)
    {
        Some(m) => m,
        None => {
            return Ok(Err(format!(
                "compute_new_state: method '{}' not found in ANF IR",
                method_name
            )));
        }
    };

    let mut env: HashMap<String, Val> = HashMap::new();

    // Load properties: mutable fields from current_state, non-initialized fields
    // from constructor_args (matched by constructor param index, which excludes
    // initialized properties).
    let ctor_idx: std::collections::HashMap<String, usize> = {
        let mut map = std::collections::HashMap::new();
        let mut ci = 0usize;
        for p in &anf.properties {
            if p.initial_value.is_none() {
                map.insert(p.name.clone(), ci);
                ci += 1;
            }
        }
        map
    };
    for prop in &anf.properties {
        if let Some(sv) = current_state.get(&prop.name) {
            env.insert(prop.name.clone(), Val::from_sdk(sv));
        } else if let Some(ref init) = prop.initial_value {
            env.insert(prop.name.clone(), json_to_val(init));
        } else if let Some(&idx) = ctor_idx.get(&prop.name) {
            if idx < constructor_args.len() {
                env.insert(prop.name.clone(), Val::from_sdk(&constructor_args[idx]));
            }
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

    // Track state mutations, data outputs, and raw outputs.
    // `raw_outputs` holds entries from `add_raw_output` ANF kinds, which the
    // simulator does NOT introspect (the script is caller-supplied). They
    // are surfaced in the result envelope so an off-chain transaction
    // builder can splice them in at the correct index.
    let mut state_delta: HashMap<String, Val> = HashMap::new();
    let mut data_outputs: Vec<DataOutputEntry> = Vec::new();
    let mut raw_outputs: Vec<RawOutputEntry> = Vec::new();

    // Walk bindings — strict-mode assert failures bubble up through `?`.
    eval_bindings(
        &method.body,
        &mut env,
        &mut state_delta,
        &mut data_outputs,
        &mut raw_outputs,
        anf,
        strict,
    )?;

    // Merge delta into current_state
    let mut result = current_state.clone();
    for (k, v) in state_delta {
        result.insert(k, v.to_sdk());
    }
    Ok(Ok((result, data_outputs, raw_outputs)))
}

// ---------------------------------------------------------------------------
// Binding evaluation
// ---------------------------------------------------------------------------

fn eval_bindings(
    bindings: &[ANFBinding],
    env: &mut HashMap<String, Val>,
    state_delta: &mut HashMap<String, Val>,
    data_outputs: &mut Vec<DataOutputEntry>,
    raw_outputs: &mut Vec<RawOutputEntry>,
    anf: &ANFProgram,
    strict: Option<&StrictCtx>,
) -> Result<(), AssertionFailureError> {
    for binding in bindings {
        let val = eval_value(
            &binding.value,
            env,
            state_delta,
            data_outputs,
            raw_outputs,
            anf,
            strict,
            &binding.name,
        )?;
        env.insert(binding.name.clone(), val);
    }
    Ok(())
}

fn eval_value(
    value: &serde_json::Value,
    env: &mut HashMap<String, Val>,
    state_delta: &mut HashMap<String, Val>,
    data_outputs: &mut Vec<DataOutputEntry>,
    raw_outputs: &mut Vec<RawOutputEntry>,
    anf: &ANFProgram,
    strict: Option<&StrictCtx>,
    binding_name: &str,
) -> Result<Val, AssertionFailureError> {
    let kind = match value.get("kind").and_then(|k| k.as_str()) {
        Some(k) => k,
        None => return Ok(Val::Undefined),
    };

    let result = match kind {
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
                    return Ok(env.get(target).cloned().unwrap_or(Val::Undefined));
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
            // Strict mode: a `call(assert, x)` lowering path enforces the
            // predicate the same way the dedicated `assert` ANF node does.
            if let Some(ctx) = strict {
                if func == "assert" {
                    let predicate = args.first().cloned().unwrap_or(Val::Undefined);
                    if !predicate.is_truthy() {
                        return Err(AssertionFailureError {
                            method_name: ctx.method_name.clone(),
                            binding_name: binding_name.to_string(),
                        });
                    }
                    return Ok(Val::Undefined);
                }
            }
            let real_crypto = strict.and_then(|c| c.real_crypto.as_ref());
            let witness = strict.and_then(|c| c.witness.as_ref());
            eval_call(&func, &args, real_crypto, witness)
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
                eval_bindings(&method.body, &mut child_env, state_delta, data_outputs, raw_outputs, anf, strict)?;
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
                eval_bindings(&bindings, &mut child_env, state_delta, data_outputs, raw_outputs, anf, strict)?;
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
                    eval_bindings(&bindings, &mut loop_env, state_delta, data_outputs, raw_outputs, anf, strict)?;
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

        "assert" => {
            // Lenient mode: skip; the on-chain script enforces.
            // Strict mode: enforce — falsy predicate returns
            // AssertionFailureError, propagated up via `?`.
            if let Some(ctx) = strict {
                let pred_ref = str_field(value, "value");
                let predicate = env.get(&pred_ref).cloned().unwrap_or(Val::Undefined);
                if !predicate.is_truthy() {
                    return Err(AssertionFailureError {
                        method_name: ctx.method_name.clone(),
                        binding_name: binding_name.to_string(),
                    });
                }
            }
            Val::Undefined
        }

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

        "add_data_output" => {
            // Resolve the two arg refs from env and record the data output.
            let sat_ref = str_field(value, "satoshis");
            let script_ref = str_field(value, "scriptBytes");
            let sats = env.get(&sat_ref).map(|v| v.to_i64()).unwrap_or(0);
            let script_hex = env.get(&script_ref).map(|v| v.as_hex()).unwrap_or_default();
            data_outputs.push(DataOutputEntry { satoshis: sats, script: script_hex });
            Val::Undefined
        }

        "add_raw_output" => {
            // `addRawOutput(satoshis, scriptBytes)`. The simulator does not
            // introspect the script bytes (they're caller-supplied raw
            // locking script); it simply forwards them in the result
            // envelope so an off-chain transaction builder can emit the
            // output at the correct index.
            let sat_ref = str_field(value, "satoshis");
            let script_ref = str_field(value, "scriptBytes");
            let sats = env.get(&sat_ref).map(|v| v.to_i64()).unwrap_or(0);
            let script_hex = env.get(&script_ref).map(|v| v.as_hex()).unwrap_or_default();
            raw_outputs.push(RawOutputEntry { satoshis: sats, script: script_hex });
            Val::Undefined
        }

        // On-chain-only operations — skip in simulation. When a witness
        // context is active (i.e. `execute_with_witness`), `check_preimage`
        // mocks success so the auto-injected `assert(check_preimage(...))`
        // at every stateful-method entry doesn't trip a spurious assertion
        // failure. Mirrors the TS reference, which mocks `checkPreimage`
        // to `true` in the AST interpreter.
        "check_preimage" => {
            if strict.and_then(|c| c.witness.as_ref()).is_some() {
                Val::Bool(true)
            } else {
                Val::Undefined
            }
        }
        "deserialize_state" | "get_state_script" => Val::Undefined,

        _ => Val::Undefined,
    };

    Ok(result)
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

fn eval_call(
    func: &str,
    args: &[Val],
    real_crypto: Option<&OnChainCryptoContext>,
    witness: Option<&IntentWitnessContext>,
) -> Val {
    match func {
        // Crypto — mocked unless real-crypto context is present.
        "checkSig" => {
            if let Some(rc) = real_crypto {
                let sig = args.first().cloned().unwrap_or(Val::Undefined);
                let pk  = args.get(1).cloned().unwrap_or(Val::Undefined);
                Val::Bool(verify_ecdsa_real(&sig, &pk, &rc.sighash))
            } else {
                Val::Bool(true)
            }
        }
        "checkMultiSig" => {
            if let Some(rc) = real_crypto {
                let sigs = args.first().cloned().unwrap_or(Val::Undefined);
                let pks  = args.get(1).cloned().unwrap_or(Val::Undefined);
                Val::Bool(verify_multi_sig_real(&sigs, &pks, &rc.sighash))
            } else {
                Val::Bool(true)
            }
        }
        "checkPreimage" => {
            if let Some(rc) = real_crypto {
                let pre = args.first().cloned().unwrap_or(Val::Undefined);
                Val::Bool(verify_preimage_real(&pre, &rc.sighash))
            } else {
                Val::Bool(true)
            }
        }

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

        // Preimage intrinsics. When a witness context is supplied (via
        // `execute_with_witness`), route through it so the desugared
        // intent-intrinsic ANF chains see real preimage-derived values;
        // otherwise fall back to the legacy zero-byte / zero-int defaults
        // existing simulation callers rely on.
        "extractLocktime" => Val::Int(
            witness
                .and_then(|w| w.mock_preimage.get("locktime").copied())
                .unwrap_or(0),
        ),
        "extractAmount" => match witness {
            Some(w) => Val::Int(w.mock_preimage.get("amount").copied().unwrap_or(10000)),
            // Pre-witness simulation kept this as a 32-zero byte string;
            // preserve that to avoid breaking existing callers.
            None => Val::Bytes("00".repeat(32)),
        },
        "extractVersion" => Val::Int(
            witness
                .and_then(|w| w.mock_preimage.get("version").copied())
                .unwrap_or(1),
        ),
        "extractSequence" => Val::Int(
            witness
                .and_then(|w| w.mock_preimage.get("sequence").copied())
                .unwrap_or(0xfffffffei64),
        ),
        "extractOutputHash" | "extractOutputs" => match witness {
            Some(w) => Val::Bytes(bytes_to_hex(
                w.mock_preimage_bytes
                    .get("outputHash")
                    .map(|v| v.as_slice())
                    .unwrap_or(&[0u8; 32]),
            )),
            None => Val::Bytes("00".repeat(32)),
        },
        "extractHashPrevouts" => Val::Bytes(bytes_to_hex(
            witness
                .and_then(|w| w.mock_preimage_bytes.get("hashPrevouts"))
                .map(|v| v.as_slice())
                .unwrap_or(&[0u8; 32]),
        )),
        "extractHashSequence" => Val::Bytes(bytes_to_hex(
            witness
                .and_then(|w| w.mock_preimage_bytes.get("hashSequence"))
                .map(|v| v.as_slice())
                .unwrap_or(&[0u8; 32]),
        )),
        "extractOutpoint" => Val::Bytes(bytes_to_hex(
            witness
                .and_then(|w| w.mock_preimage_bytes.get("outpoint"))
                .map(|v| v.as_slice())
                .unwrap_or(&[0u8; 36]),
        )),

        _ => Val::Undefined,
    }
}

// ---------------------------------------------------------------------------
// Real ECDSA / preimage verification (used by execute_on_chain_authoritative)
// ---------------------------------------------------------------------------

/// Coerce a `Val` to a byte vector. Hex string accepted; other shapes return
/// `None` so the caller can fail the verify cleanly.
fn val_to_bytes(v: &Val) -> Option<Vec<u8>> {
    match v {
        Val::Bytes(s) => hex_to_bytes_strict(s),
        _ => None,
    }
}

/// Strict hex decoder — returns `None` on odd length or non-hex characters.
/// Used by [`OnChainCryptoContext::from_hex`] and the byte-coercion helper
/// for the crypto built-ins; we want a parse failure to surface as `false`
/// from the verify (which then trips the enclosing `assert`), not as a
/// silent truncation like the lenient `hex_to_bytes` below does.
fn hex_to_bytes_strict(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

/// Strip a trailing sighash type byte from a DER-encoded ECDSA signature
/// blob, if present (Bitcoin convention). Returns the original slice when
/// the input does not look like DER+hashtype.
fn strip_sighash_byte(sig_bytes: &[u8]) -> &[u8] {
    if sig_bytes.len() < 2 || sig_bytes[0] != 0x30 {
        return sig_bytes;
    }
    let declared = sig_bytes[1] as usize;
    let expected_pure_der = declared + 2;
    if sig_bytes.len() == expected_pure_der + 1 {
        &sig_bytes[..expected_pure_der]
    } else {
        sig_bytes
    }
}

/// Verify an ECDSA signature against a 32-byte sighash digest using `k256`
/// secp256k1. Pubkey is SEC1 (compressed 33 bytes or uncompressed 65 bytes);
/// signature is DER with an optional trailing sighash type byte stripped.
/// Returns `false` on any decode error so the enclosing assert fires (and
/// surfaces as `AssertionFailureError`, not a verify-error propagated to
/// the caller).
///
/// Note on the digest: ECDSA-verifies against the supplied `sighash`
/// directly, with no extra SHA-256 layer. This mirrors the on-chain
/// `OP_CHECKSIG` semantic (sig is signed over the BIP-143 sighash, the
/// VM ECDSA-verifies sig against that 32-byte digest), and matches the
/// cross-tier real-crypto fixture convention used by every SDK driver.
fn verify_ecdsa_real(sig_val: &Val, pk_val: &Val, sighash: &[u8; 32]) -> bool {
    let sig_bytes = match val_to_bytes(sig_val) { Some(b) => b, None => return false };
    let pk_bytes  = match val_to_bytes(pk_val)  { Some(b) => b, None => return false };
    let der = strip_sighash_byte(&sig_bytes);
    let sig = match K256Signature::from_der(der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_sec1_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    vk.verify_prehash(sighash.as_ref(), &sig).is_ok()
}

/// Verify a list of signatures against a list of pubkeys. Mirrors Bitcoin's
/// `OP_CHECKMULTISIG`: iterate sigs left-to-right, consume pubkeys greedily.
///
/// The Rust interpreter's `Val` enum cannot represent arrays of bytes
/// directly (lists leak through as `Val::Undefined` from `Val::from_sdk`),
/// so this function returns `false` unless future ANF lowering wires a
/// dedicated representation. The fail path matches the spec: "On any parse
/// error → return false".
fn verify_multi_sig_real(_sigs: &Val, _pks: &Val, _sighash: &[u8; 32]) -> bool {
    false
}

/// Verify that `SHA256(SHA256(preimage)) == sighash` — the on-chain
/// `OP_PUSH_TX` semantic for `checkPreimage`.
fn verify_preimage_real(preimage_val: &Val, sighash: &[u8; 32]) -> bool {
    let pre_bytes = match val_to_bytes(preimage_val) { Some(b) => b, None => return false };
    let first = Sha256::digest(&pre_bytes);
    let second = Sha256::digest(&first);
    let actual: &[u8] = &second[..];
    actual == &sighash[..]
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

        let result = compute_new_state(&anf, "increment", &state, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.get("count"), Some(&SdkValue::Int(1)));
    }

    #[test]
    fn test_increment_twice() {
        let anf = make_anf(vec![make_increment_method()]);
        let mut state = HashMap::new();
        state.insert("count".to_string(), SdkValue::Int(5));

        let result = compute_new_state(&anf, "increment", &state, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.get("count"), Some(&SdkValue::Int(6)));
    }

    #[test]
    fn test_method_not_found() {
        let anf = make_anf(vec![]);
        let result = compute_new_state(&anf, "nonexistent", &HashMap::new(), &HashMap::new(), &[]);
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

        let result = compute_new_state(&anf, "test", &state, &HashMap::new(), &[]).unwrap();
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
        let result = compute_new_state(&anf, "test", &state, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.get("count"), Some(&SdkValue::Int(4)));

        // count == 0: take else branch → increment
        let mut state2 = HashMap::new();
        state2.insert("count".to_string(), SdkValue::Int(0));
        let result2 = compute_new_state(&anf, "test", &state2, &HashMap::new(), &[]).unwrap();
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

        let result = compute_new_state(&anf, "add", &state, &args, &[]).unwrap();
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

    /// Readonly deploy-time fields must be available in method arithmetic.
    ///
    /// Reproduces a bug where `self.strike_price` (readonly, set at deploy via
    /// constructor args, no compile-time initialValue) evaluated to 0 in
    /// state-mutating methods. The ANF interpreter's environment only contained
    /// mutable fields from `current_state`, missing readonly fields entirely.
    #[test]
    fn test_readonly_constructor_field_in_arithmetic() {
        // Build the ANF from JSON (same format as artifact.anf)
        let json = r#"{
            "contractName": "Settlement",
            "properties": [
                { "name": "strikePrice", "type": "bigint", "readonly": true },
                { "name": "runningTotal", "type": "bigint", "readonly": false }
            ],
            "methods": [{
                "name": "advanceEpoch",
                "params": [{ "name": "delta", "type": "bigint" }],
                "isPublic": true,
                "body": [
                    { "name": "_t0", "value": { "kind": "load_prop", "name": "strikePrice" } },
                    { "name": "_t1", "value": { "kind": "load_prop", "name": "runningTotal" } },
                    { "name": "_t2", "value": { "kind": "bin_op", "op": "*", "left": "_t0", "right": "delta" } },
                    { "name": "_t3", "value": { "kind": "bin_op", "op": "+", "left": "_t1", "right": "_t2" } },
                    { "name": "_t4", "value": { "kind": "update_prop", "name": "runningTotal", "value": "_t3" } }
                ]
            }]
        }"#;
        let anf: ANFProgram = serde_json::from_str(json).unwrap();

        // Mutable state: runningTotal = 1000
        let mut state = HashMap::new();
        state.insert("runningTotal".to_string(), SdkValue::Int(1000));

        // Constructor args in declaration order: [strikePrice=75000, runningTotal=0]
        let constructor_args = vec![
            SdkValue::Int(75000),  // strikePrice (readonly, deploy-time)
            SdkValue::Int(0),      // runningTotal (mutable, initial)
        ];

        let mut args = HashMap::new();
        args.insert("delta".to_string(), SdkValue::Int(2500));

        // Expected: runningTotal = 1000 + 75000 * 2500 = 187,501,000
        let result = compute_new_state(&anf, "advanceEpoch", &state, &args, &constructor_args).unwrap();
        assert_eq!(
            result.get("runningTotal"),
            Some(&SdkValue::Int(187_501_000)),
            "readonly field strikePrice (75000) must be available in method arithmetic"
        );
    }

    /// Verify the bug existed — without constructor_args, readonly fields evaluate to 0.
    #[test]
    fn test_readonly_field_without_constructor_args_is_zero() {
        let json = r#"{
            "contractName": "Settlement",
            "properties": [
                { "name": "strikePrice", "type": "bigint", "readonly": true },
                { "name": "runningTotal", "type": "bigint", "readonly": false }
            ],
            "methods": [{
                "name": "advanceEpoch",
                "params": [{ "name": "delta", "type": "bigint" }],
                "isPublic": true,
                "body": [
                    { "name": "_t0", "value": { "kind": "load_prop", "name": "strikePrice" } },
                    { "name": "_t1", "value": { "kind": "load_prop", "name": "runningTotal" } },
                    { "name": "_t2", "value": { "kind": "bin_op", "op": "*", "left": "_t0", "right": "delta" } },
                    { "name": "_t3", "value": { "kind": "bin_op", "op": "+", "left": "_t1", "right": "_t2" } },
                    { "name": "_t4", "value": { "kind": "update_prop", "name": "runningTotal", "value": "_t3" } }
                ]
            }]
        }"#;
        let anf: ANFProgram = serde_json::from_str(json).unwrap();

        let mut state = HashMap::new();
        state.insert("runningTotal".to_string(), SdkValue::Int(1000));
        let mut args = HashMap::new();
        args.insert("delta".to_string(), SdkValue::Int(2500));

        // Empty constructor_args — strikePrice falls through to Undefined → 0
        let result = compute_new_state(&anf, "advanceEpoch", &state, &args, &[]).unwrap();
        // Without fix: 1000 + 0 * 2500 = 1000 (strikePrice treated as 0)
        assert_eq!(
            result.get("runningTotal"),
            Some(&SdkValue::Int(1000)),
            "without constructor_args, readonly field defaults to 0 (pre-fix behavior)"
        );
    }
}

#[cfg(test)]
mod real_crypto_tests {
    //! Smoke-tests for `execute_on_chain_authoritative`. The deterministic
    //! test vectors are the same `sighash`/`sig`/`pubKey` triple used by
    //! `conformance/anf-interpreter/inputs/real-crypto-p2pkh-pass.json` and
    //! the TS / Java / Zig real-crypto fixtures, so a pass here means the
    //! fixture round-trips cleanly through the Rust SDK.
    use super::*;

    /// Pass fixture: pubKey is the secp256k1 compressed pubkey for the
    /// deterministic test priv key; sig is the canonical DER signature
    /// produced by RFC 6979 ECDSA-sign(sighash, priv) — signed against
    /// the raw 32-byte sighash with no extra hashing, matching the on-chain
    /// `OP_CHECKSIG` semantic. Mirrors
    /// `conformance/anf-interpreter/inputs/real-crypto-p2pkh-pass.json`.
    #[test]
    fn execute_on_chain_authoritative_passes_basic_p2pkh_fixture() {
        let sig_hex = "3045022100c82dc77c9c740a2e7e299898290e1d3586221bcbce0bfc308dad201abeaa8617022026ad5a69f741e6da936ac2cd7e099daff6b1d6f88703e41dc2955c66ccb6f5b7";
        let pk_hex = "02057ffc2b5e380939f86a29693fe6561883c4cce0ec89f215ae417dcdd1fdaa41";
        let sighash_hex = "66f605fe8c48e394c387cf4e64e859926168637caeafe8e98347232a33244588";

        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(&hex_to_bytes_strict(sighash_hex).unwrap());

        let sig = Val::Bytes(sig_hex.to_string());
        let pk = Val::Bytes(pk_hex.to_string());
        assert!(verify_ecdsa_real(&sig, &pk, &sighash));
    }

    /// Fail fixture: same sig + pubKey but sighash is all-zeros, so the
    /// signature does NOT verify; `verify_ecdsa_real` returns false (which
    /// trips the enclosing `assert` and yields `AssertionFailureError`).
    #[test]
    fn execute_on_chain_authoritative_fails_for_wrong_sighash() {
        let sig_hex = "3045022100c82dc77c9c740a2e7e299898290e1d3586221bcbce0bfc308dad201abeaa8617022026ad5a69f741e6da936ac2cd7e099daff6b1d6f88703e41dc2955c66ccb6f5b7";
        let pk_hex = "02057ffc2b5e380939f86a29693fe6561883c4cce0ec89f215ae417dcdd1fdaa41";

        let sig = Val::Bytes(sig_hex.to_string());
        let pk = Val::Bytes(pk_hex.to_string());
        let zero_sighash = [0u8; 32];
        assert!(!verify_ecdsa_real(&sig, &pk, &zero_sighash));
    }

    /// `from_hex` rejects malformed hex and wrong-length inputs.
    #[test]
    fn on_chain_crypto_context_from_hex_validates_input() {
        assert!(OnChainCryptoContext::from_hex("66f605fe8c48e394c387cf4e64e859926168637caeafe8e98347232a33244588").is_ok());
        assert!(OnChainCryptoContext::from_hex("00").is_err());
        assert!(OnChainCryptoContext::from_hex("zz").is_err());
        assert!(OnChainCryptoContext::from_hex("00112233").is_err());
    }
}
