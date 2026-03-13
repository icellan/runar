//! Main RunarContract runtime wrapper for deploying and interacting with
//! compiled Rúnar contracts on BSV.

use std::collections::HashMap;
use sha2::{Sha256, Digest};
use bsv::transaction::Transaction as BsvTransaction;
use super::types::*;
use super::state::{serialize_state, extract_state_from_script, encode_push_data, find_last_op_return};
use super::oppushtx::compute_op_push_tx_with_code_sep;
use super::deployment::{
    build_deploy_transaction, select_utxos,
    build_p2pkh_script_from_address, encode_varint,
    to_little_endian_32, to_little_endian_64, reverse_hex,
};
use super::calling::{build_call_transaction_ext, CallTxOptions, ContractOutput, AdditionalContractInput};
use super::provider::Provider;
use super::signer::Signer;
use super::anf_interpreter;
use crate::prelude::hash160 as compute_hash160;

/// Convert a raw transaction hex string to a BSV SDK Transaction object for broadcasting.
fn hex_to_bsv_tx(hex: &str) -> Result<BsvTransaction, String> {
    BsvTransaction::from_hex(hex).map_err(|e| format!("hex_to_bsv_tx: {}", e))
}

/// Runtime wrapper for a compiled Rúnar contract.
///
/// Handles deployment, method invocation, state tracking, and script
/// construction. Works with any Provider and Signer implementation.
///
/// ```ignore
/// let artifact: RunarArtifact = serde_json::from_str(&json)?;
/// let contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
/// let (txid, tx) = contract.deploy(&mut provider, &signer, DeployOptions { satoshis: 10000, .. })?;
/// ```
pub struct RunarContract {
    pub(crate) artifact: RunarArtifact,
    constructor_args: Vec<SdkValue>,
    state: HashMap<String, SdkValue>,
    code_script: Option<String>,
    current_utxo: Option<Utxo>,
    connected_provider: Option<Box<dyn Provider>>,
    connected_signer: Option<Box<dyn Signer>>,
}

impl std::fmt::Debug for RunarContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunarContract")
            .field("contract_name", &self.artifact.contract_name)
            .field("has_utxo", &self.current_utxo.is_some())
            .finish()
    }
}

impl RunarContract {
    /// Create a new RunarContract from an artifact and constructor arguments.
    pub fn new(artifact: RunarArtifact, constructor_args: Vec<SdkValue>) -> Self {
        let expected = artifact.abi.constructor.params.len();
        if constructor_args.len() != expected {
            panic!(
                "RunarContract: expected {} constructor args for {}, got {}",
                expected, artifact.contract_name, constructor_args.len()
            );
        }

        // Initialize state from constructor args for stateful contracts.
        // Properties with initial_value use their compile-time default;
        // others are matched to constructor args by their declaration
        // index, not by name, since the constructor param name may differ
        // from the state field name (e.g., "initialHash" → "rollingHash").
        let mut state = HashMap::new();
        if let Some(ref state_fields) = artifact.state_fields {
            if !state_fields.is_empty() {
                for field in state_fields {
                    if let Some(ref init_val) = field.initial_value {
                        // Property has a compile-time default value.
                        // Revive BigInt strings ("0n") that occur when artifacts
                        // are loaded via plain JSON import (without a BigInt reviver).
                        state.insert(field.name.clone(), revive_json_value(init_val, &field.field_type));
                    } else if field.index < constructor_args.len() {
                        state.insert(field.name.clone(), constructor_args[field.index].clone());
                    }
                }
            }
        }

        RunarContract {
            artifact,
            constructor_args,
            state,
            code_script: None,
            current_utxo: None,
            connected_provider: None,
            connected_signer: None,
        }
    }

    // -----------------------------------------------------------------------
    // UTXO access
    // -----------------------------------------------------------------------

    /// Returns the current UTXO tracked by this contract, if any.
    pub fn get_utxo(&self) -> Option<&Utxo> {
        self.current_utxo.as_ref()
    }

    // -----------------------------------------------------------------------
    // Connection
    // -----------------------------------------------------------------------

    /// Store a provider and signer on this contract so they don't need to be
    /// passed to every `deploy()` and `call()` invocation.
    pub fn connect(&mut self, provider: Box<dyn Provider>, signer: Box<dyn Signer>) {
        self.connected_provider = Some(provider);
        self.connected_signer = Some(signer);
    }

    /// Deploy using the connected provider and signer.
    pub fn deploy_connected(&mut self, options: &DeployOptions) -> Result<(String, TransactionData), String> {
        let provider = self.connected_provider.as_mut().ok_or_else(|| {
            "No provider connected. Call connect() first.".to_string()
        })?;
        let signer = self.connected_signer.as_ref().ok_or_else(|| {
            "No signer connected. Call connect() first.".to_string()
        })?;
        // We need to borrow provider mutably and signer immutably.
        // Since both are behind Option<Box<...>>, we can use raw pointer tricks,
        // but it's simpler to just take them out temporarily.
        // Actually, let's just delegate to the explicit method.
        let provider_ptr: *mut dyn Provider = &mut **provider;
        let signer_ptr: *const dyn Signer = &**signer;
        // SAFETY: We hold &mut self, so no other references exist.
        // provider_ptr and signer_ptr are both derived from fields of self.
        unsafe {
            self.deploy_inner(&mut *provider_ptr, &*signer_ptr, options)
        }
    }

    /// Call a method using the connected provider and signer.
    pub fn call_connected(
        &mut self,
        method_name: &str,
        args: &[SdkValue],
        options: Option<&CallOptions>,
    ) -> Result<(String, TransactionData), String> {
        let provider = self.connected_provider.as_mut().ok_or_else(|| {
            "No provider connected. Call connect() first.".to_string()
        })?;
        let signer = self.connected_signer.as_ref().ok_or_else(|| {
            "No signer connected. Call connect() first.".to_string()
        })?;
        let provider_ptr: *mut dyn Provider = &mut **provider;
        let signer_ptr: *const dyn Signer = &**signer;
        unsafe {
            self.call_inner(&mut *provider_ptr, &*signer_ptr, method_name, args, options)
        }
    }

    /// Prepare a method call using the connected provider and signer.
    pub fn prepare_call_connected(
        &mut self,
        method_name: &str,
        args: &[SdkValue],
        options: Option<&CallOptions>,
    ) -> Result<PreparedCall, String> {
        let provider = self.connected_provider.as_mut().ok_or_else(|| {
            "No provider connected. Call connect() first.".to_string()
        })?;
        let signer = self.connected_signer.as_ref().ok_or_else(|| {
            "No signer connected. Call connect() first.".to_string()
        })?;
        let provider_ptr: *mut dyn Provider = &mut **provider;
        let signer_ptr: *const dyn Signer = &**signer;
        unsafe {
            self.prepare_call(method_name, args, &mut *provider_ptr, &*signer_ptr, options)
        }
    }

    /// Finalize a prepared call using the connected provider.
    pub fn finalize_call_connected(
        &mut self,
        prepared: &PreparedCall,
        signatures: &HashMap<usize, String>,
    ) -> Result<(String, TransactionData), String> {
        let provider = self.connected_provider.as_mut().ok_or_else(|| {
            "No provider connected. Call connect() first.".to_string()
        })?;
        let provider_ptr: *mut dyn Provider = &mut **provider;
        unsafe {
            self.finalize_call(prepared, signatures, &mut *provider_ptr)
        }
    }

    // -----------------------------------------------------------------------
    // Deployment
    // -----------------------------------------------------------------------

    /// Deploy the contract by creating a UTXO with the locking script.
    ///
    /// Returns a tuple of (txid, Transaction).
    pub fn deploy(
        &mut self,
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        options: &DeployOptions,
    ) -> Result<(String, TransactionData), String> {
        self.deploy_inner(provider, signer, options)
    }

    fn deploy_inner(
        &mut self,
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        options: &DeployOptions,
    ) -> Result<(String, TransactionData), String> {
        let address = signer.get_address()?;
        let change_address = options
            .change_address
            .as_deref()
            .unwrap_or(&address);
        let locking_script = self.get_locking_script();

        // Fetch fee rate and funding UTXOs
        let fee_rate = provider.get_fee_rate()?;
        let all_utxos = provider.get_utxos(&address)?;
        if all_utxos.is_empty() {
            return Err(format!(
                "RunarContract.deploy: no UTXOs found for address {}",
                address
            ));
        }
        let utxos = select_utxos(&all_utxos, options.satoshis, locking_script.len() / 2, Some(fee_rate));

        // Build the deploy transaction
        let change_script = build_p2pkh_script_from_address(change_address);
        let (tx_hex, input_count) = build_deploy_transaction(
            &locking_script,
            &utxos,
            options.satoshis,
            change_address,
            &change_script,
            Some(fee_rate),
        );

        // Sign all inputs
        let mut signed_tx = tx_hex;
        for i in 0..input_count {
            let utxo = &utxos[i];
            let sig = signer.sign(&signed_tx, i, &utxo.script, utxo.satoshis, None)?;
            let pub_key = signer.get_public_key()?;
            // Build P2PKH unlocking script: <sig> <pubkey>
            let unlock_script = format!("{}{}", encode_push_data(&sig), encode_push_data(&pub_key));
            signed_tx = insert_unlocking_script(&signed_tx, i, &unlock_script)?;
        }

        // Broadcast
        let bsv_tx = hex_to_bsv_tx(&signed_tx)?;
        let txid = provider.broadcast(&bsv_tx)?;

        // Track the deployed UTXO
        self.current_utxo = Some(Utxo {
            txid: txid.clone(),
            output_index: 0,
            satoshis: options.satoshis,
            script: locking_script.clone(),
        });

        let tx = provider.get_transaction(&txid).unwrap_or_else(|_| {
            // Fallback: construct a minimal transaction from what we know
            TransactionData {
                txid: txid.clone(),
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    satoshis: options.satoshis,
                    script: locking_script,
                }],
                locktime: 0,
                raw: Some(signed_tx),
            }
        });

        Ok((txid, tx))
    }

    // -----------------------------------------------------------------------
    // Method invocation
    // -----------------------------------------------------------------------

    /// Call a public method on the contract (spend the UTXO).
    ///
    /// For stateful contracts, a new UTXO is created with the updated state.
    /// Returns a tuple of (txid, Transaction).
    pub fn call(
        &mut self,
        method_name: &str,
        args: &[SdkValue],
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        options: Option<&CallOptions>,
    ) -> Result<(String, TransactionData), String> {
        self.call_inner(provider, signer, method_name, args, options)
    }

    fn call_inner(
        &mut self,
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        method_name: &str,
        args: &[SdkValue],
        options: Option<&CallOptions>,
    ) -> Result<(String, TransactionData), String> {
        let prepared = self.prepare_call(method_name, args, provider, signer, options)?;
        let mut signatures = HashMap::new();
        let contract_utxo = prepared.contract_utxo.clone();
        for &idx in &prepared.sig_indices {
            // Stateful: user checkSig is AFTER OP_CODESEPARATOR — trim subscript.
            // Stateless: user checkSig is BEFORE — use full script.
            let mut subscript = contract_utxo.script.clone();
            if prepared.is_stateful && prepared.code_sep_idx >= 0 {
                let trim_pos = ((prepared.code_sep_idx as usize) + 1) * 2;
                if trim_pos <= subscript.len() {
                    subscript = subscript[trim_pos..].to_string();
                }
            }
            let sig = signer.sign(
                &prepared.tx_hex, 0,
                &subscript, contract_utxo.satoshis, None,
            )?;
            signatures.insert(idx, sig);
        }
        self.finalize_call(&prepared, &signatures, provider)
    }

    // -----------------------------------------------------------------------
    // prepare_call / finalize_call — multi-signer support
    // -----------------------------------------------------------------------

    /// Build the transaction for a method call without signing the primary
    /// contract input's Sig params. Returns a `PreparedCall` containing the
    /// BIP-143 sighash that external signers need, plus opaque internals for
    /// `finalize_call()`.
    ///
    /// P2PKH funding inputs and additional contract inputs ARE signed with the
    /// connected signer. Only the primary contract input's Sig params are left
    /// as 72-byte placeholders.
    pub fn prepare_call(
        &mut self,
        method_name: &str,
        args: &[SdkValue],
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        options: Option<&CallOptions>,
    ) -> Result<PreparedCall, String> {
        // Validate method exists
        let method = self.find_method(method_name).ok_or_else(|| {
            format!(
                "RunarContract.prepareCall: method '{}' not found in {}",
                method_name, self.artifact.contract_name
            )
        })?;

        // Determine if this is a stateful contract
        let is_stateful = self
            .artifact
            .state_fields
            .as_ref()
            .map_or(false, |f| !f.is_empty());

        // For stateful contracts, the compiler injects implicit params into every
        // public method's ABI (SigHashPreimage, and for state-mutating methods:
        // _changePKH and _changeAmount). The SDK auto-computes these.
        let method_needs_change = method.params.iter().any(|p| p.name == "_changePKH");
        let method_needs_new_amount = method.params.iter().any(|p| p.name == "_newAmount");
        let user_params: Vec<&AbiParam> = if is_stateful {
            method.params.iter().filter(|p| {
                p.param_type != "SigHashPreimage"
                    && p.name != "_changePKH"
                    && p.name != "_changeAmount"
                    && p.name != "_newAmount"
            }).collect()
        } else {
            method.params.iter().collect()
        };

        if user_params.len() != args.len() {
            return Err(format!(
                "RunarContract.prepareCall: method '{}' expects {} args, got {}",
                method_name,
                user_params.len(),
                args.len()
            ));
        }

        let current_utxo = self.current_utxo.as_ref().ok_or_else(|| {
            "RunarContract.prepareCall: contract is not deployed. Call deploy() or from_txid() first."
                .to_string()
        })?
        .clone();

        let address = signer.get_address()?;
        let change_address = options
            .and_then(|o| o.change_address.as_deref())
            .unwrap_or(&address);

        // Detect Sig/PubKey/SigHashPreimage/ByteString params that need auto-compute (user passed Auto)
        let mut resolved_args: Vec<SdkValue> = args.to_vec();
        let mut sig_indices: Vec<usize> = Vec::new();
        let mut preimage_index: Option<usize> = None;
        let mut prevouts_indices: Vec<usize> = Vec::new();
        for (i, param) in user_params.iter().enumerate() {
            if matches!(args[i], SdkValue::Auto) {
                if param.param_type == "Sig" {
                    sig_indices.push(i);
                    // 72-byte placeholder
                    resolved_args[i] = SdkValue::Bytes("00".repeat(72));
                } else if param.param_type == "PubKey" {
                    resolved_args[i] = SdkValue::Bytes(signer.get_public_key()?);
                } else if param.param_type == "SigHashPreimage" {
                    preimage_index = Some(i);
                    // Placeholder preimage (will be replaced after tx construction)
                    resolved_args[i] = SdkValue::Bytes("00".repeat(181));
                } else if param.param_type == "ByteString" {
                    prevouts_indices.push(i);
                    // Placeholder sized to estimated input count (1 primary + N extra + 1 funding)
                    let estimated_inputs = 1 + options.and_then(|o| o.additional_contract_inputs.as_ref()).map_or(0, |v| v.len()) + 1;
                    resolved_args[i] = SdkValue::Bytes("00".repeat(36 * estimated_inputs));
                }
            }
        }

        // If any param uses SigHashPreimage, or this is a stateful contract,
        // the compiler injects an implicit _opPushTxSig at the beginning of
        // the unlocking script.
        let needs_op_push_tx = preimage_index.is_some() || is_stateful;

        // Compute method selector (needed for both terminal and non-terminal)
        let mut method_selector_hex = String::new();
        if is_stateful {
            let public_methods: Vec<&AbiMethod> = self
                .artifact
                .abi
                .methods
                .iter()
                .filter(|m| m.is_public)
                .collect();
            if public_methods.len() > 1 {
                if let Some(idx) = public_methods.iter().position(|m| m.name == method_name) {
                    method_selector_hex = encode_script_number(idx as i64);
                }
            }
        }

        // Compute change PKH for stateful methods that need it
        let change_pkh_hex = if is_stateful && method_needs_change {
            let change_pub_key_hex = options
                .and_then(|o| o.change_pub_key.as_deref())
                .map(|s| s.to_string())
                .unwrap_or_else(|| signer.get_public_key().unwrap_or_default());
            let pub_key_bytes: Vec<u8> = (0..change_pub_key_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&change_pub_key_hex[i..i + 2], 16).unwrap_or(0))
                .collect();
            let hash = compute_hash160(&pub_key_bytes);
            hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        } else {
            String::new()
        };

        // -------------------------------------------------------------------
        // Terminal method path: exact outputs, no funding, no change
        // -------------------------------------------------------------------
        if let Some(ref terminal_outputs) = options.and_then(|o| o.terminal_outputs.as_ref()) {
            return self.prepare_call_terminal(
                method_name, &mut resolved_args, signer,
                options, terminal_outputs, &current_utxo,
                is_stateful, needs_op_push_tx, method_needs_change,
                &sig_indices, &prevouts_indices, preimage_index,
                &method_selector_hex, &change_pkh_hex,
            );
        }

        // -------------------------------------------------------------------
        // Non-terminal path
        // -------------------------------------------------------------------

        let unlocking_script = if needs_op_push_tx {
            // Prepend placeholder prefix (optionally _codePart + _opPushTxSig) before user args
            format!(
                "{}{}",
                self.build_stateful_prefix(&"00".repeat(72), method_needs_change),
                self.build_unlocking_script(method_name, &resolved_args)?
            )
        } else {
            self.build_unlocking_script(method_name, &resolved_args)?
        };

        let mut new_locking_script: Option<String> = None;
        let mut new_satoshis: Option<i64> = None;

        // Build contract outputs: multi-output (options.outputs) takes priority,
        // then single continuation (options.new_state), then default.
        let extra_contract_utxos: Vec<Utxo> = options
            .and_then(|o| o.additional_contract_inputs.as_ref())
            .cloned()
            .unwrap_or_default();
        let has_multi_output = options
            .and_then(|o| o.outputs.as_ref())
            .map_or(false, |v| !v.is_empty());

        let mut contract_outputs: Option<Vec<ContractOutput>> = None;

        if is_stateful && has_multi_output {
            // Multi-output: build a locking script for each output
            let code_script = self.code_script.clone().unwrap_or_else(|| self.build_code_script());
            let state_fields = self.artifact.state_fields.as_ref().unwrap();
            let outputs = options.unwrap().outputs.as_ref().unwrap();
            contract_outputs = Some(
                outputs.iter().map(|out| {
                    let state_hex = serialize_state(state_fields, &out.state);
                    ContractOutput {
                        script: format!("{}6a{}", code_script, state_hex),
                        satoshis: out.satoshis,
                    }
                }).collect()
            );
        } else if is_stateful {
            // For single-output continuations, the on-chain script uses the input amount
            // (extracted from the preimage). The SDK output must match.
            new_satoshis = Some(
                options
                    .and_then(|o| o.satoshis)
                    .unwrap_or(current_utxo.satoshis),
            );
            // Apply new state values before building the continuation output.
            // Explicit newState takes priority (backward compat); otherwise
            // auto-compute from ANF IR if available.
            if let Some(new_state) = options.and_then(|o| o.new_state.as_ref()) {
                for (k, v) in new_state {
                    self.state.insert(k.clone(), v.clone());
                }
            } else if method_needs_change {
                if let Some(ref anf) = self.artifact.anf {
                    let named_args = build_named_args(&user_params, &resolved_args);
                    if let Ok(computed) = anf_interpreter::compute_new_state(
                        anf, method_name, &self.state, &named_args,
                    ) {
                        for (k, v) in computed {
                            self.state.insert(k, v);
                        }
                    }
                }
            }
            new_locking_script = Some(self.get_locking_script());
        }

        // Fetch fee rate and funding UTXOs for all contract types.
        // For stateful contracts with change output support, the change output
        // is verified by the on-chain script (hashOutputs check).
        let fee_rate = provider.get_fee_rate()?;
        let change_script_str = build_p2pkh_script_from_address(change_address);
        let all_funding_utxos = provider.get_utxos(&address).unwrap_or_default();
        // Filter out the contract UTXO from funding UTXOs to avoid duplicate inputs
        let additional_utxos: Vec<Utxo> = all_funding_utxos
            .into_iter()
            .filter(|u| !(u.txid == current_utxo.txid && u.output_index == current_utxo.output_index))
            .collect();

        // Resolve per-input args for additional contract inputs (same Sig/PubKey/ByteString handling as primary args)
        let resolved_per_input_args: Option<Vec<Vec<SdkValue>>> = options
            .and_then(|o| o.additional_contract_input_args.as_ref())
            .map(|per_input| {
                per_input.iter().map(|input_args| {
                    let mut resolved = input_args.clone();
                    for (i, param) in user_params.iter().enumerate() {
                        if i < resolved.len() && matches!(resolved[i], SdkValue::Auto) {
                            if param.param_type == "Sig" {
                                resolved[i] = SdkValue::Bytes("00".repeat(72));
                            } else if param.param_type == "PubKey" {
                                // Use the same resolved pubkey as the primary args
                                resolved[i] = resolved_args[i].clone();
                            } else if param.param_type == "ByteString" {
                                let estimated_inputs = 1 + options.and_then(|o| o.additional_contract_inputs.as_ref()).map_or(0, |v| v.len()) + 1;
                                resolved[i] = SdkValue::Bytes("00".repeat(36 * estimated_inputs));
                            }
                        }
                    }
                    resolved
                }).collect()
            });

        // Build placeholder unlocking scripts for merge inputs
        let extra_unlock_placeholders: Vec<String> = extra_contract_utxos.iter().enumerate().map(|(i, _)| {
            let args_for_placeholder = resolved_per_input_args.as_ref()
                .and_then(|v| v.get(i))
                .unwrap_or(&resolved_args);
            format!(
                "{}{}",
                self.build_stateful_prefix(&"00".repeat(72), method_needs_change),
                self.build_unlocking_script(method_name, args_for_placeholder).unwrap_or_default(),
            )
        }).collect();

        let change_addr_opt: Option<&str> = Some(change_address);
        let change_script_opt: Option<&str> = Some(&change_script_str);

        let call_tx_options = CallTxOptions {
            contract_outputs: contract_outputs.as_ref().map(|cos| {
                cos.iter().map(|co| ContractOutput { script: co.script.clone(), satoshis: co.satoshis }).collect()
            }),
            additional_contract_inputs: if extra_contract_utxos.is_empty() {
                None
            } else {
                Some(extra_contract_utxos.iter().enumerate().map(|(i, utxo)| {
                    AdditionalContractInput {
                        utxo: utxo.clone(),
                        unlocking_script: extra_unlock_placeholders[i].clone(),
                    }
                }).collect())
            },
        };

        let (tx_hex, input_count, mut change_amount) = build_call_transaction_ext(
            &current_utxo,
            &unlocking_script,
            new_locking_script.as_deref(),
            new_satoshis,
            change_addr_opt,
            change_script_opt,
            if additional_utxos.is_empty() {
                None
            } else {
                Some(&additional_utxos)
            },
            Some(fee_rate),
            Some(&call_tx_options),
        );

        // Sign P2PKH funding inputs (after contract inputs)
        let mut signed_tx = tx_hex;
        let p2pkh_start_idx = 1 + extra_contract_utxos.len();
        for i in p2pkh_start_idx..input_count {
            if let Some(utxo) = additional_utxos.get(i - p2pkh_start_idx) {
                let sig = signer.sign(&signed_tx, i, &utxo.script, utxo.satoshis, None)?;
                let pub_key = signer.get_public_key()?;
                let unlock_script = format!("{}{}", encode_push_data(&sig), encode_push_data(&pub_key));
                signed_tx = insert_unlocking_script(&signed_tx, i, &unlock_script)?;
            }
        }

        let mut final_op_push_tx_sig = String::new();
        let mut final_preimage = String::new();

        let method_index = self.find_method_index(method_name);
        let code_sep_idx = self.get_code_sep_index(method_index);
        let code_part_for_prefix = if method_needs_change && self.has_code_separator() {
            Some(self.get_code_part_hex())
        } else {
            None
        };

        if is_stateful {
            // Helper closure to build a stateful unlock for a given input.
            // For input_idx===0 (primary), keeps placeholder Sig params.
            // For input_idx>0 (extra), signs with signer.
            let build_stateful_unlock = |tx: &str, input_idx: usize, subscript: &str, sats: i64,
                                          signer: &dyn Signer, sig_indices: &[usize],
                                          prevouts_indices: &[usize],
                                          resolved_args: &mut Vec<SdkValue>,
                                          method_selector_hex: &str,
                                          tx_change_amount: i64| -> Result<(String, String, String), String> {
                let (op_sig, preimage) = compute_op_push_tx_with_code_sep(tx, input_idx, subscript, sats, code_sep_idx)?;

                // Only sign Sig params for extra inputs, not the primary
                if input_idx > 0 {
                    // In stateful contracts, user checkSig is AFTER OP_CODESEPARATOR — trim.
                    let mut sig_subscript = subscript.to_string();
                    if code_sep_idx >= 0 {
                        let trim_pos = ((code_sep_idx as usize) + 1) * 2;
                        if trim_pos <= sig_subscript.len() {
                            sig_subscript = sig_subscript[trim_pos..].to_string();
                        }
                    }
                    for &idx in sig_indices {
                        let real_sig = signer.sign(tx, input_idx, &sig_subscript, sats, None)?;
                        resolved_args[idx] = SdkValue::Bytes(real_sig);
                    }
                }

                // Resolve ByteString params (auto-compute allPrevouts from tx)
                if !prevouts_indices.is_empty() {
                    let all_prevouts_hex = extract_all_prevouts(tx);
                    for &idx in prevouts_indices {
                        resolved_args[idx] = SdkValue::Bytes(all_prevouts_hex.clone());
                    }
                }

                let mut user_args_hex = String::new();
                for arg in resolved_args.iter() {
                    user_args_hex.push_str(&encode_arg(arg));
                }

                // Append change params (PKH + amount) for methods that need them
                let mut change_hex = String::new();
                if method_needs_change && !change_pkh_hex.is_empty() {
                    change_hex.push_str(&encode_push_data(&change_pkh_hex));
                    change_hex.push_str(&encode_arg(&SdkValue::Int(tx_change_amount)));
                }

                let mut new_amount_hex = String::new();
                if method_needs_new_amount {
                    new_amount_hex.push_str(&encode_arg(&SdkValue::Int(new_satoshis.unwrap_or(current_utxo.satoshis))));
                }

                // Build prefix: optionally _codePart + _opPushTxSig
                let mut prefix = String::new();
                if let Some(ref cp) = code_part_for_prefix {
                    prefix.push_str(&encode_push_data(cp));
                }
                prefix.push_str(&encode_push_data(&op_sig));

                let unlock = format!(
                    "{}{}{}{}{}{}",
                    prefix,
                    user_args_hex,
                    change_hex,
                    new_amount_hex,
                    encode_push_data(&preimage),
                    method_selector_hex,
                );

                Ok((unlock, op_sig, preimage))
            };

            // First pass: build unlocking scripts with current tx layout
            let (input0_unlock, _, _) = build_stateful_unlock(
                &signed_tx, 0, &current_utxo.script, current_utxo.satoshis,
                signer, &sig_indices, &prevouts_indices, &mut resolved_args, &method_selector_hex,
                change_amount,
            )?;

            let mut extra_unlocks: Vec<String> = Vec::new();
            for (i, mu) in extra_contract_utxos.iter().enumerate() {
                let mut args_for_input = resolved_per_input_args.as_ref()
                    .and_then(|v| v.get(i))
                    .cloned()
                    .unwrap_or_else(|| resolved_args.clone());
                let (unlock, _, _) = build_stateful_unlock(
                    &signed_tx, i + 1, &mu.script, mu.satoshis,
                    signer, &sig_indices, &prevouts_indices, &mut args_for_input, &method_selector_hex,
                    change_amount,
                )?;
                extra_unlocks.push(unlock);
            }

            // Rebuild TX with real unlocking scripts (sizes may differ from placeholders)
            let rebuild_options = CallTxOptions {
                contract_outputs: contract_outputs.as_ref().map(|cos| {
                    cos.iter().map(|co| ContractOutput { script: co.script.clone(), satoshis: co.satoshis }).collect()
                }),
                additional_contract_inputs: if extra_contract_utxos.is_empty() {
                    None
                } else {
                    Some(extra_contract_utxos.iter().enumerate().map(|(i, utxo)| {
                        AdditionalContractInput {
                            utxo: utxo.clone(),
                            unlocking_script: extra_unlocks[i].clone(),
                        }
                    }).collect())
                },
            };

            let (rebuilt_tx, _, rebuilt_change) = build_call_transaction_ext(
                &current_utxo,
                &input0_unlock,
                new_locking_script.as_deref(),
                new_satoshis,
                change_addr_opt,
                change_script_opt,
                if additional_utxos.is_empty() { None } else { Some(&additional_utxos) },
                Some(fee_rate),
                Some(&rebuild_options),
            );
            signed_tx = rebuilt_tx;
            change_amount = rebuilt_change;

            // Second pass: recompute with final tx (preimage changes with unlock size)
            let (final_input0_unlock, op_sig, preimage) = build_stateful_unlock(
                &signed_tx, 0, &current_utxo.script, current_utxo.satoshis,
                signer, &sig_indices, &prevouts_indices, &mut resolved_args, &method_selector_hex,
                change_amount,
            )?;
            final_op_push_tx_sig = op_sig;
            final_preimage = preimage;
            signed_tx = insert_unlocking_script(&signed_tx, 0, &final_input0_unlock)?;

            for (i, mu) in extra_contract_utxos.iter().enumerate() {
                let mut args_for_input = resolved_per_input_args.as_ref()
                    .and_then(|v| v.get(i))
                    .cloned()
                    .unwrap_or_else(|| resolved_args.clone());
                let (final_merge_unlock, _, _) = build_stateful_unlock(
                    &signed_tx, i + 1, &mu.script, mu.satoshis,
                    signer, &sig_indices, &prevouts_indices, &mut args_for_input, &method_selector_hex,
                    change_amount,
                )?;
                signed_tx = insert_unlocking_script(&signed_tx, i + 1, &final_merge_unlock)?;
            }

            // Re-sign P2PKH funding inputs (outputs changed after rebuild)
            for i in p2pkh_start_idx..input_count {
                if let Some(utxo) = additional_utxos.get(i - p2pkh_start_idx) {
                    let sig = signer.sign(&signed_tx, i, &utxo.script, utxo.satoshis, None)?;
                    let pub_key = signer.get_public_key()?;
                    let unlock_script = format!("{}{}", encode_push_data(&sig), encode_push_data(&pub_key));
                    signed_tx = insert_unlocking_script(&signed_tx, i, &unlock_script)?;
                }
            }
        } else if needs_op_push_tx || !sig_indices.is_empty() {
            // Stateless: keep placeholder sigs, compute OP_PUSH_TX
            if needs_op_push_tx {
                let (sig_hex, preimage_hex) = compute_op_push_tx_with_code_sep(
                    &signed_tx, 0, &current_utxo.script, current_utxo.satoshis, code_sep_idx,
                )?;
                final_op_push_tx_sig = sig_hex;
                if let Some(idx) = preimage_index {
                    resolved_args[idx] = SdkValue::Bytes(preimage_hex);
                }
            }
            // Don't sign Sig params — keep placeholders
            let mut real_unlocking_script = self.build_unlocking_script(method_name, &resolved_args)?;
            if needs_op_push_tx && !final_op_push_tx_sig.is_empty() {
                real_unlocking_script = format!("{}{}", self.build_stateful_prefix(&final_op_push_tx_sig, false), real_unlocking_script);

                let tmp_tx = insert_unlocking_script(&signed_tx, 0, &real_unlocking_script)?;
                let (final_sig, final_pre) = compute_op_push_tx_with_code_sep(
                    &tmp_tx, 0, &current_utxo.script, current_utxo.satoshis, code_sep_idx,
                )?;
                if let Some(idx) = preimage_index {
                    resolved_args[idx] = SdkValue::Bytes(final_pre.clone());
                }
                final_op_push_tx_sig = final_sig;
                final_preimage = final_pre;
                real_unlocking_script = format!(
                    "{}{}",
                    self.build_stateful_prefix(&final_op_push_tx_sig, false),
                    self.build_unlocking_script(method_name, &resolved_args)?
                );
            }
            signed_tx = insert_unlocking_script(&signed_tx, 0, &real_unlocking_script)?;
            if final_preimage.is_empty() && needs_op_push_tx {
                if let Some(idx) = preimage_index {
                    if let SdkValue::Bytes(ref p) = resolved_args[idx] {
                        final_preimage = p.clone();
                    }
                }
            }
        }

        // Compute sighash from preimage (single SHA-256, matching TS behavior)
        let sighash = if !final_preimage.is_empty() {
            let preimage_bytes: Vec<u8> = (0..final_preimage.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&final_preimage[i..i + 2], 16).unwrap_or(0))
                .collect();
            let hash = Sha256::digest(&preimage_bytes);
            hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        } else {
            String::new()
        };

        // Convert contract_outputs to ContractOutputEntry for PreparedCall
        let prepared_contract_outputs: Vec<ContractOutputEntry> = contract_outputs
            .as_ref()
            .map(|cos| cos.iter().map(|co| ContractOutputEntry {
                script: co.script.clone(),
                satoshis: co.satoshis,
            }).collect())
            .unwrap_or_default();

        Ok(PreparedCall {
            sighash,
            preimage: final_preimage,
            op_push_tx_sig: final_op_push_tx_sig,
            tx_hex: signed_tx,
            sig_indices,
            method_name: method_name.to_string(),
            resolved_args,
            method_selector_hex,
            is_stateful,
            is_terminal: false,
            needs_op_push_tx,
            method_needs_change,
            change_pkh_hex,
            change_amount,
            method_needs_new_amount,
            new_amount: new_satoshis.unwrap_or(current_utxo.satoshis),
            preimage_index,
            contract_utxo: current_utxo.clone(),
            new_locking_script: new_locking_script.unwrap_or_default(),
            new_satoshis: new_satoshis.unwrap_or(0),
            has_multi_output,
            contract_outputs: prepared_contract_outputs,
            code_sep_idx,
        })
    }

    /// Complete a prepared call by injecting external signatures and broadcasting.
    ///
    /// `prepared`   — The `PreparedCall` returned by `prepare_call()`.
    /// `signatures` — Map from arg index to DER signature hex (with sighash byte).
    ///                Each key must be one of `prepared.sig_indices`.
    pub fn finalize_call(
        &mut self,
        prepared: &PreparedCall,
        signatures: &HashMap<usize, String>,
        provider: &mut dyn Provider,
    ) -> Result<(String, TransactionData), String> {
        // Replace placeholder sigs with real signatures
        let mut resolved_args = prepared.resolved_args.clone();
        for &idx in &prepared.sig_indices {
            if let Some(sig) = signatures.get(&idx) {
                resolved_args[idx] = SdkValue::Bytes(sig.clone());
            }
        }

        // Assemble the primary unlocking script
        let primary_unlock = if prepared.is_stateful {
            let mut args_hex = String::new();
            for arg in &resolved_args {
                args_hex.push_str(&encode_arg(arg));
            }
            let mut change_hex = String::new();
            if prepared.method_needs_change && !prepared.change_pkh_hex.is_empty() {
                change_hex.push_str(&encode_push_data(&prepared.change_pkh_hex));
                change_hex.push_str(&encode_arg(&SdkValue::Int(prepared.change_amount)));
            }
            let mut new_amount_hex = String::new();
            if prepared.method_needs_new_amount {
                new_amount_hex.push_str(&encode_arg(&SdkValue::Int(prepared.new_amount)));
            }
            format!(
                "{}{}{}{}{}{}",
                self.build_stateful_prefix(&prepared.op_push_tx_sig, prepared.method_needs_change),
                args_hex,
                change_hex,
                new_amount_hex,
                encode_push_data(&prepared.preimage),
                prepared.method_selector_hex,
            )
        } else if prepared.needs_op_push_tx {
            // Stateless with SigHashPreimage: put preimage into resolvedArgs
            if let Some(idx) = prepared.preimage_index {
                resolved_args[idx] = SdkValue::Bytes(prepared.preimage.clone());
            }
            format!(
                "{}{}",
                self.build_stateful_prefix(&prepared.op_push_tx_sig, false),
                self.build_unlocking_script(&prepared.method_name, &resolved_args)?,
            )
        } else {
            self.build_unlocking_script(&prepared.method_name, &resolved_args)?
        };

        // Insert primary unlock into the transaction
        let final_tx = insert_unlocking_script(&prepared.tx_hex, 0, &primary_unlock)?;

        // Broadcast
        let bsv_tx = hex_to_bsv_tx(&final_tx)?;
        let txid = provider.broadcast(&bsv_tx)?;

        // Update tracked UTXO
        if prepared.is_stateful && prepared.has_multi_output && !prepared.contract_outputs.is_empty() {
            self.current_utxo = Some(Utxo {
                txid: txid.clone(),
                output_index: 0,
                satoshis: prepared.contract_outputs[0].satoshis,
                script: prepared.contract_outputs[0].script.clone(),
            });
        } else if prepared.is_stateful && !prepared.new_locking_script.is_empty() {
            self.current_utxo = Some(Utxo {
                txid: txid.clone(),
                output_index: 0,
                satoshis: if prepared.new_satoshis > 0 { prepared.new_satoshis } else { prepared.contract_utxo.satoshis },
                script: prepared.new_locking_script.clone(),
            });
        } else if prepared.is_terminal {
            self.current_utxo = None;
        } else {
            self.current_utxo = None;
        }

        let tx = provider.get_transaction(&txid).unwrap_or_else(|_| {
            TransactionData {
                txid: txid.clone(),
                version: 1,
                inputs: vec![],
                outputs: vec![],
                locktime: 0,
                raw: Some(final_tx),
            }
        });

        Ok((txid, tx))
    }

    // -----------------------------------------------------------------------
    // Terminal method call (prepare path)
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn prepare_call_terminal(
        &mut self,
        method_name: &str,
        resolved_args: &mut Vec<SdkValue>,
        _signer: &dyn Signer,
        _options: Option<&CallOptions>,
        terminal_outputs: &[TerminalOutput],
        current_utxo: &Utxo,
        is_stateful: bool,
        needs_op_push_tx: bool,
        method_needs_change: bool,
        sig_indices: &[usize],
        _prevouts_indices: &[usize],
        preimage_index: Option<usize>,
        method_selector_hex: &str,
        change_pkh_hex: &str,
    ) -> Result<PreparedCall, String> {
        let term_code_sep_idx = self.get_code_sep_index(self.find_method_index(method_name));

        // Build placeholder unlocking script
        // Terminal never needs code part (needsCodePart = false)
        let term_unlock_script = if needs_op_push_tx {
            format!(
                "{}{}",
                self.build_stateful_prefix(&"00".repeat(72), false),
                self.build_unlocking_script(method_name, resolved_args)?
            )
        } else {
            self.build_unlocking_script(method_name, resolved_args)?
        };

        // Build raw transaction: single input (contract UTXO), exact outputs
        let build_terminal_tx = |unlock: &str| -> String {
            let mut tx = String::new();
            tx.push_str(&to_little_endian_32(1)); // version
            tx.push_str(&encode_varint(1)); // 1 input
            tx.push_str(&reverse_hex(&current_utxo.txid));
            tx.push_str(&to_little_endian_32(current_utxo.output_index));
            tx.push_str(&encode_varint((unlock.len() / 2) as u64));
            tx.push_str(unlock);
            tx.push_str("ffffffff");
            tx.push_str(&encode_varint(terminal_outputs.len() as u64));
            for out in terminal_outputs {
                tx.push_str(&to_little_endian_64(out.satoshis));
                tx.push_str(&encode_varint((out.script_hex.len() / 2) as u64));
                tx.push_str(&out.script_hex);
            }
            tx.push_str(&to_little_endian_32(0)); // locktime
            tx
        };

        let mut term_tx = build_terminal_tx(&term_unlock_script);
        let mut final_op_push_tx_sig = String::new();
        let mut final_preimage = String::new();

        if is_stateful {
            // Build stateful terminal unlock with PLACEHOLDER user sigs
            let build_unlock = |tx: &str, args: &Vec<SdkValue>| -> Result<(String, String, String), String> {
                let (op_sig, preimage) = compute_op_push_tx_with_code_sep(tx, 0, &current_utxo.script, current_utxo.satoshis, term_code_sep_idx)?;
                let mut args_hex = String::new();
                for arg in args.iter() {
                    args_hex.push_str(&encode_arg(arg));
                }
                // Terminal: 0 change
                let mut change_hex = String::new();
                if method_needs_change && !change_pkh_hex.is_empty() {
                    change_hex.push_str(&encode_push_data(change_pkh_hex));
                    change_hex.push_str(&encode_arg(&SdkValue::Int(0)));
                }
                // Terminal never needs code part
                let unlock = format!(
                    "{}{}{}{}{}",
                    encode_push_data(&op_sig),
                    args_hex,
                    change_hex,
                    encode_push_data(&preimage),
                    method_selector_hex,
                );
                Ok((unlock, op_sig, preimage))
            };

            // First pass
            let (first_unlock, _, _) = build_unlock(&term_tx, resolved_args)?;
            term_tx = build_terminal_tx(&first_unlock);

            // Second pass: recompute with final tx
            let (second_unlock, op_sig, preimage) = build_unlock(&term_tx, resolved_args)?;
            term_tx = insert_unlocking_script(&term_tx, 0, &second_unlock)?;
            final_op_push_tx_sig = op_sig;
            final_preimage = preimage;
        } else if needs_op_push_tx || !sig_indices.is_empty() {
            // Stateless terminal — keep placeholder sigs
            if needs_op_push_tx {
                let (sig_hex, preimage_hex) = compute_op_push_tx_with_code_sep(
                    &term_tx, 0, &current_utxo.script, current_utxo.satoshis, term_code_sep_idx,
                )?;
                final_op_push_tx_sig = sig_hex;
                if let Some(idx) = preimage_index {
                    resolved_args[idx] = SdkValue::Bytes(preimage_hex);
                }
            }
            // Don't sign Sig params — keep 72-byte placeholders
            let mut real_unlock = self.build_unlocking_script(method_name, resolved_args)?;
            if needs_op_push_tx && !final_op_push_tx_sig.is_empty() {
                real_unlock = format!("{}{}", self.build_stateful_prefix(&final_op_push_tx_sig, false), real_unlock);
                let tmp_tx = insert_unlocking_script(&term_tx, 0, &real_unlock)?;
                let (final_sig, final_pre) = compute_op_push_tx_with_code_sep(
                    &tmp_tx, 0, &current_utxo.script, current_utxo.satoshis, term_code_sep_idx,
                )?;
                if let Some(idx) = preimage_index {
                    resolved_args[idx] = SdkValue::Bytes(final_pre.clone());
                }
                final_op_push_tx_sig = final_sig;
                final_preimage = final_pre;
                real_unlock = format!(
                    "{}{}",
                    self.build_stateful_prefix(&final_op_push_tx_sig, false),
                    self.build_unlocking_script(method_name, resolved_args)?
                );
            }
            term_tx = insert_unlocking_script(&term_tx, 0, &real_unlock)?;
            if final_preimage.is_empty() && needs_op_push_tx {
                if let Some(idx) = preimage_index {
                    if let SdkValue::Bytes(ref p) = resolved_args[idx] {
                        final_preimage = p.clone();
                    }
                }
            }
        }

        // Compute sighash from preimage (single SHA-256)
        let sighash = if !final_preimage.is_empty() {
            let preimage_bytes: Vec<u8> = (0..final_preimage.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&final_preimage[i..i + 2], 16).unwrap_or(0))
                .collect();
            let hash = Sha256::digest(&preimage_bytes);
            hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        } else {
            String::new()
        };

        Ok(PreparedCall {
            sighash,
            preimage: final_preimage,
            op_push_tx_sig: final_op_push_tx_sig,
            tx_hex: term_tx,
            sig_indices: sig_indices.to_vec(),
            method_name: method_name.to_string(),
            resolved_args: resolved_args.clone(),
            method_selector_hex: method_selector_hex.to_string(),
            is_stateful,
            is_terminal: true,
            needs_op_push_tx,
            method_needs_change,
            change_pkh_hex: change_pkh_hex.to_string(),
            change_amount: 0,
            method_needs_new_amount: false,
            new_amount: 0,
            preimage_index,
            contract_utxo: current_utxo.clone(),
            new_locking_script: String::new(),
            new_satoshis: 0,
            has_multi_output: false,
            contract_outputs: vec![],
            code_sep_idx: term_code_sep_idx,
        })
    }

    // -----------------------------------------------------------------------
    // State access
    // -----------------------------------------------------------------------

    /// Get the current contract state (for stateful contracts).
    pub fn state(&self) -> &HashMap<String, SdkValue> {
        &self.state
    }

    /// Update state values directly (for stateful contracts).
    pub fn set_state(&mut self, new_state: HashMap<String, SdkValue>) {
        for (k, v) in new_state {
            self.state.insert(k, v);
        }
    }

    // -----------------------------------------------------------------------
    // Script construction
    // -----------------------------------------------------------------------

    /// Get the full locking script hex for the contract.
    ///
    /// For stateful contracts this includes the code followed by OP_RETURN and
    /// the serialized state fields.
    pub fn get_locking_script(&self) -> String {
        // Use stored code script from chain if available (reconnected contract)
        let mut script = self
            .code_script
            .clone()
            .unwrap_or_else(|| self.build_code_script());

        // Append state section for stateful contracts
        if let Some(ref state_fields) = self.artifact.state_fields {
            if !state_fields.is_empty() {
                let state_hex = serialize_state(state_fields, &self.state);
                if !state_hex.is_empty() {
                    script.push_str("6a"); // OP_RETURN
                    script.push_str(&state_hex);
                }
            }
        }

        script
    }

    /// Build the code portion of the locking script from the artifact and
    /// constructor args. This is the script without any state suffix.
    fn build_code_script(&self) -> String {
        let mut script = self.artifact.script.clone();

        if let Some(ref slots) = self.artifact.constructor_slots {
            if !slots.is_empty() {
                // Sort by byteOffset descending so splicing doesn't shift later offsets
                let mut sorted_slots = slots.clone();
                sorted_slots.sort_by(|a, b| b.byte_offset.cmp(&a.byte_offset));

                for slot in &sorted_slots {
                    let encoded = encode_arg(&self.constructor_args[slot.param_index]);
                    let hex_offset = slot.byte_offset * 2;
                    // Replace the 1-byte OP_0 placeholder (2 hex chars) with the encoded arg
                    let before = &script[..hex_offset];
                    let after = &script[hex_offset + 2..];
                    script = format!("{}{}{}", before, encoded, after);
                }

                return script;
            }
        }

        // Backward compatibility: old stateless artifacts without constructorSlots.
        // For stateful contracts, constructor args initialize the state section
        // (after OP_RETURN), not the code portion.
        let is_stateful = self
            .artifact
            .state_fields
            .as_ref()
            .map_or(false, |f| !f.is_empty());
        if !is_stateful {
            for arg in &self.constructor_args {
                script.push_str(&encode_arg(arg));
            }
        }

        script
    }

    /// Build the unlocking script for a method call.
    ///
    /// The unlocking script pushes the method arguments onto the stack in
    /// order, followed by a method selector (the method index as a Script
    /// number) if the contract has multiple public methods.
    pub fn build_unlocking_script(
        &self,
        method_name: &str,
        args: &[SdkValue],
    ) -> Result<String, String> {
        let mut script = String::new();

        // Push each argument
        for arg in args {
            script.push_str(&encode_arg(arg));
        }

        // If there are multiple public methods, push the method selector
        let public_methods: Vec<&AbiMethod> = self
            .artifact
            .abi
            .methods
            .iter()
            .filter(|m| m.is_public)
            .collect();

        if public_methods.len() > 1 {
            let method_index = public_methods
                .iter()
                .position(|m| m.name == method_name)
                .ok_or_else(|| {
                    format!(
                        "buildUnlockingScript: public method '{}' not found",
                        method_name
                    )
                })?;
            script.push_str(&encode_script_number(method_index as i64));
        }

        Ok(script)
    }

    // -----------------------------------------------------------------------
    // Reconnection
    // -----------------------------------------------------------------------

    /// Reconnect to an existing deployed contract from its deployment transaction.
    pub fn from_txid(
        artifact: RunarArtifact,
        txid: &str,
        output_index: usize,
        provider: &dyn Provider,
    ) -> Result<Self, String> {
        let tx = provider.get_transaction(txid)?;

        if output_index >= tx.outputs.len() {
            return Err(format!(
                "RunarContract.fromTxId: output index {} out of range (tx has {} outputs)",
                output_index,
                tx.outputs.len()
            ));
        }

        let output = &tx.outputs[output_index];

        // Dummy constructor args -- we store the on-chain code script directly
        // so these won't be used in get_locking_script().
        let dummy_args: Vec<SdkValue> = artifact
            .abi
            .constructor
            .params
            .iter()
            .map(|_| SdkValue::Int(0))
            .collect();

        let mut contract = RunarContract::new(artifact, dummy_args);

        // Store the code portion of the on-chain script.
        // Use opcode-aware walking to find the real OP_RETURN (not a 0x6a
        // byte inside push data).
        if let Some(ref state_fields) = contract.artifact.state_fields {
            if !state_fields.is_empty() {
                // Stateful: code is everything before the last OP_RETURN
                let last_op_return = find_last_op_return(&output.script);
                contract.code_script = Some(
                    last_op_return
                        .map(|pos| output.script[..pos].to_string())
                        .unwrap_or_else(|| output.script.clone()),
                );
            } else {
                contract.code_script = Some(output.script.clone());
            }
        } else {
            // Stateless: the full on-chain script IS the code
            contract.code_script = Some(output.script.clone());
        }

        // Set the current UTXO
        contract.current_utxo = Some(Utxo {
            txid: txid.to_string(),
            output_index: output_index as u32,
            satoshis: output.satoshis,
            script: output.script.clone(),
        });

        // Extract state if this is a stateful contract
        if let Some(ref state_fields) = contract.artifact.state_fields {
            if !state_fields.is_empty() {
                if let Some(state) = extract_state_from_script(&contract.artifact, &output.script)
                {
                    contract.state = state;
                }
            }
        }

        Ok(contract)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn find_method(&self, name: &str) -> Option<AbiMethod> {
        self.artifact
            .abi
            .methods
            .iter()
            .find(|m| m.name == name && m.is_public)
            .cloned()
    }

    /// Get the code part hex (code script without state).
    fn get_code_part_hex(&self) -> String {
        self.code_script.clone().unwrap_or_else(|| self.build_code_script())
    }

    /// Adjust code separator byte offset for constructor arg substitution.
    fn adjust_code_sep_offset(&self, base_offset: usize) -> usize {
        if let Some(ref slots) = self.artifact.constructor_slots {
            let mut shift: isize = 0;
            for slot in slots {
                if slot.byte_offset < base_offset {
                    let encoded = encode_arg(&self.constructor_args[slot.param_index]);
                    shift += (encoded.len() / 2) as isize - 1; // encoded bytes minus 1-byte placeholder
                }
            }
            (base_offset as isize + shift) as usize
        } else {
            base_offset
        }
    }

    /// Get the adjusted code separator index for a method.
    fn get_code_sep_index(&self, method_index: usize) -> i64 {
        if let Some(ref indices) = self.artifact.code_separator_indices {
            if method_index < indices.len() {
                return self.adjust_code_sep_offset(indices[method_index]) as i64;
            }
        }
        if let Some(idx) = self.artifact.code_separator_index {
            return self.adjust_code_sep_offset(idx) as i64;
        }
        -1
    }

    /// Whether the artifact has OP_CODESEPARATOR.
    fn has_code_separator(&self) -> bool {
        self.artifact.code_separator_index.is_some()
            || self.artifact.code_separator_indices.as_ref().map_or(false, |v| !v.is_empty())
    }

    /// Build the prefix for a stateful unlocking script: optionally _codePart + _opPushTxSig.
    fn build_stateful_prefix(&self, op_sig_hex: &str, needs_code_part: bool) -> String {
        let mut prefix = String::new();
        if needs_code_part && self.has_code_separator() {
            prefix.push_str(&encode_push_data(&self.get_code_part_hex()));
        }
        prefix.push_str(&encode_push_data(op_sig_hex));
        prefix
    }

    /// Find the public method index for a method name, or 0 if not found.
    fn find_method_index(&self, name: &str) -> usize {
        let public_methods: Vec<&AbiMethod> = self.artifact.abi.methods.iter().filter(|m| m.is_public).collect();
        public_methods.iter().position(|m| m.name == name).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Extract all input outpoints from a raw tx hex as a concatenated hex string.
/// Each outpoint is txid (32 bytes LE) + vout (4 bytes LE) = 36 bytes.
fn extract_all_prevouts(tx_hex: &str) -> String {
    let bytes: Vec<u8> = (0..tx_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&tx_hex[i..i + 2], 16).unwrap_or(0))
        .collect();
    let mut offset = 4; // skip version (4 bytes)
    // Read varint for input count
    let (input_count, varint_size) = read_varint_bytes(&bytes, offset);
    offset += varint_size;

    let mut prevouts = String::new();
    for _ in 0..input_count {
        // txid (32 bytes) + vout (4 bytes) = 36 bytes of outpoint
        for b in &bytes[offset..offset + 36] {
            prevouts.push_str(&format!("{:02x}", b));
        }
        offset += 36; // skip outpoint
        // Read script length varint
        let (script_len, vsize) = read_varint_bytes(&bytes, offset);
        offset += vsize;
        offset += script_len as usize; // skip script
        offset += 4; // skip sequence
    }
    prevouts
}

fn read_varint_bytes(bytes: &[u8], offset: usize) -> (u64, usize) {
    let first = bytes[offset];
    if first < 0xfd {
        (first as u64, 1)
    } else if first == 0xfd {
        let val = (bytes[offset + 1] as u64) | ((bytes[offset + 2] as u64) << 8);
        (val, 3)
    } else if first == 0xfe {
        let val = (bytes[offset + 1] as u64)
            | ((bytes[offset + 2] as u64) << 8)
            | ((bytes[offset + 3] as u64) << 16)
            | ((bytes[offset + 4] as u64) << 24);
        (val, 5)
    } else {
        // 0xff: 8-byte varint (unlikely for tx input counts)
        (0, 9)
    }
}

/// Encode an argument value as a Bitcoin Script push data element.
fn encode_arg(value: &SdkValue) -> String {
    match value {
        SdkValue::Int(n) => encode_script_number(*n),
        SdkValue::Bool(b) => {
            if *b {
                "51".to_string() // OP_TRUE
            } else {
                "00".to_string() // OP_FALSE
            }
        }
        SdkValue::Bytes(hex) => {
            if hex.is_empty() {
                "00".to_string() // OP_0
            } else {
                encode_push_data(hex)
            }
        }
        SdkValue::Auto => {
            panic!("encode_arg: SdkValue::Auto should be resolved before encoding")
        }
    }
}

/// Encode an integer as a Bitcoin Script number opcode or push data.
fn encode_script_number(n: i64) -> String {
    if n == 0 {
        return "00".to_string(); // OP_0
    }
    if n >= 1 && n <= 16 {
        // OP_1 through OP_16
        return format!("{:02x}", 0x50 + n as u8);
    }
    if n == -1 {
        return "4f".to_string(); // OP_1NEGATE
    }

    let negative = n < 0;
    let mut abs_val = if negative { -(n as i128) } else { n as i128 } as u64;
    let mut bytes = Vec::new();

    while abs_val > 0 {
        bytes.push((abs_val & 0xff) as u8);
        abs_val >>= 8;
    }

    if (bytes.last().unwrap() & 0x80) != 0 {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = bytes.len() - 1;
        bytes[last] |= 0x80;
    }

    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    encode_push_data(&hex)
}

/// Insert an unlocking script into a raw transaction at a specific input index.
fn insert_unlocking_script(
    tx_hex: &str,
    input_index: usize,
    unlock_script: &str,
) -> Result<String, String> {
    let mut pos = 0;

    // Skip version (4 bytes = 8 hex chars)
    pos += 8;

    // Read input count
    let (input_count, ic_len) = read_varint_hex(tx_hex, pos);
    pos += ic_len;

    if input_index >= input_count as usize {
        return Err(format!(
            "insertUnlockingScript: input index {} out of range ({} inputs)",
            input_index, input_count
        ));
    }

    for i in 0..input_count as usize {
        // Skip prevTxid (32 bytes = 64 hex chars)
        pos += 64;
        // Skip prevOutputIndex (4 bytes = 8 hex chars)
        pos += 8;

        // Read scriptSig length
        let (script_len, sl_len) = read_varint_hex(tx_hex, pos);

        if i == input_index {
            // Build the replacement: new varint length + new script data
            let new_script_byte_len = unlock_script.len() / 2;
            let new_var_int = encode_varint(new_script_byte_len as u64);

            let before = &tx_hex[..pos];
            let after = &tx_hex[pos + sl_len + script_len as usize * 2..];
            return Ok(format!("{}{}{}{}", before, new_var_int, unlock_script, after));
        }

        // Skip this input's scriptSig + sequence (4 bytes = 8 hex chars)
        pos += sl_len + script_len as usize * 2 + 8;
    }

    Err(format!(
        "insertUnlockingScript: input index {} out of range",
        input_index
    ))
}

/// Read a Bitcoin varint from a hex string at the given position.
/// Returns the decoded value and the number of hex characters consumed.
fn read_varint_hex(hex: &str, pos: usize) -> (u64, usize) {
    let first = u8::from_str_radix(&hex[pos..pos + 2], 16).unwrap_or(0);
    if first < 0xfd {
        (first as u64, 2)
    } else if first == 0xfd {
        let lo = u8::from_str_radix(&hex[pos + 2..pos + 4], 16).unwrap_or(0) as u64;
        let hi = u8::from_str_radix(&hex[pos + 4..pos + 6], 16).unwrap_or(0) as u64;
        (lo | (hi << 8), 6)
    } else if first == 0xfe {
        let b0 = u8::from_str_radix(&hex[pos + 2..pos + 4], 16).unwrap_or(0) as u64;
        let b1 = u8::from_str_radix(&hex[pos + 4..pos + 6], 16).unwrap_or(0) as u64;
        let b2 = u8::from_str_radix(&hex[pos + 6..pos + 8], 16).unwrap_or(0) as u64;
        let b3 = u8::from_str_radix(&hex[pos + 8..pos + 10], 16).unwrap_or(0) as u64;
        (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24), 10)
    } else {
        // 0xff -- 8-byte varint; handle low 4 bytes
        let b0 = u8::from_str_radix(&hex[pos + 2..pos + 4], 16).unwrap_or(0) as u64;
        let b1 = u8::from_str_radix(&hex[pos + 4..pos + 6], 16).unwrap_or(0) as u64;
        let b2 = u8::from_str_radix(&hex[pos + 6..pos + 8], 16).unwrap_or(0) as u64;
        let b3 = u8::from_str_radix(&hex[pos + 8..pos + 10], 16).unwrap_or(0) as u64;
        (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24), 18)
    }
}

/// Revive a JSON value that may have been serialized as a BigInt string
/// ("0n", "1000n", "-42n") when the artifact JSON was loaded without a
/// BigInt reviver (e.g. via standard `serde_json::from_str`).
fn revive_json_value(value: &serde_json::Value, field_type: &str) -> SdkValue {
    match (field_type, value) {
        ("int" | "bigint", serde_json::Value::String(s)) => {
            let num_str = if s.ends_with('n') { &s[..s.len() - 1] } else { s.as_str() };
            let n: i64 = num_str.parse().unwrap_or(0);
            SdkValue::Int(n)
        }
        ("int" | "bigint", serde_json::Value::Number(n)) => {
            SdkValue::Int(n.as_i64().unwrap_or(0))
        }
        ("bool", serde_json::Value::Bool(b)) => SdkValue::Bool(*b),
        ("bool", serde_json::Value::String(s)) => SdkValue::Bool(s == "true"),
        (_, serde_json::Value::String(s)) => SdkValue::Bytes(s.clone()),
        _ => SdkValue::Int(0),
    }
}

/// Build a named-args map from user ABI params and resolved arg values.
fn build_named_args(
    user_params: &[&AbiParam],
    resolved_args: &[SdkValue],
) -> HashMap<String, SdkValue> {
    let mut named = HashMap::new();
    for (i, param) in user_params.iter().enumerate() {
        if let Some(val) = resolved_args.get(i) {
            named.insert(param.name.clone(), val.clone());
        }
    }
    named
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::provider::MockProvider;
    use super::super::signer::MockSigner;
    use super::super::state::serialize_state;

    fn make_artifact(script: &str, abi: Abi) -> RunarArtifact {
        RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi,
            script: script.to_string(),
            state_fields: None,
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        }
    }

    fn simple_abi() -> Abi {
        Abi {
            constructor: AbiConstructor { params: vec![] },
            methods: vec![],
        }
    }

    fn abi_with_methods(methods: Vec<AbiMethod>) -> Abi {
        Abi {
            constructor: AbiConstructor { params: vec![] },
            methods,
        }
    }

    fn make_tx(txid: &str, outputs: Vec<TxOutput>) -> TransactionData {
        TransactionData {
            txid: txid.to_string(),
            version: 1,
            inputs: vec![TxInput {
                txid: "00".repeat(32),
                output_index: 0,
                script: String::new(),
                sequence: 0xffff_ffff,
            }],
            outputs,
            locktime: 0,
            raw: None,
        }
    }

    // -----------------------------------------------------------------------
    // Constructor arg validation
    // -----------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "expected 1 constructor args")]
    fn panics_on_wrong_constructor_arg_count() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![AbiParam {
                        name: "x".to_string(),
                        param_type: "bigint".to_string(),
                    }],
                },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: None,
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };
        RunarContract::new(artifact, vec![]);
    }

    // -----------------------------------------------------------------------
    // Constructor slot splicing
    // -----------------------------------------------------------------------

    #[test]
    fn splices_addr_at_correct_offset() {
        let pub_key_hash = "18f5bdad6dac9a0a5044a970edf2897d67a7562d";
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "P2PKH".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![AbiParam {
                        name: "pubKeyHash".to_string(),
                        param_type: "Addr".to_string(),
                    }],
                },
                methods: vec![AbiMethod {
                    name: "unlock".to_string(),
                    params: vec![],
                    is_public: true,
                }],
            },
            script: "76a90088ac".to_string(),
            state_fields: None,
            constructor_slots: Some(vec![ConstructorSlot {
                param_index: 0,
                byte_offset: 2,
            }]),
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(
            artifact,
            vec![SdkValue::Bytes(pub_key_hash.to_string())],
        );
        let ls = contract.get_locking_script();

        // Expected: 76 a9 14 <20 bytes> 88 ac
        assert_eq!(ls, format!("76a914{}88ac", pub_key_hash));
    }

    #[test]
    fn splices_multiple_constructor_args() {
        let pk1 = "aa".repeat(33);
        let pk2 = "bb".repeat(33);
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "TwoKeys".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![
                        AbiParam { name: "pk1".to_string(), param_type: "PubKey".to_string() },
                        AbiParam { name: "pk2".to_string(), param_type: "PubKey".to_string() },
                    ],
                },
                methods: vec![AbiMethod { name: "unlock".to_string(), params: vec![], is_public: true }],
            },
            script: "007c00ac".to_string(),
            state_fields: None,
            constructor_slots: Some(vec![
                ConstructorSlot { param_index: 0, byte_offset: 0 },
                ConstructorSlot { param_index: 1, byte_offset: 2 },
            ]),
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(
            artifact,
            vec![SdkValue::Bytes(pk1.clone()), SdkValue::Bytes(pk2.clone())],
        );
        let ls = contract.get_locking_script();

        // 21 = 33 in hex (length prefix for 33 bytes)
        let expected = format!("21{}7c21{}ac", pk1, pk2);
        assert_eq!(ls, expected);
    }

    #[test]
    fn fallback_append_without_constructor_slots() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![AbiParam {
                        name: "pubKeyHash".to_string(),
                        param_type: "Addr".to_string(),
                    }],
                },
                methods: vec![AbiMethod { name: "unlock".to_string(), params: vec![], is_public: true }],
            },
            script: "76a90088ac".to_string(),
            state_fields: None,
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let pub_key_hash = "ab".repeat(20);
        let contract = RunarContract::new(
            artifact,
            vec![SdkValue::Bytes(pub_key_hash.clone())],
        );
        let ls = contract.get_locking_script();

        // Old behavior: args appended to end of script
        let encoded_hash = format!("14{}", pub_key_hash);
        assert_eq!(ls, format!("76a90088ac{}", encoded_hash));
    }

    #[test]
    fn splices_bigint_constructor_arg() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![AbiParam {
                        name: "threshold".to_string(),
                        param_type: "bigint".to_string(),
                    }],
                },
                methods: vec![AbiMethod { name: "check".to_string(), params: vec![], is_public: true }],
            },
            script: "009c69".to_string(),
            state_fields: None,
            constructor_slots: Some(vec![ConstructorSlot { param_index: 0, byte_offset: 0 }]),
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(artifact, vec![SdkValue::Int(1000)]);
        let ls = contract.get_locking_script();

        // 1000 = 0x03E8 -> LE: e8 03 -> push 2 bytes: 02 e8 03
        assert_eq!(ls, "02e8039c69");
    }

    #[test]
    fn does_not_corrupt_legitimate_op0() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![AbiParam { name: "x".to_string(), param_type: "bigint".to_string() }],
                },
                methods: vec![AbiMethod { name: "check".to_string(), params: vec![], is_public: true }],
            },
            script: "00930088".to_string(),
            state_fields: None,
            constructor_slots: Some(vec![ConstructorSlot { param_index: 0, byte_offset: 2 }]),
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(artifact, vec![SdkValue::Int(42)]);
        let ls = contract.get_locking_script();

        // 42 = 0x2a -> 01 2a
        assert_eq!(ls, "0093012a88");
    }

    // -----------------------------------------------------------------------
    // Unlocking script — method selector
    // -----------------------------------------------------------------------

    #[test]
    fn no_selector_for_single_public_method() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "unlock".to_string(), params: vec![AbiParam { name: "sig".to_string(), param_type: "Sig".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        let sig = "aa".repeat(72);
        let script = contract.build_unlocking_script("unlock", &[SdkValue::Bytes(sig.clone())]).unwrap();
        // 72 bytes = 0x48 push prefix
        assert_eq!(script, format!("48{}", sig));
    }

    #[test]
    fn selector_op0_for_index_0() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "release".to_string(), params: vec![], is_public: true },
            AbiMethod { name: "refund".to_string(), params: vec![], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        let script = contract.build_unlocking_script("release", &[]).unwrap();
        assert_eq!(script, "00"); // OP_0
    }

    #[test]
    fn selector_op1_for_index_1() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "release".to_string(), params: vec![], is_public: true },
            AbiMethod { name: "refund".to_string(), params: vec![], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        let script = contract.build_unlocking_script("refund", &[]).unwrap();
        assert_eq!(script, "51"); // OP_1
    }

    #[test]
    fn selector_skips_private_methods() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "release".to_string(), params: vec![], is_public: true },
            AbiMethod { name: "_helper".to_string(), params: vec![], is_public: false },
            AbiMethod { name: "refund".to_string(), params: vec![], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        // 'refund' is public method index 1 (skipping private)
        let script = contract.build_unlocking_script("refund", &[]).unwrap();
        assert_eq!(script, "51"); // OP_1
    }

    #[test]
    fn unlocking_script_unknown_method() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "release".to_string(), params: vec![], is_public: true },
            AbiMethod { name: "refund".to_string(), params: vec![], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert!(contract.build_unlocking_script("nonexistent", &[]).is_err());
    }

    // -----------------------------------------------------------------------
    // Argument encoding
    // -----------------------------------------------------------------------

    #[test]
    fn encodes_bigint_0_as_op0() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "n".to_string(), param_type: "bigint".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Int(0)]).unwrap(), "00");
    }

    #[test]
    fn encodes_bigint_1_to_16_as_opcodes() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "n".to_string(), param_type: "bigint".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Int(1)]).unwrap(), "51");
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Int(5)]).unwrap(), "55");
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Int(16)]).unwrap(), "60");
    }

    #[test]
    fn encodes_neg1_as_op1negate() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "n".to_string(), param_type: "bigint".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Int(-1)]).unwrap(), "4f");
    }

    #[test]
    fn encodes_1000_as_push_data() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "n".to_string(), param_type: "bigint".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Int(1000)]).unwrap(), "02e803");
    }

    #[test]
    fn encodes_neg42_with_sign_bit() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "n".to_string(), param_type: "bigint".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Int(-42)]).unwrap(), "01aa");
    }

    #[test]
    fn encodes_20_byte_hex_with_14_prefix() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "h".to_string(), param_type: "Addr".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        let addr = "aa".repeat(20);
        let script = contract.build_unlocking_script("check", &[SdkValue::Bytes(addr.clone())]).unwrap();
        assert_eq!(script, format!("14{}", addr));
    }

    #[test]
    fn encodes_33_byte_hex_with_21_prefix() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "pk".to_string(), param_type: "PubKey".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        let pubkey = "bb".repeat(33);
        let script = contract.build_unlocking_script("check", &[SdkValue::Bytes(pubkey.clone())]).unwrap();
        assert_eq!(script, format!("21{}", pubkey));
    }

    #[test]
    fn encodes_bool_true() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "flag".to_string(), param_type: "bool".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Bool(true)]).unwrap(), "51");
    }

    #[test]
    fn encodes_bool_false() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "check".to_string(), params: vec![AbiParam { name: "flag".to_string(), param_type: "bool".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.build_unlocking_script("check", &[SdkValue::Bool(false)]).unwrap(), "00");
    }

    // -----------------------------------------------------------------------
    // Args with method selector
    // -----------------------------------------------------------------------

    #[test]
    fn args_then_selector() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "release".to_string(), params: vec![AbiParam { name: "sig".to_string(), param_type: "Sig".to_string() }], is_public: true },
            AbiMethod { name: "refund".to_string(), params: vec![AbiParam { name: "sig".to_string(), param_type: "Sig".to_string() }], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        let sig = "cc".repeat(71);
        let script = contract.build_unlocking_script("release", &[SdkValue::Bytes(sig.clone())]).unwrap();
        // sig push: 71 bytes = 0x47, then method index 0 -> OP_0 (0x00)
        assert_eq!(script, format!("47{}00", sig));
    }

    #[test]
    fn three_methods_correct_indices() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "a".to_string(), params: vec![], is_public: true },
            AbiMethod { name: "b".to_string(), params: vec![], is_public: true },
            AbiMethod { name: "c".to_string(), params: vec![], is_public: true },
        ]));
        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.build_unlocking_script("a", &[]).unwrap(), "00");
        assert_eq!(contract.build_unlocking_script("b", &[]).unwrap(), "51");
        assert_eq!(contract.build_unlocking_script("c", &[]).unwrap(), "52");
    }

    // -----------------------------------------------------------------------
    // Deploy / call lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn deploy_broadcasts_transaction() {
        let artifact = make_artifact("51", simple_abi());
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        provider.add_utxo(&address, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        let (txid, _tx) = contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        }).unwrap();

        assert_eq!(txid.len(), 64);
        assert_eq!(provider.get_broadcasted_txs().len(), 1);
    }

    #[test]
    fn deploy_tracks_utxo_for_call() {
        let artifact = make_artifact(
            "51",
            abi_with_methods(vec![AbiMethod {
                name: "spend".to_string(),
                params: vec![],
                is_public: true,
            }]),
        );
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        provider.add_utxo(&address, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        }).unwrap();

        // Call should succeed (not throw "not deployed")
        let result = contract.call("spend", &[], &mut provider, &signer, None);
        assert!(result.is_ok());
    }

    #[test]
    fn deploy_fails_no_utxos() {
        let artifact = make_artifact("51", simple_abi());
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();

        let result = contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no UTXOs"));
    }

    // Row 332: Error on insufficient funds — a UTXO that is too small to
    // cover both the requested satoshis and the fee causes a panic from
    // build_deploy_transaction.
    #[test]
    #[should_panic(expected = "insufficient funds")]
    fn deploy_fails_insufficient_funds() {
        let artifact = make_artifact("51", simple_abi());
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        // Add a UTXO that is far too small (1 satoshi) to fund a 50_000-sat deployment.
        provider.add_utxo(&address, Utxo {
            txid: "cc".repeat(32),
            output_index: 0,
            satoshis: 1,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        // This will panic inside build_deploy_transaction with "insufficient funds".
        let _ = contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        });
    }

    #[test]
    fn call_fails_not_deployed() {
        let artifact = make_artifact(
            "51",
            abi_with_methods(vec![AbiMethod {
                name: "spend".to_string(),
                params: vec![],
                is_public: true,
            }]),
        );
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();

        let result = contract.call("spend", &[], &mut provider, &signer, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not deployed"));
    }

    #[test]
    fn call_fails_unknown_method() {
        let artifact = make_artifact(
            "51",
            abi_with_methods(vec![AbiMethod {
                name: "spend".to_string(),
                params: vec![],
                is_public: true,
            }]),
        );
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        provider.add_utxo(&address, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        }).unwrap();

        let result = contract.call("nonexistent", &[], &mut provider, &signer, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn call_fails_wrong_arg_count() {
        let artifact = make_artifact(
            "51",
            abi_with_methods(vec![AbiMethod {
                name: "transfer".to_string(),
                params: vec![
                    AbiParam { name: "to".to_string(), param_type: "Addr".to_string() },
                    AbiParam { name: "amount".to_string(), param_type: "bigint".to_string() },
                ],
                is_public: true,
            }]),
        );
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        provider.add_utxo(&address, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        }).unwrap();

        let result = contract.call(
            "transfer",
            &[SdkValue::Bytes("deadbeef".repeat(5))],
            &mut provider,
            &signer,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expects 2 args, got 1"));
    }

    // -----------------------------------------------------------------------
    // fromTxId
    // -----------------------------------------------------------------------

    #[test]
    fn from_txid_stateful_extracts_state() {
        let state_fields = vec![
            StateField { name: "count".to_string(), field_type: "bigint".to_string(), index: 0, initial_value: None },
            StateField { name: "active".to_string(), field_type: "bool".to_string(), index: 1, initial_value: None },
        ];

        let code_hex = "76a988ac";
        let state_values = {
            let mut m = HashMap::new();
            m.insert("count".to_string(), SdkValue::Int(42));
            m.insert("active".to_string(), SdkValue::Bool(true));
            m
        };
        let state_hex = serialize_state(&state_fields, &state_values);
        let full_script = format!("{}6a{}", code_hex, state_hex);

        let mut provider = MockProvider::testnet();
        let fake_txid = "aa".repeat(32);
        provider.add_transaction(make_tx(
            &fake_txid,
            vec![TxOutput { satoshis: 10_000, script: full_script }],
        ));

        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![
                        AbiParam { name: "count".to_string(), param_type: "bigint".to_string() },
                        AbiParam { name: "active".to_string(), param_type: "bool".to_string() },
                    ],
                },
                methods: vec![],
            },
            script: code_hex.to_string(),
            state_fields: Some(state_fields),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::from_txid(artifact, &fake_txid, 0, &provider).unwrap();
        assert_eq!(contract.state()["count"], SdkValue::Int(42));
        assert_eq!(contract.state()["active"], SdkValue::Bool(true));
    }

    #[test]
    fn from_txid_stateless() {
        let mut provider = MockProvider::testnet();
        let fake_txid = "aa".repeat(32);
        provider.add_transaction(make_tx(
            &fake_txid,
            vec![TxOutput { satoshis: 5_000, script: "51".to_string() }],
        ));

        let artifact = make_artifact(
            "51",
            abi_with_methods(vec![AbiMethod {
                name: "spend".to_string(),
                params: vec![],
                is_public: true,
            }]),
        );

        let contract = RunarContract::from_txid(artifact, &fake_txid, 0, &provider).unwrap();
        assert!(contract.state().is_empty());
    }

    #[test]
    fn from_txid_out_of_range() {
        let mut provider = MockProvider::testnet();
        let fake_txid = "aa".repeat(32);
        provider.add_transaction(make_tx(
            &fake_txid,
            vec![TxOutput { satoshis: 5_000, script: "51".to_string() }],
        ));

        let artifact = make_artifact("51", simple_abi());
        let result = RunarContract::from_txid(artifact, &fake_txid, 5, &provider);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of range"));
    }

    #[test]
    fn from_txid_unknown_txid() {
        let provider = MockProvider::testnet();
        let artifact = make_artifact("51", simple_abi());
        let unknown_txid = "ff".repeat(32);
        let result = RunarContract::from_txid(artifact, &unknown_txid, 0, &provider);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    // -----------------------------------------------------------------------
    // State access
    // -----------------------------------------------------------------------

    #[test]
    fn set_state_updates_values() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![AbiParam { name: "count".to_string(), param_type: "bigint".to_string() }],
                },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(vec![StateField { name: "count".to_string(), field_type: "bigint".to_string(), index: 0, initial_value: None }]),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
        assert_eq!(contract.state()["count"], SdkValue::Int(0));

        let mut new_state = HashMap::new();
        new_state.insert("count".to_string(), SdkValue::Int(42));
        contract.set_state(new_state);
        assert_eq!(contract.state()["count"], SdkValue::Int(42));
    }

    // -----------------------------------------------------------------------
    // State initialization with mismatched param/field names
    // -----------------------------------------------------------------------

    #[test]
    fn initializes_state_by_index_not_name() {
        // Constructor param "initialHash" maps to state field "rollingHash" by index
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Test".to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: vec![
                        AbiParam { name: "genesisOutpoint".to_string(), param_type: "ByteString".to_string() },
                        AbiParam { name: "initialHash".to_string(), param_type: "ByteString".to_string() },
                        AbiParam { name: "metadata".to_string(), param_type: "ByteString".to_string() },
                    ],
                },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(vec![
                StateField { name: "genesisOutpoint".to_string(), field_type: "ByteString".to_string(), index: 0, initial_value: None },
                StateField { name: "rollingHash".to_string(), field_type: "ByteString".to_string(), index: 1, initial_value: None },
                StateField { name: "metadata".to_string(), field_type: "ByteString".to_string(), index: 2, initial_value: None },
            ]),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(
            artifact,
            vec![
                SdkValue::Bytes("aabb".to_string()),
                SdkValue::Bytes("ccdd".to_string()),
                SdkValue::Bytes("eeff".to_string()),
            ],
        );
        assert_eq!(contract.state()["genesisOutpoint"], SdkValue::Bytes("aabb".to_string()));
        assert_eq!(contract.state()["rollingHash"], SdkValue::Bytes("ccdd".to_string()));
        assert_eq!(contract.state()["metadata"], SdkValue::Bytes("eeff".to_string()));
    }

    // -----------------------------------------------------------------------
    // Artifact JSON parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_artifact_json() {
        let json = r#"{
            "version": "runar-v0.1.0",
            "contractName": "P2PKH",
            "abi": {
                "constructor": { "params": [{"name": "pubKeyHash", "type": "Addr"}] },
                "methods": [{"name": "unlock", "params": [{"name": "sig", "type": "Sig"}, {"name": "pubKey", "type": "PubKey"}], "isPublic": true}]
            },
            "script": "76a90088ac",
            "stateFields": [{"name": "count", "type": "bigint", "index": 0}],
            "constructorSlots": [{"paramIndex": 0, "byteOffset": 2}]
        }"#;

        let artifact: RunarArtifact = serde_json::from_str(json).unwrap();
        assert_eq!(artifact.contract_name, "P2PKH");
        assert_eq!(artifact.abi.constructor.params.len(), 1);
        assert_eq!(artifact.abi.constructor.params[0].name, "pubKeyHash");
        assert_eq!(artifact.abi.methods.len(), 1);
        assert_eq!(artifact.abi.methods[0].name, "unlock");
        assert!(artifact.abi.methods[0].is_public);
        assert_eq!(artifact.script, "76a90088ac");
        assert_eq!(artifact.state_fields.as_ref().unwrap().len(), 1);
        assert_eq!(artifact.constructor_slots.as_ref().unwrap().len(), 1);
        assert_eq!(artifact.constructor_slots.as_ref().unwrap()[0].byte_offset, 2);
    }

    // -----------------------------------------------------------------------
    // Terminal method call tests
    // -----------------------------------------------------------------------

    #[test]
    fn terminal_call_sets_utxo_to_none() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "cancel".to_string(), params: vec![], is_public: true },
        ]));
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        provider.add_utxo(&address, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        }).unwrap();

        let payout_script = format!("76a914{}88ac", "bb".repeat(20));
        let (txid, _tx) = contract.call("cancel", &[], &mut provider, &signer, Some(&CallOptions {
            terminal_outputs: Some(vec![TerminalOutput {
                script_hex: payout_script,
                satoshis: 49_000,
            }]),
            ..Default::default()
        })).unwrap();

        assert_eq!(txid.len(), 64);
        assert!(contract.get_utxo().is_none());
    }

    #[test]
    fn terminal_call_subsequent_call_fails() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "spend".to_string(), params: vec![], is_public: true },
        ]));
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        provider.add_utxo(&address, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 10_000,
            change_address: None,
        }).unwrap();

        contract.call("spend", &[], &mut provider, &signer, Some(&CallOptions {
            terminal_outputs: Some(vec![TerminalOutput {
                script_hex: format!("76a914{}88ac", "cc".repeat(20)),
                satoshis: 9_000,
            }]),
            ..Default::default()
        })).unwrap();

        // Subsequent call should fail
        let result = contract.call("spend", &[], &mut provider, &signer, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not deployed"));
    }

    #[test]
    fn terminal_call_multiple_outputs() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "settle".to_string(), params: vec![], is_public: true },
        ]));
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        provider.add_utxo(&address, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 20_000,
            change_address: None,
        }).unwrap();

        let (txid, _) = contract.call("settle", &[], &mut provider, &signer, Some(&CallOptions {
            terminal_outputs: Some(vec![
                TerminalOutput { script_hex: format!("76a914{}88ac", "aa".repeat(20)), satoshis: 10_000 },
                TerminalOutput { script_hex: format!("76a914{}88ac", "bb".repeat(20)), satoshis: 9_000 },
            ]),
            ..Default::default()
        })).unwrap();

        assert_eq!(txid.len(), 64);
        assert!(contract.get_utxo().is_none());
    }

    #[test]
    fn terminal_call_tx_structure() {
        let artifact = make_artifact("51", abi_with_methods(vec![
            AbiMethod { name: "cancel".to_string(), params: vec![], is_public: true },
        ]));
        let mut contract = RunarContract::new(artifact, vec![]);

        let signer = MockSigner::new();
        let mut provider = MockProvider::testnet();
        let address = signer.get_address().unwrap();
        provider.add_utxo(&address, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });

        contract.deploy(&mut provider, &signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        }).unwrap();

        contract.call("cancel", &[], &mut provider, &signer, Some(&CallOptions {
            terminal_outputs: Some(vec![TerminalOutput {
                script_hex: format!("76a914{}88ac", "dd".repeat(20)),
                satoshis: 49_000,
            }]),
            ..Default::default()
        })).unwrap();

        let broadcasted = provider.get_broadcasted_txs();
        // Deploy + terminal call = 2 broadcasts
        assert_eq!(broadcasted.len(), 2);

        let term_tx_hex = &broadcasted[1];
        // Version should be 01000000
        assert_eq!(&term_tx_hex[0..8], "01000000");
        // Input count should be 1
        assert_eq!(&term_tx_hex[8..10], "01");
    }

    // -------------------------------------------------------------------
    // BigInt values from JSON without reviver ("0n" strings)
    // -------------------------------------------------------------------

    #[test]
    fn bigint_constructor_revives_0n_initial_value_from_json() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Counter".to_string(),
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(vec![StateField {
                name: "count".to_string(),
                field_type: "bigint".to_string(),
                index: 0,
                initial_value: Some(serde_json::Value::String("0n".to_string())),
            }]),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.state.get("count"), Some(&SdkValue::Int(0)));
    }

    #[test]
    fn bigint_constructor_revives_1000n_initial_value_from_json() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Counter".to_string(),
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(vec![StateField {
                name: "amount".to_string(),
                field_type: "bigint".to_string(),
                index: 0,
                initial_value: Some(serde_json::Value::String("1000n".to_string())),
            }]),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.state.get("amount"), Some(&SdkValue::Int(1000)));
    }

    #[test]
    fn bigint_constructor_revives_negative_n_initial_value_from_json() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Counter".to_string(),
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(vec![StateField {
                name: "offset".to_string(),
                field_type: "bigint".to_string(),
                index: 0,
                initial_value: Some(serde_json::Value::String("-42n".to_string())),
            }]),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(artifact, vec![]);
        assert_eq!(contract.state.get("offset"), Some(&SdkValue::Int(-42)));
    }

    #[test]
    fn bigint_end_to_end_get_locking_script_with_0n_initial_values() {
        let artifact = RunarArtifact {
            version: "runar-v0.1.0".to_string(),
            contract_name: "Counter".to_string(),
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![],
            },
            script: "51".to_string(),
            state_fields: Some(vec![StateField {
                name: "count".to_string(),
                field_type: "bigint".to_string(),
                index: 0,
                initial_value: Some(serde_json::Value::String("0n".to_string())),
            }]),
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        };

        let contract = RunarContract::new(artifact, vec![]);
        let script = contract.get_locking_script();
        // Should be valid hex, no crash
        assert!(script.chars().all(|c| c.is_ascii_hexdigit()));
        // Should contain OP_RETURN separator
        assert!(script.contains("6a"));
    }
}
