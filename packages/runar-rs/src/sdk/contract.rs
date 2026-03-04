//! Main RunarContract runtime wrapper for deploying and interacting with
//! compiled Rúnar contracts on BSV.

use std::collections::HashMap;
use super::types::*;
use super::state::{serialize_state, extract_state_from_script, encode_push_data, find_last_op_return};
use super::deployment::{
    build_deploy_transaction, select_utxos,
    build_p2pkh_script_from_address, encode_varint,
};
use super::calling::build_call_transaction;
use super::provider::Provider;
use super::signer::Signer;

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
        // State fields are matched to constructor args by their declaration
        // index, not by name, since the constructor param name may differ
        // from the state field name (e.g., "initialHash" → "rollingHash").
        let mut state = HashMap::new();
        if let Some(ref state_fields) = artifact.state_fields {
            if !state_fields.is_empty() {
                for field in state_fields {
                    if field.index < constructor_args.len() {
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
    // Connection
    // -----------------------------------------------------------------------

    /// Store a provider and signer on this contract so they don't need to be
    /// passed to every `deploy()` and `call()` invocation.
    pub fn connect(&mut self, provider: Box<dyn Provider>, signer: Box<dyn Signer>) {
        self.connected_provider = Some(provider);
        self.connected_signer = Some(signer);
    }

    /// Deploy using the connected provider and signer.
    pub fn deploy_connected(&mut self, options: &DeployOptions) -> Result<(String, Transaction), String> {
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
    ) -> Result<(String, Transaction), String> {
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
    ) -> Result<(String, Transaction), String> {
        self.deploy_inner(provider, signer, options)
    }

    fn deploy_inner(
        &mut self,
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        options: &DeployOptions,
    ) -> Result<(String, Transaction), String> {
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
        let txid = provider.broadcast(&signed_tx)?;

        // Track the deployed UTXO
        self.current_utxo = Some(Utxo {
            txid: txid.clone(),
            output_index: 0,
            satoshis: options.satoshis,
            script: locking_script.clone(),
        });

        let tx = provider.get_transaction(&txid).unwrap_or_else(|_| {
            // Fallback: construct a minimal transaction from what we know
            Transaction {
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
    ) -> Result<(String, Transaction), String> {
        self.call_inner(provider, signer, method_name, args, options)
    }

    fn call_inner(
        &mut self,
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        method_name: &str,
        args: &[SdkValue],
        options: Option<&CallOptions>,
    ) -> Result<(String, Transaction), String> {
        // Validate method exists
        let method = self.find_method(method_name).ok_or_else(|| {
            format!(
                "RunarContract.call: method '{}' not found in {}",
                method_name, self.artifact.contract_name
            )
        })?;
        if method.params.len() != args.len() {
            return Err(format!(
                "RunarContract.call: method '{}' expects {} args, got {}",
                method_name,
                method.params.len(),
                args.len()
            ));
        }

        let current_utxo = self.current_utxo.as_ref().ok_or_else(|| {
            "RunarContract.call: contract is not deployed. Call deploy() or from_txid() first."
                .to_string()
        })?
        .clone();

        let address = signer.get_address()?;
        let change_address = options
            .and_then(|o| o.change_address.as_deref())
            .unwrap_or(&address);
        let unlocking_script = self.build_unlocking_script(method_name, args)?;

        // Determine if this is a stateful call
        let is_stateful = self
            .artifact
            .state_fields
            .as_ref()
            .map_or(false, |f| !f.is_empty());

        let mut new_locking_script: Option<String> = None;
        let mut new_satoshis: Option<i64> = None;

        if is_stateful {
            new_satoshis = Some(
                options
                    .and_then(|o| o.satoshis)
                    .unwrap_or(current_utxo.satoshis),
            );
            // Apply new state values before building the continuation output
            if let Some(new_state) = options.and_then(|o| o.new_state.as_ref()) {
                for (k, v) in new_state {
                    self.state.insert(k.clone(), v.clone());
                }
            }
            new_locking_script = Some(self.get_locking_script());
        }

        let change_script = build_p2pkh_script_from_address(change_address);

        // Fetch fee rate and additional funding UTXOs if needed
        let fee_rate = provider.get_fee_rate()?;
        let additional_utxos = provider.get_utxos(&address).unwrap_or_default();

        let (tx_hex, input_count) = build_call_transaction(
            &current_utxo,
            &unlocking_script,
            new_locking_script.as_deref(),
            new_satoshis,
            Some(change_address),
            Some(&change_script),
            if additional_utxos.is_empty() {
                None
            } else {
                Some(&additional_utxos)
            },
            Some(fee_rate),
        );

        // Sign additional inputs (input 0 already has the unlocking script)
        let mut signed_tx = tx_hex;
        for i in 1..input_count {
            if let Some(utxo) = additional_utxos.get(i - 1) {
                let sig = signer.sign(&signed_tx, i, &utxo.script, utxo.satoshis, None)?;
                let pub_key = signer.get_public_key()?;
                let unlock_script = format!("{}{}", encode_push_data(&sig), encode_push_data(&pub_key));
                signed_tx = insert_unlocking_script(&signed_tx, i, &unlock_script)?;
            }
        }

        // Broadcast
        let txid = provider.broadcast(&signed_tx)?;

        // Update tracked UTXO for stateful contracts
        if is_stateful {
            if let Some(ref nls) = new_locking_script {
                self.current_utxo = Some(Utxo {
                    txid: txid.clone(),
                    output_index: 0,
                    satoshis: new_satoshis.unwrap_or(current_utxo.satoshis),
                    script: nls.clone(),
                });
            }
        } else {
            self.current_utxo = None;
        }

        let tx = provider.get_transaction(&txid).unwrap_or_else(|_| {
            Transaction {
                txid: txid.clone(),
                version: 1,
                inputs: vec![],
                outputs: vec![],
                locktime: 0,
                raw: Some(signed_tx),
            }
        });

        Ok((txid, tx))
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

        // Backward compatibility: old artifacts without constructorSlots
        for arg in &self.constructor_args {
            script.push_str(&encode_arg(arg));
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
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

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

    fn make_tx(txid: &str, outputs: Vec<TxOutput>) -> Transaction {
        Transaction {
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
            StateField { name: "count".to_string(), field_type: "bigint".to_string(), index: 0 },
            StateField { name: "active".to_string(), field_type: "bool".to_string(), index: 1 },
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
            state_fields: Some(vec![StateField { name: "count".to_string(), field_type: "bigint".to_string(), index: 0 }]),
            constructor_slots: None,
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
                StateField { name: "genesisOutpoint".to_string(), field_type: "ByteString".to_string(), index: 0 },
                StateField { name: "rollingHash".to_string(), field_type: "ByteString".to_string(), index: 1 },
                StateField { name: "metadata".to_string(), field_type: "ByteString".to_string(), index: 2 },
            ]),
            constructor_slots: None,
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
}
