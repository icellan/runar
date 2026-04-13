//! Token UTXO management — higher-level wrapper for fungible token contracts.

use super::types::{RunarArtifact, Utxo, SdkValue, CallOptions};
use super::provider::Provider;
use super::signer::Signer;
use super::contract::RunarContract;
use super::script_utils::build_p2pkh_script;
use super::calling::build_call_transaction;

/// Manages token UTXOs for a fungible token contract.
///
/// Assumes the artifact describes a token contract with:
/// - A `transfer` public method.
/// - A state field named `balance`, `supply`, or `amount` of type int/bigint.
///
/// This is a higher-level convenience wrapper around RunarContract for the
/// common token use-case.
pub struct TokenWallet {
    artifact: RunarArtifact,
    provider: Box<dyn Provider>,
    signer: Box<dyn Signer>,
}

impl TokenWallet {
    /// Create a new TokenWallet.
    pub fn new(
        artifact: RunarArtifact,
        provider: Box<dyn Provider>,
        signer: Box<dyn Signer>,
    ) -> Self {
        TokenWallet {
            artifact,
            provider,
            signer,
        }
    }

    /// Get the total token balance across all UTXOs belonging to this wallet.
    pub fn get_balance(&self) -> Result<i64, String> {
        let utxos = self.get_utxos()?;
        let mut total: i64 = 0;

        for utxo in &utxos {
            let contract = RunarContract::from_txid(
                self.artifact.clone(),
                &utxo.txid,
                utxo.output_index as usize,
                &*self.provider,
            )?;
            let state = contract.state();
            let balance = get_balance_from_state(state);
            total += balance;
        }

        Ok(total)
    }

    /// Transfer the entire balance of a token UTXO to a new address.
    ///
    /// The FungibleToken.transfer(sig, to) method transfers the full supply
    /// held in the UTXO to the given address. The signature is produced by
    /// this wallet's signer and passed as the first argument.
    ///
    /// Returns the txid of the transfer transaction.
    pub fn transfer(&mut self, recipient_addr: &str, amount: i64) -> Result<String, String> {
        let utxos = self.get_utxos()?;
        if utxos.is_empty() {
            return Err("TokenWallet.transfer: no token UTXOs found".to_string());
        }

        for utxo in &utxos {
            let contract = RunarContract::from_txid(
                self.artifact.clone(),
                &utxo.txid,
                utxo.output_index as usize,
                &*self.provider,
            )?;
            let state = contract.state();
            let balance = get_balance_from_state(state);

            if balance >= amount {
                // FungibleToken.transfer(sig: Sig, to: Addr)
                // Build a preliminary unlocking script with a placeholder sig
                let placeholder_sig = "00".repeat(72);
                let prelim_unlock = contract.build_unlocking_script(
                    "transfer",
                    &[SdkValue::Bytes(placeholder_sig), SdkValue::Bytes(recipient_addr.to_string())],
                )?;

                let change_address = self.signer.get_address()?;
                let fee_rate = self.provider.get_fee_rate()?;
                let additional_utxos = self.provider.get_utxos(&change_address)?;
                let change_script = build_p2pkh_script(&change_address);

                let (prelim_tx, _, _) = build_call_transaction(
                    utxo,
                    &prelim_unlock,
                    None, // FungibleToken is stateless
                    None,
                    Some(&change_address),
                    Some(&change_script),
                    if additional_utxos.is_empty() { None } else { Some(&additional_utxos) },
                    Some(fee_rate),
                );

                // Sign input 0 against the contract UTXO's locking script
                let sig = self.signer.sign(&prelim_tx, 0, &utxo.script, utxo.satoshis, None)?;

                let mut contract_mut = contract;
                let (txid, _) = contract_mut.call(
                    "transfer",
                    &[SdkValue::Bytes(sig), SdkValue::Bytes(recipient_addr.to_string())],
                    &mut *self.provider,
                    &*self.signer,
                    Some(&CallOptions {
                        change_address: Some(change_address),
                        ..Default::default()
                    }),
                )?;
                return Ok(txid);
            }
        }

        Err(format!(
            "TokenWallet.transfer: insufficient token balance for transfer of {}",
            amount
        ))
    }

    /// Merge two token UTXOs into a single UTXO.
    ///
    /// FungibleToken.merge(sig, otherSupply, otherHolder) combines the supply
    /// from two UTXOs. The second UTXO's supply and holder are read from its
    /// on-chain state and passed as arguments.
    ///
    /// Returns the txid of the merge transaction.
    pub fn merge(&mut self) -> Result<String, String> {
        let utxos = self.get_utxos()?;
        if utxos.len() < 2 {
            return Err("TokenWallet.merge: need at least 2 UTXOs to merge".to_string());
        }

        let first_utxo = &utxos[0];
        let contract = RunarContract::from_txid(
            self.artifact.clone(),
            &first_utxo.txid,
            first_utxo.output_index as usize,
            &*self.provider,
        )?;

        // Read the second UTXO's state
        let second_utxo = &utxos[1];
        let second_contract = RunarContract::from_txid(
            self.artifact.clone(),
            &second_utxo.txid,
            second_utxo.output_index as usize,
            &*self.provider,
        )?;
        let second_state = second_contract.state();
        let other_supply = get_balance_from_state(second_state);
        let other_holder = second_state.get("holder")
            .map(|v| match v {
                SdkValue::Bytes(s) => s.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();

        // FungibleToken.merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey)
        let placeholder_sig = "00".repeat(72);
        let prelim_unlock = contract.build_unlocking_script(
            "merge",
            &[
                SdkValue::Bytes(placeholder_sig),
                SdkValue::Int(other_supply),
                SdkValue::Bytes(other_holder.clone()),
            ],
        )?;

        let change_address = self.signer.get_address()?;
        let fee_rate = self.provider.get_fee_rate()?;
        let additional_utxos = self.provider.get_utxos(&change_address)?;
        let change_script = build_p2pkh_script(&change_address);

        let (prelim_tx, _, _) = build_call_transaction(
            first_utxo,
            &prelim_unlock,
            None,
            None,
            Some(&change_address),
            Some(&change_script),
            if additional_utxos.is_empty() { None } else { Some(&additional_utxos) },
            Some(fee_rate),
        );

        // Sign input 0 against the first contract UTXO's locking script
        let sig = self.signer.sign(&prelim_tx, 0, &first_utxo.script, first_utxo.satoshis, None)?;

        let mut contract_mut = contract;
        let (txid, _) = contract_mut.call(
            "merge",
            &[
                SdkValue::Bytes(sig),
                SdkValue::Int(other_supply),
                SdkValue::Bytes(other_holder),
            ],
            &mut *self.provider,
            &*self.signer,
            Some(&CallOptions {
                change_address: Some(change_address),
                ..Default::default()
            }),
        )?;

        Ok(txid)
    }

    /// Get all token UTXOs associated with this wallet's signer address.
    pub fn get_utxos(&self) -> Result<Vec<Utxo>, String> {
        let address = self.signer.get_address()?;
        let all_utxos = self.provider.get_utxos(&address)?;

        let script_prefix = &self.artifact.script;

        Ok(all_utxos
            .into_iter()
            .filter(|utxo| {
                if !utxo.script.is_empty() && !script_prefix.is_empty() {
                    utxo.script.starts_with(script_prefix)
                } else {
                    true
                }
            })
            .collect())
    }
}

/// Extract the balance value from a contract's state map.
/// Looks for "supply", "balance", or "amount" fields.
fn get_balance_from_state(state: &std::collections::HashMap<String, SdkValue>) -> i64 {
    let val = state.get("supply")
        .or_else(|| state.get("balance"))
        .or_else(|| state.get("amount"));

    match val {
        Some(SdkValue::Int(n)) => *n,
        Some(SdkValue::BigInt(n)) => n.to_string().parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::types::*;

    fn make_token_artifact() -> RunarArtifact {
        RunarArtifact {
            version: "0.1.0".to_string(),
            contract_name: "FungibleToken".to_string(),
            abi: Abi {
                constructor: AbiConstructor { params: vec![] },
                methods: vec![
                    AbiMethod {
                        name: "transfer".to_string(),
                        params: vec![
                            AbiParam { name: "sig".to_string(), param_type: "Sig".to_string(), fixed_array: None  },
                            AbiParam { name: "to".to_string(), param_type: "Addr".to_string(), fixed_array: None  },
                        ],
                        is_public: true,
                        is_terminal: None,
                    },
                    AbiMethod {
                        name: "merge".to_string(),
                        params: vec![
                            AbiParam { name: "sig".to_string(), param_type: "Sig".to_string(), fixed_array: None  },
                            AbiParam { name: "otherSupply".to_string(), param_type: "bigint".to_string(), fixed_array: None  },
                            AbiParam { name: "otherHolder".to_string(), param_type: "PubKey".to_string(), fixed_array: None  },
                        ],
                        is_public: true,
                        is_terminal: None,
                    },
                ],
            },
            script: "51".to_string(),
            state_fields: None,
            constructor_slots: None,
            code_sep_index_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        }
    }

    #[test]
    fn token_wallet_creation() {
        use crate::sdk::provider::MockProvider;
        use crate::sdk::signer::MockSigner;

        let artifact = make_token_artifact();
        let provider = Box::new(MockProvider::testnet());
        let signer = Box::new(MockSigner::new());
        let wallet = TokenWallet::new(artifact, provider, signer);
        assert_eq!(wallet.artifact.contract_name, "FungibleToken");
    }

    #[test]
    fn get_balance_from_state_finds_supply() {
        let mut state = std::collections::HashMap::new();
        state.insert("supply".to_string(), SdkValue::Int(1000));
        assert_eq!(get_balance_from_state(&state), 1000);
    }

    #[test]
    fn get_balance_from_state_finds_balance() {
        let mut state = std::collections::HashMap::new();
        state.insert("balance".to_string(), SdkValue::Int(500));
        assert_eq!(get_balance_from_state(&state), 500);
    }

    #[test]
    fn get_balance_from_state_finds_amount() {
        let mut state = std::collections::HashMap::new();
        state.insert("amount".to_string(), SdkValue::Int(250));
        assert_eq!(get_balance_from_state(&state), 250);
    }

    #[test]
    fn get_balance_from_state_returns_zero_when_missing() {
        let state = std::collections::HashMap::new();
        assert_eq!(get_balance_from_state(&state), 0);
    }

    #[test]
    fn get_utxos_filters_by_script_prefix() {
        use crate::sdk::provider::MockProvider;
        use crate::sdk::signer::MockSigner;

        let artifact = make_token_artifact();
        let mut provider = MockProvider::testnet();
        let signer = MockSigner::new();
        let addr = signer.get_address().unwrap();

        // Add a matching UTXO (starts with "51")
        provider.add_utxo(&addr, Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 10_000,
            script: "5193".to_string(),
        });
        // Add a non-matching UTXO
        provider.add_utxo(&addr, Utxo {
            txid: "bb".repeat(32),
            output_index: 0,
            satoshis: 5_000,
            script: "76a914".to_string(),
        });

        let wallet = TokenWallet::new(artifact, Box::new(provider), Box::new(signer));
        let utxos = wallet.get_utxos().unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, "aa".repeat(32));
    }
}
