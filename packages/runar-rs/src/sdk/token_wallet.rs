//! Token UTXO management — higher-level wrapper for fungible token contracts.

use super::types::{RunarArtifact, Utxo, SdkValue, CallOptions};
use super::provider::Provider;
use super::signer::Signer;
use super::contract::RunarContract;
use super::script_utils::{build_p2pkh_script, is_hex_bytes, matches_artifact};
use super::state::find_last_op_return;
use std::sync::Once;

// N-239 (user decision R92): `merge` and `transfer` drive an ABI that cannot
// be made sound, so they are deprecated rather than redesigned or removed.
// Each warns once per process on first use.
const MERGE_DEPRECATION: &str = "runar-sdk: warning: TokenWallet::merge is deprecated and unsafe. \
    Its merge(sig, otherSupply, otherHolder) ABI cannot authenticate the companion input, \
    so a holder can call merge on ONE input with a made-up otherSupply (supply inflation). \
    Use the token-ft example (FungibleTokenExample, examples/*/token-ft/) instead (N-239).";
const TRANSFER_DEPRECATION: &str = "runar-sdk: warning: TokenWallet::transfer is deprecated and unsafe. \
    Its transfer(sig, to: Addr) ABI cannot re-key the PubKey holder from an Addr, \
    so the token stays with the current holder instead of moving to the recipient. \
    Use the token-ft example (FungibleTokenExample, examples/*/token-ft/) instead (N-239).";
static MERGE_WARN_ONCE: Once = Once::new();
static TRANSFER_WARN_ONCE: Once = Once::new();

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
    #[deprecated(
        note = "unsafe (N-239): the transfer(sig, to: Addr) ABI cannot re-key a PubKey holder, \
                so the token does not move to the recipient; use the token-ft example \
                (FungibleTokenExample) instead"
    )]
    pub fn transfer(&mut self, recipient_addr: &str, amount: i64) -> Result<String, String> {
        TRANSFER_WARN_ONCE.call_once(|| eprintln!("{}", TRANSFER_DEPRECATION));
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
                // F-045: pass Auto for the Sig so `call` auto-signs the
                // transaction it actually builds and broadcasts. Signing a
                // locally built preliminary tx covers a different tx and is
                // rejected on-chain.
                // An Addr is a 20-byte hash160: accept a Base58 address (as
                // documented), a raw hash160, or a public key.
                let to_pkh = build_p2pkh_script(recipient_addr)[6..46].to_string();
                let change_address = self.signer.get_address()?;

                let mut contract_mut = contract;
                let (txid, _) = contract_mut.call(
                    "transfer",
                    &[SdkValue::Auto, SdkValue::Bytes(to_pkh)],
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
    #[deprecated(
        note = "unsafe (N-239): the merge(sig, otherSupply, otherHolder) ABI cannot authenticate \
                its companion input, so a holder can inflate supply; use the token-ft example \
                (FungibleTokenExample) instead"
    )]
    pub fn merge(&mut self) -> Result<String, String> {
        MERGE_WARN_ONCE.call_once(|| eprintln!("{}", MERGE_DEPRECATION));
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
        // F-045: spend BOTH token UTXOs in one tx. Each input's unlock carries
        // the OTHER input's supply/holder, and every Sig is Auto so `call`
        // signs each input over the transaction it actually broadcasts.
        let first_state = contract.state();
        let first_supply = get_balance_from_state(first_state);
        let first_holder = first_state.get("holder")
            .map(|v| match v {
                SdkValue::Bytes(s) => s.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();

        let change_address = self.signer.get_address()?;

        let mut contract_mut = contract;
        let (txid, _) = contract_mut.call(
            "merge",
            &[
                SdkValue::Auto,
                SdkValue::Int(other_supply),
                SdkValue::Bytes(other_holder),
            ],
            &mut *self.provider,
            &*self.signer,
            Some(&CallOptions {
                change_address: Some(change_address),
                additional_contract_inputs: Some(vec![second_utxo.clone()]),
                additional_contract_input_args: Some(vec![vec![
                    SdkValue::Auto,
                    SdkValue::Int(first_supply),
                    SdkValue::Bytes(first_holder),
                ]]),
                ..Default::default()
            }),
        )?;

        Ok(txid)
    }

    /// Get all token UTXOs associated with this wallet's signer address.
    pub fn get_utxos(&self) -> Result<Vec<Utxo>, String> {
        let address = self.signer.get_address()?;
        let all_utxos = self.provider.get_utxos(&address)?;

        // N-076: the artifact script is the TEMPLATE; every slot (constructor
        // arg, codeSepIndex, code-part length) is a placeholder that
        // deployment replaces, so a raw prefix of it never matches a slotted
        // deployment. With constructor slots, use the slot-aware
        // `matches_artifact`; a template with none is deployed verbatim, so
        // its literal prefix is exact.
        let template = &self.artifact.script;
        let slotted = self
            .artifact
            .constructor_slots
            .as_ref()
            .map_or(false, |s| !s.is_empty());
        let declares_state = self
            .artifact
            .state_fields
            .as_ref()
            .map_or(false, |s| !s.is_empty());

        Ok(all_utxos
            .into_iter()
            .filter(|utxo| {
                if utxo.script.is_empty() || template.is_empty() {
                    return true;
                }
                if !slotted {
                    return utxo.script.starts_with(template.as_str());
                }
                // N-317: any UTXO the provider lists is attacker-influenced; a
                // script that is not whole ASCII hex bytes is not an instance of
                // this contract (and slicing it below could panic).
                if !is_hex_bytes(&utxo.script) {
                    return false;
                }
                // `matches_artifact` strips the state section only for
                // artifacts that declare state fields; cut it here for the rest.
                let mut code_hex = utxo.script.as_str();
                if !declares_state {
                    if let Some(pos) = find_last_op_return(code_hex) {
                        code_hex = &code_hex[..pos];
                    }
                }
                // A script that is not well-formed at the artifact's slot
                // offsets (F-238) is an Err and not an instance of this contract.
                matches_artifact(&self.artifact, code_hex).unwrap_or(false)
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
            parent_class: None,
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
                        is_terminal: None, uses_code_part: None,
                        sig_hash_type: None,
                    },
                    AbiMethod {
                        name: "merge".to_string(),
                        params: vec![
                            AbiParam { name: "sig".to_string(), param_type: "Sig".to_string(), fixed_array: None  },
                            AbiParam { name: "otherSupply".to_string(), param_type: "bigint".to_string(), fixed_array: None  },
                            AbiParam { name: "otherHolder".to_string(), param_type: "PubKey".to_string(), fixed_array: None  },
                        ],
                        is_public: true,
                        is_terminal: None, uses_code_part: None,
                        sig_hash_type: None,
                    },
                ],
            },
            script: "51".to_string(),
            asm: None,
            state_fields: None,
            constructor_slots: None,
            code_sep_index_slots: None,
            code_part_len_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
            unsound_primitives: None,
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

    // -----------------------------------------------------------------------
    // N-239: merge / transfer are deprecated and unsafe. The ABI they drive
    // cannot be made sound: merge(sig, otherSupply, otherHolder) cannot
    // authenticate its companion input (supply inflation) and
    // transfer(sig, to: Addr) cannot re-key a PubKey holder. User decision
    // R92: deprecate (marker + one-time runtime warning + docs), do not
    // redesign or remove.
    //
    // Proves: each method carries `#[deprecated]`; calling it writes a
    // warning to the process's real stderr naming its specific unsoundness
    // and pointing to token-ft (FungibleTokenExample), once per process, not
    // per call; the method's own behaviour (here, its error path) is
    // unchanged. libtest captures eprintln!, so the parent re-runs this test
    // binary on the child test below with --nocapture and reads its stderr.
    // Does NOT prove: that anyone reads the warning, or anything on-chain —
    // the happy paths stay covered by tests/f045_token_wallet.rs.
    // -----------------------------------------------------------------------

    const N239_CHILD_ENV: &str = "RUNAR_N239_CHILD";

    /// Child half: only does anything when the parent re-executes it.
    #[test]
    #[allow(deprecated)]
    fn n239_child_calls_deprecated_methods() {
        if std::env::var(N239_CHILD_ENV).is_err() {
            return;
        }
        use crate::sdk::provider::MockProvider;
        use crate::sdk::signer::MockSigner;
        let mut wallet = TokenWallet::new(
            make_token_artifact(),
            Box::new(MockProvider::testnet()),
            Box::new(MockSigner::new()),
        );
        for _ in 0..2 {
            let e = wallet.merge().unwrap_err();
            assert!(e.contains("need at least 2 UTXOs"), "merge error path changed: {e}");
            let e = wallet.transfer("recipient", 1).unwrap_err();
            assert!(e.contains("no token UTXOs found"), "transfer error path changed: {e}");
        }
    }

    #[test]
    fn n239_merge_and_transfer_warn_once_on_stderr() {
        let child = format!(
            "{}::n239_child_calls_deprecated_methods",
            module_path!().split_once("::").map(|(_, rest)| rest).unwrap()
        );
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &child, "--nocapture", "--test-threads=1"])
            .env(N239_CHILD_ENV, "1")
            .output()
            .expect("re-exec test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "child failed\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(stdout.contains("1 passed"), "child test did not run: {stdout}");

        let merge: Vec<&str> = stderr.lines().filter(|l| l.contains("TokenWallet::merge")).collect();
        let transfer: Vec<&str> = stderr.lines().filter(|l| l.contains("TokenWallet::transfer")).collect();
        assert_eq!(merge.len(), 1, "want one merge warning, stderr:\n{stderr}");
        assert_eq!(transfer.len(), 1, "want one transfer warning, stderr:\n{stderr}");
        for needle in ["deprecated", "supply inflation", "token-ft", "FungibleTokenExample"] {
            assert!(merge[0].contains(needle), "merge warning lacks {needle:?}: {}", merge[0]);
        }
        for needle in ["deprecated", "re-key", "token-ft", "FungibleTokenExample"] {
            assert!(transfer[0].contains(needle), "transfer warning lacks {needle:?}: {}", transfer[0]);
        }
    }

    #[test]
    fn n239_methods_carry_deprecated_attribute() {
        let src = include_str!("token_wallet.rs");
        for m in ["transfer", "merge"] {
            let sig = format!("pub fn {m}(&mut self");
            let at = src.find(&sig).unwrap_or_else(|| panic!("{m} not found"));
            let before = &src[..at];
            let attr = before.rfind("#[deprecated").unwrap_or_else(|| panic!("{m} lacks #[deprecated]"));
            // The attribute must belong to THIS fn: no other `fn ` between it and the signature.
            assert!(!before[attr..].contains("fn "), "{m} lacks #[deprecated]");
        }
    }
}
