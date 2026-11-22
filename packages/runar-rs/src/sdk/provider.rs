//! Provider trait and MockProvider for blockchain access.

use std::collections::HashMap;
use bsv::transaction::Transaction as BsvTransaction;
use super::types::{TransactionData, Utxo};
use super::errors::{assert_script_hex_under_limit, MAX_SCRIPT_BYTES};
#[cfg(test)]
use super::types::TxOutput;

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// Abstraction over blockchain access for fetching transactions, UTXOs,
/// and broadcasting raw transactions.
pub trait Provider {
    /// Fetch a transaction by its txid.
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String>;

    /// Broadcast a BSV SDK Transaction object. Returns the txid on success.
    fn broadcast(&mut self, tx: &BsvTransaction) -> Result<String, String>;

    /// Get all UTXOs for a given address.
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String>;

    /// Find a UTXO by its script hash (for stateful contract lookup).
    /// Returns None if no UTXO is found with the given script hash.
    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String>;

    /// Return the network this provider is connected to.
    fn get_network(&self) -> &str;

    /// Get the current fee rate in satoshis per KB (1000 bytes).
    /// BSV standard is 100 sat/KB (0.1 sat/byte).
    fn get_fee_rate(&self) -> Result<i64, String>;

    /// Fetch the raw transaction hex by its txid.
    fn get_raw_transaction(&self, txid: &str) -> Result<String, String>;
}

// ---------------------------------------------------------------------------
// MockProvider
// ---------------------------------------------------------------------------

/// Script + value of an outpoint the MockProvider knows about. Broadcast
/// validation can only execute inputs whose outpoint appears here.
#[derive(Clone, Debug)]
struct KnownOutpoint {
    script: String,
    satoshis: i64,
}

/// Outcome of validating one broadcast transaction.
///
/// Every input lands in exactly one bucket, and only `validated` means "a
/// script really ran and really passed". The other buckets exist so a
/// not-checked input can never masquerade as a checked one.
#[derive(Clone, Debug, Default)]
pub struct BroadcastValidationReport {
    /// Inputs actually executed by `Spend` and accepted.
    pub validated: usize,
    /// Inputs whose outpoint this provider does not know (nothing was run).
    pub unknown: usize,
    /// Inputs the bundled `bsv-sdk` interpreter refuses to run — see
    /// [`validate_broadcast_tx`]. NOT counted as validated.
    pub unvalidatable: usize,
    /// True when every input's outpoint was known, so the outputs-vs-inputs
    /// value-conservation check actually ran.
    pub value_conserved: bool,
    /// Total inputs in the transaction.
    pub total: usize,
}

/// In-memory mock provider for unit tests and local development.
///
/// Allows injecting transactions and UTXOs, and records broadcasts for
/// assertion in tests.
///
/// Broadcast validation is DEFAULT-ON (testing-gap remediation Phase A5) —
/// see [`MockProvider::broadcast`] and README "How fund-path tests fail closed
/// in the Rust tier".
pub struct MockProvider {
    transactions: HashMap<String, TransactionData>,
    raw_transactions: HashMap<String, String>,
    utxos: HashMap<String, Vec<Utxo>>,
    contract_utxos: HashMap<String, Utxo>,
    broadcasted_txs: Vec<String>,
    network: String,
    broadcast_count: u32,
    fee_rate: i64,
    /// Gates the fail-closed check in `broadcast`. Default `true`; the opt-out
    /// is governed by `always_ack_allowlist.json`
    /// (see `tests/always_ack_allowlist.rs`).
    validate_broadcasts: bool,
    /// "txid:vout" -> script + value for every outpoint this provider knows.
    known_outpoints: HashMap<String, KnownOutpoint>,
    /// Non-vacuity witness of the most recent validating `broadcast`.
    last_report: BroadcastValidationReport,
    /// "txid:vout" -> txid of the accepted broadcast that spent it. Checked on
    /// EVERY `broadcast`, whatever `validate_broadcasts` says: a node refuses a
    /// second transaction spending an outpoint already spent.
    spent_outpoints: HashMap<String, String>,
    /// Real txid of every accepted broadcast -> the txid this provider
    /// returned for it: re-broadcasting the identical tx is idempotent.
    accepted_txids: HashMap<String, String>,
}

impl MockProvider {
    /// Create a new MockProvider for the given network, with broadcast
    /// validation ON.
    pub fn new(network: &str) -> Self {
        MockProvider {
            transactions: HashMap::new(),
            raw_transactions: HashMap::new(),
            utxos: HashMap::new(),
            contract_utxos: HashMap::new(),
            broadcasted_txs: Vec::new(),
            network: network.to_string(),
            broadcast_count: 0,
            fee_rate: 100,
            validate_broadcasts: true,
            known_outpoints: HashMap::new(),
            last_report: BroadcastValidationReport::default(),
            spent_outpoints: HashMap::new(),
            accepted_txids: HashMap::new(),
        }
    }

    /// Create a new MockProvider defaulting to testnet.
    pub fn testnet() -> Self {
        Self::new("testnet")
    }

    /// Create a MockProvider whose `broadcast` never validates — the
    /// pre-Phase-A5 behaviour.
    ///
    /// FOR ALLOWLISTED TESTS ONLY: every test file that calls this (or the
    /// other opt-outs) must carry a matching entry in
    /// `always_ack_allowlist.json`, enforced by `tests/always_ack_allowlist.rs`.
    /// Fund-path deploy/call tests must not use it.
    pub fn always_ack(network: &str) -> Self {
        let mut p = Self::new(network);
        p.validate_broadcasts = false;
        p
    }

    /// Turn the fail-closed `broadcast` check on or off. Passing `false` is an
    /// allowlisted opt-out — see [`MockProvider::always_ack`].
    pub fn enable_broadcast_validation(&mut self, enabled: bool) {
        self.validate_broadcasts = enabled;
    }

    /// Restore the legacy always-ack `broadcast`. Allowlisted opt-out.
    pub fn disable_broadcast_validation(&mut self) {
        self.validate_broadcasts = false;
    }

    /// Report from the most recent validating `broadcast`. Exposed so a test
    /// can assert its gate is NOT vacuous.
    pub fn last_validation_report(&self) -> &BroadcastValidationReport {
        &self.last_report
    }

    /// Shorthand for `last_validation_report().validated`.
    pub fn last_validated_input_count(&self) -> usize {
        self.last_report.validated
    }

    fn remember_outpoint(&mut self, txid: &str, vout: u32, script: &str, satoshis: i64) {
        if script.is_empty() {
            return;
        }
        self.known_outpoints.insert(
            format!("{}:{}", txid, vout),
            KnownOutpoint { script: script.to_string(), satoshis },
        );
    }

    // -----------------------------------------------------------------------
    // Test data injection
    // -----------------------------------------------------------------------

    /// Add a transaction to the mock store.
    pub fn add_transaction(&mut self, tx: TransactionData) {
        for (i, out) in tx.outputs.iter().enumerate() {
            let (script, satoshis) = (out.script.clone(), out.satoshis);
            self.remember_outpoint(&tx.txid, i as u32, &script, satoshis);
        }
        self.transactions.insert(tx.txid.clone(), tx);
    }

    /// Add a UTXO for an address.
    pub fn add_utxo(&mut self, address: &str, utxo: Utxo) {
        self.remember_outpoint(&utxo.txid, utxo.output_index, &utxo.script, utxo.satoshis);
        self.utxos
            .entry(address.to_string())
            .or_insert_with(Vec::new)
            .push(utxo);
    }

    /// Add a contract UTXO for lookup by script hash.
    pub fn add_contract_utxo(&mut self, script_hash: &str, utxo: Utxo) {
        self.remember_outpoint(&utxo.txid, utxo.output_index, &utxo.script, utxo.satoshis);
        self.contract_utxos.insert(script_hash.to_string(), utxo);
    }

    /// Get all raw tx hexes that were broadcast through this provider.
    pub fn get_broadcasted_txs(&self) -> &[String] {
        &self.broadcasted_txs
    }

    /// Set the fee rate returned by get_fee_rate() (for testing).
    pub fn set_fee_rate(&mut self, rate: i64) {
        self.fee_rate = rate;
    }
}

// ---------------------------------------------------------------------------
// Fail-closed broadcast validation (testing-gap remediation Phase A5)
// ---------------------------------------------------------------------------

/// Replay the inputs the bundled interpreter can actually judge through
/// `bsv-sdk`'s `Spend` with FULL transaction context, then check value
/// conservation when every input is known.
///
/// # What this tier can and cannot check — stated, not papered over
///
/// The Rust tier's `Spend` wrapper is **execute-only** (upstream keeps the
/// stack / program counter `pub(crate)`) — the divergence recorded in the root
/// CLAUDE.md.
///
/// **EVERY known input is executed, at any index.** `bsv-sdk` 0.1.72 built the
/// BIP-143 `hashPrevouts` as *current input's outpoint first, then
/// `other_inputs`*, which equals transaction order only at index 0, so this
/// function used to refuse to draw any conclusion from inputs at index > 0.
/// That defect is **fixed as of 0.2.89** (this crate now requires it — see
/// `Cargo.toml` and `docs/audit/upstream-bsv-sdk-bip143-hashprevouts.md`), and
/// the carve-out is gone: a multi-input transaction is now validated in full.
///
/// One limitation remains, and it gets its OWN bucket in
/// [`BroadcastValidationReport`] so a not-checked input can never be mistaken
/// for a passing one:
///
/// - **Rúnar OP_PUSH_TX covenants cannot be run.** Rúnar targets *Chronicle*,
///   the post-Genesis BSV profile that re-enables `OP_2MUL` (0x8d), and the
///   OP_PUSH_TX low-S normalisation emits exactly that opcode. `bsv-sdk`
///   implements the pre-Chronicle policy and hard-disables it with no config
///   escape, so the covenant aborts with `disabled opcode: OP_2MUL`. Those
///   inputs are counted as `unvalidatable`, never as validated. Pinned by
///   `mock_broadcast_validation.rs::pin_bsv_sdk_rejects_op2mul_*`, which go RED
///   the day upstream adopts the Chronicle opcode set — at which point this
///   tolerated-error class should be deleted too. See
///   `docs/audit/upstream-bsv-sdk-op2mul-chronicle.md`.
fn validate_broadcast_tx(
    tx: &BsvTransaction,
    known: &HashMap<String, KnownOutpoint>,
) -> Result<BroadcastValidationReport, String> {
    use bsv::script::locking_script::LockingScript;
    use bsv::script::spend::{Spend, SpendParams};

    let mut report = BroadcastValidationReport { total: tx.inputs.len(), ..Default::default() };
    let mut all_inputs_known = true;
    let mut total_known_in: i64 = 0;

    for (i, input) in tx.inputs.iter().enumerate() {
        let key = match &input.source_txid {
            Some(txid) => format!("{}:{}", txid, input.source_output_index),
            None => {
                all_inputs_known = false;
                report.unknown += 1;
                continue;
            }
        };
        let ko = match known.get(&key) {
            Some(ko) => ko,
            None => {
                all_inputs_known = false;
                report.unknown += 1;
                continue;
            }
        };
        total_known_in += ko.satoshis;

        let locking_script = LockingScript::from_hex(&ko.script)
            .map_err(|e| format!("input {}: known outpoint {} has invalid script hex: {}", i, key, e))?;
        let unlocking_script = match &input.unlocking_script {
            Some(u) => u.clone(),
            None => return Err(format!("input {}: no unlocking script (transaction is unsigned)", i)),
        };
        let other_inputs: Vec<_> = tx
            .inputs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, v)| v.clone())
            .collect();

        let mut spend = Spend::new(SpendParams {
            locking_script,
            unlocking_script,
            source_txid: input.source_txid.clone().unwrap_or_default(),
            source_output_index: input.source_output_index as usize,
            source_satoshis: ko.satoshis.max(0) as u64,
            transaction_version: tx.version,
            transaction_lock_time: tx.lock_time,
            transaction_sequence: input.sequence,
            other_inputs,
            other_outputs: tx.outputs.clone(),
            input_index: i,
        });

        match spend.validate() {
            Ok(true) => report.validated += 1,
            Ok(false) => {
                return Err(format!("input {}: script evaluated to false", i));
            }
            Err(e) => {
                let msg = e.to_string();
                // The ONLY tolerated class: bsv-sdk's pre-Chronicle opcode
                // policy refusing the OP_2MUL a Rúnar push-tx covenant emits.
                // Counted, never treated as a pass.
                if msg.contains("disabled opcode") {
                    report.unvalidatable += 1;
                } else {
                    return Err(format!("input {}: script REJECTED by bsv-sdk Spend: {}", i, msg));
                }
            }
        }
    }

    if all_inputs_known {
        report.value_conserved = true;
        let total_out: i64 = tx.outputs.iter().map(|o| o.satoshis.unwrap_or(0) as i64).sum();
        if total_out > total_known_in {
            return Err(format!(
                "underfunded: outputs ({} sats) exceed known inputs ({} sats)",
                total_out, total_known_in
            ));
        }
    }

    Ok(report)
}

impl Provider for MockProvider {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> {
        self.transactions
            .get(txid)
            .cloned()
            .ok_or_else(|| format!("MockProvider: transaction {} not found", txid))
    }

    /// Validate the transaction (unless validation has been opted out of) and
    /// then record it, returning a deterministic fake txid.
    ///
    /// Fail-closed by default (testing-gap remediation Phase A5): every input
    /// whose outpoint the provider knows is executed by `bsv-sdk`'s `Spend`
    /// with full transaction context, outputs may not exceed known inputs, and
    /// a transaction on which ZERO inputs could actually be executed is
    /// REJECTED rather than waved through — a gate that validates nothing is
    /// worse than no gate.
    fn broadcast(&mut self, tx: &BsvTransaction) -> Result<String, String> {
        if self.validate_broadcasts {
            let report = validate_broadcast_tx(tx, &self.known_outpoints);
            match report {
                Ok(r) => {
                    // Non-vacuity: at least ONE real check must have run —
                    // either a script actually executed, or (when every input's
                    // outpoint is known) the value-conservation check. If
                    // neither did, nothing was verified and the ack would be a
                    // lie.
                    let vacuous = r.validated == 0 && !r.value_conserved;
                    self.last_report = r;
                    if vacuous {
                        return Err(format!(
                            "MockProvider: refusing to broadcast — NOTHING was checked \
                             (0 of {} inputs executed; unknown outpoints: {}, rejected by \
                             bsv-sdk's pre-Chronicle opcode policy: {}; value conservation \
                             could not run because not every input's outpoint is known). \
                             Seed the spent outpoints via add_utxo/add_contract_utxo/\
                             add_transaction, or use MockProvider::always_ack (allowlisted) if \
                             this test genuinely needs always-ack",
                            self.last_report.total,
                            self.last_report.unknown,
                            self.last_report.unvalidatable,
                        ));
                    }
                }
                Err(e) => {
                    self.last_report = BroadcastValidationReport {
                        total: tx.inputs.len(),
                        ..Default::default()
                    };
                    return Err(format!(
                        "MockProvider: refusing to broadcast invalid transaction: {}",
                        e
                    ));
                }
            }
        }

        // Double-spend gate, independent of `validate_broadcasts`.
        // Re-broadcasting the identical tx is not a conflict (a node treats it
        // as already known).
        let spending_txid = tx.id().map_err(|e| format!("broadcast: txid failed: {}", e))?;
        let prior = self.accepted_txids.get(&spending_txid).cloned();
        let mut input_outpoints: Vec<String> = Vec::with_capacity(tx.inputs.len());
        for input in tx.inputs.iter() {
            // An input naming no outpoint has nothing to check here;
            // validation (when on) counts it as unknown.
            let key = match &input.source_txid {
                Some(txid) => format!("{}:{}", txid, input.source_output_index),
                None => continue,
            };
            if input_outpoints.contains(&key) {
                return Err(format!(
                    "MockProvider: refusing to broadcast a transaction that spends {} more than once",
                    key
                ));
            }
            if let (Some(spender), None) = (self.spent_outpoints.get(&key), &prior) {
                return Err(format!(
                    "MockProvider: refusing to broadcast a double spend: {} is already spent by {}",
                    key, spender
                ));
            }
            input_outpoints.push(key);
        }

        // Re-broadcasting a tx already accepted is idempotent, as on a node:
        // same txid, nothing registered twice. It is still validated above, so
        // a tx an always-ack provider acked is not waved through once
        // validation is on.
        if let Some(prior) = prior {
            return Ok(prior);
        }
        let raw_tx = tx.to_hex().map_err(|e| format!("broadcast: to_hex failed: {}", e))?;
        // Accepted: its inputs are now spent.
        for key in input_outpoints {
            self.spent_outpoints.insert(key, spending_txid.clone());
        }
        self.broadcasted_txs.push(raw_tx.clone());
        self.broadcast_count += 1;
        // Generate a deterministic fake txid from the broadcast count
        let fake_txid = mock_sha256_hex(&format!(
            "mock-broadcast-{}-{}",
            self.broadcast_count,
            &raw_tx[..raw_tx.len().min(16)]
        ));
        // Auto-store raw hex for subsequent get_raw_transaction lookups
        self.raw_transactions.insert(fake_txid.clone(), raw_tx);
        // Register this tx's own outputs so a chained call (spending the
        // continuation this broadcast just created) can be validated too.
        for (i, out) in tx.outputs.iter().enumerate() {
            let script = out.locking_script.to_hex();
            let sats = out.satoshis.unwrap_or(0) as i64;
            self.remember_outpoint(&fake_txid, i as u32, &script, sats);
        }
        self.accepted_txids.insert(spending_txid, fake_txid.clone());
        // A P2PKH output paying an address this provider lists (e.g. the
        // change of a deploy) is a new UTXO of that address, as a node's
        // listing would show it, so a later call can be funded from it.
        let addresses: Vec<String> = self.utxos.keys().cloned().collect();
        for address in addresses {
            let Some(p2pkh) = super::script_utils::try_build_p2pkh_script(&address) else { continue };
            for (i, out) in tx.outputs.iter().enumerate() {
                let script = out.locking_script.to_hex();
                if script.eq_ignore_ascii_case(&p2pkh) {
                    self.utxos.get_mut(&address).unwrap().push(Utxo {
                        txid: fake_txid.clone(),
                        output_index: i as u32,
                        satoshis: out.satoshis.unwrap_or(0) as i64,
                        script,
                    });
                }
            }
        }
        Ok(fake_txid)
    }

    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        // An outpoint an accepted broadcast spent is no longer a UTXO (a node's
        // listing would not return it either).
        let utxos: Vec<Utxo> = self
            .utxos
            .get(address)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|u| !self.spent_outpoints.contains_key(&format!("{}:{}", u.txid, u.output_index)))
            .collect();
        // DoS-bound: reject pathological scripts at the provider boundary.
        for u in &utxos {
            if u.script.is_empty() { continue; }
            assert_script_hex_under_limit(
                &u.script, MAX_SCRIPT_BYTES,
                &format!("MockProvider.get_utxos({})", address),
            )?;
        }
        Ok(utxos)
    }

    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String> {
        let utxo = self.contract_utxos.get(script_hash).cloned();
        if let Some(ref u) = utxo {
            if !u.script.is_empty() {
                assert_script_hex_under_limit(
                    &u.script, MAX_SCRIPT_BYTES,
                    &format!("MockProvider.get_contract_utxo({})", script_hash),
                )?;
            }
        }
        Ok(utxo)
    }

    fn get_network(&self) -> &str {
        &self.network
    }

    fn get_fee_rate(&self) -> Result<i64, String> {
        Ok(self.fee_rate)
    }

    fn get_raw_transaction(&self, txid: &str) -> Result<String, String> {
        // Check auto-stored raw hex from broadcasts first
        if let Some(raw) = self.raw_transactions.get(txid) {
            return Ok(raw.clone());
        }
        let tx = self.transactions
            .get(txid)
            .ok_or_else(|| format!("MockProvider: transaction {} not found", txid))?;
        tx.raw.clone()
            .ok_or_else(|| format!("MockProvider: transaction {} has no raw hex", txid))
    }
}

// ---------------------------------------------------------------------------
// Mock hash for deterministic fake txids
// ---------------------------------------------------------------------------

/// Simple deterministic hash for mock purposes -- not cryptographically
/// secure. Produces a 64-char hex string that looks like a txid.
fn mock_sha256_hex(input: &str) -> String {
    let mut h0: u32 = 0x6a09e667;
    let mut h1: u32 = 0xbb67ae85;
    let mut h2: u32 = 0x3c6ef372;
    let mut h3: u32 = 0xa54ff53a;

    for c in input.bytes() {
        h0 = (h0 ^ c as u32).wrapping_mul(0x01000193);
        h1 = (h1 ^ c as u32).wrapping_mul(0x01000193);
        h2 = (h2 ^ c as u32).wrapping_mul(0x01000193);
        h3 = (h3 ^ c as u32).wrapping_mul(0x01000193);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_provider_stores_and_retrieves_transactions() {
        let mut provider = MockProvider::testnet();
        let tx = TransactionData {
            txid: "aa".repeat(32),
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { satoshis: 50_000, script: "51".to_string() }],
            locktime: 0,
            raw: None,
        };
        provider.add_transaction(tx.clone());

        let retrieved = provider.get_transaction(&"aa".repeat(32)).unwrap();
        assert_eq!(retrieved.txid, "aa".repeat(32));
        assert_eq!(retrieved.outputs[0].satoshis, 50_000);
    }

    #[test]
    fn mock_provider_returns_error_for_unknown_txid() {
        let provider = MockProvider::testnet();
        let result = provider.get_transaction(&"ff".repeat(32));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn mock_provider_stores_and_retrieves_utxos() {
        let mut provider = MockProvider::testnet();
        let utxo = Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: "51".to_string(),
        };
        provider.add_utxo("myaddr", utxo);

        let utxos = provider.get_utxos("myaddr").unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].satoshis, 100_000);
    }

    #[test]
    fn mock_provider_returns_empty_for_unknown_address() {
        let provider = MockProvider::testnet();
        let utxos = provider.get_utxos("unknown").unwrap();
        assert!(utxos.is_empty());
    }

    #[test]
    fn mock_provider_records_broadcasts() {
        use bsv::transaction::{
            Transaction as BsvTx,
            TransactionInput as BsvTxIn,
            TransactionOutput as BsvTxOut,
        };
        use bsv::script::LockingScript;

        let mut provider = MockProvider::testnet();
        // Seed the spent outpoint so the default (fail-closed) broadcast check
        // has something to actually execute — a validating provider rejects a
        // tx none of whose inputs it knows rather than passing vacuously.
        provider.add_utxo("mock", Utxo {
            txid: "00".repeat(32),
            output_index: 0,
            satoshis: 100_000,
            script: "51".to_string(),
        });
        let mut tx = BsvTx::new();
        tx.add_input(BsvTxIn {
            source_txid: Some("00".repeat(32)),
            source_output_index: 0,
            // OP_TRUE coin: empty (but PRESENT) scriptSig. `None` means the
            // transaction is unsigned, which the validating provider rejects.
            unlocking_script: Some(bsv::script::UnlockingScript::from_hex("").unwrap()),
            sequence: 0xffffffff,
            source_transaction: None,
        });
        tx.add_output(BsvTxOut {
            satoshis: Some(50_000),
            locking_script: LockingScript::from_hex("51").unwrap(),
            change: false,
        });
        let txid = provider.broadcast(&tx).unwrap();

        assert_eq!(txid.len(), 64);
        assert!(txid.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(provider.get_broadcasted_txs().len(), 1);
        // The stored hex should match the transaction's serialization
        assert!(!provider.get_broadcasted_txs()[0].is_empty());
    }

    #[test]
    fn mock_provider_deterministic_txids() {
        use bsv::transaction::{
            Transaction as BsvTx,
            TransactionInput as BsvTxIn,
            TransactionOutput as BsvTxOut,
        };
        use bsv::script::LockingScript;

        fn make_test_tx() -> BsvTx {
            let mut tx = BsvTx::new();
            tx.add_input(BsvTxIn {
                source_txid: Some("aa".repeat(32)),
                source_output_index: 0,
                unlocking_script: Some(bsv::script::UnlockingScript::from_hex("").unwrap()),
                sequence: 0xffffffff,
                source_transaction: None,
            });
            tx.add_output(BsvTxOut {
                satoshis: Some(1000),
                locking_script: LockingScript::from_hex("51").unwrap(),
                change: false,
            });
            tx
        }

        fn seeded() -> MockProvider {
            let mut p = MockProvider::testnet();
            p.add_utxo("mock", Utxo {
                txid: "aa".repeat(32),
                output_index: 0,
                satoshis: 100_000,
                script: "51".to_string(),
            });
            p
        }

        let mut p1 = seeded();
        let mut p2 = seeded();

        let txid1 = p1.broadcast(&make_test_tx()).unwrap();
        let txid2 = p2.broadcast(&make_test_tx()).unwrap();

        assert_eq!(txid1, txid2);
    }

    #[test]
    fn mock_provider_network() {
        let provider = MockProvider::new("mainnet");
        assert_eq!(provider.get_network(), "mainnet");
    }
}
