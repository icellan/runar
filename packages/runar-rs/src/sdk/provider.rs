//! Provider trait and MockProvider for blockchain access.

use std::collections::HashMap;
use super::types::{Transaction, Utxo};
#[cfg(test)]
use super::types::TxOutput;

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// Abstraction over blockchain access for fetching transactions, UTXOs,
/// and broadcasting raw transactions.
pub trait Provider {
    /// Fetch a transaction by its txid.
    fn get_transaction(&self, txid: &str) -> Result<Transaction, String>;

    /// Broadcast a raw transaction hex. Returns the txid on success.
    fn broadcast(&mut self, raw_tx: &str) -> Result<String, String>;

    /// Get all UTXOs for a given address.
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String>;

    /// Find a UTXO by its script hash (for stateful contract lookup).
    /// Returns None if no UTXO is found with the given script hash.
    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String>;

    /// Return the network this provider is connected to.
    fn get_network(&self) -> &str;

    /// Get the current fee rate in satoshis per byte.
    /// BSV standard is 1 sat/byte.
    fn get_fee_rate(&self) -> Result<i64, String>;
}

// ---------------------------------------------------------------------------
// MockProvider
// ---------------------------------------------------------------------------

/// In-memory mock provider for unit tests and local development.
///
/// Allows injecting transactions and UTXOs, and records broadcasts for
/// assertion in tests.
pub struct MockProvider {
    transactions: HashMap<String, Transaction>,
    utxos: HashMap<String, Vec<Utxo>>,
    contract_utxos: HashMap<String, Utxo>,
    broadcasted_txs: Vec<String>,
    network: String,
    broadcast_count: u32,
    fee_rate: i64,
}

impl MockProvider {
    /// Create a new MockProvider for the given network.
    pub fn new(network: &str) -> Self {
        MockProvider {
            transactions: HashMap::new(),
            utxos: HashMap::new(),
            contract_utxos: HashMap::new(),
            broadcasted_txs: Vec::new(),
            network: network.to_string(),
            broadcast_count: 0,
            fee_rate: 1,
        }
    }

    /// Create a new MockProvider defaulting to testnet.
    pub fn testnet() -> Self {
        Self::new("testnet")
    }

    // -----------------------------------------------------------------------
    // Test data injection
    // -----------------------------------------------------------------------

    /// Add a transaction to the mock store.
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.transactions.insert(tx.txid.clone(), tx);
    }

    /// Add a UTXO for an address.
    pub fn add_utxo(&mut self, address: &str, utxo: Utxo) {
        self.utxos
            .entry(address.to_string())
            .or_insert_with(Vec::new)
            .push(utxo);
    }

    /// Add a contract UTXO for lookup by script hash.
    pub fn add_contract_utxo(&mut self, script_hash: &str, utxo: Utxo) {
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

impl Provider for MockProvider {
    fn get_transaction(&self, txid: &str) -> Result<Transaction, String> {
        self.transactions
            .get(txid)
            .cloned()
            .ok_or_else(|| format!("MockProvider: transaction {} not found", txid))
    }

    fn broadcast(&mut self, raw_tx: &str) -> Result<String, String> {
        self.broadcasted_txs.push(raw_tx.to_string());
        self.broadcast_count += 1;
        // Generate a deterministic fake txid from the broadcast count
        let fake_txid = mock_sha256_hex(&format!(
            "mock-broadcast-{}-{}",
            self.broadcast_count,
            &raw_tx[..raw_tx.len().min(16)]
        ));
        Ok(fake_txid)
    }

    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        Ok(self.utxos.get(address).cloned().unwrap_or_default())
    }

    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String> {
        Ok(self.contract_utxos.get(script_hash).cloned())
    }

    fn get_network(&self) -> &str {
        &self.network
    }

    fn get_fee_rate(&self) -> Result<i64, String> {
        Ok(self.fee_rate)
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
        let tx = Transaction {
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
        let mut provider = MockProvider::testnet();
        let txid = provider.broadcast("deadbeef").unwrap();

        assert_eq!(txid.len(), 64);
        assert!(txid.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(provider.get_broadcasted_txs().len(), 1);
        assert_eq!(provider.get_broadcasted_txs()[0], "deadbeef");
    }

    #[test]
    fn mock_provider_deterministic_txids() {
        let mut p1 = MockProvider::testnet();
        let mut p2 = MockProvider::testnet();

        let txid1 = p1.broadcast("aabb").unwrap();
        let txid2 = p2.broadcast("aabb").unwrap();

        assert_eq!(txid1, txid2);
    }

    #[test]
    fn mock_provider_network() {
        let provider = MockProvider::new("mainnet");
        assert_eq!(provider.get_network(), "mainnet");
    }
}
