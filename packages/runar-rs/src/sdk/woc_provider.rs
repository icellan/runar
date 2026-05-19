//! WhatsOnChain provider — HTTP-based BSV blockchain API.

use bsv::transaction::Transaction as BsvTransaction;
use serde_json::Value;
use super::types::{TransactionData, TxInput, TxOutput, Utxo};
use super::provider::Provider;
use super::errors::{assert_script_hex_under_limit, MAX_SCRIPT_BYTES};

// ---------------------------------------------------------------------------
// WhatsOnChainProvider
// ---------------------------------------------------------------------------

/// Provider implementation that fetches data from the WhatsOnChain API.
///
/// Supports mainnet and testnet. Uses stdlib TCP + manual HTTP for zero
/// additional dependencies (no reqwest / ureq needed).
pub struct WhatsOnChainProvider {
    network: String,
    base_url: String,
}

impl WhatsOnChainProvider {
    /// Create a new WhatsOnChainProvider for the given network.
    ///
    /// Valid networks: `"mainnet"`, `"testnet"`.
    pub fn new(network: &str) -> Self {
        let base_url = match network {
            "mainnet" => "https://api.whatsonchain.com/v1/bsv/main".to_string(),
            _ => "https://api.whatsonchain.com/v1/bsv/test".to_string(),
        };
        WhatsOnChainProvider {
            network: network.to_string(),
            base_url,
        }
    }

    /// Perform an HTTP GET request and return the response body as a string.
    fn http_get(&self, url: &str) -> Result<String, String> {
        let resp = ureq::get(url)
            .call()
            .map_err(|e| format!("WoC GET {} failed: {}", url, e))?;
        resp.into_string()
            .map_err(|e| format!("WoC GET {} read body: {}", url, e))
    }

    /// Perform an HTTP POST request and return the response body as a string.
    fn http_post(&self, url: &str, body: &str) -> Result<String, String> {
        let resp = ureq::post(url)
            .set("Content-Type", "application/json")
            .send_string(body)
            .map_err(|e| format!("WoC POST {} failed: {}", url, e))?;
        resp.into_string()
            .map_err(|e| format!("WoC POST {} read body: {}", url, e))
    }
}

impl Provider for WhatsOnChainProvider {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> {
        let url = format!("{}/tx/hash/{}", self.base_url, txid);
        let body = self.http_get(&url)?;
        let data: Value = serde_json::from_str(&body)
            .map_err(|e| format!("WoC getTransaction parse: {}", e))?;

        let inputs: Vec<TxInput> = data["vin"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|vin| TxInput {
                txid: vin["txid"].as_str().unwrap_or("").to_string(),
                output_index: vin["vout"].as_u64().unwrap_or(0) as u32,
                script: vin["scriptSig"]["hex"].as_str().unwrap_or("").to_string(),
                sequence: vin["sequence"].as_u64().unwrap_or(0xffffffff) as u32,
            })
            .collect();

        let outputs: Vec<TxOutput> = data["vout"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|vout| {
                let val_btc = vout["value"].as_f64().unwrap_or(0.0);
                TxOutput {
                    satoshis: (val_btc * 1e8).round() as i64,
                    script: vout["scriptPubKey"]["hex"].as_str().unwrap_or("").to_string(),
                }
            })
            .collect();

        let raw = data["hex"].as_str().map(|s| s.to_string());

        Ok(TransactionData {
            txid: data["txid"].as_str().unwrap_or(txid).to_string(),
            version: data["version"].as_u64().unwrap_or(1) as u32,
            inputs,
            outputs,
            locktime: data["locktime"].as_u64().unwrap_or(0) as u32,
            raw,
        })
    }

    fn broadcast(&mut self, tx: &BsvTransaction) -> Result<String, String> {
        let raw_tx = tx.to_hex().map_err(|e| format!("broadcast: to_hex failed: {}", e))?;
        let url = format!("{}/tx/raw", self.base_url);
        let payload = serde_json::json!({ "txhex": raw_tx }).to_string();
        let body = self.http_post(&url, &payload)?;

        // WoC returns the txid as a JSON-encoded string
        let txid: String = serde_json::from_str(&body)
            .unwrap_or_else(|_| body.trim().trim_matches('"').to_string());
        Ok(txid)
    }

    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        let url = format!("{}/address/{}/unspent", self.base_url, address);
        let body = self.http_get(&url)?;
        let entries: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("WoC getUtxos parse: {}", e))?;

        let utxos: Vec<Utxo> = entries
            .iter()
            .map(|e| Utxo {
                txid: e["tx_hash"].as_str().unwrap_or("").to_string(),
                output_index: e["tx_pos"].as_u64().unwrap_or(0) as u32,
                satoshis: e["value"].as_i64().unwrap_or(0),
                script: String::new(), // WoC doesn't return script in UTXO list
            })
            .collect();
        // DoS-bound: defensive — WoC currently returns empty scripts but a
        // future enriched response must not bypass MAX_SCRIPT_BYTES.
        for u in &utxos {
            if u.script.is_empty() { continue; }
            assert_script_hex_under_limit(
                &u.script, MAX_SCRIPT_BYTES,
                &format!("WhatsOnChainProvider.get_utxos({})", address),
            )?;
        }
        Ok(utxos)
    }

    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String> {
        let url = format!("{}/script/{}/unspent", self.base_url, script_hash);
        let body = match self.http_get(&url) {
            Ok(b) => b,
            Err(e) => {
                // 404 simply means no UTXO found
                if e.contains("404") {
                    return Ok(None);
                }
                return Err(e);
            }
        };

        let entries: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("WoC getContractUtxo parse: {}", e))?;

        if entries.is_empty() {
            return Ok(None);
        }

        let first = &entries[0];
        let utxo = Utxo {
            txid: first["tx_hash"].as_str().unwrap_or("").to_string(),
            output_index: first["tx_pos"].as_u64().unwrap_or(0) as u32,
            satoshis: first["value"].as_i64().unwrap_or(0),
            script: String::new(),
        };
        if !utxo.script.is_empty() {
            assert_script_hex_under_limit(
                &utxo.script, MAX_SCRIPT_BYTES,
                &format!("WhatsOnChainProvider.get_contract_utxo({})", script_hash),
            )?;
        }
        Ok(Some(utxo))
    }

    fn get_network(&self) -> &str {
        &self.network
    }

    fn get_fee_rate(&self) -> Result<i64, String> {
        // BSV standard relay fee is 0.1 sat/byte (100 sat/KB).
        Ok(100)
    }

    fn get_raw_transaction(&self, txid: &str) -> Result<String, String> {
        let url = format!("{}/tx/{}/hex", self.base_url, txid);
        let body = self.http_get(&url)?;
        Ok(body.trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn woc_provider_new_mainnet() {
        let p = WhatsOnChainProvider::new("mainnet");
        assert_eq!(p.get_network(), "mainnet");
        assert_eq!(p.base_url, "https://api.whatsonchain.com/v1/bsv/main");
    }

    #[test]
    fn woc_provider_new_testnet() {
        let p = WhatsOnChainProvider::new("testnet");
        assert_eq!(p.get_network(), "testnet");
        assert_eq!(p.base_url, "https://api.whatsonchain.com/v1/bsv/test");
    }

    #[test]
    fn woc_provider_get_fee_rate() {
        let p = WhatsOnChainProvider::new("mainnet");
        assert_eq!(p.get_fee_rate().unwrap(), 100);
    }
}
