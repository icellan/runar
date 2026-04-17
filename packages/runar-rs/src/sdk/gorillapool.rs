//! GorillaPool 1sat Ordinals provider — HTTP-based BSV blockchain + ordinals API.
//!
//! Implements the standard Provider trait plus ordinal-specific methods
//! for querying inscriptions, BSV-20/BSV-21 balances, and token UTXOs.
//!
//! Endpoints:
//!   Mainnet: https://ordinals.gorillapool.io/api/
//!   Testnet: https://testnet.ordinals.gorillapool.io/api/

use bsv::transaction::Transaction as BsvTransaction;
use serde_json::Value;
use super::types::{TransactionData, TxInput, TxOutput, Utxo};
use super::provider::Provider;

// ---------------------------------------------------------------------------
// Ordinal-specific response types
// ---------------------------------------------------------------------------

/// Basic inscription metadata returned by GorillaPool.
#[derive(Debug, Clone)]
pub struct InscriptionInfo {
    pub txid: String,
    pub vout: u32,
    pub origin: String,
    pub content_type: String,
    pub content_length: u64,
    pub height: u64,
}

/// Full inscription detail including hex-encoded content data.
#[derive(Debug, Clone)]
pub struct InscriptionDetail {
    pub txid: String,
    pub vout: u32,
    pub origin: String,
    pub content_type: String,
    pub content_length: u64,
    pub height: u64,
    pub data: String, // hex-encoded content
}

// ---------------------------------------------------------------------------
// GorillaPoolProvider
// ---------------------------------------------------------------------------

/// Provider implementation that fetches data from the GorillaPool 1sat
/// Ordinals API.
///
/// Supports mainnet and testnet. Uses `ureq` for HTTP requests (same as
/// WhatsOnChainProvider).
pub struct GorillaPoolProvider {
    network: String,
    base_url: String,
}

impl GorillaPoolProvider {
    /// Create a new GorillaPoolProvider for the given network.
    ///
    /// Valid networks: `"mainnet"`, `"testnet"`.
    pub fn new(network: &str) -> Self {
        let base_url = match network {
            "mainnet" => "https://ordinals.gorillapool.io/api".to_string(),
            _ => "https://testnet.ordinals.gorillapool.io/api".to_string(),
        };
        GorillaPoolProvider {
            network: network.to_string(),
            base_url,
        }
    }

    /// Perform an HTTP GET request and return the response body as a string.
    fn http_get(&self, url: &str) -> Result<String, String> {
        let resp = ureq::get(url)
            .call()
            .map_err(|e| format!("GorillaPool GET {} failed: {}", url, e))?;
        resp.into_string()
            .map_err(|e| format!("GorillaPool GET {} read body: {}", url, e))
    }

    /// Perform an HTTP POST request and return the response body as a string.
    fn http_post(&self, url: &str, body: &str) -> Result<String, String> {
        let resp = ureq::post(url)
            .set("Content-Type", "application/json")
            .send_string(body)
            .map_err(|e| format!("GorillaPool POST {} failed: {}", url, e))?;
        resp.into_string()
            .map_err(|e| format!("GorillaPool POST {} read body: {}", url, e))
    }

    // -----------------------------------------------------------------------
    // Ordinal-specific methods
    // -----------------------------------------------------------------------

    /// Get all inscriptions associated with an address.
    pub fn get_inscriptions_by_address(&self, address: &str) -> Result<Vec<InscriptionInfo>, String> {
        let url = format!("{}/inscriptions/address/{}", self.base_url, address);
        let body = match self.http_get(&url) {
            Ok(b) => b,
            Err(e) => {
                if e.contains("404") {
                    return Ok(vec![]);
                }
                return Err(e);
            }
        };
        let entries: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("GorillaPool getInscriptionsByAddress parse: {}", e))?;

        Ok(entries
            .iter()
            .map(|e| InscriptionInfo {
                txid: e["txid"].as_str().unwrap_or("").to_string(),
                vout: e["vout"].as_u64().unwrap_or(0) as u32,
                origin: e["origin"].as_str().unwrap_or("").to_string(),
                content_type: e["contentType"].as_str().unwrap_or("").to_string(),
                content_length: e["contentLength"].as_u64().unwrap_or(0),
                height: e["height"].as_u64().unwrap_or(0),
            })
            .collect())
    }

    /// Get inscription details (including content) by inscription ID.
    ///
    /// `inscription_id` is in format `<txid>_<vout>`.
    pub fn get_inscription(&self, inscription_id: &str) -> Result<InscriptionDetail, String> {
        let url = format!("{}/inscriptions/{}", self.base_url, inscription_id);
        let body = self.http_get(&url)?;
        let e: Value = serde_json::from_str(&body)
            .map_err(|e| format!("GorillaPool getInscription parse: {}", e))?;

        Ok(InscriptionDetail {
            txid: e["txid"].as_str().unwrap_or("").to_string(),
            vout: e["vout"].as_u64().unwrap_or(0) as u32,
            origin: e["origin"].as_str().unwrap_or("").to_string(),
            content_type: e["contentType"].as_str().unwrap_or("").to_string(),
            content_length: e["contentLength"].as_u64().unwrap_or(0),
            height: e["height"].as_u64().unwrap_or(0),
            data: e["data"].as_str().unwrap_or("").to_string(),
        })
    }

    /// Get BSV-20 (v1, tick-based) token balance for an address.
    pub fn get_bsv20_balance(&self, address: &str, tick: &str) -> Result<String, String> {
        let url = format!(
            "{}/bsv20/balance/{}/{}",
            self.base_url, address, urlencoded(tick),
        );
        let body = match self.http_get(&url) {
            Ok(b) => b,
            Err(e) => {
                if e.contains("404") {
                    return Ok("0".to_string());
                }
                return Err(e);
            }
        };
        let result: Value = serde_json::from_str(&body).unwrap_or(Value::String(body.trim().to_string()));
        Ok(match result {
            Value::String(s) => s,
            _ => result["balance"].as_str().unwrap_or("0").to_string(),
        })
    }

    /// Get BSV-20 token UTXOs for an address and ticker.
    pub fn get_bsv20_utxos(&self, address: &str, tick: &str) -> Result<Vec<Utxo>, String> {
        let url = format!(
            "{}/bsv20/utxos/{}/{}",
            self.base_url, address, urlencoded(tick),
        );
        self.fetch_utxo_list(&url)
    }

    /// Get BSV-21 (v2, ID-based) token balance for an address.
    ///
    /// `id` is the token ID in format `<txid>_<vout>`.
    pub fn get_bsv21_balance(&self, address: &str, id: &str) -> Result<String, String> {
        let url = format!(
            "{}/bsv20/balance/{}/{}",
            self.base_url, address, urlencoded(id),
        );
        let body = match self.http_get(&url) {
            Ok(b) => b,
            Err(e) => {
                if e.contains("404") {
                    return Ok("0".to_string());
                }
                return Err(e);
            }
        };
        let result: Value = serde_json::from_str(&body).unwrap_or(Value::String(body.trim().to_string()));
        Ok(match result {
            Value::String(s) => s,
            _ => result["balance"].as_str().unwrap_or("0").to_string(),
        })
    }

    /// Get BSV-21 token UTXOs for an address and token ID.
    ///
    /// `id` is the token ID in format `<txid>_<vout>`.
    pub fn get_bsv21_utxos(&self, address: &str, id: &str) -> Result<Vec<Utxo>, String> {
        let url = format!(
            "{}/bsv20/utxos/{}/{}",
            self.base_url, address, urlencoded(id),
        );
        self.fetch_utxo_list(&url)
    }

    /// Shared helper to fetch a list of UTXOs from a GorillaPool endpoint.
    fn fetch_utxo_list(&self, url: &str) -> Result<Vec<Utxo>, String> {
        let body = match self.http_get(url) {
            Ok(b) => b,
            Err(e) => {
                if e.contains("404") {
                    return Ok(vec![]);
                }
                return Err(e);
            }
        };
        let entries: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("GorillaPool fetch UTXOs parse: {}", e))?;

        Ok(entries
            .iter()
            .map(|e| Utxo {
                txid: e["txid"].as_str().unwrap_or("").to_string(),
                output_index: e["vout"].as_u64().unwrap_or(0) as u32,
                satoshis: e["satoshis"].as_i64().unwrap_or(0),
                script: e["script"].as_str().unwrap_or("").to_string(),
            })
            .collect())
    }
}

/// Minimal URL encoding for path segments (just handles common cases).
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('#', "%23")
        .replace('&', "%26")
        .replace('+', "%2B")
        .replace('/', "%2F")
}

// ---------------------------------------------------------------------------
// Provider trait implementation
// ---------------------------------------------------------------------------

impl Provider for GorillaPoolProvider {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> {
        let url = format!("{}/tx/{}", self.base_url, txid);
        let body = self.http_get(&url)?;
        let data: Value = serde_json::from_str(&body)
            .map_err(|e| format!("GorillaPool getTransaction parse: {}", e))?;

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
                // GorillaPool may return value in BTC or satoshis
                let val = vout["value"].as_f64().unwrap_or(0.0);
                let satoshis = if val < 1000.0 {
                    (val * 1e8).round() as i64
                } else {
                    val as i64
                };
                TxOutput {
                    satoshis,
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
        let url = format!("{}/tx", self.base_url);
        let payload = serde_json::json!({ "rawTx": raw_tx }).to_string();
        let body = self.http_post(&url, &payload)?;

        // GorillaPool returns the txid as a JSON-encoded string or { "txid": "..." }
        let result: Value = serde_json::from_str(&body)
            .unwrap_or(Value::String(body.trim().trim_matches('"').to_string()));
        Ok(match result {
            Value::String(s) => s,
            _ => result["txid"].as_str().unwrap_or("").to_string(),
        })
    }

    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        let url = format!("{}/address/{}/utxos", self.base_url, address);
        let body = match self.http_get(&url) {
            Ok(b) => b,
            Err(e) => {
                if e.contains("404") {
                    return Ok(vec![]);
                }
                return Err(e);
            }
        };
        let entries: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("GorillaPool getUtxos parse: {}", e))?;

        Ok(entries
            .iter()
            .map(|e| Utxo {
                txid: e["txid"].as_str().unwrap_or("").to_string(),
                output_index: e["vout"].as_u64().unwrap_or(0) as u32,
                satoshis: e["satoshis"].as_i64().unwrap_or(0),
                script: e["script"].as_str().unwrap_or("").to_string(),
            })
            .collect())
    }

    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String> {
        let url = format!("{}/script/{}/utxos", self.base_url, script_hash);
        let body = match self.http_get(&url) {
            Ok(b) => b,
            Err(e) => {
                if e.contains("404") {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let entries: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("GorillaPool getContractUtxo parse: {}", e))?;

        if entries.is_empty() {
            return Ok(None);
        }

        let first = &entries[0];
        Ok(Some(Utxo {
            txid: first["txid"].as_str().unwrap_or("").to_string(),
            output_index: first["vout"].as_u64().unwrap_or(0) as u32,
            satoshis: first["satoshis"].as_i64().unwrap_or(0),
            script: first["script"].as_str().unwrap_or("").to_string(),
        }))
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
    fn gorillapool_provider_new_mainnet() {
        let p = GorillaPoolProvider::new("mainnet");
        assert_eq!(p.get_network(), "mainnet");
        assert_eq!(p.base_url, "https://ordinals.gorillapool.io/api");
    }

    #[test]
    fn gorillapool_provider_new_testnet() {
        let p = GorillaPoolProvider::new("testnet");
        assert_eq!(p.get_network(), "testnet");
        assert_eq!(p.base_url, "https://testnet.ordinals.gorillapool.io/api");
    }

    #[test]
    fn gorillapool_provider_get_fee_rate() {
        let p = GorillaPoolProvider::new("mainnet");
        assert_eq!(p.get_fee_rate().unwrap(), 100);
    }

    #[test]
    fn urlencoded_handles_special_chars() {
        assert_eq!(urlencoded("hello world"), "hello%20world");
        assert_eq!(urlencoded("a+b"), "a%2Bb");
        assert_eq!(urlencoded("100%"), "100%25");
    }
}
