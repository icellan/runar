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
use super::errors::{assert_script_hex_under_limit, MAX_SCRIPT_BYTES};

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

    /// Perform an HTTP GET request and return the raw response body bytes.
    fn http_get_bytes(&self, url: &str) -> Result<Vec<u8>, String> {
        let resp = ureq::get(url)
            .call()
            .map_err(|e| format!("GorillaPool GET {} failed: {}", url, e))?;
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut body)
            .map_err(|e| format!("GorillaPool GET {} read body: {}", url, e))?;
        Ok(body)
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
    /// Fetch a transaction via GET /tx/{txid}/raw (the bare serialized tx).
    ///
    /// Each output's satoshis is read from its 8-byte little-endian field, so
    /// values are exact (F-027: the former JSON `vout[].value` decode with its
    /// `< 1000 → BTC` guess targeted a field GorillaPool never returns). The
    /// body must hash to the requested txid.
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> {
        let url = format!("{}/tx/{}/raw", self.base_url, txid);
        let raw = self.http_get_bytes(&url)?;

        let mut digest = bsv::primitives::hash::hash256(&raw);
        digest.reverse();
        let body_txid = bsv::primitives::utils::to_hex(&digest);
        if body_txid != txid.to_ascii_lowercase() {
            return Err(format!(
                "GorillaPool getTransaction: txid mismatch: response body hashes to {}, requested {}",
                body_txid, txid
            ));
        }

        let tx = BsvTransaction::from_binary(&mut std::io::Cursor::new(&raw))
            .map_err(|e| format!("GorillaPool getTransaction: parsing tx: {}", e))?;

        let inputs: Vec<TxInput> = tx
            .inputs
            .iter()
            .map(|input| TxInput {
                txid: input.source_txid.clone().unwrap_or_default(),
                output_index: input.source_output_index,
                script: input
                    .unlocking_script
                    .as_ref()
                    .map(|s| s.to_hex())
                    .unwrap_or_default(),
                sequence: input.sequence,
            })
            .collect();

        let outputs: Vec<TxOutput> = tx
            .outputs
            .iter()
            .map(|output| TxOutput {
                satoshis: output.satoshis.unwrap_or(0) as i64,
                script: output.locking_script.to_hex(),
            })
            .collect();

        Ok(TransactionData {
            txid: body_txid,
            version: tx.version,
            inputs,
            outputs,
            locktime: tx.lock_time,
            raw: Some(bsv::primitives::utils::to_hex(&raw)),
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

        let utxos: Vec<Utxo> = entries
            .iter()
            .map(|e| Utxo {
                txid: e["txid"].as_str().unwrap_or("").to_string(),
                output_index: e["vout"].as_u64().unwrap_or(0) as u32,
                satoshis: e["satoshis"].as_i64().unwrap_or(0),
                script: e["script"].as_str().unwrap_or("").to_string(),
            })
            .collect();
        // DoS-bound: reject pathological scripts at the provider boundary.
        for u in &utxos {
            if u.script.is_empty() { continue; }
            assert_script_hex_under_limit(
                &u.script, MAX_SCRIPT_BYTES,
                &format!("GorillaPoolProvider.get_utxos({})", address),
            )?;
        }
        Ok(utxos)
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
        let utxo = Utxo {
            txid: first["txid"].as_str().unwrap_or("").to_string(),
            output_index: first["vout"].as_u64().unwrap_or(0) as u32,
            satoshis: first["satoshis"].as_i64().unwrap_or(0),
            script: first["script"].as_str().unwrap_or("").to_string(),
        };
        if !utxo.script.is_empty() {
            assert_script_hex_under_limit(
                &utxo.script, MAX_SCRIPT_BYTES,
                &format!("GorillaPoolProvider.get_contract_utxo({})", script_hash),
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

    // -----------------------------------------------------------------------
    // F-027: get_transaction decodes the real GorillaPool response.
    //
    // GET /tx/{txid} is binary, not the JSON `vout[].value` the old decoder
    // (with its `< 1000 → BTC` guess) expected. get_transaction now fetches
    // /tx/{txid}/raw and reads each output's 8-byte LE satoshis.
    // Proves: the shared recorded vectors (conformance/sdk-gorillapool)
    // decode exactly — a real 1-sat inscription output is 1 sat; 999, 1000,
    // 1e12 and 2.1e15 are exact; a body hashing to another txid is rejected.
    // Does NOT prove the live API still serves /tx/{txid}/raw.
    // -----------------------------------------------------------------------

    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    fn load_vectors() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/sdk-gorillapool/vectors.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        serde_json::from_str(&text).unwrap()
    }

    fn sha256_hex_of_hex(h: &str) -> String {
        bsv::primitives::utils::to_hex(&bsv::primitives::hash::sha256(
            &bsv::primitives::utils::from_hex(h).unwrap(),
        ))
    }

    /// One-shot HTTP server: serves `body` at `/tx/{txid}/raw`, 404 otherwise.
    fn serve_raw_tx(txid: &str, body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let want = format!("GET /tx/{}/raw ", txid);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let (status, payload) = if buf.starts_with(want.as_bytes()) {
                    ("200 OK", body)
                } else {
                    ("404 Not Found", br#"{"message":"Not Found"}"#.to_vec())
                };
                let head = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    payload.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&payload);
                let _ = stream.flush();
            }
        });
        format!("http://{}", addr)
    }

    fn provider_at(base_url: String) -> GorillaPoolProvider {
        let mut p = GorillaPoolProvider::new("mainnet");
        p.base_url = base_url;
        p
    }

    #[test]
    fn f027_get_transaction_decodes_recorded_raw_tx_vectors() {
        let doc = load_vectors();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 3);
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let txid = v["txid"].as_str().unwrap();
            let resp_hex = v["responseHex"].as_str().unwrap();
            let exp = &v["expected"];
            let body = bsv::primitives::utils::from_hex(resp_hex).unwrap();
            let p = provider_at(serve_raw_tx(txid, body));
            let data = p
                .get_transaction(txid)
                .unwrap_or_else(|e| panic!("{}: get_transaction failed: {}", name, e));

            assert_eq!(data.txid, txid, "{}", name);
            assert_eq!(data.version as u64, exp["version"].as_u64().unwrap(), "{}", name);
            assert_eq!(data.locktime as u64, exp["locktime"].as_u64().unwrap(), "{}", name);
            assert_eq!(data.raw.as_deref(), Some(resp_hex), "{}: raw", name);
            assert_eq!(data.inputs.len() as u64, exp["inputCount"].as_u64().unwrap(), "{}", name);
            let fi = &exp["firstInput"];
            let in0 = &data.inputs[0];
            assert_eq!(in0.txid, fi["txid"].as_str().unwrap(), "{}", name);
            assert_eq!(in0.output_index as u64, fi["outputIndex"].as_u64().unwrap(), "{}", name);
            assert_eq!(in0.sequence as u64, fi["sequence"].as_u64().unwrap(), "{}", name);
            assert_eq!(in0.script.len() as u64, 2 * fi["scriptLen"].as_u64().unwrap(), "{}", name);
            assert_eq!(sha256_hex_of_hex(&in0.script), fi["scriptSha256"].as_str().unwrap(), "{}", name);
            let outs = exp["outputs"].as_array().unwrap();
            let got: Vec<i64> = data.outputs.iter().map(|o| o.satoshis).collect();
            let want: Vec<i64> = outs.iter().map(|o| o["satoshis"].as_i64().unwrap()).collect();
            assert_eq!(got, want, "{}: output satoshis", name);
            for (o, e) in data.outputs.iter().zip(outs) {
                assert_eq!(o.script.len() as u64, 2 * e["scriptLen"].as_u64().unwrap(), "{}", name);
                assert_eq!(sha256_hex_of_hex(&o.script), e["scriptSha256"].as_str().unwrap(), "{}", name);
            }
        }
    }

    #[test]
    fn f027_get_transaction_rejects_txid_mismatch() {
        let doc = load_vectors();
        for rv in doc["rejection_vectors"].as_array().unwrap() {
            let requested = rv["requestedTxid"].as_str().unwrap();
            let src = doc["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == rv["responseOf"])
                .unwrap();
            let body = bsv::primitives::utils::from_hex(src["responseHex"].as_str().unwrap()).unwrap();
            let p = provider_at(serve_raw_tx(requested, body));
            let err = p.get_transaction(requested).err().expect("expected an error");
            assert!(err.contains("txid mismatch"), "{}: got {}", rv["name"], err);
        }
    }

    #[test]
    fn urlencoded_handles_special_chars() {
        assert_eq!(urlencoded("hello world"), "hello%20world");
        assert_eq!(urlencoded("a+b"), "a%2Bb");
        assert_eq!(urlencoded("100%"), "100%25");
    }
}
