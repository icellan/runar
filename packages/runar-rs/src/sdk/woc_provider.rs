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

    /// WoC's GET /address/{address}/unspent listing carries outpoints and
    /// values but no locking script. The script is the BIP-143 scriptCode a
    /// signer commits to, so an empty one yields signatures no OP_CHECKSIG
    /// accepts (F-040). Each distinct txid is therefore fetched via
    /// GET /tx/{txid}/hex, its double-SHA256 must equal the txid, and tx_pos
    /// must be an output whose value equals the listed value. Any failure is
    /// an error; no UTXO is returned with an empty script.
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        let url = format!("{}/address/{}/unspent", self.base_url, address);
        let body = self.http_get(&url)?;
        let entries: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("WoC getUtxos parse: {}", e))?;

        let mut txs: std::collections::HashMap<String, BsvTransaction> =
            std::collections::HashMap::new();
        let mut utxos: Vec<Utxo> = Vec::with_capacity(entries.len());
        for e in &entries {
            let txid = e["tx_hash"]
                .as_str()
                .ok_or_else(|| "WoC getUtxos: entry has no tx_hash".to_string())?
                .to_string();
            let tx_pos = e["tx_pos"]
                .as_u64()
                .ok_or_else(|| format!("WoC getUtxos: entry {} has no tx_pos", txid))?;
            let value = e["value"]
                .as_u64()
                .ok_or_else(|| format!("WoC getUtxos: entry {}:{} has no value", txid, tx_pos))?;

            if !txs.contains_key(&txid) {
                let raw_hex = self
                    .get_raw_transaction(&txid)
                    .map_err(|err| format!("WoC getUtxos: fetching tx {}: {}", txid, err))?;
                let raw = bsv::primitives::utils::from_hex(&raw_hex)
                    .map_err(|err| format!("WoC getUtxos: /tx/{}/hex body is not hex: {}", txid, err))?;
                let mut digest = bsv::primitives::hash::hash256(&raw);
                digest.reverse();
                let body_txid = bsv::primitives::utils::to_hex(&digest);
                if body_txid != txid.to_ascii_lowercase() {
                    return Err(format!(
                        "WoC getUtxos: txid mismatch: /tx/{}/hex body hashes to {}",
                        txid, body_txid
                    ));
                }
                let tx = BsvTransaction::from_binary(&mut std::io::Cursor::new(&raw))
                    .map_err(|err| format!("WoC getUtxos: parsing tx {}: {}", txid, err))?;
                txs.insert(txid.clone(), tx);
            }
            let tx = &txs[&txid];
            let out = tx.outputs.get(tx_pos as usize).ok_or_else(|| {
                format!(
                    "WoC getUtxos: no output {} in tx {} ({} outputs)",
                    tx_pos, txid, tx.outputs.len()
                )
            })?;
            let out_sats = out.satoshis.unwrap_or(0);
            if out_sats != value {
                return Err(format!(
                    "WoC getUtxos: value mismatch for {}:{}: listing says {}, tx says {}",
                    txid, tx_pos, value, out_sats
                ));
            }
            let script = out.locking_script.to_hex();
            if script.is_empty() {
                return Err(format!("WoC getUtxos: empty locking script for {}:{}", txid, tx_pos));
            }
            assert_script_hex_under_limit(
                &script, MAX_SCRIPT_BYTES,
                &format!("WhatsOnChainProvider.get_utxos({})", address),
            )?;
            utxos.push(Utxo {
                txid,
                output_index: tx_pos as u32,
                satoshis: value as i64,
                script,
            });
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

    // -----------------------------------------------------------------------
    // F-040: get_utxos returns the real locking script.
    //
    // WoC's /address/{a}/unspent listing has no script, and get_utxos used to
    // return script "" — which became the BIP-143 scriptCode of every funding
    // signature. get_utxos now fetches /tx/{txid}/hex per UTXO.
    // Proves: the shared recorded vectors (conformance/sdk-woc) yield the real
    // script + value; a body for another txid, a missing output, a value that
    // disagrees, an unavailable tx and an empty output script are errors.
    // Does NOT prove the live API still serves these shapes (recorded
    // 2026-09-29). The Spend.validate harm demo lives in the TS tier.
    // -----------------------------------------------------------------------

    use std::collections::HashMap;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    fn load_woc_vectors() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/sdk-woc/vectors.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        serde_json::from_str(&text).unwrap()
    }

    /// HTTP server: `routes` maps a request path to its body; anything else is 404.
    fn serve_routes(routes: HashMap<String, String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&buf).to_string();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let (status, payload) = match routes.get(&path) {
                    Some(b) => ("200 OK", b.clone()),
                    None => ("404 Not Found", "Not Found".to_string()),
                };
                let head = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    payload.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(payload.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{}", addr)
    }

    fn woc_at(address: &str, unspent_body: &str, raw_tx_hex: &Value) -> WhatsOnChainProvider {
        let mut routes = HashMap::new();
        routes.insert(format!("/address/{}/unspent", address), unspent_body.to_string());
        for (txid, body) in raw_tx_hex.as_object().unwrap() {
            routes.insert(format!("/tx/{}/hex", txid), body.as_str().unwrap().to_string());
        }
        let mut p = WhatsOnChainProvider::new("mainnet");
        p.base_url = serve_routes(routes);
        p
    }

    #[test]
    fn f040_get_utxos_returns_recorded_locking_scripts() {
        let v = load_woc_vectors();
        let address = v["address"].as_str().unwrap();
        let p = woc_at(address, v["unspentBody"].as_str().unwrap(), &v["rawTxHex"]);
        let utxos = p.get_utxos(address).expect("get_utxos");
        let expected = v["expected"].as_array().unwrap();
        assert_eq!(utxos.len(), expected.len());
        for (u, e) in utxos.iter().zip(expected) {
            assert_eq!(u.txid, e["txid"].as_str().unwrap());
            assert_eq!(u.output_index as u64, e["outputIndex"].as_u64().unwrap());
            assert_eq!(u.satoshis, e["satoshis"].as_i64().unwrap());
            assert_eq!(u.script, e["script"].as_str().unwrap());
        }
    }

    #[test]
    fn f040_get_utxos_rejection_vectors() {
        let v = load_woc_vectors();
        let address = v["address"].as_str().unwrap();
        for rv in v["rejection_vectors"].as_array().unwrap() {
            let name = rv["name"].as_str().unwrap();
            let want = rv["error"].as_str().unwrap();
            let p = woc_at(address, rv["unspentBody"].as_str().unwrap(), &rv["rawTxHex"]);
            match p.get_utxos(address) {
                Ok(u) => panic!("{}: expected an error containing {:?}, got {:?}", name, want, u),
                Err(e) => assert!(e.contains(want), "{}: error {:?} does not contain {:?}", name, e, want),
            }
        }
    }
}
