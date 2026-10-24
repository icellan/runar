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
use sha2::Digest as _;
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

    /// N-025: inscriptions currently held by an address — the unspent Txos
    /// from GET /txos/address/{address}/unspent whose `origin` is set.
    pub fn get_inscriptions_by_address(&self, address: &str) -> Result<Vec<InscriptionInfo>, String> {
        let entries = self.get_json_array(
            &format!("/txos/address/{}/unspent", address),
            "getInscriptionsByAddress",
        )?;
        Ok(entries
            .iter()
            .filter(|t| !t["origin"].is_null())
            .map(inscription_info)
            .collect())
    }

    /// N-025: GET /inscriptions/{outpoint} returns a Txo (not a content
    /// record). The content is GET /content/{outpoint} (host root), and its
    /// base64 sha256 must equal origin.data.insc.file.hash.
    ///
    /// `inscription_id` is in format `<txid>_<vout>`.
    pub fn get_inscription(&self, inscription_id: &str) -> Result<InscriptionDetail, String> {
        let t = self.get_json(&format!("/inscriptions/{}", inscription_id), "getInscription")?;
        if t["origin"].is_null() {
            return Err(format!(
                "GorillaPool getInscription: {} is not an inscription (no origin)",
                inscription_id
            ));
        }
        let info = inscription_info(&t);
        let content_url = format!("{}/content/{}", self.content_base_url(), inscription_id);
        let content = self
            .http_get_bytes(&content_url)
            .map_err(|e| format!("GorillaPool getInscription content: {}", e))?;
        let want = t["origin"]["data"]["insc"]["file"]["hash"].as_str();
        let got = sha2::Sha256::digest(&content);
        let matches = match want.and_then(base64_decode) {
            Some(w) => w.as_slice() == got.as_slice(),
            None => false,
        };
        if !matches {
            return Err(format!(
                "GorillaPool getInscription: content hash mismatch for {}: sha256 {}, inscription says {}",
                inscription_id,
                bsv::primitives::utils::to_hex(&got),
                want.unwrap_or("(none)")
            ));
        }
        Ok(InscriptionDetail {
            txid: info.txid,
            vout: info.vout,
            origin: info.origin,
            content_type: info.content_type,
            content_length: info.content_length,
            height: info.height,
            data: bsv::primitives::utils::to_hex(&content),
        })
    }

    /// N-025: BSV-20 (v1, tick-based) confirmed balance, from
    /// GET /bsv20/{address}/balance. No entry for the tick means "0".
    pub fn get_bsv20_balance(&self, address: &str, tick: &str) -> Result<String, String> {
        self.token_balance(address, "tick", tick, "getBSV20Balance")
    }

    /// N-025: BSV-20 token UTXOs, from GET /bsv20/{address}/tick/{tick}.
    pub fn get_bsv20_utxos(&self, address: &str, tick: &str) -> Result<Vec<Utxo>, String> {
        self.bsv20_utxo_list(
            &format!("/bsv20/{}/tick/{}", address, urlencoded(tick)),
            "getBSV20Utxos",
        )
    }

    /// N-025: BSV-21 (v2, ID-based) confirmed balance, from
    /// GET /bsv20/{address}/balance. No entry for the id means "0".
    ///
    /// `id` is the token ID in format `<txid>_<vout>`.
    pub fn get_bsv21_balance(&self, address: &str, id: &str) -> Result<String, String> {
        self.token_balance(address, "id", id, "getBSV21Balance")
    }

    /// N-025: BSV-21 token UTXOs, from GET /bsv20/{address}/id/{id}.
    ///
    /// `id` is the token ID in format `<txid>_<vout>`.
    pub fn get_bsv21_utxos(&self, address: &str, id: &str) -> Result<Vec<Utxo>, String> {
        self.bsv20_utxo_list(
            &format!("/bsv20/{}/id/{}", address, urlencoded(id)),
            "getBSV21Utxos",
        )
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Host root (base URL without the trailing `/api`), where /content lives.
    fn content_base_url(&self) -> &str {
        self.base_url.strip_suffix("/api").unwrap_or(&self.base_url)
    }

    /// GET a JSON route; any non-2xx (a 404 included) is an error.
    fn get_json(&self, path: &str, method: &str) -> Result<Value, String> {
        let body = self
            .http_get(&format!("{}{}", self.base_url, path))
            .map_err(|e| format!("GorillaPool {}: {}", method, e))?;
        serde_json::from_str(&body).map_err(|e| format!("GorillaPool {} parse: {}", method, e))
    }

    fn get_json_array(&self, path: &str, method: &str) -> Result<Vec<Value>, String> {
        match self.get_json(path, method)? {
            Value::Array(v) => Ok(v),
            other => Err(format!("GorillaPool {}: expected a JSON array, got {}", method, other)),
        }
    }

    /// GET /tx/{txid}/raw; the body must hash (sha256d, reversed) to txid.
    fn fetch_verified_raw(&self, txid: &str, method: &str) -> Result<Vec<u8>, String> {
        let url = format!("{}/tx/{}/raw", self.base_url, txid);
        let raw = self
            .http_get_bytes(&url)
            .map_err(|e| format!("GorillaPool {}: {}", method, e))?;
        let mut digest = bsv::primitives::hash::hash256(&raw);
        digest.reverse();
        let body_txid = bsv::primitives::utils::to_hex(&digest);
        if body_txid != txid.to_ascii_lowercase() {
            return Err(format!(
                "GorillaPool {}: txid mismatch: response body hashes to {}, requested {}",
                method, body_txid, txid
            ));
        }
        Ok(raw)
    }

    /// GET /bsv20/{address}/balance; the row whose `key` equals `value` ->
    /// all.confirmed; no such row -> "0".
    fn token_balance(&self, address: &str, key: &str, value: &str, method: &str) -> Result<String, String> {
        let rows = self.get_json_array(&format!("/bsv20/{}/balance", address), method)?;
        match rows.iter().find(|r| r[key].as_str() == Some(value)) {
            None => Ok("0".to_string()),
            Some(r) => r["all"]["confirmed"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| format!("GorillaPool {}: balance row without all.confirmed", method)),
        }
    }

    /// BSV20Txo[] -> UTXOs; the base64 `script` is decoded, empty refused.
    fn bsv20_utxo_list(&self, path: &str, method: &str) -> Result<Vec<Utxo>, String> {
        let rows = self.get_json_array(path, method)?;
        rows.iter()
            .map(|r| {
                let txid = r["txid"].as_str().ok_or_else(|| format!("GorillaPool {}: entry without txid", method))?;
                let vout = r["vout"].as_u64().ok_or_else(|| format!("GorillaPool {}: entry without vout", method))?;
                let satoshis = r["satoshis"].as_i64().ok_or_else(|| format!("GorillaPool {}: entry without integer satoshis", method))?;
                let script = r["script"]
                    .as_str()
                    .and_then(base64_decode)
                    .map(|b| bsv::primitives::utils::to_hex(&b))
                    .unwrap_or_default();
                if script.is_empty() {
                    return Err(format!("GorillaPool {}: no locking script for {}_{}", method, txid, vout));
                }
                assert_script_hex_under_limit(&script, MAX_SCRIPT_BYTES, &format!("GorillaPoolProvider.{}", method))?;
                Ok(Utxo { txid: txid.to_string(), output_index: vout as u32, satoshis, script })
            })
            .collect()
    }
}

fn inscription_info(t: &Value) -> InscriptionInfo {
    let file = &t["origin"]["data"]["insc"]["file"];
    InscriptionInfo {
        txid: t["txid"].as_str().unwrap_or("").to_string(),
        vout: t["vout"].as_u64().unwrap_or(0) as u32,
        origin: t["origin"]["outpoint"].as_str().unwrap_or("").to_string(),
        content_type: file["type"].as_str().unwrap_or("").to_string(),
        content_length: file["size"].as_u64().unwrap_or(0),
        height: t["height"].as_u64().unwrap_or(0),
    }
}

/// Strict standard-alphabet base64 decoder (padding optional). None on any
/// invalid character.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.trim_end_matches('=').as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        let n = chunk.len() - 1;
        for i in 0..n {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
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
        let raw = self.fetch_verified_raw(txid, "getTransaction")?;
        let body_txid = txid.to_ascii_lowercase();

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
        // N-025: the documented Broadcast body is {"rawtx": string} (lowercase).
        let payload = serde_json::json!({ "rawtx": raw_tx }).to_string();
        let body = self.http_post(&url, &payload)?;

        // GorillaPool returns the txid as a JSON-encoded string or { "txid": "..." }
        let result: Value = serde_json::from_str(&body)
            .unwrap_or(Value::String(body.trim().trim_matches('"').to_string()));
        Ok(match result {
            Value::String(s) => s,
            _ => result["txid"].as_str().unwrap_or("").to_string(),
        })
    }

    /// N-025: GET /txos/address/{address}/unspent (Txo[]). The listing has
    /// no locking script, so each entry's tx is fetched via /tx/{txid}/raw
    /// (hash-verified); the output must exist, its value must equal the
    /// listing's, and its script is returned. Any non-2xx (404 included) is
    /// an error. N-159: entries whose `origin` is set (1-sat ordinal
    /// inscriptions, BSV-20 / BSV-21 token outputs) are dropped before any
    /// fetch — spending one as a fee input destroys the inscription or token.
    /// They remain available via get_inscriptions_by_address /
    /// get_bsv20_utxos / get_bsv21_utxos.
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        let entries = self.get_json_array(&format!("/txos/address/{}/unspent", address), "getUtxos")?;
        let mut txs: std::collections::HashMap<String, BsvTransaction> = std::collections::HashMap::new();
        let mut utxos = Vec::with_capacity(entries.len());
        for e in &entries {
            if !e["origin"].is_null() {
                continue;
            }
            let txid = e["txid"].as_str().ok_or("GorillaPool getUtxos: entry without txid")?.to_string();
            let vout = e["vout"].as_u64().ok_or("GorillaPool getUtxos: entry without vout")?;
            let sats = e["satoshis"].as_u64().ok_or("GorillaPool getUtxos: entry without integer satoshis")?;
            if !txs.contains_key(&txid) {
                let raw = self.fetch_verified_raw(&txid, "getUtxos")?;
                let tx = BsvTransaction::from_binary(&mut std::io::Cursor::new(&raw))
                    .map_err(|e| format!("GorillaPool getUtxos: parsing tx {}: {}", txid, e))?;
                txs.insert(txid.clone(), tx);
            }
            let tx = &txs[&txid];
            let out = tx.outputs.get(vout as usize).ok_or_else(|| format!(
                "GorillaPool getUtxos: no output {} in tx {} ({} outputs)", vout, txid, tx.outputs.len()
            ))?;
            let out_sats = out.satoshis.unwrap_or(0);
            if out_sats != sats {
                return Err(format!(
                    "GorillaPool getUtxos: value mismatch for {}_{}: listing says {}, tx says {}",
                    txid, vout, sats, out_sats
                ));
            }
            let script = out.locking_script.to_hex();
            if script.is_empty() {
                return Err(format!("GorillaPool getUtxos: empty locking script for {}_{}", txid, vout));
            }
            assert_script_hex_under_limit(
                &script, MAX_SCRIPT_BYTES,
                &format!("GorillaPoolProvider.get_utxos({})", address),
            )?;
            utxos.push(Utxo { txid, output_index: vout as u32, satoshis: sats as i64, script });
        }
        Ok(utxos)
    }

    /// N-025: the GorillaPool API has no documented route that looks UTXOs up
    /// by script hash (the former /script/{hash}/utxos is a 404), so this
    /// refuses rather than reporting "no UTXO".
    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String> {
        Err(format!(
            "GorillaPool getContractUtxo({}): lookup by script hash is not supported by the GorillaPool API",
            script_hash
        ))
    }

    fn get_network(&self) -> &str {
        &self.network
    }

    fn get_fee_rate(&self) -> Result<i64, String> {
        // BSV standard relay fee is 0.1 sat/byte (100 sat/KB).
        Ok(100)
    }

    /// N-025: GET /tx/{txid}/raw (binary), hash-verified, returned as hex.
    fn get_raw_transaction(&self, txid: &str) -> Result<String, String> {
        let raw = self.fetch_verified_raw(txid, "getRawTransaction")?;
        Ok(bsv::primitives::utils::to_hex(&raw))
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

    // -----------------------------------------------------------------------
    // N-025: every GorillaPool call uses a route the API documents and serves,
    // decodes its documented shape, and surfaces a 404 as an error. The old
    // routes (/tx/{txid}/hex, /address/{a}/utxos, /script/{h}/utxos,
    // /inscriptions/address/{a}, /bsv20/balance/..., /bsv20/utxos/...) do not
    // exist and were mapped from 404 to [] / None / "0".
    // Proves: replaying conformance/sdk-gorillapool/endpoint-vectors.json
    // (recorded 2026-10-05) through a local HTTP server (unlisted request ->
    // the recorded 404), every call the Rust provider exposes decodes to the
    // independently derived expectation, every 404 raises, tampered bodies
    // (txid mismatch, listing value != raw tx value, content not matching its
    // hash) are refused, get_contract_utxo refuses, broadcast posts
    // {"rawtx": hex}.
    // N-159: the synthetic listing for 1SyntheticOrdinalAndPlain... holds a 1-sat
    // BSV-20 inscription output (origin set) before a plain P2PKH output, both in
    // the recorded tx 8c28...; getUtxos must return only the plain one, so an
    // inscription the indexer reports is never offered as a funding input. Does
    // NOT prove: that the live listing populates `origin` for every inscription
    // or token output, nor anything about outputs that carry `data` but no origin.
    // Does NOT prove: that the live API still serves these shapes; that POST
    // /api/tx accepts {"rawtx"} (schema-documented, never sent live);
    // pagination beyond the API's default page.
    // -----------------------------------------------------------------------

    use std::sync::{Arc, Mutex};

    fn load_endpoint_vectors() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/sdk-gorillapool/endpoint-vectors.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        serde_json::from_str(&text).unwrap()
    }

    /// Multi-request HTTP server replaying the vector routes (path from host
    /// root); anything else gets `notFound`. Returns (host url, posted bodies).
    fn serve_routes(doc: &Value) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let routes = doc["routes"].as_array().unwrap().clone();
        let not_found = doc["notFound"].clone();
        let posted = Arc::new(Mutex::new(Vec::new()));
        let posted2 = posted.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let head_end = loop {
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => break buf.len(),
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let clen = head
                    .lines()
                    .find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + clen {
                    match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let mut parts = head.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                if method == "POST" {
                    posted2
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[head_end..]).to_string());
                }
                let r = routes
                    .iter()
                    .find(|r| r["method"] == method.as_str() && r["path"] == path.as_str())
                    .unwrap_or(&not_found);
                let payload =
                    bsv::primitives::utils::from_hex(r["bodyHex"].as_str().unwrap()).unwrap();
                let status = r["status"].as_u64().unwrap();
                let reason = if status == 200 { "OK" } else { "Not Found" };
                let ct = r["contentType"].as_str().unwrap_or("");
                let mut head = format!("HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n", status, reason, payload.len());
                if !ct.is_empty() {
                    head.push_str(&format!("Content-Type: {}\r\n", ct));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&payload);
                let _ = stream.flush();
            }
        });
        (format!("http://{}", addr), posted)
    }

    fn utxos_json(v: Vec<Utxo>) -> Value {
        Value::Array(
            v.into_iter()
                .map(|u| serde_json::json!({
                    "txid": u.txid, "outputIndex": u.output_index,
                    "satoshis": u.satoshis, "script": u.script,
                }))
                .collect(),
        )
    }

    fn insc_json(i: &InscriptionInfo) -> Value {
        serde_json::json!({
            "txid": i.txid, "vout": i.vout, "origin": i.origin,
            "contentType": i.content_type, "contentLength": i.content_length, "height": i.height,
        })
    }

    #[test]
    fn n025_gorillapool_replays_recorded_documented_endpoints() {
        let doc = load_endpoint_vectors();
        let (host, posted) = serve_routes(&doc);
        let mut p = provider_at(format!("{}/api", host));
        let calls = doc["calls"].as_array().unwrap();
        assert!(calls.len() >= 27);
        let mut failures = Vec::new();
        for (i, c) in calls.iter().enumerate() {
            let name = c["call"].as_str().unwrap();
            let a: Vec<String> = c["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            posted.lock().unwrap().clear();
            let got: Result<Value, String> = match name {
                "getRawTransaction" => p.get_raw_transaction(&a[0]).map(Value::String),
                "getUtxos" => p.get_utxos(&a[0]).map(utxos_json),
                "getContractUtxo" => p
                    .get_contract_utxo(&a[0])
                    .map(|o| o.map(|u| utxos_json(vec![u])).unwrap_or(Value::Null)),
                "getInscriptionsByAddress" => p
                    .get_inscriptions_by_address(&a[0])
                    .map(|v| Value::Array(v.iter().map(insc_json).collect())),
                "getInscription" => p.get_inscription(&a[0]).map(|d| {
                    let mut j = insc_json(&InscriptionInfo {
                        txid: d.txid.clone(), vout: d.vout, origin: d.origin.clone(),
                        content_type: d.content_type.clone(),
                        content_length: d.content_length, height: d.height,
                    });
                    j["data"] = Value::String(d.data);
                    j
                }),
                "getBSV20Balance" => p.get_bsv20_balance(&a[0], &a[1]).map(Value::String),
                "getBSV21Balance" => p.get_bsv21_balance(&a[0], &a[1]).map(Value::String),
                "getBSV20Utxos" => p.get_bsv20_utxos(&a[0], &a[1]).map(utxos_json),
                "getBSV21Utxos" => p.get_bsv21_utxos(&a[0], &a[1]).map(utxos_json),
                "broadcast" => {
                    let raw = bsv::primitives::utils::from_hex(&a[0]).unwrap();
                    let tx = BsvTransaction::from_binary(&mut std::io::Cursor::new(&raw)).unwrap();
                    p.broadcast(&tx).map(Value::String)
                }
                other => panic!("unknown call {}", other),
            };
            let label = format!("#{} {}({:?})", i, name, a.iter().map(|x| &x[..x.len().min(16)]).collect::<Vec<_>>());
            if let Some(want_err) = c["expectError"].as_str() {
                match &got {
                    Err(e) if e.contains(want_err) => {}
                    other => failures.push(format!("{}: expected error /{}/, got {:?}", label, want_err, other)),
                }
            } else {
                match &got {
                    Ok(v) if *v == c["expect"] => {}
                    other => failures.push(format!("{}: expected {}, got {:?}", label, c["expect"], other)),
                }
            }
            if !c["expectRequestJson"].is_null() {
                let bodies = posted.lock().unwrap().clone();
                let ok = bodies.len() == 1
                    && serde_json::from_str::<Value>(&bodies[0]).ok().as_ref() == Some(&c["expectRequestJson"]);
                if !ok {
                    failures.push(format!("{}: posted {:?}, expected {}", label, bodies, c["expectRequestJson"]));
                }
            }
        }
        assert!(failures.is_empty(), "{} of {} calls failed:\n{}", failures.len(), calls.len(), failures.join("\n"));
    }

    #[test]
    fn urlencoded_handles_special_chars() {
        assert_eq!(urlencoded("hello world"), "hello%20world");
        assert_eq!(urlencoded("a+b"), "a%2Bb");
        assert_eq!(urlencoded("100%"), "100%25");
    }
}
