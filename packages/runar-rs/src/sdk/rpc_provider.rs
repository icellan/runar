//! RPCProvider — JSON-RPC provider for Bitcoin nodes.
//!
//! Requires the `rpc` feature to be enabled (adds `reqwest` dependency).

use bsv::transaction::Transaction as BsvTransaction;
use super::types::{TransactionData, TxOutput, Utxo};
use super::provider::Provider;
use super::errors::{assert_script_hex_under_limit, MAX_SCRIPT_BYTES};
use serde_json::Value;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpStream;

/// RPCProvider implements Provider by making JSON-RPC calls to a Bitcoin node.
/// Uses stdlib HTTP (no external dependencies) for maximum compatibility.
pub struct RPCProvider {
    url: String,
    user: String,
    pass: String,
    network: String,
    auto_mine: bool,
}

impl RPCProvider {
    /// Create a new RPCProvider.
    pub fn new(url: &str, user: &str, pass: &str) -> Self {
        Self {
            url: url.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            network: "testnet".to_string(),
            auto_mine: false,
        }
    }

    /// Create an RPCProvider configured for regtest (auto-mines after broadcast).
    pub fn new_regtest(url: &str, user: &str, pass: &str) -> Self {
        Self {
            url: url.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            network: "regtest".to_string(),
            auto_mine: true,
        }
    }

    fn rpc_call(&self, method: &str, params: &[Value]) -> Result<Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "runar",
            "method": method,
            "params": params,
        });
        let body_str = body.to_string();

        // Parse URL to extract host:port and path
        let url = &self.url;
        let (host_port, path) = parse_url(url)?;

        // Base64 encode auth
        let auth = base64_encode(&format!("{}:{}", self.user, self.pass));

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
             Authorization: Basic {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            path, host_port, auth, body_str.len(), body_str
        );

        let mut stream = TcpStream::connect(&host_port)
            .map_err(|e| format!("RPC connect to {}: {}", host_port, e))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(600)))
            .map_err(|e| format!("set timeout: {}", e))?;
        stream.write_all(request.as_bytes())
            .map_err(|e| format!("RPC write: {}", e))?;

        let mut response = String::new();
        stream.read_to_string(&mut response)
            .map_err(|e| format!("RPC read: {}", e))?;

        // Extract JSON body after \r\n\r\n
        let body_start = response.find("\r\n\r\n")
            .ok_or_else(|| "RPC: no HTTP body separator found".to_string())?;
        let json_str = &response[body_start + 4..];

        // Handle chunked transfer encoding
        let json_str = if response.contains("Transfer-Encoding: chunked") {
            decode_chunked(json_str)?
        } else {
            json_str.to_string()
        };

        let json: Value = serde_json::from_str(&json_str)
            .map_err(|e| format!("RPC parse response: {} (body: {})", e, &json_str[..json_str.len().min(200)]))?;

        if let Some(err) = json.get("error") {
            if !err.is_null() {
                let msg = err.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                return Err(format!("RPC {}: {}", method, msg));
            }
        }

        Ok(json["result"].clone())
    }

    fn mine(&self, blocks: u32) -> Result<(), String> {
        self.rpc_call("generate", &[Value::from(blocks)])?;
        Ok(())
    }
}

impl Provider for RPCProvider {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> {
        let raw = self.rpc_call("getrawtransaction", &[Value::from(txid), Value::from(true)])?;
        let raw_hex = raw["hex"].as_str().unwrap_or("").to_string();

        let mut outputs = Vec::new();
        if let Some(vout) = raw["vout"].as_array() {
            for o in vout {
                let val_btc = o["value"].as_f64().unwrap_or(0.0);
                let sats = (val_btc * 1e8).round() as i64;
                let script_hex = o["scriptPubKey"]["hex"].as_str().unwrap_or("").to_string();
                outputs.push(TxOutput {
                    satoshis: sats,
                    script: script_hex,
                });
            }
        }

        Ok(TransactionData {
            txid: txid.to_string(),
            version: 1,
            inputs: Vec::new(),
            outputs,
            locktime: 0,
            raw: Some(raw_hex),
        })
    }

    fn broadcast(&mut self, tx: &BsvTransaction) -> Result<String, String> {
        let raw_tx = tx.to_hex().map_err(|e| format!("broadcast: to_hex failed: {}", e))?;
        let txid = self.rpc_call("sendrawtransaction", &[Value::from(raw_tx)])?;
        let txid_str = txid.as_str()
            .ok_or_else(|| "RPC sendrawtransaction: expected string txid".to_string())?
            .to_string();
        if self.auto_mine {
            // GK-BUG-004: the tx is already in the mempool, but the caller asked
            // for it to be confirmed; reporting success here would hand back a
            // txid for a block that never came. Mirrors Go / Java / TS.
            self.mine(1).map_err(|e| {
                format!("broadcast succeeded (txid {}) but auto-mine failed: {}", txid_str, e)
            })?;
        }
        Ok(txid_str)
    }

    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        let result = self.rpc_call("listunspent", &[
            Value::from(0),
            Value::from(9999999),
            Value::Array(vec![Value::from(address)]),
        ])?;

        let utxo_list = result.as_array()
            .ok_or_else(|| "RPC listunspent: expected array".to_string())?;

        let mut utxos = Vec::new();
        for u in utxo_list {
            utxos.push(Utxo {
                txid: u["txid"].as_str().unwrap_or("").to_string(),
                output_index: u["vout"].as_u64().unwrap_or(0) as u32,
                satoshis: (u["amount"].as_f64().unwrap_or(0.0) * 1e8).round() as i64,
                script: u["scriptPubKey"].as_str().unwrap_or("").to_string(),
            });
        }
        // DoS-bound: reject pathological scripts at the provider boundary.
        for u in &utxos {
            if u.script.is_empty() { continue; }
            assert_script_hex_under_limit(
                &u.script, MAX_SCRIPT_BYTES,
                &format!("RPCProvider.get_utxos({})", address),
            )?;
        }
        Ok(utxos)
    }

    fn get_contract_utxo(&self, _script_hash: &str) -> Result<Option<Utxo>, String> {
        Ok(None)
    }

    fn get_network(&self) -> &str {
        &self.network
    }

    fn get_raw_transaction(&self, txid: &str) -> Result<String, String> {
        let result = self.rpc_call("getrawtransaction", &[Value::from(txid), Value::from(false)])?;
        result.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "getrawtransaction: expected string".to_string())
    }

    fn get_fee_rate(&self) -> Result<i64, String> {
        Ok(100)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_url(url: &str) -> Result<(String, String), String> {
    let url = url.strip_prefix("http://").unwrap_or(url);
    let url = url.strip_prefix("https://").unwrap_or(url);
    let (host_port, path) = if let Some(idx) = url.find('/') {
        (&url[..idx], &url[idx..])
    } else {
        (url, "/")
    };
    Ok((host_port.to_string(), path.to_string()))
}

fn base64_encode(input: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            result.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < bytes.len() {
            result.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

fn decode_chunked(input: &str) -> Result<String, String> {
    let mut result = String::new();
    let mut remaining = input;
    loop {
        let remaining_trimmed = remaining.trim_start();
        let line_end = remaining_trimmed.find("\r\n")
            .unwrap_or(remaining_trimmed.len());
        let size_str = &remaining_trimmed[..line_end];
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|e| format!("chunked decode: bad size '{}': {}", size_str, e))?;
        if size == 0 {
            break;
        }
        let data_start = line_end + 2;
        if data_start + size > remaining_trimmed.len() {
            // Partial chunk, take what we have
            result.push_str(&remaining_trimmed[data_start..]);
            break;
        }
        result.push_str(&remaining_trimmed[data_start..data_start + size]);
        remaining = &remaining_trimmed[data_start + size..];
        if remaining.starts_with("\r\n") {
            remaining = &remaining[2..];
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_provider_new_sets_fields() {
        let p = RPCProvider::new("http://localhost:8332", "user", "pass");
        assert_eq!(p.url, "http://localhost:8332");
        assert_eq!(p.user, "user");
        assert_eq!(p.pass, "pass");
        assert_eq!(p.network, "testnet");
        assert!(!p.auto_mine);
    }

    #[test]
    fn rpc_provider_new_regtest_sets_fields() {
        let p = RPCProvider::new_regtest("http://localhost:18332", "bitcoin", "bitcoin");
        assert_eq!(p.url, "http://localhost:18332");
        assert_eq!(p.user, "bitcoin");
        assert_eq!(p.pass, "bitcoin");
        assert_eq!(p.network, "regtest");
        assert!(p.auto_mine);
    }

    #[test]
    fn rpc_provider_get_network() {
        let p = RPCProvider::new("http://localhost:8332", "u", "p");
        assert_eq!(p.get_network(), "testnet");

        let p2 = RPCProvider::new_regtest("http://localhost:18332", "u", "p");
        assert_eq!(p2.get_network(), "regtest");
    }

    #[test]
    fn rpc_provider_get_fee_rate() {
        let p = RPCProvider::new("http://localhost:8332", "u", "p");
        assert_eq!(p.get_fee_rate().unwrap(), 100);
    }

    // -----------------------------------------------------------------------
    // Helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_url_with_path() {
        let (host, path) = parse_url("http://localhost:8332/rpc").unwrap();
        assert_eq!(host, "localhost:8332");
        assert_eq!(path, "/rpc");
    }

    #[test]
    fn parse_url_without_path() {
        let (host, path) = parse_url("http://localhost:8332").unwrap();
        assert_eq!(host, "localhost:8332");
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_strips_https() {
        let (host, _) = parse_url("https://node.example.com:443/api").unwrap();
        assert_eq!(host, "node.example.com:443");
    }

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode("user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_encode(""), "");
    }

    #[test]
    fn base64_encode_with_padding() {
        // "a" -> "YQ==" (needs 2 padding chars)
        assert_eq!(base64_encode("a"), "YQ==");
        // "ab" -> "YWI=" (needs 1 padding char)
        assert_eq!(base64_encode("ab"), "YWI=");
        // "abc" -> "YWJj" (no padding)
        assert_eq!(base64_encode("abc"), "YWJj");
    }

    #[test]
    fn decode_chunked_single_chunk() {
        let input = "5\r\nhello\r\n0\r\n";
        let result = decode_chunked(input).unwrap();
        assert_eq!(result, "hello");
    }

    // -----------------------------------------------------------------------
    // GK-BUG-004: auto-mine failure must not be swallowed
    // -----------------------------------------------------------------------

    /// One-shot-per-connection JSON-RPC stub: answers each request by method
    /// name and records the methods it saw.
    fn spawn_stub_node(
        answer: fn(&str) -> String,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream { Ok(s) => s, Err(_) => return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read headers + Content-Length body.
                loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 { break; }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(h) = text.find("\r\n\r\n") {
                        let len = text[..h]
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= h + 4 + len { break; }
                    }
                }
                let text = String::from_utf8_lossy(&buf).to_string();
                let body = &text[text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0)..];
                let method = serde_json::from_str::<Value>(body)
                    .ok()
                    .and_then(|v| v["method"].as_str().map(|s| s.to_string()))
                    .unwrap_or_default();
                seen2.lock().unwrap().push(method.clone());
                let resp_body = answer(&method);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(), resp_body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{}", addr), seen)
    }

    fn one_input_tx() -> BsvTransaction {
        let hex = [
            "01000000", "01", &"11".repeat(32), "00000000", "0151", "ffffffff",
            "01", "e803000000000000", "0151", "00000000",
        ]
        .concat();
        BsvTransaction::from_hex(&hex).unwrap()
    }

    const STUB_TXID: &str = "aa00000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn broadcast_reports_auto_mine_failure_with_txid() {
        let (url, seen) = spawn_stub_node(|method| match method {
            "sendrawtransaction" => format!(r#"{{"result":"{}","error":null,"id":"runar"}}"#, STUB_TXID),
            _ => r#"{"result":null,"error":{"code":-32601,"message":"Method not found"},"id":"runar"}"#.to_string(),
        });
        let mut p = RPCProvider::new_regtest(&url, "u", "p");
        let err = p.broadcast(&one_input_tx()).expect_err(
            "broadcast returned Ok although the auto-mine after it failed",
        );
        assert!(err.contains(STUB_TXID), "error must carry the broadcast txid: {}", err);
        assert!(err.contains("auto-mine failed"), "error must name the failing step: {}", err);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.first().map(String::as_str), Some("sendrawtransaction"));
        assert!(seen.iter().any(|m| m == "generate"), "auto-mine was never attempted: {:?}", *seen);
    }

    #[test]
    fn broadcast_succeeds_when_auto_mine_succeeds() {
        let (url, _seen) = spawn_stub_node(|method| match method {
            "sendrawtransaction" => format!(r#"{{"result":"{}","error":null,"id":"runar"}}"#, STUB_TXID),
            "generate" => r#"{"result":["bb"],"error":null,"id":"runar"}"#.to_string(),
            _ => r#"{"result":null,"error":{"code":-1,"message":"unexpected"},"id":"runar"}"#.to_string(),
        });
        let mut p = RPCProvider::new_regtest(&url, "u", "p");
        assert_eq!(p.broadcast(&one_input_tx()).unwrap(), STUB_TXID);
    }
}
