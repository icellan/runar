//! RPCProvider — JSON-RPC provider for Bitcoin nodes.
//!
//! Requires the `rpc` feature to be enabled (adds `reqwest` dependency).

use super::types::{Transaction, TxOutput, Utxo};
use super::provider::Provider;
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
    fn get_transaction(&self, txid: &str) -> Result<Transaction, String> {
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

        Ok(Transaction {
            txid: txid.to_string(),
            version: 1,
            inputs: Vec::new(),
            outputs,
            locktime: 0,
            raw: Some(raw_hex),
        })
    }

    fn broadcast(&mut self, raw_tx: &str) -> Result<String, String> {
        let txid = self.rpc_call("sendrawtransaction", &[Value::from(raw_tx)])?;
        let txid_str = txid.as_str()
            .ok_or_else(|| "RPC sendrawtransaction: expected string txid".to_string())?
            .to_string();
        if self.auto_mine {
            let _ = self.mine(1);
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
        Ok(1)
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
