#[allow(dead_code)]
pub mod crypto;

use runar_lang::sdk::{
    ExternalSigner, LocalSigner, RPCProvider, RunarArtifact, Signer,
};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use k256::ecdsa::SigningKey;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Compile helpers
// ---------------------------------------------------------------------------

/// Project root (two levels up from integration/rust/).
fn project_root() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // manifest_dir = .../integration/rust
    let p = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("could not resolve project root");
    p.to_string_lossy().to_string()
}

/// Compile a contract from a source file path relative to the project root.
/// Returns the SDK-compatible `RunarArtifact`.
pub fn compile_contract(source_path: &str) -> RunarArtifact {
    let root = project_root();
    let abs_path = format!("{}/{}", root, source_path);
    let source = std::fs::read_to_string(&abs_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", abs_path, e));
    let file_name = std::path::Path::new(&abs_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.ts".to_string());
    compile_source(&source, &file_name)
}

/// Compile a contract from source code and a file name.
/// Returns the SDK-compatible `RunarArtifact`.
pub fn compile_source(source: &str, file_name: &str) -> RunarArtifact {
    let compiler_artifact =
        runar_compiler_rust::compile_from_source_str(source, Some(file_name))
            .unwrap_or_else(|e| panic!("compile failed for {}: {}", file_name, e));

    // Bridge: serialize compiler artifact to JSON, deserialize into SDK artifact.
    let json = serde_json::to_string(&compiler_artifact)
        .expect("failed to serialize compiler artifact");
    serde_json::from_str::<RunarArtifact>(&json)
        .expect("failed to deserialize SDK artifact from compiler JSON")
}

// ---------------------------------------------------------------------------
// Provider / Node helpers
// ---------------------------------------------------------------------------

/// Create an RPCProvider configured for regtest.
pub fn create_provider() -> RPCProvider {
    let url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:18332".to_string());
    let user = std::env::var("RPC_USER").unwrap_or_else(|_| "bitcoin".to_string());
    let pass = std::env::var("RPC_PASS").unwrap_or_else(|_| "bitcoin".to_string());
    RPCProvider::new_regtest(&url, &user, &pass)
}

/// Check if the regtest node is reachable. Panics with a descriptive message
/// if not, so individual tests can call this at the top.
pub fn skip_if_no_node() {
    if !is_node_available() {
        panic!(
            "SKIPPED: regtest node not available at {}. \
             Start the node with `./integration/regtest.sh start` before running integration tests.",
            std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:18332".to_string()),
        );
    }
}

/// Returns true if the regtest node responds to `getblockcount`.
pub fn is_node_available() -> bool {
    match rpc_call("getblockcount", &[]) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Make a raw JSON-RPC call to the Bitcoin node.
pub fn rpc_call(method: &str, params: &[serde_json::Value]) -> Result<serde_json::Value, String> {
    let url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:18332".to_string());
    let user = std::env::var("RPC_USER").unwrap_or_else(|_| "bitcoin".to_string());
    let pass = std::env::var("RPC_PASS").unwrap_or_else(|_| "bitcoin".to_string());

    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "runar-rust-test",
        "method": method,
        "params": params,
    });
    let body_str = body.to_string();

    // Parse URL
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(&url);
    let (host_port, path) = if let Some(idx) = stripped.find('/') {
        (&stripped[..idx], &stripped[idx..])
    } else {
        (stripped, "/")
    };

    // Base64 auth
    let auth = base64_encode(&format!("{}:{}", user, pass));

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Authorization: Basic {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path, host_port, auth, body_str.len(), body_str,
    );

    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(host_port)
        .map_err(|e| format!("connect to {}: {}", host_port, e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| format!("set timeout: {}", e))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {}", e))?;

    let body_start = response
        .find("\r\n\r\n")
        .ok_or_else(|| "no HTTP body separator".to_string())?;
    let json_str = &response[body_start + 4..];

    // Handle chunked transfer encoding
    let json_str = if response.contains("Transfer-Encoding: chunked") {
        decode_chunked(json_str)?
    } else {
        json_str.to_string()
    };

    let json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("parse response: {} (body: {})", e, &json_str[..json_str.len().min(200)]))?;

    if let Some(err) = json.get("error") {
        if !err.is_null() {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(format!("RPC {}: {}", method, msg));
        }
    }

    Ok(json["result"].clone())
}

/// Mine the specified number of blocks on regtest.
pub fn mine(blocks: usize) {
    rpc_call("generate", &[serde_json::Value::from(blocks as u64)])
        .expect("failed to mine blocks");
}

/// Fund an address with the given BTC amount on regtest.
pub fn fund_address(address: &str, amount: f64) {
    // Import address so listunspent can find it
    let _ = rpc_call(
        "importaddress",
        &[
            serde_json::Value::from(address),
            serde_json::Value::from(""),
            serde_json::Value::from(false),
        ],
    );
    rpc_call(
        "sendtoaddress",
        &[
            serde_json::Value::from(address),
            serde_json::Value::from(amount),
        ],
    )
    .expect("failed to fund address");
    mine(1);
}

// ---------------------------------------------------------------------------
// Wallet helpers
// ---------------------------------------------------------------------------

/// A test wallet with keys and a signer ready for regtest.
pub struct TestWallet {
    pub priv_key_hex: String,
    pub pub_key_hex: String,
    pub pub_key_hash: String,
    pub address: String,
}

/// Counter for deterministic sequential keys, seeded from process ID to
/// avoid collisions between parallel test processes.
static WALLET_INDEX: AtomicU64 = AtomicU64::new(0);

fn next_wallet_index() -> u64 {
    let idx = WALLET_INDEX.fetch_add(1, Ordering::Relaxed);
    if idx == 0 {
        // First call: seed from process ID
        let seed = std::process::id() as u64 * 1000;
        WALLET_INDEX.store(seed + 1, Ordering::Relaxed);
        return seed;
    }
    idx
}

/// Generate a deterministic key from a sequential counter.
/// Does NOT fund the address.
pub fn create_wallet() -> TestWallet {
    let idx = next_wallet_index();
    let mut key_bytes = [0u8; 32];
    key_bytes[24..32].copy_from_slice(&idx.to_be_bytes());
    let signing_key = SigningKey::from_bytes((&key_bytes).into())
        .expect("valid private key");
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(true);
    let pubkey_bytes = point.as_bytes();

    let priv_key_hex = hex_encode(&signing_key.to_bytes()[..]);
    let pub_key_hex = hex_encode(pubkey_bytes);

    // hash160 = RIPEMD160(SHA256(compressed_pubkey))
    let sha_hash = Sha256::digest(pubkey_bytes);
    let pkh = Ripemd160::digest(sha_hash);
    let pub_key_hash = hex_encode(&pkh);

    let address = regtest_address(&pub_key_hash);

    TestWallet {
        priv_key_hex,
        pub_key_hex,
        pub_key_hash,
        address,
    }
}

/// Create a funded wallet and return (ExternalSigner wrapping LocalSigner, TestWallet).
/// The ExternalSigner returns the regtest address but delegates signing to LocalSigner.
pub fn create_funded_wallet(
    _provider: &mut RPCProvider,
) -> (Box<dyn Signer>, TestWallet) {
    let wallet = create_wallet();
    fund_address(&wallet.address, 1.0);

    let local_signer = LocalSigner::new(&wallet.priv_key_hex)
        .expect("failed to create LocalSigner");

    // Capture values for closures
    let pub_key = wallet.pub_key_hex.clone();
    let addr = wallet.address.clone();

    let external_signer = ExternalSigner::new(
        move || Ok(pub_key.clone()),
        move || Ok(addr.clone()),
        move |tx_hex: &str,
              input_index: usize,
              subscript: &str,
              satoshis: i64,
              sig_hash_type: Option<u32>| {
            local_signer.sign(tx_hex, input_index, subscript, satoshis, sig_hash_type)
        },
    );

    (Box::new(external_signer), wallet)
}

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

/// Derive a regtest P2PKH address from a hex-encoded pubKeyHash.
/// Regtest uses version byte 0x6f.
fn regtest_address(pub_key_hash_hex: &str) -> String {
    let pkh = hex_decode(pub_key_hash_hex).expect("invalid pubKeyHash hex");
    let mut payload = vec![0x6fu8];
    payload.extend_from_slice(&pkh);

    // Base58Check: payload + first 4 bytes of SHA256(SHA256(payload))
    let hash1 = Sha256::digest(&payload);
    let hash2 = Sha256::digest(hash1);
    let checksum = &hash2[..4];

    let mut full = payload;
    full.extend_from_slice(checksum);
    base58_encode(&full)
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(data: &[u8]) -> String {
    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert to a big number (big-endian)
    let mut num = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for digit in num.iter_mut() {
            carry += (*digit as u32) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            num.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::new();
    // Leading '1's for each leading zero byte
    for _ in 0..leading_zeros {
        result.push('1');
    }
    // Digits in reverse order
    for &digit in num.iter().rev() {
        result.push(BASE58_ALPHABET[digit as usize] as char);
    }
    result
}

fn base64_encode(input: &str) -> String {
    const TABLE: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
        if remaining_trimmed.is_empty() {
            break;
        }
        let line_end = remaining_trimmed
            .find("\r\n")
            .unwrap_or(remaining_trimmed.len());
        let size_str = &remaining_trimmed[..line_end];
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|e| format!("chunked decode: bad size '{}': {}", size_str, e))?;
        if size == 0 {
            break;
        }
        let data_start = line_end + 2;
        if data_start + size > remaining_trimmed.len() {
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("invalid hex at position {}", i))
        })
        .collect()
}
