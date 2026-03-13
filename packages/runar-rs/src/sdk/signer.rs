//! Signer trait and implementations for transaction signing.

use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

// ---------------------------------------------------------------------------
// Signer trait
// ---------------------------------------------------------------------------

/// Abstraction over transaction signing.
pub trait Signer {
    /// Get the hex-encoded compressed public key (33 bytes = 66 hex chars).
    fn get_public_key(&self) -> Result<String, String>;

    /// Get the BSV address.
    fn get_address(&self) -> Result<String, String>;

    /// Sign a transaction input.
    ///
    /// - `tx_hex`:       The full raw transaction hex being signed.
    /// - `input_index`:  Index of the input being signed.
    /// - `subscript`:    The locking script of the UTXO being spent (hex).
    /// - `satoshis`:     The satoshi value of the UTXO being spent.
    /// - `sig_hash_type`: Sighash flags (defaults to ALL | FORKID = 0x41).
    ///
    /// Returns the DER-encoded signature with sighash byte appended, hex-encoded.
    fn sign(
        &self,
        tx_hex: &str,
        input_index: usize,
        subscript: &str,
        satoshis: i64,
        sig_hash_type: Option<u32>,
    ) -> Result<String, String>;
}

// ---------------------------------------------------------------------------
// LocalSigner — private key in memory
// ---------------------------------------------------------------------------

/// SIGHASH_ALL | SIGHASH_FORKID — the default BSV sighash type.
const SIGHASH_ALL_FORKID: u32 = 0x41;

/// A local signer that holds a private key in memory.
///
/// Uses secp256k1 ECDSA via the `k256` crate for real signing and
/// manual BIP-143 sighash preimage computation.
///
/// Suitable for CLI tooling and testing. For production wallets, use
/// ExternalSigner with hardware wallet callbacks instead.
pub struct LocalSigner {
    signing_key: SigningKey,
}

impl LocalSigner {
    /// Create a new LocalSigner from a private key.
    ///
    /// `key_input` can be a 64-char hex string or a WIF-encoded key
    /// (starts with 5, K, or L).
    pub fn new(key_input: &str) -> Result<Self, String> {
        let key_bytes = if is_hex_key(key_input) {
            hex_to_bytes(key_input).map_err(|e| format!("LocalSigner: invalid hex key: {}", e))?
        } else if is_wif_key(key_input) {
            decode_wif(key_input)?
        } else {
            return Err("LocalSigner: expected a 64-char hex private key or a WIF-encoded key (starts with 5, K, or L)".to_string());
        };

        let signing_key = SigningKey::from_slice(&key_bytes)
            .map_err(|e| format!("LocalSigner: invalid private key: {}", e))?;

        Ok(LocalSigner { signing_key })
    }
}

impl Signer for LocalSigner {
    fn get_public_key(&self) -> Result<String, String> {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(true); // compressed
        Ok(bytes_to_hex(point.as_bytes()))
    }

    fn get_address(&self) -> Result<String, String> {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(true);
        let pubkey_bytes = point.as_bytes();

        // P2PKH address = Base58Check(0x00 + RIPEMD160(SHA256(compressed_pubkey)))
        let sha_hash = Sha256::digest(pubkey_bytes);
        let pkh = Ripemd160::digest(sha_hash);

        let mut payload = vec![0x00u8]; // mainnet version byte
        payload.extend_from_slice(&pkh);

        Ok(bs58::encode(&payload).with_check().into_string())
    }

    fn sign(
        &self,
        tx_hex: &str,
        input_index: usize,
        subscript: &str,
        satoshis: i64,
        sig_hash_type: Option<u32>,
    ) -> Result<String, String> {
        let flag = sig_hash_type.unwrap_or(SIGHASH_ALL_FORKID);

        let tx_bytes = hex_to_bytes(tx_hex)
            .map_err(|e| format!("LocalSigner: invalid tx hex: {}", e))?;
        let tx = parse_raw_tx(&tx_bytes)?;

        if input_index >= tx.inputs.len() {
            return Err(format!(
                "LocalSigner: input index {} out of range (tx has {} inputs)",
                input_index, tx.inputs.len()
            ));
        }

        let subscript_bytes = hex_to_bytes(subscript)
            .map_err(|e| format!("LocalSigner: invalid subscript hex: {}", e))?;

        let sighash = bip143_sighash(&tx, input_index, &subscript_bytes, satoshis as u64, flag);

        let (sig, _) = self.signing_key.sign_prehash(&sighash)
            .map_err(|e| format!("LocalSigner: ECDSA signing failed: {}", e))?;

        let der_bytes = sig.to_der();
        let mut result = der_bytes.as_bytes().to_vec();
        result.push(flag as u8);
        Ok(bytes_to_hex(&result))
    }
}

// ---------------------------------------------------------------------------
// BIP-143 sighash computation
// ---------------------------------------------------------------------------

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn bip143_sighash(
    tx: &ParsedTx,
    input_index: usize,
    subscript: &[u8],
    satoshis: u64,
    sig_hash_type: u32,
) -> [u8; 32] {
    // hashPrevouts = SHA256d(all outpoints)
    let mut prevouts_data = Vec::new();
    for inp in &tx.inputs {
        prevouts_data.extend_from_slice(&inp.prev_txid_bytes);
        prevouts_data.extend_from_slice(&inp.prev_output_index.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_data);

    // hashSequence = SHA256d(all sequences)
    let mut sequence_data = Vec::new();
    for inp in &tx.inputs {
        sequence_data.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    let hash_sequence = sha256d(&sequence_data);

    // hashOutputs = SHA256d(all outputs)
    let mut outputs_data = Vec::new();
    for out in &tx.outputs {
        outputs_data.extend_from_slice(&out.satoshis.to_le_bytes());
        write_var_int(&mut outputs_data, out.script.len() as u64);
        outputs_data.extend_from_slice(&out.script);
    }
    let hash_outputs = sha256d(&outputs_data);

    // BIP-143 preimage
    let input = &tx.inputs[input_index];
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&input.prev_txid_bytes);
    preimage.extend_from_slice(&input.prev_output_index.to_le_bytes());
    write_var_int(&mut preimage, subscript.len() as u64);
    preimage.extend_from_slice(subscript);
    preimage.extend_from_slice(&satoshis.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    preimage.extend_from_slice(&sig_hash_type.to_le_bytes());

    sha256d(&preimage)
}

// ---------------------------------------------------------------------------
// Minimal raw transaction parser
// ---------------------------------------------------------------------------

struct ParsedInput {
    prev_txid_bytes: [u8; 32], // raw internal byte order
    prev_output_index: u32,
    sequence: u32,
}

struct ParsedOutput {
    satoshis: u64,
    script: Vec<u8>,
}

struct ParsedTx {
    version: u32,
    inputs: Vec<ParsedInput>,
    outputs: Vec<ParsedOutput>,
    locktime: u32,
}

fn parse_raw_tx(bytes: &[u8]) -> Result<ParsedTx, String> {
    let mut offset = 0;

    let read = |offset: &mut usize, n: usize| -> Result<&[u8], String> {
        if *offset + n > bytes.len() {
            return Err("LocalSigner: transaction hex too short".to_string());
        }
        let slice = &bytes[*offset..*offset + n];
        *offset += n;
        Ok(slice)
    };

    let read_u32_le = |offset: &mut usize| -> Result<u32, String> {
        let b = read(offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    let read_u64_le = |offset: &mut usize| -> Result<u64, String> {
        let b = read(offset, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    };

    let read_var_int = |offset: &mut usize| -> Result<u64, String> {
        let first = read(offset, 1)?[0];
        match first {
            0..=0xfc => Ok(first as u64),
            0xfd => {
                let b = read(offset, 2)?;
                Ok(u16::from_le_bytes([b[0], b[1]]) as u64)
            }
            0xfe => {
                let b = read(offset, 4)?;
                Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)
            }
            0xff => {
                let b = read(offset, 8)?;
                Ok(u64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
        }
    };

    let version = read_u32_le(&mut offset)?;

    let input_count = read_var_int(&mut offset)?;
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        let txid_slice = read(&mut offset, 32)?;
        let mut prev_txid_bytes = [0u8; 32];
        prev_txid_bytes.copy_from_slice(txid_slice);
        let prev_output_index = read_u32_le(&mut offset)?;
        let script_len = read_var_int(&mut offset)?;
        let _ = read(&mut offset, script_len as usize)?; // skip scriptSig
        let sequence = read_u32_le(&mut offset)?;
        inputs.push(ParsedInput {
            prev_txid_bytes,
            prev_output_index,
            sequence,
        });
    }

    let output_count = read_var_int(&mut offset)?;
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let satoshis = read_u64_le(&mut offset)?;
        let script_len = read_var_int(&mut offset)?;
        let script = read(&mut offset, script_len as usize)?.to_vec();
        outputs.push(ParsedOutput { satoshis, script });
    }

    let locktime = read_u32_le(&mut offset)?;

    Ok(ParsedTx {
        version,
        inputs,
        outputs,
        locktime,
    })
}

fn write_var_int(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Hex / WIF helpers
// ---------------------------------------------------------------------------

fn is_hex_key(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_wif_key(s: &str) -> bool {
    let len = s.len();
    (51..=52).contains(&len)
        && matches!(s.as_bytes()[0], b'5' | b'K' | b'L')
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l'
        })
}

fn decode_wif(wif: &str) -> Result<Vec<u8>, String> {
    let decoded = bs58::decode(wif)
        .with_check(None)
        .into_vec()
        .map_err(|e| format!("LocalSigner: invalid WIF key: {}", e))?;

    // Strip version byte (0x80) and optional compression flag (0x01)
    if decoded.len() == 33 {
        // Uncompressed: version(1) + key(32)
        Ok(decoded[1..].to_vec())
    } else if decoded.len() == 34 {
        // Compressed: version(1) + key(32) + compression_flag(1)
        Ok(decoded[1..33].to_vec())
    } else {
        Err(format!(
            "LocalSigner: unexpected WIF decoded length: {}",
            decoded.len()
        ))
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
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

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// ExternalSigner
// ---------------------------------------------------------------------------

/// A signer that delegates to external callback functions.
///
/// Useful for integrating with hardware wallets, web wallet extensions,
/// or remote signing services.
pub struct ExternalSigner {
    public_key_fn: Box<dyn Fn() -> Result<String, String>>,
    address_fn: Box<dyn Fn() -> Result<String, String>>,
    sign_fn: Box<dyn Fn(&str, usize, &str, i64, Option<u32>) -> Result<String, String>>,
}

impl ExternalSigner {
    /// Create a new ExternalSigner with callback functions.
    pub fn new(
        public_key_fn: impl Fn() -> Result<String, String> + 'static,
        address_fn: impl Fn() -> Result<String, String> + 'static,
        sign_fn: impl Fn(&str, usize, &str, i64, Option<u32>) -> Result<String, String> + 'static,
    ) -> Self {
        ExternalSigner {
            public_key_fn: Box::new(public_key_fn),
            address_fn: Box::new(address_fn),
            sign_fn: Box::new(sign_fn),
        }
    }
}

impl Signer for ExternalSigner {
    fn get_public_key(&self) -> Result<String, String> {
        (self.public_key_fn)()
    }

    fn get_address(&self) -> Result<String, String> {
        (self.address_fn)()
    }

    fn sign(
        &self,
        tx_hex: &str,
        input_index: usize,
        subscript: &str,
        satoshis: i64,
        sig_hash_type: Option<u32>,
    ) -> Result<String, String> {
        (self.sign_fn)(tx_hex, input_index, subscript, satoshis, sig_hash_type)
    }
}

// ---------------------------------------------------------------------------
// MockSigner (for testing)
// ---------------------------------------------------------------------------

/// A mock signer that returns deterministic dummy values.
/// Suitable for unit tests where real signing is not needed.
pub struct MockSigner {
    pub public_key: String,
    pub address: String,
}

impl MockSigner {
    /// Create a MockSigner with sensible defaults.
    pub fn new() -> Self {
        MockSigner {
            public_key: format!("02{}", "00".repeat(32)),
            address: "00".repeat(20),
        }
    }
}

impl Default for MockSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer for MockSigner {
    fn get_public_key(&self) -> Result<String, String> {
        Ok(self.public_key.clone())
    }

    fn get_address(&self) -> Result<String, String> {
        Ok(self.address.clone())
    }

    fn sign(
        &self,
        _tx_hex: &str,
        _input_index: usize,
        _subscript: &str,
        _satoshis: i64,
        _sig_hash_type: Option<u32>,
    ) -> Result<String, String> {
        // Return a mock 72-byte DER signature + sighash byte
        Ok(format!("30{}41", "00".repeat(70)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV_KEY_1: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    const PRIV_KEY_2: &str =
        "0000000000000000000000000000000000000000000000000000000000000002";
    const WIF_COMPRESSED: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

    fn minimal_tx_hex() -> String {
        format!(
            "01000000\
             01\
             {}\
             00000000\
             00\
             ffffffff\
             01\
             5000000000000000\
             01\
             51\
             00000000",
            "00".repeat(32)
        )
    }

    // --- Constructor ---

    #[test]
    fn local_signer_from_hex() {
        let signer = LocalSigner::new(PRIV_KEY_1);
        assert!(signer.is_ok());
    }

    #[test]
    fn local_signer_from_wif() {
        let signer = LocalSigner::new(WIF_COMPRESSED);
        assert!(signer.is_ok());
    }

    #[test]
    fn local_signer_rejects_invalid() {
        assert!(LocalSigner::new("not-a-key").is_err());
        assert!(LocalSigner::new("aabb").is_err());
        assert!(LocalSigner::new(&"aa".repeat(33)).is_err());
    }

    // --- Public key ---

    #[test]
    fn local_signer_returns_known_public_key() {
        let signer = LocalSigner::new(PRIV_KEY_1).unwrap();
        let pk = signer.get_public_key().unwrap();
        assert_eq!(
            pk,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn local_signer_pubkey_66_chars() {
        let signer = LocalSigner::new(PRIV_KEY_1).unwrap();
        let pk = signer.get_public_key().unwrap();
        assert_eq!(pk.len(), 66);
        assert!(pk.starts_with("02") || pk.starts_with("03"));
    }

    // --- Address ---

    #[test]
    fn local_signer_address_starts_with_1() {
        let signer = LocalSigner::new(PRIV_KEY_1).unwrap();
        let addr = signer.get_address().unwrap();
        assert!(addr.starts_with('1'), "expected mainnet address, got {}", addr);
    }

    // --- WIF produces same results as hex ---

    #[test]
    fn wif_same_pubkey_as_hex() {
        let from_hex = LocalSigner::new(PRIV_KEY_1).unwrap();
        let from_wif = LocalSigner::new(WIF_COMPRESSED).unwrap();
        assert_eq!(
            from_hex.get_public_key().unwrap(),
            from_wif.get_public_key().unwrap()
        );
    }

    #[test]
    fn wif_same_address_as_hex() {
        let from_hex = LocalSigner::new(PRIV_KEY_1).unwrap();
        let from_wif = LocalSigner::new(WIF_COMPRESSED).unwrap();
        assert_eq!(
            from_hex.get_address().unwrap(),
            from_wif.get_address().unwrap()
        );
    }

    // --- Signing ---

    #[test]
    fn local_signer_sign_returns_valid_hex() {
        let signer = LocalSigner::new(PRIV_KEY_1).unwrap();
        let sig = signer.sign(&minimal_tx_hex(), 0, "51", 100, None).unwrap();
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn local_signer_sign_ends_with_sighash_byte() {
        let signer = LocalSigner::new(PRIV_KEY_1).unwrap();
        let sig = signer.sign(&minimal_tx_hex(), 0, "51", 100, None).unwrap();
        assert!(sig.ends_with("41"), "expected sig ending with 41, got {}", sig);
    }

    #[test]
    fn local_signer_sign_starts_with_der_prefix() {
        let signer = LocalSigner::new(PRIV_KEY_1).unwrap();
        let sig = signer.sign(&minimal_tx_hex(), 0, "51", 100, None).unwrap();
        assert!(sig.starts_with("30"), "expected DER prefix 30, got {}", sig);
    }

    #[test]
    fn local_signer_sign_is_deterministic() {
        let signer = LocalSigner::new(PRIV_KEY_1).unwrap();
        let tx = minimal_tx_hex();
        let sig1 = signer.sign(&tx, 0, "51", 100, None).unwrap();
        let sig2 = signer.sign(&tx, 0, "51", 100, None).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn local_signer_different_keys_different_sigs() {
        let signer1 = LocalSigner::new(PRIV_KEY_1).unwrap();
        let signer2 = LocalSigner::new(PRIV_KEY_2).unwrap();
        let tx = minimal_tx_hex();
        let sig1 = signer1.sign(&tx, 0, "51", 100, None).unwrap();
        let sig2 = signer2.sign(&tx, 0, "51", 100, None).unwrap();
        assert_ne!(sig1, sig2);
    }

    // --- Existing tests ---

    #[test]
    fn mock_signer_returns_deterministic_values() {
        let signer = MockSigner::new();
        let pk = signer.get_public_key().unwrap();
        assert_eq!(pk.len(), 66);

        let addr = signer.get_address().unwrap();
        assert_eq!(addr.len(), 40);

        let sig = signer.sign("aabb", 0, "51", 1000, None).unwrap();
        assert!(!sig.is_empty());
    }

    // Row 386: MockSigner signature ends with sighash byte 0x41 (SIGHASH_ALL | SIGHASH_FORKID)
    #[test]
    fn mock_signer_sign_ends_with_sighash_byte_41() {
        let signer = MockSigner::new();
        let sig = signer.sign("deadbeef", 0, "51", 1000, None).unwrap();
        assert!(
            sig.ends_with("41"),
            "MockSigner signature should end with sighash byte 0x41; got: {}",
            sig
        );
    }

    #[test]
    fn external_signer_delegates_to_callbacks() {
        let signer = ExternalSigner::new(
            || Ok("02aabb".to_string()),
            || Ok("myaddr".to_string()),
            |_tx, _idx, _sub, _sats, _sht| Ok("sig_hex".to_string()),
        );

        assert_eq!(signer.get_public_key().unwrap(), "02aabb");
        assert_eq!(signer.get_address().unwrap(), "myaddr");
        assert_eq!(signer.sign("tx", 0, "51", 100, None).unwrap(), "sig_hex");
    }
}
