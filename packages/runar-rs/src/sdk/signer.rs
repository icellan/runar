//! Signer trait and implementations for transaction signing.

use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

use super::oppushtx::{bip143_preimage, parse_raw_tx, sha256d};

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

        // F-040: the subscript is the BIP-143 scriptCode. An empty one yields a
        // signature no OP_CHECKSIG accepts, so refuse it instead of signing.
        if subscript.is_empty() {
            return Err(format!(
                "LocalSigner: refusing to sign input {} with an empty subscript (scriptCode); pass the locking script of the UTXO being spent",
                input_index
            ));
        }

        let tx_bytes = hex_to_bytes(tx_hex)
            .map_err(|e| format!("LocalSigner: invalid tx hex: {}", e))?;
        let tx = parse_raw_tx(&tx_bytes).map_err(|e| format!("LocalSigner: {}", e))?;

        if input_index >= tx.inputs.len() {
            return Err(format!(
                "LocalSigner: input index {} out of range (tx has {} inputs)",
                input_index, tx.inputs.len()
            ));
        }

        let subscript_bytes = hex_to_bytes(subscript)
            .map_err(|e| format!("LocalSigner: invalid subscript hex: {}", e))?;

        // F-137: the SDK's one BIP-143 builder (oppushtx.rs).
        let sighash = sha256d(&bip143_preimage(&tx, input_index, &subscript_bytes, satoshis as u64, flag));

        let (sig, _) = self.signing_key.sign_prehash(&sighash)
            .map_err(|e| format!("LocalSigner: ECDSA signing failed: {}", e))?;

        let der_bytes = sig.to_der();
        let mut result = der_bytes.as_bytes().to_vec();
        result.push(flag as u8);
        Ok(bytes_to_hex(&result))
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

    // F-040: an empty subscript (what WoC's get_utxos used to return) is the
    // BIP-143 scriptCode of a signature no OP_CHECKSIG accepts, so sign must
    // refuse it. Proves the refusal; the Spend.validate harm demo is in TS.
    #[test]
    fn f040_local_signer_refuses_empty_subscript() {
        let signer = LocalSigner::new(PRIV_KEY_1).unwrap();
        let err = signer
            .sign(&minimal_tx_hex(), 0, "", 1000, None)
            .expect_err("LocalSigner.sign with an empty subscript must fail");
        assert!(err.contains("empty subscript"), "error: {}", err);
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
