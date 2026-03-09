use runar::prelude::*;

/// P2PKH — Pay-to-Public-Key-Hash.
///
/// The most fundamental Bitcoin spending pattern. Funds are locked to the
/// HASH160 (SHA-256 → RIPEMD-160) of a public key. To spend, the recipient
/// must provide their full public key (which must hash to the stored hash)
/// and a valid ECDSA signature over the transaction.
///
/// # How It Works: Two-Step Verification
///
///  1. **Hash check** — `hash160(pub_key) == pub_key_hash` proves the provided
///     public key matches the one committed to when the output was created.
///  2. **Signature check** — `check_sig(sig, pub_key)` proves the spender
///     holds the private key corresponding to that public key.
///
/// This is the same pattern as standard Bitcoin P2PKH transactions, but
/// expressed in the Rúnar smart contract language.
///
/// # Script Layout
///
///   Unlocking: `<sig> <pubKey>`
///   Locking:   `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`
///
/// # Parameter Sizes
///
///   - pub_key_hash: 20 bytes (HASH160 of compressed public key)
///   - sig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
///   - pub_key: 33 bytes (compressed secp256k1 public key)
#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(P2PKH)]
impl P2PKH {
    /// Unlock verifies the pub_key hashes to the committed hash, then checks the signature.
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        // Step 1: Verify pub_key matches the committed hash
        assert!(hash160(pub_key) == self.pub_key_hash);
        // Step 2: Verify ECDSA signature proves ownership of the private key
        assert!(check_sig(sig, pub_key));
    }
}
