use runar::prelude::*;

/// Hybrid secp256k1 + P-384 wallet.
///
/// # Security Model: Two-Layer Authentication
///
/// This contract binds a spend to two independent keys:
///
///  1. **secp256k1 OP_CHECKSIG** proves the signature commits to this specific
///     transaction (via the Bitcoin sighash preimage).
///  2. **P-384 ECDSA** verifies the secp256k1 sig bytes — proving the transaction
///     was also authorized by the P-384 (NIST / high-assurance) key holder.
///
/// The secp256k1 sig bytes ARE the message that P-384 signs. This means a
/// FIPS-140 validated HSM (which often speaks P-384) can gate Bitcoin spending
/// without any new opcode.
///
/// # Locking Script Layout
///
/// ```text
/// Unlocking: <p384Sig(96B)> <p384PubKey(49B)> <ecdsaSig(~72B)> <ecdsaPubKey(33B)>
///
/// Locking:
///   // --- secp256k1 verification (P2PKH) ---
///   OP_OVER OP_TOALTSTACK           // copy ecdsaSig to alt stack for P-384 later
///   OP_DUP OP_HASH160 <ecdsaPubKeyHash(20B)> OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
///   // --- P-384 pubkey commitment ---
///   OP_DUP OP_HASH160 <p384PubKeyHash(20B)> OP_EQUALVERIFY
///   // --- P-384 verification ---
///   OP_FROMALTSTACK OP_ROT OP_ROT   // bring ecdsaSig back as P-384 message
///   <verify_ecdsa_p384 inline>       // verify P384(ecdsaSig, p384Sig, p384PubKey)
/// ```
///
/// # Parameter Sizes
///
/// - ecdsaPubKeyHash: 20 bytes (HASH160 of compressed secp256k1 public key)
/// - p384PubKeyHash: 20 bytes (HASH160 of 49-byte compressed P-384 public key)
/// - ecdsaSig: ~72 bytes (DER-encoded secp256k1 signature + sighash flag)
/// - ecdsaPubKey: 33 bytes (compressed secp256k1 public key)
/// - p384Sig: 96 bytes (raw r[48] || s[48] P-384 signature)
/// - p384PubKey: 49 bytes (compressed P-384 public key: 02/03 prefix + x[48])
///
/// The compiled P-384 verifier script is ~500 KB (larger than P-256 ~200 KB due
/// to 48-byte coordinates and the bigger field prime). It still fits well within
/// BSV's 32 MB stack memory limit.
#[runar::contract]
pub struct P384Wallet {
    #[readonly]
    pub ecdsa_pub_key_hash: Addr,
    #[readonly]
    pub p384_pub_key_hash: ByteString,
}

#[runar::methods(P384Wallet)]
impl P384Wallet {
    /// Verify both secp256k1 and P-384 signatures to allow spending.
    #[public]
    pub fn spend(&self, p384_sig: &ByteString, p384_pub_key: &ByteString, sig: &Sig, pub_key: &PubKey) {
        // Step 1: Verify secp256k1 — proves sig commits to this transaction
        assert!(hash160(pub_key) == self.ecdsa_pub_key_hash);
        assert!(check_sig(sig, pub_key));

        // Step 2: Verify P-384 — proves secp256k1 sig was authorized by P-384 key
        assert!(hash160(p384_pub_key) == self.p384_pub_key_hash);
        assert!(verify_ecdsa_p384(sig, p384_sig, p384_pub_key));
    }
}
