// SPHINCSWallet -- Hybrid ECDSA + SLH-DSA-SHA2-128s (SPHINCS+) Post-Quantum Wallet.
//
// Security Model: Two-Layer Authentication
//
// This contract creates a quantum-resistant spending path by combining
// classical ECDSA with SLH-DSA (FIPS 205, SPHINCS+):
//
//  1. ECDSA proves the signature commits to this specific transaction
//     (via OP_CHECKSIG over the sighash preimage).
//  2. SLH-DSA proves the ECDSA signature was authorized by the SLH-DSA
//     key holder -- the ECDSA signature bytes ARE the message that SLH-DSA signs.
//
// A quantum attacker who can break ECDSA could forge a valid ECDSA
// signature, but they cannot produce a valid SLH-DSA signature over their
// forged sig without knowing the SLH-DSA secret key. SLH-DSA security
// relies only on SHA-256 collision resistance, not on any number-theoretic
// assumption vulnerable to Shor's algorithm.
//
// Unlike WOTS+ (one-time), SLH-DSA is stateless and the same keypair
// can sign many messages -- it's NIST FIPS 205 standardized.
//
// Locking Script Layout (~200 KB)
//
//   Unlocking: <slhdsaSig(7856B)> <slhdsaPubKey(32B)> <ecdsaSig(~72B)> <ecdsaPubKey(33B)>
//
//   Locking:
//     // --- ECDSA verification (P2PKH) ---
//     OP_OVER OP_TOALTSTACK
//     OP_DUP OP_HASH160 <ecdsaPubKeyHash(20B)> OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
//     // --- SLH-DSA pubkey commitment ---
//     OP_DUP OP_HASH160 <slhdsaPubKeyHash(20B)> OP_EQUALVERIFY
//     // --- SLH-DSA verification ---
//     OP_FROMALTSTACK OP_ROT OP_ROT
//     <verifySLHDSA ~200KB inline>
//
// Parameter Sizes
//
//   - ecdsa_pub_key_hash: 20 bytes (HASH160 of compressed ECDSA public key)
//   - slhdsa_pub_key_hash: 20 bytes (HASH160 of 32-byte SLH-DSA public key)
//   - ecdsa_sig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
//   - ecdsa_pub_key: 33 bytes (compressed secp256k1 public key)
//   - slhdsa_sig: 7,856 bytes (SLH-DSA-SHA2-128s signature)
//   - slhdsa_pub_key: 32 bytes (PK.seed || PK.root)
module SPHINCSWallet {
    use runar::types::{Addr, Sig, PubKey};
    use runar::crypto::{hash160, check_sig, verify_slh_dsa_sha2_128s};

    struct SPHINCSWallet {
        ecdsa_pub_key_hash: Addr,
        slhdsa_pub_key_hash: ByteString,
    }

    // Verify both ECDSA and SLH-DSA-SHA2-128s signatures to allow spending.
    public fun spend(contract: &SPHINCSWallet, slhdsa_sig: ByteString, slhdsa_pub_key: ByteString, sig: Sig, pub_key: PubKey) {
        // Step 1: Verify ECDSA -- proves sig commits to this transaction
        assert!(hash160(pub_key) == contract.ecdsa_pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);

        // Step 2: Verify SLH-DSA -- proves ECDSA sig was authorized by SLH-DSA key holder
        assert!(hash160(slhdsa_pub_key) == contract.slhdsa_pub_key_hash, 0);
        assert!(verify_slh_dsa_sha2_128s(sig, slhdsa_sig, slhdsa_pub_key), 0);
    }
}
