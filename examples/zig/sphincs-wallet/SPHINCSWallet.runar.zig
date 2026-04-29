const runar = @import("runar");

// SPHINCSWallet — Hybrid ECDSA + SLH-DSA-SHA2-128s (SPHINCS+) Post-Quantum Wallet.
//
// Security Model: Two-Layer Authentication
//
// This contract creates a quantum-resistant spending path by combining
// classical ECDSA with SLH-DSA (FIPS 205, SPHINCS+):
//
//  1. ECDSA proves the signature commits to this specific transaction
//     (via OP_CHECKSIG over the sighash preimage).
//  2. SLH-DSA proves the ECDSA signature was authorized by the SLH-DSA
//     key holder — the ECDSA signature bytes ARE the message that SLH-DSA signs.
//
// A quantum attacker who can break ECDSA could forge a valid ECDSA
// signature, but they cannot produce a valid SLH-DSA signature over their
// forged sig without knowing the SLH-DSA secret key. SLH-DSA security
// relies only on SHA-256 collision resistance, not on any number-theoretic
// assumption vulnerable to Shor's algorithm.
//
// Unlike WOTS+ (one-time), SLH-DSA is stateless and the same keypair
// can sign many messages — it's NIST FIPS 205 standardized.
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
//   - ecdsaPubKeyHash: 20 bytes (HASH160 of compressed ECDSA public key)
//   - slhdsaPubKeyHash: 20 bytes (HASH160 of 32-byte SLH-DSA public key)
//   - ecdsaSig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
//   - ecdsaPubKey: 33 bytes (compressed secp256k1 public key)
//   - slhdsaSig: 7,856 bytes (SLH-DSA-SHA2-128s signature)
//   - slhdsaPubKey: 32 bytes (PK.seed || PK.root)
pub const SPHINCSWallet = struct {
    pub const Contract = runar.SmartContract;

    ecdsaPubKeyHash: runar.Addr,
    slhdsaPubKeyHash: runar.ByteString,

    pub fn init(ecdsaPubKeyHash: runar.Addr, slhdsaPubKeyHash: runar.ByteString) SPHINCSWallet {
        return .{
            .ecdsaPubKeyHash = ecdsaPubKeyHash,
            .slhdsaPubKeyHash = slhdsaPubKeyHash,
        };
    }

    /// Verify both ECDSA and SLH-DSA-SHA2-128s signatures to allow spending.
    pub fn spend(
        self: *const SPHINCSWallet,
        slhdsaSig: runar.ByteString,
        slhdsaPubKey: runar.ByteString,
        sig: runar.Sig,
        pubKey: runar.PubKey,
    ) void {
        // Step 1: Verify ECDSA — proves sig commits to this transaction
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.ecdsaPubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));

        // Step 2: Verify SLH-DSA — proves ECDSA sig was authorized by SLH-DSA key holder
        runar.assert(runar.bytesEq(runar.hash160(slhdsaPubKey), self.slhdsaPubKeyHash));
        runar.assert(runar.verifySLHDSA_SHA2_128s(sig, slhdsaSig, slhdsaPubKey));
    }
};
