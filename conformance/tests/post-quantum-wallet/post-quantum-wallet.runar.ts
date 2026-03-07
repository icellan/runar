import { SmartContract, assert, hash160, checkSig, verifyWOTS } from 'runar-lang';
import type { ByteString, Sig, PubKey, Addr } from 'runar-lang';

/**
 * Hybrid ECDSA + WOTS+ Post-Quantum Wallet.
 *
 * ## Security Model: Two-Layer Authentication
 *
 * This contract creates a quantum-resistant spending path by combining
 * classical ECDSA with WOTS+ (Winternitz One-Time Signature):
 *
 * 1. **ECDSA** proves the signature commits to this specific transaction
 *    (via OP_CHECKSIG over the sighash preimage).
 * 2. **WOTS+** proves the ECDSA signature was authorized by the WOTS key
 *    holder — the ECDSA signature bytes ARE the message that WOTS signs.
 *
 * A quantum attacker who can break ECDSA could forge a valid ECDSA
 * signature, but they cannot produce a valid WOTS+ signature over their
 * forged sig without knowing the WOTS secret key. WOTS+ security relies
 * only on SHA-256 collision resistance, not on any number-theoretic
 * assumption vulnerable to Shor's algorithm.
 *
 * ## Locking Script Layout (~10 KB)
 *
 * ```
 * Unlocking: <wotsSig(2144B)> <wotsPubKey(64B)> <ecdsaSig(~72B)> <ecdsaPubKey(33B)>
 *
 * Locking:
 *   // --- ECDSA verification (P2PKH) ---
 *   OP_OVER OP_TOALTSTACK           // copy ecdsaSig to alt stack for WOTS later
 *   OP_DUP OP_HASH160 <ecdsaPubKeyHash(20B)> OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
 *   // --- WOTS+ pubkey commitment ---
 *   OP_DUP OP_HASH160 <wotsPubKeyHash(20B)> OP_EQUALVERIFY
 *   // --- WOTS+ verification ---
 *   OP_FROMALTSTACK OP_ROT OP_ROT   // bring ecdsaSig back as WOTS message
 *   <verifyWOTS ~10KB inline>        // verify WOTS+(ecdsaSig, wotsSig, wotsPubKey)
 * ```
 *
 * ## Stack Trace
 *
 * | Step | Stack (top → bottom) |
 * |------|---------------------|
 * | Start | wotsSig, wotsPK, ecdsaSig, ecdsaPK |
 * | After ECDSA verify | wotsSig, wotsPK |
 * | After WOTS PK hash check | wotsSig, wotsPK |
 * | After WOTS verify | (empty / true) |
 *
 * ## Parameter Sizes
 *
 * - ecdsaPubKeyHash: 20 bytes (HASH160 of compressed ECDSA public key)
 * - wotsPubKeyHash: 20 bytes (HASH160 of 64-byte WOTS+ public key: pubSeed[32] || pkRoot[32])
 * - ecdsaSig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
 * - ecdsaPubKey: 33 bytes (compressed secp256k1 public key)
 * - wotsSig: 2,144 bytes (67 chains x 32 bytes)
 * - wotsPubKey: 64 bytes (pubSeed[32] || pkRoot[32])
 */
class PostQuantumWallet extends SmartContract {
  readonly ecdsaPubKeyHash: Addr;
  readonly wotsPubKeyHash: ByteString;

  constructor(ecdsaPubKeyHash: Addr, wotsPubKeyHash: ByteString) {
    super(ecdsaPubKeyHash, wotsPubKeyHash);
    this.ecdsaPubKeyHash = ecdsaPubKeyHash;
    this.wotsPubKeyHash = wotsPubKeyHash;
  }

  public spend(wotsSig: ByteString, wotsPubKey: ByteString, sig: Sig, pubKey: PubKey) {
    // Step 1: Verify ECDSA — proves sig commits to this transaction
    assert(hash160(pubKey) === this.ecdsaPubKeyHash);
    assert(checkSig(sig, pubKey));

    // Step 2: Verify WOTS+ — proves ECDSA sig was authorized by WOTS key holder
    assert(hash160(wotsPubKey) === this.wotsPubKeyHash);
    assert(verifyWOTS(sig, wotsSig, wotsPubKey));
  }
}
