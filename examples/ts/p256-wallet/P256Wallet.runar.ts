import { SmartContract, assert, hash160, checkSig, verifyECDSA_P256 } from 'runar-lang';
import type { ByteString, Sig, PubKey, Addr } from 'runar-lang';

/**
 * Hybrid secp256k1 + P-256 wallet.
 *
 * ## Security Model: Two-Layer Authentication
 *
 * This contract binds a spend to two independent keys:
 *
 * 1. **secp256k1 OP_CHECKSIG** proves the signature commits to this specific
 *    transaction (via the Bitcoin sighash preimage).
 * 2. **P-256 ECDSA** verifies the secp256k1 sig bytes — proving the transaction
 *    was also authorized by the P-256 (NIST / Web PKI) key holder.
 *
 * The secp256k1 sig bytes ARE the message that P-256 signs. This means a
 * hardware security module or browser WebAuthn key (which speaks P-256) can
 * gate Bitcoin spending without any new opcode.
 *
 * ## Locking Script Layout
 *
 * ```
 * Unlocking: <p256Sig(64B)> <p256PubKey(33B)> <ecdsaSig(~72B)> <ecdsaPubKey(33B)>
 *
 * Locking:
 *   // --- secp256k1 verification (P2PKH) ---
 *   OP_OVER OP_TOALTSTACK           // copy ecdsaSig to alt stack for P-256 later
 *   OP_DUP OP_HASH160 <ecdsaPubKeyHash(20B)> OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
 *   // --- P-256 pubkey commitment ---
 *   OP_DUP OP_HASH160 <p256PubKeyHash(20B)> OP_EQUALVERIFY
 *   // --- P-256 verification ---
 *   OP_FROMALTSTACK OP_ROT OP_ROT   // bring ecdsaSig back as P-256 message
 *   <verifyECDSA_P256 inline>        // verify P256(ecdsaSig, p256Sig, p256PubKey)
 * ```
 *
 * ## Parameter Sizes
 *
 * - ecdsaPubKeyHash: 20 bytes (HASH160 of compressed secp256k1 public key)
 * - p256PubKeyHash: 20 bytes (HASH160 of 33-byte compressed P-256 public key)
 * - ecdsaSig: ~72 bytes (DER-encoded secp256k1 signature + sighash flag)
 * - ecdsaPubKey: 33 bytes (compressed secp256k1 public key)
 * - p256Sig: 64 bytes (raw r[32] || s[32] P-256 signature)
 * - p256PubKey: 33 bytes (compressed P-256 public key)
 */
class P256Wallet extends SmartContract {
  readonly ecdsaPubKeyHash: Addr;
  readonly p256PubKeyHash: ByteString;

  constructor(ecdsaPubKeyHash: Addr, p256PubKeyHash: ByteString) {
    super(ecdsaPubKeyHash, p256PubKeyHash);
    this.ecdsaPubKeyHash = ecdsaPubKeyHash;
    this.p256PubKeyHash = p256PubKeyHash;
  }

  public spend(p256Sig: ByteString, p256PubKey: ByteString, sig: Sig, pubKey: PubKey) {
    // Step 1: Verify secp256k1 — proves sig commits to this transaction
    assert(hash160(pubKey) === this.ecdsaPubKeyHash);
    assert(checkSig(sig, pubKey));

    // Step 2: Verify P-256 — proves secp256k1 sig was authorized by P-256 key
    assert(hash160(p256PubKey) === this.p256PubKeyHash);
    assert(verifyECDSA_P256(sig, p256Sig, p256PubKey));
  }
}
