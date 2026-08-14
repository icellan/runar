import {
  SmartContract,
  assert,
  cat,
  checkPreimage,
  checkSig,
  hash160,
  len,
  substr,
  sha256,
  verifyECDSA_P256,
} from 'runar-lang';
import type {
  Addr,
  ByteString,
  PubKey,
  Sig,
  SigHashPreimage,
} from 'runar-lang';

/**
 * R1-K1 Wallet -- hardware-backed primary spending with mnemonic recovery.
 *
 * Two independent keys can spend an output:
 *
 * 1. `spendR1` is the normal path. A NIST P-256 / secp256r1 key signs the
 *    current transaction's BIP-143 sighash. This key can be generated inside
 *    a YubiKey PIV slot so its private component never leaves the device.
 * 2. `recoverK1` is the backup path. A secp256k1 key authorizes an ordinary
 *    Bitcoin signature and can be restored from an offline mnemonic and
 *    passphrase if the YubiKey is lost.
 *
 * The R1 commitment is salted per output as
 * `HASH160(compressedR1PubKey || r1Salt)`. Only the commitment is placed in
 * the locking script; the unique high-entropy salt is supplied with the R1
 * unlocking witness. This prevents passive observers from linking unspent
 * outputs that reuse the same R1 key. The K1 constructor value is an ordinary
 * HASH160 commitment. A public key is revealed only when its path is used.
 *
 * R1 signing protocol:
 *
 *   sighash = SHA256(SHA256(txPreimage))
 *
 * The contract computes the first SHA-256 explicitly, and
 * `verifyECDSA_P256` applies the second SHA-256 internally. The YubiKey PIV
 * application receives `sighash` as its 32-byte ECCP256 digest and returns a
 * DER ECDSA signature, which the caller converts to 64-byte `r || s` form.
 * `checkPreimage` binds the supplied preimage to the actual transaction, while
 * the 0x41 pin requires SIGHASH_ALL | SIGHASH_FORKID.
 */
class R1K1Wallet extends SmartContract {
  /** HASH160 of the compressed 33-byte P-256 public key and a private salt. */
  readonly r1SaltedPubKeyHash: Addr;

  /** HASH160 of the compressed 33-byte secp256k1 recovery public key. */
  readonly k1PubKeyHash: Addr;

  constructor(r1SaltedPubKeyHash: Addr, k1PubKeyHash: Addr) {
    super(r1SaltedPubKeyHash, k1PubKeyHash);
    this.r1SaltedPubKeyHash = r1SaltedPubKeyHash;
    this.k1PubKeyHash = k1PubKeyHash;
  }

  /**
   * Normal spend using a hardware-backed P-256 signature.
   *
   * @param r1Sig       Raw 64-byte P-256 signature (`r[32] || s[32]`).
   * @param r1PubKey    Compressed 33-byte P-256 public key.
   * @param r1Salt      Private, unique per-output salt committed at locking.
   * @param txPreimage  BIP-143 preimage for the current transaction input.
   */
  public spendR1(
    r1Sig: ByteString,
    r1PubKey: ByteString,
    r1Salt: ByteString,
    txPreimage: SigHashPreimage,
  ) {
    assert(len(r1Salt) === 32n);
    assert(hash160(cat(r1PubKey, r1Salt)) === this.r1SaltedPubKeyHash);
    assert(substr(txPreimage, len(txPreimage) - 4n, 4n) === '41000000');
    assert(checkPreimage(txPreimage));

    // verifyECDSA_P256 hashes its message once. Passing SHA256(preimage)
    // therefore verifies the YubiKey signature over HASH256(preimage), the
    // same transaction digest bound by checkPreimage.
    assert(verifyECDSA_P256(sha256(txPreimage), r1Sig, r1PubKey));
  }

  /**
   * Emergency recovery using the mnemonic-derived secp256k1 key.
   *
   * This path is intentionally independent of the YubiKey. Possession of the
   * recovery key is sufficient to spend, so its mnemonic and passphrase must
   * remain offline and separately protected.
   */
  public recoverK1(k1Sig: Sig, k1PubKey: PubKey) {
    assert(hash160(k1PubKey) === this.k1PubKeyHash);
    assert(checkSig(k1Sig, k1PubKey));
  }
}
