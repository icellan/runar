import { SmartContract, assert, PubKey, Sig, checkMultiSig } from 'runar-lang';

/**
 * MultiSig2of3 — a 2-of-3 multi-signature contract.
 *
 * Funds are locked to three public keys. To spend, the unlocker must supply
 * two valid ECDSA signatures from any two of the committed keys. The signing
 * pair can be (pk1,pk2), (pk1,pk3), or (pk2,pk3); the order of the supplied
 * signatures must match the order of the corresponding pubkeys in the
 * committed array.
 *
 * ## Why this contract exists
 *
 * `checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3])` lowers to two
 * `array_literal` ANF nodes — one for the signature array, one for the pubkey
 * array. This is the canonical site where `array_literal` is emitted and is
 * useful as a cross-compiler conformance fixture.
 *
 * ## Script layout
 *
 *   Unlocking: <sig1> <sig2>
 *   Locking:   OP_0 <sig1> <sig2> 2 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG
 *              OP_VERIFY
 *
 * ## Parameter sizes
 *
 *   - pk1, pk2, pk3: 33 bytes each (compressed secp256k1 public keys)
 *   - sig1, sig2: ~72 bytes each (DER-encoded ECDSA signatures + sighash flag)
 */
class MultiSig2of3 extends SmartContract {
  readonly pk1: PubKey;
  readonly pk2: PubKey;
  readonly pk3: PubKey;

  constructor(pk1: PubKey, pk2: PubKey, pk3: PubKey) {
    super(pk1, pk2, pk3);
    this.pk1 = pk1;
    this.pk2 = pk2;
    this.pk3 = pk3;
  }

  /** Unlock requires two valid signatures from any two of the three committed pubkeys. */
  public unlock(sig1: Sig, sig2: Sig): void {
    assert(checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3]));
  }
}
