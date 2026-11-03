import { SmartContract, assert, PubKey, Sig, checkMultiSig } from 'runar-lang';

/**
 * MultiSigVerifyFused -- a 2-of-3 multisig whose checkMultiSig assert is NOT
 * the last statement. A trailing `assert(checkMultiSig(...))` leaves its
 * result on the stack as the script's final truthy value and compiles to a
 * bare OP_CHECKMULTISIG (see the `multisig` fixture). Followed by a second
 * assert, the compiler emits OP_CHECKMULTISIG OP_VERIFY, which the peephole
 * pass fuses into the single opcode OP_CHECKMULTISIGVERIFY (0xaf). This
 * fixture exists so a golden pins that fusion in all seven tiers.
 */
class MultiSigVerifyFused extends SmartContract {
  readonly pk1: PubKey;
  readonly pk2: PubKey;
  readonly pk3: PubKey;

  constructor(pk1: PubKey, pk2: PubKey, pk3: PubKey) {
    super(pk1, pk2, pk3);
    this.pk1 = pk1;
    this.pk2 = pk2;
    this.pk3 = pk3;
  }

  public unlock(sig1: Sig, sig2: Sig, amount: bigint): void {
    assert(checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3]));
    assert(amount > 0n);
  }
}
