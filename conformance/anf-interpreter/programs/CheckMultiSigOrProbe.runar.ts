import { SmartContract, assert, checkMultiSig, checkSig, Sig, PubKey } from 'runar-lang';

/**
 * CheckMultiSigOrProbe -- source for `checkmultisig-or-probe.anf.json` (N-259).
 *
 * A 2-of-3 `checkMultiSig` lowers to a bare OP_CHECKMULTISIG. The `||` arm
 * separates "the multisig pushed false" (falls through to `checkSig(sigB, pubB)`)
 * from "the multisig aborted the script" (no arm runs). A vector that gives an
 * EMPTY `sigB` makes the B-arm push false, so the probe then succeeds only if
 * the multisig itself answered true. Replayed by
 * `../checkmultisig-onchain.test.ts`.
 */
class CheckMultiSigOrProbe extends SmartContract {
  constructor() {
    super();
  }

  public unlock(s1: Sig, s2: Sig, pk1: PubKey, pk2: PubKey, pk3: PubKey, sigB: Sig, pubB: PubKey) {
    assert(checkMultiSig([s1, s2], [pk1, pk2, pk3]) || checkSig(sigB, pubB));
  }
}
