import { SmartContract, assert, checkSig, Sig, PubKey } from 'runar-lang';

/**
 * CheckSigOrProbe -- source for `checksig-or-probe.anf.json` (N-197).
 *
 * `checkSig` lowers to a bare OP_CHECKSIG, which ABORTS the script on a
 * malformed signature or public-key encoding instead of pushing false. Under
 * `assert(checkSig(...))` the difference is invisible (both reject); under
 * `checkSig(a, A) || checkSig(b, B)` it is not: an interpreter that answers
 * false on the A-arm takes the B-arm and accepts a spend the chain aborts on.
 * The B-arm is always given a valid signature, so any failure of the probe is
 * the A-arm's doing. Replayed by `../checksig-encoding-abort.test.ts`.
 */
class CheckSigOrProbe extends SmartContract {
  constructor() {
    super();
  }

  public unlock(sigA: Sig, pubA: PubKey, sigB: Sig, pubB: PubKey) {
    assert(checkSig(sigA, pubA) || checkSig(sigB, pubB));
  }
}
