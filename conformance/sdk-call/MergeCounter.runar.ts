import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

/**
 * MergeCounter — a stateful covenant with one owner-signed method, used by the
 * N-286 cross-SDK vector `stateful-merge-prepared.json`: a two-phase
 * (prepareCall / finalizeCall) call that spends TWO contract UTXOs at once.
 *
 * Each contract input runs `increment` against its own locking script. Both
 * UTXOs carry the same state, so both derive the same continuation and the
 * merged tx satisfies each input's hashOutputs check.
 */
class MergeCounter extends StatefulSmartContract {
  count: bigint;
  readonly owner: PubKey;

  constructor(count: bigint, owner: PubKey) {
    super(count, owner);
    this.count = count;
    this.owner = owner;
  }

  public increment(sig: Sig) {
    assert(checkSig(sig, this.owner));
    this.count = this.count + 1n;
  }
}
