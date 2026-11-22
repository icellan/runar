import { StatefulSmartContract, assert, checkSig, extractAmount } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

/**
 * MergeCounter — a stateful covenant with one owner-signed method, used by the
 * N-286 cross-SDK vector `stateful-merge-prepared.json`: a two-phase
 * (prepareCall / finalizeCall) call that spends TWO contract UTXOs at once.
 *
 * Each contract input runs `increment` against its own locking script. Both
 * UTXOs carry the same state, so both derive the same continuation and the
 * merged tx satisfies each input's hashOutputs check.
 *
 * D25: the continuation is an EXPLICIT `addOutput`. Two inputs satisfied by
 * one continuation is exactly the twin-input shape D25 refuses for an
 * auto-continuation (mutate-only) method — such a method now commits under
 * SIGHASH_SINGLE and every SDK refuses `additionalContractInputs` for it. A
 * many-to-one spend is only legitimate when the AUTHOR writes it, as
 * FungibleToken.merge does; here the owner's signature authorizes it, and the
 * contract stays ALL|FORKID (explicit class: no hidden state field).
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
    this.addOutput(extractAmount(this.txPreimage), this.count + 1n);
  }
}
