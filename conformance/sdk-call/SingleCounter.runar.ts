import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';

/**
 * SingleCounter — a stateful covenant whose `bump` method is declared
 * `@sighash SINGLE|FORKID`.
 *
 * BIP-143 SINGLE commits hashOutputs to hash256 of the output at the SAME
 * index as the input being spent, and to nothing else. The auto-injected
 * continuation therefore hashes only the method's own output: there is no
 * change segment and no `_changePKH` / `_changeAmount` parameter (N-038). The
 * caller may still add a change output after the continuation; it is protected
 * by the funding input's own signature, not by this covenant.
 *
 * SINGLE does not pin the continuation's VALUE, so `bump` re-creates the
 * output at the full input amount read from the preimage, which the covenant
 * does commit to.
 *
 * `reset` keeps the default ALL|FORKID mode, so it still commits every output,
 * change included, and still takes the change parameters.
 */
class SingleCounter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  /** @sighash SINGLE|FORKID */
  public bump() {
    this.addOutput(extractAmount(this.txPreimage), this.count + 1n);
  }

  public reset() {
    assert(this.count > 0n);
    this.count = 0n;
  }
}
