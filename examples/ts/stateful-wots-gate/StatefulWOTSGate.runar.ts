import { StatefulSmartContract, assert, verifyWOTS } from 'runar-lang';
import type { ByteString } from 'runar-lang';

// StatefulWOTSGate - stateful + post-quantum interaction fixture (GAP-407).
// TEST FIXTURE, NOT AN AUTHORIZATION GATE: wotsPubKey is a spender-supplied witness,
// so anyone can advance the counter; it exists to exercise stateful covenant +
// WOTS+ verify composition (GAP-407).
// It composes the auto-injected stateful covenant (checkPreimage + 0x41
// sighash pin + state continuation) with a ~10 KB post-quantum verify in one
// script.
class StatefulWOTSGate extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public advance(msg: ByteString, sig: ByteString, wotsPubKey: ByteString) {
    assert(verifyWOTS(msg, sig, wotsPubKey));
    this.count = this.count + 1n;
  }
}
