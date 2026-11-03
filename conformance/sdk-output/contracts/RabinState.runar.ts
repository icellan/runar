import { StatefulSmartContract, assert } from 'runar-lang';
import type { RabinPubKey, RabinSig } from 'runar-lang';

/**
 * RabinState — the SDK-output corpus's only MUTABLE `RabinPubKey` /
 * `RabinSig` state fields (F-035).
 *
 * `RabinSig` and `RabinPubKey` are bigint aliases. Every compiler writes and
 * reads them in the state section exactly like `bigint`: a bare 8-byte
 * OP_NUM2BIN word, no push-data prefix. The shared width table
 * (runar-ir-schema STATE_FIELD_WIDTHS) and all seven SDK state codecs used to
 * omit both types, so they push-data framed them instead. That deploys a state
 * section the compiled script's own reader cannot parse.
 *
 * `count` follows the two Rabin fields so the fixture pins their byte OFFSETS
 * as well as their widths: a framed Rabin field shifts every later field.
 */
class RabinState extends StatefulSmartContract {
  oracleKey: RabinPubKey;
  lastSig: RabinSig;
  count: bigint;

  constructor(oracleKey: RabinPubKey, lastSig: RabinSig, count: bigint) {
    super(oracleKey, lastSig, count);
    this.oracleKey = oracleKey;
    this.lastSig = lastSig;
    this.count = count;
  }

  /** Rotates the oracle key, records the latest signature, bumps the counter. */
  public rotate(nextKey: RabinPubKey, nextSig: RabinSig) {
    assert(nextKey > 0n);
    this.oracleKey = nextKey;
    this.lastSig = nextSig;
    this.count++;
  }
}
