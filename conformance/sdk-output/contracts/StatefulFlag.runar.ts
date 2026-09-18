import { StatefulSmartContract, assert } from 'runar-lang';

/**
 * StatefulFlag — the SDK-output corpus's only MUTABLE `boolean` state field.
 *
 * It exists because nothing else in the corpus has this shape. Zero of the
 * conformance fixtures declared a non-readonly `boolean` property, so the
 * seven deployment SDKs were free to disagree about how to serialize one —
 * and five of them did, in three different ways (R-248): two framed the
 * ASCII text `true`/`false` as push data, two silently wrote `00` whatever
 * the value was, and one panicked. All five deploy a state tail the
 * compiler's own on-chain reader cannot reconstruct, so the first spend
 * fails `hash256(outputs)` and the UTXO is stuck.
 *
 * The compiler spells the type `boolean` (never `bool`) and annotates it
 * `encoding: "bool1", byteLength: 1`, i.e. ONE raw byte, `01` or `00`.
 *
 * `count` is here so the boolean is not the only field: it pins the byte
 * OFFSET of the flag as well as its width, which is what caught the
 * wrong-length `02true` encodings.
 */
class StatefulFlag extends StatefulSmartContract {
  count: bigint;
  flag: boolean;

  constructor(count: bigint, flag: boolean) {
    super(count, flag);
    this.count = count;
    this.flag = flag;
  }

  /** Bumps the counter and raises the flag. */
  public raise() {
    assert(this.count >= 0n);
    this.count++;
    this.flag = true;
  }

  /** Bumps the counter and lowers the flag. */
  public lower() {
    assert(this.count >= 0n);
    this.count++;
    this.flag = false;
  }
}
