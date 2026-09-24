// F-011: an unterminated .runar.ts string literal. ts-morph ends it at the
// line break and records a syntax diagnostic that the reference parser used
// to ignore, so the TS tier compiled this program. Every tier must refuse;
// the hand-written TS surfaces say
//   unterminated string literal
import { SmartContract, ByteString, assert } from 'runar-lang';

export class Guarded extends SmartContract {
  constructor() {
    super();
  }

  public unlock(y: bigint): void {
    const tag: ByteString = "cafe;
    assert(y < 5n);
    assert(y >= 0n);
  }
}
