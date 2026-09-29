// F-026: `0b102` is not a TypeScript literal (TS reports "',' expected" after
// `0b10`). ts-morph recovered from that syntax error and the reference tier
// compiled the guard as `a > 2`. Every tier must refuse; the hand-written
// tokenizers and the ts-morph / tree-sitter / swc literal checks say:
//   invalid TypeScript integer literal '0b102'
import { SmartContract, assert } from 'runar-lang';

class T extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint): void {
    assert(a > 0b102);
  }
}
