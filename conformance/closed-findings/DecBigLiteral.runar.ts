// N-134 control: the same number in DECIMAL — the spelling every tier already
// accepted. Paired with HexBigLiteral.runar.ts: the two are one number, so a
// tier that compiles both must emit one script for both, and this file is how
// that comparison gets its second operand.
import { SmartContract, assert } from 'runar-lang';

export class DecBigLiteral extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x < 115792089237316195423570985008687907852837564279074904382605163141518161494337n && x > this.a);
  }
}
