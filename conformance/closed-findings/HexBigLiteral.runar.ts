// N-134: an oversize integer literal written in HEX.
//
// `0xFFFF…41n` is secp256k1's group order, and the ordinary way to write any
// curve bound. Six tiers compiled this; the Zig tier's nine surface parsers all
// rejected it with `invalid integer`, because their oversize-literal fallback
// recognised decimal digits only. The failure mode is the worst kind for a
// parity suite — not a divergent script but an absent one, so a cross-tier
// comparison never gets a value from that tier to disagree with.
//
// DecBigLiteral.runar.ts is the same number in decimal. The pair is the real
// assertion: two spellings of one number must compile to one script, in every
// tier.
import { SmartContract, assert } from 'runar-lang';

export class HexBigLiteral extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n && x > this.a);
  }
}
