import {
  SmartContract, assert,
  ecAdd, ecMul, ecMulGen, ecPointX, ecPointY, ecOnCurve,
  hash256, cat, bin2num,
} from 'runar-lang';
import type { Point } from 'runar-lang';

class SchnorrZKP extends SmartContract {
  readonly pubKey: Point;

  constructor(pubKey: Point) {
    super(pubKey);
    this.pubKey = pubKey;
  }

  public verify(rPoint: Point, s: bigint) {
    assert(ecOnCurve(rPoint));
    const e = bin2num(hash256(cat(rPoint, this.pubKey)));
    const sG = ecMulGen(s);
    const eP = ecMul(this.pubKey, e);
    const rhs = ecAdd(rPoint, eP);
    assert(ecPointX(sG) === ecPointX(rhs));
    assert(ecPointY(sG) === ecPointY(rhs));
  }
}
