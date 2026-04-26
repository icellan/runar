import {
  SmartContract,
  assert,
  bbFieldAdd,
  bbFieldSub,
  bbFieldMul,
  bbFieldInv,
  bbExt4Mul0,
  bbExt4Mul1,
  bbExt4Mul2,
  bbExt4Mul3,
  bbExt4Inv0,
  bbExt4Inv1,
  bbExt4Inv2,
  bbExt4Inv3,
} from 'runar-lang';

class BabyBearExt4Demo extends SmartContract {
  constructor() {
    super();
  }

  /** Ext4 multiplication: verify all 4 components */
  public checkMul(
    a0: bigint, a1: bigint, a2: bigint, a3: bigint,
    b0: bigint, b1: bigint, b2: bigint, b3: bigint,
    e0: bigint, e1: bigint, e2: bigint, e3: bigint,
  ) {
    assert(bbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3) === e0);
    assert(bbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3) === e1);
    assert(bbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3) === e2);
    assert(bbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3) === e3);
  }

  /** Ext4 inverse: verify all 4 components */
  public checkInv(
    a0: bigint, a1: bigint, a2: bigint, a3: bigint,
    e0: bigint, e1: bigint, e2: bigint, e3: bigint,
  ) {
    assert(bbExt4Inv0(a0, a1, a2, a3) === e0);
    assert(bbExt4Inv1(a0, a1, a2, a3) === e1);
    assert(bbExt4Inv2(a0, a1, a2, a3) === e2);
    assert(bbExt4Inv3(a0, a1, a2, a3) === e3);
  }

  /** FRI colinearity check: the core FRI folding relation */
  public checkFriFold(
    x: bigint,
    fx0: bigint, fx1: bigint, fx2: bigint, fx3: bigint,
    fnx0: bigint, fnx1: bigint, fnx2: bigint, fnx3: bigint,
    a0: bigint, a1: bigint, a2: bigint, a3: bigint,
    eg0: bigint, eg1: bigint, eg2: bigint, eg3: bigint,
  ) {
    const s0 = bbFieldAdd(fx0, fnx0);
    const s1 = bbFieldAdd(fx1, fnx1);
    const s2 = bbFieldAdd(fx2, fnx2);
    const s3 = bbFieldAdd(fx3, fnx3);
    const inv2 = bbFieldInv(2n);
    const hs0 = bbFieldMul(s0, inv2);
    const hs1 = bbFieldMul(s1, inv2);
    const hs2 = bbFieldMul(s2, inv2);
    const hs3 = bbFieldMul(s3, inv2);
    const d0 = bbFieldSub(fx0, fnx0);
    const d1 = bbFieldSub(fx1, fnx1);
    const d2 = bbFieldSub(fx2, fnx2);
    const d3 = bbFieldSub(fx3, fnx3);
    const ad0 = bbExt4Mul0(a0, a1, a2, a3, d0, d1, d2, d3);
    const ad1 = bbExt4Mul1(a0, a1, a2, a3, d0, d1, d2, d3);
    const ad2 = bbExt4Mul2(a0, a1, a2, a3, d0, d1, d2, d3);
    const ad3 = bbExt4Mul3(a0, a1, a2, a3, d0, d1, d2, d3);
    const inv2x = bbFieldInv(bbFieldMul(2n, x));
    const at0 = bbFieldMul(ad0, inv2x);
    const at1 = bbFieldMul(ad1, inv2x);
    const at2 = bbFieldMul(ad2, inv2x);
    const at3 = bbFieldMul(ad3, inv2x);
    const g0 = bbFieldAdd(hs0, at0);
    const g1 = bbFieldAdd(hs1, at1);
    const g2 = bbFieldAdd(hs2, at2);
    const g3 = bbFieldAdd(hs3, at3);
    assert(g0 === eg0);
    assert(g1 === eg1);
    assert(g2 === eg2);
    assert(g3 === eg3);
  }
}
