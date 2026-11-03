import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * N-201 — the EC algebraic optimizer rewrites EC calls inside `if` arms and
 * loop bodies, not only at the method's top level.
 *
 * Before the fix every nested call below survived to stack lowering: each
 * `ecMulGen(0n)` shipped the full ~850 KB scalar multiplier. After it, every
 * EC call here is rewritten away (Rule 5 `ecMulGen(0) -> O`, Rule 6
 * `ecMulGen(1) -> G`, Rule 1 `ecAdd(q, O) -> q` with its N-104 operand gate,
 * Rule 3 `ecMul(q, 1) -> q` with its N-104 operand gate) and the script is a
 * few kilobytes.
 */
export class EcNestedRewrite extends SmartContract {
  constructor() {
    super();
  }

  /** flag = 1: result is O (0, 0). Otherwise G. */
  public ifArm(flag: bigint, expectedX: bigint, expectedY: bigint) {
    let result: Point = ecMulGen(1n);
    if (flag === 1n) {
      result = ecMulGen(0n);
    }
    assert(ecPointX(result) === expectedX);
    assert(ecPointY(result) === expectedY);
  }

  /** The loop body leaves O on every iteration. */
  public loopBody(expectedX: bigint, expectedY: bigint) {
    let result: Point = ecMulGen(1n);
    for (let i: bigint = 0n; i < 2n; i++) {
      result = ecMulGen(0n);
    }
    assert(ecPointX(result) === expectedX);
    assert(ecPointY(result) === expectedY);
  }

  /**
   * Gate-emitting rewrites inside both arms: then `ecAdd(p, O) -> p` keeps the
   * ecAdd operand gate (64 bytes, canonical coordinates); else
   * `ecMul(p, 1) -> p` keeps the ecMul operand gate (O or on-curve).
   */
  public gatedArms(p: Point, flag: bigint, expectedX: bigint) {
    let result: Point = p;
    if (flag === 1n) {
      result = ecAdd(p, ecMulGen(0n));
    } else {
      result = ecMul(p, 1n);
    }
    assert(ecPointX(result) === expectedX);
  }
}
