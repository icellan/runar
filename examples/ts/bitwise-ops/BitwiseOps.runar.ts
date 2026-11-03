import { SmartContract, assert } from 'runar-lang';

/**
 * The caller supplies the expected result of each shift / AND / OR / XOR and
 * the contract checks it, so a wrong value (or a miscompiled operator) makes
 * the spend fail.
 *
 * These operators compile to byte-array opcodes (OP_LSHIFT, OP_RSHIFT, OP_AND,
 * OP_OR, OP_XOR, OP_INVERT) that work on the operand's stack BYTES and keep its
 * length — see spec/opcodes.md. For small positive operands whose results stay
 * below 0x80 (e.g. a = 12, b = 10) the values match ordinary integer
 * arithmetic. `~a` never does: OP_INVERT on 12 (0x0c) leaves 0xf3, which is the
 * script number -115, not -13. So `~` is checked by properties that hold under
 * both readings: inverting twice gives `a` back, and De Morgan's law
 * `~(a | b) == ~a & ~b`.
 */
class BitwiseOps extends SmartContract {
  readonly a: bigint;
  readonly b: bigint;

  constructor(a: bigint, b: bigint) {
    super(a, b);
    this.a = a;
    this.b = b;
  }

  public testShift(expectedLeft: bigint, expectedRight: bigint): void {
    const left = this.a << 2n;
    const right = this.a >> 1n;
    assert(left === expectedLeft);
    assert(right === expectedRight);
  }

  public testBitwise(expectedAnd: bigint, expectedOr: bigint, expectedXor: bigint): void {
    const andResult = this.a & this.b;
    const orResult = this.a | this.b;
    const xorResult = this.a ^ this.b;
    const notResult = ~this.a;
    assert(andResult === expectedAnd);
    assert(orResult === expectedOr);
    assert(xorResult === expectedXor);
    assert(~notResult === this.a);
    assert(~(this.a | this.b) === (notResult & ~this.b));
  }
}
