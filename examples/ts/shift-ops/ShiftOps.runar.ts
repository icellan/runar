import { SmartContract, assert } from 'runar-lang';

/**
 * WARNING — read before copying this shape.
 *
 * `<<` and `>>` compile to `OP_LSHIFT` / `OP_RSHIFT`, which operate on the
 * operand's raw stack BYTES and PRESERVE its byte length — they are NOT numeric
 * shifts (spec/opcodes.md:176, docs/language-reference.md:287). So `16 << 3`
 * leaves the 1-byte `0x80` and `4 >> 2` leaves `0x00`, neither of which is a
 * MINIMALLY encoded script number. The `===` below is a numeric read, and every
 * numeric read on chain decodes with fRequireMinimal=true and ABORTS on a
 * non-minimal operand — so the spend fails for such an `a` whatever expected
 * values the caller supplies. Where the result is minimal it equals the
 * integer `a * 8` / `a / 4` only while no set bit leaves its byte.
 *
 * The caller supplies the expected results and the contract checks them, so a
 * wrong value — or a miscompiled shift — makes the spend fail. With a = 12:
 * left = 96, right = 3.
 *
 * This file exists as a CODEGEN fixture for the shift opcodes
 * (`conformance/tests/shift-ops`), not as a contract to imitate. For numeric
 * shifting use `a / pow(2n, b)` and `a * pow(2n, b)`, which compile to
 * OP_DIV / OP_MUL.
 */
class ShiftOps extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public testShift(expectedLeft: bigint, expectedRight: bigint): void {
    const left: bigint = this.a << 3n;
    const right: bigint = this.a >> 2n;
    assert(left === expectedLeft);
    assert(right === expectedRight);
  }
}
