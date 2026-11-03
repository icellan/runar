// N-234: a FixedArray property initializer's element-type check (N-133,
// see N29-fixed-array-initializer-element-type.runar.ts) only recognised a
// bare ByteStringLiteral AST node, not the `toByteString(<hex>)` CALL shape
// that 02-validate's own `isToByteStringLiteral` treats as the SAME
// ByteStringLiteral production (spec/grammar.md section 11).
//
// `FixedArray<bigint, 2> = [toByteString('ab'), 0n]` slipped past N-133's
// check for that reason alone — a bare `'ab'` element (no call wrapper) in
// the same slot was already caught. All seven tiers accepted this contract
// and emitted `01ab519c`, pushing a byte string where the contract's own
// arithmetic expects a script NUMBER.
import { SmartContract, assert, FixedArray, toByteString } from 'runar-lang';

export class ArrayInitCallWrappedTypeMismatch extends SmartContract {
  readonly arr: FixedArray<bigint, 2> = [toByteString('ab'), 0n];

  constructor() {
    super();
  }

  public check(): void {
    assert(this.arr[0] === 1n);
  }
}
