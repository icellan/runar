// N-133: a FixedArray property initializer with an element of the wrong type.
//
// Found while building the R-101 diagnostic-coverage corpus. 03-typecheck's
// element-type check lives on the `array_literal` branch of expression
// inference, and a PROPERTY INITIALIZER never reaches it — initializers are
// consumed by 03b-expand-fixed-arrays, which validated only the LENGTH.
//
// All seven tiers accepted this contract and emitted `5151937ca0`
// (OP_1 OP_1 OP_ADD OP_SWAP OP_GREATERTHAN): the boolean silently became the
// number 1. With a hex literal in the same slot the emitted script pushes a
// BYTE STRING where the contract's own arithmetic expects a number, so
// `this.arr[0n] + this.arr[1n]` becomes an OP_ADD over a 2-byte blob — a
// different program from the one the author wrote, deployed without complaint.
// Seven-tier agreement on the wrong answer, which is why a positive-parity
// suite could never have caught it.
//
// The shape stays invalid under any future typing rule: `true` is not a member
// of the bigint family on any surface.
import { SmartContract, assert, FixedArray } from 'runar-lang';

export class FixedArrayInitElementType extends SmartContract {
  readonly arr: FixedArray<bigint, 2> = [1n, true];

  constructor() {
    super();
  }

  public go(x: bigint) {
    assert(this.arr[0n] + this.arr[1n] > x);
  }
}
