// R-301 (CL-TODO-001): the `number` type.
//
// Rúnar has no `number`. Its numeric type is `bigint`, and the reason is not
// stylistic: `number` is IEEE-754 double, Bitcoin Script arithmetic is exact
// integer, and a contract whose author believes a parameter is a double has
// a different program in mind than the one that gets emitted.
//
// Two tiers said so. Five did not. Measured on this shape:
//
//   go      parse errors: use 'bigint' instead of 'number' in Rúnar contracts
//   rust    'number' type is not allowed in Rúnar contracts; use 'bigint' instead
//   ts      warning: Unsupported type: 'number'   then 009c77
//   python  009c77
//   ruby    009c77
//   zig     009c77
//   java    009c77
//
// Five tiers compiled it, to identical bytes — `number` was silently treated
// as `bigint`, which is the same coercion go and rust perform, except they say
// so and refuse. The TS tier printed a WARNING and continued, which is how the
// gap survived: it looks handled.
//
// The TS half is the finding as filed. `checkNoNumberType`
// (packages/runar-compiler/src/passes/02-validate.ts) was a no-op stub whose
// own comment said "'number' would not be a PrimitiveTypeName in Rúnar ... so
// this is mainly a sanity check" — called from two sites, doing nothing, while
// the parser was quietly mapping `number` onto `bigint` upstream.
//
// A contract that compares the parameter is refused by the TS tier for a
// DIFFERENT reason ("Cannot compare 'number' and 'bigint' with '==='"), which
// is why this fixture deliberately does not compare it: an accidental refusal
// is not a rule.
//
// No fixture, example or conformance source in the repo declares a `number`
// type (checked across all nine surfaces), so requiring the refusal breaks
// nothing that compiled.

import { SmartContract, assert } from 'runar-lang';

class NumberType extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: number, y: bigint) {
    assert(y === this.limit);
  }
}
