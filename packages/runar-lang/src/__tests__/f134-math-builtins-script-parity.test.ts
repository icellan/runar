import { describe, it, expect } from 'vitest';
import { safediv, safemod, pow, mulDiv, percentOf, sqrt, divmod } from '../runtime/index.js';

// F-134: the native TS runtime of the math builtins must compute what the
// compiled script computes. The expected column was established by EXECUTING
// the TS compiler's script for each builtin in @bsv/sdk's Spend (fold ON and
// OFF, identical): OP_DIV/OP_MOD truncate toward zero; a zero divisor aborts;
// `pow` aborts outside 0 <= exp <= 32; `sqrt` aborts on n < 0 and n >= 2^495.
//
// Proves: for each listed input the runtime returns the script's value or
// throws where the script aborts. Does not prove: agreement outside the table,
// or anything about the script itself (it is the oracle here).

const ABORT = 'ABORT' as const;
const P495 = 1n << 495n;
type Fn = (...a: bigint[]) => bigint;

const VECTORS: Array<[string, Fn, bigint[], bigint | typeof ABORT]> = [
  ['divmod', divmod as Fn, [-7n, 2n], -3n],
  ['divmod', divmod as Fn, [1n, 0n], ABORT],
  ['mulDiv', mulDiv as Fn, [-7n, 1n, 2n], -3n],
  ['mulDiv', mulDiv as Fn, [1n, 1n, 0n], ABORT],
  ['percentOf', percentOf as Fn, [-1n, 5000n], 0n],
  ['percentOf', percentOf as Fn, [-15000n, 1n], -1n],
  ['pow', pow as Fn, [2n, -1n], ABORT],
  ['pow', pow as Fn, [2n, 32n], 4294967296n],
  ['pow', pow as Fn, [2n, 33n], ABORT],
  ['pow', pow as Fn, [1n, 40n], ABORT],
  ['sqrt', sqrt as Fn, [-1n], ABORT],
  ['sqrt', sqrt as Fn, [8n], 2n],
  ['sqrt', sqrt as Fn, [P495 - 1n], 319833482451031748506059381027264173076200908090793894772741615627956073369n],
  ['sqrt', sqrt as Fn, [P495], ABORT],
  ['safediv', safediv as Fn, [-7n, 2n], -3n],
  ['safediv', safediv as Fn, [1n, 0n], ABORT],
  ['safemod', safemod as Fn, [-7n, 2n], -1n],
  ['safemod', safemod as Fn, [1n, 0n], ABORT],
];

describe('F-134: runar-lang runtime math builtins match the compiled script', () => {
  for (const [name, fn, args, want] of VECTORS) {
    const label = `${name}(${args.map((a) => (a === P495 ? '2**495' : a === P495 - 1n ? '2**495-1' : String(a))).join(', ')})`;
    it(`${label} -> ${String(want)}`, () => {
      if (want === ABORT) {
        expect(() => fn(...args)).toThrow();
      } else {
        expect(fn(...args)).toBe(want);
      }
    });
  }
});
