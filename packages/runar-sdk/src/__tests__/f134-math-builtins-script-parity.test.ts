import { describe, it, expect } from 'vitest';
import { computeNewState } from '../anf-interpreter.js';
import type { ANFProgram } from 'runar-ir-schema';

// F-134: the SDK ANF interpreter (what derives a call's post-state) must compute
// what the compiled script computes for the math builtins.
//
// The expected column was established by EXECUTING the TS compiler's script for
// each builtin in @bsv/sdk's Spend (ScriptExecutionContract, fold ON and OFF,
// identical): OP_DIV/OP_MOD truncate toward zero; a zero divisor aborts; `pow`
// aborts outside 0 <= exp <= 32; `sqrt` aborts on n < 0 and n >= 2^495. ABORT
// means the script fails, so the interpreter must throw rather than invent a
// value (it used to return 0, so the SDK built a continuation for a spend the
// script rejects).
//
// Proves: for each listed input the interpreter returns the script's value or
// throws where the script aborts. Does not prove: agreement outside the table,
// or anything about the script itself (it is the oracle here, not the subject).

const ABORT = 'ABORT' as const;
const P495 = 1n << 495n;

const VECTORS: Array<[string, bigint[], bigint | typeof ABORT]> = [
  ['divmod', [-7n, 2n], -3n],
  ['divmod', [7n, -2n], -3n],
  ['divmod', [1n, 0n], ABORT],
  ['mulDiv', [-7n, 1n, 2n], -3n],
  ['mulDiv', [1n, 1n, 0n], ABORT],
  ['percentOf', [-1n, 5000n], 0n],
  ['percentOf', [-15000n, 1n], -1n],
  ['pow', [2n, -1n], ABORT],
  ['pow', [2n, 0n], 1n],
  ['pow', [-2n, 3n], -8n],
  ['pow', [2n, 32n], 4294967296n],
  ['pow', [2n, 33n], ABORT],
  ['sqrt', [-1n], ABORT],
  ['sqrt', [0n], 0n],
  ['sqrt', [8n], 2n],
  ['sqrt', [P495], ABORT],
  ['safediv', [-7n, 2n], -3n],
  ['safediv', [1n, 0n], ABORT],
  ['safemod', [-7n, 2n], -1n],
  ['safemod', [7n, -2n], 1n],
  ['safemod', [1n, 0n], ABORT],
];

function probe(func: string, args: bigint[]): bigint {
  const params = ['a', 'b', 'c'].slice(0, args.length);
  const anf: ANFProgram = {
    contractName: 'MathProbe',
    properties: [{ name: 'result', type: 'bigint', readonly: false }],
    methods: [
      {
        name: 'probe',
        params: params.map((name) => ({ name, type: 'bigint' })),
        body: [
          ...params.map((name, i) => ({ name: `t${i}`, value: { kind: 'load_param' as const, name } })),
          { name: 'r', value: { kind: 'call' as const, func, args: params.map((_, i) => `t${i}`) } },
          { name: 'u', value: { kind: 'update_prop' as const, name: 'result', value: 'r' } },
        ],
        isPublic: true,
      },
    ],
  };
  const named = Object.fromEntries(params.map((p, i) => [p, args[i]!]));
  return computeNewState(anf, 'probe', { result: 0n }, named).result as bigint;
}

describe('F-134: SDK ANF interpreter math builtins match the compiled script', () => {
  for (const [func, args, want] of VECTORS) {
    const label = `${func}(${args.map((a) => (a === P495 ? '2**495' : String(a))).join(', ')})`;
    it(`${label} -> ${String(want)}`, () => {
      if (want === ABORT) {
        expect(() => probe(func, args)).toThrow();
      } else {
        expect(probe(func, args)).toBe(want);
      }
    });
  }
});
