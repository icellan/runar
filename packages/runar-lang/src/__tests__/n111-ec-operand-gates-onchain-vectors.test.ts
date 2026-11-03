import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  ecAdd, ecMul, ecMulGen, ecNegate, ecPointX, ecPointY, ecEncodeCompressed, ecOnCurve,
} from '../runtime/index.js';

// N-111: the native TS runtime (`runar-lang/runtime`, what a .runar.ts
// contract calls when run as plain TypeScript) must apply the compiled
// script's EC operand gates — ecAdd / ecNegate: 64 bytes and x, y < p
// (R-117); ecMul: on-curve or the all-zero identity O (R-157); ecPointX /
// ecPointY / ecEncodeCompressed: width only — and the script's identity
// semantics (R-053: P + O = P, P + (-P) = O, k*P = O for k = 0).
//
// Oracle: packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json,
// every row executed on @bsv/sdk Spend.validate by
// packages/runar-testing/src/__tests__/n111-ec-operand-gates-onchain.test.ts.
//
// Proves: for every row, each builtin returns the on-chain value, or throws
// where the script aborts (never a value).
// Does not prove: inputs outside the file, or the script itself.

const REPO = resolve(__dirname, '../../../..');

interface Row { fn: string; p?: string; q?: string; k?: string; expect: string; why: string }

const rows = (JSON.parse(readFileSync(
  resolve(REPO, 'packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json'),
  'utf8',
)) as { cases: Row[] }).cases;

function run(r: Row): unknown {
  const p = r.p as never;
  const q = r.q as never;
  switch (r.fn) {
    case 'ecAdd': return ecAdd(p, q);
    case 'ecMul': return ecMul(p, BigInt(r.k!));
    case 'ecMulGen': return ecMulGen(BigInt(r.k!));
    case 'ecNegate': return ecNegate(p);
    case 'ecPointX': return ecPointX(p);
    case 'ecPointY': return ecPointY(p);
    case 'ecEncodeCompressed': return ecEncodeCompressed(p);
    case 'ecOnCurve': return ecOnCurve(p);
    default: throw new Error(`unknown fn ${r.fn}`);
  }
}

describe('N-111: runar-lang runtime EC builtins match the on-chain operand gates', () => {
  for (const r of rows) {
    it(`${r.fn} [${r.why}] -> ${r.expect === 'abort' ? 'abort' : 'value'}`, () => {
      if (r.expect === 'abort') {
        expect(() => run(r)).toThrow();
        return;
      }
      const want = r.fn === 'ecPointX' || r.fn === 'ecPointY' ? BigInt(r.expect)
        : r.fn === 'ecOnCurve' ? r.expect === 'true'
        : r.expect;
      expect(run(r)).toBe(want);
    });
  }
});
