import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { left, right } from '../runtime/index.js';

// F-274 (CL-BUG-163): the native TS runtime (`runar-lang/runtime`, what a
// .runar.ts contract calls when run as plain TypeScript) must return what the
// COMPILED SCRIPT returns, for every vector in the shared on-chain file
// packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
// packages/runar-testing/src/__tests__/f274-split-builtins-onchain.test.ts.
// `right(data, 0)` used to compute `data.slice(data.length - 0)` which is
// `data.slice(data.length)` — correct — but `.slice()` never throws, so an
// out-of-range `length` (negative, or past the end) silently returned a
// clamped substring instead of the abort OP_SPLIT actually produces.
//
// Proves: for every row, `left`/`right` return the on-chain value, or throw
// where the script aborts (never a value) — covering n=0, n=len(data),
// n>len(data), n<0, and an empty `data` input.
// Does not prove: inputs outside the file, or the script itself (the oracle).

const REPO = resolve(__dirname, '../../../..');

interface Row { fn: 'left' | 'right'; data: string; n: number; expect: string | 'abort' }

function loadRows(): Row[] {
  const text = readFileSync(
    resolve(REPO, 'packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json'),
    'utf8',
  );
  return (JSON.parse(text) as { cases: Row[] }).cases;
}

const FNS = { left, right };

describe('F-274: runar-lang runtime left/right return the on-chain value for every shared vector', () => {
  const rows = loadRows();

  for (const r of rows) {
    it(`${r.fn}(${JSON.stringify(r.data)}, ${r.n}) -> ${JSON.stringify(r.expect)}`, () => {
      const fn = FNS[r.fn];
      if (r.expect === 'abort') {
        expect(() => fn(r.data as never, BigInt(r.n))).toThrow();
      } else {
        expect(fn(r.data as never, BigInt(r.n))).toBe(r.expect);
      }
    });
  }
});
