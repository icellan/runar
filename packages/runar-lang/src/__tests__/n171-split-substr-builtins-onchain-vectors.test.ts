import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { split, substr } from '../runtime/index.js';

// N-171 (sibling of F-274): the native TS runtime (`runar-lang/runtime`, what
// a .runar.ts contract calls when run as plain TypeScript) must return what
// the COMPILED SCRIPT returns, for every vector in the shared on-chain file
// packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate
// by packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts.
// `.slice()` never throws, so an out-of-range `start`/`length`/`index`
// (negative, or past the end) silently returned a clamped substring instead
// of the abort OP_SPLIT actually produces.
//
// Proves: for every row, `split`/`substr` return the on-chain value, or throw
// where the script aborts (never a value) — covering n=0, interior, n=len,
// n>len, n<0, and an empty `data` input.
// Does not prove: inputs outside the file, or the script itself (the oracle).

const REPO = resolve(__dirname, '../../../..');

interface Row {
  fn: 'split' | 'substr';
  data: string;
  a: number;
  b: number;
  expect: string | 'abort';
}

function loadRows(): Row[] {
  const text = readFileSync(
    resolve(REPO, 'packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json'),
    'utf8',
  );
  return (JSON.parse(text) as { cases: Row[] }).cases;
}

describe('N-171: runar-lang runtime split/substr return the on-chain value for every shared vector', () => {
  const rows = loadRows();

  for (const r of rows) {
    const label = `${r.fn}(${JSON.stringify(r.data)}, ${r.a}${r.fn === 'substr' ? `, ${r.b}` : ''}) -> ${JSON.stringify(r.expect)}`;
    it(label, () => {
      const call = () =>
        r.fn === 'split'
          ? split(r.data as never, BigInt(r.a))
          : substr(r.data as never, BigInt(r.a), BigInt(r.b));
      if (r.expect === 'abort') {
        expect(call).toThrow();
      } else {
        expect(call()).toBe(r.expect);
      }
    });
  }
});
