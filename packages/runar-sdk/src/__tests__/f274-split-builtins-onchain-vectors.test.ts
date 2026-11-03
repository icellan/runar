import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { computeNewState } from '../anf-interpreter.js';
import type { ANFProgram } from 'runar-ir-schema';

// F-274 (CL-BUG-163): the SDK ANF interpreter (what derives a call's
// post-state before the SDK builds the spend) must return what the COMPILED
// SCRIPT returns for `left`/`right`, for every vector in the shared on-chain
// file packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
// packages/runar-testing/src/__tests__/f274-split-builtins-onchain.test.ts.
//
// Proves: for every row, the interpreter returns the on-chain value, or
// throws where the script aborts (never a value) — covering n=0, n=len(data),
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

function probe(func: string, data: string, n: bigint): unknown {
  const anf: ANFProgram = {
    contractName: 'SplitProbe',
    properties: [{ name: 'result', type: 'ByteString', readonly: false }],
    methods: [
      {
        name: 'probe',
        params: [
          { name: 'data', type: 'ByteString' },
          { name: 'n', type: 'bigint' },
        ],
        body: [
          { name: 't0', value: { kind: 'load_param' as const, name: 'data' } },
          { name: 't1', value: { kind: 'load_param' as const, name: 'n' } },
          { name: 'r', value: { kind: 'call' as const, func, args: ['t0', 't1'] } },
          { name: 'u', value: { kind: 'update_prop' as const, name: 'result', value: 'r' } },
        ],
        isPublic: true,
      },
    ],
  };
  return computeNewState(anf, 'probe', { result: '' }, { data, n }).result;
}

describe('F-274: SDK ANF interpreter left/right return the on-chain value for every shared vector', () => {
  for (const r of loadRows()) {
    it(`${r.fn}(${JSON.stringify(r.data)}, ${r.n}) -> ${JSON.stringify(r.expect)}`, () => {
      if (r.expect === 'abort') {
        expect(() => probe(r.fn, r.data, BigInt(r.n))).toThrow();
        return;
      }
      expect(probe(r.fn, r.data, BigInt(r.n))).toBe(r.expect);
    });
  }
});
