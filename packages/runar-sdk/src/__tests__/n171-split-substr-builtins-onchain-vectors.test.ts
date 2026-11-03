import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { computeNewState } from '../anf-interpreter.js';
import type { ANFProgram } from 'runar-ir-schema';

// N-171 (sibling of F-274): the SDK ANF interpreter (what derives a call's
// post-state before the SDK builds the spend) must return what the COMPILED
// SCRIPT returns for `split` and `substr`, for every vector in the shared
// on-chain file packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json.
//
// R67: `substr` used to be left modelled-but-not-abort-faithful here, because
// its one caller via `extractScriptCode` (`FungibleToken.merge`) got an empty
// dummy scriptCode, turning a realistic `substr(sc, ...)` call into a POSITIVE
// overflow the old clamp had to swallow to avoid breaking `prepareCall`.
// `extractScriptCode` now returns the contract's own REAL codePart
// (`contract.ts`'s `prepareCall` supplies it via `ContinuationContext.scriptCode`
// — see that file's `getSubscriptForSigning(getCodePartHex(), methodIndex)`),
// so `substr` can be fully abort-faithful without starving `merge` of a
// realistic scriptCode. Confirmed by
// packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
// packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts.
//
// Proves: for every row, the interpreter returns the on-chain value, or
// throws where the script aborts (never a value) — covering n=0, interior,
// n=len(data), n>len(data), n<0, and an empty `data` input.
// Does not prove: inputs outside the file, or the script itself (the oracle).

const REPO = resolve(__dirname, '../../../..');

interface Row { fn: 'split' | 'substr'; data: string; a: number; b: number; expect: string | 'abort' }

function loadRows(): Row[] {
  const text = readFileSync(
    resolve(REPO, 'packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json'),
    'utf8',
  );
  return (JSON.parse(text) as { cases: Row[] }).cases;
}

function probe(fn: 'split' | 'substr', data: string, a: bigint, b: bigint): unknown {
  const params = fn === 'split'
    ? [{ name: 'data', type: 'ByteString' }, { name: 'a', type: 'bigint' }]
    : [{ name: 'data', type: 'ByteString' }, { name: 'a', type: 'bigint' }, { name: 'b', type: 'bigint' }];
  const callArgs = fn === 'split' ? ['t0', 't1'] : ['t0', 't1', 't2'];
  const body = [
    { name: 't0', value: { kind: 'load_param' as const, name: 'data' } },
    { name: 't1', value: { kind: 'load_param' as const, name: 'a' } },
    ...(fn === 'substr' ? [{ name: 't2', value: { kind: 'load_param' as const, name: 'b' } }] : []),
    { name: 'r', value: { kind: 'call' as const, func: fn, args: callArgs } },
    { name: 'u', value: { kind: 'update_prop' as const, name: 'result', value: 'r' } },
  ];
  const anf: ANFProgram = {
    contractName: 'SplitSubstrProbe',
    properties: [{ name: 'result', type: 'ByteString', readonly: false }],
    methods: [{ name: 'probe', params, body, isPublic: true }],
  };
  return computeNewState(anf, 'probe', { result: '' }, { data, a, b }).result;
}

describe('N-171: SDK ANF interpreter split/substr return the on-chain value for every shared vector', () => {
  const rows = loadRows();

  it('covers n=0, interior, n=len(data), n>len(data), n<0, and an empty data input for both builtins', () => {
    expect(rows.filter((r) => r.fn === 'split').length).toBeGreaterThan(0);
    expect(rows.filter((r) => r.fn === 'substr').length).toBeGreaterThan(0);
  });

  for (const r of rows) {
    const label = `${r.fn}(${JSON.stringify(r.data)}, ${r.a}${r.fn === 'substr' ? `, ${r.b}` : ''}) -> ${JSON.stringify(r.expect)}`;
    it(label, () => {
      if (r.expect === 'abort') {
        expect(() => probe(r.fn, r.data, BigInt(r.a), BigInt(r.b))).toThrow();
        return;
      }
      expect(probe(r.fn, r.data, BigInt(r.a), BigInt(r.b))).toBe(r.expect);
    });
  }
});
