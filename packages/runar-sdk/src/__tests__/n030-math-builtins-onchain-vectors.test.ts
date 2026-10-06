import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { computeNewState } from '../anf-interpreter.js';
import type { ANFProgram } from 'runar-ir-schema';

// N-030 (CL-BUG-104): the SDK ANF interpreter (what derives a call's
// post-state before the SDK builds the spend) must return what the COMPILED
// SCRIPT returns, for every vector in the shared on-chain file
// packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
// packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts
// (accept at `expect`, reject at `expect + 1`; an `abort` row rejects both
// `=== 0` and `!== 0`). Every other tier replays the same file.
//
// Proves: for every `cases` and `wideCases` row the interpreter returns the
// on-chain value, or throws where the script aborts (never a value) — including
// clamp with lo > hi (min(max(v, lo), hi)), log2 saturating at 64 and gcd's
// partial remainder after 256 Euclid steps.
// Does not prove: inputs outside the file, or the script itself (the oracle).
// `bool`/`within` results are compared as script numbers (true == 1, false == 0).

const REPO = resolve(__dirname, '../../../..');

type Want = bigint | boolean | 'abort';
interface Row { fn: string; args: bigint[]; expect: Want }

function loadRows(): Row[] {
  const text = readFileSync(
    resolve(REPO, 'packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json'),
    'utf8',
  );
  const parsed = JSON.parse(text, (_k, v, ctx?: { source?: string }) => {
    if (typeof v !== 'number') return v;
    if (!ctx || ctx.source === undefined) {
      throw new Error('JSON.parse reviver has no source text (needs Node >= 21)');
    }
    return BigInt(ctx.source);
  }) as {
    cases: Row[];
    wideCases: Array<{ fn: string; args: string[]; expect: string | boolean }>;
  };
  const wide = parsed.wideCases.map((c) => ({
    fn: c.fn,
    args: c.args.map((a) => BigInt(a)),
    expect: (typeof c.expect === 'boolean' ? c.expect : c.expect === 'abort' ? 'abort' : BigInt(c.expect)) as Want,
  }));
  return [...parsed.cases, ...wide];
}

function probe(func: string, args: bigint[]): unknown {
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
  return computeNewState(anf, 'probe', { result: 0n }, named).result;
}

function asScriptNumber(v: unknown): bigint {
  if (typeof v === 'boolean') return v ? 1n : 0n;
  if (typeof v === 'bigint') return v;
  throw new Error(`interpreter returned a non-integer: ${String(v)}`);
}

describe('N-030: SDK ANF interpreter math builtins return the on-chain value for every shared vector', () => {
  for (const r of loadRows()) {
    it(`${r.fn}(${r.args.join(', ')}) -> ${String(r.expect)}`, () => {
      if (r.expect === 'abort') {
        expect(() => probe(r.fn, r.args)).toThrow();
        return;
      }
      expect(asScriptNumber(probe(r.fn, r.args))).toBe(asScriptNumber(r.expect));
    });
  }
});
