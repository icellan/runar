import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import * as rt from '../runtime/index.js';

// N-030 (CL-BUG-104): the native TS runtime (`runar-lang/runtime`, what a
// .runar.ts contract calls when run as plain TypeScript) must return what the
// COMPILED SCRIPT returns, for every vector in the shared on-chain file
// packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
// packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts
// (accept at `expect`, reject at `expect + 1`; an `abort` row rejects both
// `=== 0` and `!== 0`). Every other tier's native runtime and SDK ANF
// interpreter replays the same file.
//
// Proves: for every `cases` and `wideCases` row, the runtime returns the
// on-chain value, or throws where the script aborts (never a value) — including
// clamp with lo > hi, log2 of n <= 0 (0, not an error) and saturating at 64,
// and gcd's partial remainder after 256 Euclid steps.
// Does not prove: inputs outside the file, or the script itself (the oracle).

const REPO = resolve(__dirname, '../../../..');

type Want = bigint | boolean | 'abort';
interface Row { fn: string; args: bigint[]; expect: Want }

function loadRows(): Row[] {
  const text = readFileSync(
    resolve(REPO, 'packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json'),
    'utf8',
  );
  // `cases` hold exact JSON integers (keep them exact via the source text);
  // `wideCases` hold decimal strings.
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

const FNS: Record<string, (...a: bigint[]) => bigint | boolean> = {
  percentOf: rt.percentOf, mulDiv: rt.mulDiv, safediv: rt.safediv, safemod: rt.safemod,
  divmod: rt.divmod, sqrt: rt.sqrt, log2: rt.log2, pow: rt.pow, clamp: rt.clamp,
  within: rt.within, sign: rt.sign, gcd: rt.gcd, abs: rt.abs, min: rt.min, max: rt.max,
  bool: rt.bool,
};

describe('N-030: runar-lang runtime math builtins return the on-chain value for every shared vector', () => {
  const rows = loadRows();

  it('the shared file covers every math builtin of the runtime', () => {
    expect(new Set(rows.map((r) => r.fn))).toEqual(new Set(Object.keys(FNS)));
  });

  for (const r of rows) {
    it(`${r.fn}(${r.args.join(', ')}) -> ${String(r.expect)}`, () => {
      const fn = FNS[r.fn]!;
      if (r.expect === 'abort') {
        expect(() => fn(...r.args)).toThrow();
      } else {
        expect(fn(...r.args)).toBe(r.expect);
      }
    });
  }
});
