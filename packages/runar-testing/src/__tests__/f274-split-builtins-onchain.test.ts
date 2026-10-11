/**
 * F-274 (CL-BUG-163) — the on-chain half of the `left`/`right` builtin check.
 *
 * `right(data, 0)` in `packages/runar-rb/lib/runar/builtins.rb` computed
 * `data[-(0*2)..]`, which Ruby's `String#[]` resolves to `data[0..]` — the
 * WHOLE string, not the empty one the compiled script produces. More broadly,
 * `left`/`right` in several native runtimes and SDK ANF interpreters return a
 * truncated or clamped value for an out-of-range split instead of the abort
 * `OP_SPLIT` actually produces.
 *
 * This file pins what the COMPILED SCRIPT returns, on `@bsv/sdk`
 * `Spend.validate`, for every vector in
 * `packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json`. Every
 * tier's own F-274 vector test replays the same file against its native
 * runtime and/or SDK ANF interpreter.
 *
 * How a value is pinned: a probe method `assert(f(data, n) === e)` must
 * ACCEPT with `e = expect` and REJECT with `e` = a flipped witness (a script
 * that accepts every witness cannot pass). An `abort` case must reject BOTH
 * `assert(f(data, n) === e)` and `assert(f(data, n) !== e)`: no witness
 * satisfies either, because the script failed before the comparison ran.
 *
 * What this proves: for every vector, the compiled `left`/`right` script
 * accepts exactly the pinned value (or aborts) on a real consensus-shaped
 * interpreter. What it does not prove: anything about a native runtime or
 * ANF interpreter by itself — each tier's own F-274 vector test replays this
 * file against its own code.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ScriptExecutionContract } from '../script-execution.js';

const REPO = resolve(__dirname, '../../../..');

interface SplitCase {
  fn: 'left' | 'right';
  data: string;
  n: number;
  expect: string | 'abort';
}

function readVectors(): { cases: SplitCase[] } {
  const text = readFileSync(
    resolve(REPO, 'packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json'),
    'utf8',
  );
  return JSON.parse(text) as { cases: SplitCase[] };
}

/** A witness that must NOT equal the real result: flip the last hex byte, or
 * use a non-empty value when the real result is empty. */
function wrongWitness(expect: string): string {
  if (expect === '') return '00';
  const lastByte = expect.slice(-2);
  const flipped = (parseInt(lastByte, 16) ^ 0xff).toString(16).padStart(2, '0');
  return expect.slice(0, -2) + flipped;
}

function probeSource(): string {
  return [
    `import { SmartContract, assert, left, right } from 'runar-lang';`,
    `class F274SplitProbe extends SmartContract {`,
    `  constructor() { super(); }`,
    `  public eq_left(a0: ByteString, a1: bigint, e: ByteString) { assert(left(a0, a1) === e); }`,
    `  public ne_left(a0: ByteString, a1: bigint, e: ByteString) { assert(left(a0, a1) !== e); }`,
    `  public eq_right(a0: ByteString, a1: bigint, e: ByteString) { assert(right(a0, a1) === e); }`,
    `  public ne_right(a0: ByteString, a1: bigint, e: ByteString) { assert(right(a0, a1) !== e); }`,
    `}`,
  ].join('\n');
}

describe('F-274: left/right builtins — compiled script verdict on Spend.validate', () => {
  const { cases } = readVectors();
  const probe = ScriptExecutionContract.fromSource(probeSource(), {}, 'F274SplitProbe.runar.ts');

  it('covers n=0, n=len, n>len, n<0, and an empty input for both builtins', () => {
    const key = (c: SplitCase) => `${c.fn}:${c.data === '' ? 'empty' : c.data.length / 2}:${c.n}`;
    const keys = new Set(cases.map(key));
    for (const fn of ['left', 'right'] as const) {
      expect(keys.has(`${fn}:4:0`), `${fn} n=0`).toBe(true);
      expect(keys.has(`${fn}:4:4`), `${fn} n=len`).toBe(true);
      expect(keys.has(`${fn}:4:5`), `${fn} n>len`).toBe(true);
      expect(keys.has(`${fn}:4:-1`), `${fn} n<0`).toBe(true);
      expect(keys.has(`${fn}:empty:0`), `${fn} empty input, n=0`).toBe(true);
      expect(keys.has(`${fn}:empty:1`), `${fn} empty input, n>len`).toBe(true);
    }
  });

  for (const c of cases) {
    const label = `${c.fn}(${JSON.stringify(c.data)}, ${c.n}) -> ${JSON.stringify(c.expect)}`;
    it(label, () => {
      const n = BigInt(c.n);
      if (c.expect === 'abort') {
        const eq = probe.execute(`eq_${c.fn}`, [c.data, n, c.data]);
        const ne = probe.execute(`ne_${c.fn}`, [c.data, n, c.data]);
        expect(eq.success, `${label}: f(args) === anything must not verify`).toBe(false);
        expect(ne.success, `${label}: f(args) !== anything must not verify`).toBe(false);
        return;
      }
      const ok = probe.execute(`eq_${c.fn}`, [c.data, n, c.expect]);
      expect(ok.success, ok.error).toBe(true);
      const wrong = wrongWitness(c.expect);
      expect(probe.execute(`eq_${c.fn}`, [c.data, n, wrong]).success, label).toBe(false);
      expect(probe.execute(`ne_${c.fn}`, [c.data, n, c.expect]).success, label).toBe(false);
    });
  }
});
