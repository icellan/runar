/**
 * N-171 — the on-chain half of the `split`/`substr` builtin check. Sibling of
 * F-274 (`f274-split-builtins-onchain.test.ts`), which pinned the same shape
 * of bug for `left`/`right`.
 *
 * `split(data, index)` compiles to a bare `OP_SPLIT` (05-stack-lower.ts:
 * `BUILTIN_OPCODES.split`, with an `OP_NIP` appended in the same pass) and
 * binds the RIGHT half. `substr(data, start, length)` compiles to `<data>
 * <start> OP_SPLIT OP_NIP <length> OP_SPLIT OP_DROP` (`lowerSubstr`) — TWO
 * chained `OP_SPLIT`s, the second against the REMAINDER `size(data) -
 * start`. Both ABORT when the computed split position is outside `[0,
 * size(data)]`; several native runtimes and SDK ANF interpreters instead
 * clamp, wrap, or return nil/None/null (queued as N-171 by F-274's commit
 * message).
 *
 * This file pins what the COMPILED SCRIPT returns, on `@bsv/sdk`
 * `Spend.validate`, for every vector in
 * `packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json`.
 * Every tier's own N-171 vector test replays the same file against its
 * native runtime and/or SDK ANF interpreter.
 *
 * How a value is pinned: a probe method `assert(f(...) === e)` must ACCEPT
 * with `e = expect` and REJECT with `e` = a flipped witness (a script that
 * accepts every witness cannot pass). An `abort` case must reject BOTH
 * `assert(f(...) === e)` and `assert(f(...) !== e)`: no witness satisfies
 * either, because the script failed before the comparison ran.
 *
 * What this proves: for every vector, the compiled `split`/`substr` script
 * accepts exactly the pinned value (or aborts) on a real consensus-shaped
 * interpreter. What it does not prove: anything about a native runtime or
 * ANF interpreter by itself — each tier's own N-171 vector test replays this
 * file against its own code.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ScriptExecutionContract } from '../script-execution.js';

const REPO = resolve(__dirname, '../../../..');

interface SplitSubstrCase {
  fn: 'split' | 'substr';
  data: string;
  a: number;
  b: number;
  expect: string | 'abort';
}

function readVectors(): { cases: SplitSubstrCase[] } {
  const text = readFileSync(
    resolve(REPO, 'packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json'),
    'utf8',
  );
  return JSON.parse(text) as { cases: SplitSubstrCase[] };
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
    `import { SmartContract, assert, split, substr } from 'runar-lang';`,
    `class N171SplitSubstrProbe extends SmartContract {`,
    `  constructor() { super(); }`,
    `  public eq_split(a0: ByteString, a1: bigint, e: ByteString) { assert(split(a0, a1) === e); }`,
    `  public ne_split(a0: ByteString, a1: bigint, e: ByteString) { assert(split(a0, a1) !== e); }`,
    `  public eq_substr(a0: ByteString, a1: bigint, a2: bigint, e: ByteString) { assert(substr(a0, a1, a2) === e); }`,
    `  public ne_substr(a0: ByteString, a1: bigint, a2: bigint, e: ByteString) { assert(substr(a0, a1, a2) !== e); }`,
    `}`,
  ].join('\n');
}

describe('N-171: split/substr builtins — compiled script verdict on Spend.validate', () => {
  const { cases } = readVectors();
  const probe = ScriptExecutionContract.fromSource(probeSource(), {}, 'N171SplitSubstrProbe.runar.ts');

  it('covers n=0, interior, n=len, n>len, n<0, and an empty input for both builtins', () => {
    const splitKeys = new Set(
      cases.filter((c) => c.fn === 'split').map((c) => `${c.data === '' ? 'empty' : c.data.length / 2}:${c.a}`),
    );
    expect(splitKeys.has('4:0'), 'split n=0').toBe(true);
    expect(splitKeys.has('4:2'), 'split interior').toBe(true);
    expect(splitKeys.has('4:4'), 'split n=len').toBe(true);
    expect(splitKeys.has('4:5'), 'split n>len').toBe(true);
    expect(splitKeys.has('4:-1'), 'split n<0').toBe(true);
    expect(splitKeys.has('empty:0'), 'split empty, n=0').toBe(true);
    expect(splitKeys.has('empty:1'), 'split empty, n>len').toBe(true);

    const substrKeys = new Set(
      cases
        .filter((c) => c.fn === 'substr')
        .map((c) => `${c.data === '' ? 'empty' : c.data.length / 2}:${c.a}:${c.b}`),
    );
    expect(substrKeys.has('4:0:0'), 'substr start=0,len=0').toBe(true);
    expect(substrKeys.has('4:0:4'), 'substr whole').toBe(true);
    expect(substrKeys.has('4:4:0'), 'substr start=len,len=0').toBe(true);
    expect(substrKeys.has('4:2:2'), 'substr interior').toBe(true);
    expect(substrKeys.has('4:5:0'), 'substr start>len').toBe(true);
    expect(substrKeys.has('4:0:5'), 'substr start+len>len').toBe(true);
    expect(substrKeys.has('4:3:2'), 'substr start in range, start+len>len').toBe(true);
    expect(substrKeys.has('4:-1:1'), 'substr negative start').toBe(true);
    expect(substrKeys.has('4:0:-1'), 'substr negative length').toBe(true);
    expect(substrKeys.has('empty:0:0'), 'substr empty, start=0,len=0').toBe(true);
    expect(substrKeys.has('empty:0:1'), 'substr empty, start+len>len').toBe(true);
    expect(substrKeys.has('empty:1:0'), 'substr empty, start>len').toBe(true);
  });

  for (const c of cases) {
    const label = `${c.fn}(${JSON.stringify(c.data)}, ${c.a}${c.fn === 'substr' ? `, ${c.b}` : ''}) -> ${JSON.stringify(c.expect)}`;
    it(label, () => {
      const a0 = c.data;
      const a1 = BigInt(c.a);
      const args: (string | bigint)[] = c.fn === 'substr' ? [a0, a1, BigInt(c.b)] : [a0, a1];
      if (c.expect === 'abort') {
        const eq = probe.execute(`eq_${c.fn}`, [...args, c.data]);
        const ne = probe.execute(`ne_${c.fn}`, [...args, c.data]);
        expect(eq.success, `${label}: f(args) === anything must not verify`).toBe(false);
        expect(ne.success, `${label}: f(args) !== anything must not verify`).toBe(false);
        return;
      }
      const ok = probe.execute(`eq_${c.fn}`, [...args, c.expect]);
      expect(ok.success, ok.error).toBe(true);
      const wrong = wrongWitness(c.expect);
      expect(probe.execute(`eq_${c.fn}`, [...args, wrong]).success, label).toBe(false);
      expect(probe.execute(`ne_${c.fn}`, [...args, c.expect]).success, label).toBe(false);
    });
  }
});
