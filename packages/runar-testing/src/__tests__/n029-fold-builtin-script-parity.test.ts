/**
 * N-029 (CL-BUG-104) — the constant folder and the reference interpreter must
 * compute exactly what the COMPILED SCRIPT computes, for every foldable math
 * builtin.
 *
 * At HEAD three builtins disagreed with the script they compile to:
 *
 *   clamp(v, lo, hi)  the script is `<v> <lo> OP_MAX <hi> OP_MIN`, i.e.
 *                     min(max(v, lo), hi). The folder and the interpreter
 *                     computed `v < lo ? lo : (v > hi ? hi : v)`, which is a
 *                     different function once lo > hi: clamp(5, 10, 0) is 0
 *                     on-chain and folded to 10.
 *   log2(n)           the script unrolls 64 halvings, so it returns
 *                     min(floor(log2 n), 64). The folder returned the true
 *                     floor(log2 n): log2(2^70) is 64 on-chain, folded to 70.
 *   gcd(a, b)         the script unrolls 256 Euclid steps. Past 256 steps it
 *                     returns the partial remainder, not the gcd:
 *                     gcd(F300, F299) is 701408733 on-chain, folded to 1.
 *
 * So the default fold-ON compile and the fold-OFF compile of the same source
 * accepted MUTUALLY EXCLUSIVE witnesses. The fix makes the folder decline
 * wherever the script does not compute the mathematical answer (log2 beyond 64
 * halvings, gcd beyond 256 steps) and fold clamp as min(max(v, lo), hi); the
 * interpreter returns the script's value.
 *
 * How a value is pinned (same as F-033): a probe whose call has ALL-CONSTANT
 * arguments — so the fold-ON compile may fold it — must ACCEPT `=== expect`
 * and REJECT `=== expect + 1`, in BOTH fold modes, on `@bsv/sdk`
 * `Spend.validate`. An `abort` vector must reject both `=== 0` and `!== 0` in
 * both modes (the folder must leave it to the script). The fold-OFF script is
 * the oracle: the expectations are F-033's executed vectors plus edge cases
 * whose values the fold-OFF assertions below re-execute.
 *
 * Proves: for every F-033 vector and the edge cases below, the TS fold-ON
 * script, the TS fold-OFF script and the TS interpreter give the same verdict.
 * Does NOT prove: anything for the other six tiers by itself — their folders
 * are pinned by their own unit tests and by the fold-ON byte-parity fixture
 * conformance/subtype-parity/FoldBuiltinScriptParity.runar.ts. Nor does it
 * cover non-constant arguments (no folding happens there).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ScriptExecutionContract } from '../script-execution.js';
import { TestContract } from '../test-contract.js';

const REPO = resolve(__dirname, '../../../..');

type Expect = bigint | boolean | 'abort';
interface Case { fn: string; args: bigint[]; expect: Expect }

function readF033(): Case[] {
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
  }) as { cases: Case[] };
  return parsed.cases;
}

function fib(n: number): bigint {
  let a = 0n;
  let b = 1n;
  for (let i = 0; i < n; i++) [a, b] = [b, a + b];
  return a;
}

// Edge cases beyond F-033. Each expectation is re-executed on the fold-OFF
// script below, so a wrong number here fails the test rather than hiding.
const EDGE: Case[] = [
  // clamp with lo > hi: the script's OP_MIN runs last, so hi wins.
  { fn: 'clamp', args: [0n, 3n, -3n], expect: -3n },
  { fn: 'clamp', args: [-20n, 10n, 0n], expect: 0n },
  { fn: 'clamp', args: [7n, 7n, 7n], expect: 7n },
  // log2: exact up to 64 halvings (n < 2^65), saturates at 64 after.
  { fn: 'log2', args: [1n << 64n], expect: 64n },
  { fn: 'log2', args: [(1n << 65n) - 1n], expect: 64n },
  { fn: 'log2', args: [1n << 65n], expect: 64n },
  { fn: 'log2', args: [1n << 70n], expect: 64n },
  { fn: 'log2', args: [1n << 200n], expect: 64n },
  // gcd: consecutive Fibonacci numbers are Euclid's worst case.
  // gcd(F258, F257) needs exactly 256 steps (the unroll): exact.
  { fn: 'gcd', args: [fib(258), fib(257)], expect: 1n },
  // gcd(F259, F258) needs 257: the script stops one step short.
  { fn: 'gcd', args: [fib(259), fib(258)], expect: 2n },
  { fn: 'gcd', args: [fib(300), fib(299)], expect: 701408733n },
  // zero divisors and negatives the folder must decline / match.
  { fn: 'mulDiv', args: [0n, 5n, 0n], expect: 'abort' },
  { fn: 'divmod', args: [0n, 0n], expect: 'abort' },
  { fn: 'safemod', args: [-7n, 0n], expect: 'abort' },
  { fn: 'safediv', args: [-7n, 2n], expect: -3n },
  { fn: 'safemod', args: [-7n, 2n], expect: -1n },
  { fn: 'sign', args: [-(1n << 80n)], expect: -1n },
];

const BOOL_FNS = new Set(['within', 'bool']);

function lit(v: bigint): string {
  return v < 0n ? `(-${-v}n)` : `${v}n`;
}

function probeSource(c: Case): string {
  const call = `${c.fn}(${c.args.map(lit).join(', ')})`;
  const eType = BOOL_FNS.has(c.fn) ? 'boolean' : 'bigint';
  return [
    `import { SmartContract, assert, ${c.fn} } from 'runar-lang';`,
    `class N029Probe extends SmartContract {`,
    `  constructor() { super(); }`,
    `  public eq(e: ${eType}) { assert(${call} === e); }`,
    `  public ne(e: ${eType}) { assert(${call} !== e); }`,
    `}`,
  ].join('\n');
}

describe('N-029: fold-ON script, fold-OFF script and interpreter agree with the script', () => {
  const cases = [...readF033(), ...EDGE];

  for (const c of cases) {
    const label = `${c.fn}(${c.args.join(', ')}) -> ${String(c.expect)}`;
    it(label, () => {
      const src = probeSource(c);
      const isBool = BOOL_FNS.has(c.fn);
      const modes = [
        ['fold-OFF', true],
        ['fold-ON', false],
      ] as const;

      for (const [mode, disableConstantFolding] of modes) {
        const p = ScriptExecutionContract.fromSource(src, {}, 'N029Probe.runar.ts', {
          disableConstantFolding,
        });
        if (c.expect === 'abort') {
          const zero = isBool ? false : 0n;
          expect(p.execute('eq', [zero]).success, `${mode}: f === 0 must not verify`).toBe(false);
          expect(p.execute('ne', [zero]).success, `${mode}: f !== 0 must not verify`).toBe(false);
          continue;
        }
        const ok = p.execute('eq', [c.expect]);
        expect(ok.success, `${mode}: script must accept ${String(c.expect)} (${ok.error ?? ''})`).toBe(true);
        const wrong = isBool ? !(c.expect as boolean) : (c.expect as bigint) + 1n;
        expect(p.execute('eq', [wrong]).success, `${mode}: script must reject ${String(wrong)}`).toBe(false);
      }

      // The reference interpreter must return the script's value too.
      const tc = TestContract.fromSource(src, {}, 'N029Probe.runar.ts');
      if (c.expect === 'abort') {
        const zero = isBool ? false : 0n;
        expect(tc.call('eq', { e: zero }).success, 'interpreter: f === 0').toBe(false);
        expect(tc.call('ne', { e: zero }).success, 'interpreter: f !== 0').toBe(false);
        return;
      }
      const r = tc.call('eq', { e: c.expect });
      expect(r.success, `interpreter must accept ${String(c.expect)} (${r.error ?? ''})`).toBe(true);
    });
  }
});
