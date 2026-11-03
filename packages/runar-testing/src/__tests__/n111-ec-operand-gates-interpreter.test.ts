/**
 * N-111 — the TestContract interpreter must apply the compiled script's EC
 * operand gates, not just its arithmetic.
 *
 * Replays every row of
 * `packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json` (each
 * row executed on @bsv/sdk Spend.validate by n111-ec-operand-gates-onchain.test.ts)
 * through `TestContract`, using the same eq/ne probe. Before this fix the
 * interpreter returned a value where the script aborts — `ecMul((5,7), 1n)`
 * was (5,7), `ecAdd(P, P')` with P' the x + p alias of P was not a point,
 * `ecNegate((p+1, 2))` was a value — and `ecAdd(G, O)` took the chord path
 * where the script returns G.
 *
 * Proves: for every row, the interpreter's verdict equals the script's — the
 * on-chain value for an accepted row, a failed call (both probes) for an
 * abort row. Does not prove: inputs outside the file, or the script itself
 * (the oracle file pins that); P-256 / P-384 are out of scope.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TestContract } from '../test-contract.js';

const REPO = resolve(__dirname, '../../../..');

interface GateRow {
  fn: string;
  p?: string;
  q?: string;
  k?: string;
  expect: string;
  why: string;
}

const rows = (JSON.parse(readFileSync(
  resolve(REPO, 'packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json'),
  'utf8',
)) as { cases: GateRow[] }).cases;

const G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const INT_FNS = new Set(['ecPointX', 'ecPointY']);
const BOOL_FNS = new Set(['ecOnCurve']);

function witness(r: GateRow): string | bigint | boolean {
  if (r.expect !== 'abort') {
    if (INT_FNS.has(r.fn)) return BigInt(r.expect);
    if (BOOL_FNS.has(r.fn)) return r.expect === 'true';
    return r.expect;
  }
  if (INT_FNS.has(r.fn)) return 0n;
  return r.fn === 'ecEncodeCompressed' ? '02' + G.slice(0, 64) : G;
}

function wrongWitness(r: GateRow): string | bigint | boolean {
  if (INT_FNS.has(r.fn)) return BigInt(r.expect) + 1n;
  if (BOOL_FNS.has(r.fn)) return r.expect !== 'true';
  const last = (parseInt(r.expect.slice(-2), 16) ^ 0xff).toString(16).padStart(2, '0');
  return r.expect.slice(0, -2) + last;
}

function args(r: GateRow, e: string | bigint | boolean): Record<string, unknown> {
  const out: Record<string, unknown> = { e };
  if (r.p !== undefined) out.p = r.p;
  if (r.q !== undefined) out.q = r.q;
  if (r.k !== undefined) out.k = BigInt(r.k);
  return out;
}

const PROBES: Array<[string, string, string]> = [
  ['ecAdd', 'p: Point, q: Point, e: Point', 'ecAdd(p, q)'],
  ['ecMul', 'p: Point, k: bigint, e: Point', 'ecMul(p, k)'],
  ['ecMulGen', 'k: bigint, e: Point', 'ecMulGen(k)'],
  ['ecNegate', 'p: Point, e: Point', 'ecNegate(p)'],
  ['ecPointX', 'p: Point, e: bigint', 'ecPointX(p)'],
  ['ecPointY', 'p: Point, e: bigint', 'ecPointY(p)'],
  ['ecEncodeCompressed', 'p: Point, e: ByteString', 'ecEncodeCompressed(p)'],
  // N-184: ecOnCurve is boolean, so the eq/ne probe compares a boolean.
  ['ecOnCurve', 'p: Point, e: boolean', 'ecOnCurve(p)'],
];

const source = [
  `import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecNegate, ecPointX, ecPointY, ecEncodeCompressed, ecOnCurve } from 'runar-lang';`,
  `import type { Point, ByteString } from 'runar-lang';`,
  `class N111EcGateProbe extends SmartContract {`,
  `  constructor() { super(); }`,
  ...PROBES.flatMap(([fn, params, call]) => [
    `  public eq_${fn}(${params}) { assert(${call} === e); }`,
    `  public ne_${fn}(${params}) { assert(${call} !== e); }`,
  ]),
  `}`,
].join('\n');

describe('N-111: TestContract interpreter applies the on-chain EC operand gates', () => {
  for (const r of rows) {
    const label = `${r.fn} [${r.why}] -> ${r.expect === 'abort' ? 'abort' : 'value'}`;
    it(label, () => {
      const c = TestContract.fromSource(source, {}, 'N111EcGateProbe.runar.ts');
      if (r.expect === 'abort') {
        const w = witness(r);
        expect(c.call(`eq_${r.fn}`, args(r, w)).success, `${label}: eq must fail`).toBe(false);
        expect(c.call(`ne_${r.fn}`, args(r, w)).success, `${label}: ne must fail`).toBe(false);
        return;
      }
      const ok = c.call(`eq_${r.fn}`, args(r, witness(r)));
      expect(ok.success, ok.error).toBe(true);
      expect(c.call(`eq_${r.fn}`, args(r, wrongWitness(r))).success, label).toBe(false);
      expect(c.call(`ne_${r.fn}`, args(r, witness(r))).success, label).toBe(false);
    });
  }
});
