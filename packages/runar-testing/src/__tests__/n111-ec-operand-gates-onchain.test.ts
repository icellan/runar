/**
 * N-111 — the on-chain half of the secp256k1 EC operand-gate check.
 *
 * The compiled EC builtins gate their Point operands (ec-codegen.ts):
 *   - ecAdd / ecNegate: 64-byte width (CL-BUG-095) and canonical coordinates,
 *     x < p and y < p (R-117). Off-curve operands and the all-zero identity O
 *     are accepted (R-053).
 *   - ecMul: on the curve OR O (R-157), which subsumes width and canonicity.
 *   - ecPointX / ecPointY / ecEncodeCompressed: width only.
 * The off-chain implementations (the TestContract interpreter, the native
 * runtimes) did not mirror these gates: `ecMul((5,7), 1n)` returned (5,7)
 * off-chain and aborts on-chain.
 *
 * This file pins what the COMPILED SCRIPT does, on `@bsv/sdk`
 * `Spend.validate` through ScriptExecutionContract, for every row of
 * `packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json`. Each
 * off-chain implementation replays the same file in its own N-111 test.
 *
 * How a row is pinned: `assert(f(args) === e)` must ACCEPT at `e = expect` and
 * REJECT at a different witness, and `assert(f(args) !== e)` must REJECT at
 * `expect`. An `abort` row must reject BOTH probes at the same witness: no
 * witness satisfies either, because the script failed before the comparison.
 *
 * Proves: every row's verdict on a consensus-shaped interpreter — including
 * N-110's (5, 0) + (5, 0) row: the compiled adder ABORTS when it doubles a
 * y = 0 point other than O (it used to return (p - 10, 0)), while G + G, O + O
 * and the chord rows still verify.
 * Does not prove: anything about an off-chain implementation by itself, or
 * inputs outside the file; P-256 / P-384 analogues are out of scope.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ScriptExecutionContract } from '../script-execution.js';

const REPO = resolve(__dirname, '../../../..');

interface GateRow {
  fn: 'ecAdd' | 'ecMul' | 'ecMulGen' | 'ecNegate' | 'ecPointX' | 'ecPointY' | 'ecEncodeCompressed' | 'ecOnCurve';
  p?: string;
  q?: string;
  k?: string;
  expect: string;
  why: string;
}

function readRows(): GateRow[] {
  const text = readFileSync(
    resolve(REPO, 'packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json'),
    'utf8',
  );
  return (JSON.parse(text) as { cases: GateRow[] }).cases;
}

const G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

const INT_FNS = new Set(['ecPointX', 'ecPointY']);
const BOOL_FNS = new Set(['ecOnCurve']);

/** The witness that equals the real result (or any witness, for an abort). */
function witness(r: GateRow): string | bigint | boolean {
  if (r.expect !== 'abort') {
    if (INT_FNS.has(r.fn)) return BigInt(r.expect);
    if (BOOL_FNS.has(r.fn)) return r.expect === 'true';
    return r.expect;
  }
  if (INT_FNS.has(r.fn)) return 0n;
  return r.fn === 'ecEncodeCompressed' ? '02' + G.slice(0, 64) : G;
}

/** A witness that must NOT equal the real result. */
function wrongWitness(r: GateRow): string | bigint | boolean {
  if (INT_FNS.has(r.fn)) return BigInt(r.expect) + 1n;
  if (BOOL_FNS.has(r.fn)) return r.expect !== 'true';
  const last = (parseInt(r.expect.slice(-2), 16) ^ 0xff).toString(16).padStart(2, '0');
  return r.expect.slice(0, -2) + last;
}

function args(r: GateRow, e: string | bigint | boolean): unknown[] {
  const out: unknown[] = [];
  if (r.p !== undefined) out.push(r.p);
  if (r.q !== undefined) out.push(r.q);
  if (r.k !== undefined) out.push(BigInt(r.k));
  out.push(e);
  return out;
}

const PROBES: Array<[string, string, string]> = [
  // [fn, params, call]
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

function probeSource(): string {
  const lines = [
    `import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecNegate, ecPointX, ecPointY, ecEncodeCompressed, ecOnCurve } from 'runar-lang';`,
    `import type { Point, ByteString } from 'runar-lang';`,
    `class N111EcGateProbe extends SmartContract {`,
    `  constructor() { super(); }`,
  ];
  for (const [fn, params, call] of PROBES) {
    lines.push(`  public eq_${fn}(${params}) { assert(${call} === e); }`);
    lines.push(`  public ne_${fn}(${params}) { assert(${call} !== e); }`);
  }
  lines.push('}');
  return lines.join('\n');
}

describe('N-111: secp256k1 EC operand gates — compiled script verdict on Spend.validate', () => {
  const rows = readRows();
  const probe = ScriptExecutionContract.fromSource(probeSource(), {}, 'N111EcGateProbe.runar.ts');

  it('covers valid, identity, off-curve, non-canonical and wrong-width operands', () => {
    const whys = rows.map((r) => r.why).join('\n');
    for (const needle of ['P+O = P', 'R-117: x + p alias', 'R-157: off-curve', 'R-157: O is exempt', 'width 63', 'width 65', 'y == p', '(p+1, 2)', 'N-110: off-curve doubling with y = 0 aborts']) {
      expect(whys).toContain(needle);
    }
    for (const [fn] of PROBES) expect(rows.some((r) => r.fn === fn), fn).toBe(true);
  });

  for (const r of rows) {
    const label = `${r.fn}(${[r.p, r.q, r.k].filter((v) => v !== undefined).map((v) => v!.length > 20 ? v!.slice(0, 8) + '…' + `[${v!.length / 2}B]` : v).join(', ')}) -> ${r.expect === 'abort' ? 'abort' : r.expect.slice(0, 16)} (${r.why})`;
    it(label, { timeout: 120_000 }, () => {
      if (r.expect === 'abort') {
        const w = witness(r);
        const eq = probe.execute(`eq_${r.fn}`, args(r, w));
        const ne = probe.execute(`ne_${r.fn}`, args(r, w));
        expect(eq.success, `${label}: f(args) === w must not verify`).toBe(false);
        expect(ne.success, `${label}: f(args) !== w must not verify`).toBe(false);
        return;
      }
      const ok = probe.execute(`eq_${r.fn}`, args(r, witness(r)));
      expect(ok.success, ok.error).toBe(true);
      expect(probe.execute(`eq_${r.fn}`, args(r, wrongWitness(r))).success, label).toBe(false);
      expect(probe.execute(`ne_${r.fn}`, args(r, witness(r))).success, label).toBe(false);
    });
  }
});
