import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { Tier, buildSourceTiers, compileHex, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-360 — a method parameter reassigned inside an `if` arm must be merged into
 * the `if`'s results like a local, in every tier, fold OFF and ON.
 *
 * `collectBranchMergedLocals` (and its six ports) counted only locals, so an
 * `if` whose arms both reassigned a parameter declared no results for it and a
 * read after the `if` resolved to the caller's argument. Counting parameters
 * as well collided with a public parameter that shares a property's name (the
 * merged-local slot and the property result are told apart by name), so — per
 * the R128 decision — a property-named public parameter that the method body
 * reassigns is bound under its collision-proof slot name (`<name>@local`, the
 * mechanism private helpers already use) and a write to any renamed parameter
 * rebinds that slot (it used to rebind the bare name, so a private helper's
 * renamed parameter silently ignored its own reassignment).
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules, minimal pushes.
 *
 * What this proves: for every stateless shape, every available tier's CLI,
 * fold OFF and ON, emits the TS reference bytes, and those bytes accept the
 * right answer and reject the stale-argument answer on the real interpreter,
 * for both branch directions — so all seven tiers agreeing on a wrong script
 * still fails. The stateful shapes are held to 7-tier byte parity, and the two
 * that compiled correctly before (Shadow, Out) to their pre-fix TS bytes; a
 * conditional that both emits an output and reassigns a parameter read after
 * it is refused by every tier with the shared clean diagnostic.
 * What it does NOT prove: execution of the stateful shapes (their spend needs a
 * real preimage; the property-named stateful shape's auto-state is executed
 * on-chain by `conformance/anf-interpreter/inputs/n360-shadow-param-rebind-{true,false}.json`),
 * nor any shape not listed below.
 */

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
type Pt = [bigint, bigint] | null;
const mod = (a: bigint) => ((a % P) + P) % P;
function inv(a: bigint): bigint {
  let [r, nr, t, nt] = [P, mod(a), 0n, 1n];
  while (nr !== 0n) {
    const q = r / nr;
    [r, nr] = [nr, r - q * nr];
    [t, nt] = [nt, t - q * nt];
  }
  return mod(t);
}
function add(A: Pt, B: Pt): Pt {
  if (A === null) return B;
  if (B === null) return A;
  let l: bigint;
  if (A[0] === B[0]) {
    if (mod(A[1] + B[1]) === 0n) return null;
    l = mod(3n * A[0] * A[0] * inv(2n * A[1]));
  } else {
    l = mod((B[1] - A[1]) * inv(B[0] - A[0]));
  }
  const x = mod(l * l - A[0] - B[0]);
  return [x, mod(l * (A[0] - x) - A[1])];
}
function mul(A: Pt, k: bigint): Pt {
  let R: Pt = null;
  let Q = A;
  for (k = ((k % N) + N) % N; k > 0n; k >>= 1n) {
    if (k & 1n) R = add(R, Q);
    Q = add(Q, Q);
  }
  return R;
}
const neg = (A: Pt): Pt => (A === null ? null : [A[0], mod(P - A[1])]);
const G: Pt = [GX, GY];
const G2 = mul(G, 2n);

const h32 = (n: bigint) => n.toString(16).padStart(64, '0');
const pushPoint = (A: Pt) => '40' + (A === null ? '00'.repeat(64) : h32(A[0]) + h32(A[1]));
/** Minimal push of a small non-negative script number. */
function pushNum(n: bigint): string {
  if (n === 0n) return '00';
  if (n <= 16n) return (0x50 + Number(n)).toString(16);
  if (n < 0x80n) return '01' + n.toString(16).padStart(2, '0');
  throw new Error('pushNum only handles 0..127');
}
const T = '51';
const F = '00';

const stateless = (name: string, members: string) =>
  `import { SmartContract, assert, ecNegate } from 'runar-lang';
import type { Point } from 'runar-lang';
class ${name} extends SmartContract {
${members}
}
`;

/** One unlocking case: args before `e`, the right `e`, the stale-argument `e`. */
interface Case { args: string; right: string; wrong: string }
const SHAPES: { name: string; src: string; cases: Case[] }[] = [
  {
    name: 'bigint param reassigned in both arms (bigint-if-both)',
    src: stateless('N360A', `  constructor() { super(); }
  public unlock(p: bigint, q: bigint, c: boolean, e: bigint) {
    if (c) { p = q; } else { p = p + 5n; }
    assert(p === e);
  }`),
    cases: [
      { args: pushNum(2n) + pushNum(3n) + T, right: pushNum(3n), wrong: pushNum(2n) },
      { args: pushNum(2n) + pushNum(3n) + F, right: pushNum(7n), wrong: pushNum(2n) },
    ],
  },
  {
    name: 'Point param reassigned in both arms (point-if-both)',
    src: stateless('N360B', `  constructor() { super(); }
  public unlock(p: Point, q: Point, c: boolean, e: Point) {
    if (c) { p = q; } else { p = ecNegate(p); }
    assert(p === e);
  }`),
    cases: [
      { args: pushPoint(G2) + pushPoint(G) + T, right: pushPoint(G), wrong: pushPoint(G2) },
      { args: pushPoint(G2) + pushPoint(G) + F, right: pushPoint(neg(G2)), wrong: pushPoint(G2) },
    ],
  },
  {
    name: 'private helper param reassigned in both arms (PrivIf)',
    src: stateless('N360C', `  constructor() { super(); }
  private f(a: bigint, b: bigint, c: boolean): bigint {
    const n: bigint = a * 10n;
    if (c) { a = b; } else { a = a + 5n; }
    return a + n;
  }
  public unlock(p: bigint, q: bigint, c: boolean, e: bigint) {
    assert(this.f(p, q, c) === e);
  }`),
    cases: [
      { args: pushNum(2n) + pushNum(3n) + T, right: pushNum(23n), wrong: pushNum(22n) },
      { args: pushNum(2n) + pushNum(3n) + F, right: pushNum(27n), wrong: pushNum(22n) },
    ],
  },
  {
    name: 'param reassigned in both arms inside a loop body, read after the loop',
    src: stateless('N360D', `  constructor() { super(); }
  public unlock(p: bigint, e: bigint) {
    for (let i = 0n; i < 3n; i++) {
      if (i == 1n) { p = p * 2n; } else { p = p + 1n; }
    }
    assert(p === e);
  }`),
    // 2 -> 3 -> 6 -> 7
    cases: [{ args: pushNum(2n), right: pushNum(7n), wrong: pushNum(2n) }],
  },
  {
    name: 'param reassigned in a loop body, read after the loop',
    src: stateless('N360E', `  constructor() { super(); }
  public unlock(p: bigint, e: bigint) {
    for (let i = 0n; i < 3n; i++) {
      p = p + i;
    }
    assert(p === e);
  }`),
    cases: [{ args: pushNum(2n), right: pushNum(5n), wrong: pushNum(2n) }],
  },
  {
    name: 'property-named public param reassigned in both arms, read after',
    src: stateless('N360F', `  readonly k: bigint = 7n;
  constructor() { super(); }
  public unlock(k: bigint, j: bigint, c: boolean, e: bigint) {
    if (c) { k = j + 1n; } else { k = k + 2n; }
    assert(k * 10n + this.k === e);
  }`),
    cases: [
      { args: pushNum(2n) + pushNum(3n) + T, right: pushNum(47n), wrong: pushNum(27n) },
      { args: pushNum(2n) + pushNum(3n) + F, right: pushNum(47n), wrong: pushNum(27n) },
    ],
  },
  {
    // The pre-existing private-param rename path: the write rebound the bare
    // name `k` while every read loaded the renamed slot `k@local`.
    name: 'property-named private helper param reassigned, read after',
    src: stateless('N360G', `  readonly k: bigint = 7n;
  constructor() { super(); }
  private f(k: bigint, j: bigint): bigint {
    k = k + j;
    return k * 10n + this.k;
  }
  public unlock(p: bigint, q: bigint, e: bigint) {
    assert(this.f(p, q) === e);
  }`),
    cases: [{ args: pushNum(2n) + pushNum(3n), right: pushNum(57n), wrong: pushNum(27n) }],
  },
];

const stateful = (name: string, method: string) =>
  `import { StatefulSmartContract, assert } from 'runar-lang';
class ${name} extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
${method}
}
`;

/**
 * Stateful shapes, held to 7-tier byte parity. `headSha` pins the TS bytes the
 * shape compiled to BEFORE this fix (both were correct then and must not move).
 */
const STATEFUL: { name: string; src: string; headSha?: { off: string; on: string } }[] = [
  {
    // A public param named like the property, written to the property in an
    // arm. Compiled correctly before; the naive isParam merge refused it.
    name: 'Shadow',
    src: stateful('Shadow', `  public m(count: bigint, c: boolean) {
    if (c) { count = count + 1n; this.count = count; } else { this.count = count; }
    assert(true);
  }`),
    headSha: { off: 'e0019cc299bfb325', on: 'e0019cc299bfb325' },
  },
  {
    name: 'Out',
    src: stateful('Out', `  public m(x: bigint, c: boolean) {
    if (c) { x = x + 1n; this.addOutput(1000n, x); } else { this.addOutput(1000n, x); }
  }`),
    headSha: { off: '58c5d9cbbeb07df2', on: '58c5d9cbbeb07df2' },
  },
  {
    name: 'property-named public param reassigned in both arms, read after (stateful)',
    src: stateful('ShadowBoth', `  public m(count: bigint, c: boolean) {
    if (c) { count = count + 1n; } else { count = count + 2n; }
    this.count = count * 10n + this.count;
  }`),
  },
];

/** Reassigns `x` in an arm that emits an output, then reads it after the `if`. */
const OUT2 = stateful('Out2', `  public m(x: bigint, c: boolean) {
    if (c) { x = x + 1n; this.addOutput(1000n, x); } else { this.addOutput(1000n, x); }
    assert(x > 0n);
  }`);

function accepts(lockingHex: string, unlockingHex: string): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false; // a thrown validation error is a failed spend
  }
}

const sha16 = (hex: string) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex').slice(0, 16);
const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TS_TIER = TIERS.find((t) => t.id === 'ts');
const MODES: { label: string; key: 'off' | 'on'; tier: (t: Tier) => Tier }[] = [
  { label: 'fold OFF', key: 'off', tier: foldOff },
  { label: 'fold ON', key: 'on', tier: (t) => t },
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n360-param-merge-'));
});
function write(name: string, src: string): string {
  const p = join(dir, name);
  writeFileSync(p, src);
  return p;
}

describe('N-360 parameter reassigned in an if arm is branch-merged — seven tiers, executed on @bsv/sdk', () => {
  it('the TS reference and at least one other tier are available (all seven in CI)', () => {
    expect(TS_TIER).toBeDefined();
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [i, s] of SHAPES.entries()) {
    for (const mode of MODES) {
      describe(`${s.name} (${mode.label})`, () => {
        let tsHex = '';
        beforeAll(() => {
          tsHex = compileHex(mode.tier(TS_TIER!), write(`S${i}.runar.ts`, s.src));
        }, 240_000);

        it('the TS reference accepts the right answer and rejects the stale-argument answer', () => {
          for (const c of s.cases) {
            expect(accepts(tsHex, c.args + c.right), `right answer rejected (${c.args})`).toBe(true);
            expect(accepts(tsHex, c.args + c.wrong), `stale answer accepted (${c.args})`).toBe(false);
          }
        });

        for (const tier of TIERS.filter((t) => t.id !== 'ts')) {
          it(`${tier.id} emits the TS reference bytes, which execute correctly`, () => {
            const hex = compileHex(mode.tier(tier), write(`S${i}.runar.ts`, s.src));
            for (const c of s.cases) {
              expect(accepts(hex, c.args + c.right), `right answer rejected (${c.args})`).toBe(true);
              expect(accepts(hex, c.args + c.wrong), `stale answer accepted (${c.args})`).toBe(false);
            }
            expect(hex).toBe(tsHex);
          }, 240_000);
        }
      });
    }
  }

  for (const [i, s] of STATEFUL.entries()) {
    for (const mode of MODES) {
      describe(`stateful: ${s.name} (${mode.label})`, () => {
        let tsHex = '';
        beforeAll(() => {
          tsHex = compileHex(mode.tier(TS_TIER!), write(`St${i}.runar.ts`, s.src));
        }, 240_000);
        if (s.headSha) {
          it('the TS reference still emits its pre-fix bytes', () => {
            expect(sha16(tsHex)).toBe(s.headSha![mode.key]);
          });
        }
        for (const tier of TIERS.filter((t) => t.id !== 'ts')) {
          it(`${tier.id} emits the TS reference bytes`, () => {
            expect(compileHex(mode.tier(tier), write(`St${i}.runar.ts`, s.src))).toBe(tsHex);
          }, 240_000);
        }
      });
    }
  }

  for (const mode of MODES) {
    describe(`an output arm that reassigns a param read after the if is refused cleanly (${mode.label})`, () => {
      for (const tier of TIERS) {
        it(`${tier.id} refuses with the shared diagnostic`, () => {
          const { verdict, diag } = judge(mode.tier(tier), write('Out2.runar.ts', OUT2));
          expect(verdict).toBe('rejected');
          expect(diag).toMatch(/declares outputs and reassigns local variables read after it \(x\)/);
          expect(diag).not.toMatch(/internal|depth mismatch/i);
        }, 240_000);
      }
    });
  }
});
