import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-356 — a reassigned method parameter must survive the EC optimizer's dead
 * code elimination, in every tier, fold OFF and ON.
 *
 * ANF lowering binds `p = q` (p a parameter) as a binding NAMED `p`, and every
 * later read of p stays `load_param p`; stack lowering resolves that by name to
 * the shallowest `p` slot, i.e. the rebinding. DCE's reference collector
 * treated `load_param` as referencing nothing, so the rebinding had no
 * readers and was deleted (taking its `load_param q` with it), and the later
 * read silently fell back to the caller's argument. DCE only runs inside the
 * EC optimizer: TS / Go / Rust after a rewrite fired, Python / Ruby / Zig /
 * Java whenever the method has an EC call. So `const n = ecNegate(p); p = q;
 * assert(ecAdd(p, n) === e)` with p = 2G, q = G accepted e = O instead of -G
 * in those four tiers, and the same program with a rewrite that fires
 * (`ecNegate(ecNegate(..))`) accepted O in all seven, TS included.
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules, minimal pushes.
 *
 * What this proves: for each shape, every available tier's CLI, fold OFF and
 * ON, emits the TS reference bytes, and those bytes accept the correct `e` and
 * reject the stale-parameter `e` on the real interpreter — so all seven tiers
 * agreeing on a wrong script still fails. The stateful public-method shape is
 * held to byte parity with TS (its spend needs a real preimage, so it is not
 * executed here); the stateless shapes cover its semantics.
 * What it does NOT prove: a parameter reassigned in BOTH arms of an if/else.
 * That is a separate branch-merge defect (`collectBranchMergedLocals` and its
 * six ports count only locals), wrong in all seven tiers with or without EC
 * calls, and deliberately not fixed here: the obvious fix turns a currently
 * correct compile (a parameter named like a property, written to it in an
 * arm) into a refusal. Nor a branch that both reassigns a parameter and emits
 * an output, or any shape not listed below.
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
const O: Pt = null;

const h32 = (n: bigint) => n.toString(16).padStart(64, '0');
const pushPoint = (A: Pt) => '40' + (A === null ? '00'.repeat(64) : h32(A[0]) + h32(A[1]));
/** Minimal push of a small non-negative script number. */
function pushNum(n: bigint): string {
  if (n === 0n) return '00';
  if (n <= 16n) return (0x50 + Number(n)).toString(16);
  if (n < 0x80n) return '01' + n.toString(16).padStart(2, '0');
  throw new Error('pushNum only handles 0..127');
}

const cls = (name: string, params: string, body: string, extra = '') =>
  `import { SmartContract, assert, ecAdd, ecNegate } from 'runar-lang';
import type { Point } from 'runar-lang';
class ${name} extends SmartContract {
  constructor() { super(); }
${extra}
  public unlock(${params}) {
${body}
  }
}
`;

/** Each shape: the unlocking args before `e`, the right `e`, and the stale-parameter `e`. */
const SHAPES: { name: string; src: string; args: string; right: string; wrong: string }[] = [
  {
    // The item's repro: wrong in python / ruby / zig / java.
    name: 'Point param rebind',
    src: cls('N356A', 'p: Point, q: Point, e: Point', `    const n: Point = ecNegate(p);
    p = q;
    assert(ecAdd(p, n) === e);`),
    args: pushPoint(G2) + pushPoint(G),
    right: pushPoint(neg(G)),
    wrong: pushPoint(O),
  },
  {
    // An EC rewrite (R7) fires, so TS / Go / Rust run DCE too: wrong in all seven.
    name: 'Point param rebind with a firing EC rewrite',
    src: cls('N356B', 'p: Point, q: Point, e: Point', `    const n: Point = ecNegate(p);
    p = q;
    assert(ecNegate(ecNegate(ecAdd(p, n))) === e);`),
    args: pushPoint(G2) + pushPoint(G),
    right: pushPoint(neg(G)),
    wrong: pushPoint(O),
  },
  {
    name: 'Point param rebind in a one-armed if',
    src: cls('N356C', 'p: Point, q: Point, c: boolean, e: Point', `    const n: Point = ecNegate(p);
    if (c) { p = q; }
    assert(ecAdd(p, n) === e);`),
    args: pushPoint(G2) + pushPoint(G) + '51',
    right: pushPoint(neg(G)),
    wrong: pushPoint(O),
  },
  {
    name: 'inlined private method rebinds its own Point param',
    src: cls('N356D', 'p: Point, q: Point, e: Point', `    assert(this.f(p, q) === e);`, `  private f(a: Point, b: Point): Point {
    const n: Point = ecNegate(a);
    a = b;
    return ecAdd(a, n);
  }`),
    args: pushPoint(G2) + pushPoint(G),
    right: pushPoint(neg(G)),
    wrong: pushPoint(O),
  },
  {
    // Control: a bigint rebind, read before and after, beside an EC call.
    name: 'bigint param rebind beside an EC call',
    src: cls('N356E', 'p: bigint, q: bigint, g: Point, e: bigint', `    const r1: bigint = p;
    p = q;
    assert(ecAdd(g, g) === ecAdd(g, g));
    assert(r1 * 10n + p === e);`),
    args: pushNum(2n) + pushNum(3n) + pushPoint(G),
    right: pushNum(23n),
    wrong: pushNum(22n),
  },
];

const STATEFUL = `import { StatefulSmartContract, assert, ecAdd, ecNegate } from 'runar-lang';
import type { Point } from 'runar-lang';
class N356St extends StatefulSmartContract {
  count: bigint;
  acc: Point;
  constructor(count: bigint, acc: Point) { super(count, acc); this.count = count; this.acc = acc; }
  public step(p: bigint, q: bigint, a: Point, b: Point) {
    const n: bigint = p * 10n;
    const na: Point = ecNegate(a);
    p = q;
    a = b;
    this.count = this.count + p + n;
    this.acc = ecAdd(a, na);
    assert(p > 0n);
  }
}
`;

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

const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TS_TIER = TIERS.find((t) => t.id === 'ts');
const MODES: { label: string; tier: (t: Tier) => Tier }[] = [
  { label: 'fold OFF', tier: foldOff },
  { label: 'fold ON', tier: (t) => t },
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n356-param-rebind-'));
});
function write(name: string, src: string): string {
  const p = join(dir, name);
  writeFileSync(p, src);
  return p;
}

describe('N-356 parameter rebind survives EC-optimizer DCE — seven tiers, executed on @bsv/sdk', () => {
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

        it('the TS reference accepts the right e and rejects the stale-parameter e', () => {
          expect(accepts(tsHex, s.args + s.right), 'right e rejected').toBe(true);
          expect(accepts(tsHex, s.args + s.wrong), 'stale-parameter e accepted').toBe(false);
        });

        for (const tier of TIERS.filter((t) => t.id !== 'ts')) {
          it(`${tier.id} emits the TS reference bytes, which execute correctly`, () => {
            const hex = compileHex(mode.tier(tier), write(`S${i}.runar.ts`, s.src));
            expect(accepts(hex, s.args + s.right), 'right e rejected').toBe(true);
            expect(accepts(hex, s.args + s.wrong), 'stale-parameter e accepted').toBe(false);
            expect(hex).toBe(tsHex);
          }, 240_000);
        }
      });
    }
  }

  for (const mode of MODES) {
    describe(`stateful public method rebinds bigint and Point params (${mode.label})`, () => {
      let tsHex = '';
      beforeAll(() => {
        tsHex = compileHex(mode.tier(TS_TIER!), write('St.runar.ts', STATEFUL));
      }, 240_000);
      for (const tier of TIERS.filter((t) => t.id !== 'ts')) {
        it(`${tier.id} emits the TS reference bytes`, () => {
          expect(compileHex(mode.tier(tier), write('St.runar.ts', STATEFUL))).toBe(tsHex);
        }, 240_000);
      }
    });
  }
});
