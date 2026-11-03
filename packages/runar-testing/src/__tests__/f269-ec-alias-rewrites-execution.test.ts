/**
 * F-269 — the rewrites alias resolution newly enables must agree, on the real
 * Spend engine, with the builtins they replace.
 *
 * F-269 (user decision R77) made the EC optimizer resolve operands through
 * `@ref:` aliases, so R1/R3/R7/R8/R8r now fire on aliased spellings they used
 * to leave alone. Each of those rewrites keeps its gate (N-104 / N-251), and
 * this file checks that the gate still sits where the replaced builtin's own
 * check was: for every probe, every input class gets the same answer from the
 * optimized script, the `disableEcOptimizer` script, and the fold-ON script.
 *
 * It also executes the two rebinding shapes that alias resolution must NOT see
 * through — `let a = p; const y = a; a = q; ecAdd(y, ecNegate(a))`, at top
 * level and inside an if arm — with p = 2G, q = G, where folding to O would be
 * a wrong answer (the right one is G).
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules (`newConsensusSpend`), minimal
 * pushes so MINIMALDATA cannot abort a row for the wrong reason.
 *
 * WHAT IT PROVES: for each aliased probe and each input class, the three
 * compile modes return the same value or all abort, and that answer is the
 * one pinned in the table (so they cannot agree by regressing together); a
 * wrong expected value is rejected, so "accepted" is not vacuous; the rewrite
 * still fires (the optimized script is a small fraction of the unoptimized
 * one); and the rebinding programs compute p - q, not O, in both fold modes.
 *
 * WHAT IT DOES NOT PROVE: that the other six tiers emit the same bytes. Their
 * byte parity with TS on these probes (via `--ir`) is pinned by
 * packages/runar-compiler/src/__tests__/f269-ec-alias-resolution.test.ts.
 */

import { describe, it, expect } from 'vitest';
import { compile, compileFromANF } from 'runar-compiler';
import type { ANFProgram, ANFBinding, ANFValue } from 'runar-compiler';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import { CONSENSUS_SPEND_CONTEXT, newConsensusSpend } from '../consensus-spend.js';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const h32 = (n: bigint) => n.toString(16).padStart(64, '0');

const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const G = h32(GX) + h32(GY);
const O = '00'.repeat(64);

const INPUTS: Record<string, string> = {
  G,
  O,
  offCurve: h32(5n) + h32(7n),       // canonical, off the curve, y != 0
  twoTorsion: h32(5n) + h32(0n),     // canonical, off the curve, y = 0
  zeroX: h32(0n) + h32(5n),          // x = 0, y != 0
  xGeP: h32(1n + P) + h32(2n),       // non-canonical x
  short63: G.slice(0, 126),          // 63 bytes
};

/** 'q' = returns the input point, 'O' = returns infinity, 'abort' = script fails. */
type Outcome = 'q' | 'O' | 'abort';

const NEG_CANCEL: Record<string, Outcome> = {
  G: 'O', O: 'O', offCurve: 'O', twoTorsion: 'abort', zeroX: 'O', xGeP: 'abort', short63: 'abort',
};
// ecAdd(q, O): ecAdd checks width and canonicity, not on-curve (R-157).
const ADD_IDENTITY: Record<string, Outcome> = {
  G: 'q', O: 'q', offCurve: 'q', twoTorsion: 'q', zeroX: 'q', xGeP: 'abort', short63: 'abort',
};
// ecMul(q, 1): ecMul requires on-curve or O (R-157).
const MUL_ONE: Record<string, Outcome> = {
  G: 'q', O: 'q', offCurve: 'abort', twoTorsion: 'abort', zeroX: 'abort', xGeP: 'abort', short63: 'abort',
};
// ecNegate(ecNegate(q)): ecNegate checks width and canonicity.
const NEG_NEG: Record<string, Outcome> = {
  G: 'q', O: 'q', offCurve: 'q', twoTorsion: 'q', zeroX: 'q', xGeP: 'abort', short63: 'abort',
};

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}
const ref = (x: string): ANFValue => ({ kind: 'load_const', value: `@ref:${x}` });
const call = (func: string, ...args: string[]): ANFValue => ({ kind: 'call', func, args });

/** `t = <body>` over q, then `assert(t === e)`. */
function probe(body: ANFBinding[]): ANFProgram {
  return {
    contractName: 'AliasRewrite',
    properties: [],
    methods: [
      {
        name: 'constructor',
        params: [],
        body: [b('c0', { kind: 'call', func: 'super', args: [] })],
        isPublic: false,
      },
      {
        name: 'check',
        params: [{ name: 'q', type: 'Point' }, { name: 'e', type: 'Point' }],
        body: [
          b('x', { kind: 'load_param', name: 'q' }),
          ...body,
          b('ev', { kind: 'load_param', name: 'e' }),
          b('eq', { kind: 'bin_op', op: '===', left: 't', right: 'ev', result_type: 'bytes' }),
          b('a', { kind: 'assert', value: 'eq' }),
        ],
        isPublic: true,
      },
    ],
  };
}

/** `shrink`: how many times smaller the optimized script must be (an elided ecNegate is small). */
const PROBES: { name: string; anf: ANFProgram; expected: Record<string, Outcome>; shrink: number }[] = [
  {
    name: 'R8 through an R1-produced alias',
    anf: probe([
      b('inf', { kind: 'load_const', value: O }),
      b('y', call('ecAdd', 'x', 'inf')),
      b('nx', call('ecNegate', 'x')),
      b('t', call('ecAdd', 'y', 'nx')),
    ]),
    expected: NEG_CANCEL,
    shrink: 3,
  },
  {
    name: 'R8r through a pass-04 alias',
    anf: probe([b('y', ref('x')), b('nx', call('ecNegate', 'x')), b('t', call('ecAdd', 'nx', 'y'))]),
    expected: NEG_CANCEL,
    shrink: 3,
  },
  {
    name: 'R1 with an aliased INFINITY',
    anf: probe([b('i0', { kind: 'load_const', value: O }), b('inf', ref('i0')), b('t', call('ecAdd', 'x', 'inf'))]),
    expected: ADD_IDENTITY,
    shrink: 3,
  },
  {
    name: 'R3 with an aliased scalar 1',
    anf: probe([b('c', { kind: 'load_const', value: 1n }), b('one', ref('c')), b('t', call('ecMul', 'x', 'one'))]),
    expected: MUL_ONE,
    shrink: 3,
  },
  {
    name: 'R7 through an aliased inner ecNegate',
    anf: probe([b('n1', call('ecNegate', 'x')), b('na', ref('n1')), b('t', call('ecNegate', 'na'))]),
    expected: NEG_NEG,
    shrink: 1,
  },
];

/** Minimal push of a blob under 76 bytes (every point here is 63 or 64). */
function push(hex: string): string {
  const len = hex.length / 2;
  if (len >= 0x4c) throw new Error('push helper only handles < 76 bytes');
  return len.toString(16).padStart(2, '0') + hex;
}

function accepts(scriptHex: string, unlockHex: string): boolean {
  const spend = newConsensusSpend({
    ...CONSENSUS_SPEND_CONTEXT,
    lockingScript: LockingScript.fromHex(scriptHex),
    otherInputs: [],
    outputs: [],
    unlockingScript: UnlockingScript.fromHex(unlockHex),
  });
  try {
    return spend.validate();
  } catch {
    return false;
  }
}

/** What the script returns for q, checked against the candidate answers. */
function outcome(scriptHex: string, q: string): Outcome {
  const ok = (e: string) => accepts(scriptHex, push(q) + push(e));
  if (ok(q)) {
    // q === O makes 'q' and 'O' the same answer; label it by the input.
    if (q !== G) expect(ok(G), 'accepts a wrong answer too').toBe(false);
    else expect(ok(O), 'accepts a wrong answer too').toBe(false);
    return q === O ? 'O' : 'q';
  }
  if (ok(O)) {
    expect(ok(G), 'accepts a wrong answer too').toBe(false);
    return 'O';
  }
  expect(ok(G)).toBe(false);
  return 'abort';
}

/** The pinned table, with 'q' for O normalised to 'O' (the same 64 zero bytes). */
function normalise(expected: Record<string, Outcome>): Record<string, Outcome> {
  const out: Record<string, Outcome> = {};
  for (const [k, v] of Object.entries(expected)) out[k] = k === 'O' && v === 'q' ? 'O' : v;
  return out;
}

describe('F-269: aliased EC rewrites agree with the builtins they replace', () => {
  for (const p of PROBES) {
    describe(p.name, () => {
      const modes = {
        optimized: compileFromANF(p.anf, { disableConstantFolding: true }).scriptHex as string,
        unoptimized: compileFromANF(p.anf, { disableConstantFolding: true, disableEcOptimizer: true }).scriptHex as string,
        'optimized, fold ON': compileFromANF(p.anf, {}).scriptHex as string,
      };
      for (const [mode, hex] of Object.entries(modes)) {
        it(`${mode}: every input class gets the pinned answer`, () => {
          const got: Record<string, Outcome> = {};
          for (const [name, q] of Object.entries(INPUTS)) got[name] = outcome(hex, q);
          expect(got).toEqual(normalise(p.expected));
        });
      }
      it('the rewrite fires: the optimized script is smaller than the unoptimized one', () => {
        expect(modes.optimized.length * p.shrink).toBeLessThan(modes.unoptimized.length);
      });
    });
  }
}, 600_000);

// ---------------------------------------------------------------------------
// Rebinding: the aliases resolution must leave opaque
// ---------------------------------------------------------------------------

function double(x: bigint, y: bigint): [bigint, bigint] {
  const mod = (a: bigint) => ((a % P) + P) % P;
  const inv = (a: bigint) => {
    let [r, nr, t, nt] = [P, mod(a), 0n, 1n];
    while (nr !== 0n) {
      const q = r / nr;
      [r, nr] = [nr, r - q * nr];
      [t, nt] = [nt, t - q * nt];
    }
    return mod(t);
  };
  const l = mod(3n * x * x * inv(2n * y));
  const x3 = mod(l * l - 2n * x);
  return [x3, mod(l * (x - x3) - y)];
}

const [G2X, G2Y] = double(GX, GY);
const G2 = h32(G2X) + h32(G2Y);

const TOP_LEVEL = `
class Reassign extends SmartContract {
  constructor() { super(); }
  public unlock(p: Point, q: Point, e: Point) {
    let a: Point = p;
    const y: Point = a;
    a = q;
    assert(ecAdd(y, ecNegate(a)) === e);
  }
}
`;

const IF_ARM = `
class IfReassign extends SmartContract {
  constructor() { super(); }
  public unlock(p: Point, q: Point, c: boolean, e: Point) {
    let a: Point = p;
    const y: Point = a;
    if (c) { a = q; }
    assert(ecAdd(y, ecNegate(a)) === e);
  }
}
`;

describe('F-269: an alias through a rebound local is not resolved (p - q, not O)', () => {
  for (const fold of [true, false]) {
    const label = fold ? 'fold ON' : 'fold OFF';
    it(`${label}: top-level rebinding computes 2G - G = G`, () => {
      const r = compile(TOP_LEVEL, { disableConstantFolding: !fold });
      expect(r.success).toBe(true);
      const hex = r.scriptHex as string;
      expect(accepts(hex, push(G2) + push(G) + push(G))).toBe(true);
      expect(accepts(hex, push(G2) + push(G) + push(O))).toBe(false);
    });
    it(`${label}: rebinding in an if arm computes 2G - G = G when taken, O when not`, () => {
      const r = compile(IF_ARM, { disableConstantFolding: !fold });
      expect(r.success).toBe(true);
      const hex = r.scriptHex as string;
      const T = '51';
      const F = '00';
      expect(accepts(hex, push(G2) + push(G) + T + push(G))).toBe(true);
      expect(accepts(hex, push(G2) + push(G) + T + push(O))).toBe(false);
      expect(accepts(hex, push(G2) + push(G) + F + push(O))).toBe(true);
      expect(accepts(hex, push(G2) + push(G) + F + push(G))).toBe(false);
    });
  }
}, 600_000);

// ---------------------------------------------------------------------------
// F-269 attempt 2: wrong-value shapes through a rebound local, from source
// ---------------------------------------------------------------------------
//
// An adversarial review of the first attempt found these miscompiles in all
// seven tiers: a rebound name compared equal to itself across positions, and
// an operand lifted out of an earlier binding (`const nx = ecNegate(a)`) was
// re-emitted where `a` already held its new value. Each row runs the optimized
// script (fold OFF and ON) and the `disableEcOptimizer` script on Spend and
// requires all three to accept the true value and reject the value the
// miscompile produced. The `--ir` rows replace the `const` alias with its
// target (N-352's raw-name form, which misfired before F-269 too).

type Pt = [bigint, bigint] | null;
const fmod = (a: bigint) => ((a % P) + P) % P;
function finv(a: bigint): bigint {
  let [r, nr, t, nt] = [P, fmod(a), 0n, 1n];
  while (nr !== 0n) {
    const qq = r / nr;
    [r, nr] = [nr, r - qq * nr];
    [t, nt] = [nt, t - qq * nt];
  }
  return fmod(t);
}
function ptAdd(a: Pt, b: Pt): Pt {
  if (a === null) return b;
  if (b === null) return a;
  if (a[0] === b[0] && fmod(a[1] + b[1]) === 0n) return null;
  const l = a[0] === b[0]
    ? fmod(3n * a[0] * a[0] * finv(2n * a[1]))
    : fmod((b[1] - a[1]) * finv(b[0] - a[0]));
  const x = fmod(l * l - a[0] - b[0]);
  return [x, fmod(l * (a[0] - x) - a[1])];
}
function ptMul(a: Pt, k: bigint): Pt {
  let r: Pt = null;
  let d = a;
  for (; k > 0n; k >>= 1n) {
    if (k & 1n) r = ptAdd(r, d);
    d = ptAdd(d, d);
  }
  return r;
}
const ptNeg = (a: Pt): Pt => (a === null ? null : [a[0], fmod(-a[1])]);
const ptHex = (a: Pt) => (a === null ? O : h32(a[0]) + h32(a[1]));
const GP: Pt = [GX, GY];

const rebindSrc = (name: string, body: string, params = 'p: Point, q: Point') => `
class ${name} extends SmartContract {
  constructor() { super(); }
  public unlock(${params}, e: Point) {
${body}
  }
}
`;

interface RebindRow {
  name: string;
  src: string;
  deAlias?: string[];
  /** unlocking pushes before `e`, as hex. */
  args: string;
  truth: Pt;
  wrong: Pt;
}

const TOP_R8 = '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    a = q;\n    assert(ecAdd(a, nx) === e);';
const TOP_R8R = '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    a = q;\n    assert(ecAdd(nx, a) === e);';
const TOP_R7 = '    let a: Point = p;\n    const n: Point = ecNegate(a);\n    a = q;\n    assert(ecNegate(n) === e);';
const TOP_R9 = '    let a: Point = p;\n    const m: Point = ecMul(a, 2n);\n    a = q;\n    assert(ecMul(m, 3n) === e);';
const TOP_R11 = '    let a: Point = p;\n    const l: Point = ecMul(a, 2n);\n    a = q;\n    const r: Point = ecMul(a, 3n);\n    assert(ecAdd(l, r) === e);';

const P2G = ptMul(GP, 2n);
const argsPQ = (p: Pt, q: Pt) => push(ptHex(p)) + push(ptHex(q));

const REBIND_ROWS: RebindRow[] = [
  // p = 2G, q = G: q - p = -G; the miscompile gave O.
  { name: 'R8 rebind via const nx', src: rebindSrc('R8Top', TOP_R8), args: argsPQ(P2G, GP), truth: ptNeg(GP), wrong: null },
  { name: 'R8r rebind via const nx', src: rebindSrc('R8rTop', TOP_R8R), args: argsPQ(P2G, GP), truth: ptNeg(GP), wrong: null },
  // -(-p) = p = 2G; the miscompile gave q = G.
  { name: 'R7 rebind via const n', src: rebindSrc('R7Top', TOP_R7), args: argsPQ(P2G, GP), truth: P2G, wrong: GP },
  // p = G, q = 2G: 3 * (2p) = 6G; the miscompile gave 6q = 12G.
  { name: 'R9 rebind via const m', src: rebindSrc('R9Top', TOP_R9), args: argsPQ(GP, P2G), truth: ptMul(GP, 6n), wrong: ptMul(GP, 12n) },
  // 2p + 3q = 2G + 6G = 8G; the miscompile gave 5q = 10G.
  { name: 'R11 rebind (same name, different values)', src: rebindSrc('R11Top', TOP_R11), args: argsPQ(GP, P2G), truth: ptMul(GP, 8n), wrong: ptMul(GP, 10n) },
  {
    name: 'R8 rebind in an if arm (taken)',
    src: rebindSrc('R8If', '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    if (c) { a = q; }\n    assert(ecAdd(a, nx) === e);', 'p: Point, q: Point, c: boolean'),
    args: argsPQ(P2G, GP) + '51', truth: ptNeg(GP), wrong: null,
  },
  {
    name: 'R8 rebind in a loop',
    src: rebindSrc('R8Loop', '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    for (let i = 0n; i < 1n; i++) { a = q; }\n    assert(ecAdd(a, nx) === e);'),
    args: argsPQ(P2G, GP), truth: ptNeg(GP), wrong: null,
  },
  {
    name: 'R8 two aliases of one rebound name (N-353)',
    src: rebindSrc('GoEqAlias', '    let t: Point = p;\n    const a: Point = t;\n    t = q;\n    const b: Point = t;\n    const nb: Point = ecNegate(b);\n    assert(ecAdd(a, nb) === e);'),
    args: argsPQ(P2G, GP), truth: GP, wrong: null,
  },
  { name: '--ir de-aliased R7 (N-352)', src: rebindSrc('R7Ir', TOP_R7), deAlias: ['n'], args: argsPQ(P2G, GP), truth: P2G, wrong: GP },
  { name: '--ir de-aliased R8 (N-352)', src: rebindSrc('R8Ir', TOP_R8), deAlias: ['nx'], args: argsPQ(P2G, GP), truth: ptNeg(GP), wrong: null },
  { name: '--ir de-aliased R8r (N-352)', src: rebindSrc('R8rIr', TOP_R8R), deAlias: ['nx'], args: argsPQ(P2G, GP), truth: ptNeg(GP), wrong: null },
  { name: '--ir de-aliased R9 (N-352)', src: rebindSrc('R9Ir', TOP_R9), deAlias: ['m'], args: argsPQ(GP, P2G), truth: ptMul(GP, 6n), wrong: ptMul(GP, 12n) },
  { name: '--ir de-aliased R11 (N-352)', src: rebindSrc('R11Ir', TOP_R11), deAlias: ['l', 'r'], args: argsPQ(GP, P2G), truth: ptMul(GP, 8n), wrong: ptMul(GP, 10n) },
];

/** Pass-04 ANF for `src` (no optimizer), with the named `const` aliases replaced by their targets in call args. */
function deAliasedAnf(src: string, names: string[]): ANFProgram {
  const r = compile(src, { disableConstantFolding: true, disableEcOptimizer: true });
  expect(r.success).toBe(true);
  const anf = structuredClone(r.anf!) as ANFProgram;
  const m = anf.methods.find((x) => x.name === 'unlock')!;
  for (const alias of names) {
    const v = m.body.find((x) => x.name === alias)!.value as { value: string };
    const target = v.value.slice(5);
    for (const x of m.body) if (x.value.kind === 'call') x.value.args = x.value.args.map((a) => (a === alias ? target : a));
    m.body = m.body.filter((x) => x.name !== alias);
  }
  return anf;
}

describe('F-269: no wrong value through a rebound local (optimizer vs builtins, on Spend)', () => {
  expect(ptHex(ptMul(GP, 2n))).toBe(G2);
  for (const row of REBIND_ROWS) {
    it(row.name, () => {
      const build = (opts: { disableEcOptimizer?: boolean; disableConstantFolding?: boolean }): string => {
        if (row.deAlias) return compileFromANF(deAliasedAnf(row.src, row.deAlias), opts).scriptHex as string;
        const r = compile(row.src, opts);
        expect(r.success).toBe(true);
        return r.scriptHex as string;
      };
      const modes = {
        'optimized, fold OFF': build({ disableConstantFolding: true }),
        'optimized, fold ON': build({}),
        unoptimized: build({ disableConstantFolding: true, disableEcOptimizer: true }),
      };
      for (const [mode, hex] of Object.entries(modes)) {
        expect(accepts(hex, row.args + push(ptHex(row.truth))), `${mode}: rejects the true value`).toBe(true);
        expect(accepts(hex, row.args + push(ptHex(row.wrong))), `${mode}: accepts the miscompiled value`).toBe(false);
      }
    });
  }
}, 900_000);
