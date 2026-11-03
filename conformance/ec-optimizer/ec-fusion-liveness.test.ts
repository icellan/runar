import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { createECDH, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { ScriptVM } from 'runar-testing';
import { compile } from 'runar-compiler';
import {
  ALL_TIER_IDS,
  REPO,
  Tier,
  buildSourceTiers,
  compileHex,
  missingTierIds,
} from '../negatives/tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-460 — an EC fusing rule (R9, R10, R11) fires only when the fusion
 * removes a scalar multiplication, so the EC optimizer never makes a script
 * larger.
 *
 * A fusion adds ONE multiplication (the fused call) and shrinks the script
 * only if the N-113 post-pass then drops an inner call it read. After N-113
 * the rules still fired when no inner call could go: both inner calls read
 * again elsewhere (R10/R11: +~400 KB, R9: +2 bytes), an inner `ecMul` bound
 * outside the fusion's `if` arm (its only witness, the fused call, is nested:
 * +4 bytes for R9, +~400 KB for R11), or inner `ecMulGen`s bound outside a
 * loop the fusion sits in (one multiplication per iteration: +~350 KB). Each
 * rule now fires only when at least one inner operand is eliminable: its alias
 * chain is read by nothing but the rewritten binding, and it is an `ecMulGen`
 * bound in the fusion's scope or an enclosing one inside the same loop body,
 * or an `ecMul` bound in the fusion's own scope.
 *
 * What this proves: (1) in TS, each of those shapes compiles no larger with
 * the EC optimizer than without it, and three positive controls (one inner
 * call still live, or ecMulGen operands outside an `if` arm) still fuse and
 * shrink; (2) per method, which shapes fuse (scalar-multiplication and ecAdd
 * call counts of the optimized ANF), both fold modes; (3) all seven tiers
 * compile each of the three fixtures, fold-ON and fold-OFF, to the same pinned
 * bytes and to the TS reference's optimized ANF — so every tier makes the same
 * fire/skip decision; (4) the pinned scripts execute with the source's
 * semantics on @bsv/sdk (ScriptVM), expected points from OpenSSL's secp256k1.
 *
 * N-465: R9 readers that share one inner `ecMul` (each `ecMul(g, k)`, k a
 * constant other than 0 and 1, in g's own scope) no longer count each other:
 * they all fuse in one sweep and g goes. Two R9 readers of one `ecMul` are
 * back at 848,169 bytes and `g = ecMul(q, 7n); ecAdd(ecMul(g, 2n),
 * ecMul(g, 3n))` at 424,655 (SHARED_INNER, EcFusionLiveness4).
 *
 * What it does not prove: that the optimizer finds every saving. The guard
 * is local and conservative, and it gives up wins the unguarded rules had,
 * each now equal to the unoptimized size rather than below it: R10/R11
 * fusions that share an inner call each see the other as a reader, so
 * `ecAdd(a, b)` twice skips both (848,296 -> 897,530 bytes); R9 readers of
 * one inner through different aliases, or beside any other reader, still
 * count each other. An inner read through a second alias counts as read elsewhere, and an
 * `ecMulGen` outside a loop blocks the fusion even at two iterations, where
 * it would have shrunk. Nor stateful contracts or private methods.
 */

/**
 * Three fixtures, so each script stays under ScriptVM's 4 MB limit. `sha256`
 * is of the hex string every tier must emit, both fold modes.
 */
const FIXTURES = [
  { file: 'EcFusionLiveness1.runar.ts', sha256: 'b2e314e53a718e00325e9add08cfe46ea670f0c5878c385c445add7c5b8bf371', bytes: 2569268 },
  { file: 'EcFusionLiveness2.runar.ts', sha256: '03901e252c07f6e1d8d8f78d4ca8b2284f0b1039ada16b25b4956526de6587af', bytes: 2741959 },
  { file: 'EcFusionLiveness3.runar.ts', sha256: 'd4c81a4c814dbb799b9998f1d5ed413d3b6e197cd10dd568db851364be8d75fc', bytes: 3865980 },
  { file: 'EcFusionLiveness4.runar.ts', sha256: 'bde66f26a8d63942d54054ae5ef701e3000717016b4d5af0fac111c28f7be21a', bytes: 1272263 },
].map((f) => ({ ...f, path: join(__dirname, f.file) }));

type FoldMode = 'fold-on' | 'fold-off';
const FOLD_MODES: FoldMode[] = ['fold-on', 'fold-off'];

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

function withFold(tier: Tier, fold: FoldMode): Tier {
  if (fold === 'fold-on') return tier;
  return { ...tier, argsFor: (s) => [...tier.argsFor(s), '--disable-constant-folding'] };
}

// ---------------------------------------------------------------------------
// TS size check: each shape, optimizer on vs off
// ---------------------------------------------------------------------------

/** Shapes no fusion may grow (the fixtures' first eight methods, plus one). */
const NO_GROWTH: Record<string, string> = {
  'R9 inner read again':
    'const t: Point = ecMul(q, 2n); const r: Point = ecMul(t, 3n); assert(ecPointX(r) === ex && ecPointY(t) === ey);',
  'R9 inner outside the if arm':
    'const t: Point = ecMul(q, 2n); let r: Point = q; if (flag === 1n) { r = ecMul(t, 3n); } assert(ecPointX(r) === ex);',
  'R10 both inner read again':
    'const a: Point = ecMulGen(2n); const b: Point = ecMulGen(3n); const r: Point = ecAdd(a, b); assert(ecPointX(r) === ex && ecPointY(a) === ey2 && ecPointY(b) === ey3);',
  'R10 both inner read again, through an alias':
    'const a: Point = ecMulGen(2n); const b: Point = ecMulGen(3n); const a2: Point = a; const r: Point = ecAdd(a2, b); assert(ecPointX(r) === ex && ecPointY(a) === ey2 && ecPointY(b) === ey3);',
  'R10 in a loop, inner outside it':
    'const a: Point = ecMulGen(2n); const b: Point = ecMulGen(3n); let r: Point = q; for (let i = 0n; i < 3n; i++) { r = ecAdd(r, ecAdd(a, b)); } assert(ecPointX(r) === ex);',
  'R11 both inner read again':
    'const a: Point = ecMul(q, 2n); const b: Point = ecMul(q, 3n); const r: Point = ecAdd(a, b); assert(ecPointX(r) === ex && ecPointY(a) === ey2 && ecPointY(b) === ey3);',
  'R11 both inner outside the if arm':
    'const a: Point = ecMul(q, 2n); const b: Point = ecMul(q, 3n); let r: Point = q; if (flag === 1n) { r = ecAdd(a, b); } assert(ecPointX(r) === ex);',
  'R11 a outside the arm, b inside and read again':
    'const a: Point = ecMul(q, 2n); let r: Point = q; if (flag === 1n) { const b: Point = ecMul(q, 3n); r = ecAdd(a, b); assert(ecPointY(b) === ey); } assert(ecPointX(r) === ex);',
  'R10 the same sum twice':
    'const a: Point = ecMulGen(2n); const b: Point = ecMulGen(3n); const r: Point = ecAdd(a, b); const s: Point = ecAdd(a, b); assert(ecPointX(r) === ex && ecPointY(s) === ey);',
};

/** Positive controls: these must still fuse, and shrink (the fixtures' last three methods). */
const MUST_SHRINK: Record<string, string> = {
  'R10 a read again':
    'const a: Point = ecMulGen(2n); const b: Point = ecMulGen(3n); const r: Point = ecAdd(a, b); assert(ecPointX(r) === ex && ecPointY(a) === ey);',
  'R11 a read again':
    'const a: Point = ecMul(q, 2n); const b: Point = ecMul(q, 3n); const r: Point = ecAdd(a, b); assert(ecPointX(r) === ex && ecPointY(a) === ey);',
  'R10 in an if arm, ecMulGen outside it':
    'const a: Point = ecMulGen(2n); const b: Point = ecMulGen(3n); let r: Point = q; if (flag === 1n) { r = ecAdd(a, b); } assert(ecPointX(r) === ex);',
};

/**
 * N-465: R9 readers sharing one inner `ecMul`, at the sizes they had before
 * N-460's guard (which counted each reader as keeping the inner alive). The
 * shapes and source are N-460's measurements (`sharedInnerSource`), so the
 * byte counts are the pre-N-460 ones exactly; with the optimizer off they are
 * 1,296,934 and 1,272,003.
 */
const SHARED_INNER: Record<string, { body: string; bytes: number }> = {
  'R9 twice on one inner, then R11 (the n112 shape)': {
    body: 'const g: Point = ecMul(q, 7n); assert(ecOnCurve(ecAdd(ecMul(g, 2n), ecMul(g, 3n))));',
    bytes: 424655,
  },
  'R9 twice on one inner, both read': {
    body: 'const g: Point = ecMul(q, 7n); const r: Point = ecMul(g, 2n); const s: Point = ecMul(g, 3n); assert(ecPointX(r) === ex && ecPointX(s) === ey);',
    bytes: 848169,
  },
};

function sharedInnerSource(body: string): string {
  return `import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecNegate, ecPointX, ecPointY, ecOnCurve } from 'runar-lang';
import type { Point } from 'runar-lang';
export class S extends SmartContract {
  constructor() { super(); }
  public m(p: Point, k: bigint, ex: bigint, ey: bigint) {
    const q: Point = p;
    ${body}
  }
}
`;
}

function shapeSource(body: string): string {
  return `import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';
export class S extends SmartContract {
  constructor() { super(); }
  public m(p: Point, flag: bigint, ex: bigint, ey: bigint, ey2: bigint, ey3: bigint) {
    const q: Point = p;
    ${body}
  }
}
`;
}

function tsBytes(source: string, disableEcOptimizer: boolean): number {
  const r = compile(source, { fileName: 'S.runar.ts', disableEcOptimizer });
  if (!r.scriptHex) throw new Error(`TS produced no script: ${JSON.stringify(r.diagnostics)}`);
  return r.scriptHex.length / 2;
}

// ---------------------------------------------------------------------------
// ANF comparison (same normalisation as ec-fusion-dce.test.ts)
// ---------------------------------------------------------------------------

function normalise(value: unknown): unknown {
  if (typeof value === 'bigint') return { $int: value.toString() };
  if (typeof value === 'number' && Number.isInteger(value)) return { $int: String(value) };
  if (typeof value === 'string' && /^-?\d+n$/.test(value)) return { $int: value.slice(0, -1) };
  if (Array.isArray(value)) return value.map(normalise);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      if (k === 'sourceLoc') continue;
      const v = (value as Record<string, unknown>)[k];
      if (v === undefined) continue;
      out[k] = normalise(v);
    }
    return out;
  }
  return value;
}

function tsAnf(fx: number, fold: FoldMode): unknown {
  const r = compile(readFileSync(FIXTURES[fx]!.path, 'utf8'), {
    fileName: FIXTURES[fx]!.file,
    disableConstantFolding: fold === 'fold-off',
  });
  if (!r.anf) throw new Error(`TS produced no ANF: ${JSON.stringify(r.diagnostics)}`);
  return normalise(r.anf);
}

function nativeAnf(tier: Tier, fx: number, fold: FoldMode): unknown {
  const args = [...tier.prefix, '--source', FIXTURES[fx]!.path, '--emit-ir'];
  if (fold === 'fold-off') args.push('--disable-constant-folding');
  const res = spawnSync(tier.cmd!, args, {
    cwd: tier.cwd, encoding: 'utf-8', timeout: tier.timeoutMs, maxBuffer: 64 * 1024 * 1024,
  });
  if (res.status !== 0) {
    throw new Error(`${tier.id} --emit-ir exited ${res.status}: ${(res.stderr ?? '').slice(0, 600)}`);
  }
  return normalise(JSON.parse(res.stdout));
}

/** Scalar multiplications and ecAdds per public method of the optimized ANF. */
function ecCalls(anf: unknown): Record<string, { mul: number; add: number }> {
  const out: Record<string, { mul: number; add: number }> = {};
  const methods = (anf as { methods: Array<{ name: string; body: unknown }> }).methods;
  for (const m of methods) {
    const n = { mul: 0, add: 0 };
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) { node.forEach(walk); return; }
      if (node === null || typeof node !== 'object') return;
      const o = node as Record<string, unknown>;
      if (o.kind === 'call' && (o.func === 'ecMul' || o.func === 'ecMulGen')) n.mul++;
      if (o.kind === 'call' && o.func === 'ecAdd') n.add++;
      Object.values(o).forEach(walk);
    };
    walk(m.body);
    if (m.name !== 'constructor') out[m.name] = n;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Unlocking scripts
// ---------------------------------------------------------------------------

function pushBytes(bytes: number[]): number[] {
  if (bytes.length === 0) return [0x00];
  if (bytes.length <= 75) return [bytes.length, ...bytes];
  return [0x4c, bytes.length, ...bytes];
}

/** Minimal script-number push of `n`. */
function pushInt(n: bigint): number[] {
  if (n === 0n) return [0x00];
  if (n === -1n) return [0x4f];
  if (n >= 1n && n <= 16n) return [0x50 + Number(n)];
  const neg = n < 0n;
  let a = neg ? -n : n;
  const bytes: number[] = [];
  while (a > 0n) {
    bytes.push(Number(a & 0xffn));
    a >>= 8n;
  }
  if (bytes[bytes.length - 1]! & 0x80) bytes.push(neg ? 0x80 : 0x00);
  else if (neg) bytes[bytes.length - 1]! |= 0x80;
  return pushBytes(bytes);
}

function be32(n: bigint): number[] {
  const out: number[] = [];
  for (let i = 31; i >= 0; i--) out.push(Number((n >> BigInt(8 * i)) & 0xffn));
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** k*G from OpenSSL's secp256k1 (independent of the compiler). */
function mulG(k: bigint): { x: bigint; y: bigint } {
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(k.toString(16).padStart(64, '0'), 'hex'));
  const pub = ecdh.getPublicKey(undefined, 'uncompressed');
  return {
    x: BigInt('0x' + pub.subarray(1, 33).toString('hex')),
    y: BigInt('0x' + pub.subarray(33, 65).toString('hex')),
  };
}

const G = mulG(1n);
const G_POINT = [...be32(G.x), ...be32(G.y)];
/** (1, 1): 64 bytes, canonical coordinates, NOT on the curve. */
const OFF_CURVE = [...be32(1n), ...be32(1n)];

type Arg = { int: bigint } | { bytes: number[] };

/** Public methods: [fixture, index in declaration order]. */
const M = {
  r9InnerLive: [0, 0], r9OuterNested: [0, 1], r10BothLive: [0, 2],
  r10BothLiveAlias: [1, 0], r10OuterLoop: [1, 1], r11BothLive: [1, 2],
  r11OuterBothNested: [2, 0], r11OuterANestedBLive: [2, 1],
  r10LeftLive: [2, 2], r11LeftLive: [2, 3], r10OuterNested: [2, 4],
  r9SharedThenR11: [3, 0], r9SharedTwoReaders: [3, 1],
} as const;

function unlock(method: readonly [number, number], args: Arg[]): { fx: number; bytes: Uint8Array } {
  const out: number[] = [];
  for (const a of args) out.push(...('int' in a ? pushInt(a.int) : pushBytes(a.bytes)));
  out.push(...pushInt(BigInt(method[1])));
  return { fx: method[0], bytes: new Uint8Array(out) };
}

const i = (n: bigint): Arg => ({ int: n });
const bs = (b: number[]): Arg => ({ bytes: b });

const P2 = mulG(2n);
const P3 = mulG(3n);
const P5 = mulG(5n);
const P6 = mulG(6n);
const P16 = mulG(16n);
const P14 = mulG(14n);
const P21 = mulG(21n);
const P35 = mulG(35n);

const SPENDS: Array<{ what: string; unlock: { fx: number; bytes: Uint8Array }; ok: boolean }> = [
  { what: 'r9InnerLive q = G -> 6G, t = 2G', unlock: unlock(M.r9InnerLive, [bs(G_POINT), i(P6.x), i(P2.y)]), ok: true },
  { what: 'r9InnerLive wrong y(t)', unlock: unlock(M.r9InnerLive, [bs(G_POINT), i(P6.x), i(P3.y)]), ok: false },
  { what: 'r9InnerLive off-curve q', unlock: unlock(M.r9InnerLive, [bs(OFF_CURVE), i(P6.x), i(P2.y)]), ok: false },
  { what: 'r9OuterNested then -> 6G', unlock: unlock(M.r9OuterNested, [bs(G_POINT), i(1n), i(P6.x)]), ok: true },
  { what: 'r9OuterNested skip -> q', unlock: unlock(M.r9OuterNested, [bs(G_POINT), i(0n), i(G.x)]), ok: true },
  { what: 'r9OuterNested then, wrong x', unlock: unlock(M.r9OuterNested, [bs(G_POINT), i(1n), i(P5.x)]), ok: false },
  { what: 'r9OuterNested skip, off-curve q', unlock: unlock(M.r9OuterNested, [bs(OFF_CURVE), i(0n), i(1n)]), ok: false },
  { what: 'r10BothLive -> 5G', unlock: unlock(M.r10BothLive, [i(P5.x), i(P2.y), i(P3.y)]), ok: true },
  { what: 'r10BothLive wrong y(b)', unlock: unlock(M.r10BothLive, [i(P5.x), i(P2.y), i(P2.y)]), ok: false },
  { what: 'r10BothLiveAlias -> 5G', unlock: unlock(M.r10BothLiveAlias, [i(P5.x), i(P2.y), i(P3.y)]), ok: true },
  { what: 'r10BothLiveAlias wrong x', unlock: unlock(M.r10BothLiveAlias, [i(P6.x), i(P2.y), i(P3.y)]), ok: false },
  { what: 'r10OuterLoop q = G -> 16G', unlock: unlock(M.r10OuterLoop, [bs(G_POINT), i(P16.x)]), ok: true },
  { what: 'r10OuterLoop wrong x (6G)', unlock: unlock(M.r10OuterLoop, [bs(G_POINT), i(P6.x)]), ok: false },
  { what: 'r11BothLive q = G -> 5G', unlock: unlock(M.r11BothLive, [bs(G_POINT), i(P5.x), i(P2.y), i(P3.y)]), ok: true },
  { what: 'r11BothLive wrong y(a)', unlock: unlock(M.r11BothLive, [bs(G_POINT), i(P5.x), i(P3.y), i(P3.y)]), ok: false },
  { what: 'r11BothLive off-curve q', unlock: unlock(M.r11BothLive, [bs(OFF_CURVE), i(P5.x), i(P2.y), i(P3.y)]), ok: false },
  { what: 'r11OuterBothNested then -> 5G', unlock: unlock(M.r11OuterBothNested, [bs(G_POINT), i(1n), i(P5.x)]), ok: true },
  { what: 'r11OuterBothNested skip -> q', unlock: unlock(M.r11OuterBothNested, [bs(G_POINT), i(0n), i(G.x)]), ok: true },
  { what: 'r11OuterBothNested skip, off-curve q', unlock: unlock(M.r11OuterBothNested, [bs(OFF_CURVE), i(0n), i(1n)]), ok: false },
  { what: 'r11OuterANestedBLive then -> 5G', unlock: unlock(M.r11OuterANestedBLive, [bs(G_POINT), i(1n), i(P5.x), i(P3.y)]), ok: true },
  { what: 'r11OuterANestedBLive then, wrong y(b)', unlock: unlock(M.r11OuterANestedBLive, [bs(G_POINT), i(1n), i(P5.x), i(P2.y)]), ok: false },
  { what: 'r11OuterANestedBLive skip -> q', unlock: unlock(M.r11OuterANestedBLive, [bs(G_POINT), i(0n), i(G.x), i(0n)]), ok: true },
  { what: 'r10LeftLive -> 5G', unlock: unlock(M.r10LeftLive, [i(P5.x), i(P2.y)]), ok: true },
  { what: 'r10LeftLive wrong y(a)', unlock: unlock(M.r10LeftLive, [i(P5.x), i(P3.y)]), ok: false },
  { what: 'r11LeftLive q = G -> 5G', unlock: unlock(M.r11LeftLive, [bs(G_POINT), i(P5.x), i(P2.y)]), ok: true },
  { what: 'r11LeftLive wrong x', unlock: unlock(M.r11LeftLive, [bs(G_POINT), i(P6.x), i(P2.y)]), ok: false },
  { what: 'r11LeftLive off-curve q', unlock: unlock(M.r11LeftLive, [bs(OFF_CURVE), i(P5.x), i(P2.y)]), ok: false },
  { what: 'r10OuterNested then -> 5G', unlock: unlock(M.r10OuterNested, [bs(G_POINT), i(1n), i(P5.x)]), ok: true },
  { what: 'r10OuterNested skip -> q', unlock: unlock(M.r10OuterNested, [bs(G_POINT), i(0n), i(G.x)]), ok: true },
  { what: 'r10OuterNested then, wrong x', unlock: unlock(M.r10OuterNested, [bs(G_POINT), i(1n), i(G.x)]), ok: false },
  { what: 'r9SharedThenR11 q = G -> 35G', unlock: unlock(M.r9SharedThenR11, [bs(G_POINT), i(P35.x)]), ok: true },
  { what: 'r9SharedThenR11 wrong x (14G)', unlock: unlock(M.r9SharedThenR11, [bs(G_POINT), i(P14.x)]), ok: false },
  { what: 'r9SharedThenR11 off-curve q', unlock: unlock(M.r9SharedThenR11, [bs(OFF_CURVE), i(P35.x)]), ok: false },
  { what: 'r9SharedTwoReaders q = G -> 14G, 21G', unlock: unlock(M.r9SharedTwoReaders, [bs(G_POINT), i(P14.x), i(P21.x)]), ok: true },
  { what: 'r9SharedTwoReaders swapped x', unlock: unlock(M.r9SharedTwoReaders, [bs(G_POINT), i(P21.x), i(P14.x)]), ok: false },
  { what: 'r9SharedTwoReaders off-curve q', unlock: unlock(M.r9SharedTwoReaders, [bs(OFF_CURVE), i(P14.x), i(P21.x)]), ok: false },
];

describe('N-460: an EC fusing rule fires only when it removes a multiplication, in all seven tiers', () => {
  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = missingTierIds(TIERS);
    if (isCiEnv(process.env) || process.env.RUNAR_CONFORMANCE_STRICT) {
      expect(missing, `these tiers have no toolchain: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length, `REPO=${REPO}`).toBeGreaterThanOrEqual(2);
  });

  for (const [shape, body] of Object.entries(NO_GROWTH)) {
    it(`ts: ${shape} is no larger optimized than unoptimized`, () => {
      const src = shapeSource(body);
      const off = tsBytes(src, true);
      const on = tsBytes(src, false);
      expect(on, `${shape}: optimized ${on} vs unoptimized ${off}`).toBeLessThanOrEqual(off);
    });
  }

  for (const [shape, body] of Object.entries(MUST_SHRINK)) {
    it(`ts: ${shape} still fuses and shrinks`, () => {
      const src = shapeSource(body);
      const off = tsBytes(src, true);
      const on = tsBytes(src, false);
      expect(on, `${shape}: optimized ${on} vs unoptimized ${off}`).toBeLessThan(off);
    });
  }

  for (const [shape, { body, bytes }] of Object.entries(SHARED_INNER)) {
    it(`ts: ${shape} fuses every reader and drops the inner (${bytes} bytes)`, () => {
      const src = sharedInnerSource(body);
      expect(tsBytes(src, false)).toBe(bytes);
      expect(tsBytes(src, false)).toBeLessThan(tsBytes(src, true));
    });
  }

  it('ts: only the positive controls fuse (ecMul/ecMulGen and ecAdd calls per method)', () => {
    for (const fold of FOLD_MODES) {
      const calls = Object.assign({}, ...FIXTURES.map((_, fx) => ecCalls(tsAnf(fx, fold))));
      expect(calls).toEqual({
        r9InnerLive: { mul: 2, add: 0 },
        r9OuterNested: { mul: 2, add: 0 },
        r10BothLive: { mul: 2, add: 1 },
        r10BothLiveAlias: { mul: 2, add: 1 },
        r10OuterLoop: { mul: 2, add: 2 },
        r11BothLive: { mul: 2, add: 1 },
        r11OuterBothNested: { mul: 2, add: 1 },
        r11OuterANestedBLive: { mul: 2, add: 1 },
        r10LeftLive: { mul: 2, add: 0 },
        r11LeftLive: { mul: 2, add: 0 },
        r10OuterNested: { mul: 1, add: 0 },
        r9SharedThenR11: { mul: 1, add: 0 },
        r9SharedTwoReaders: { mul: 2, add: 0 },
      });
    }
  });

  for (const [fx, fixture] of FIXTURES.entries()) {
    for (const fold of FOLD_MODES) {
      for (const tier of available) {
        it(`${tier.id} ${fold}: ${fixture.file} compiles to the pinned script`, () => {
          const hex = compileHex(withFold(tier, fold), fixture.path);
          expect(hex.length / 2).toBe(fixture.bytes);
          expect(createHash('sha256').update(hex).digest('hex')).toBe(fixture.sha256);
        });

        if (tier.id !== 'ts') {
          it(`${tier.id} ${fold}: ${fixture.file} optimized ANF equals the TS reference`, () => {
            expect(nativeAnf(tier, fx, fold)).toEqual(tsAnf(fx, fold));
          });
        }
      }
    }
  }

  it('the pinned scripts execute with the source\'s semantics (@bsv/sdk)', () => {
    const tsTier = available.find((t) => t.id === 'ts');
    expect(tsTier, 'the TS tier must be available').toBeDefined();
    const locks = FIXTURES.map((fixture) => {
      const hex = compileHex(tsTier!, fixture.path);
      expect(createHash('sha256').update(hex).digest('hex')).toBe(fixture.sha256);
      return hexToBytes(hex);
    });
    for (const s of SPENDS) {
      const res = new ScriptVM({ maxOps: 100_000_000 }).execute(s.unlock.bytes, locks[s.unlock.fx]!);
      expect(res.success, `${s.what}: error=${res.error ?? '(none)'}`).toBe(s.ok);
    }
  }, 1_200_000);
});
