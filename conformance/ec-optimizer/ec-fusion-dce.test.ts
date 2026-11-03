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
 * N-113 — the EC optimizer's fusing rules (R9, R10, R11) never make a script
 * larger.
 *
 * Each fusion replaces an expression with ONE scalar multiplication and
 * orphans the inner calls it read. Those inner calls used to stay in the
 * script, because DCE treats every call as side-effecting: R10 and R11 grew a
 * method from ~872 KB to ~1.27 MB, R9 by 5 bytes. The optimizer now removes an
 * orphaned `ecMulGen(<const>)` (no abort channel: G is fixed, the scalar is
 * reduced inside the ladder) and an orphaned `ecMul(q, <const>)` when a
 * surviving `ecMul` on the same binding q, in the same or an enclosing scope,
 * performs the identical operand gate (`q === O || ecOnCurve(q)`, ecMul's only
 * abort). `ecNegate` is never removed (R7/R8/R8r rely on it as a gate).
 *
 * What this proves: (1) in TS, every fusing shape — top level and inside an
 * `if` arm — compiles no larger than with the EC optimizer off; (2) all seven
 * tiers compile the fixture, fold-ON and fold-OFF, to the same pinned bytes and
 * to the TS reference's optimized ANF; (3) the pinned script executes with the
 * source's semantics on @bsv/sdk (ScriptVM), the expected points derived from
 * OpenSSL's secp256k1, not from the compiler: an off-curve or non-canonical q
 * still aborts every fused method, and in `crossScope` an off-curve q aborts
 * even on the path that never reaches the fusion (the outer ecMul survived).
 *
 * What it does not prove: shapes where an orphaned inner call is still read
 * elsewhere (it then stays; N-460's guard at the rule's fire site now refuses
 * those fusions, pinned by ec-fusion-liveness.test.ts), loops, or stateful
 * contracts.
 */

const FIXTURE = join(__dirname, 'EcFusionDce.runar.ts');
// sha256 of the hex string every tier must emit, both fold modes.
const EXPECTED_HEX_SHA256 = '17498b757c32bf95d6bfe43cb41a193a205c93af1a91ee8068b52c7c2134ac54';
const EXPECTED_BYTES = 3816690;

type FoldMode = 'fold-on' | 'fold-off';
const FOLD_MODES: FoldMode[] = ['fold-on', 'fold-off'];

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

function withFold(tier: Tier, fold: FoldMode): Tier {
  if (fold === 'fold-on') return tier;
  return { ...tier, argsFor: (s) => [...tier.argsFor(s), '--disable-constant-folding'] };
}

// ---------------------------------------------------------------------------
// TS size check: each fusing shape, optimizer on vs off
// ---------------------------------------------------------------------------

const SHAPES: Record<string, string> = {
  R9: 'ecMul(ecMul(q, 2n), 3n)',
  'R9 chain': 'ecMul(ecMul(ecMul(q, 2n), 3n), 5n)',
  R10: 'ecAdd(ecMulGen(2n), ecMulGen(3n))',
  R11: 'ecAdd(ecMul(q, 2n), ecMul(q, 3n))',
};

function shapeSource(expr: string, nested: boolean): string {
  const body = nested
    ? `let r: Point = q;\n    if (flag === 1n) {\n      r = ${expr};\n    }`
    : `const r: Point = ${expr};`;
  return `import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';
export class S extends SmartContract {
  constructor() { super(); }
  public m(p: Point, flag: bigint, ex: bigint) {
    const q: Point = p;
    ${body}
    assert(ecPointX(r) === ex);
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
// ANF comparison (same normalisation as ec-nested-rewrite.test.ts)
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

function tsAnf(fold: FoldMode): unknown {
  const r = compile(readFileSync(FIXTURE, 'utf8'), {
    fileName: 'EcFusionDce.runar.ts',
    disableConstantFolding: fold === 'fold-off',
  });
  if (!r.anf) throw new Error(`TS produced no ANF: ${JSON.stringify(r.diagnostics)}`);
  return normalise(r.anf);
}

function nativeAnf(tier: Tier, fold: FoldMode): unknown {
  const args = [...tier.prefix, '--source', FIXTURE, '--emit-ir'];
  if (fold === 'fold-off') args.push('--disable-constant-folding');
  const res = spawnSync(tier.cmd!, args, {
    cwd: tier.cwd, encoding: 'utf-8', timeout: tier.timeoutMs, maxBuffer: 64 * 1024 * 1024,
  });
  if (res.status !== 0) {
    throw new Error(`${tier.id} --emit-ir exited ${res.status}: ${(res.stderr ?? '').slice(0, 600)}`);
  }
  return normalise(JSON.parse(res.stdout));
}

/** EC scalar-multiplication calls per public method of the optimized ANF. */
function mulCalls(anf: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  const methods = (anf as { methods: Array<{ name: string; body: unknown }> }).methods;
  for (const m of methods) {
    let n = 0;
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) { node.forEach(walk); return; }
      if (node === null || typeof node !== 'object') return;
      const o = node as Record<string, unknown>;
      if (o.kind === 'call' && (o.func === 'ecMul' || o.func === 'ecMulGen')) n++;
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

/** x-coordinate of k*G, from OpenSSL's secp256k1 (independent of the compiler). */
function xOfMulG(k: bigint): bigint {
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(k.toString(16).padStart(64, '0'), 'hex'));
  const pub = ecdh.getPublicKey(undefined, 'uncompressed');
  return BigInt('0x' + pub.subarray(1, 33).toString('hex'));
}

const GX = xOfMulG(1n);
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const G_POINT = [...be32(GX), ...be32(GY)];
/** (1, 1): 64 bytes, canonical coordinates, NOT on the curve. */
const OFF_CURVE = [...be32(1n), ...be32(1n)];
/** (p, y_G): x is not a canonical field element. */
const NON_CANONICAL = [...be32(FIELD_P), ...be32(GY)];

type Arg = { int: bigint } | { bytes: number[] };

/** Public methods in declaration order. */
const M = {
  r9Top: 0, r9Chain: 1, r10Top: 2, r11Top: 3, r9Nested: 4, r10Nested: 5, r11Nested: 6, crossScope: 7,
} as const;

function unlock(method: number, args: Arg[]): Uint8Array {
  const out: number[] = [];
  for (const a of args) out.push(...('int' in a ? pushInt(a.int) : pushBytes(a.bytes)));
  out.push(...pushInt(BigInt(method)));
  return new Uint8Array(out);
}

const i = (n: bigint): Arg => ({ int: n });
const bs = (b: number[]): Arg => ({ bytes: b });

const X5 = xOfMulG(5n);
const X6 = xOfMulG(6n);
const X30 = xOfMulG(30n);

const SPENDS: Array<{ what: string; unlock: Uint8Array; ok: boolean }> = [
  { what: 'r9Top q = G -> 6G', unlock: unlock(M.r9Top, [bs(G_POINT), i(X6)]), ok: true },
  { what: 'r9Top wrong x (5G)', unlock: unlock(M.r9Top, [bs(G_POINT), i(X5)]), ok: false },
  { what: 'r9Top off-curve q', unlock: unlock(M.r9Top, [bs(OFF_CURVE), i(X6)]), ok: false },
  { what: 'r9Top non-canonical q', unlock: unlock(M.r9Top, [bs(NON_CANONICAL), i(X6)]), ok: false },
  { what: 'r9Chain q = G -> 30G', unlock: unlock(M.r9Chain, [bs(G_POINT), i(X30)]), ok: true },
  { what: 'r9Chain wrong x (6G)', unlock: unlock(M.r9Chain, [bs(G_POINT), i(X6)]), ok: false },
  { what: 'r9Chain off-curve q', unlock: unlock(M.r9Chain, [bs(OFF_CURVE), i(X30)]), ok: false },
  { what: 'r10Top -> 5G', unlock: unlock(M.r10Top, [i(X5)]), ok: true },
  { what: 'r10Top wrong x (6G)', unlock: unlock(M.r10Top, [i(X6)]), ok: false },
  { what: 'r11Top q = G -> 5G', unlock: unlock(M.r11Top, [bs(G_POINT), i(X5)]), ok: true },
  { what: 'r11Top wrong x (6G)', unlock: unlock(M.r11Top, [bs(G_POINT), i(X6)]), ok: false },
  { what: 'r11Top off-curve q', unlock: unlock(M.r11Top, [bs(OFF_CURVE), i(X5)]), ok: false },
  { what: 'r11Top non-canonical q', unlock: unlock(M.r11Top, [bs(NON_CANONICAL), i(X5)]), ok: false },
  { what: 'r9Nested then -> 6G', unlock: unlock(M.r9Nested, [bs(G_POINT), i(1n), i(X6)]), ok: true },
  { what: 'r9Nested then, off-curve q', unlock: unlock(M.r9Nested, [bs(OFF_CURVE), i(1n), i(X6)]), ok: false },
  { what: 'r9Nested skip -> q', unlock: unlock(M.r9Nested, [bs(G_POINT), i(0n), i(GX)]), ok: true },
  { what: 'r10Nested then -> 5G', unlock: unlock(M.r10Nested, [bs(G_POINT), i(1n), i(X5)]), ok: true },
  { what: 'r10Nested then, wrong x', unlock: unlock(M.r10Nested, [bs(G_POINT), i(1n), i(GX)]), ok: false },
  { what: 'r11Nested then -> 5G', unlock: unlock(M.r11Nested, [bs(G_POINT), i(1n), i(X5)]), ok: true },
  { what: 'r11Nested then, off-curve q', unlock: unlock(M.r11Nested, [bs(OFF_CURVE), i(1n), i(X5)]), ok: false },
  { what: 'r11Nested then, non-canonical q', unlock: unlock(M.r11Nested, [bs(NON_CANONICAL), i(1n), i(X5)]), ok: false },
  { what: 'crossScope then -> 5G', unlock: unlock(M.crossScope, [bs(G_POINT), i(1n), i(X5)]), ok: true },
  { what: 'crossScope skip -> q', unlock: unlock(M.crossScope, [bs(G_POINT), i(0n), i(GX)]), ok: true },
  // The outer ecMul(q, 2n) runs on the skip path too: its gate must survive.
  { what: 'crossScope skip, off-curve q', unlock: unlock(M.crossScope, [bs(OFF_CURVE), i(0n), i(1n)]), ok: false },
  { what: 'crossScope skip, non-canonical q', unlock: unlock(M.crossScope, [bs(NON_CANONICAL), i(0n), i(FIELD_P)]), ok: false },
];

describe('N-113: the EC fusing rules never grow the script, in all seven tiers', () => {
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

  for (const [rule, expr] of Object.entries(SHAPES)) {
    for (const nested of [false, true]) {
      it(`ts: ${rule} ${nested ? 'in an if arm' : 'at top level'} is no larger optimized than unoptimized`, () => {
        const src = shapeSource(expr, nested);
        const off = tsBytes(src, true);
        const on = tsBytes(src, false);
        expect(on, `${rule}: optimized ${on} vs unoptimized ${off}`).toBeLessThanOrEqual(off);
      });
    }
  }

  it('ts: one scalar multiplication per fused method; crossScope keeps its outer ecMul', () => {
    for (const fold of FOLD_MODES) {
      expect(mulCalls(tsAnf(fold))).toEqual({
        r9Top: 1, r9Chain: 1, r10Top: 1, r11Top: 1,
        r9Nested: 1, r10Nested: 1, r11Nested: 1,
        crossScope: 2,
      });
    }
  });

  for (const fold of FOLD_MODES) {
    for (const tier of available) {
      it(`${tier.id} ${fold}: compiles to the pinned script`, () => {
        const hex = compileHex(withFold(tier, fold), FIXTURE);
        expect(hex.length / 2).toBe(EXPECTED_BYTES);
        expect(createHash('sha256').update(hex).digest('hex')).toBe(EXPECTED_HEX_SHA256);
      });

      if (tier.id !== 'ts') {
        it(`${tier.id} ${fold}: optimized ANF equals the TS reference`, () => {
          expect(nativeAnf(tier, fold)).toEqual(tsAnf(fold));
        });
      }
    }
  }

  it('the pinned script executes with the source\'s semantics (@bsv/sdk)', () => {
    const tsTier = available.find((t) => t.id === 'ts');
    expect(tsTier, 'the TS tier must be available').toBeDefined();
    const hex = compileHex(tsTier!, FIXTURE);
    expect(createHash('sha256').update(hex).digest('hex')).toBe(EXPECTED_HEX_SHA256);
    const lock = hexToBytes(hex);
    for (const s of SPENDS) {
      const res = new ScriptVM({ maxOps: 100_000_000 }).execute(s.unlock, lock);
      expect(res.success, `${s.what}: error=${res.error ?? '(none)'}`).toBe(s.ok);
    }
  }, 600_000);
});
