import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
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
 * N-201 — the EC algebraic optimizer rewrites EC calls inside `if` arms and
 * loop bodies.
 *
 * It used to sweep only a method's top-level bindings, in all seven tiers, so
 * `if (c) { r = ecMulGen(0n); }` kept the full scalar multiplier: the fixture
 * below compiled to 2,145,442 bytes. Every EC call in it is now rewritten
 * (Rules 1, 3, 5, 6, the first two keeping their N-104 operand gates inside
 * the arm), and the operand each rewrite orphans inside the arm is pruned.
 *
 * What this proves: all seven tiers compile the fixture, fold-ON and fold-OFF,
 * to the same pinned bytes (2,984 bytes) and to the TS reference's optimized
 * ANF, binding for binding (so the gate helpers minted inside an arm carry the
 * same names everywhere); and the script executes with the source's
 * semantics — accepting and rejecting on both arms of each `if` and after the
 * loop, including the ecAdd gate refusing a non-canonical x and the ecMul gate
 * refusing an off-curve point.
 *
 * What it does not prove: the fusing rules (9, 10, 11) or the negate rules
 * (7, 8, 8r) inside nested scopes — each leaves a full EC call behind that DCE
 * keeps, so a byte-pinned script would be hundreds of kilobytes; they share
 * the nested sweep exercised here, but are not pinned. Scope isolation (no
 * then->else or arm->after-if leakage, the loop iteration variable hidden) is
 * pinned in TS only, by `anf-ec-optimizer.test.ts`. Nor any stateful contract.
 */

const FIXTURE = join(__dirname, 'EcNestedRewrite.runar.ts');
// sha256 of the hex string every tier must emit, both fold modes.
const EXPECTED_HEX_SHA256 = '969833f065ad228edb9554c48469515d5899f1056dbcba41ff7f78d354c46401';
const EXPECTED_BYTES = 2984;

type FoldMode = 'fold-on' | 'fold-off';
const FOLD_MODES: FoldMode[] = ['fold-on', 'fold-off'];

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

function withFold(tier: Tier, fold: FoldMode): Tier {
  if (fold === 'fold-on') return tier;
  return { ...tier, argsFor: (s) => [...tier.argsFor(s), '--disable-constant-folding'] };
}

// ---------------------------------------------------------------------------
// ANF comparison (same normalisation as n112-ec-fusion-helper-name-parity)
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
    fileName: 'EcNestedRewrite.runar.ts',
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

/** Every EC call left anywhere in the optimized ANF (expected: none). */
function ecCalls(anf: unknown): string[] {
  const out: string[] = [];
  const EC = new Set(['ecMulGen', 'ecMul', 'ecAdd', 'ecNegate']);
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) { node.forEach(walk); return; }
    if (node === null || typeof node !== 'object') return;
    const o = node as Record<string, unknown>;
    if (o.kind === 'call' && typeof o.func === 'string' && EC.has(o.func)) out.push(o.func);
    Object.values(o).forEach(walk);
  };
  walk(anf);
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

const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const G_POINT = [...be32(GX), ...be32(GY)];
/** (1, 1): 64 bytes, canonical coordinates, NOT on the curve. */
const OFF_CURVE = [...be32(1n), ...be32(1n)];
/** (p, 1): x is not a canonical field element. */
const NON_CANONICAL = [...be32(FIELD_P), ...be32(1n)];

type Arg = { int: bigint } | { bytes: number[] };

/** Public methods in declaration order: ifArm = 0, loopBody = 1, gatedArms = 2. */
function unlock(method: number, args: Arg[]): Uint8Array {
  const out: number[] = [];
  for (const a of args) out.push(...('int' in a ? pushInt(a.int) : pushBytes(a.bytes)));
  out.push(...pushInt(BigInt(method)));
  return new Uint8Array(out);
}

const i = (n: bigint): Arg => ({ int: n });
const bs = (b: number[]): Arg => ({ bytes: b });

const SPENDS: Array<{ what: string; unlock: Uint8Array; ok: boolean }> = [
  // ifArm(flag, ex, ey): flag = 1 -> O, else G.
  { what: 'ifArm then -> O', unlock: unlock(0, [i(1n), i(0n), i(0n)]), ok: true },
  { what: 'ifArm then is not G', unlock: unlock(0, [i(1n), i(GX), i(GY)]), ok: false },
  { what: 'ifArm skip -> G', unlock: unlock(0, [i(0n), i(GX), i(GY)]), ok: true },
  { what: 'ifArm skip is not O', unlock: unlock(0, [i(0n), i(0n), i(0n)]), ok: false },
  // loopBody(ex, ey): O after the loop.
  { what: 'loopBody -> O', unlock: unlock(1, [i(0n), i(0n)]), ok: true },
  { what: 'loopBody is not G', unlock: unlock(1, [i(GX), i(GY)]), ok: false },
  // gatedArms(p, flag, ex): result is p on both arms, behind each arm's gate.
  { what: 'gatedArms then, p = G', unlock: unlock(2, [bs(G_POINT), i(1n), i(GX)]), ok: true },
  { what: 'gatedArms else, p = G', unlock: unlock(2, [bs(G_POINT), i(0n), i(GX)]), ok: true },
  { what: 'gatedArms then, wrong x', unlock: unlock(2, [bs(G_POINT), i(1n), i(GY)]), ok: false },
  // ecAdd needs no on-curve operand (R-157): the add gate lets (1, 1) through.
  { what: 'gatedArms then, off-curve p', unlock: unlock(2, [bs(OFF_CURVE), i(1n), i(1n)]), ok: true },
  // ...but the ecMul gate refuses it, as ecMul itself would.
  { what: 'gatedArms else, off-curve p', unlock: unlock(2, [bs(OFF_CURVE), i(0n), i(1n)]), ok: false },
  // The add gate refuses a non-canonical x, as ecAdd itself would.
  { what: 'gatedArms then, x = p', unlock: unlock(2, [bs(NON_CANONICAL), i(1n), i(FIELD_P)]), ok: false },
];

describe('N-201: EC calls inside if arms and loop bodies are rewritten in all seven tiers', () => {
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

  for (const fold of FOLD_MODES) {
    it(`ts ${fold}: no EC call survives in the optimized ANF`, () => {
      expect(ecCalls(tsAnf(fold))).toEqual([]);
    });

    for (const tier of available) {
      it(`${tier.id} ${fold}: compiles to the pinned reduced script`, () => {
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

  for (const tier of available) {
    it(`${tier.id}: the script executes with the source's semantics`, () => {
      const lock = hexToBytes(compileHex(tier, FIXTURE));
      for (const s of SPENDS) {
        const res = new ScriptVM().execute(s.unlock, lock);
        expect(res.success, `${tier.id} ${s.what}: error=${res.error ?? '(none)'}`).toBe(s.ok);
      }
    });
  }
});
