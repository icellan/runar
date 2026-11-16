/**
 * GK-BUG-011 — SchnorrZKP must refuse a deployed pubKey that is the identity.
 *
 * The EC codegen represents the point at infinity O as the 64-byte all-zero
 * blob, and R-157 deliberately lets O through ecMul's on-curve gate:
 * `ecMul(O, k) = O`, and `ecAdd(R, O) = R` (r157-ecmul-curve-gate.test.ts pins
 * both). The verifier checks `s·G == R + e·P`, so with `P = O` the right side
 * collapses to R and the witness `(rPoint = G, s = 1)` spends with no discrete
 * log at all. `ecOnCurve(O)` is false, so `assert(ecOnCurve(this.pubKey))`
 * rejects that deployment and nothing else: every honest key is on the curve.
 *
 * Oracle: the shipped `examples/ts/schnorr-zkp/SchnorrZKP.runar.ts`, compiled by
 * the TS compiler (fold ON, the deployed bytes) and EXECUTED on `@bsv/sdk`'s
 * production `Spend` under consensus rules (`runStatelessSigned`). The honest
 * proof is built here from textbook secp256k1 affine arithmetic and node's
 * SHA-256, never from the code under test. The ANF interpreter is asserted to
 * agree on both rows.
 *
 * What this proves: with `pubKey = 0^64`, `verify(G, 1)` is refused, and the
 * refusal is the OP_VERIFY of the last assert before the Fiat-Shamir
 * OP_HASH256 (the new pubKey gate; `within(1, …)` and `ecOnCurve(G)` both hold),
 * so no ecMul ever runs on O; an honest proof (k = 42, r = 12345) still spends.
 * What it does NOT prove: anything about replay or nonce reuse (the contract
 * header documents both), or the other eight surfaces' bytes (the conformance
 * runner holds all nine surfaces x seven tiers to one golden).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LockingScript } from '@bsv/sdk';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = readFileSync(join(HERE, '../../../../examples/ts/schnorr-zkp/SchnorrZKP.runar.ts'), 'utf8');

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

const mod = (a: bigint, m: bigint) => ((a % m) + m) % m;
function inv(a: bigint, m: bigint): bigint {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  return mod(s0, m);
}
type Pt = [bigint, bigint];
function add(a: Pt, b: Pt): Pt {
  const l = a[0] === b[0] && a[1] === b[1]
    ? mod(3n * a[0] * a[0] * inv(2n * a[1], P), P)
    : mod((b[1] - a[1]) * inv(b[0] - a[0], P), P);
  const x = mod(l * l - a[0] - b[0], P);
  return [x, mod(l * (a[0] - x) - a[1], P)];
}
function mul(k: bigint, pt: Pt): Pt {
  let acc: Pt | null = null;
  let addend = pt;
  for (let e = mod(k, N); e > 0n; e >>= 1n) {
    if (e & 1n) acc = acc ? add(acc, addend) : addend;
    addend = add(addend, addend);
  }
  if (!acc) throw new Error('mul: k = 0 has no affine result');
  return acc;
}
const hex32 = (n: bigint) => n.toString(16).padStart(64, '0');
const ptHex = (p: Pt) => hex32(p[0]) + hex32(p[1]);
const sha256 = (b: Buffer) => createHash('sha256').update(b).digest();

/** Bitcoin script-number decode (little-endian sign-magnitude), i.e. bin2num. */
function bin2num(b: Buffer): bigint {
  if (b.length === 0) return 0n;
  const neg = (b[b.length - 1]! & 0x80) !== 0;
  let v = BigInt(b[b.length - 1]! & 0x7f);
  for (let i = b.length - 2; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return neg ? -v : v;
}

const G: Pt = [GX, GY];
const O_HEX = '00'.repeat(64);

/** Chunk index of the first OP_HASH256 (the Fiat-Shamir challenge). */
function hashIndex(lockingHex: string): number {
  return LockingScript.fromHex(lockingHex).chunks.findIndex((c) => c.op === 0xaa);
}

/** VERIFY-family opcodes an `assert` can lower to (after peephole fusion). */
const VERIFY_OPS = new Set([0x69, 0x88, 0x9d]);

describe('GK-BUG-011 SchnorrZKP refuses the identity as its pubKey', () => {
  it('the honest-proof generator is anchored: 42·G is on the curve and differs from G', () => {
    const [x, y] = mul(42n, G);
    expect(mod(y * y - (x * x * x + 7n), P)).toBe(0n);
    expect(x).not.toBe(GX);
  });

  it('pubKey = 0^64, verify(G, 1): REFUSED at the pubKey gate, before any hash or ecMul', () => {
    const r = runStatelessSigned({
      source: SRC,
      fileName: 'SchnorrZKP.runar.ts',
      method: 'verify',
      args: [Buffer.from(ptHex(G), 'hex'), 1n],
      constructorArgs: { pubKey: O_HEX },
    });
    expect(r.reachedEngine).toBe(true);
    expect(r.vmAccepted, 'Spend ACCEPTED s·G == R + e·O with no discrete log').toBe(false);
    expect(r.vmError ?? '').toMatch(/OP_VERIFY requires the top stack value to be truthy/);
    expect(r.vmError ?? '').toMatch(/Context: LockingScript, PC: \d+/);

    const pc = Number(/PC: (\d+)/.exec(r.vmError ?? '')![1]);
    const chunks = LockingScript.fromHex(r.lockingHex!).chunks;
    const h = hashIndex(r.lockingHex!);
    expect(h, 'no OP_HASH256 in the compiled verifier').toBeGreaterThan(0);
    expect(pc, 'the refusal came after the Fiat-Shamir hash').toBeLessThan(h);
    expect(VERIFY_OPS.has(chunks[pc]!.op)).toBe(true);
    // ...and it is the LAST assert before the hash: the pubKey gate, not the
    // `within` bound or ecOnCurve(rPoint), both of which hold for (G, 1).
    for (let i = pc + 1; i < h; i++) {
      expect(VERIFY_OPS.has(chunks[i]!.op), `another assert at chunk ${i} follows the refusal`).toBe(false);
    }

    expect(r.interpreterAccepted, `interpreter: ${r.interpreterError}`).toBe(false);
  }, 1_800_000);

  it('an honest proof (k = 42, r = 12345) still spends', () => {
    const k = 42n;
    const pub = mul(k, G);
    const nonce = 12345n;
    const R = mul(nonce, G);
    const e = bin2num(sha256(sha256(Buffer.from(ptHex(R) + ptHex(pub), 'hex'))));
    const s = mod(nonce + e * k, N);

    const r = runStatelessSigned({
      source: SRC,
      fileName: 'SchnorrZKP.runar.ts',
      method: 'verify',
      args: [Buffer.from(ptHex(R), 'hex'), s],
      constructorArgs: { pubKey: ptHex(pub) },
    });
    expect(r.reachedEngine).toBe(true);
    expect(r.vmAccepted, `honest proof refused: ${r.vmError}`).toBe(true);
    expect(r.interpreterAccepted, `interpreter: ${r.interpreterError}`).toBe(true);
  }, 1_800_000);
});
