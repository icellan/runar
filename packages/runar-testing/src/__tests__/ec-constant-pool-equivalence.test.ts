/**
 * EC constant pooling — semantic equivalence on the real interpreter.
 *
 * Pooling replaces ~20,000 inline pushes of a curve's field prime with picks
 * from one resident stack slot (see
 * `docs/experiments/script-size-optimization-baseline.md`). It changes stack
 * layout inside every EC emitter, including inside `OP_IF` arms, so "the byte
 * count went down" is not evidence of anything on its own.
 *
 * Two kinds of proof here, both through @bsv/sdk's `Spend`:
 *
 *  1. DIFFERENTIAL — for the same inputs, the pooled and unpooled scripts leave
 *     an identical stack. No oracle needed and no fixture to get wrong: the
 *     unpooled emitter is the specification.
 *  2. ORACLE — `verifyECDSA_*` accepts a genuine OpenSSL signature and rejects
 *     every near-miss, under BOTH variants. This is the one that would catch a
 *     pooled slot being read where a *different* value was intended, which a
 *     pure differential over random inputs can miss if both variants are wrong
 *     in the same way (they cannot be here — only one of them was changed —
 *     but the reject cases also pin the security-relevant behaviour).
 *
 * Max stack depth is measured, not assumed: pooling adds resident slots, and
 * the interpreter's 1,000-element budget is the real limit.
 */

import { describe, it, expect } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import {
  emitMethod,
  emitVerifyECDSA_P256, emitVerifyECDSA_P384,
  emitP256Add, emitP256Mul, emitP256Negate, emitP256OnCurve,
  emitP384Add, emitP384Negate, emitP384OnCurve,
  emitEcAdd, emitEcMul, emitEcNegate, emitEcOnCurve,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

type Emitter = (emit: (op: StackOp) => void, opts?: { constantPool?: boolean }) => void;

const blob = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));

interface RunResult {
  stack: string[];
  error: string | null;
  maxStackDepth: number;
}

/** Emit `inputs` then the emitter's body, and execute the whole thing. */
function run(emitter: Emitter, inputs: StackOp[], pooled: boolean): RunResult {
  const ops: StackOp[] = [...inputs];
  emitter(op => ops.push(op), pooled ? { constantPool: true } : undefined);
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex) as never as {
    stack: Uint8Array[]; error?: string; maxStackDepth: number;
  };
  return {
    stack: r.stack.map(b => Buffer.from(b).toString('hex')),
    error: r.error ?? null,
    maxStackDepth: r.maxStackDepth,
  };
}

/** Assert both variants agree completely, and report the depth cost. */
function expectSame(emitter: Emitter, inputs: StackOp[]): { off: RunResult; on: RunResult } {
  const off = run(emitter, inputs, false);
  const on = run(emitter, inputs, true);
  expect(on.error).toBe(off.error);
  expect(on.stack).toEqual(off.stack);
  return { off, on };
}

const push = (hex: string): StackOp => ({ op: 'push', value: blob(hex) } as StackOp);
const pushN = (n: bigint): StackOp => ({ op: 'push', value: n } as StackOp);

// ---------------------------------------------------------------------------
// Curve fixtures
// ---------------------------------------------------------------------------

const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  bytes: 32,
};
const SECP = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  bytes: 32,
};
const P384 = {
  gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
  gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
  bytes: 48,
};

const hx = (v: bigint, bytes: number) => v.toString(16).padStart(bytes * 2, '0');
const point = (x: bigint, y: bigint, bytes: number) => hx(x, bytes) + hx(y, bytes);

// ---------------------------------------------------------------------------
// 1. Differential — the unpooled emitter is the specification
// ---------------------------------------------------------------------------

describe('pooled and unpooled emitters agree (differential)', () => {
  const G256 = point(P256.gx, P256.gy, 32);
  const GSEC = point(SECP.gx, SECP.gy, 32);
  const G384 = point(P384.gx, P384.gy, 48);

  it('p256Add: G + G (the doubling path)', () => {
    expectSame(emitP256Add, [push(G256), push(G256)]);
  });

  it('p256Negate: -G', () => {
    expectSame(emitP256Negate, [push(G256)]);
  });

  it('p256OnCurve: accepts G', () => {
    const { off } = expectSame(emitP256OnCurve, [push(G256)]);
    expect(off.stack).toEqual(['01']);
  });

  it('p256OnCurve: rejects a point off the curve', () => {
    const { off } = expectSame(emitP256OnCurve, [push(point(P256.gx, P256.gy + 1n, 32))]);
    expect(off.stack).toEqual(['']);
  });

  it('p256OnCurve: rejects a non-canonical x >= p', () => {
    // The pooled prime is what the canonicity guard compares against, so this
    // is the case that would break first if the pool ever served a stale slot.
    expectSame(emitP256OnCurve, [push(point(P256.gx + P256.p, P256.gy, 32))]);
  });

  it.each([1n, 2n, 3n, 7n, P256.n - 1n, 0n, P256.n])('p256Mul: G * %s', (k) => {
    expectSame(emitP256Mul, [push(G256), pushN(k)]);
  });

  it('p384Add: G + G', () => {
    expectSame(emitP384Add, [push(G384), push(G384)]);
  });

  it('p384Negate / p384OnCurve on G', () => {
    expectSame(emitP384Negate, [push(G384)]);
    expectSame(emitP384OnCurve, [push(G384)]);
  });

  it('ecAdd: G + G (secp256k1)', () => {
    expectSame(emitEcAdd, [push(GSEC), push(GSEC)]);
  });

  it('ecNegate / ecOnCurve on G (secp256k1)', () => {
    expectSame(emitEcNegate, [push(GSEC)]);
    expectSame(emitEcOnCurve, [push(GSEC)]);
  });

  it.each([1n, 2n, 5n, SECP.n - 1n, 0n])('ecMul: G * %s (secp256k1)', (k) => {
    expectSame(emitEcMul, [push(GSEC), pushN(k)]);
  });

  it('agrees on garbage inputs too — both must fail the same way', () => {
    // Totality matters: these builtins are specified as "consume N, push 1"
    // for ANY argument bytes, so a divergence in the ERROR is as bad as a
    // divergence in the result.
    expectSame(emitP256OnCurve, [push('00'.repeat(64))]);
    expectSame(emitP256Add, [push('ff'.repeat(64)), push('00'.repeat(64))]);
  });
});

// ---------------------------------------------------------------------------
// 2. Oracle — OpenSSL signatures, both variants
// ---------------------------------------------------------------------------

/** DER SEQUENCE { INTEGER r, INTEGER s } -> fixed-width r||s. */
function derToRaw(der: Buffer, bytes: number): string {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('not a DER sequence');
  if (der[i]! & 0x80) i += 1 + (der[i]! & 0x7f); else i += 1;
  const readInt = (): bigint => {
    if (der[i++] !== 0x02) throw new Error('not a DER integer');
    const len = der[i++]!;
    const v = BigInt('0x' + der.subarray(i, i + len).toString('hex'));
    i += len;
    return v;
  };
  const r = readInt();
  const s = readInt();
  const w = bytes * 2;
  return r.toString(16).padStart(w, '0') + s.toString(16).padStart(w, '0');
}

const CURVES = [
  { name: 'p256', node: 'prime256v1' as const, bytes: 32, emit: emitVerifyECDSA_P256, n: P256.n },
  { name: 'p384', node: 'secp384r1' as const, bytes: 48, emit: emitVerifyECDSA_P384,
    n: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n },
];

for (const c of CURVES) {
  describe(`${c.name} verifyECDSA agrees under pooling (OpenSSL oracle)`, () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: c.node });
    const pub = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const uncompressed = pub.subarray(pub.length - (1 + c.bytes * 2)).toString('hex');
    const w = c.bytes * 2;
    const qx = BigInt('0x' + uncompressed.slice(2, 2 + w));
    const qy = BigInt('0x' + uncompressed.slice(2 + w));
    const compressed = ((qy & 1n) === 0n ? '02' : '03') + hx(qx, c.bytes);

    const msgHex = '52c3ad6172206d657373616765'; // "Rúnar message"
    const signer = createSign('sha256');
    signer.update(Buffer.from(msgHex, 'hex'));
    const sigHex = derToRaw(signer.sign(privateKey) as Buffer, c.bytes);

    const verify = (msg: string, sig: string, pk: string, pooled: boolean): boolean => {
      const r = run(c.emit, [push(msg), push(sig), push(pk)], pooled);
      expect(r.error, 'verifier aborted instead of returning a boolean').toBe(null);
      expect(r.stack.length, 'specified as 3 args in, 1 boolean out').toBe(1);
      return r.stack[0] !== '' && r.stack[0] !== '00';
    };

    const zero = '0'.repeat(w);
    const rGen = sigHex.slice(0, w);
    const sGen = sigHex.slice(w);
    const flipped = (compressed.slice(0, 2) === '02' ? '03' : '02') + compressed.slice(2);

    const CASES: Array<[string, string, string, string, boolean]> = [
      ['genuine signature', msgHex, sigHex, compressed, true],
      ['wrong message', msgHex + '00', sigHex, compressed, false],
      ['wrong pubkey parity', msgHex, sigHex, flipped, false],
      ['all-zero signature (universal forgery)', msgHex, zero + zero, compressed, false],
      ['r = 0', msgHex, zero + sGen, compressed, false],
      ['s = 0', msgHex, rGen + zero, compressed, false],
      ['r = n', msgHex, hx(c.n, c.bytes) + sGen, compressed, false],
      ['s = n', msgHex, rGen + hx(c.n, c.bytes), compressed, false],
      ['truncated signature', msgHex, sigHex.slice(0, w), compressed, false],
      ['oversized signature', msgHex, sigHex + 'ff', compressed, false],
    ];

    it.each(CASES)('%s', (_label, msg, sig, pk, want) => {
      expect(verify(msg, sig, pk, false)).toBe(want);
      expect(verify(msg, sig, pk, true)).toBe(want);
    });

    it('does not blow the interpreter stack budget', () => {
      const off = run(c.emit, [push(msgHex), push(sigHex), push(compressed)], false);
      const on = run(c.emit, [push(msgHex), push(sigHex), push(compressed)], true);
      // The pool is a small constant number of extra resident slots.
      expect(on.maxStackDepth).toBeLessThanOrEqual(off.maxStackDepth + 8);
      expect(on.maxStackDepth).toBeLessThan(800);
    });
  });
}
