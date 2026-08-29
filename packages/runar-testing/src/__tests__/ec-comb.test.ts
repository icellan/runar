/**
 * Fixed-base comb — differential against the binary ladder, on the real engine.
 *
 * The comb changes the scalar recoding, the round count, the accumulator's
 * initial value and which addition formula each round uses. Its soundness rests
 * on `comb.ts#combSafeRounds`, an interval argument re-derived for the comb
 * because the ladder's own version does not transfer. That is exactly the kind
 * of argument that can be subtly wrong while every ordinary input still works,
 * so the gate here is: for the same scalar, the comb and the ladder must return
 * the SAME POINT — over the scalars that sit on every boundary the argument
 * turns on.
 */

import { describe, it, expect } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import {
  emitMethod, emitP256MulGen, emitP384MulGen, emitP256Mul, emitVerifyECDSA_P256,
  emitEcMulGen, emitEcMul,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

type Opts = { constantPool?: boolean; reductionSinking?: boolean; fixedBaseComb?: boolean };

const LADDER: Opts = { constantPool: true, reductionSinking: true };
const COMB: Opts = { constantPool: true, reductionSinking: true, fixedBaseComb: true };

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P384_N = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n;
const P256_G = '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
  + '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';
const K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const K1_G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

function run(
  emitter: (e: (o: StackOp) => void, o?: Opts) => void,
  inputs: StackOp[], opts: Opts,
): string[] {
  const ops = [...inputs];
  emitter(op => ops.push(op), opts);
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex) as never as { stack: Uint8Array[]; error?: string };
  return r.error ? [`ERR:${r.error}`] : r.stack.map(b => Buffer.from(b).toString('hex'));
}

const num = (v: bigint): StackOp => ({ op: 'push', value: v } as StackOp);
const bytes = (h: string): StackOp => ({ op: 'push', value: Uint8Array.from(Buffer.from(h, 'hex')) } as StackOp);

describe('P-256 comb agrees with the binary ladder', () => {
  /**
   * Every boundary the interval argument turns on: the ends of the reduced
   * domain, the values that make the accumulator hit a table entry early, the
   * scalars whose leading comb digits are minimal, and the out-of-range inputs
   * the reduce is there to fold back in.
   */
  const SCALARS = [
    0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 15n, 16n, 17n,
    P256_N - 2n, P256_N - 1n, P256_N, P256_N + 1n, 2n * P256_N,
    -1n, -2n, -P256_N,
    (1n << 85n), (1n << 86n), (1n << 86n) - 1n,
    (1n << 171n), (1n << 172n), (1n << 255n), (1n << 256n) - 1n,
    0x2n ** 128n + 12345n,
    0xdeadbeefcafebaben,
  ];

  it.each(SCALARS)('G * %s', (k) => {
    const comb = run(emitP256MulGen, [num(k)], COMB);
    const ladder = run(emitP256MulGen, [num(k)], LADDER);
    expect(comb).toEqual(ladder);
  });

  it('agrees with the generic ladder driven by an explicit G, too', () => {
    // emitP256MulGen and emitP256Mul share a code path today; pin that the comb
    // matches the INDEPENDENT generic-point ladder as well, so a shared bug in
    // the MulGen wrapper cannot hide.
    for (const k of [1n, 2n, 7n, P256_N - 1n, 0n]) {
      const comb = run(emitP256MulGen, [num(k)], COMB);
      const generic = run(emitP256Mul, [bytes(P256_G), num(k)], LADDER);
      expect(comb, `k=${k}`).toEqual(generic);
    }
  });
});

describe('secp256k1 comb agrees with the binary ladder', () => {
  /**
   * secp256k1 is the curve every `ecMulGen` contract in the corpus actually
   * uses, and it is the one curve where the comb's doubling formula differs:
   * a = 0, so `jacobianDouble` computes D = 3X² rather than the NIST
   * 3(X-Z²)(X+Z²). Same boundary set as P-256 — the reduced domain's ends, the
   * scalars whose leading comb digits are minimal, and the out-of-range inputs
   * `emitScalarReduce` exists to fold back in.
   */
  const SCALARS = [
    0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 15n, 16n, 17n,
    K1_N - 2n, K1_N - 1n, K1_N, K1_N + 1n, 2n * K1_N,
    -1n, -2n, -K1_N,
    (1n << 85n), (1n << 86n), (1n << 86n) - 1n,
    (1n << 171n), (1n << 172n), (1n << 255n), (1n << 256n) - 1n,
    0x2n ** 128n + 12345n,
    0xdeadbeefcafebaben,
  ];

  it.each(SCALARS)('G * %s', (k) => {
    expect(run(emitEcMulGen, [num(k)], COMB)).toEqual(run(emitEcMulGen, [num(k)], LADDER));
  });

  it('agrees with the generic ladder driven by an explicit G, too', () => {
    // `emitEcMulGen` delegates to `emitEcMul` on the ladder path, so a shared
    // bug in the wrapper would cancel out above. Pin against the generic
    // runtime-point ladder as well.
    for (const k of [1n, 2n, 7n, K1_N - 1n, 0n]) {
      expect(run(emitEcMulGen, [num(k)], COMB), `k=${k}`)
        .toEqual(run(emitEcMul, [bytes(K1_G), num(k)], LADDER));
    }
  });

  it('reproduces the published k·G vectors', () => {
    // Absolute, not differential: both sides above could be wrong together.
    const VECTORS: Array<[bigint, string]> = [
      [1n, K1_G],
      [2n, 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
         + '1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'],
      [3n, 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
         + '388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672'],
      [7n, '5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc'
         + '6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da'],
    ];
    for (const [k, want] of VECTORS) {
      expect(run(emitEcMulGen, [num(k)], COMB), `k=${k}`).toEqual([want]);
    }
  });
});

describe('P-384 comb agrees with the binary ladder', () => {
  // P-384 at w=3 needs a different scalar offset than P-256; if combParams got
  // that wrong the leading digit could be zero and the accumulator would start
  // at infinity. These are the cases that would show it.
  const SCALARS = [0n, 1n, 2n, 3n, 7n, 8n, P384_N - 1n, P384_N, (1n << 128n), (1n << 383n)];

  it.each(SCALARS)('G * %s', (k) => {
    expect(run(emitP384MulGen, [num(k)], COMB)).toEqual(run(emitP384MulGen, [num(k)], LADDER));
  });
});

describe('verifyECDSA_P256 with the comb for u1*G', () => {
  // The verifier is the reason the comb exists. Q arrives in the witness so its
  // half stays a ladder; only u1*G changes. Differential against the all-ladder
  // build, then an absolute OpenSSL oracle.
  const hx = (v: bigint) => v.toString(16).padStart(64, '0');
  const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const der = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const un = der.subarray(der.length - 65).toString('hex');
  const qy = BigInt('0x' + un.slice(66));
  const compressed = ((qy & 1n) === 0n ? '02' : '03') + un.slice(2, 66);
  const msgHex = '52c3ad6172206d657373616765';
  const signer = createSign('sha256');
  signer.update(Buffer.from(msgHex, 'hex'));
  const d = signer.sign(privateKey) as Buffer;
  let i = 0;
  if (d[i++] !== 0x30) throw new Error('not DER');
  if (d[i]! & 0x80) i += 1 + (d[i]! & 0x7f); else i += 1;
  const rd = (): bigint => {
    if (d[i++] !== 0x02) throw new Error('not int');
    const len = d[i++]!;
    const v = BigInt('0x' + d.subarray(i, i + len).toString('hex'));
    i += len;
    return v;
  };
  const sigHex = hx(rd()) + hx(rd());

  const verdict = (msg: string, sig: string, pk: string, o: Opts): boolean => {
    const st = run(emitVerifyECDSA_P256, [bytes(msg), bytes(sig), bytes(pk)], o);
    expect(st.length, `expected one boolean, got ${st.join(',')}`).toBe(1);
    return st[0] !== '' && st[0] !== '00';
  };

  const CASES: Array<[string, string, string, string, boolean]> = [
    ['genuine signature', msgHex, sigHex, compressed, true],
    ['wrong message', msgHex + '00', sigHex, compressed, false],
    ['flipped parity', msgHex, sigHex,
      (compressed.slice(0, 2) === '02' ? '03' : '02') + compressed.slice(2), false],
    ['all-zero signature', msgHex, '0'.repeat(128), compressed, false],
    ['r = 0', msgHex, '0'.repeat(64) + sigHex.slice(64), compressed, false],
    ['s = 0', msgHex, sigHex.slice(0, 64) + '0'.repeat(64), compressed, false],
    ['non-canonical pubkey x', msgHex, sigHex, '02' + hx(P256_P + 1n), false],
    ['truncated signature', msgHex, sigHex.slice(0, 64), compressed, false],
  ];

  it.each(CASES)('%s — comb matches ladder and the oracle', (_l, msg, sig, pk, want) => {
    expect(verdict(msg, sig, pk, COMB)).toBe(verdict(msg, sig, pk, LADDER));
    expect(verdict(msg, sig, pk, COMB)).toBe(want);
  });
});

describe('the comb is actually smaller', () => {
  it.each([
    ['emitP256MulGen', emitP256MulGen],
    ['emitP384MulGen', emitP384MulGen],
    ['emitVerifyECDSA_P256', emitVerifyECDSA_P256],
    ['emitEcMulGen', emitEcMulGen],
  ] as Array<[string, (e: (o: StackOp) => void, o?: Opts) => void]>)('%s', (name, e) => {
    const size = (o: Opts): number => {
      const ops: StackOp[] = [];
      e(op => ops.push(op), o);
      return (emitMethod({ name: 't', ops } as never) as { scriptHex: string }).scriptHex.length / 2;
    };
    const ladder = size(LADDER);
    const comb = size(COMB);
    // eslint-disable-next-line no-console
    console.log(`  ${name}: ladder ${ladder} -> comb ${comb} (${(((comb - ladder) / ladder) * 100).toFixed(1)}%)`);
    expect(comb).toBeLessThan(ladder);
  });
});
