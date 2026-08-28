/**
 * Reduction sinking — soundness, by differential sweep over the boundary.
 *
 * `fieldMod` costs 10 bytes and is emitted ~20,000 times in a P-256 verify. Six
 * of those bytes are a sign fix-up that exists only because `OP_MOD` takes the
 * sign of the dividend; where the dividend is provably non-negative they are
 * dead weight. Dropping them is worth ~124 kB on p256-wallet
 * (docs/experiments/script-size-optimizer-results.md §3.7).
 *
 * The danger is precise and was found by construction before this was built
 * (§3.8): the multiply / add paths need only `dividend >= 0`, which unsigned
 * coordinate decoding already gives — but the SUBTRACT path needs the strictly
 * stronger `subtrahend < p`, and `OP_BIN2NUM` of 32 unsigned bytes does not
 * imply it. A blanket rewrite passes 256 EC oracle assertions and is still
 * wrong on:
 *
 *     ecAdd((0, 1), (2^256 - 1, 1))
 *
 * where the two differ by exactly 2^256 - p = 2^32 + 977.
 *
 * So this file does not test "does it still verify a signature" — that question
 * was already answered wrongly once. It sweeps the coordinate values that sit
 * on the boundary (0, 1, p-1, p, p+1, 2^256-1) and requires the sunk script to
 * be byte-for-byte identical in RESULT to the shipping one for every single
 * combination, including the ones no valid curve point could ever produce.
 */

import { describe, it, expect } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import {
  emitMethod,
  emitEcAdd, emitEcNegate, emitEcOnCurve, emitEcMul,
  emitP256Add, emitP256Negate, emitP256OnCurve,
  emitVerifyECDSA_P256,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

type Opts = { constantPool?: boolean; reductionSinking?: boolean };
type Emitter = (emit: (op: StackOp) => void, opts?: Opts) => void;

const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const MAX256 = (1n << 256n) - 1n;

const SECP_G = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};
const P256_G = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

const hx = (v: bigint) => v.toString(16).padStart(64, '0');
const pt = (x: bigint, y: bigint) => hx(x) + hx(y);

/** Compile the emitter under `opts`, run it on `inputs`, return the final stack. */
function run(emitter: Emitter, inputs: string[], opts: Opts): string[] {
  const ops: StackOp[] = inputs.map(
    h => ({ op: 'push', value: Uint8Array.from(Buffer.from(h, 'hex')) } as StackOp),
  );
  emitter(op => ops.push(op), opts);
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex) as never as {
    stack: Uint8Array[]; error?: string;
  };
  if (r.error) return [`ERR:${r.error}`];
  return r.stack.map(b => Buffer.from(b).toString('hex'));
}

/** Sinking is compared against pooling alone, so only the reduction changes. */
const BASE: Opts = { constantPool: true };
const SUNK: Opts = { constantPool: true, reductionSinking: true };

function expectAgrees(emitter: Emitter, inputs: string[], label: string): void {
  expect(run(emitter, inputs, SUNK), label).toEqual(run(emitter, inputs, BASE));
}

/**
 * Coordinate values that sit on every boundary the analysis has to respect.
 * `p`, `p+1` and `2^256-1` are NON-CANONICAL — no valid point has them — but
 * the bare builtins accept raw coordinates, so the emitted script must still
 * agree with the shipping one on them.
 */
const SECP_EDGE = [0n, 1n, 2n, SECP_P - 1n, SECP_P, SECP_P + 1n, MAX256, SECP_G.x];
const P256_EDGE = [0n, 1n, 2n, P256_P - 1n, P256_P, P256_P + 1n, MAX256, P256_G.x];

describe('reduction sinking agrees with the shipping reduction', () => {
  describe('secp256k1', () => {
    it.each(SECP_EDGE)('ecOnCurve at x = %s', (x) => {
      expectAgrees(emitEcOnCurve, [pt(x, 1n)], `onCurve x=${x}`);
      expectAgrees(emitEcOnCurve, [pt(1n, x)], `onCurve y=${x}`);
    });

    it.each(SECP_EDGE)('ecNegate at y = %s', (y) => {
      expectAgrees(emitEcNegate, [pt(1n, y)], `negate y=${y}`);
    });

    // The cross product is where the subtraction precondition lives: the cheap
    // form breaks only when the SUBTRAHEND is non-canonical and the minuend is
    // smaller than 2^256 - p.
    const PAIRS: Array<[bigint, bigint]> = [];
    for (const a of SECP_EDGE) for (const b of SECP_EDGE) PAIRS.push([a, b]);

    it.each(PAIRS)('ecAdd((%s,1), (%s,1))', (ax, bx) => {
      expectAgrees(emitEcAdd, [pt(ax, 1n), pt(bx, 1n)], `ecAdd ${ax} ${bx}`);
    });

    it('ecAdd((0,1), (2^256-1,1)) — the counterexample that motivated this', () => {
      // A blanket short reduction returns a value differing by exactly
      // 2^256 - p = 0x1000003d0. This must now agree.
      expectAgrees(emitEcAdd, [pt(0n, 1n), pt(MAX256, 1n)], 'counterexample');
    });

    it.each([0n, 1n, 2n, 7n, SECP_P])('ecMul(G, %s)', (k) => {
      const ops: StackOp[] = [
        { op: 'push', value: Uint8Array.from(Buffer.from(pt(SECP_G.x, SECP_G.y), 'hex')) } as StackOp,
        { op: 'push', value: k } as StackOp,
      ];
      const go = (opts: Opts): string[] => {
        const list = [...ops];
        emitEcMul(op => list.push(op), opts);
        const { scriptHex } = emitMethod({ name: 't', ops: list } as never) as { scriptHex: string };
        const r = new ScriptVM().executeHex(scriptHex) as never as { stack: Uint8Array[]; error?: string };
        return r.error ? [`ERR:${r.error}`] : r.stack.map(b => Buffer.from(b).toString('hex'));
      };
      expect(go(SUNK)).toEqual(go(BASE));
    });
  });

  describe('P-256', () => {
    it.each(P256_EDGE)('p256OnCurve at x = %s', (x) => {
      expectAgrees(emitP256OnCurve, [pt(x, 1n)], `p256OnCurve x=${x}`);
      expectAgrees(emitP256OnCurve, [pt(1n, x)], `p256OnCurve y=${x}`);
    });

    it.each(P256_EDGE)('p256Negate at y = %s', (y) => {
      expectAgrees(emitP256Negate, [pt(1n, y)], `p256Negate y=${y}`);
    });

    const PAIRS: Array<[bigint, bigint]> = [];
    for (const a of P256_EDGE) for (const b of P256_EDGE) PAIRS.push([a, b]);

    it.each(PAIRS)('p256Add((%s,1), (%s,1))', (ax, bx) => {
      expectAgrees(emitP256Add, [pt(ax, 1n), pt(bx, 1n)], `p256Add ${ax} ${bx}`);
    });
  });

  describe('verifyECDSA_P256', () => {
    const CASES: Array<[string, string, string, string]> = [
      ['all-zero', '00'.repeat(4), '00'.repeat(64), '02' + hx(0n)],
      ['non-canonical pubkey x', 'aabbccdd', '11'.repeat(64), '02' + hx(P256_P + 1n)],
      ['max pubkey x', 'aabbccdd', '11'.repeat(64), '02' + hx(MAX256)],
      ['max r and s', 'aabbccdd', hx(MAX256) + hx(MAX256), '02' + hx(P256_G.x)],
      ['r = p, s = 1', 'aabbccdd', hx(P256_P) + hx(1n), '02' + hx(P256_G.x)],
    ];
    it.each(CASES)('%s', (_label, msg, sig, pk) => {
      expectAgrees(emitVerifyECDSA_P256, [msg, sig, pk], _label);
    });
  });
});

describe('reduction sinking under an absolute oracle', () => {
  // The differential sweep above proves "same as before". This proves "still
  // right", against a signature this repo did not produce — the check that a
  // blanket rewrite would also have passed, which is why it is not the only one.
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const der = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const uncompressed = der.subarray(der.length - 65).toString('hex');
  const qx = BigInt('0x' + uncompressed.slice(2, 66));
  const qy = BigInt('0x' + uncompressed.slice(66));
  const compressed = ((qy & 1n) === 0n ? '02' : '03') + hx(qx);

  const msgHex = '52c3ad6172206d657373616765';
  const signer = createSign('sha256');
  signer.update(Buffer.from(msgHex, 'hex'));
  const sigDer = signer.sign(privateKey) as Buffer;
  let i = 0;
  if (sigDer[i++] !== 0x30) throw new Error('not DER');
  if (sigDer[i]! & 0x80) i += 1 + (sigDer[i]! & 0x7f); else i += 1;
  const readInt = (): bigint => {
    if (sigDer[i++] !== 0x02) throw new Error('not a DER integer');
    const len = sigDer[i++]!;
    const v = BigInt('0x' + sigDer.subarray(i, i + len).toString('hex'));
    i += len;
    return v;
  };
  const sigHex = hx(readInt()) + hx(readInt());

  const verify = (msg: string, sig: string, pk: string): boolean => {
    const st = run(emitVerifyECDSA_P256, [msg, sig, pk], SUNK);
    expect(st.length, `expected one boolean out, got ${st.join(',')}`).toBe(1);
    return st[0] !== '' && st[0] !== '00';
  };

  it('accepts a genuine OpenSSL signature', () => {
    expect(verify(msgHex, sigHex, compressed)).toBe(true);
  });

  it.each([
    ['wrong message', msgHex + '00', () => sigHex, () => compressed],
    ['wrong pubkey parity', msgHex, () => sigHex,
      () => (compressed.slice(0, 2) === '02' ? '03' : '02') + compressed.slice(2)],
    ['all-zero signature', msgHex, () => '0'.repeat(128), () => compressed],
    ['r = 0', msgHex, () => '0'.repeat(64) + sigHex.slice(64), () => compressed],
    ['s = 0', msgHex, () => sigHex.slice(0, 64) + '0'.repeat(64), () => compressed],
    ['r = n', msgHex, () => hx(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n) + sigHex.slice(64), () => compressed],
    ['non-canonical pubkey x', msgHex, () => sigHex, () => '02' + hx(P256_P + 1n)],
  ] as Array<[string, string, () => string, () => string]>)('rejects %s', (_l, msg, sig, pk) => {
    expect(verify(msg, sig(), pk())).toBe(false);
  });
});

describe('reduction sinking is not a no-op', () => {
  it('shrinks every emitter it applies to', () => {
    const bytes = (e: Emitter, o: Opts): number => {
      const ops: StackOp[] = [];
      e(op => ops.push(op), o);
      return (emitMethod({ name: 't', ops } as never) as { scriptHex: string }).scriptHex.length / 2;
    };
    for (const [name, e] of [
      ['emitEcAdd', emitEcAdd], ['emitEcOnCurve', emitEcOnCurve],
      ['emitP256Add', emitP256Add], ['emitVerifyECDSA_P256', emitVerifyECDSA_P256],
    ] as Array<[string, Emitter]>) {
      const base = bytes(e, BASE);
      const sunk = bytes(e, SUNK);
      expect(sunk, `${name} did not shrink (${base} -> ${sunk})`).toBeLessThan(base);
    }
  });
});
