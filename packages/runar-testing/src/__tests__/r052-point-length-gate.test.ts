import { describe, it, expect } from 'vitest';
import {
  emitMethod,
  emitEcAdd, emitEcMul, emitEcNegate, emitEcOnCurve,
  emitEcEncodeCompressed, emitEcPointX, emitEcPointY,
  emitP256Add, emitP256Mul, emitP256Negate, emitP256OnCurve, emitP256EncodeCompressed,
  emitP384Add, emitP384Mul, emitP384Negate, emitP384OnCurve, emitP384EncodeCompressed,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * CL-BUG-095 / R-052 — no length validation on any `Point` argument.
 *
 * A `Point` is DEFINED as exactly 2*w bytes (x[w] ‖ y[w], big-endian, no
 * prefix byte): 64 for secp256k1 and P-256, 96 for P-384. Nothing anywhere
 * checked that. The type checker gives `Point` no width, and every one of
 * these values arrives as an unlock argument, so the blob is attacker-sized.
 *
 * What that bought an attacker, all three measured through the real @bsv/sdk
 * `Spend` interpreter before the fix:
 *
 *   - `ecOnCurve(G ‖ 0xff)` returned TRUE. `decomposePoint` splits at w and
 *     then reverses exactly w bytes, so `emitReverse32`'s 32nd iteration left
 *     the surplus byte in the "rest" slot and the trailing `drop` threw it
 *     away. The gate every contract is told to put in front of an untrusted
 *     point therefore certified a blob that is not a point — and a point's
 *     identity AS BYTES (nullifier, commitment, equality test) stopped being
 *     unique the moment 2^8 blobs all passed the same gate.
 *   - `ecEncodeCompressed` took the parity bit from the blob's LAST byte via
 *     `OP_SIZE 1 OP_SUB OP_SPLIT`, not from a fixed offset. Appending one byte
 *     therefore FLIPPED THE SIGN of the compressed encoding: the same 64-byte
 *     point compressed to 02‖x or 03‖x at the caller's choice. Anything that
 *     hashes a compressed pubkey (P2PKH address, a commitment) is forgeable
 *     between the two spellings.
 *   - `ecPointX` on a 32-byte blob SUCCEEDED, returning that blob as x. Note
 *     `ecPointY` on the same input already aborted — the two accessors had
 *     opposite behaviour on the identical malformed input, which is how the
 *     hole survived: a short point looked "already rejected".
 *
 * Asymmetry is the theme. Under-length inputs already abort by accident
 * (`OP_SPLIT` runs off the end of the value), over-length inputs were silently
 * truncated. So this fix introduces NO new failure channel — it makes the
 * existing one explicit and total.
 *
 * Semantics chosen, and why they differ by builtin:
 *   - `*OnCurve` is a PREDICATE over untrusted bytes. "Is this a valid point?"
 *     has a correct answer for a wrong-length blob, and it is `false`.
 *     Aborting would break `if (ecOnCurve(p)) {...} else {...}` — the exact
 *     idiom this codegen's own comments tell authors to write. So it clamps
 *     and ANDs a length flag into the result, the same shape `cEmitLengthGate`
 *     already used for the ECDSA signature/pubkey arguments.
 *   - every other Point consumer produces a VALUE with no error channel
 *     (`ecAdd`, `ecMul`, `ecNegate`, `ecPointX`, `ecPointY`,
 *     `*EncodeCompressed`). There is no correct value to return for a blob
 *     that is not a point, so the length check is an `OP_NUMEQUALVERIFY`.
 *
 * Everything below is EXECUTED on @bsv/sdk's `Spend`. Hex-to-hex comparison
 * would only have proved the seven tiers agree, which they did — wrongly.
 */

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

interface Run { aborted: boolean; truthy: boolean; top: string; error?: string }

function run(args: string[], emitFn: (e: (op: StackOp) => void) => void): Run {
  const ops: StackOp[] = [];
  for (const h of args) ops.push({ op: 'push', value: bytes(h) } as StackOp);
  emitFn((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex);
  return {
    aborted: r.error !== undefined,
    truthy: r.success,
    top: r.stack.length ? hex(r.stack[r.stack.length - 1]!) : '',
    error: r.error,
  };
}

/** Same, with a bigint scalar pushed after the point (for `*Mul`). */
function runMul(point: string, k: bigint, emitFn: (e: (op: StackOp) => void) => void): Run {
  const ops: StackOp[] = [{ op: 'push', value: bytes(point) } as StackOp, { op: 'push', value: k } as StackOp];
  emitFn((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex);
  return { aborted: r.error !== undefined, truthy: r.success, top: r.stack.length ? hex(r.stack[r.stack.length - 1]!) : '', error: r.error };
}

const CURVES = {
  secp256k1: {
    w: 32,
    gx: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    gy: '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', // last byte b8, EVEN
    /** A trailing byte of the OPPOSITE parity to y's real last byte. */
    flipByte: '01',
    emitAdd: emitEcAdd, emitMul: emitEcMul, emitNegate: emitEcNegate,
    emitOnCurve: emitEcOnCurve, emitEncode: emitEcEncodeCompressed,
  },
  p256: {
    w: 32,
    gx: '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
    gy: '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', // last byte f5, ODD
    flipByte: '02',
    emitAdd: emitP256Add, emitMul: emitP256Mul, emitNegate: emitP256Negate,
    emitOnCurve: emitP256OnCurve, emitEncode: emitP256EncodeCompressed,
  },
  p384: {
    w: 48,
    gx: 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
    gy: '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f', // last byte 5f, ODD
    flipByte: '02',
    emitAdd: emitP384Add, emitMul: emitP384Mul, emitNegate: emitP384Negate,
    emitOnCurve: emitP384OnCurve, emitEncode: emitP384EncodeCompressed,
  },
} as const;

describe.each(Object.entries(CURVES))('R-052 Point length gate — %s', (_name, C) => {
  const G = C.gx + C.gy;
  const LONG = G + C.flipByte;           // one byte too many
  const LONGER = G + '00'.repeat(C.w);   // a whole extra coordinate

  // --- CONTROLS: a legitimate point must still work exactly as before -------
  it('CONTROL — onCurve(G) is still true', () => {
    const r = run([G], C.emitOnCurve);
    expect(r.aborted).toBe(false);
    expect(r.truthy).toBe(true);
  });

  it('CONTROL — add / mul / negate / encode on a real point still succeed', () => {
    expect(run([G, G], C.emitAdd).aborted).toBe(false);
    expect(runMul(G, 3n, C.emitMul).aborted).toBe(false);
    expect(run([G], C.emitNegate).aborted).toBe(false);
    const enc = run([G], C.emitEncode);
    expect(enc.aborted).toBe(false);
    expect(enc.top).toHaveLength(2 * (C.w + 1));
    expect(enc.top.slice(2)).toBe(C.gx);
  });

  it('CONTROL — negate(negate(G)) round-trips to G through the gate', () => {
    const once = run([G], C.emitNegate);
    expect(once.aborted).toBe(false);
    const twice = run([once.top], C.emitNegate);
    expect(twice.aborted).toBe(false);
    expect(twice.top).toBe(G);
  });

  // --- ASSERTION 1 ---------------------------------------------------------
  it('ASSERTION 1 — onCurve(G ‖ surplus) is FALSE, not true', () => {
    const r = run([LONG], C.emitOnCurve);
    expect(r.aborted).toBe(false);      // a predicate answers, it does not abort
    expect(r.truthy).toBe(false);
  });

  it('ASSERTION 1 — onCurve(G ‖ a whole extra coordinate) is FALSE', () => {
    const r = run([LONGER], C.emitOnCurve);
    expect(r.aborted).toBe(false);
    expect(r.truthy).toBe(false);
  });

  // --- ASSERTION 3 ---------------------------------------------------------
  it('ASSERTION 3 — an appended byte cannot flip the compressed parity', () => {
    const base = run([G], C.emitEncode);
    expect(base.aborted).toBe(false);
    const long = run([LONG], C.emitEncode);
    // Either the over-length blob is rejected outright, or it compresses to
    // exactly what the real 2w-byte point compresses to. What it must NEVER do
    // is succeed with a different prefix byte.
    if (!long.aborted) expect(long.top).toBe(base.top);
    expect(long.aborted || long.top === base.top).toBe(true);
  });

  // --- value-producing consumers reject a wrong-length Point ---------------
  it('over-length Point is rejected by add / mul / negate / encode', () => {
    expect(run([LONG, G], C.emitAdd).aborted).toBe(true);
    expect(run([G, LONG], C.emitAdd).aborted).toBe(true);
    expect(runMul(LONG, 3n, C.emitMul).aborted).toBe(true);
    expect(run([LONG], C.emitNegate).aborted).toBe(true);
    expect(run([LONG], C.emitEncode).aborted).toBe(true);
  });

  it('under-length Point is rejected by add / mul / negate / encode / onCurve', () => {
    const SHORT = G.slice(0, 2 * (2 * C.w - 1));
    expect(run([SHORT, G], C.emitAdd).aborted).toBe(true);
    expect(runMul(SHORT, 3n, C.emitMul).aborted).toBe(true);
    expect(run([SHORT], C.emitNegate).aborted).toBe(true);
    expect(run([SHORT], C.emitEncode).aborted).toBe(true);
    const oc = run([SHORT], C.emitOnCurve);
    expect(oc.truthy).toBe(false);
  });
});

// --- ASSERTION 2: secp256k1 coordinate accessors --------------------------
describe('R-052 Point length gate — ecPointX / ecPointY', () => {
  const C = CURVES.secp256k1;
  const G = C.gx + C.gy;

  it('CONTROL — ecPointX(G) and ecPointY(G) still return the coordinates', () => {
    const x = run([G], emitEcPointX);
    expect(x.aborted).toBe(false);
    // BIN2NUM of the reversed big-endian bytes: the top of stack is the
    // little-endian minimal script number, so compare against that spelling.
    expect(x.top).toBe(hex(bytes(C.gx).reverse()));
    const y = run([G], emitEcPointY);
    expect(y.aborted).toBe(false);
    expect(y.top).toBe(hex(bytes(C.gy).reverse()));
  });

  it('ASSERTION 2 — ecPointX on a 32-byte input FAILS', () => {
    expect(run([C.gx], emitEcPointX).aborted).toBe(true);
  });

  it('ecPointY on a 32-byte input fails (already did; pinned so it stays)', () => {
    expect(run([C.gx], emitEcPointY).aborted).toBe(true);
  });

  it('ecPointX / ecPointY on an over-length Point FAIL', () => {
    expect(run([G + '01'], emitEcPointX).aborted).toBe(true);
    expect(run([G + '01'], emitEcPointY).aborted).toBe(true);
  });
});
