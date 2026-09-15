import { describe, it, expect } from 'vitest';
import { emitMethod, emitEcMakePoint, emitEcPointX, emitEcPointY, emitEcOnCurve } from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * R-156 — `ecMakePoint(x, y)` threw away the sign byte and the top bits, so it
 * was not injective: infinitely many `(x, y)` pairs produced the SAME Point.
 *
 * The emitter is, per coordinate:
 *
 *     push 33, OP_NUM2BIN, push 32, OP_SPLIT, OP_DROP, <reverse32>
 *
 * NUM2BIN(33) writes a 33-byte little-endian SIGN-MAGNITUDE script number, so
 * byte 32 is exactly where the sign bit lives AND where any bits ≥ 2^256 land.
 * `OP_SPLIT 32` + `OP_DROP` discards precisely that byte. Two consequences,
 * both measured on @bsv/sdk's Spend before this commit:
 *
 *     ecMakePoint( 1n, y) == ecMakePoint(-1n, y)              sign discarded
 *     ecMakePoint( 1n, y) == ecMakePoint(1n + 2^256, y)       magnitude truncated
 *     ecMakePoint(x,  y)  == ecMakePoint(x, -y)               and on the y half too
 *
 * The y-half collision is the sharpest of the three, because `-y` is how a
 * contract author spells point negation by hand: `ecMakePoint(x, 0n - y)`
 * silently produced (x, +y) — the point you were trying to negate — rather
 * than (x, p-y) or an error.
 *
 * R-117's coordinate-canonicity gate does NOT cover this and cannot: the bytes
 * `ecMakePoint` emits for `-1n` are the perfectly canonical encoding of 1. The
 * aliasing happens before any Point exists.
 *
 * FIXED BY REJECTING, consistent with every other value-producing Point
 * builtin: each coordinate must be a field element, `0 <= v < p`, checked with
 * OP_WITHIN and OP_VERIFY. Reducing mod p was considered and rejected for the
 * same reason as in R-117 — `ecOnCurve` answers "no" to a coordinate outside
 * [0, p), so reducing here would leave the constructor and the predicate
 * disagreeing about what a point is. Rejecting also keeps `ecMakePoint`
 * INJECTIVE on its accepted domain, which is the property the defect broke.
 */

const bytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const be32 = (n: bigint) => n.toString(16).padStart(64, '0');

function mk(x: bigint, y: bigint) {
  const ops: StackOp[] = [
    { op: 'push', value: x } as StackOp,
    { op: 'push', value: y } as StackOp,
  ];
  emitEcMakePoint((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex);
  return {
    rejected: r.error !== undefined,
    point: r.stack.length ? hex(r.stack[r.stack.length - 1]!) : '',
  };
}

function roundTrip(point: string, which: 'x' | 'y') {
  const ops: StackOp[] = [{ op: 'push', value: bytes(point) } as StackOp];
  (which === 'x' ? emitEcPointX : emitEcPointY)((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex);
  const top = r.stack[r.stack.length - 1]!;
  // Script numbers are little-endian sign-magnitude; these are all unsigned.
  return BigInt('0x' + (hex(top).match(/../g) ?? []).reverse().join('') || '0');
}

// A genuine secp256k1 point with the smallest possible x.
const GX = 1n;
const GY = 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7een;

describe('R-156 ecMakePoint is injective: the sign byte and the top bits are no longer discarded', () => {
  it('CONTROL — the honest call still builds the point it is asked for', () => {
    const r = mk(GX, GY);
    expect(r.rejected).toBe(false);
    expect(r.point).toBe(be32(GX) + be32(GY));
    // …and it is a real curve point, so the constructor has not been broken.
    const ops: StackOp[] = [{ op: 'push', value: bytes(r.point) } as StackOp];
    emitEcOnCurve((op) => ops.push(op));
    const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
    expect(new ScriptVM().executeHex(scriptHex).success).toBe(true);
  });

  it('CONTROL — round-trips through ecPointX / ecPointY', () => {
    const r = mk(GX, GY);
    expect(roundTrip(r.point, 'x')).toBe(GX);
    expect(roundTrip(r.point, 'y')).toBe(GY);
  });

  it('ASSERTION — a NEGATIVE x is rejected, not silently made positive', () => {
    expect(mk(-1n, GY).rejected).toBe(true);
  });

  it('ASSERTION — a NEGATIVE y is rejected: `ecMakePoint(x, 0n - y)` must not yield (x, +y)', () => {
    expect(mk(GX, -GY).rejected).toBe(true);
  });

  it('ASSERTION — x >= 2^256 is rejected, not truncated', () => {
    expect(mk(1n + (1n << 256n), GY).rejected).toBe(true);
  });

  it('ASSERTION — y >= 2^256 is rejected, not truncated', () => {
    expect(mk(GX, GY + (1n << 256n)).rejected).toBe(true);
  });

  it('ASSERTION — the three historical collisions can no longer happen', () => {
    const base = mk(GX, GY);
    for (const alias of [mk(-GX, GY), mk(GX + (1n << 256n), GY), mk(GX, -GY)]) {
      expect(alias.rejected).toBe(true);
      expect(alias.point).not.toBe(base.point);
    }
  });

  it('BOUNDARY — p-1 is accepted on both halves, p is rejected on both', () => {
    expect(mk(FIELD_P - 1n, GY).rejected).toBe(false);
    expect(mk(GX, FIELD_P - 1n).rejected).toBe(false);
    expect(mk(FIELD_P, GY).rejected).toBe(true);
    expect(mk(GX, FIELD_P).rejected).toBe(true);
  });

  it('BOUNDARY — zero is accepted on both halves: O is a legal value here', () => {
    const o = mk(0n, 0n);
    expect(o.rejected).toBe(false);
    expect(o.point).toBe('00'.repeat(64));
  });
});
