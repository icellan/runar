import { describe, it, expect } from 'vitest';
import { ecMakePoint } from '../runtime/index.js';

// N-183: the native TS runtime's ecMakePoint must apply the compiled script's
// R-156 gate: each coordinate must satisfy 0 <= v < p, or the script aborts.
// Before the fix it built a (possibly longer than 64 byte, or "-1"-containing)
// string from any bigint.
//
// Proves: boundary operands (p, p+1, -1, 2^256 on either half) throw, and
// p - 1 / 0 / a real curve point still build the 64-byte point.
// Does not prove: the script itself (packages/runar-testing r156 test pins it).

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const GY = 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7een;
const be32 = (n: bigint) => n.toString(16).padStart(64, '0');

describe('N-183: runar-lang ecMakePoint applies the R-156 field gate', () => {
  const abort: Array<[string, bigint, bigint]> = [
    ['x = p', P, GY],
    ['x = p + 1', P + 1n, GY],
    ['y = p', 1n, P],
    ['y = p + 1', 1n, P + 1n],
    ['x = -1', -1n, GY],
    ['y = -1', 1n, -1n],
    ['x = 2^256', 1n << 256n, GY],
    ['y = 2^256 + 1', 1n, (1n << 256n) + 1n],
  ];
  for (const [why, x, y] of abort) {
    it(`throws: ${why}`, () => {
      expect(() => ecMakePoint(x, y)).toThrow();
    });
  }
  it('control: p - 1, 0 and a real curve point build', () => {
    expect(ecMakePoint(P - 1n, P - 1n) as unknown as string).toBe(be32(P - 1n) + be32(P - 1n));
    expect(ecMakePoint(0n, 0n) as unknown as string).toBe(be32(0n) + be32(0n));
    expect(ecMakePoint(1n, GY) as unknown as string).toBe(be32(1n) + be32(GY));
  });
});
