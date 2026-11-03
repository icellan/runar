/**
 * N-183 — the TestContract interpreter's `ecMakePoint` must apply the compiled
 * script's R-156 field-element gate: each coordinate must satisfy `0 <= v < p`
 * (OP_WITHIN + OP_VERIFY), otherwise the script aborts.
 *
 * Before the fix the interpreter wrote the low 256 bits of any bigint, so
 * `ecMakePoint(p, y)` returned a Point (aliasing x = 0), `ecMakePoint(-1n, y)`
 * returned the bytes of 2^256 - 1, and a coordinate >= 2^256 was silently
 * truncated.
 *
 * Proves: for crafted boundary operands (p, p+1, -1, 2^256, 2^256+1 on each
 * half) the interpreter fails the call exactly where the script aborts, and
 * still builds the point for p-1 and 0.
 * Does not prove: the script itself (r156-makepoint-injective.test.ts pins
 * that on @bsv/sdk Spend), or any other EC builtin.
 */
import { describe, it, expect } from 'vitest';
import { TestContract } from '../test-contract.js';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const GY = 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7een;
const be32 = (n: bigint) => n.toString(16).padStart(64, '0');

const source = [
  `import { SmartContract, assert, ecMakePoint } from 'runar-lang';`,
  `import type { Point } from 'runar-lang';`,
  `class N183MakePointProbe extends SmartContract {`,
  `  constructor() { super(); }`,
  `  public eq(x: bigint, y: bigint, e: Point) { assert(ecMakePoint(x, y) === e); }`,
  `}`,
].join('\n');

function call(x: bigint, y: bigint, e: string) {
  const c = TestContract.fromSource(source, {}, 'N183MakePointProbe.runar.ts');
  return c.call('eq', { x, y, e });
}

const ABORT: Array<[string, bigint, bigint]> = [
  ['x = p', P, GY],
  ['x = p + 1', P + 1n, GY],
  ['y = p', 1n, P],
  ['y = p + 1', 1n, P + 1n],
  ['x = -1', -1n, GY],
  ['y = -1', 1n, -1n],
  ['x = 2^256', 1n << 256n, GY],
  ['y = 2^256 + 1', 1n, (1n << 256n) + 1n],
];

describe('N-183: TestContract ecMakePoint applies the R-156 field gate (0 <= v < p)', () => {
  for (const [why, x, y] of ABORT) {
    it(`aborts: ${why}`, () => {
      // The witness is what a gate-less build would produce (low 256 bits),
      // so a pass here means the call itself was refused, not mismatched.
      const mask = (1n << 256n) - 1n;
      const r = call(x, y, be32(x & mask) + be32(y & mask));
      expect(r.success, `${why} must abort`).toBe(false);
    });
  }

  it('control: p - 1 on both halves still builds the point', () => {
    const r = call(P - 1n, P - 1n, be32(P - 1n) + be32(P - 1n));
    expect(r.success, r.error).toBe(true);
  });

  it('control: x = 0 and a real curve point still build', () => {
    expect(call(0n, 0n, be32(0n) + be32(0n)).success).toBe(true);
    expect(call(1n, GY, be32(1n) + be32(GY)).success).toBe(true);
  });
});
