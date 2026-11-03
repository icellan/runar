import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'ShiftOps.runar.ts'), 'utf8');

// The caller supplies the expected shift results and the contract checks them
// (F-167: it used to assert only tautologies, so no input could fail). The
// wrong-value cases run on the interpreter only; the on-chain verdict for the
// same values is pinned by conformance/witnesses/real-crypto/shift-ops.json.
describe('ShiftOps', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { a: 42n });
    expect(c.state.a).toBe(42n);
  });

  it('testShift accepts the correct results (12 << 3 = 96, 12 >> 2 = 3)', () => {
    const c = TestContract.fromSource(source, { a: 12n });
    const r = c.call('testShift', { expectedLeft: 96n, expectedRight: 3n });
    expect(r.success).toBe(true);
  });

  it('testShift REJECTS a wrong left-shift result', () => {
    const c = TestContract.fromSource(source, { a: 12n });
    const r = c.call('testShift', { expectedLeft: 97n, expectedRight: 3n });
    expect(r.success).toBe(false);
  });

  it('testShift REJECTS a wrong right-shift result', () => {
    const c = TestContract.fromSource(source, { a: 12n });
    const r = c.call('testShift', { expectedLeft: 96n, expectedRight: 2n });
    expect(r.success).toBe(false);
  });

  it('testShift runs on zero', () => {
    const c = TestContract.fromSource(source, { a: 0n });
    const r = c.call('testShift', { expectedLeft: 0n, expectedRight: 0n });
    expect(r.success).toBe(true);
  });
});
