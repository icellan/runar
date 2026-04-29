import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BitwiseOps.runar.ts'), 'utf8');

// The asserts inside testShift / testBitwise are tautologies (`x >= 0 || x < 0`)
// so any non-erroring run is a successful exercise of the operators.
describe('BitwiseOps', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { a: 42n, b: 17n });
    expect(c.state.a).toBe(42n);
    expect(c.state.b).toBe(17n);
  });

  it('testShift runs on positive values', () => {
    const c = TestContract.fromSource(source, { a: 42n, b: 17n });
    const r = c.call('testShift');
    expect(r.success).toBe(true);
  });

  it('testBitwise runs on positive values', () => {
    const c = TestContract.fromSource(source, { a: 42n, b: 17n });
    const r = c.call('testBitwise');
    expect(r.success).toBe(true);
  });

  it('testBitwise runs on zero', () => {
    const c = TestContract.fromSource(source, { a: 0n, b: 0n });
    const r = c.call('testBitwise');
    expect(r.success).toBe(true);
  });
});
