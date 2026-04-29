import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BitwiseOps.runar.sol'), 'utf8');
const FILE_NAME = 'BitwiseOps.runar.sol';

// The asserts inside testShift / testBitwise are tautologies, so any non-erroring
// run successfully exercises the operators.
describe('BitwiseOps (Solidity)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { a: 42n, b: 17n }, FILE_NAME);
    expect(c.state.a).toBe(42n);
  });

  it('testShift runs on positive values', () => {
    const c = TestContract.fromSource(source, { a: 42n, b: 17n }, FILE_NAME);
    expect(c.call('testShift').success).toBe(true);
  });

  it('testBitwise runs on positive values', () => {
    const c = TestContract.fromSource(source, { a: 42n, b: 17n }, FILE_NAME);
    expect(c.call('testBitwise').success).toBe(true);
  });
});
