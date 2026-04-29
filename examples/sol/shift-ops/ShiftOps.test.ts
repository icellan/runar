import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'ShiftOps.runar.sol'), 'utf8');
const FILE_NAME = 'ShiftOps.runar.sol';

// testShift's asserts are tautologies — we only verify it compiles + runs.
describe('ShiftOps (Solidity)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { a: 42n }, FILE_NAME);
    expect(c.state.a).toBe(42n);
  });

  it('testShift runs on a positive value', () => {
    const c = TestContract.fromSource(source, { a: 42n }, FILE_NAME);
    expect(c.call('testShift').success).toBe(true);
  });

  it('testShift runs on zero', () => {
    const c = TestContract.fromSource(source, { a: 0n }, FILE_NAME);
    expect(c.call('testShift').success).toBe(true);
  });
});
