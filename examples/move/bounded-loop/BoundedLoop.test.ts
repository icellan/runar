import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BoundedLoop.runar.move'), 'utf8');
const FILE_NAME = 'BoundedLoop.runar.move';

describe('BoundedLoop (Move)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { expectedSum: 10n }, FILE_NAME);
    expect(c.state.expectedSum).toBe(10n);
  });

  it('verify accepts the expected sum from start=0 (10)', () => {
    const c = TestContract.fromSource(source, { expectedSum: 10n }, FILE_NAME);
    expect(c.call('verify', { start: 0n }).success).toBe(true);
  });

  it('verify accepts the expected sum from start=2 (20)', () => {
    const c = TestContract.fromSource(source, { expectedSum: 20n }, FILE_NAME);
    expect(c.call('verify', { start: 2n }).success).toBe(true);
  });

  it('verify rejects mismatched expected sum', () => {
    const c = TestContract.fromSource(source, { expectedSum: 999n }, FILE_NAME);
    expect(c.call('verify', { start: 0n }).success).toBe(false);
  });
});
