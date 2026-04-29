import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Stateful.runar.sol'), 'utf8');
const FILE_NAME = 'Stateful.runar.sol';

describe('Stateful (Solidity)', () => {
  it('initialises count and maxCount', () => {
    const c = TestContract.fromSource(source, { count: 0n, maxCount: 10n }, FILE_NAME);
    expect(c.state.count).toBe(0n);
    expect(c.state.maxCount).toBe(10n);
  });

  it('increments up to the maximum', () => {
    const c = TestContract.fromSource(source, { count: 0n, maxCount: 10n }, FILE_NAME);
    expect(c.call('increment', { amount: 3n }).success).toBe(true);
    expect(c.state.count).toBe(3n);
    expect(c.call('increment', { amount: 7n }).success).toBe(true);
    expect(c.state.count).toBe(10n);
  });

  it('rejects increments that exceed maxCount', () => {
    const c = TestContract.fromSource(source, { count: 0n, maxCount: 10n }, FILE_NAME);
    expect(c.call('increment', { amount: 11n }).success).toBe(false);
  });

  it('reset clears the count back to zero', () => {
    const c = TestContract.fromSource(source, { count: 5n, maxCount: 10n }, FILE_NAME);
    expect(c.call('reset').success).toBe(true);
    expect(c.state.count).toBe(0n);
  });
});
