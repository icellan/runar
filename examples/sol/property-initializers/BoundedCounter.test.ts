import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BoundedCounter.runar.sol'), 'utf8');
const FILE_NAME = 'BoundedCounter.runar.sol';

describe('BoundedCounter (Solidity — Property Initializers)', () => {
  it('initializes count to 0 and active to true by default', () => {
    // Only maxCount is passed — count and active use their property initializers
    const counter = TestContract.fromSource(source, { maxCount: 10n }, FILE_NAME);
    // count defaults to 0
    expect(counter.state.count).toBe(0n);
    // active defaults to true — verified by increment succeeding (it requires active)
    const result = counter.call('increment', { amount: 1n });
    expect(result.success).toBe(true);
  });

  it('increments the count', () => {
    const counter = TestContract.fromSource(source, { maxCount: 10n }, FILE_NAME);
    const result = counter.call('increment', { amount: 3n });
    expect(result.success).toBe(true);
    expect(counter.state.count).toBe(3n);
  });

  it('rejects increment beyond max', () => {
    const counter = TestContract.fromSource(source, { maxCount: 5n }, FILE_NAME);
    const result = counter.call('increment', { amount: 6n });
    expect(result.success).toBe(false);
  });

  it('resets count to zero', () => {
    const counter = TestContract.fromSource(source, { maxCount: 10n }, FILE_NAME);
    counter.call('increment', { amount: 7n });
    expect(counter.state.count).toBe(7n);

    const result = counter.call('reset');
    expect(result.success).toBe(true);
    expect(counter.state.count).toBe(0n);
  });
});
