import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'tsop-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Counter.tsop.ts'), 'utf8');

describe('Counter', () => {
  it('starts with the initial count', () => {
    const counter = TestContract.fromSource(source, { count: 0n });
    expect(counter.state.count).toBe(0n);
  });

  it('increments the count', () => {
    const counter = TestContract.fromSource(source, { count: 0n });
    const result = counter.call('increment');
    expect(result.success).toBe(true);
    expect(counter.state.count).toBe(1n);
  });

  it('decrements the count', () => {
    const counter = TestContract.fromSource(source, { count: 5n });
    const result = counter.call('decrement');
    expect(result.success).toBe(true);
    expect(counter.state.count).toBe(4n);
  });

  it('rejects decrement at zero', () => {
    const counter = TestContract.fromSource(source, { count: 0n });
    const result = counter.call('decrement');
    expect(result.success).toBe(false);
  });

  it('tracks state across multiple calls', () => {
    const counter = TestContract.fromSource(source, { count: 0n });

    counter.call('increment');
    counter.call('increment');
    counter.call('increment');
    expect(counter.state.count).toBe(3n);

    counter.call('decrement');
    expect(counter.state.count).toBe(2n);
  });
});
