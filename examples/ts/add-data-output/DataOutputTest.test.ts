import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'DataOutputTest.runar.ts'), 'utf8');

describe('DataOutputTest', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { count: 0n });
    expect(c.state.count).toBe(0n);
  });

  it('publish increments count and emits a data output', () => {
    const c = TestContract.fromSource(source, { count: 0n });
    const r = c.call('publish', { payload: '6a0568656c6c6f' });
    expect(r.success).toBe(true);
    expect(c.state.count).toBe(1n);
    // The interpreter records the addDataOutput as a tagged output entry.
    expect(r.outputs!.some((o) => '_dataScript' in (o as object))).toBe(true);
  });

  it('publish twice tracks state across calls', () => {
    const c = TestContract.fromSource(source, { count: 0n });
    expect(c.call('publish', { payload: '6a01' }).success).toBe(true);
    expect(c.call('publish', { payload: '6a02' }).success).toBe(true);
    expect(c.state.count).toBe(2n);
  });
});
