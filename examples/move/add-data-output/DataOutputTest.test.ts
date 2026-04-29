import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'DataOutputTest.runar.move'), 'utf8');
const FILE_NAME = 'DataOutputTest.runar.move';

describe('DataOutputTest (Move)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { count: 0n }, FILE_NAME);
    expect(c.state.count).toBe(0n);
  });

  it('publish increments count and emits a data output', () => {
    const c = TestContract.fromSource(source, { count: 0n }, FILE_NAME);
    const r = c.call('publish', { payload: '6a0568656c6c6f' });
    expect(r.success).toBe(true);
    expect(c.state.count).toBe(1n);
    expect(r.outputs!.some((o) => '_dataScript' in (o as object))).toBe(true);
  });
});
