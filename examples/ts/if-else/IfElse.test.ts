import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'IfElse.runar.ts'), 'utf8');

describe('IfElse', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { limit: 5n });
    expect(c.state.limit).toBe(5n);
  });

  it('passes on the true branch (value + limit > 0)', () => {
    const c = TestContract.fromSource(source, { limit: 5n });
    const r = c.call('check', { value: 3n, mode: true });
    expect(r.success).toBe(true);
  });

  it('passes on the false branch (value - limit > 0)', () => {
    const c = TestContract.fromSource(source, { limit: 5n });
    const r = c.call('check', { value: 20n, mode: false });
    expect(r.success).toBe(true);
  });

  it('rejects when neither branch yields a positive result', () => {
    const c = TestContract.fromSource(source, { limit: 5n });
    const r = c.call('check', { value: 1n, mode: false });
    expect(r.success).toBe(false);
  });
});
