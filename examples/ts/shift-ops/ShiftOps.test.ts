import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'ShiftOps.runar.ts'), 'utf8');

// testShift's asserts are tautologies — we only verify it compiles + runs.
describe('ShiftOps', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { a: 42n });
    expect(c.state.a).toBe(42n);
  });

  it('testShift runs on a positive value', () => {
    const c = TestContract.fromSource(source, { a: 42n });
    const r = c.call('testShift');
    expect(r.success).toBe(true);
  });

  it('testShift runs on zero', () => {
    const c = TestContract.fromSource(source, { a: 0n });
    const r = c.call('testShift');
    expect(r.success).toBe(true);
  });
});
