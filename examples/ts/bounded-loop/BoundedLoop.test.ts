import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BoundedLoop.runar.ts'), 'utf8');

describe('BoundedLoop', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { expectedSum: 10n });
    expect(c.state.expectedSum).toBe(10n);
  });

  it('verify accepts the expected sum from start=0', () => {
    // sum_{i=0..4} (0+i) = 0+1+2+3+4 = 10
    const c = TestContract.fromSource(source, { expectedSum: 10n });
    const r = c.call('verify', { start: 0n });
    expect(r.success).toBe(true);
  });

  it('verify accepts the expected sum from start=2', () => {
    // sum_{i=0..4} (2+i) = 5*2 + 10 = 20
    const c = TestContract.fromSource(source, { expectedSum: 20n });
    const r = c.call('verify', { start: 2n });
    expect(r.success).toBe(true);
  });

  it('verify rejects mismatched expected sum', () => {
    const c = TestContract.fromSource(source, { expectedSum: 999n });
    const r = c.call('verify', { start: 0n });
    expect(r.success).toBe(false);
  });
});
