import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'IfWithoutElse.runar.ts'), 'utf8');

describe('IfWithoutElse', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { threshold: 10n });
    expect(c.state.threshold).toBe(10n);
  });

  it('passes when one input is above the threshold', () => {
    const c = TestContract.fromSource(source, { threshold: 10n });
    const r = c.call('check', { a: 15n, b: 5n });
    expect(r.success).toBe(true);
  });

  it('passes when both inputs are above the threshold', () => {
    const c = TestContract.fromSource(source, { threshold: 10n });
    const r = c.call('check', { a: 15n, b: 20n });
    expect(r.success).toBe(true);
  });

  it('rejects when neither input is above the threshold', () => {
    const c = TestContract.fromSource(source, { threshold: 10n });
    const r = c.call('check', { a: 1n, b: 2n });
    expect(r.success).toBe(false);
  });
});
