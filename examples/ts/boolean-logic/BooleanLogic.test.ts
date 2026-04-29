import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BooleanLogic.runar.ts'), 'utf8');

describe('BooleanLogic', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { threshold: 10n });
    expect(c.state.threshold).toBe(10n);
  });

  it('verify passes when both inputs are above the threshold', () => {
    const c = TestContract.fromSource(source, { threshold: 10n });
    const r = c.call('verify', { a: 20n, b: 30n, flag: true });
    expect(r.success).toBe(true);
  });

  it('verify passes when one input is above and flag is false', () => {
    const c = TestContract.fromSource(source, { threshold: 10n });
    const r = c.call('verify', { a: 20n, b: 5n, flag: false });
    expect(r.success).toBe(true);
  });

  it('verify rejects when neither is above threshold', () => {
    const c = TestContract.fromSource(source, { threshold: 10n });
    const r = c.call('verify', { a: 1n, b: 2n, flag: false });
    expect(r.success).toBe(false);
  });
});
