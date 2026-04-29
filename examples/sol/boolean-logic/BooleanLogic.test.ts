import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BooleanLogic.runar.sol'), 'utf8');
const FILE_NAME = 'BooleanLogic.runar.sol';

describe('BooleanLogic (Solidity)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { threshold: 10n }, FILE_NAME);
    expect(c.state.threshold).toBe(10n);
  });

  it('passes when both inputs are above threshold', () => {
    const c = TestContract.fromSource(source, { threshold: 10n }, FILE_NAME);
    expect(c.call('verify', { a: 20n, b: 30n, flag: true }).success).toBe(true);
  });

  it('passes when one input is above and flag is false', () => {
    const c = TestContract.fromSource(source, { threshold: 10n }, FILE_NAME);
    expect(c.call('verify', { a: 20n, b: 5n, flag: false }).success).toBe(true);
  });

  it('rejects when neither is above threshold', () => {
    const c = TestContract.fromSource(source, { threshold: 10n }, FILE_NAME);
    expect(c.call('verify', { a: 1n, b: 2n, flag: false }).success).toBe(false);
  });
});
