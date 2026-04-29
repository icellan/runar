import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BabyBearExt4Demo.runar.sol'), 'utf8');
const FILE_NAME = 'BabyBearExt4Demo.runar.sol';

// Multiplication by the Ext4 identity (1, 0, 0, 0) leaves (a0, a1, a2, a3)
// unchanged, which lets us pin a known-good vector without reaching for the
// full Ext4 mul reference.
describe('BabyBearExt4Demo (Solidity)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, {}, FILE_NAME);
    expect(c).toBeDefined();
  });

  it('checkMul: (7,11,13,17) * (1,0,0,0) = (7,11,13,17)', () => {
    const c = TestContract.fromSource(source, {}, FILE_NAME);
    const r = c.call('checkMul', {
      a0: 7n, a1: 11n, a2: 13n, a3: 17n,
      b0: 1n, b1: 0n, b2: 0n, b3: 0n,
      e0: 7n, e1: 11n, e2: 13n, e3: 17n,
    });
    expect(r.success).toBe(true);
  });

  it('checkMul rejects a wrong product', () => {
    const c = TestContract.fromSource(source, {}, FILE_NAME);
    const r = c.call('checkMul', {
      a0: 7n, a1: 11n, a2: 13n, a3: 17n,
      b0: 1n, b1: 0n, b2: 0n, b3: 0n,
      e0: 0n, e1: 0n, e2: 0n, e3: 0n,
    });
    expect(r.success).toBe(false);
  });
});
