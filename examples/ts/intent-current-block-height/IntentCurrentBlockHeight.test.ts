// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/intent-current-block-height.json
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

/**
 * R-106 — `intent-current-block-height` had no test in any of the nine formats.
 *
 * `currentBlockHeight()` is one of the three cross-tier intent intrinsics that
 * this audit also found documented only in a niche pattern doc. It desugars to
 * a read of the preimage's locktime, so the deadline comparison is a REAL
 * guard — and a guard is only tested by the call that must fail.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'IntentCurrentBlockHeight.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

describe('IntentCurrentBlockHeight (a deadline guard on the preimage locktime)', () => {
  it('spends before the deadline and advances the counter', () => {
    const c = TestContract.fromSource(source, { deadline: 800_000n, count: 0n }, FILE);
    c.setMockPreimage({ locktime: 799_999n });
    const r = c.call('spend', {});
    expect(r.success, r.error).toBe(true);
    expect(c.state.count).toBe(1n);
  });

  it('spends exactly AT the deadline — the comparison is <=', () => {
    const c = TestContract.fromSource(source, { deadline: 800_000n, count: 0n }, FILE);
    c.setMockPreimage({ locktime: 800_000n });
    expect(c.call('spend', {}).success).toBe(true);
  });

  it('FAILS past the deadline', () => {
    const c = TestContract.fromSource(source, { deadline: 800_000n, count: 0n }, FILE);
    c.setMockPreimage({ locktime: 800_001n });
    expect(
      c.call('spend', {}).success,
      'if this passes, the height guard is decoration and the contract is ' +
        'spendable forever',
    ).toBe(false);
  });

  it('a failed spend does not advance the counter', () => {
    const c = TestContract.fromSource(source, { deadline: 10n, count: 5n }, FILE);
    c.setMockPreimage({ locktime: 999n });
    c.call('spend', {});
    expect(c.state.count).toBe(5n);
  });
});
