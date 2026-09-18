// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/selector.json
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

/**
 * R-106 — `selector` is a regression fixture for deep-review finding C20 and
 * had no test anywhere in any of the nine formats.
 *
 * The defect it exists for: `liftBranchUpdateProps` dropped the terminal
 * `assert(false)` of a dispatch chain, so a selector matching NO branch
 * produced a spendable NO-OP state continuation instead of failing the script.
 * A fixture that only proves "this compiles" would have stayed green through
 * that, because the pre-fix compiler compiled it happily — it emitted the
 * wrong script.
 *
 * So the assertions are about the out-of-range path specifically.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Selector.runar.ts'), 'utf8');

describe('Selector (C20 — a dispatch chain must keep its terminal abort)', () => {
  it('selector 0 writes a and leaves b alone', () => {
    const c = TestContract.fromSource(source, { a: 1n, b: 2n });
    const r = c.call('set', { i: 0n, v: 99n });
    expect(r.success, r.error).toBe(true);
    expect(c.state.a).toBe(99n);
    expect(c.state.b).toBe(2n);
  });

  it('selector 1 writes b and leaves a alone', () => {
    const c = TestContract.fromSource(source, { a: 1n, b: 2n });
    const r = c.call('set', { i: 1n, v: 99n });
    expect(r.success, r.error).toBe(true);
    expect(c.state.a).toBe(1n);
    expect(c.state.b).toBe(99n);
  });

  it('an out-of-range selector ABORTS — it must not be a spendable no-op', () => {
    const c = TestContract.fromSource(source, { a: 1n, b: 2n });
    const r = c.call('set', { i: 2n, v: 99n });
    expect(
      r.success,
      'C20 verbatim: a selector matching no branch produced a spendable no-op ' +
        'continuation instead of failing',
    ).toBe(false);
  });

  it('a rejected dispatch leaves the state untouched', () => {
    const c = TestContract.fromSource(source, { a: 1n, b: 2n });
    c.call('set', { i: 7n, v: 99n });
    expect(c.state.a).toBe(1n);
    expect(c.state.b).toBe(2n);
  });
});
