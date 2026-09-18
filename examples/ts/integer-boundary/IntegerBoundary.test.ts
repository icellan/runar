import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, runDifferentialExecution } from 'runar-testing';

/**
 * R-106 — `integer-boundary` had no test in any of the nine formats.
 *
 * It exists to prove that Rúnar's `bigint` is genuinely arbitrary-precision
 * on chain: the four constants straddle every boundary a 32- or 64-bit
 * implementation would quietly wrap at (2^32-1 squared, int64 max + 1, 2^64,
 * int64 max squared). The whole point is the exact total, so the test names it
 * — computed independently here, not copied from compiler output.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'IntegerBoundary.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const P = 4294967295n * 4294967295n;          // (2^32 - 1)^2
const Q = 9223372036854775807n + 1n;          // int64 max + 1
const R = 4294967296n * 4294967296n;          // 2^64
const S = 9223372036854775807n * 9223372036854775807n;
const SUM = P + Q + R + S;

describe('IntegerBoundary (bigint is arbitrary precision, not int64)', () => {
  it('the constants really do exceed 64 bits', () => {
    expect(SUM > 2n ** 64n).toBe(true);
    expect(SUM).toBe(85070591730234615893513767959916445698n);
  });

  it('accepts delta 0 against the exact sum', () => {
    const c = TestContract.fromSource(source, { target: SUM }, FILE);
    const r = c.call('verify', { delta: 0n });
    expect(r.success, r.error).toBe(true);
  });

  it('accepts a shifted target with the matching delta', () => {
    const c = TestContract.fromSource(source, { target: SUM + 12345n }, FILE);
    expect(c.call('verify', { delta: 12345n }).success).toBe(true);
  });

  it('rejects an off-by-one — no silent wrap makes it fit', () => {
    const c = TestContract.fromSource(source, { target: SUM }, FILE);
    expect(c.call('verify', { delta: 1n }).success).toBe(false);
    expect(c.call('verify', { delta: -1n }).success).toBe(false);
  });

  it('rejects a target truncated to 64 bits', () => {
    const truncated = SUM & (2n ** 64n - 1n);
    expect(truncated, 'the truncation must actually differ').not.toBe(SUM);
    const c = TestContract.fromSource(source, { target: truncated }, FILE);
    expect(
      c.call('verify', { delta: 0n }).success,
      'an implementation that wrapped to 64 bits would accept this',
    ).toBe(false);
  });

  it('the interpreter and the ScriptVM agree on the accepting case', () => {
    const r = runDifferentialExecution({
      source,
      fileName: FILE,
      method: 'verify',
      args: [0n],
      constructorArgs: { target: SUM },
    });
    expect(r.agrees, `interpreter=${r.interpreterAccepted} vm=${r.vmAccepted}`).toBe(true);
  });
});
