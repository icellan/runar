// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/fixed-array-write.json
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

/**
 * R-094 / R-106 — the runtime-index WRITE (`this.table[i]++`) at the examples
 * layer.
 *
 * This is the construct N-019 was a fund-loss defect in: the increment's
 * operand was rewritten into a read dispatch, the write was dropped, and the
 * method emitted no state continuation while still compiling. The bytes are
 * pinned by the conformance fixture and the post-spend state by the real-crypto
 * witness; here the same property is read a third way, off the interpreter.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'ArrayWrite.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const table = (c: { state: Record<string, unknown> }) => c.state.table as bigint[];

describe('ArrayWrite (dynamic-index increment)', () => {
  it.each([0n, 1n, 2n, 3n])('bump(%s) increments exactly that slot', (i) => {
    const c = TestContract.fromSource(source, {}, FILE);
    const r = c.call('bump', { i });
    expect(r.success, r.error).toBe(true);

    const expected = [0n, 0n, 0n, 0n];
    expected[Number(i)] = 1n;
    expect(
      table(c),
      'a write that lands on the wrong slot — or on none — is N-019 exactly',
    ).toEqual(expected);
  });

  it('two bumps of the same slot accumulate', () => {
    const c = TestContract.fromSource(source, {}, FILE);
    c.call('bump', { i: 2n });
    c.call('bump', { i: 2n });
    expect(table(c)).toEqual([0n, 0n, 2n, 0n]);
  });

  it('an out-of-range index writes nothing at all', () => {
    const c = TestContract.fromSource(source, {}, FILE);
    c.call('bump', { i: 9n });
    expect(
      table(c),
      'falling through to slot 0 would be worse than failing',
    ).toEqual([0n, 0n, 0n, 0n]);
  });
});
