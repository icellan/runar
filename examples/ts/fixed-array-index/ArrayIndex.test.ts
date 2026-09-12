import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, runDifferentialExecution } from 'runar-testing';

/**
 * R-094 / R-106 — the runtime-index READ of a FixedArray, at the examples layer.
 *
 * The conformance fixture pins the bytes across seven tiers and the witness
 * executes five spends; this is the third, independent reading: the ANF
 * interpreter running the SOURCE. The dispatch chain the expand pass builds is
 * a comparison per slot, so the cases that matter are the ends of the chain and
 * an index that falls off it.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'ArrayIndex.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

describe('ArrayIndex (dynamic-index read)', () => {
  it.each([
    [0n, 10n],
    [1n, 20n],
    [2n, 30n],
    [3n, 40n],
  ])('table[%s] is %s', (i, expected) => {
    const c = TestContract.fromSource(source, {}, FILE);
    const r = c.call('lookup', { i, expected });
    expect(r.success, r.error).toBe(true);
  });

  it('a wrong expectation fails', () => {
    const c = TestContract.fromSource(source, {}, FILE);
    expect(c.call('lookup', { i: 1n, expected: 30n }).success).toBe(false);
  });

  it('an index past the end does not fall through to a neighbour', () => {
    const c = TestContract.fromSource(source, {}, FILE);
    expect(
      c.call('lookup', { i: 4n, expected: 10n }).success,
      'the dispatch chain must terminate in a failure, not wrap to slot 0',
    ).toBe(false);
  });

  it('the interpreter and the ScriptVM agree', () => {
    const r = runDifferentialExecution({
      source,
      fileName: FILE,
      method: 'lookup',
      args: [2n, 30n],
    });
    expect(r.agrees, `interpreter=${r.interpreterAccepted} vm=${r.vmAccepted}`).toBe(true);
  });
});
