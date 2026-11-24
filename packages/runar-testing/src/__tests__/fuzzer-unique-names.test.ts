/**
 * The contract generators must never declare two properties, or two
 * parameters of one method, with the same name.
 *
 * Property and parameter names are drawn from `prop0..99` / `param0..99` and
 * de-duplicated by appending `X`. The de-dup appended ONE `X`, so a third draw
 * of the same name produced a second `prop62X`. Every compiler refuses a
 * contract with duplicate properties (its constructor cannot initialise both
 * slots), so the nightly fuzzer reported compile errors instead of testing
 * anything (seed 236002632: FuzzContract90, property `prop62X`).
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  arbGeneratedContract,
  arbGeneratedStatefulContract,
  type GeneratedContract,
} from '../fuzzer/index.js';

const SEED = 236002632;
const RUNS = 20000;

function duplicates(names: string[]): string[] {
  const seen = new Set<string>();
  return names.filter((n) => (seen.has(n) ? true : (seen.add(n), false)));
}

function nameDuplicates(c: GeneratedContract): string[] {
  const dups = duplicates(c.properties.map((p) => p.name));
  for (const m of c.methods) dups.push(...duplicates(m.params.map((p) => p.name)));
  return dups;
}

describe('fuzzer generators draw unique property and parameter names', () => {
  for (const [label, arb] of [
    ['stateless', arbGeneratedContract],
    ['stateful', arbGeneratedStatefulContract],
  ] as const) {
    it(label, () => {
      const bad = fc
        .sample(arb, { seed: SEED, numRuns: RUNS })
        .map((c) => ({ name: c.name, dups: nameDuplicates(c) }))
        .filter((r) => r.dups.length > 0);
      expect(bad).toEqual([]);
    });
  }
});
