/**
 * N-103 — the TS frontend must emit `syntheticArrayChain` in its ANF.
 *
 * `expandFixedArrays` replaces a `FixedArray` property with N scalar leaves and
 * marks each leaf with `__syntheticArrayChain` on the AST. The artifact
 * assembler consumes that chain to regroup the leaves back into a single
 * FixedArray state/ABI entry — an artifact without it degrades the SDK's
 * `state.grid` accessor into N raw scalars.
 *
 * N-095 made all six non-TS tiers write and read one spelling of that chain in
 * the ANF IR. TS was left out on the reasoning that it reads the chain off its
 * own AST and has no ANF-input mode, so it "need not emit it". That is true of
 * TS in isolation and false of the conformance gate: the multi-format runner
 * compares the TS tier's ANF against `expected-ir.json`, so the moment a
 * FixedArray fixture lands (R-094) TS becomes a 1-vs-6 ANF divergence.
 *
 * Measured before the fix, on `examples/ts/fixed-array-nested/Grid2x2.v2.runar.ts`:
 *
 *   go  --emit-ir   properties[0].syntheticArrayChain =
 *                     [{base: grid, index: 0, length: 2},
 *                      {base: grid__0, index: 0, length: 2}]
 *   ts  --ir        properties[0] has no such key
 *
 * The chain is omitted on ordinary properties in every tier — emitting an empty
 * array instead would move the ANF bytes of every contract in the suite, which
 * is the companion change Python needed under N-095.
 */

import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { expandFixedArrays } from '../passes/03b-expand-fixed-arrays.js';
import { lowerToANF } from '../passes/04-anf-lower.js';

const SOURCE = `
import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class Grid extends StatefulSmartContract {
  plain: bigint = 0n;
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public set00(v: bigint) {
    this.grid[0][0] = v;
    assert(true);
  }
}
`;

function anfProperties() {
  const parsed = parse(SOURCE, 'Grid.runar.ts');
  const errors = parsed.errors.filter((e) => e.severity === 'error');
  expect(errors, `fixture must parse:\n${errors.map((e) => e.message).join('\n')}`).toEqual([]);
  const expanded = expandFixedArrays(parsed.contract!);
  const expandErrors = expanded.errors.filter((e) => e.severity === 'error');
  expect(
    expandErrors,
    `the expand pass must succeed:\n${expandErrors.map((e) => e.message).join('\n')}`,
  ).toEqual([]);
  return lowerToANF(expanded.contract).properties;
}

describe('N-103: syntheticArrayChain reaches the TS ANF', () => {
  it('every synthetic leaf carries the chain the AST marked it with', () => {
    const props = anfProperties();
    const leaves = props.filter((p) => p.name.startsWith('grid__'));

    // Non-vacuity: the expand pass must have produced the 2x2 leaves at all.
    expect(leaves.map((p) => p.name)).toEqual([
      'grid__0__0',
      'grid__0__1',
      'grid__1__0',
      'grid__1__1',
    ]);

    expect(leaves[0]!.syntheticArrayChain).toEqual([
      { base: 'grid', index: 0, length: 2 },
      { base: 'grid__0', index: 0, length: 2 },
    ]);
    expect(leaves[3]!.syntheticArrayChain).toEqual([
      { base: 'grid', index: 1, length: 2 },
      { base: 'grid__1', index: 1, length: 2 },
    ]);
  });

  it('an ordinary property omits the key entirely', () => {
    const plain = anfProperties().find((p) => p.name === 'plain');
    expect(plain, 'the non-array property must survive the expand pass').toBeDefined();
    expect(Object.prototype.hasOwnProperty.call(plain!, 'syntheticArrayChain')).toBe(false);
  });
});
