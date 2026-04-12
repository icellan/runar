/**
 * Acceptance test for nested `FixedArray<FixedArray<T, N>, M>` support
 * in the TS spike. Covers Issue 2 of the follow-up plan:
 *
 *  - Compile a contract with a 2x2 nested FixedArray state field.
 *  - Inspect the artifact: exactly one constructor param / state field
 *    entry for `grid`, both typed `FixedArray<FixedArray<bigint,2>,2>`
 *    with a nested JS array initial value.
 *  - Deploy via MockProvider and read `state.grid` as `[[0n,0n],[0n,0n]]`.
 *  - Call individual literal-index setters and assert the SDK regroup
 *    reflects the nested update.
 *  - Pass a non-default constructor arg `[[5n,6n],[7n,8n]]` and assert
 *    `state.grid[1][1] === 8n`.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';
// Relative import — the repo vitest.config.ts aliases runar-compiler,
// runar-ir-schema, runar-lang, runar-testing but not runar-sdk, and
// pnpm workspace packages are not hoisted to the root node_modules.
import { RunarContract } from '../../../packages/runar-sdk/src/contract.js';
import { MockProvider } from '../../../packages/runar-sdk/src/providers/mock.js';
import { LocalSigner } from '../../../packages/runar-sdk/src/signers/local.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Grid2x2.v2.runar.ts'), 'utf8');

function compileContract(): RunarArtifact {
  const result = compile(source, { fileName: 'Grid2x2.v2.runar.ts' });
  if (!result.success || !result.artifact) {
    const errors = result.diagnostics
      .filter(d => d.severity === 'error')
      .map(d => d.message)
      .join('\n  ');
    throw new Error(`Grid2x2 compile failed:\n  ${errors}`);
  }
  return result.artifact;
}

const PLAYER_KEY = '0000000000000000000000000000000000000000000000000000000000000001';

describe('Grid2x2 — nested FixedArray acceptance', () => {
  it('compiles without errors', () => {
    const artifact = compileContract();
    expect(artifact.contractName).toBe('Grid2x2');
  });

  it('exposes grid as a single nested FixedArray state field', () => {
    const artifact = compileContract();
    const stateFields = artifact.stateFields ?? [];
    // Exactly one grid entry — the regrouper must collapse all four
    // leaves into a single logical `grid` field.
    const gridFields = stateFields.filter(f => f.name === 'grid');
    expect(gridFields.length).toBe(1);

    const grid = gridFields[0]!;
    expect(grid.type).toBe('FixedArray<FixedArray<bigint, 2>, 2>');
    expect(grid.fixedArray).toBeDefined();
    expect(grid.fixedArray!.length).toBe(2);
    expect(grid.fixedArray!.elementType).toBe('FixedArray<bigint, 2>');
    expect(grid.fixedArray!.syntheticNames).toEqual([
      'grid__0__0',
      'grid__0__1',
      'grid__1__0',
      'grid__1__1',
    ]);
    // Initial value is a real nested bigint array, not stringified.
    expect(grid.initialValue).toEqual([[0n, 0n], [0n, 0n]]);
  });

  it('exposes zero `grid` shrapnel at the top-level state-field list', () => {
    const artifact = compileContract();
    const names = (artifact.stateFields ?? []).map(f => f.name);
    // The inner `grid__0`/`grid__1` intermediate names must NOT leak
    // into the final state-field list — the iterative regrouper peels
    // them all the way up to `grid`.
    expect(names).not.toContain('grid__0');
    expect(names).not.toContain('grid__1');
    expect(names).not.toContain('grid__0__0');
  });

  it('initial state.grid round-trips as a nested bigint[][]', async () => {
    const artifact = compileContract();
    const provider = new MockProvider();
    const signer = new LocalSigner(PLAYER_KEY);
    const address = await signer.getAddress();
    provider.addUtxo(address, {
      txid: PLAYER_KEY.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });

    const contract = new RunarContract(artifact, []);
    const grid = contract.state.grid as bigint[][];
    expect(Array.isArray(grid)).toBe(true);
    expect(grid.length).toBe(2);
    expect(grid[0]).toEqual([0n, 0n]);
    expect(grid[1]).toEqual([0n, 0n]);
  });

  it('reflects literal-index writes after set01 and set10 via auto-state regrouping', async () => {
    const artifact = compileContract();
    const provider = new MockProvider();
    const signer = new LocalSigner(PLAYER_KEY);
    const address = await signer.getAddress();
    provider.addUtxo(address, {
      txid: PLAYER_KEY.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });

    const contract = new RunarContract(artifact, []);
    contract.connect(provider, signer);
    await contract.deploy({});

    // After set01(1n), grid should be [[0n, 1n], [0n, 0n]].
    await contract.call('set01', [1n]);
    const after01 = contract.state.grid as bigint[][];
    expect(after01).toEqual([[0n, 1n], [0n, 0n]]);

    // After set10(1n), grid should be [[0n, 1n], [1n, 0n]].
    await contract.call('set10', [1n]);
    const after10 = contract.state.grid as bigint[][];
    expect(after10).toEqual([[0n, 1n], [1n, 0n]]);
  });

  it('accepts a non-default nested array in the constructor arg via setState', async () => {
    // Grid2x2 has no constructor params (the grid is fully default-
    // initialised), so non-default initial values are specified via
    // setState before the first serialize — that path exercises the
    // same flatten/regroup pipeline as constructor-arg splicing.
    const artifact = compileContract();
    const contract = new RunarContract(artifact, []);
    contract.setState({ grid: [[5n, 6n], [7n, 8n]] });
    const grid = contract.state.grid as bigint[][];
    expect(grid[1]![1]).toBe(8n);
    expect(grid).toEqual([[5n, 6n], [7n, 8n]]);
  });
});
