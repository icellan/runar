/**
 * SDK round-trip test for the TicTacToe v2 contract that uses a
 * `FixedArray<bigint, 9>` for its board state.
 *
 * Validates that:
 *
 *  - The grouped ABI exposes `board` as a FixedArray state field (with
 *    synthetic names listed for SDK use).
 *  - `RunarContract.state.board` is a JS array, not nine separate
 *    scalars.
 *  - State serialization writes the underlying nine fields in declaration
 *    order, so `getLockingScript()` produces a script whose state
 *    section byte-matches a hand-constructed hex.
 *  - `extractStateFromScript` round-trips the array back to a grouped
 *    JS array.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import type { RunarArtifact } from 'runar-ir-schema';
import { extractStateFromScript } from '../state.js';

const PROJECT_ROOT = resolve(import.meta.dirname, '..', '..', '..', '..');

function compileContract(sourcePath: string): RunarArtifact {
  const absPath = resolve(PROJECT_ROOT, sourcePath);
  const source = readFileSync(absPath, 'utf-8');
  const fileName = absPath.split('/').pop()!;
  const result = compile(source, { fileName });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity?: string }) => d.severity === 'error')
      .map((d: { message?: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

const PLAYER_X_KEY = '0000000000000000000000000000000000000000000000000000000000000001';

describe('TicTacToe v2 — FixedArray SDK round-trip', () => {
  it('exposes grouped board state field in the artifact', () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts');
    const stateFields = artifact.stateFields ?? [];
    const board = stateFields.find(f => f.name === 'board');
    expect(board).toBeDefined();
    expect(board!.fixedArray).toBeDefined();
    expect(board!.fixedArray!.length).toBe(9);
    expect(board!.fixedArray!.elementType).toBe('bigint');
  });

  it('initializes `state.board` to a 9-element bigint array', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts');
    const provider = new MockProvider();
    const signer = new LocalSigner(PLAYER_X_KEY);
    const pubKeyHex = await signer.getPublicKey();
    const address = await signer.getAddress();
    provider.addUtxo(address, {
      txid: PLAYER_X_KEY.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });

    const contract = new RunarContract(artifact, [pubKeyHex, 5000n]);
    const state = contract.state;
    expect(Array.isArray(state.board)).toBe(true);
    const arr = state.board as unknown[];
    expect(arr.length).toBe(9);
    for (const v of arr) {
      expect(typeof v).toBe('bigint');
      expect(v).toBe(0n);
    }
  });

  it('deploys to MockProvider and round-trips state.board from on-chain script', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts');
    const provider = new MockProvider();
    const signer = new LocalSigner(PLAYER_X_KEY);
    const pubKeyHex = await signer.getPublicKey();
    const address = await signer.getAddress();
    provider.addUtxo(address, {
      txid: PLAYER_X_KEY.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });

    const contract = new RunarContract(artifact, [pubKeyHex, 5000n]);
    // Poke values into state.board manually — the grouping layer should
    // serialize them into the underlying nine scalar slots.
    contract.setState({ board: [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n] });
    await contract.deploy(provider, signer, {});

    const utxo = contract.getUtxo();
    expect(utxo).toBeTruthy();
    const scriptHex = utxo!.script;

    // Extract the full state section from the deployed script and verify the
    // grouped array comes back as a JS array of bigints with the right values.
    const extracted = extractStateFromScript(artifact, scriptHex);
    expect(extracted).toBeTruthy();
    const board = (extracted as Record<string, unknown>).board;
    expect(Array.isArray(board)).toBe(true);
    const arr = board as unknown[];
    expect(arr).toEqual([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n]);
  });

  it('state serialization matches the v1 hand-rolled contract byte-for-byte at initial state', async () => {
    const artifactV1 = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');
    const artifactV2 = compileContract('examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts');

    const signer = new LocalSigner(PLAYER_X_KEY);
    const pubKeyHex = await signer.getPublicKey();

    const v1 = new RunarContract(artifactV1, [pubKeyHex, 5000n]);
    const v2 = new RunarContract(artifactV2, [pubKeyHex, 5000n]);

    const lockV1 = v1.getLockingScript();
    const lockV2 = v2.getLockingScript();
    expect(lockV2).toBe(lockV1);
  });
});
