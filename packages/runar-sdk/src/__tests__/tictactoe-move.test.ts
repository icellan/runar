/**
 * Unit test for TicTacToe move method — reproduces the on-chain failure locally.
 *
 * The join method works on-chain, but move fails with "Script failed an
 * OP_VERIFY operation". This test captures the exact TX the SDK builds for
 * move and validates it through BSV SDK's Spend interpreter to identify
 * the root cause without needing a regtest node.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { Spend, LockingScript, UnlockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(import.meta.dirname, '..', '..', '..', '..');

function compileContract(sourcePath: string): RunarArtifact {
  const absPath = resolve(PROJECT_ROOT, sourcePath);
  const source = readFileSync(absPath, 'utf-8');
  const fileName = absPath.split('/').pop()!;
  const result = compile(source, { fileName });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: any) => d.severity === 'error')
      .map((d: any) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

const PLAYER_X_KEY = '0000000000000000000000000000000000000000000000000000000000000001';
const PLAYER_O_KEY = '0000000000000000000000000000000000000000000000000000000000000002';

async function setupWallet(
  provider: MockProvider,
  privKey: string,
  satoshis: number,
): Promise<{ signer: LocalSigner; pubKeyHex: string }> {
  const signer = new LocalSigner(privKey);
  const address = await signer.getAddress();
  const pubKeyHex = await signer.getPublicKey();
  provider.addUtxo(address, {
    txid: privKey.slice(0, 64),
    outputIndex: 0,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  });
  return { signer, pubKeyHex };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TicTacToe move method script validation', () => {
  it('move TX should pass local script validation', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');

    const provider = new MockProvider();
    const playerX = await setupWallet(provider, PLAYER_X_KEY, 500_000);
    const playerO = await setupWallet(provider, PLAYER_O_KEY, 500_000);

    const contract = new RunarContract(artifact, [playerX.pubKeyHex, 5000n]);

    // Deploy
    await contract.deploy(provider, playerX.signer, {});
    expect(provider.getBroadcastedTxs().length).toBe(1);

    // Join — this works on-chain, so it should work locally
    await contract.call('join', [playerO.pubKeyHex, null], provider, playerO.signer);
    expect(provider.getBroadcastedTxs().length).toBe(2);
    expect(contract.state.status).toBe(1n);
    expect(contract.state.turn).toBe(1n);

    // Get the join TX to extract the continuation UTXO
    const joinTxHex = provider.getBroadcastedTxs()[1]!;
    const joinTx = Transaction.fromHex(joinTxHex);
    const joinOutput = joinTx.outputs[0]!;
    const joinLockingScript = joinOutput.lockingScript;
    const joinSatoshis = joinOutput.satoshis!;

    // Also validate the join TX itself
    const deployTxHex = provider.getBroadcastedTxs()[0]!;
    const deployTx = Transaction.fromHex(deployTxHex);
    const deployOutput = deployTx.outputs[0]!;
    const joinInput = joinTx.inputs[0]!;
    const joinSpend = new Spend({
      sourceTXID: joinInput.sourceTXID!,
      sourceOutputIndex: joinInput.sourceOutputIndex,
      sourceSatoshis: deployOutput.satoshis!,
      lockingScript: deployOutput.lockingScript,
      transactionVersion: joinTx.version,
      otherInputs: joinTx.inputs.slice(1).map((inp, idx) => ({
        inputIndex: idx + 1,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: inp.unlockingScript,
        sourceSatoshis: 0,
        lockingScript: LockingScript.fromHex(''),
      })),
      outputs: joinTx.outputs.map(o => ({
        lockingScript: o.lockingScript,
        satoshis: o.satoshis,
      })),
      unlockingScript: joinInput.unlockingScript,
      inputIndex: 0,
      inputSequence: joinInput.sequence,
      lockTime: joinTx.lockTime,
    });
    const joinOk = joinSpend.validate();
    expect(joinOk).toBe(true);

    // Move — this fails on-chain
    await contract.call('move', [4n, playerX.pubKeyHex, null], provider, playerX.signer);
    expect(provider.getBroadcastedTxs().length).toBe(3);

    // Extract the move TX
    const moveTxHex = provider.getBroadcastedTxs()[2]!;
    const moveTx = Transaction.fromHex(moveTxHex);

    // Validate the move TX's input[0] against the join output
    const moveInput = moveTx.inputs[0]!;
    const moveUnlockingScript = moveInput.unlockingScript;

    // Use BSV SDK Spend to validate
    const spend = new Spend({
      sourceTXID: moveInput.sourceTXID!,
      sourceOutputIndex: moveInput.sourceOutputIndex,
      sourceSatoshis: joinSatoshis,
      lockingScript: joinLockingScript,
      transactionVersion: moveTx.version,
      otherInputs: moveTx.inputs.slice(1).map((inp, idx) => ({
        inputIndex: idx + 1,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: inp.unlockingScript,
        sourceSatoshis: 0,
        lockingScript: LockingScript.fromHex(''),
      })),
      outputs: moveTx.outputs.map(o => ({
        lockingScript: o.lockingScript,
        satoshis: o.satoshis,
      })),
      unlockingScript: moveUnlockingScript,
      inputIndex: 0,
      inputSequence: moveInput.sequence,
      lockTime: moveTx.lockTime,
    });

    try {
      const ok = spend.validate();
      expect(ok).toBe(true);
    } catch (e: unknown) {
      // If validation fails, report the error for debugging
      const msg = e instanceof Error ? e.message : String(e);
      // Fail the test with the actual error
      expect.fail(`Move TX script validation failed: ${msg}`);
    }
  });
});
