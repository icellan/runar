/**
 * PrivateHelperOutputs integration test — 2026-04-30 audit regression
 * (F1 + F3).
 *
 * The contract delegates state mutation, addDataOutput, and addOutput
 * to private helpers. A correct compiler must auto-inject continuation
 * params (`_changePKH`, `_changeAmount`, `_newAmount`, `txPreimage`)
 * for each public method as if the public body called the intrinsic
 * directly. Before the F1 fix the auto-injection was a shallow scan
 * of the public body, so these methods were silently classified as
 * terminal and the deploy + call cycle would fail.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('PrivateHelperOutputs', () => {
  it('commit invokes private state mutation and broadcasts a continuation tx', async () => {
    const artifact = compileContract('examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();

    const { txid: callTxid } = await contract.call('commit', [], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.counter).toBe(1n);
  });

  it('log routes a data output through a private helper', async () => {
    const artifact = compileContract('examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    const payload = '6a09' + '6273766d2d74657374';
    const { txid } = await contract.call('log', [payload], provider, signer);
    expect(txid).toBeTruthy();
  });

  it('repeated commit calls accumulate state across continuations', async () => {
    const artifact = compileContract('examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    await contract.call('commit', [], provider, signer);
    await contract.call('commit', [], provider, signer);
    await contract.call('commit', [], provider, signer);

    expect(contract.state.counter).toBe(3n);
  });
});
