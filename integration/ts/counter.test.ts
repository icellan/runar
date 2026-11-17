/**
 * Counter integration test — stateful contract (SDK Deploy/Call path).
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider, expectNodeRejected } from './helpers/node.js';
import { readOnChainState } from './helpers/on-chain-state.js';

describe('Counter', () => {
  it('should increment count from 0 to 1 (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();

    // No manual newState — SDK auto-computes from ANF IR
    const { txid: callTxid } = await contract.call('increment', [], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.count).toBe(1n);

    // Read the value back out of the ACTUAL output script the node accepted,
    // not the SDK's predicted next state (contract.state above).
    const onChain = await readOnChainState(provider, artifact, contract.getUtxo()!);
    expect(onChain.count).toBe(1n);
  });

  it('should chain increments 0 -> 1 -> 2 (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    await contract.call('increment', [], provider, signer);
    expect(contract.state.count).toBe(1n);
    expect((await readOnChainState(provider, artifact, contract.getUtxo()!)).count).toBe(1n);

    await contract.call('increment', [], provider, signer);
    expect(contract.state.count).toBe(2n);
    expect((await readOnChainState(provider, artifact, contract.getUtxo()!)).count).toBe(2n);
  });

  it('should increment then decrement 0 -> 1 -> 0 (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    await contract.call('increment', [], provider, signer);
    expect(contract.state.count).toBe(1n);
    expect((await readOnChainState(provider, artifact, contract.getUtxo()!)).count).toBe(1n);

    await contract.call('decrement', [], provider, signer);
    expect(contract.state.count).toBe(0n);
    expect((await readOnChainState(provider, artifact, contract.getUtxo()!)).count).toBe(0n);
  });

  it('should reject wrong state hash', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    // Claim count=99 instead of 1 — hashOutputs mismatch
    await expectNodeRejected(provider, () =>
      contract.call('increment', [], provider, signer, {
        newState: { count: 99n },
      }),
    );
  });

  it('should reject decrement from zero (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    // count=0, decrement → assert(count > 0) fails on-chain
    // Auto-computed state will be -1n, but the on-chain assert rejects
    await expectNodeRejected(provider, () =>
      contract.call('decrement', [], provider, signer),
    );
  });
});
