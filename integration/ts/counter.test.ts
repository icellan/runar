/**
 * Counter integration test — stateful contract (SDK Deploy/Call path).
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('Counter', () => {
  it('should increment count from 0 to 1', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();

    const { txid: callTxid } = await contract.call('increment', [], provider, signer, {
      newState: { count: 1n },
    });
    expect(callTxid).toBeTruthy();
  });

  it('should chain increments 0 -> 1 -> 2', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    await contract.call('increment', [], provider, signer, {
      newState: { count: 1n },
    });

    await contract.call('increment', [], provider, signer, {
      newState: { count: 2n },
    });
  });

  it('should increment then decrement 0 -> 1 -> 0', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    await contract.call('increment', [], provider, signer, {
      newState: { count: 1n },
    });

    await contract.call('decrement', [], provider, signer, {
      newState: { count: 0n },
    });
  });

  it('should reject wrong state hash', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    // Claim count=99 instead of 1 — hashOutputs mismatch
    await expect(
      contract.call('increment', [], provider, signer, {
        newState: { count: 99n },
      }),
    ).rejects.toThrow();
  });

  it('should reject decrement from zero', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    // count=0, decrement → assert(count > 0) fails
    await expect(
      contract.call('decrement', [], provider, signer, {
        newState: { count: -1n },
      }),
    ).rejects.toThrow();
  });
});
