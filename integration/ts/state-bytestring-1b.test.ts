/**
 * StateByteString1B regtest — 1-byte ByteString state with explicit framing pin.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider, expectNodeRejected } from './helpers/node.js';
import {
  assertOnChainState,
  assertOnChainByteString1B,
} from './helpers/onchain.js';

const SOURCE = 'integration/contracts/constructs/StateByteString1B.runar.ts';

describe('StateByteString1B (regtest)', () => {
  it('deploys with 1-byte tag framed as 0x01||byte and updates', async () => {
    const artifact = compileContract(SOURCE);
    const contract = new RunarContract(artifact, ['05']);
    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {
      satoshis: 10_000,
    });
    expect(deployTxid).toHaveLength(64);
    // Deploy output[0] is the contract UTXO with initial state
    await assertOnChainByteString1B(deployTxid, 0, '05');

    const { txid } = await contract.call('setTag', ['ab'], provider, signer);
    expect(txid).toHaveLength(64);
    await assertOnChainState(artifact, txid, 0, { tag: 'ab' });
    await assertOnChainByteString1B(txid, 0, 'ab');
  });

  it('chains two 1-byte updates with framing pin', async () => {
    const artifact = compileContract(SOURCE);
    const contract = new RunarContract(artifact, ['01']);
    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 10_000 });
    const { txid: t1 } = await contract.call('setTag', ['02'], provider, signer);
    await assertOnChainByteString1B(t1, 0, '02');
    const { txid: t2 } = await contract.call('setTag', ['ff'], provider, signer);
    await assertOnChainByteString1B(t2, 0, 'ff');
  });

  it('rejects wrong-length tag on-chain (len !== 1)', async () => {
    const artifact = compileContract(SOURCE);
    const contract = new RunarContract(artifact, ['05']);
    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 10_000 });
    await expectNodeRejected(provider, () =>
      contract.call('setTag', ['abcd'], provider, signer),
    );
    await expectNodeRejected(provider, () =>
      contract.call('setTag', [''], provider, signer),
    );
  });
});
