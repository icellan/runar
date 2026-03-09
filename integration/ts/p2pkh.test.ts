/**
 * P2PKH integration test — stateless contract with checkSig.
 *
 * P2PKH locks funds to a public key hash. Spending requires a valid
 * signature and the matching public key. The SDK auto-computes Sig params
 * when null is passed.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('P2PKH', () => {
  it('should compile and deploy with a valid pubKeyHash', async () => {
    const artifact = compileContract('examples/ts/p2pkh/P2PKH.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('P2PKH');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy and spend with unlock(sig, pubKey)', async () => {
    const artifact = compileContract('examples/ts/p2pkh/P2PKH.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);
    await contract.deploy(provider, signer, { satoshis: 5000 });

    // null Sig and PubKey args are auto-computed by the SDK
    const { txid: callTxid } = await contract.call(
      'unlock', [null, null], provider, signer,
    );
    expect(callTxid).toBeTruthy();
    expect(callTxid.length).toBe(64);
  });

  it('should deploy with a different pubKeyHash', async () => {
    const artifact = compileContract('examples/ts/p2pkh/P2PKH.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const otherWallet = createWallet();
    const contract = new RunarContract(artifact, [otherWallet.pubKeyHash]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();
  });

  it('should reject unlock with wrong signer', async () => {
    const artifact = compileContract('examples/ts/p2pkh/P2PKH.runar.ts');

    const provider = createProvider();
    // Deploy locked to walletA's pubKeyHash
    const walletA = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [walletA.pubKeyHash]);
    await contract.deploy(provider, walletA.signer, { satoshis: 5000 });

    // Call unlock with walletB — auto-computed sig+pubkey won't match the hash
    const walletB = await createFundedWallet(provider);

    await expect(
      contract.call('unlock', [null, null], provider, walletB.signer),
    ).rejects.toThrow();
  });
});
