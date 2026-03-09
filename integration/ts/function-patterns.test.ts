/**
 * FunctionPatterns integration test — stateful contract demonstrating private methods,
 * built-in functions, and method composition (SDK Deploy path).
 *
 * FunctionPatterns is a StatefulSmartContract with properties:
 *   - owner: PubKey (readonly)
 *   - balance: bigint (mutable)
 *
 * Methods:
 *   - deposit(sig: Sig, amount: bigint)
 *   - withdraw(sig: Sig, amount: bigint, feeBps: bigint)
 *   - scale(sig: Sig, numerator: bigint, denominator: bigint)
 *   - normalize(sig: Sig, lo: bigint, hi: bigint, step: bigint)
 *
 * All methods require a Sig parameter via requireOwner(sig) which calls
 * checkSig(sig, this.owner), so spending requires raw transaction construction.
 * We test compile + deploy via the SDK. Full spending tests (deposit, withdraw,
 * chained operations, wrong-owner rejection) are covered by the Go integration
 * suite (function_patterns_test.go).
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('FunctionPatterns', () => {
  it('should compile the FunctionPatterns contract', () => {
    const artifact = compileContract('examples/ts/function-patterns/FunctionPatterns.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('FunctionPatterns');
  });

  it('should deploy with owner and initial balance', async () => {
    const artifact = compileContract('examples/ts/function-patterns/FunctionPatterns.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const { signer } = await createFundedWallet(provider);

    // Constructor: (owner: PubKey, balance: bigint)
    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      1000n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 10000 });
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with zero initial balance', async () => {
    const artifact = compileContract('examples/ts/function-patterns/FunctionPatterns.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const { signer } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      0n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 10000 });
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy with large initial balance', async () => {
    const artifact = compileContract('examples/ts/function-patterns/FunctionPatterns.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const { signer } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      999_999_999n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 10000 });
    expect(deployTxid).toBeTruthy();
  });

  it('should produce distinct deploy txids for different instances', async () => {
    const artifact = compileContract('examples/ts/function-patterns/FunctionPatterns.runar.ts');

    const provider = createProvider();
    const owner1 = createWallet();
    const owner2 = createWallet();
    const { signer } = await createFundedWallet(provider);

    const contract1 = new RunarContract(artifact, [owner1.pubKeyHex, 100n]);
    const { txid: txid1 } = await contract1.deploy(provider, signer, { satoshis: 10000 });

    const contract2 = new RunarContract(artifact, [owner2.pubKeyHex, 200n]);
    const { txid: txid2 } = await contract2.deploy(provider, signer, { satoshis: 10000 });

    expect(txid1).toBeTruthy();
    expect(txid2).toBeTruthy();
    expect(txid1).not.toBe(txid2);
  });

  it('should call deposit to increase balance', async () => {
    const artifact = compileContract('examples/ts/function-patterns/FunctionPatterns.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);
    const signerPubKeyHex = await signer.getPublicKey();

    // Constructor: (owner: PubKey, balance: bigint)
    const contract = new RunarContract(artifact, [
      signerPubKeyHex,
      100n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 10000 });
    expect(deployTxid).toBeTruthy();
    expect(deployTxid.length).toBe(64);

    // Call deposit(sig, amount) — null Sig is auto-computed by the SDK
    const { txid: callTxid } = await contract.call('deposit', [null, 50n], provider, signer, {
      satoshis: 10000,
      newState: {
        owner: signerPubKeyHex,
        balance: 150n,
      },
    });
    expect(callTxid).toBeTruthy();
    expect(typeof callTxid).toBe('string');
    expect(callTxid.length).toBe(64);
  });

  it('should deposit then withdraw', async () => {
    const artifact = compileContract('examples/ts/function-patterns/FunctionPatterns.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);
    const signerPubKeyHex = await signer.getPublicKey();

    const contract = new RunarContract(artifact, [signerPubKeyHex, 1000n]);

    await contract.deploy(provider, signer, { satoshis: 10000 });

    // deposit(sig, 500) -> balance = 1500
    await contract.call('deposit', [null, 500n], provider, signer, {
      satoshis: 10000,
      newState: { owner: signerPubKeyHex, balance: 1500n },
    });

    // withdraw(sig, 200, 100) -> fee=2, balance = 1500-202 = 1298
    await contract.call('withdraw', [null, 200n, 100n], provider, signer, {
      satoshis: 10000,
      newState: { owner: signerPubKeyHex, balance: 1298n },
    });
  });

  it('should reject deposit with wrong signer', async () => {
    const artifact = compileContract('examples/ts/function-patterns/FunctionPatterns.runar.ts');

    const provider = createProvider();
    // Deploy with owner=walletA
    const { signer: ownerSigner } = await createFundedWallet(provider);
    const ownerPubKeyHex = await ownerSigner.getPublicKey();

    const contract = new RunarContract(artifact, [
      ownerPubKeyHex,
      100n,
    ]);

    await contract.deploy(provider, ownerSigner, { satoshis: 10000 });

    // Call deposit with walletB — checkSig will fail on-chain
    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call('deposit', [null, 50n], provider, wrongSigner, {
        satoshis: 10000,
        newState: {
          owner: ownerPubKeyHex,
          balance: 150n,
        },
      }),
    ).rejects.toThrow();
  });
});
