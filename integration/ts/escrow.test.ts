/**
 * Escrow integration test — stateless contract with dual-signature checkSig.
 *
 * Escrow is a stateless contract that locks funds and allows release or refund
 * via two methods, each requiring two signatures for security:
 *   - release(sellerSig, arbiterSig) — seller + arbiter both sign to release funds
 *   - refund(buyerSig, arbiterSig) — buyer + arbiter both sign to refund
 *
 * No single party can act unilaterally — the arbiter serves as a trust anchor.
 *
 * The SDK's contract.call() auto-computes Sig params set to null using the
 * single signer's private key. For dual-sig testing, we use the same key for
 * both required roles so both null params auto-compute correctly.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('Escrow', () => {
  it('should compile the Escrow contract', () => {
    const artifact = compileContract('examples/ts/escrow/Escrow.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('Escrow');
  });

  it('should deploy with three distinct pubkeys', async () => {
    const artifact = compileContract('examples/ts/escrow/Escrow.runar.ts');

    const provider = createProvider();
    const buyer = createWallet();
    const seller = createWallet();
    const arbiter = createWallet();

    // Fund a separate wallet to pay for the deploy transaction
    const { signer } = await createFundedWallet(provider);

    // Constructor takes (buyer: PubKey, seller: PubKey, arbiter: PubKey)
    const contract = new RunarContract(artifact, [
      buyer.pubKeyHex,
      seller.pubKeyHex,
      arbiter.pubKeyHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with the same key for multiple roles', async () => {
    const artifact = compileContract('examples/ts/escrow/Escrow.runar.ts');

    const provider = createProvider();
    const buyerAndArbiter = createWallet();
    const seller = createWallet();

    const { signer } = await createFundedWallet(provider);

    // Same key as both buyer and arbiter
    const contract = new RunarContract(artifact, [
      buyerAndArbiter.pubKeyHex,
      seller.pubKeyHex,
      buyerAndArbiter.pubKeyHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 5000 });
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy and spend with release(sellerSig, arbiterSig)', async () => {
    const artifact = compileContract('examples/ts/escrow/Escrow.runar.ts');

    const provider = createProvider();
    const buyer = createWallet();

    // Use the same funded wallet as both seller and arbiter so both null Sig
    // params auto-compute to the same key (dual-sig requires both to match)
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    // Constructor takes (buyer: PubKey, seller: PubKey, arbiter: PubKey)
    const contract = new RunarContract(artifact, [
      buyer.pubKeyHex,
      pubKeyHex,    // seller
      pubKeyHex,    // arbiter (same key)
    ]);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    // release(sellerSig=null, arbiterSig=null) — both auto-computed from same signer
    const { txid: callTxid } = await contract.call(
      'release', [null, null], provider, signer,
    );
    expect(callTxid).toBeTruthy();
    expect(callTxid.length).toBe(64);
  });

  it('should deploy and spend with refund(buyerSig, arbiterSig)', async () => {
    const artifact = compileContract('examples/ts/escrow/Escrow.runar.ts');

    const provider = createProvider();
    const seller = createWallet();

    // Use the same funded wallet as both buyer and arbiter
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      pubKeyHex,    // buyer
      seller.pubKeyHex,
      pubKeyHex,    // arbiter (same key as buyer)
    ]);

    await contract.deploy(provider, signer, { satoshis: 5000 });

    // refund(buyerSig=null, arbiterSig=null) — both auto-computed from same signer
    const { txid: callTxid } = await contract.call(
      'refund', [null, null], provider, signer,
    );
    expect(callTxid).toBeTruthy();
    expect(callTxid.length).toBe(64);
  });

  it('should reject release with wrong signer', async () => {
    const artifact = compileContract('examples/ts/escrow/Escrow.runar.ts');

    const provider = createProvider();
    const buyer = createWallet();

    // Deploy with seller=walletA, arbiter=walletA (same key)
    const { signer: correctSigner, pubKeyHex: correctPubKey } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      buyer.pubKeyHex,
      correctPubKey,  // seller
      correctPubKey,  // arbiter
    ]);

    await contract.deploy(provider, correctSigner, { satoshis: 5000 });

    // Call with wrong signer — checkSig will fail on-chain
    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call('release', [null, null], provider, wrongSigner),
    ).rejects.toThrow();
  });

  it('should reject refund with wrong signer', async () => {
    const artifact = compileContract('examples/ts/escrow/Escrow.runar.ts');

    const provider = createProvider();
    const seller = createWallet();

    // Deploy with buyer=walletA, arbiter=walletA (same key)
    const { signer: correctSigner, pubKeyHex: correctPubKey } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      correctPubKey,  // buyer
      seller.pubKeyHex,
      correctPubKey,  // arbiter
    ]);

    await contract.deploy(provider, correctSigner, { satoshis: 5000 });

    // Call refund with wrong signer — checkSig will fail on-chain
    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call('refund', [null, null], provider, wrongSigner),
    ).rejects.toThrow();
  });
});
