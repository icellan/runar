/**
 * SimpleNFT integration test — stateful contract with addOutput (SDK Deploy path).
 *
 * SimpleNFT is a StatefulSmartContract with properties:
 *   - owner: PubKey (mutable)
 *   - tokenId: ByteString (readonly)
 *   - metadata: ByteString (readonly)
 *
 * Methods: transfer(sig, newOwner, outputSatoshis), burn(sig)
 *
 * Both methods require a Sig parameter (checkSig). The SDK auto-computes Sig when
 * null is passed. We test compile, deploy, transfer, and burn via the SDK.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('SimpleNFT', () => {
  it('should compile the SimpleNFT contract', () => {
    const artifact = compileContract('examples/ts/token-nft/NFTExample.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('SimpleNFT');
  });

  it('should deploy with owner, tokenId, and metadata', async () => {
    const artifact = compileContract('examples/ts/token-nft/NFTExample.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const { signer } = await createFundedWallet(provider);

    const tokenIdHex = Buffer.from('NFT-001').toString('hex');
    const metadataHex = Buffer.from('My First NFT').toString('hex');

    // Constructor: (owner: PubKey, tokenId: ByteString, metadata: ByteString)
    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      tokenIdHex,
      metadataHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with different owners', async () => {
    const artifact = compileContract('examples/ts/token-nft/NFTExample.runar.ts');

    const provider = createProvider();
    const owner1 = createWallet();
    const owner2 = createWallet();
    const { signer } = await createFundedWallet(provider);

    const tokenIdHex = Buffer.from('NFT-MULTI').toString('hex');
    const metadataHex = Buffer.from('Unique Art Piece').toString('hex');

    // Deploy two NFTs with different owners but same metadata
    const contract1 = new RunarContract(artifact, [
      owner1.pubKeyHex,
      tokenIdHex,
      metadataHex,
    ]);
    const { txid: txid1 } = await contract1.deploy(provider, signer, {});
    expect(txid1).toBeTruthy();

    const contract2 = new RunarContract(artifact, [
      owner2.pubKeyHex,
      tokenIdHex,
      metadataHex,
    ]);
    const { txid: txid2 } = await contract2.deploy(provider, signer, {});
    expect(txid2).toBeTruthy();

    // Different deploy txids
    expect(txid1).not.toBe(txid2);
  });

  it('should deploy with long metadata', async () => {
    const artifact = compileContract('examples/ts/token-nft/NFTExample.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const { signer } = await createFundedWallet(provider);

    const tokenIdHex = Buffer.from('NFT-LONG-META').toString('hex');
    // 256 bytes of metadata
    const metadataHex = Buffer.from('A'.repeat(256)).toString('hex');

    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      tokenIdHex,
      metadataHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  it('should transfer to a new owner', async () => {
    const artifact = compileContract('examples/ts/token-nft/NFTExample.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);
    const signerPubKeyHex = await signer.getPublicKey();
    const newOwner = createWallet();

    const tokenIdHex = Buffer.from('NFT-TRANSFER').toString('hex');
    const metadataHex = Buffer.from('Transfer Test').toString('hex');

    const contract = new RunarContract(artifact, [
      signerPubKeyHex,
      tokenIdHex,
      metadataHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();

    // transfer(sig, newOwner, outputSatoshis) — null Sig is auto-computed by the SDK
    const { txid: callTxid } = await contract.call('transfer', [null, newOwner.pubKeyHex, 1n], provider, signer, {
      newState: { owner: newOwner.pubKeyHex, tokenId: tokenIdHex, metadata: metadataHex },
    });
    expect(callTxid).toBeTruthy();
    expect(typeof callTxid).toBe('string');
    expect(callTxid.length).toBe(64);
  });

  it('should burn an NFT', async () => {
    const artifact = compileContract('examples/ts/token-nft/NFTExample.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);
    const signerPubKeyHex = await signer.getPublicKey();

    const tokenIdHex = Buffer.from('NFT-BURN').toString('hex');
    const metadataHex = Buffer.from('Burn Test').toString('hex');

    const contract = new RunarContract(artifact, [
      signerPubKeyHex,
      tokenIdHex,
      metadataHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();

    // burn(sig) — null Sig is auto-computed by the SDK; no newState since burn destroys the UTXO
    const { txid: callTxid } = await contract.call('burn', [null], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(typeof callTxid).toBe('string');
    expect(callTxid.length).toBe(64);
  });

  it('should reject transfer with wrong signer', async () => {
    const artifact = compileContract('examples/ts/token-nft/NFTExample.runar.ts');

    const provider = createProvider();
    // Deploy with owner=walletA
    const { signer: ownerSigner } = await createFundedWallet(provider);
    const ownerPubKeyHex = await ownerSigner.getPublicKey();
    const newOwner = createWallet();

    const tokenIdHex = Buffer.from('NFT-REJECT').toString('hex');
    const metadataHex = Buffer.from('Reject Transfer Test').toString('hex');

    const contract = new RunarContract(artifact, [
      ownerPubKeyHex,
      tokenIdHex,
      metadataHex,
    ]);

    await contract.deploy(provider, ownerSigner, {});

    // Call transfer with walletB — checkSig will fail on-chain
    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call(
        'transfer', [null, newOwner.pubKeyHex, 1n], provider, wrongSigner,
        { newState: { owner: newOwner.pubKeyHex, tokenId: tokenIdHex, metadata: metadataHex } },
      ),
    ).rejects.toThrow();
  });
});
