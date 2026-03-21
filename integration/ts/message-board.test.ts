/**
 * MessageBoard integration test -- stateful contract with ByteString state (SDK Deploy/Call path).
 *
 * MessageBoard is a stateful contract that stores a ByteString message and a
 * readonly PubKey owner:
 *   - post(newMessage) -- updates the message (anyone can call)
 *   - burn(sig) -- owner burns the contract (terminal, no continuation output)
 *
 * The SDK's contract.call() auto-computes Sig params set to null using the
 * signer's private key.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('MessageBoard', () => {
  it('should post a message (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/message-board/MessageBoard.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    // Constructor: (message: ByteString, owner: PubKey)
    // Use empty message '00' and the funded wallet's pubkey as owner
    const contract = new RunarContract(artifact, ['00', pubKeyHex]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();

    const { txid: callTxid } = await contract.call('post', ['48656c6c6f'], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.message).toBe('48656c6c6f');
  });

  it('should chain posts (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/message-board/MessageBoard.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, ['00', pubKeyHex]);
    await contract.deploy(provider, signer, {});

    await contract.call('post', ['aabb'], provider, signer);
    expect(contract.state.message).toBe('aabb');

    await contract.call('post', ['ccddee'], provider, signer);
    expect(contract.state.message).toBe('ccddee');
  });

  it('should burn with owner signature', async () => {
    const artifact = compileContract('examples/ts/message-board/MessageBoard.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, ['00', pubKeyHex]);
    await contract.deploy(provider, signer, {});

    // burn(sig=null) -- auto-computed from signer (owner)
    const { txid: burnTxid } = await contract.call('burn', [null], provider, signer);
    expect(burnTxid).toBeTruthy();
  });

  it('should reject burn with wrong signer', async () => {
    const artifact = compileContract('examples/ts/message-board/MessageBoard.runar.ts');
    const provider = createProvider();
    const { signer: ownerSigner, pubKeyHex: ownerPubKey } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, ['00', ownerPubKey]);
    await contract.deploy(provider, ownerSigner, {});

    // Call burn with wrong signer -- checkSig will fail on-chain
    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call('burn', [null], provider, wrongSigner),
    ).rejects.toThrow();
  });

  it('should deploy with empty message and post', async () => {
    const artifact = compileContract('examples/ts/message-board/MessageBoard.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);

    // Constructor: (message: ByteString, owner: PubKey)
    // Use empty message '' (empty hex string) and the funded wallet's pubkey as owner
    const contract = new RunarContract(artifact, ['', pubKeyHex]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();

    const { txid: callTxid } = await contract.call('post', ['48656c6c6f'], provider, signer);
    expect(callTxid).toBeTruthy();
    expect(contract.state.message).toBe('48656c6c6f');
  });
});
