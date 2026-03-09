/**
 * FungibleToken integration test — stateful contract with secure merge via addOutput.
 *
 * FungibleToken is a StatefulSmartContract with properties:
 *   - owner: PubKey (mutable)
 *   - balance: bigint (mutable)
 *   - mergeBalance: bigint (mutable, used for cross-input merge verification)
 *   - tokenId: ByteString (readonly)
 *
 * Methods: transfer(sig, to, amount, outputSatoshis), send(sig, to, outputSatoshis),
 *          merge(sig, otherBalance, allPrevouts, outputSatoshis)
 *
 * The merge uses position-dependent output construction: each input writes its own
 * verified balance to a slot based on its position in the transaction. hashOutputs
 * in BIP-143 forces both inputs to agree on identical outputs, preventing inflation.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

/**
 * Build allPrevouts hex from a list of outpoints (txid + outputIndex).
 * Each outpoint is txid in little-endian (32 bytes) + vout in little-endian (4 bytes).
 */
function buildAllPrevouts(utxos: Array<{ txid: string; outputIndex: number }>): string {
  let hex = '';
  for (const utxo of utxos) {
    // txid is displayed big-endian, reverse to little-endian
    const txidLE = utxo.txid.match(/.{2}/g)!.reverse().join('');
    // vout as 4-byte little-endian
    const voutLE = utxo.outputIndex.toString(16).padStart(8, '0')
      .match(/.{2}/g)!.reverse().join('');
    hex += txidLE + voutLE;
  }
  return hex;
}

describe('FungibleToken', () => {
  it('should compile the FungibleToken contract', () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('FungibleToken');
  });

  it('should deploy with owner and initial balance', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const { signer } = await createFundedWallet(provider);

    const tokenIdHex = Buffer.from('TEST-TOKEN-001').toString('hex');

    // Constructor: (owner: PubKey, balance: bigint, mergeBalance: bigint, tokenId: ByteString)
    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      1000n,
      0n,
      tokenIdHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with zero initial balance', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const { signer } = await createFundedWallet(provider);

    const tokenIdHex = Buffer.from('ZERO-BAL-TOKEN').toString('hex');

    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      0n,
      0n,
      tokenIdHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy with large balance', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const { signer } = await createFundedWallet(provider);

    const tokenIdHex = Buffer.from('BIG-TOKEN').toString('hex');

    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      21000000_00000000n, // 21 million * 10^8 (satoshi-scale)
      0n,
      tokenIdHex,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  it('should send entire balance to a recipient', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);
    const recipient = createWallet();

    const tokenIdHex = Buffer.from('SEND-TOKEN').toString('hex');

    const contract = new RunarContract(artifact, [
      pubKeyHex,
      1000n,
      0n,
      tokenIdHex,
    ]);

    await contract.deploy(provider, signer, {});

    // send(sig, to, outputSatoshis) — null Sig is auto-computed from the signer
    const { txid: callTxid } = await contract.call(
      'send', [null, recipient.pubKeyHex, 1n], provider, signer,
      { newState: { owner: recipient.pubKeyHex } },
    );
    expect(callTxid).toBeTruthy();
    expect(callTxid.length).toBe(64);
  });

  it('should reject send with wrong signer', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');

    const provider = createProvider();
    const { signer: ownerSigner, pubKeyHex: ownerPubKey } = await createFundedWallet(provider);
    const recipient = createWallet();

    const tokenIdHex = Buffer.from('REJECT-SEND-TOKEN').toString('hex');

    const contract = new RunarContract(artifact, [
      ownerPubKey,
      1000n,
      0n,
      tokenIdHex,
    ]);

    await contract.deploy(provider, ownerSigner, {});

    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call(
        'send', [null, recipient.pubKeyHex, 1n], provider, wrongSigner,
        { newState: { owner: recipient.pubKeyHex } },
      ),
    ).rejects.toThrow();
  });

  it('should transfer tokens (split into 2 outputs)', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);
    const recipient = createWallet();
    const tokenIdHex = Buffer.from('TRANSFER-TOKEN').toString('hex');

    const contract = new RunarContract(artifact, [pubKeyHex, 1000n, 0n, tokenIdHex]);
    await contract.deploy(provider, signer, {});

    // transfer(sig, to, amount, outputSatoshis) — creates 2 outputs
    const { txid } = await contract.call(
      'transfer', [null, recipient.pubKeyHex, 300n, 1n], provider, signer,
      {
        outputs: [
          { satoshis: 1, state: { owner: recipient.pubKeyHex, balance: 300n, mergeBalance: 0n } },
          { satoshis: 1, state: { owner: pubKeyHex, balance: 700n, mergeBalance: 0n } },
        ],
      },
    );
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('should merge two token UTXOs into one', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);
    const tokenIdHex = Buffer.from('MERGE-TOKEN').toString('hex');

    // Deploy two contracts with the same owner and tokenId
    const contract1 = new RunarContract(artifact, [pubKeyHex, 400n, 0n, tokenIdHex]);
    await contract1.deploy(provider, signer, {});

    const contract2 = new RunarContract(artifact, [pubKeyHex, 600n, 0n, tokenIdHex]);
    await contract2.deploy(provider, signer, {});

    const utxo1 = contract1.getUtxo()!;
    const utxo2 = contract2.getUtxo()!;

    // merge(sig, otherBalance, allPrevouts, outputSatoshis)
    // allPrevouts is auto-computed by the SDK from the transaction inputs (null = auto)
    const { txid } = await contract1.call(
      'merge', [null, 600n, null, 1n], provider, signer,
      {
        additionalContractInputs: [utxo2],
        additionalContractInputArgs: [[null, 400n, null, 1n]],
        outputs: [
          { satoshis: 1, state: { owner: pubKeyHex, balance: 400n, mergeBalance: 600n } },
        ],
      },
    );
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('should reject merge with inflated otherBalance (supply inflation attack)', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);
    const tokenIdHex = Buffer.from('INFLATE-TOKEN').toString('hex');

    const contract1 = new RunarContract(artifact, [pubKeyHex, 400n, 0n, tokenIdHex]);
    await contract1.deploy(provider, signer, {});

    const contract2 = new RunarContract(artifact, [pubKeyHex, 600n, 0n, tokenIdHex]);
    await contract2.deploy(provider, signer, {});

    // Attacker lies: input 0 claims otherBalance=1600, input 1 claims otherBalance=1400
    // Output would have balance=400, mergeBalance=1600 from input 0
    // But input 1 would produce balance=1400, mergeBalance=600
    // These don't match → hashOutputs mismatch → rejected on-chain
    const utxo2 = contract2.getUtxo()!;
    await expect(
      contract1.call(
        'merge', [null, 1600n, null, 1n], provider, signer,
        {
          additionalContractInputs: [utxo2],
          additionalContractInputArgs: [[null, 1400n, null, 1n]],
          outputs: [
            { satoshis: 1, state: { owner: pubKeyHex, balance: 400n, mergeBalance: 1600n } },
          ],
        },
      ),
    ).rejects.toThrow();
  });

  it('should reject merge with deflated otherBalance', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);
    const tokenIdHex = Buffer.from('DEFLATE-TOKEN').toString('hex');

    const contract1 = new RunarContract(artifact, [pubKeyHex, 400n, 0n, tokenIdHex]);
    await contract1.deploy(provider, signer, {});

    const contract2 = new RunarContract(artifact, [pubKeyHex, 600n, 0n, tokenIdHex]);
    await contract2.deploy(provider, signer, {});

    // Attacker passes otherBalance=-1 for input 1 — fails assert(otherBalance >= 0)
    const utxo2 = contract2.getUtxo()!;
    await expect(
      contract1.call(
        'merge', [null, 100n, null, 1n], provider, signer,
        {
          additionalContractInputs: [utxo2],
          additionalContractInputArgs: [[null, -1n, null, 1n]],
          outputs: [
            { satoshis: 1, state: { owner: pubKeyHex, balance: 100n, mergeBalance: 400n } },
          ],
        },
      ),
    ).rejects.toThrow();
  });

  it('should merge with one zero-balance UTXO', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);
    const tokenIdHex = Buffer.from('ZERO-MERGE-TOKEN').toString('hex');

    const contract1 = new RunarContract(artifact, [pubKeyHex, 0n, 0n, tokenIdHex]);
    await contract1.deploy(provider, signer, {});

    const contract2 = new RunarContract(artifact, [pubKeyHex, 500n, 0n, tokenIdHex]);
    await contract2.deploy(provider, signer, {});

    const utxo2 = contract2.getUtxo()!;
    const { txid } = await contract1.call(
      'merge', [null, 500n, null, 1n], provider, signer,
      {
        additionalContractInputs: [utxo2],
        additionalContractInputArgs: [[null, 0n, null, 1n]],
        outputs: [
          { satoshis: 1, state: { owner: pubKeyHex, balance: 0n, mergeBalance: 500n } },
        ],
      },
    );
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('should reject merge with wrong signer', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');
    const provider = createProvider();
    const { signer: ownerSigner, pubKeyHex: ownerPubKey } = await createFundedWallet(provider);
    const { signer: wrongSigner } = await createFundedWallet(provider);
    const tokenIdHex = Buffer.from('WRONG-MERGE-TOKEN').toString('hex');

    const contract1 = new RunarContract(artifact, [ownerPubKey, 400n, 0n, tokenIdHex]);
    await contract1.deploy(provider, ownerSigner, {});

    const contract2 = new RunarContract(artifact, [ownerPubKey, 600n, 0n, tokenIdHex]);
    await contract2.deploy(provider, ownerSigner, {});

    const utxo2 = contract2.getUtxo()!;
    await expect(
      contract1.call(
        'merge', [null, 600n, null, 1n], provider, wrongSigner,
        {
          additionalContractInputs: [utxo2],
          additionalContractInputArgs: [[null, 400n, null, 1n]],
          outputs: [
            { satoshis: 1, state: { owner: ownerPubKey, balance: 400n, mergeBalance: 600n } },
          ],
        },
      ),
    ).rejects.toThrow();
  });

  it('should reject transfer with wrong signer', async () => {
    const artifact = compileContract('examples/ts/token-ft/FungibleTokenExample.runar.ts');
    const provider = createProvider();
    const { signer: ownerSigner, pubKeyHex: ownerPubKey } = await createFundedWallet(provider);
    const { signer: wrongSigner } = await createFundedWallet(provider);
    const recipient = createWallet();
    const tokenIdHex = Buffer.from('REJECT-TRANSFER').toString('hex');

    const contract = new RunarContract(artifact, [ownerPubKey, 1000n, 0n, tokenIdHex]);
    await contract.deploy(provider, ownerSigner, {});

    await expect(
      contract.call('transfer', [null, recipient.pubKeyHex, 300n, 1n], provider, wrongSigner, {
        outputs: [
          { satoshis: 1, state: { owner: recipient.pubKeyHex, balance: 300n, mergeBalance: 0n } },
          { satoshis: 1, state: { owner: ownerPubKey, balance: 700n, mergeBalance: 0n } },
        ],
      }),
    ).rejects.toThrow();
  });
});
