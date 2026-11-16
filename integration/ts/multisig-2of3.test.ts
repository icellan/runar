/**
 * MultiSig2of3 regtest — real OP_CHECKMULTISIG on SV Node with three distinct keys.
 *
 * Happy path uses prepareCall + two LocalSigners (pk1, pk2) so the live node
 * sees a true 2-of-3 ordered CHECKMULTISIG, not a same-key double auto-sign.
 */

import { describe, it, expect } from 'vitest';
import { LocalSigner } from 'runar-sdk';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider, expectNodeRejected } from './helpers/node.js';

const SOURCE = 'integration/contracts/crypto/MultiSig2of3.runar.ts';

describe('MultiSig2of3 (regtest)', () => {
  it('deploys and spends with distinct pk1+pk2 of three keys', async () => {
    const artifact = compileContract(SOURCE);
    expect(artifact.contractName).toBe('MultiSig2of3');

    const provider = createProvider();
    const funder = await createFundedWallet(provider);
    const alice = createWallet();
    const bob = createWallet();
    const charlie = createWallet();

    const contract = new RunarContract(artifact, [
      alice.pubKeyHex,
      bob.pubKeyHex,
      charlie.pubKeyHex,
    ]);
    await contract.deploy(provider, funder.signer, { satoshis: 5000 });
    contract.connect(provider, funder.signer);

    const prepared = await contract.prepareCall('unlock', [null, null]);
    expect(prepared.sigIndices).toEqual([0, 1]);

    const utxo = contract.getUtxo()!;
    const aliceSigner = new LocalSigner(alice.privKeyHex);
    const bobSigner = new LocalSigner(bob.privKeyHex);
    const txHex = prepared.tx.toHex();
    const sig0 = await aliceSigner.sign(txHex, 0, utxo.script, utxo.satoshis);
    const sig1 = await bobSigner.sign(txHex, 0, utxo.script, utxo.satoshis);

    const { txid } = await contract.finalizeCall(prepared, { 0: sig0, 1: sig1 });
    expect(txid).toHaveLength(64);
  });

  it('rejects wrong key pair (attackers not in the 2-of-3 set)', async () => {
    const artifact = compileContract(SOURCE);
    const provider = createProvider();
    const funder = await createFundedWallet(provider);
    const alice = createWallet();
    const bob = createWallet();
    const charlie = createWallet();
    const attacker1 = createWallet();
    const attacker2 = createWallet();

    const contract = new RunarContract(artifact, [
      alice.pubKeyHex,
      bob.pubKeyHex,
      charlie.pubKeyHex,
    ]);
    await contract.deploy(provider, funder.signer, { satoshis: 5000 });
    contract.connect(provider, funder.signer);

    const prepared = await contract.prepareCall('unlock', [null, null]);
    const utxo = contract.getUtxo()!;
    const a1 = new LocalSigner(attacker1.privKeyHex);
    const a2 = new LocalSigner(attacker2.privKeyHex);
    const txHex = prepared.tx.toHex();
    const sig0 = await a1.sign(txHex, 0, utxo.script, utxo.satoshis);
    const sig1 = await a2.sign(txHex, 0, utxo.script, utxo.satoshis);

    await expectNodeRejected(provider, () =>
      contract.finalizeCall(prepared, { 0: sig0, 1: sig1 }),
    );
  });

  it('rejects swapped signature order (sig2 before sig1 for pk1,pk2)', async () => {
    const artifact = compileContract(SOURCE);
    const provider = createProvider();
    const funder = await createFundedWallet(provider);
    const alice = createWallet();
    const bob = createWallet();
    const charlie = createWallet();

    const contract = new RunarContract(artifact, [
      alice.pubKeyHex,
      bob.pubKeyHex,
      charlie.pubKeyHex,
    ]);
    await contract.deploy(provider, funder.signer, { satoshis: 5000 });
    contract.connect(provider, funder.signer);

    const prepared = await contract.prepareCall('unlock', [null, null]);
    const utxo = contract.getUtxo()!;
    const aliceSigner = new LocalSigner(alice.privKeyHex);
    const bobSigner = new LocalSigner(bob.privKeyHex);
    const txHex = prepared.tx.toHex();
    const sigAlice = await aliceSigner.sign(txHex, 0, utxo.script, utxo.satoshis);
    const sigBob = await bobSigner.sign(txHex, 0, utxo.script, utxo.satoshis);

    // Wrong order: slot0=bob, slot1=alice — CHECKMULTISIG key walk fails
    await expectNodeRejected(provider, () =>
      contract.finalizeCall(prepared, { 0: sigBob, 1: sigAlice }),
    );
  });
});
