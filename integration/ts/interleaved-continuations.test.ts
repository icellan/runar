/**
 * #197 regtest — `addOutput(a); addRawOutput(fee, payee); addOutput(b)`.
 * The real node must accept the transaction the SDK builds from the
 * interpreter's source order, the result must report both continuations, and
 * BOTH continuations must be spendable on-chain (neither stranded).
 */

import { describe, it, expect } from 'vitest';
import { Transaction } from '@bsv/sdk';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider, rpcCall } from './helpers/node.js';

const SOURCE = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class Splitter extends StatefulSmartContract {
  owner: PubKey;
  count: bigint;

  constructor(owner: PubKey, count: bigint) {
    super(owner, count);
    this.owner = owner;
    this.count = count;
  }

  public split(sig: Sig, payee: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addOutput(1000n, this.owner, this.count + 1n);
    this.addRawOutput(546n, payee);
    this.addOutput(1000n, this.owner, this.count + 100n);
  }
}
`;

describe('interleaved continuations (regtest, #197)', () => {
  it('node accepts [a][raw][b]; both continuations are reported and spendable', async () => {
    const artifact = compileSource(SOURCE, 'Splitter.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHex, 0n]);
    await contract.deploy(provider, signer, { satoshis: 5000 });

    const payee = '76a914' + pubKeyHash + '88ac';
    const { txid, continuations } = await contract.call('split', [null, payee], provider, signer);

    const tx = Transaction.fromHex((await rpcCall('getrawtransaction', txid)) as string);
    expect(tx.outputs[1]!.lockingScript.toHex()).toBe(payee);
    expect(tx.outputs[1]!.satoshis).toBe(546);
    expect(continuations).toEqual([
      { outputIndex: 0, satoshis: 1000, state: { owner: pubKeyHex, count: 1n } },
      { outputIndex: 2, satoshis: 1000, state: { owner: pubKeyHex, count: 100n } },
    ]);
    expect(contract.getUtxo()?.outputIndex).toBe(0);
    expect(contract.state.count).toBe(1n);

    // Continuation 1 (output 2) is an independent UTXO: spend it FIRST, from a
    // contract built at its outpoint, before the tracked one.
    const second = RunarContract.fromUtxo(artifact, {
      txid, outputIndex: 2, satoshis: 1000, script: tx.outputs[2]!.lockingScript.toHex(),
    });
    expect(second.state.count).toBe(100n);
    second.connect(provider, signer);
    const { txid: txidB } = await second.call('split', [null, payee], provider, signer);
    expect(txidB).toHaveLength(64);
    expect(second.state.count).toBe(101n);

    // Continuation 0 (tracked): spendable too.
    const { txid: txidA } = await contract.call('split', [null, payee], provider, signer);
    expect(txidA).toHaveLength(64);
    expect(contract.state.count).toBe(2n);
  });
});
