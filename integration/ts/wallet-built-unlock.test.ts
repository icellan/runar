/**
 * #198 regtest — a covenant input unlocked inside a transaction built OUTSIDE
 * Rúnar (the BRC-100 wallet-funding shape): foreign P2PKH funding input at
 * index 0, the contract input at index 1, outputs in the covenant's order
 * with change at exactly _changeAmount/_changePKH. The real node accepting the
 * broadcast is the proof; the continuation is then spent again to show it is
 * not stranded.
 */

import { describe, it, expect } from 'vitest';
import { Transaction, LockingScript, UnlockingScript } from '@bsv/sdk';
import { compileSource } from './helpers/compile.js';
import { RunarContract, LocalSigner, buildContractUnlock, encodePushData } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider, rpcCall } from './helpers/node.js';

const TOKEN_SOURCE = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class BumpToken extends StatefulSmartContract {
  owner: PubKey;
  value: bigint;

  constructor(owner: PubKey, value: bigint) {
    super(owner, value);
    this.owner = owner;
    this.value = value;
  }

  public bump(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.value + 1n);
  }
}
`;

const p2pkh = (pkh: string): string => '76a914' + pkh + '88ac';

describe('buildContractUnlock on a wallet-built tx (regtest, #198)', () => {
  it('node accepts the tx, and the continuation is spendable', async () => {
    const artifact = compileSource(TOKEN_SOURCE, 'BumpToken.runar.ts');
    const provider = createProvider();
    const owner = await createFundedWallet(provider);
    const funder = await createFundedWallet(provider);

    const token = new RunarContract(artifact, [owner.pubKeyHex, 5n]);
    await token.deploy(provider, owner.signer, { satoshis: 5000 });
    const utxo = token.getUtxo()!;

    const funding = (await provider.getUtxos(funder.address)).find((u) => u.satoshis >= 10_000)!;
    expect(funding).toBeDefined();

    const next = new RunarContract(artifact, [owner.pubKeyHex, 5n]);
    next.setState({ owner: owner.pubKeyHex, value: 6n });
    const contScript = next.getLockingScript();

    // Wallet-built shape: [foreign funding][contract], outputs [continuation][change].
    const FEE = 1000;
    const contSats = 2000;
    const changeSats = funding.satoshis + utxo.satoshis - contSats - FEE;
    const tx = new Transaction();
    tx.addInput({ sourceTXID: funding.txid, sourceOutputIndex: funding.outputIndex, unlockingScript: new UnlockingScript(), sequence: 0xffffffff });
    tx.addInput({ sourceTXID: utxo.txid, sourceOutputIndex: utxo.outputIndex, unlockingScript: new UnlockingScript(), sequence: 0xffffffff });
    tx.addOutput({ satoshis: contSats, lockingScript: LockingScript.fromHex(contScript) });
    tx.addOutput({ satoshis: changeSats, lockingScript: LockingScript.fromHex(p2pkh(owner.pubKeyHash)) });

    const { unlockingScript } = await buildContractUnlock(tx, 1, {
      contract: token, method: 'bump', args: [null, BigInt(contSats)], utxo,
      signer: owner.signer, changePKH: owner.pubKeyHash, changeAmount: BigInt(changeSats),
    }, { dryRun: true });
    tx.inputs[1]!.unlockingScript = UnlockingScript.fromHex(unlockingScript);

    const fundingSigner = new LocalSigner(funder.privKeyHex);
    const sig = await fundingSigner.sign(tx.toHex(), 0, funding.script, funding.satoshis);
    tx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(
      encodePushData(sig) + encodePushData(funder.pubKeyHex),
    );

    const txid = await provider.broadcast(tx);
    expect(txid).toHaveLength(64);
    const mined = (await rpcCall('getrawtransaction', txid, true)) as { confirmations?: number };
    expect(mined.confirmations ?? 0).toBeGreaterThanOrEqual(1);

    // The continuation (output 0) is live: spend it through the normal path.
    const cont = RunarContract.fromUtxo(artifact, {
      txid, outputIndex: 0, satoshis: contSats, script: contScript,
    });
    cont.connect(provider, owner.signer);
    const { txid: txid2 } = await cont.call('bump', [null, 1500n], provider, owner.signer);
    expect(txid2).toHaveLength(64);
    expect(cont.state.value).toBe(7n);
  });
});
