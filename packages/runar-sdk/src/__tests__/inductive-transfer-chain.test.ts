/**
 * Reproduces the multi-output transfer → send chain for InductiveSmartContract.
 * This tests the specific scenario: deploy → send (genesis) → transfer (split) → send (continuation).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import type { RunarArtifact } from 'runar-ir-schema';
import { Transaction, LockingScript, UnlockingScript, Spend, Hash } from '@bsv/sdk';

const PROJECT_ROOT = resolve(import.meta.dirname, '..', '..', '..', '..');
const ZERO_SENTINEL = '00'.repeat(36);
const ZERO_PROOF = '00'.repeat(256);
const PRIV_KEY = '0000000000000000000000000000000000000000000000000000000000000001';

function compileContract(sourcePath: string): RunarArtifact {
  const absPath = resolve(PROJECT_ROOT, sourcePath);
  const source = readFileSync(absPath, 'utf-8');
  const result = compile(source, { fileName: absPath.split('/').pop()! });
  if (!result.artifact) throw new Error(`Compile failed: ${JSON.stringify(result.errors)}`);
  return result.artifact;
}

function setupRealTxidBroadcast(provider: MockProvider, signer: LocalSigner) {
  provider.broadcast = async (rawTxOrObj: any): Promise<string> => {
    const rawTx = typeof rawTxOrObj === 'string' ? rawTxOrObj : rawTxOrObj.toHex();
    const rawBytes = rawTx.match(/.{2}/g)!.map((b: string) => parseInt(b, 16));
    const hash1 = Hash.sha256(rawBytes);
    const hash2 = Hash.sha256(hash1);
    const txid = Array.from(hash2).reverse().map((b) => b.toString(16).padStart(2, '0')).join('');
    const tx = Transaction.fromHex(rawTx);
    provider.addTransaction({
      txid, version: tx.version,
      inputs: tx.inputs.map((inp) => ({ txid: inp.sourceTXID!, outputIndex: inp.sourceOutputIndex, script: inp.unlockingScript?.toHex() ?? '', sequence: inp.sequence })),
      outputs: tx.outputs.map((out) => ({ satoshis: out.satoshis ?? 0, script: out.lockingScript.toHex() })),
      locktime: tx.lockTime, raw: rawTx,
    });
    const address = await signer.getAddress();
    for (let i = 0; i < tx.outputs.length; i++) {
      provider.addUtxo(address, { txid, outputIndex: i, satoshis: tx.outputs[i]!.satoshis ?? 0, script: tx.outputs[i]!.lockingScript.toHex() });
    }
    return txid;
  };
}

describe('InductiveSmartContract transfer chain', () => {
  it('should validate send after multi-output transfer', async () => {
    const artifact = compileContract('examples/ts/inductive-token/InductiveToken.runar.ts');
    const signer = new LocalSigner(PRIV_KEY);
    const address = await signer.getAddress();
    const pubKeyHex = await signer.getPublicKey();
    const recipientPub = '02' + 'bb'.repeat(32);

    const provider = new MockProvider();
    provider.addUtxo(address, { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 2_000_000, script: '76a914' + '00'.repeat(20) + '88ac' });
    setupRealTxidBroadcast(provider, signer);

    const contract = new RunarContract(artifact, [pubKeyHex, 1000n, Buffer.from('TEST').toString('hex'), ZERO_SENTINEL, ZERO_PROOF]);
    contract.connect(provider, signer);

    // Deploy
    const { txid: deployTxid } = await contract.deploy({ satoshis: 500_000 });
    expect(deployTxid).toBeTruthy();

    // Tx1: genesis send
    const { txid: tx1id } = await contract.call('send', [null, pubKeyHex, 1n], {
      outputs: [{ satoshis: 1, state: { owner: pubKeyHex, balance: 1000n } }],
    });
    expect(tx1id).toBeTruthy();

    // Tx2: transfer (split)
    const { txid: tx2id } = await contract.call('transfer', [null, recipientPub, 300n, 1n], {
      outputs: [
        { satoshis: 1, state: { owner: recipientPub, balance: 300n } },
        { satoshis: 1, state: { owner: pubKeyHex, balance: 700n } },
      ],
      continuationOutputIndex: 1,
    });
    expect(tx2id).toBeTruthy();

    // Tx3: send from 700-balance continuation
    const { txid: tx3id } = await contract.call('send', [null, pubKeyHex, 1n], {
      outputs: [{ satoshis: 1, state: { owner: pubKeyHex, balance: 700n } }],
    });
    expect(tx3id).toBeTruthy();

    // Validate Tx3 via BSV SDK Spend
    const tx2Data = await provider.getTransaction(tx2id);
    const tx2Parsed = Transaction.fromHex(tx2Data.raw!);
    const sourceOutputIndex = 1; // continuation
    const lockingScriptHex = tx2Parsed.outputs[sourceOutputIndex]!.lockingScript.toHex();
    const sourceSatoshis = tx2Parsed.outputs[sourceOutputIndex]!.satoshis ?? 0;

    const tx3Data = await provider.getTransaction(tx3id);
    const tx3Parsed = Transaction.fromHex(tx3Data.raw!);

    const spend = new Spend({
      sourceTXID: tx2id,
      sourceOutputIndex,
      sourceSatoshis,
      lockingScript: LockingScript.fromHex(lockingScriptHex),
      transactionVersion: tx3Parsed.version,
      otherInputs: tx3Parsed.inputs.filter((_inp, i) => i !== 0).map((inp) => ({
        sourceOutputIndex: inp.sourceOutputIndex, sourceTXID: inp.sourceTXID!, sequence: inp.sequence, unlockingScript: inp.unlockingScript,
      })),
      inputIndex: 0,
      unlockingScript: UnlockingScript.fromHex(tx3Parsed.inputs[0]!.unlockingScript?.toHex() ?? ''),
      outputs: tx3Parsed.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis ?? 0 })),
      inputSequence: tx3Parsed.inputs[0]!.sequence,
      lockTime: tx3Parsed.lockTime,
    });

    expect(spend.validate()).toBe(true);
  });
});
