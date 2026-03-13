/**
 * End-to-end test for InductiveSmartContract OP_PUSH_TX preimage.
 *
 * Compiles InductiveToken, deploys via MockProvider, prepares a call,
 * then verifies the BIP-143 preimage via BSV SDK's Spend.validate().
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import type { RunarArtifact } from 'runar-ir-schema';
import {
  Transaction,
  LockingScript,
  UnlockingScript,
  Spend,
  Hash,
} from '@bsv/sdk';

const PROJECT_ROOT = resolve(import.meta.dirname, '..', '..', '..', '..');
const ZERO_SENTINEL = '00'.repeat(36);
const ZERO_PROOF = '00'.repeat(192);

function compileContract(sourcePath: string): RunarArtifact {
  const absPath = resolve(PROJECT_ROOT, sourcePath);
  const source = readFileSync(absPath, 'utf-8');
  const fileName = absPath.split('/').pop()!;
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`Compile failed: ${JSON.stringify(result.errors)}`);
  }
  return result.artifact;
}

const PRIV_KEY =
  '0000000000000000000000000000000000000000000000000000000000000001';

async function setupFundedProvider(
  satoshis: number,
): Promise<{
  provider: MockProvider;
  signer: LocalSigner;
  address: string;
  pubKeyHex: string;
}> {
  const signer = new LocalSigner(PRIV_KEY);
  const address = await signer.getAddress();
  const pubKeyHex = await signer.getPublicKey();
  const provider = new MockProvider();
  provider.addUtxo(address, {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  });
  return { provider, signer, address, pubKeyHex };
}

function setupRealTxidBroadcast(provider: MockProvider, signer: LocalSigner) {
  provider.broadcast = async (rawTxOrObj: any): Promise<string> => {
    const rawTx = typeof rawTxOrObj === 'string' ? rawTxOrObj : rawTxOrObj.toHex();
    const rawBytes = rawTx.match(/.{2}/g)!.map((b: string) => parseInt(b, 16));
    const hash1 = Hash.sha256(rawBytes);
    const hash2 = Hash.sha256(hash1);
    const txid = Array.from(hash2)
      .reverse()
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    const tx = Transaction.fromHex(rawTx);
    provider.addTransaction({
      txid,
      version: tx.version,
      inputs: tx.inputs.map((inp) => ({
        txid: inp.sourceTXID!,
        outputIndex: inp.sourceOutputIndex,
        script: inp.unlockingScript?.toHex() ?? '',
        sequence: inp.sequence,
      })),
      outputs: tx.outputs.map((out) => ({
        satoshis: out.satoshis ?? 0,
        script: out.lockingScript.toHex(),
      })),
      locktime: tx.lockTime,
      raw: rawTx,
    });

    const address = await signer.getAddress();
    for (let i = 0; i < tx.outputs.length; i++) {
      provider.addUtxo(address, {
        txid,
        outputIndex: i,
        satoshis: tx.outputs[i]!.satoshis ?? 0,
        script: tx.outputs[i]!.lockingScript.toHex(),
      });
    }

    return txid;
  };
}

function validateSpend(
  sourceTxid: string,
  sourceOutputIndex: number,
  sourceSatoshis: number,
  lockingScriptHex: string,
  spendTx: Transaction,
): boolean {
  const spend = new Spend({
    sourceTXID: sourceTxid,
    sourceOutputIndex,
    sourceSatoshis,
    lockingScript: LockingScript.fromHex(lockingScriptHex),
    transactionVersion: spendTx.version,
    otherInputs: spendTx.inputs
      .filter((_inp, i) => i !== 0)
      .map((inp) => ({
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: inp.unlockingScript,
      })),
    inputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(
      spendTx.inputs[0]!.unlockingScript?.toHex() ?? '',
    ),
    outputs: spendTx.outputs.map((o) => ({
      lockingScript: o.lockingScript,
      satoshis: o.satoshis ?? 0,
    })),
    inputSequence: spendTx.inputs[0]!.sequence,
    lockTime: spendTx.lockTime,
  });
  return spend.validate();
}

describe('InductiveSmartContract preimage verification', () => {
  it('should produce a valid OP_PUSH_TX preimage for first spend (outputs path)', async () => {
    const artifact = compileContract(
      'examples/ts/inductive-token/InductiveToken.runar.ts',
    );
    const { provider, signer, pubKeyHex } = await setupFundedProvider(2_000_000);

    const contract = new RunarContract(artifact, [
      pubKeyHex,
      1000n,
      Buffer.from('TEST-TOKEN').toString('hex'),
      ZERO_SENTINEL,
      ZERO_PROOF,
    ]);

    contract.connect(provider, signer);
    setupRealTxidBroadcast(provider, signer);

    const { txid: deployTxid } = await contract.deploy({ satoshis: 500_000 });
    expect(deployTxid).toBeTruthy();

    const { txid: callTxid } = await contract.call('send', [null, pubKeyHex, 1n], {
      outputs: [{ satoshis: 1, state: { owner: pubKeyHex, balance: 1000n } }],
    });
    expect(callTxid).toBeTruthy();

    // Validate the spend
    const deployTxData = await provider.getTransaction(deployTxid);
    const deployTx = Transaction.fromHex(deployTxData.raw!);
    const lockingScriptHex = deployTx.outputs[0]!.lockingScript.toHex();

    const callTxData = await provider.getTransaction(callTxid);
    const spendTx = Transaction.fromHex(callTxData.raw!);

    const valid = validateSpend(deployTxid, 0, 500_000, lockingScriptHex, spendTx);
    expect(valid).toBe(true);
  });

  it('should produce a valid preimage using newState path (single-output)', async () => {
    const artifact = compileContract(
      'examples/ts/inductive-token/InductiveToken.runar.ts',
    );
    const { provider, signer, pubKeyHex } = await setupFundedProvider(2_000_000);

    const contract = new RunarContract(artifact, [
      pubKeyHex,
      1000n,
      Buffer.from('TEST-TOKEN').toString('hex'),
      ZERO_SENTINEL,
      ZERO_PROOF,
    ]);

    contract.connect(provider, signer);
    setupRealTxidBroadcast(provider, signer);

    const { txid: deployTxid } = await contract.deploy({ satoshis: 500_000 });
    expect(deployTxid).toBeTruthy();

    const { txid: callTxid } = await contract.call('send', [null, pubKeyHex, 1n], {
      newState: { owner: pubKeyHex },
      satoshis: 1,
    });
    expect(callTxid).toBeTruthy();

    const deployTxData = await provider.getTransaction(deployTxid);
    const deployTx = Transaction.fromHex(deployTxData.raw!);
    const lockingScriptHex = deployTx.outputs[0]!.lockingScript.toHex();

    const callTxData = await provider.getTransaction(callTxid);
    const spendTx = Transaction.fromHex(callTxData.raw!);

    const valid = validateSpend(deployTxid, 0, 500_000, lockingScriptHex, spendTx);
    expect(valid).toBe(true);
  });

  it('should validate second spend (non-genesis)', async () => {
    const artifact = compileContract(
      'examples/ts/inductive-token/InductiveToken.runar.ts',
    );
    const { provider, signer, pubKeyHex } = await setupFundedProvider(2_000_000);

    const contract = new RunarContract(artifact, [
      pubKeyHex,
      1000n,
      Buffer.from('TEST-CHAIN').toString('hex'),
      ZERO_SENTINEL,
      ZERO_PROOF,
    ]);

    contract.connect(provider, signer);
    setupRealTxidBroadcast(provider, signer);

    // Deploy
    const { txid: deployTxid } = await contract.deploy({ satoshis: 500_000 });
    expect(deployTxid).toBeTruthy();

    // Tx1: genesis spend
    const { txid: tx1id } = await contract.call('send', [null, pubKeyHex, 1n], {
      outputs: [{ satoshis: 1, state: { owner: pubKeyHex, balance: 1000n } }],
    });
    expect(tx1id).toBeTruthy();

    // Tx2: non-genesis spend
    const { txid: tx2id } = await contract.call('send', [null, pubKeyHex, 1n], {
      outputs: [{ satoshis: 1, state: { owner: pubKeyHex, balance: 1000n } }],
    });
    expect(tx2id).toBeTruthy();

    // Validate Tx2 spend
    const tx1Data = await provider.getTransaction(tx1id);
    const tx1Parsed = Transaction.fromHex(tx1Data.raw!);

    // Find contract output in Tx1
    let sourceOutputIndex = 0;
    for (let i = 0; i < tx1Parsed.outputs.length; i++) {
      if (tx1Parsed.outputs[i]!.lockingScript.toHex().length > 100) {
        sourceOutputIndex = i;
        break;
      }
    }

    const lockingScriptHex = tx1Parsed.outputs[sourceOutputIndex]!.lockingScript.toHex();
    const sourceSatoshis = tx1Parsed.outputs[sourceOutputIndex]!.satoshis ?? 0;

    const tx2Data = await provider.getTransaction(tx2id);
    const tx2Parsed = Transaction.fromHex(tx2Data.raw!);

    const valid = validateSpend(tx1id, sourceOutputIndex, sourceSatoshis, lockingScriptHex, tx2Parsed);
    expect(valid).toBe(true);
  });

  it('should produce matching outputs for both paths', async () => {
    const artifact = compileContract(
      'examples/ts/inductive-token/InductiveToken.runar.ts',
    );

    // Run outputs path
    const { provider: p1, signer: s1, pubKeyHex: pk1 } = await setupFundedProvider(2_000_000);
    const c1 = new RunarContract(artifact, [pk1, 1000n, Buffer.from('TEST').toString('hex'), ZERO_SENTINEL, ZERO_PROOF]);
    c1.connect(p1, s1);
    setupRealTxidBroadcast(p1, s1);
    await c1.deploy({ satoshis: 500_000 });
    const { txid: txid1 } = await c1.call('send', [null, pk1, 1n], {
      outputs: [{ satoshis: 1, state: { owner: pk1, balance: 1000n } }],
    });
    const txData1 = await p1.getTransaction(txid1);
    const tx1 = Transaction.fromHex(txData1.raw!);

    // Run newState path
    const { provider: p2, signer: s2, pubKeyHex: pk2 } = await setupFundedProvider(2_000_000);
    const c2 = new RunarContract(artifact, [pk2, 1000n, Buffer.from('TEST').toString('hex'), ZERO_SENTINEL, ZERO_PROOF]);
    c2.connect(p2, s2);
    setupRealTxidBroadcast(p2, s2);
    await c2.deploy({ satoshis: 500_000 });
    const { txid: txid2 } = await c2.call('send', [null, pk2, 1n], {
      newState: { owner: pk2 },
    });
    const txData2 = await p2.getTransaction(txid2);
    const tx2 = Transaction.fromHex(txData2.raw!);

    // Contract output scripts should match (same key, same contract)
    const isContractOutput = (hex: string) => hex.length > 100;
    const contractOuts1 = tx1.outputs.filter(o => isContractOutput(o.lockingScript.toHex()));
    const contractOuts2 = tx2.outputs.filter(o => isContractOutput(o.lockingScript.toHex()));

    expect(contractOuts1.length).toBeGreaterThan(0);
    expect(contractOuts2.length).toBeGreaterThan(0);
    expect(contractOuts1[0]!.lockingScript.toHex()).toBe(contractOuts2[0]!.lockingScript.toHex());
  });
});
