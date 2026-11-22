/**
 * Issue #134 — funding inputs signed with the method/connected signer.
 *
 * deploy() and prepareCall()'s funding-signing loops signed every P2PKH
 * funding input with the connected method `signer` and pushed that signer's
 * pubkey. When the funding UTXOs are owned by a DIFFERENT key, the resulting
 * scriptSig fails OP_EQUALVERIFY. Fix: CallOptions.fundingSigner /
 * DeployOptions.fundingSigner; the funding-input loops use
 * `fundingSigner ?? signer`, while the method's own Sig args keep the
 * connected signer. Default (unset) => connected signer => zero behaviour change.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

// Two distinct keys: the connected method signer, and the funding-coin owner.
const METHOD_KEY = '00'.repeat(31) + '03';
const FUNDING_KEY = '00'.repeat(31) + '07';

/** Replay one input offline; return false instead of throwing on script failure. */
function trySpend(tx: Transaction, inputIdx: number, sourceScriptHex: string, sourceSats: number): boolean {
  const input = tx.inputs[inputIdx]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceSats,
    lockingScript: LockingScript.fromHex(sourceScriptHex),
    transactionVersion: tx.version,
    otherInputs: tx.inputs
      .filter((_: unknown, i: number) => i !== inputIdx)
      .map((inp, idx: number) => ({
        inputIndex: idx >= inputIdx ? idx + 1 : idx,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: undefined as never,
        sourceSatoshis: 0,
        lockingScript: LockingScript.fromHex(''),
      })),
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis })),
    unlockingScript: input.unlockingScript,
    inputIndex: inputIdx,
    inputSequence: input.sequence,
    lockTime: tx.lockTime,
  });
  try {
    return spend.validate();
  } catch {
    return false;
  }
}

function compileSource(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) throw new Error('compile failed');
  return result.artifact;
}

const TRIVIAL_ARTIFACT: RunarArtifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'Trivial',
  asm: '',
  buildTimestamp: '2026-03-02T00:00:00.000Z',
  script: '51', // OP_TRUE
  abi: { constructor: { params: [] }, methods: [{ name: 'spend', params: [], isPublic: true }] },
};

const COUNTER_SRC = `
  class Counter extends StatefulSmartContract {
    count: bigint;
    constructor(count: bigint) { super(count); this.count = count; }
    public increment(): void { this.count = this.count + 1n; }
  }
`;

async function fundingCoinUnderMethodAddress(
  provider: MockProvider,
  methodSigner: LocalSigner,
  fundingScript: string,
  satoshis: number,
  txidSeed: string,
) {
  const address = await methodSigner.getAddress();
  provider.addUtxo(address, { txid: txidSeed.repeat(32), outputIndex: 0, satoshis, script: fundingScript });
}

describe('#134 — deploy() funding inputs honor fundingSigner', () => {
  it('funding input signed by the connected signer FAILS when the coin is owned by another key', async () => {
    const methodSigner = new LocalSigner(METHOD_KEY);
    const fundingSigner = new LocalSigner(FUNDING_KEY);
    const fundingScript = buildP2PKHScript(await fundingSigner.getPublicKey());

    const provider = new MockProvider('testnet', { validateBroadcasts: false });
    await fundingCoinUnderMethodAddress(provider, methodSigner, fundingScript, 100_000, 'a1');

    const contract = new RunarContract(TRIVIAL_ARTIFACT, []);
    await contract.deploy(provider, methodSigner, { satoshis: 1_000 });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    // Bug: input 0 (funding) is signed by methodSigner, pushes methodSigner's
    // pubkey -> OP_EQUALVERIFY against fundingSigner's PKH fails.
    expect(trySpend(deployTx, 0, fundingScript, 100_000)).toBe(false);
  });

  it('funding input is VALID when DeployOptions.fundingSigner owns the coin', async () => {
    const methodSigner = new LocalSigner(METHOD_KEY);
    const fundingSigner = new LocalSigner(FUNDING_KEY);
    const fundingScript = buildP2PKHScript(await fundingSigner.getPublicKey());

    const provider = new MockProvider('testnet', { validateBroadcasts: false });
    await fundingCoinUnderMethodAddress(provider, methodSigner, fundingScript, 100_000, 'a1');

    const contract = new RunarContract(TRIVIAL_ARTIFACT, []);
    await contract.deploy(provider, methodSigner, { satoshis: 1_000, fundingSigner });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    expect(trySpend(deployTx, 0, fundingScript, 100_000)).toBe(true);
  });
});

describe('#134 — call() funding inputs honor fundingSigner', () => {
  it('call funding input is VALID with CallOptions.fundingSigner, INVALID without', async () => {
    const artifact = compileSource(COUNTER_SRC, 'Counter.runar.ts');
    const methodSigner = new LocalSigner(METHOD_KEY);
    const fundingSigner = new LocalSigner(FUNDING_KEY);
    const fundingScript = buildP2PKHScript(await fundingSigner.getPublicKey());

    // ---- without fundingSigner: funding input signed by methodSigner ----
    const provA = new MockProvider('testnet', { validateBroadcasts: false });
    await fundingCoinUnderMethodAddress(provA, methodSigner, fundingScript, 100_000, 'b2');
    const contractA = new RunarContract(artifact, [0n]);
    await contractA.deploy(provA, methodSigner, { satoshis: 1_000 });
    // The deploy spent coin b2; the call needs a coin of its own (it used to
    // re-spend b2, a double spend). 100_000 sats outranks the deploy's change.
    await fundingCoinUnderMethodAddress(provA, methodSigner, fundingScript, 100_000, 'c3');
    await contractA.call('increment', [], provA, methodSigner);
    const callTxA = Transaction.fromHex(provA.getBroadcastedTxs()[1]!);
    expect(callTxA.inputs.length).toBe(2); // 1 contract + 1 funding
    expect(trySpend(callTxA, 1, fundingScript, 100_000)).toBe(false);

    // ---- with fundingSigner: funding input signed by fundingSigner ----
    const provB = new MockProvider('testnet', { validateBroadcasts: false });
    await fundingCoinUnderMethodAddress(provB, methodSigner, fundingScript, 100_000, 'b2');
    const contractB = new RunarContract(artifact, [0n]);
    await contractB.deploy(provB, methodSigner, { satoshis: 1_000 });
    await fundingCoinUnderMethodAddress(provB, methodSigner, fundingScript, 100_000, 'c3');
    await contractB.call('increment', [], provB, methodSigner, { fundingSigner });
    const callTxB = Transaction.fromHex(provB.getBroadcastedTxs()[1]!);
    expect(trySpend(callTxB, 1, fundingScript, 100_000)).toBe(true);
  });
});
