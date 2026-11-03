/**
 * N-286 — the cross-SDK stateful-merge two-phase vector
 * (`stateful-merge-prepared.json`) is (a) what the TS SDK's
 * prepareCall/finalizeCall derives today, and (b) consensus-valid: @bsv/sdk
 * Spend accepts BOTH contract inputs of the recorded tx, and rejects input 0
 * when its signature is the prepareCall placeholder or input 1's state
 * continuation output is tampered.
 *
 * Does not prove: that the other six SDKs reproduce it — each tier's own
 * N-286 test does that against this file. Nor a live node.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { LockingScript, Spend, Transaction } from '@bsv/sdk';
import { buildMergeVector, MERGE_VECTOR_PATH } from './generate-stateful-merge.js';

interface U { txid: string; outputIndex: number; satoshis: number; script: string }
interface Vector {
  contractUtxo: U;
  extraContractUtxo: U;
  fundingUtxo: U;
  expected: { referenceTxHex: string; preparedTxHex: string; inputCount: number; sigIndices: number[] };
}

const vector: Vector = JSON.parse(readFileSync(MERGE_VECTOR_PATH, 'utf8'));
const prevouts = [vector.contractUtxo, vector.extraContractUtxo, vector.fundingUtxo];

function spendInput(tx: Transaction, i: number): boolean {
  const input = tx.inputs[i]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: prevouts[i]!.satoshis,
    lockingScript: LockingScript.fromHex(prevouts[i]!.script),
    transactionVersion: tx.version,
    otherInputs: tx.inputs
      .map((inp, idx) => ({ inp, idx }))
      .filter(({ idx }) => idx !== i)
      .map(({ inp, idx }) => ({
        inputIndex: idx,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: undefined as never,
        sourceSatoshis: prevouts[idx]!.satoshis,
        lockingScript: LockingScript.fromHex(prevouts[idx]!.script),
      })),
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis })),
    unlockingScript: input.unlockingScript!,
    inputIndex: i,
    inputSequence: input.sequence!,
    lockTime: tx.lockTime,
  });
  try {
    return spend.validate();
  } catch (e) {
    if (e instanceof Error && /^Script evaluation error:/.test(e.message)) return false;
    throw e;
  }
}

describe('N-286 sdk-call vector — stateful merge through prepareCall/finalizeCall', () => {
  it('matches a fresh TS SDK derivation', async () => {
    expect(JSON.parse(JSON.stringify(await buildMergeVector()))).toEqual(vector);
  });

  it('spends two contract inputs plus funding, primary Sig at index 0', () => {
    const tx = Transaction.fromHex(vector.expected.referenceTxHex);
    expect(tx.inputs.length).toBe(3);
    expect(vector.expected.inputCount).toBe(3);
    expect(vector.expected.sigIndices).toEqual([0]);
    expect(tx.inputs[1]!.sourceTXID).toBe(vector.extraContractUtxo.txid);
  });

  it('Spend accepts every input of the recorded tx', () => {
    const tx = Transaction.fromHex(vector.expected.referenceTxHex);
    for (let i = 0; i < 3; i++) expect(spendInput(tx, i)).toBe(true);
  });

  it('finalizeCall rewrote input 0 only; the placeholder primary is rejected', () => {
    const ref = Transaction.fromHex(vector.expected.referenceTxHex);
    const prep = Transaction.fromHex(vector.expected.preparedTxHex);
    expect(prep.inputs[1]!.unlockingScript!.toHex()).toBe(ref.inputs[1]!.unlockingScript!.toHex());
    expect(prep.inputs[2]!.unlockingScript!.toHex()).toBe(ref.inputs[2]!.unlockingScript!.toHex());
    expect(prep.inputs[0]!.unlockingScript!.toHex()).not.toBe(ref.inputs[0]!.unlockingScript!.toHex());
    expect(spendInput(prep, 0)).toBe(false);
  });

  it('a tampered continuation output is rejected on the extra contract input', () => {
    const tx = Transaction.fromHex(vector.expected.referenceTxHex);
    tx.outputs[0]!.satoshis = tx.outputs[0]!.satoshis! - 1;
    expect(spendInput(tx, 1)).toBe(false);
  });
});
