/**
 * N-038 — the cross-SDK SIGHASH_SINGLE stateful call vector
 * (`sighash-single-stateful.json`) is (a) what the TS SDK derives today, and
 * (b) consensus-valid: its recorded call tx's contract input is accepted by
 * @bsv/sdk Spend, and rejected once output[0] (the one output SINGLE commits)
 * is tampered in state or satoshis.
 *
 * Also pins the fold-OFF compiler outputs (`expected-ir.json`,
 * `expected-script.hex`) every tier's N-038 compiler test compares against, and
 * checks they equal a fresh TS compile and the vector's own artifact script.
 *
 * Does not prove: the other six SDKs / compilers reproduce it — each tier's own
 * N-038 test does that against these files.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { LockingScript, Spend, Transaction } from '@bsv/sdk';
import { buildCompilerPins, buildVector, IR_PATH, SCRIPT_PATH, VECTOR_PATH } from './generate.js';

interface Vector {
  contractUtxo: { satoshis: number; script: string };
  expected: { referenceTxHex: string; input0UnlockingHex: string; outputCount: number; methodParams: string[] };
}

const vector: Vector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));

function spendInput0(tx: Transaction): { valid: boolean; error?: string } {
  const input = tx.inputs[0]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: vector.contractUtxo.satoshis,
    lockingScript: LockingScript.fromHex(vector.contractUtxo.script),
    transactionVersion: tx.version,
    otherInputs: tx.inputs.slice(1).map((inp, idx) => ({
      inputIndex: idx + 1,
      sourceOutputIndex: inp.sourceOutputIndex,
      sourceTXID: inp.sourceTXID!,
      sequence: inp.sequence,
      unlockingScript: undefined as never,
      sourceSatoshis: 0,
      lockingScript: LockingScript.fromHex(''),
    })),
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis })),
    unlockingScript: input.unlockingScript!,
    inputIndex: 0,
    inputSequence: input.sequence!,
    lockTime: tx.lockTime,
  });
  try {
    return { valid: spend.validate() };
  } catch (e) {
    if (e instanceof Error && /^Script evaluation error:/.test(e.message)) return { valid: false, error: e.message };
    throw e;
  }
}

describe('N-038 sdk-call vector — SIGHASH_SINGLE stateful call with change', () => {
  it('matches a fresh TS SDK derivation', async () => {
    expect(JSON.parse(JSON.stringify(await buildVector()))).toEqual(vector);
  });

  it('the compiler pins match a fresh TS compile and the vector artifact', () => {
    const pins = buildCompilerPins();
    expect(readFileSync(IR_PATH, 'utf8')).toBe(pins.ir);
    expect(readFileSync(SCRIPT_PATH, 'utf8')).toBe(pins.script);
    const v = JSON.parse(readFileSync(VECTOR_PATH, 'utf8')) as { artifact: { script: string } };
    expect(v.artifact.script).toBe(pins.script.trim());
  });

  it('declares no change params and carries a change output', () => {
    expect(vector.expected.methodParams).toEqual(['txPreimage']);
    expect(vector.expected.outputCount).toBe(2);
  });

  it('the recorded contract input is accepted by Spend', () => {
    const tx = Transaction.fromHex(vector.expected.referenceTxHex);
    expect(tx.inputs[0]!.unlockingScript!.toHex()).toBe(vector.expected.input0UnlockingHex);
    expect(spendInput0(tx)).toEqual({ valid: true });
  });

  it('a tampered output[0] (state byte or satoshis) is rejected', () => {
    const state = Transaction.fromHex(vector.expected.referenceTxHex);
    const hex = state.outputs[0]!.lockingScript.toHex();
    state.outputs[0]!.lockingScript = LockingScript.fromHex(
      hex.slice(0, -2) + (parseInt(hex.slice(-2), 16) ^ 0xff).toString(16).padStart(2, '0'),
    );
    expect(spendInput0(state).valid).toBe(false);
    const sats = Transaction.fromHex(vector.expected.referenceTxHex);
    sats.outputs[0]!.satoshis = sats.outputs[0]!.satoshis! - 1;
    expect(spendInput0(sats).valid).toBe(false);
  });
});
