/**
 * N-412 — a STATELESS contract method that takes the auto-injected intent
 * witness `_prevOutScript_0` gets the witness push in its REAL unlocking
 * script, between the declared args and the method selector.
 *
 * Proves: (a) the shared cross-SDK vector `stateless-witness.json` is what the
 * TS SDK derives today (call() for `peek` and `spend`, and prepareCall +
 * finalizeCall for `spend`); (b) each recorded contract input is accepted by
 * @bsv/sdk Spend — for `spend` that includes a real OP_CHECKSIG over the
 * LocalSigner signature; (c) the unlock layout is exactly
 * `<declared args> <push(prevOutScript)> <selector>`; (d) a near-miss with one
 * byte of the witness push flipped, or with the witness push removed, is
 * rejected by Spend.
 *
 * Does not prove: `_serialisedOutputs` on a stateless method (requireOutputP2PKH
 * is typecheck-gated to StatefulSmartContract, so that shape cannot be
 * compiled), or that the other six SDKs reproduce the vector — each tier's own
 * N-412 test does that against this file.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { LockingScript, Spend, Transaction, UnlockingScript } from '@bsv/sdk';
import { encodePushData } from '../../packages/runar-sdk/src/contract.js';
import { buildStatelessWitnessVector, STATELESS_WITNESS_VECTOR_PATH } from './generate-stateless-witness.js';

interface Scenario { input0UnlockingHex: string; referenceTxHex: string }
interface Vector {
  contractUtxo: { satoshis: number; script: string };
  pubKeyHex: string;
  prevOutScriptHex: string;
  expected: { peek: Scenario; spend: Scenario & { signatureHex: string } };
}

const vector: Vector = JSON.parse(readFileSync(STATELESS_WITNESS_VECTOR_PATH, 'utf8'));

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

function withInput0Unlock(txHex: string, unlockHex: string): Transaction {
  const tx = Transaction.fromHex(txHex);
  tx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(unlockHex);
  return tx;
}

describe('N-412 stateless intent-witness call vector', () => {
  const witnessPush = encodePushData(vector.prevOutScriptHex);

  it('matches a fresh TS SDK derivation (call + prepareCall/finalizeCall)', async () => {
    expect(JSON.parse(JSON.stringify(await buildStatelessWitnessVector()))).toEqual(vector);
  });

  it('pushes <declared args> <witness> <selector>', () => {
    // peek(5): OP_5, witness, selector OP_1 (second public method).
    expect(vector.expected.peek.input0UnlockingHex).toBe('55' + witnessPush + '51');
    // spend(sig, pubKey): sig push, pubKey push, witness, selector OP_0.
    const sig = vector.expected.spend.signatureHex;
    expect(vector.expected.spend.input0UnlockingHex).toBe(
      encodePushData(sig) + encodePushData(vector.pubKeyHex) + witnessPush + '00',
    );
  });

  for (const name of ['peek', 'spend'] as const) {
    it(`${name}: the recorded contract input is accepted by Spend`, () => {
      const s = vector.expected[name];
      const tx = Transaction.fromHex(s.referenceTxHex);
      expect(tx.inputs[0]!.unlockingScript!.toHex()).toBe(s.input0UnlockingHex);
      expect(spendInput0(tx)).toEqual({ valid: true });
    });

    it(`${name}: a tampered or missing witness push is rejected by Spend`, () => {
      const s = vector.expected[name];
      const at = s.input0UnlockingHex.indexOf(witnessPush);
      expect(at).toBeGreaterThan(0);
      // Flip the last byte of the witness data: hash256 no longer matches.
      const lastByte = at + witnessPush.length - 2;
      const flipped = (parseInt(s.input0UnlockingHex.slice(lastByte, lastByte + 2), 16) ^ 0x01)
        .toString(16).padStart(2, '0');
      const tampered = s.input0UnlockingHex.slice(0, lastByte) + flipped + s.input0UnlockingHex.slice(lastByte + 2);
      expect(spendInput0(withInput0Unlock(s.referenceTxHex, tampered)).valid).toBe(false);
      // The pre-N-412 shape: the witness push omitted entirely.
      const omitted = s.input0UnlockingHex.slice(0, at) + s.input0UnlockingHex.slice(at + witnessPush.length);
      expect(spendInput0(withInput0Unlock(s.referenceTxHex, omitted)).valid).toBe(false);
    });
  }
});
