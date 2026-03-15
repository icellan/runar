// ---------------------------------------------------------------------------
// runar-sdk/calling.ts — Transaction construction for method invocation
// ---------------------------------------------------------------------------

import { Transaction, LockingScript, UnlockingScript } from '@bsv/sdk';
import type { UTXO } from './types.js';
import { buildP2PKHScript } from './script-utils.js';

/**
 * Build a transaction that spends a contract UTXO (method call).
 *
 * The transaction:
 * - Input 0: the current contract UTXO with the given unlocking script.
 * - Additional inputs: funding UTXOs if provided.
 * - Output 0 (optional): new contract UTXO with updated locking script
 *   (for stateful contracts).
 * - Last output (optional): change.
 *
 * Returns the Transaction object (with unlocking script for input 0
 * already placed) and the total input count.
 */
export function buildCallTransaction(
  currentUtxo: UTXO,
  unlockingScript: string,
  newLockingScript?: string,
  newSatoshis?: number,
  changeAddress?: string,
  changeScript?: string,
  additionalUtxos?: UTXO[],
  feeRate: number = 1,
  options?: {
    /** Multiple contract outputs (replaces single newLockingScript). */
    contractOutputs?: Array<{ script: string; satoshis: number }>;
    /** Additional contract inputs with their own unlocking scripts (for merge). */
    additionalContractInputs?: Array<{ utxo: UTXO; unlockingScript: string }>;
  },
): { tx: Transaction; inputCount: number; changeAmount: number } {
  const extraContractInputs = options?.additionalContractInputs ?? [];
  const allUtxos = [currentUtxo, ...extraContractInputs.map((i) => i.utxo), ...(additionalUtxos ?? [])];

  const totalInput = allUtxos.reduce((sum, u) => sum + u.satoshis, 0);

  // Determine contract outputs: multi-output takes priority over single
  const contractOutputs: Array<{ script: string; satoshis: number }> =
    options?.contractOutputs ??
    (newLockingScript
      ? [{ script: newLockingScript, satoshis: newSatoshis ?? currentUtxo.satoshis }]
      : []);

  const contractOutputSats = contractOutputs.reduce((sum, o) => sum + o.satoshis, 0);

  // Estimate fee using actual script sizes
  const input0Size = 32 + 4 + varIntByteSize(unlockingScript.length / 2) +
    unlockingScript.length / 2 + 4;
  let extraContractInputsSize = 0;
  for (const ci of extraContractInputs) {
    extraContractInputsSize += 32 + 4 +
      varIntByteSize(ci.unlockingScript.length / 2) +
      ci.unlockingScript.length / 2 + 4;
  }
  const p2pkhInputsSize = (additionalUtxos?.length ?? 0) * 148;
  const inputsSize = input0Size + extraContractInputsSize + p2pkhInputsSize;

  let outputsSize = 0;
  for (const co of contractOutputs) {
    outputsSize += 8 + varIntByteSize(co.script.length / 2) + co.script.length / 2;
  }
  if (changeAddress || changeScript) {
    outputsSize += 34; // P2PKH change
  }
  const estimatedSize = 10 + inputsSize + outputsSize;
  const fee = Math.ceil(estimatedSize * feeRate);

  const change = totalInput - contractOutputSats - fee;

  // Build Transaction object
  const tx = new Transaction();

  // Input 0: primary contract UTXO with unlocking script
  tx.addInput({
    sourceTXID: currentUtxo.txid,
    sourceOutputIndex: currentUtxo.outputIndex,
    unlockingScript: UnlockingScript.fromHex(unlockingScript),
    sequence: 0xffffffff,
  });

  // Additional contract inputs (with their own unlocking scripts)
  for (const ci of extraContractInputs) {
    tx.addInput({
      sourceTXID: ci.utxo.txid,
      sourceOutputIndex: ci.utxo.outputIndex,
      unlockingScript: UnlockingScript.fromHex(ci.unlockingScript),
      sequence: 0xffffffff,
    });
  }

  // P2PKH funding inputs (unsigned)
  if (additionalUtxos) {
    for (const utxo of additionalUtxos) {
      tx.addInput({
        sourceTXID: utxo.txid,
        sourceOutputIndex: utxo.outputIndex,
        unlockingScript: new UnlockingScript(),
        sequence: 0xffffffff,
      });
    }
  }

  // Contract outputs
  for (const co of contractOutputs) {
    tx.addOutput({
      satoshis: co.satoshis,
      lockingScript: LockingScript.fromHex(co.script),
    });
  }

  // Change output
  if (change > 0 && (changeAddress || changeScript)) {
    const actualChangeScript =
      changeScript || buildP2PKHScript(changeAddress!);
    tx.addOutput({
      satoshis: change,
      lockingScript: LockingScript.fromHex(actualChangeScript),
    });
  }

  return { tx, inputCount: allUtxos.length, changeAmount: change > 0 ? change : 0 };
}

// ---------------------------------------------------------------------------
// Fee estimation
// ---------------------------------------------------------------------------

const P2PKH_INPUT_SIZE = 148;
const P2PKH_OUTPUT_SIZE = 34;
const TX_OVERHEAD = 10;

/**
 * Estimate the fee for a method call transaction.
 */
export function estimateCallFee(
  lockingScriptByteLen: number,
  unlockingScriptByteLen: number,
  numFundingInputs: number,
  feeRate: number = 1,
): number {
  const contractInputSize = 32 + 4 + varIntByteSize(unlockingScriptByteLen) + unlockingScriptByteLen + 4;
  const fundingInputsSize = numFundingInputs * P2PKH_INPUT_SIZE;
  const contractOutputSize = 8 + varIntByteSize(lockingScriptByteLen) + lockingScriptByteLen;
  const changeOutputSize = P2PKH_OUTPUT_SIZE;
  const txSize = TX_OVERHEAD + contractInputSize + fundingInputsSize + contractOutputSize + changeOutputSize;
  return Math.ceil(txSize * feeRate);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function varIntByteSize(n: number): number {
  if (n < 0xfd) return 1;
  if (n <= 0xffff) return 3;
  if (n <= 0xffffffff) return 5;
  return 9;
}
