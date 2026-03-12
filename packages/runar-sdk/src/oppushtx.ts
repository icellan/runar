// ---------------------------------------------------------------------------
// runar-sdk/oppushtx.ts — OP_PUSH_TX helper for checkPreimage contracts
// ---------------------------------------------------------------------------
//
// Computes the BIP-143 sighash preimage and OP_PUSH_TX signature for contracts
// that use checkPreimage() (both stateful and stateless).
//
// The OP_PUSH_TX technique uses private key k=1 (public key = generator point G).
// The on-chain script derives the signature from the preimage, so both must be
// provided in the unlocking script.
// ---------------------------------------------------------------------------

import { PrivateKey, TransactionSignature, Hash, Transaction, Script, BigNumber } from '@bsv/sdk';

/** SIGHASH_ALL | SIGHASH_FORKID — the default BSV sighash type. */
const SIGHASH_ALL_FORKID = 0x41;

/** secp256k1 curve order N. */
const CURVE_ORDER = new BigNumber('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);

/** OP_PUSH_TX private key (k=1). */
const opPushTxPrivKey = PrivateKey.fromHex('0000000000000000000000000000000000000000000000000000000000000001');

/**
 * Compute the OP_PUSH_TX DER signature and BIP-143 preimage for a contract input.
 *
 * @param txOrHex     - The Transaction object or raw hex string
 * @param inputIndex  - The contract input index (usually 0)
 * @param subscript   - The locking script of the UTXO being spent (hex)
 * @param satoshis    - The satoshi value of the UTXO being spent
 * @param codeSeparatorIndex - Byte offset of OP_CODESEPARATOR in the locking script (optional).
 *                             When present, the scriptCode in BIP-143 is the portion AFTER
 *                             the OP_CODESEPARATOR (excluding the separator byte itself).
 * @returns Object with `sigHex` (DER + sighash byte) and `preimageHex` (raw preimage)
 */
export function computeOpPushTx(
  txOrHex: Transaction | string,
  inputIndex: number,
  subscript: string,
  satoshis: number,
  codeSeparatorIndex?: number,
): { sigHex: string; preimageHex: string } {
  const tx = typeof txOrHex === 'string' ? Transaction.fromHex(txOrHex) : txOrHex;
  const input = tx.inputs[inputIndex]!;

  const otherInputs = tx.inputs
    .filter((_inp, i) => i !== inputIndex)
    .map((inp) => ({
      sourceTXID: inp.sourceTXID!,
      sourceOutputIndex: inp.sourceOutputIndex,
      sequence: inp.sequence!,
    }));

  const outputs = tx.outputs.map((out) => ({
    satoshis: out.satoshis!,
    lockingScript: out.lockingScript,
  }));

  // If OP_CODESEPARATOR is present, use only the script after it as scriptCode.
  // The separator byte itself (0xab) is excluded from the scriptCode.
  let scriptCode = subscript;
  if (codeSeparatorIndex !== undefined) {
    // Each byte is 2 hex chars. Skip past the separator byte (+1 byte = +2 hex chars).
    scriptCode = subscript.slice((codeSeparatorIndex + 1) * 2);
  }

  // Compute BIP-143 preimage
  const preimage = TransactionSignature.format({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: satoshis,
    transactionVersion: tx.version,
    otherInputs: otherInputs as Parameters<typeof TransactionSignature.format>[0]['otherInputs'],
    outputs: outputs as unknown as Parameters<typeof TransactionSignature.format>[0]['outputs'],
    inputIndex,
    subscript: Script.fromHex(scriptCode) as unknown as Parameters<typeof TransactionSignature.format>[0]['subscript'],
    inputSequence: input.sequence!,
    lockTime: tx.lockTime,
    scope: SIGHASH_ALL_FORKID,
  });

  // Double-SHA256 for BIP-143 sighash
  const sighash = Hash.sha256(preimage);

  // Sign with k=1 private key
  const signature = opPushTxPrivKey.sign(sighash);

  // Enforce low-S
  const halfN = CURVE_ORDER.div(new BigNumber(2));
  if (signature.s.gt(halfN)) {
    signature.s = CURVE_ORDER.sub(signature.s);
  }

  const derHex = signature.toDER('hex') as string;
  const sigHex = derHex + SIGHASH_ALL_FORKID.toString(16).padStart(2, '0');

  // Convert preimage to hex
  const preimageHex = Array.from(preimage).map((b) => b.toString(16).padStart(2, '0')).join('');

  return { sigHex, preimageHex };
}
