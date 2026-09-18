// ---------------------------------------------------------------------------
// runar-sdk/providers/provider.ts — Provider interface for blockchain access
// ---------------------------------------------------------------------------

import type { Transaction } from '@bsv/sdk';
import type { TransactionData, UTXO } from '../types.js';

export interface Provider {
  /** Fetch a transaction by its txid (as a plain data shape). */
  getTransaction(txid: string): Promise<TransactionData>;

  /**
   * Broadcast a transaction. Returns the txid on success.
   * Accepts a @bsv/sdk Transaction object — implementations call
   * `tx.toHex()` (or `tx.toHexEF()` for ARC) as needed.
   */
  broadcast(tx: Transaction): Promise<string>;

  /** Get all UTXOs for a given address. */
  getUtxos(address: string): Promise<UTXO[]>;

  /**
   * Get the UTXO holding a contract identified by its script hash.
   * Returns null if no matching UTXO is found on chain.
   */
  getContractUtxo(scriptHash: string): Promise<UTXO | null>;

  /** Return the network this provider is connected to. */
  getNetwork(): 'mainnet' | 'testnet';

  /**
   * Get the current fee rate in satoshis per KB (1000 bytes).
   * Defaults to 100 sat/KB for BSV (0.1 sat/byte standard relay fee).
   */
  getFeeRate(): Promise<number>;

  /** Fetch the raw transaction hex by its txid. */
  getRawTransaction(txid: string): Promise<string>;
}


/**
 * Report a failure that is deliberately non-fatal (R-273).
 *
 * Four paths in this SDK — two overlay submissions, the funding broadcast and
 * the BEEF parse after deploy — are fire-and-forget by design: the caller's
 * transaction is already broadcast, and an indexing or caching failure must not
 * turn a successful spend into a thrown error. They were written as
 * `.catch(() => {})` and `catch { /* non-fatal *\/ }`, which is the intent
 * correctly expressed and the evidence thrown away: an overlay that is down
 * looks exactly like an overlay that is fine.
 *
 * `console.warn` is what the rest of this SDK already uses for advisory
 * failures (contract.ts and providers/mock.ts), so these now match.
 */
export function warnNonFatal(context: string, err: unknown): void {
  console.warn(`runar-sdk: ${context} (non-fatal):`, err);
}

/**
 * Audit finding C4: project a locally-held @bsv/sdk `Transaction` into the
 * plain `TransactionData` shape `getTransaction()` returns.
 *
 * Two call sites need exactly this, and they must not drift apart:
 *   - `MockProvider.broadcast()` registers the tx it just accepted, so
 *     `getTransaction()` can resolve it instead of throwing "not found".
 *   - `RunarContract.deploy()` / `finalizeCall()` fall back to it when
 *     `provider.getTransaction()` fails (a real node can 404 a transaction it
 *     has accepted but not yet indexed).
 *
 * Both previously improvised their own shape, and the contract.ts one
 * improvised an EMPTY one — `inputs: []`, `outputs: []` — indistinguishable
 * from a confirmed transaction with no outputs, which is what made every
 * post-broadcast `result.tx.outputs` assertion vacuous. Lives here because
 * `providers/provider.ts` is a leaf both sides already import.
 *
 * `txid` is passed in rather than read off `tx`: the mock provider assigns
 * synthetic txids, and the real deploy/call path uses the txid the provider
 * returned from `broadcast()`.
 */
export function txToTransactionData(txid: string, tx: Transaction): TransactionData {
  return {
    txid,
    version: tx.version,
    inputs: tx.inputs.map((input) => ({
      txid: input.sourceTXID ?? input.sourceTransaction?.id('hex') ?? '',
      outputIndex: input.sourceOutputIndex,
      script: input.unlockingScript?.toHex() ?? '',
      sequence: input.sequence ?? 0xffffffff,
    })),
    outputs: tx.outputs.map((out) => ({
      satoshis: out.satoshis ?? 0,
      script: out.lockingScript.toHex(),
    })),
    locktime: tx.lockTime,
    raw: tx.toHex(),
  };
}
