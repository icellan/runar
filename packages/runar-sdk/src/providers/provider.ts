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
