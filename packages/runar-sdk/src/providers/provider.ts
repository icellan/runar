// ---------------------------------------------------------------------------
// runar-sdk/providers/provider.ts — Provider interface for blockchain access
// ---------------------------------------------------------------------------

import type { Transaction, UTXO } from '../types.js';

export interface Provider {
  /** Fetch a transaction by its txid. */
  getTransaction(txid: string): Promise<Transaction>;

  /** Broadcast a raw transaction hex. Returns the txid on success. */
  broadcast(rawTx: string): Promise<string>;

  /** Get all UTXOs for a given address. */
  getUtxos(address: string): Promise<UTXO[]>;

  /**
   * Get the UTXO holding a contract identified by its script hash.
   * Returns null if no matching UTXO is found on chain.
   */
  getContractUtxo(scriptHash: string): Promise<UTXO | null>;

  /** Return the network this provider is connected to. */
  getNetwork(): 'mainnet' | 'testnet';
}
