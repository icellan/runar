// ---------------------------------------------------------------------------
// runar-sdk/providers/mock.ts — Mock provider for testing
// ---------------------------------------------------------------------------

import type { Provider } from './provider.js';
import type { Transaction, UTXO } from '../types.js';

/**
 * In-memory mock provider for unit tests and local development.
 *
 * Allows injecting transactions and UTXOs, and records broadcasts for
 * assertion in tests.
 */
export class MockProvider implements Provider {
  private readonly transactions: Map<string, Transaction> = new Map();
  private readonly utxos: Map<string, UTXO[]> = new Map();
  private readonly contractUtxos: Map<string, UTXO> = new Map();
  private readonly broadcastedTxs: string[] = [];
  private readonly network: 'mainnet' | 'testnet';
  private broadcastCount = 0;

  constructor(network: 'mainnet' | 'testnet' = 'testnet') {
    this.network = network;
  }

  // -------------------------------------------------------------------------
  // Test data injection
  // -------------------------------------------------------------------------

  addTransaction(tx: Transaction): void {
    this.transactions.set(tx.txid, tx);
  }

  addUtxo(address: string, utxo: UTXO): void {
    const existing = this.utxos.get(address) ?? [];
    existing.push(utxo);
    this.utxos.set(address, existing);
  }

  addContractUtxo(scriptHash: string, utxo: UTXO): void {
    this.contractUtxos.set(scriptHash, utxo);
  }

  /** Get all raw tx hexes that were broadcast through this provider. */
  getBroadcastedTxs(): readonly string[] {
    return this.broadcastedTxs;
  }

  // -------------------------------------------------------------------------
  // Provider implementation
  // -------------------------------------------------------------------------

  async getTransaction(txid: string): Promise<Transaction> {
    const tx = this.transactions.get(txid);
    if (!tx) {
      throw new Error(`MockProvider: transaction ${txid} not found`);
    }
    return tx;
  }

  async broadcast(rawTx: string): Promise<string> {
    this.broadcastedTxs.push(rawTx);
    this.broadcastCount++;
    // Generate a deterministic fake txid from the broadcast count
    const fakeTxid = sha256Hex(`mock-broadcast-${this.broadcastCount}-${rawTx.slice(0, 16)}`);
    return fakeTxid;
  }

  async getUtxos(address: string): Promise<UTXO[]> {
    return this.utxos.get(address) ?? [];
  }

  async getContractUtxo(scriptHash: string): Promise<UTXO | null> {
    return this.contractUtxos.get(scriptHash) ?? null;
  }

  getNetwork(): 'mainnet' | 'testnet' {
    return this.network;
  }
}

// ---------------------------------------------------------------------------
// Minimal hex sha256 for deterministic fake txids (no external deps)
// ---------------------------------------------------------------------------

function sha256Hex(input: string): string {
  // Simple deterministic hash for mock purposes — not cryptographically
  // secure. Produces a 64-char hex string that looks like a txid.
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h0 = Math.imul(h0 ^ c, 0x01000193) >>> 0;
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c, 0x01000193) >>> 0;
    h3 = Math.imul(h3 ^ c, 0x01000193) >>> 0;
  }
  return [h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3]
    .map((n) => (n >>> 0).toString(16).padStart(8, '0'))
    .join('');
}
