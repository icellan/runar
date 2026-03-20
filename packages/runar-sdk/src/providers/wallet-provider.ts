// ---------------------------------------------------------------------------
// runar-sdk/providers/wallet-provider.ts — BRC-100 wallet provider
// ---------------------------------------------------------------------------
//
// Provider implementation that uses a BRC-100 wallet for UTXO management,
// GorillaPool ARC for broadcast (EF format), and an optional overlay
// service for tx indexing.
// ---------------------------------------------------------------------------

import type { Provider } from './provider.js';
import type { Signer } from '../signers/signer.js';
import type { TransactionData, TxInput, TxOutput, UTXO } from '../types.js';
import { buildP2PKHScript } from '../script-utils.js';
import {
  Transaction,
  type WalletClient,
} from '@bsv/sdk';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface WalletProviderOptions {
  /** BRC-100 WalletClient instance. */
  wallet: WalletClient;
  /** Signer derived from the same wallet (e.g. WalletSigner). */
  signer: Signer;
  /** Wallet basket name for UTXO management (e.g. 'my-app'). */
  basket: string;
  /** Tag for funding UTXOs within the basket (default: 'funding'). */
  fundingTag?: string;
  /** ARC broadcast endpoint (default: 'https://arc.gorillapool.io'). */
  arcUrl?: string;
  /** Overlay service URL for tx submission and raw tx lookups (optional). */
  overlayUrl?: string;
  /** Overlay topic names for tx submission (optional, e.g. ['tm_myapp']). */
  overlayTopics?: string[];
  /** Network (default: 'mainnet'). */
  network?: 'mainnet' | 'testnet';
  /** Fee rate in sats/KB (default: 100, i.e. 0.1 sat/byte). */
  feeRate?: number;
}

// ---------------------------------------------------------------------------
// WalletProvider
// ---------------------------------------------------------------------------

export class WalletProvider implements Provider {
  private readonly wallet: WalletClient;
  private readonly signer: Signer;
  private readonly basket: string;
  private readonly fundingTag: string;
  private readonly arcUrl: string;
  private readonly overlayUrl: string | undefined;
  private readonly overlayTopics: string[] | undefined;
  private readonly _network: 'mainnet' | 'testnet';
  private readonly _feeRate: number;
  private readonly txCache = new Map<string, string>();

  constructor(options: WalletProviderOptions) {
    this.wallet = options.wallet;
    this.signer = options.signer;
    this.basket = options.basket;
    this.fundingTag = options.fundingTag ?? 'funding';
    this.arcUrl = options.arcUrl ?? 'https://arc.gorillapool.io';
    this.overlayUrl = options.overlayUrl;
    this.overlayTopics = options.overlayTopics;
    this._network = options.network ?? 'mainnet';
    this._feeRate = options.feeRate ?? 100;
  }

  // -------------------------------------------------------------------------
  // Transaction cache
  // -------------------------------------------------------------------------

  /** Cache a raw tx hex by its txid (for EF parent lookups). */
  cacheTx(txid: string, rawHex: string): void {
    this.txCache.set(txid, rawHex);
  }

  /** Fetch raw tx hex: local cache → overlay → throw. */
  private async fetchRawTx(txid: string): Promise<string> {
    const cached = this.txCache.get(txid);
    if (cached) return cached;

    if (this.overlayUrl) {
      const resp = await fetch(`${this.overlayUrl}/api/tx/${txid}/hex`);
      if (resp.ok) {
        const hex = (await resp.text()).trim();
        this.txCache.set(txid, hex);
        return hex;
      }
    }

    throw new Error(
      `WalletProvider: could not fetch parent tx ${txid} (not in cache${this.overlayUrl ? ', overlay returned error' : ''})`,
    );
  }

  // -------------------------------------------------------------------------
  // Broadcast
  // -------------------------------------------------------------------------

  /** Broadcast a transaction via ARC in EF format. */
  private async broadcastTx(tx: Transaction): Promise<string> {
    // Attach source transactions for EF format
    for (const input of tx.inputs) {
      if (input.sourceTransaction) continue;
      const parentTxid = input.sourceTXID;
      if (!parentTxid) continue;
      const parentHex = await this.fetchRawTx(parentTxid);
      input.sourceTransaction = Transaction.fromHex(parentHex);
    }

    const efBytes = tx.toEFUint8Array();

    const resp = await fetch(`${this.arcUrl}/v1/tx`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: efBytes.buffer as ArrayBuffer,
    });
    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`WalletProvider: ARC broadcast failed (${resp.status}): ${body}`);
    }
    const result = (await resp.json()) as { txid: string };
    const txid = result.txid;

    // Cache for future EF lookups
    this.txCache.set(txid, tx.toHex());

    // Fire-and-forget: submit to overlay for indexing
    if (this.overlayUrl && this.overlayTopics && this.overlayTopics.length > 0) {
      this.submitToOverlay(tx).catch(() => {});
    }

    return txid;
  }

  /** Submit a transaction to the overlay for indexing (non-fatal). */
  private async submitToOverlay(tx: Transaction): Promise<void> {
    if (!this.overlayUrl || !this.overlayTopics) return;

    const beef = tx.toBEEF();
    await fetch(`${this.overlayUrl}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Topics': JSON.stringify(this.overlayTopics),
      },
      body: JSON.stringify({
        beef: Array.from(beef),
        topics: this.overlayTopics,
      }),
    });
  }

  // -------------------------------------------------------------------------
  // Provider interface
  // -------------------------------------------------------------------------

  /**
   * Get UTXOs from the wallet's basket.
   * Returns only spendable P2PKH UTXOs locked to the signer's derived key.
   */
  async getUtxos(_address: string): Promise<UTXO[]> {
    const result = await this.wallet.listOutputs({
      basket: this.basket,
      tags: [this.fundingTag],
      tagQueryMode: 'all',
      include: 'locking scripts',
      limit: 100,
      seekPermission: false,
    });

    const derivedPubKey = await this.signer.getPublicKey();
    const expectedScript = buildP2PKHScript(derivedPubKey);

    const utxos: UTXO[] = [];
    for (const out of result.outputs) {
      if (!(out as any).spendable || !out.lockingScript) continue;
      if (out.lockingScript !== expectedScript) continue;

      const [txid, voutStr] = out.outpoint.split('.');
      utxos.push({
        txid: txid!,
        outputIndex: Number(voutStr),
        satoshis: out.satoshis,
        script: out.lockingScript,
      });
    }

    return utxos;
  }

  async getTransaction(txid: string): Promise<TransactionData> {
    const cached = this.txCache.get(txid);
    if (cached) {
      try {
        const tx = Transaction.fromHex(cached);
        const inputs: TxInput[] = tx.inputs.map((inp) => ({
          txid: inp.sourceTXID || '',
          outputIndex: inp.sourceOutputIndex,
          script: inp.unlockingScript?.toHex() || '',
          sequence: inp.sequence ?? 0xffffffff,
        }));
        const outputs: TxOutput[] = tx.outputs.map((out) => ({
          satoshis: out.satoshis ?? 0,
          script: out.lockingScript?.toHex() || '',
        }));
        return { txid, version: tx.version, inputs, outputs, locktime: tx.lockTime, raw: cached };
      } catch { /* fall through */ }
    }

    // Minimal fallback
    return { txid, version: 1, inputs: [], outputs: [], locktime: 0 };
  }

  async broadcast(tx: any): Promise<string> {
    return this.broadcastTx(tx);
  }

  async getContractUtxo(_scriptHash: string): Promise<UTXO | null> {
    // Contract UTXOs typically come from overlay services or app logic,
    // not from the wallet provider.
    return null;
  }

  getNetwork(): 'mainnet' | 'testnet' {
    return this._network;
  }

  async getRawTransaction(txid: string): Promise<string> {
    return this.fetchRawTx(txid);
  }

  async getFeeRate(): Promise<number> {
    return this._feeRate;
  }

  // -------------------------------------------------------------------------
  // Funding
  // -------------------------------------------------------------------------

  /**
   * Ensure there are enough P2PKH funding UTXOs in the wallet basket.
   * Creates a new funding UTXO via the wallet if the balance is insufficient.
   *
   * @param minSatoshis - Minimum total satoshis required.
   */
  async ensureFunding(minSatoshis: number): Promise<void> {
    const address = await this.signer.getAddress();
    const utxos = await this.getUtxos(address);

    const totalAvailable = utxos.reduce((sum, u) => sum + u.satoshis, 0);
    if (totalAvailable >= minSatoshis) return;

    const derivedPubKey = await this.signer.getPublicKey();
    const lockingScript = buildP2PKHScript(derivedPubKey);
    const fundAmount = minSatoshis - totalAvailable;

    const result = await this.wallet.createAction({
      description: 'Runar contract funding',
      outputs: [{
        lockingScript,
        satoshis: fundAmount,
        outputDescription: 'Funding UTXO',
        basket: this.basket,
        tags: [this.fundingTag],
      }],
    });

    // Cache the funding tx so child txs can build EF
    if (result.tx) {
      try {
        const tx = Transaction.fromAtomicBEEF(result.tx);
        const rawHex = tx.toHex();
        const txid = result.txid || '';
        if (txid) this.txCache.set(txid, rawHex);

        // Broadcast to ARC (may already be known — non-fatal)
        await this.broadcastTx(Transaction.fromHex(rawHex)).catch(() => {});
      } catch { /* funding tx parse failure is non-fatal */ }
    }
  }
}
