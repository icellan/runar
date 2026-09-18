// ---------------------------------------------------------------------------
// runar-sdk/providers/wallet-provider.ts — BRC-100 wallet provider
// ---------------------------------------------------------------------------
//
// Provider implementation that uses a BRC-100 wallet for UTXO management,
// GorillaPool ARC for broadcast (EF format), and an optional overlay
// service for tx indexing.
// ---------------------------------------------------------------------------

import type { Provider } from './provider.js';
import { txToTransactionData, warnNonFatal } from './provider.js';
import type { Signer } from '../signers/signer.js';
import type { TransactionData, UTXO } from '../types.js';
import { buildP2PKHScript } from '../script-utils.js';
import {
  Transaction,
  type WalletClient,
  type Broadcaster,
} from '@bsv/sdk';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * The default ARC broadcaster. This is a MAINNET endpoint — see R-179 for why
 * that matters at construction time.
 */
const MAINNET_ARC_URL = 'https://arc.gorillapool.io';

export interface WalletProviderOptions {
  /** BRC-100 WalletClient instance. */
  wallet: WalletClient;
  /** Signer derived from the same wallet (e.g. WalletSigner). */
  signer: Signer;
  /** Wallet basket name for UTXO management (e.g. 'my-app'). */
  basket: string;
  /** Tag for funding UTXOs within the basket (default: 'funding'). */
  fundingTag?: string;
  /**
   * ARC broadcast endpoint. Defaults to the MAINNET endpoint
   * ('https://arc.gorillapool.io') and is therefore REQUIRED when `network` is
   * anything other than 'mainnet' — see R-179.
   */
  arcUrl?: string;
  /** Overlay service URL for tx submission and raw tx lookups (optional). */
  overlayUrl?: string;
  /** Overlay topic names for tx submission (optional, e.g. ['tm_myapp']). */
  overlayTopics?: string[];
  /** Network (default: 'mainnet'). */
  network?: 'mainnet' | 'testnet';
  /** Fee rate in sats/KB (default: 100, i.e. 0.1 sat/byte). */
  feeRate?: number;
  /**
   * Injected `@bsv/sdk` Broadcaster (issue #107). When provided, `broadcast()`
   * delegates to this instance instead of the hardcoded ARC URL, so the SDK
   * and a downstream layer (e.g. wallet-toolbox) share ONE broadcaster/config
   * — keeping parent and child txs at the same ARC deployment (avoids
   * `SEEN_IN_ORPHAN_MEMPOOL`). Additive and non-breaking; omit for the default
   * ARC path.
   */
  broadcaster?: Broadcaster;
}

// ---------------------------------------------------------------------------
// WalletProvider
// ---------------------------------------------------------------------------

export class WalletProvider implements Provider {
  protected readonly wallet: WalletClient;
  protected readonly signer: Signer;
  protected readonly basket: string;
  protected readonly fundingTag: string;
  protected readonly arcUrl: string;
  protected readonly overlayUrl: string | undefined;
  protected readonly overlayTopics: string[] | undefined;
  protected readonly _network: 'mainnet' | 'testnet';
  protected readonly _feeRate: number;
  protected readonly broadcaster: Broadcaster | undefined;
  protected readonly txCache = new Map<string, string>();

  constructor(options: WalletProviderOptions) {
    this.wallet = options.wallet;
    this.signer = options.signer;
    this.basket = options.basket;
    this.fundingTag = options.fundingTag ?? 'funding';
    this._network = options.network ?? 'mainnet';
    // R-179: arcUrl and network used to be defaulted independently, so a
    // provider configured for testnet reported getNetwork() === 'testnet' and
    // broadcast every transaction to the MAINNET ARC, with nothing to say so.
    // There is no canonical testnet ARC endpoint in this repo to default to,
    // so a testnet provider has to name its own rather than inherit one that
    // points at real money. The sibling GorillaPoolProvider derives its base
    // URL from the network for the same reason.
    if (options.arcUrl) {
      this.arcUrl = options.arcUrl;
    } else if (this._network === 'mainnet') {
      this.arcUrl = MAINNET_ARC_URL;
    } else {
      throw new Error(
        `WalletProvider: no default ARC endpoint for network '${this._network}' — ` +
          `${MAINNET_ARC_URL} is a MAINNET broadcaster. Pass arcUrl explicitly.`,
      );
    }
    this.overlayUrl = options.overlayUrl;
    this.overlayTopics = options.overlayTopics;
    this._feeRate = options.feeRate ?? 100;
    this.broadcaster = options.broadcaster;
  }

  // -------------------------------------------------------------------------
  // Typed accessors (used by RunarContract.deployWithWallet; also lets
  // consumers reach the wallet without reaching into internals)
  // -------------------------------------------------------------------------

  /** The BRC-100 wallet client this provider wraps. */
  get walletClient(): WalletClient {
    return this.wallet;
  }

  /** The wallet basket used for UTXO management. */
  get basketName(): string {
    return this.basket;
  }

  // -------------------------------------------------------------------------
  // Transaction cache
  // -------------------------------------------------------------------------

  /** Cache a raw tx hex by its txid (for EF parent lookups). */
  cacheTx(txid: string, rawHex: string): void {
    this.txCache.set(txid, rawHex);
  }

  /**
   * Fetch raw tx hex: local cache → overlay → throw.
   *
   * Protected so subclasses can supply parents from another source (their
   * own index, a node RPC, …); the EF assembly in `broadcastTx` dispatches
   * through the override.
   */
  protected async fetchRawTx(txid: string): Promise<string> {
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

  /**
   * Broadcast a transaction via ARC in EF format.
   *
   * Protected so subclasses can reroute broadcast (e.g. through an overlay
   * that gates admission) while `broadcast()` and `ensureFunding()` keep
   * dispatching through the override.
   */
  protected async broadcastTx(tx: Transaction): Promise<string> {
    // Attach source transactions for EF format
    for (const input of tx.inputs) {
      if (input.sourceTransaction) continue;
      const parentTxid = input.sourceTXID;
      if (!parentTxid) continue;
      const parentHex = await this.fetchRawTx(parentTxid);
      input.sourceTransaction = Transaction.fromHex(parentHex);
    }

    // Issue #107: when a broadcaster is injected, delegate to it so the SDK and
    // the calling layer share ONE broadcaster instance/config (keeps parent +
    // child at the same ARC deployment → avoids SEEN_IN_ORPHAN_MEMPOOL). The
    // structured BroadcastFailure is flattened into a thrown Error to preserve
    // the existing `broadcast()` contract.
    if (this.broadcaster) {
      const result = await this.broadcaster.broadcast(tx);
      if (result.status === 'error') {
        throw new Error(
          `WalletProvider: injected broadcaster failed (${result.code}): ${result.description}`,
        );
      }
      const txid = result.txid;
      this.txCache.set(txid, tx.toHex());
      if (this.overlayUrl && this.overlayTopics && this.overlayTopics.length > 0) {
        this.submitToOverlay(tx).catch((e) => warnNonFatal('overlay submission', e));
      }
      return txid;
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
      this.submitToOverlay(tx).catch((e) => warnNonFatal('overlay submission', e));
    }

    return txid;
  }

  /** Submit a transaction to the overlay for indexing (non-fatal).
   * Protected so subclasses can adapt the submit request to their overlay. */
  protected async submitToOverlay(tx: Transaction): Promise<void> {
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
    // R-151: this used to fall back to
    //   { txid, version: 1, inputs: [], outputs: [], locktime: 0 }
    // on a cache miss OR a parse failure, so a caller could not tell "this
    // transaction has no outputs" from "I could not find this transaction".
    // The same shape was already fixed once in this SDK — txToTransactionData
    // in providers/provider.ts is that remediation — and never applied here.
    const cached = this.txCache.get(txid);
    if (cached === undefined) {
      throw new Error(
        `WalletProvider.getTransaction: transaction ${txid} is not in the provider's ` +
          `cache. A wallet provider only knows transactions it has broadcast or been ` +
          `given via cacheTx().`,
      );
    }

    let tx: Transaction;
    try {
      tx = Transaction.fromHex(cached);
    } catch (e) {
      throw new Error(
        `WalletProvider.getTransaction: cached hex for ${txid} did not parse as a ` +
          `transaction: ${e instanceof Error ? e.message : String(e)}`,
      );
    }

    return txToTransactionData(txid, tx);
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
        await this.broadcastTx(Transaction.fromHex(rawHex)).catch((e) =>
          warnNonFatal('funding-tx broadcast', e),
        );
      } catch (e) {
        warnNonFatal('funding-tx parse', e);
      }
    }
  }
}
