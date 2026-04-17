// ---------------------------------------------------------------------------
// runar-sdk/providers/gorillapool.ts — GorillaPool 1sat Ordinals provider
// ---------------------------------------------------------------------------
//
// Implements the standard Provider interface plus ordinal-specific methods
// for querying inscriptions, BSV-20/BSV-21 balances, and token UTXOs.
//
// Endpoints:
//   Mainnet: https://ordinals.gorillapool.io/api/
//   Testnet: https://testnet.ordinals.gorillapool.io/api/
// ---------------------------------------------------------------------------

import type { Transaction } from '@bsv/sdk';
import type { Provider } from './provider.js';
import type { TransactionData, TxInput, TxOutput, UTXO } from '../types.js';

// ---------------------------------------------------------------------------
// GorillaPool API response shapes
// ---------------------------------------------------------------------------

export interface InscriptionInfo {
  txid: string;
  vout: number;
  origin: string;
  contentType: string;
  contentLength: number;
  height: number;
}

export interface InscriptionDetail extends InscriptionInfo {
  data: string; // hex-encoded content
}

interface GpTxVin {
  txid: string;
  vout: number;
  scriptSig: { hex: string };
  sequence: number;
}

interface GpTxVout {
  value: number;
  n: number;
  scriptPubKey: { hex: string };
}

interface GpTxResponse {
  txid: string;
  version: number;
  vin: GpTxVin[];
  vout: GpTxVout[];
  locktime: number;
  hex?: string;
}

interface GpUtxoEntry {
  txid: string;
  vout: number;
  satoshis: number;
  script?: string;
}

// ---------------------------------------------------------------------------
// Provider implementation
// ---------------------------------------------------------------------------

export class GorillaPoolProvider implements Provider {
  private readonly baseUrl: string;
  private readonly network: 'mainnet' | 'testnet';

  constructor(network: 'mainnet' | 'testnet' = 'mainnet') {
    this.network = network;
    this.baseUrl =
      network === 'mainnet'
        ? 'https://ordinals.gorillapool.io/api'
        : 'https://testnet.ordinals.gorillapool.io/api';
  }

  // -----------------------------------------------------------------------
  // Standard Provider methods
  // -----------------------------------------------------------------------

  async getTransaction(txid: string): Promise<TransactionData> {
    const resp = await fetch(`${this.baseUrl}/tx/${txid}`);
    if (!resp.ok) {
      throw new Error(`GorillaPool getTransaction failed (${resp.status}): ${await resp.text()}`);
    }
    const data = (await resp.json()) as GpTxResponse;

    const inputs: TxInput[] = (data.vin ?? []).map((vin) => ({
      txid: vin.txid,
      outputIndex: vin.vout,
      script: vin.scriptSig?.hex ?? '',
      sequence: vin.sequence,
    }));

    const outputs: TxOutput[] = (data.vout ?? []).map((vout) => ({
      satoshis: typeof vout.value === 'number' && vout.value < 1000
        ? Math.round(vout.value * 1e8)
        : vout.value,
      script: vout.scriptPubKey?.hex ?? '',
    }));

    return {
      txid: data.txid,
      version: data.version,
      inputs,
      outputs,
      locktime: data.locktime,
      raw: data.hex,
    };
  }

  async broadcast(tx: Transaction): Promise<string> {
    const rawTx = tx.toHex();
    const resp = await fetch(`${this.baseUrl}/tx`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawTx }),
    });
    if (!resp.ok) {
      throw new Error(`GorillaPool broadcast failed (${resp.status}): ${await resp.text()}`);
    }
    const result = await resp.json();
    return typeof result === 'string' ? result : (result as { txid: string }).txid;
  }

  async getUtxos(address: string): Promise<UTXO[]> {
    const resp = await fetch(`${this.baseUrl}/address/${address}/utxos`);
    if (!resp.ok) {
      if (resp.status === 404) return [];
      throw new Error(`GorillaPool getUtxos failed (${resp.status}): ${await resp.text()}`);
    }
    const entries = (await resp.json()) as GpUtxoEntry[];
    return entries.map((e) => ({
      txid: e.txid,
      outputIndex: e.vout,
      satoshis: e.satoshis,
      script: e.script ?? '',
    }));
  }

  async getContractUtxo(scriptHash: string): Promise<UTXO | null> {
    const resp = await fetch(`${this.baseUrl}/script/${scriptHash}/utxos`);
    if (!resp.ok) {
      if (resp.status === 404) return null;
      throw new Error(`GorillaPool getContractUtxo failed (${resp.status}): ${await resp.text()}`);
    }
    const entries = (await resp.json()) as GpUtxoEntry[];
    if (entries.length === 0) return null;
    const first = entries[0]!;
    return {
      txid: first.txid,
      outputIndex: first.vout,
      satoshis: first.satoshis,
      script: first.script ?? '',
    };
  }

  getNetwork(): 'mainnet' | 'testnet' {
    return this.network;
  }

  async getRawTransaction(txid: string): Promise<string> {
    const resp = await fetch(`${this.baseUrl}/tx/${txid}/hex`);
    if (!resp.ok) {
      throw new Error(`GorillaPool getRawTransaction failed (${resp.status}): ${await resp.text()}`);
    }
    return (await resp.text()).trim();
  }

  async getFeeRate(): Promise<number> {
    return 100; // BSV standard relay fee: 0.1 sat/byte
  }

  // -----------------------------------------------------------------------
  // Ordinal-specific methods
  // -----------------------------------------------------------------------

  /**
   * Get all inscriptions associated with an address.
   */
  async getInscriptionsByAddress(address: string): Promise<InscriptionInfo[]> {
    const resp = await fetch(`${this.baseUrl}/inscriptions/address/${address}`);
    if (!resp.ok) {
      if (resp.status === 404) return [];
      throw new Error(`GorillaPool getInscriptionsByAddress failed (${resp.status}): ${await resp.text()}`);
    }
    return (await resp.json()) as InscriptionInfo[];
  }

  /**
   * Get inscription details (including content) by inscription ID.
   *
   * @param inscriptionId - Format: `<txid>_<vout>`
   */
  async getInscription(inscriptionId: string): Promise<InscriptionDetail> {
    const resp = await fetch(`${this.baseUrl}/inscriptions/${inscriptionId}`);
    if (!resp.ok) {
      throw new Error(`GorillaPool getInscription failed (${resp.status}): ${await resp.text()}`);
    }
    return (await resp.json()) as InscriptionDetail;
  }

  /**
   * Get BSV-20 (v1, tick-based) token balance for an address.
   */
  async getBSV20Balance(address: string, tick: string): Promise<string> {
    const resp = await fetch(`${this.baseUrl}/bsv20/balance/${address}/${encodeURIComponent(tick)}`);
    if (!resp.ok) {
      if (resp.status === 404) return '0';
      throw new Error(`GorillaPool getBSV20Balance failed (${resp.status}): ${await resp.text()}`);
    }
    const result = await resp.json();
    return typeof result === 'string' ? result : String((result as { balance: string }).balance ?? '0');
  }

  /**
   * Get BSV-20 token UTXOs for an address and ticker.
   */
  async getBSV20Utxos(address: string, tick: string): Promise<UTXO[]> {
    const resp = await fetch(`${this.baseUrl}/bsv20/utxos/${address}/${encodeURIComponent(tick)}`);
    if (!resp.ok) {
      if (resp.status === 404) return [];
      throw new Error(`GorillaPool getBSV20Utxos failed (${resp.status}): ${await resp.text()}`);
    }
    const entries = (await resp.json()) as GpUtxoEntry[];
    return entries.map((e) => ({
      txid: e.txid,
      outputIndex: e.vout,
      satoshis: e.satoshis,
      script: e.script ?? '',
    }));
  }

  /**
   * Get BSV-21 (v2, ID-based) token balance for an address.
   *
   * @param id - Token ID in format `<txid>_<vout>`
   */
  async getBSV21Balance(address: string, id: string): Promise<string> {
    const resp = await fetch(`${this.baseUrl}/bsv20/balance/${address}/${encodeURIComponent(id)}`);
    if (!resp.ok) {
      if (resp.status === 404) return '0';
      throw new Error(`GorillaPool getBSV21Balance failed (${resp.status}): ${await resp.text()}`);
    }
    const result = await resp.json();
    return typeof result === 'string' ? result : String((result as { balance: string }).balance ?? '0');
  }

  /**
   * Get BSV-21 token UTXOs for an address and token ID.
   *
   * @param id - Token ID in format `<txid>_<vout>`
   */
  async getBSV21Utxos(address: string, id: string): Promise<UTXO[]> {
    const resp = await fetch(`${this.baseUrl}/bsv20/utxos/${address}/${encodeURIComponent(id)}`);
    if (!resp.ok) {
      if (resp.status === 404) return [];
      throw new Error(`GorillaPool getBSV21Utxos failed (${resp.status}): ${await resp.text()}`);
    }
    const entries = (await resp.json()) as GpUtxoEntry[];
    return entries.map((e) => ({
      txid: e.txid,
      outputIndex: e.vout,
      satoshis: e.satoshis,
      script: e.script ?? '',
    }));
  }
}
