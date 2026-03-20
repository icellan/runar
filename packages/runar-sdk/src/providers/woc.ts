// ---------------------------------------------------------------------------
// runar-sdk/providers/woc.ts — WhatsOnChain provider (HTTP-based BSV API)
// ---------------------------------------------------------------------------

import type { Transaction } from '@bsv/sdk';
import type { Provider } from './provider.js';
import type { TransactionData, TxInput, TxOutput, UTXO } from '../types.js';

// ---------------------------------------------------------------------------
// WoC API response shapes (partial)
// ---------------------------------------------------------------------------

interface WocTxVin {
  txid: string;
  vout: number;
  scriptSig: { hex: string };
  sequence: number;
}

interface WocTxVout {
  value: number;
  n: number;
  scriptPubKey: { hex: string };
}

interface WocTxResponse {
  txid: string;
  version: number;
  vin: WocTxVin[];
  vout: WocTxVout[];
  locktime: number;
  hex?: string;
}

interface WocUtxoEntry {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
}

interface WocScriptUtxoEntry {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
}

// ---------------------------------------------------------------------------
// Provider implementation
// ---------------------------------------------------------------------------

export class WhatsOnChainProvider implements Provider {
  private readonly baseUrl: string;
  private readonly network: 'mainnet' | 'testnet';

  constructor(network: 'mainnet' | 'testnet' = 'mainnet') {
    this.network = network;
    this.baseUrl =
      network === 'mainnet'
        ? 'https://api.whatsonchain.com/v1/bsv/main'
        : 'https://api.whatsonchain.com/v1/bsv/test';
  }

  async getTransaction(txid: string): Promise<TransactionData> {
    const resp = await fetch(`${this.baseUrl}/tx/hash/${txid}`);
    if (!resp.ok) {
      throw new Error(`WoC getTransaction failed (${resp.status}): ${await resp.text()}`);
    }
    const data = (await resp.json()) as WocTxResponse;

    const inputs: TxInput[] = data.vin.map((vin) => ({
      txid: vin.txid,
      outputIndex: vin.vout,
      script: vin.scriptSig.hex,
      sequence: vin.sequence,
    }));

    const outputs: TxOutput[] = data.vout.map((vout) => ({
      satoshis: Math.round(vout.value * 1e8),
      script: vout.scriptPubKey.hex,
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
    const resp = await fetch(`${this.baseUrl}/tx/raw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ txhex: rawTx }),
    });
    if (!resp.ok) {
      throw new Error(`WoC broadcast failed (${resp.status}): ${await resp.text()}`);
    }
    // WoC returns the txid as a plain string (JSON-encoded)
    const txid = (await resp.json()) as string;
    return txid;
  }

  async getUtxos(address: string): Promise<UTXO[]> {
    const resp = await fetch(`${this.baseUrl}/address/${address}/unspent`);
    if (!resp.ok) {
      throw new Error(`WoC getUtxos failed (${resp.status}): ${await resp.text()}`);
    }
    const entries = (await resp.json()) as WocUtxoEntry[];

    // WoC doesn't return the locking script in the UTXO list, so we set it
    // to empty and callers can look it up if needed.
    return entries.map((e) => ({
      txid: e.tx_hash,
      outputIndex: e.tx_pos,
      satoshis: e.value,
      script: '',
    }));
  }

  async getContractUtxo(scriptHash: string): Promise<UTXO | null> {
    const resp = await fetch(`${this.baseUrl}/script/${scriptHash}/unspent`);
    if (!resp.ok) {
      // 404 simply means no UTXO found
      if (resp.status === 404) return null;
      throw new Error(`WoC getContractUtxo failed (${resp.status}): ${await resp.text()}`);
    }
    const entries = (await resp.json()) as WocScriptUtxoEntry[];
    if (entries.length === 0) return null;

    // Return the first (latest) unspent entry
    const first = entries[0]!;
    return {
      txid: first.tx_hash,
      outputIndex: first.tx_pos,
      satoshis: first.value,
      script: '',
    };
  }

  getNetwork(): 'mainnet' | 'testnet' {
    return this.network;
  }

  async getRawTransaction(txid: string): Promise<string> {
    const resp = await fetch(`${this.baseUrl}/tx/${txid}/hex`);
    if (!resp.ok) {
      throw new Error(`WoC getRawTransaction failed (${resp.status}): ${await resp.text()}`);
    }
    return (await resp.text()).trim();
  }

  async getFeeRate(): Promise<number> {
    // BSV standard relay fee is 0.1 sat/byte (100 sat/KB).
    return 100;
  }
}
