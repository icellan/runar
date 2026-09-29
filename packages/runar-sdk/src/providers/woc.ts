// ---------------------------------------------------------------------------
// runar-sdk/providers/woc.ts — WhatsOnChain provider (HTTP-based BSV API)
// ---------------------------------------------------------------------------

import { Transaction as BsvTransaction, Hash, Utils } from '@bsv/sdk';
import type { Transaction } from '@bsv/sdk';
import type { Provider } from './provider.js';
import type { TransactionData, TxInput, TxOutput, UTXO } from '../types.js';
import { InputLimits } from 'runar-ir-schema';
import { assertScriptHexUnderLimit } from '../errors.js';

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

  /**
   * WoC's GET /address/{address}/unspent listing carries outpoints and values
   * but no locking script. The script is the BIP-143 scriptCode a signer
   * commits to, so an empty one yields signatures no OP_CHECKSIG accepts
   * (F-040). Each distinct txid is therefore fetched via GET /tx/{txid}/hex,
   * its double-SHA256 must equal the txid, and tx_pos must be an output whose
   * value equals the listed value. Any failure throws; no UTXO is ever
   * returned with an empty script.
   */
  async getUtxos(address: string): Promise<UTXO[]> {
    const resp = await fetch(`${this.baseUrl}/address/${address}/unspent`);
    if (!resp.ok) {
      throw new Error(`WoC getUtxos failed (${resp.status}): ${await resp.text()}`);
    }
    const entries = (await resp.json()) as WocUtxoEntry[];

    const txs = new Map<string, BsvTransaction>();
    const utxos: UTXO[] = [];
    for (const e of entries) {
      let tx = txs.get(e.tx_hash);
      if (!tx) {
        const rawHex = await this.getRawTransaction(e.tx_hash);
        const raw = Utils.toArray(rawHex, 'hex');
        const bodyTxid = Utils.toHex(Hash.hash256(raw).reverse());
        if (bodyTxid !== e.tx_hash.toLowerCase()) {
          throw new Error(
            `WoC getUtxos: txid mismatch: /tx/${e.tx_hash}/hex body hashes to ${bodyTxid}`,
          );
        }
        tx = BsvTransaction.fromBinary(raw);
        txs.set(e.tx_hash, tx);
      }
      const out = tx.outputs[e.tx_pos];
      if (!out) {
        throw new Error(
          `WoC getUtxos: no output ${e.tx_pos} in tx ${e.tx_hash} (${tx.outputs.length} outputs)`,
        );
      }
      if (out.satoshis !== e.value) {
        throw new Error(
          `WoC getUtxos: value mismatch for ${e.tx_hash}:${e.tx_pos}: listing says ${e.value}, tx says ${out.satoshis}`,
        );
      }
      const script = out.lockingScript.toHex();
      if (script === '') {
        throw new Error(`WoC getUtxos: empty locking script for ${e.tx_hash}:${e.tx_pos}`);
      }
      assertScriptHexUnderLimit(
        script, InputLimits.MAX_SCRIPT_BYTES,
        `WhatsOnChainProvider.getUtxos(${address})`,
      );
      utxos.push({ txid: e.tx_hash, outputIndex: e.tx_pos, satoshis: e.value, script });
    }
    return utxos;
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
    const utxo: UTXO = {
      txid: first.tx_hash,
      outputIndex: first.tx_pos,
      satoshis: first.value,
      script: '',
    };
    if (utxo.script) {
      assertScriptHexUnderLimit(
        utxo.script, InputLimits.MAX_SCRIPT_BYTES,
        `WhatsOnChainProvider.getContractUtxo(${scriptHash})`,
      );
    }
    return utxo;
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
