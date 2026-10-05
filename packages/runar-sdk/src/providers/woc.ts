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

  /**
   * N-041: GET /tx/hash/{txid} has no `hex` field and reports values as float
   * BTC, so `raw` was always empty. The serialized tx is fetched via
   * GET /tx/{txid}/hex instead, its double-SHA256 must equal the txid, and
   * inputs/outputs (with integer satoshis) are parsed from those bytes.
   */
  async getTransaction(txid: string): Promise<TransactionData> {
    const { tx, rawHex } = await this.fetchVerifiedTx(txid, 'getTransaction');

    const inputs: TxInput[] = tx.inputs.map((input) => ({
      txid: input.sourceTXID ?? '',
      outputIndex: input.sourceOutputIndex,
      script: input.unlockingScript?.toHex() ?? '',
      sequence: input.sequence ?? 0xffffffff,
    }));

    const outputs: TxOutput[] = tx.outputs.map((output) => ({
      satoshis: output.satoshis ?? 0,
      script: output.lockingScript.toHex(),
    }));

    return {
      txid: txid.toLowerCase(),
      version: tx.version,
      inputs,
      outputs,
      locktime: tx.lockTime,
      raw: rawHex,
    };
  }

  /**
   * Fetch GET /tx/{txid}/hex and require its double-SHA256 (reversed) to
   * equal `txid` before parsing it (F-040 / N-041).
   */
  private async fetchVerifiedTx(
    txid: string,
    context: string,
  ): Promise<{ tx: BsvTransaction; rawHex: string }> {
    const rawHex = await this.getRawTransaction(txid);
    const raw = Utils.toArray(rawHex, 'hex');
    const bodyTxid = Utils.toHex(Hash.hash256(raw).reverse());
    if (bodyTxid !== txid.toLowerCase()) {
      throw new Error(`WoC ${context}: txid mismatch: /tx/${txid}/hex body hashes to ${bodyTxid}`);
    }
    return { tx: BsvTransaction.fromBinary(raw), rawHex: Utils.toHex(raw) };
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
   *
   * Note: WoC caps this legacy listing at about 1000 entries, so an address
   * holding more UTXOs is returned truncated.
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
        tx = (await this.fetchVerifiedTx(e.tx_hash, 'getUtxos')).tx;
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

  /**
   * WoC's GET /script/{scriptHash}/unspent listing (a legacy array, or a
   * `{script, result}` object on the /unspent/all family) carries outpoints
   * and values but no locking script (N-041). The first entry's tx is fetched
   * via GET /tx/{txid}/hex and hash-verified; tx_pos must be an output whose
   * value equals the listed value, whose script is non-empty and hashes
   * (sha256, reversed: WoC's scripthash) to `scriptHash`. Any failure throws.
   */
  async getContractUtxo(scriptHash: string): Promise<UTXO | null> {
    const resp = await fetch(`${this.baseUrl}/script/${scriptHash}/unspent`);
    if (!resp.ok) {
      // 404 simply means no UTXO found
      if (resp.status === 404) return null;
      throw new Error(`WoC getContractUtxo failed (${resp.status}): ${await resp.text()}`);
    }
    const body = (await resp.json()) as WocScriptUtxoEntry[] | { result?: WocScriptUtxoEntry[] };
    const entries = Array.isArray(body) ? body : body.result;
    if (!Array.isArray(entries)) {
      throw new Error(`WoC getContractUtxo: unexpected listing shape for ${scriptHash}`);
    }
    if (entries.length === 0) return null;

    const first = entries[0]!;
    const { tx } = await this.fetchVerifiedTx(first.tx_hash, 'getContractUtxo');
    const out = tx.outputs[first.tx_pos];
    if (!out) {
      throw new Error(
        `WoC getContractUtxo: no output ${first.tx_pos} in tx ${first.tx_hash} (${tx.outputs.length} outputs)`,
      );
    }
    if (out.satoshis !== first.value) {
      throw new Error(
        `WoC getContractUtxo: value mismatch for ${first.tx_hash}:${first.tx_pos}: listing says ${first.value}, tx says ${out.satoshis}`,
      );
    }
    const script = out.lockingScript.toHex();
    if (script === '') {
      throw new Error(
        `WoC getContractUtxo: empty locking script for ${first.tx_hash}:${first.tx_pos}`,
      );
    }
    const gotHash = Utils.toHex(Hash.sha256(Utils.toArray(script, 'hex')).reverse());
    if (gotHash !== scriptHash.toLowerCase()) {
      throw new Error(
        `WoC getContractUtxo: script hash mismatch for ${first.tx_hash}:${first.tx_pos}: output script hashes to ${gotHash}, requested ${scriptHash}`,
      );
    }
    assertScriptHexUnderLimit(
      script, InputLimits.MAX_SCRIPT_BYTES,
      `WhatsOnChainProvider.getContractUtxo(${scriptHash})`,
    );
    return { txid: first.tx_hash, outputIndex: first.tx_pos, satoshis: first.value, script };
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
