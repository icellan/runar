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

import { Transaction as BsvTransaction, Hash, Utils } from '@bsv/sdk';
import type { Transaction } from '@bsv/sdk';
import type { Provider } from './provider.js';
import type { TransactionData, TxInput, TxOutput, UTXO } from '../types.js';
import { InputLimits } from 'runar-ir-schema';
import { assertScriptHexUnderLimit } from '../errors.js';

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

// Documented schemas (GorillaPool OpenAPI: Txo, BSV20Txo, TokenBalanceResponse),
// trimmed to the fields read here.
interface GpTxo {
  txid: string;
  vout: number;
  satoshis: number;
  height?: number | null;
  origin?: {
    outpoint: string;
    data?: { insc?: { file?: { hash?: string; size?: number; type?: string } } } | null;
  } | null;
}

interface GpBsv20Txo {
  txid: string;
  vout: number;
  satoshis: number;
  script?: string; // base64
}

interface GpTokenBalance {
  tick?: string;
  id?: string;
  all: { confirmed: string; pending: string };
}

// ---------------------------------------------------------------------------
// Provider implementation
// ---------------------------------------------------------------------------

export class GorillaPoolProvider implements Provider {
  private readonly baseUrl: string;
  private readonly contentBaseUrl: string;
  private readonly network: 'mainnet' | 'testnet';

  constructor(network: 'mainnet' | 'testnet' = 'mainnet') {
    this.network = network;
    this.baseUrl =
      network === 'mainnet'
        ? 'https://ordinals.gorillapool.io/api'
        : 'https://testnet.ordinals.gorillapool.io/api';
    this.contentBaseUrl = this.baseUrl.slice(0, -'/api'.length);
  }

  // -----------------------------------------------------------------------
  // Standard Provider methods
  // -----------------------------------------------------------------------

  /**
   * Fetch a transaction via GET /tx/{txid}/raw, which returns the bare
   * serialized transaction (binary). Each output's satoshis is read from its
   * 8-byte little-endian field, so values are exact (F-027: the former JSON
   * `vout[].value` decode with its `< 1000 → BTC` guess targeted a field
   * GorillaPool never returns). The body must hash to the requested txid.
   */
  async getTransaction(txid: string): Promise<TransactionData> {
    const raw = await this.fetchVerifiedRaw(txid, 'getTransaction');
    const bodyTxid = txid.toLowerCase();
    const tx = BsvTransaction.fromBinary(raw);

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
      txid: bodyTxid,
      version: tx.version,
      inputs,
      outputs,
      locktime: tx.lockTime,
      raw: Utils.toHex(raw),
    };
  }

  async broadcast(tx: Transaction): Promise<string> {
    const rawtx = tx.toHex();
    // N-025: the documented Broadcast body is {"rawtx": string} (lowercase).
    const resp = await fetch(`${this.baseUrl}/tx`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawtx }),
    });
    if (!resp.ok) {
      throw new Error(`GorillaPool broadcast failed (${resp.status}): ${await resp.text()}`);
    }
    const result = await resp.json();
    return typeof result === 'string' ? result : (result as { txid: string }).txid;
  }

  /**
   * N-025: GET /txos/address/{address}/unspent (Txo[]). The listing carries
   * no locking script, so each entry's tx is fetched via /tx/{txid}/raw
   * (hash-verified); the output must exist, its value must equal the
   * listing's, and its script is returned. Any non-2xx (404 included) throws.
   * The listing is not filtered: 1-sat ordinal outputs are returned too.
   */
  async getUtxos(address: string): Promise<UTXO[]> {
    const entries = await this.getJson<GpTxo[]>(`/txos/address/${address}/unspent`, 'getUtxos');
    const txs = new Map<string, BsvTransaction>();
    const utxos: UTXO[] = [];
    for (const e of entries) {
      let tx = txs.get(e.txid);
      if (!tx) {
        tx = BsvTransaction.fromBinary(await this.fetchVerifiedRaw(e.txid, 'getUtxos'));
        txs.set(e.txid, tx);
      }
      const out = tx.outputs[e.vout];
      if (!out) {
        throw new Error(`GorillaPool getUtxos: no output ${e.vout} in tx ${e.txid} (${tx.outputs.length} outputs)`);
      }
      if (out.satoshis !== e.satoshis) {
        throw new Error(
          `GorillaPool getUtxos: value mismatch for ${e.txid}_${e.vout}: listing says ${e.satoshis}, tx says ${out.satoshis}`,
        );
      }
      const script = out.lockingScript.toHex();
      if (script === '') {
        throw new Error(`GorillaPool getUtxos: empty locking script for ${e.txid}_${e.vout}`);
      }
      assertScriptHexUnderLimit(script, InputLimits.MAX_SCRIPT_BYTES, `GorillaPoolProvider.getUtxos(${address})`);
      utxos.push({ txid: e.txid, outputIndex: e.vout, satoshis: e.satoshis, script });
    }
    return utxos;
  }

  /**
   * N-025: the GorillaPool API has no documented route that looks UTXOs up by
   * script hash (the former /script/{hash}/utxos is a 404), so this refuses
   * rather than reporting "no UTXO".
   */
  async getContractUtxo(scriptHash: string): Promise<UTXO | null> {
    throw new Error(
      `GorillaPool getContractUtxo(${scriptHash}): lookup by script hash is not supported by the GorillaPool API`,
    );
  }

  getNetwork(): 'mainnet' | 'testnet' {
    return this.network;
  }

  /** N-025: GET /tx/{txid}/raw (binary), hash-verified, returned as hex. */
  async getRawTransaction(txid: string): Promise<string> {
    return Utils.toHex(await this.fetchVerifiedRaw(txid, 'getRawTransaction'));
  }

  async getFeeRate(): Promise<number> {
    return 100; // BSV standard relay fee: 0.1 sat/byte
  }

  // -----------------------------------------------------------------------
  // Ordinal-specific methods
  // -----------------------------------------------------------------------

  /**
   * N-025: inscriptions currently held by an address — the unspent Txos from
   * GET /txos/address/{address}/unspent whose `origin` is set.
   */
  async getInscriptionsByAddress(address: string): Promise<InscriptionInfo[]> {
    const entries = await this.getJson<GpTxo[]>(`/txos/address/${address}/unspent`, 'getInscriptionsByAddress');
    return entries.filter((t) => t.origin != null).map((t) => inscriptionInfo(t));
  }

  /**
   * N-025: GET /inscriptions/{outpoint} returns a Txo (not a content record).
   * The content is GET /content/{outpoint} (host root), and its base64
   * sha256 must equal origin.data.insc.file.hash.
   *
   * @param inscriptionId - Format: `<txid>_<vout>`
   */
  async getInscription(inscriptionId: string): Promise<InscriptionDetail> {
    const t = await this.getJson<GpTxo>(`/inscriptions/${inscriptionId}`, 'getInscription');
    if (t == null || t.origin == null) {
      throw new Error(`GorillaPool getInscription: ${inscriptionId} is not an inscription (no origin)`);
    }
    const info = inscriptionInfo(t);
    const resp = await fetch(`${this.contentBaseUrl}/content/${inscriptionId}`);
    if (!resp.ok) {
      throw new Error(`GorillaPool getInscription content failed (${resp.status}): ${await resp.text()}`);
    }
    const content = Array.from(new Uint8Array(await resp.arrayBuffer()));
    const want = t.origin.data?.insc?.file?.hash;
    const got = Utils.toBase64(Hash.sha256(content));
    if (want === undefined || got !== want) {
      throw new Error(
        `GorillaPool getInscription: content hash mismatch for ${inscriptionId}: sha256 ${got}, inscription says ${want ?? '(none)'}`,
      );
    }
    return { ...info, data: Utils.toHex(content) };
  }

  /**
   * N-025: BSV-20 (v1, tick-based) confirmed balance, from
   * GET /bsv20/{address}/balance. No entry for the tick means "0".
   */
  async getBSV20Balance(address: string, tick: string): Promise<string> {
    const rows = await this.getJson<GpTokenBalance[]>(`/bsv20/${address}/balance`, 'getBSV20Balance');
    return rows.find((r) => r.tick === tick)?.all.confirmed ?? '0';
  }

  /** N-025: BSV-20 token UTXOs, from GET /bsv20/{address}/tick/{tick}. */
  async getBSV20Utxos(address: string, tick: string): Promise<UTXO[]> {
    const rows = await this.getJson<GpBsv20Txo[]>(
      `/bsv20/${address}/tick/${encodeURIComponent(tick)}`, 'getBSV20Utxos',
    );
    return rows.map((r) => bsv20Utxo(r, 'getBSV20Utxos'));
  }

  /**
   * N-025: BSV-21 (v2, ID-based) confirmed balance, from
   * GET /bsv20/{address}/balance. No entry for the id means "0".
   *
   * @param id - Token ID in format `<txid>_<vout>`
   */
  async getBSV21Balance(address: string, id: string): Promise<string> {
    const rows = await this.getJson<GpTokenBalance[]>(`/bsv20/${address}/balance`, 'getBSV21Balance');
    return rows.find((r) => r.id === id)?.all.confirmed ?? '0';
  }

  /**
   * N-025: BSV-21 token UTXOs, from GET /bsv20/{address}/id/{id}.
   *
   * @param id - Token ID in format `<txid>_<vout>`
   */
  async getBSV21Utxos(address: string, id: string): Promise<UTXO[]> {
    const rows = await this.getJson<GpBsv20Txo[]>(
      `/bsv20/${address}/id/${encodeURIComponent(id)}`, 'getBSV21Utxos',
    );
    return rows.map((r) => bsv20Utxo(r, 'getBSV21Utxos'));
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  /** GET a JSON route; any non-2xx (a 404 included) throws. */
  private async getJson<T>(path: string, method: string): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`);
    if (!resp.ok) {
      throw new Error(`GorillaPool ${method} failed (${resp.status}): ${await resp.text()}`);
    }
    return (await resp.json()) as T;
  }

  /** GET /tx/{txid}/raw; the body must hash (sha256d, reversed) to txid. */
  private async fetchVerifiedRaw(txid: string, method: string): Promise<number[]> {
    const resp = await fetch(`${this.baseUrl}/tx/${txid}/raw`);
    if (!resp.ok) {
      throw new Error(`GorillaPool ${method} failed (${resp.status}): ${await resp.text()}`);
    }
    const raw = Array.from(new Uint8Array(await resp.arrayBuffer()));
    const bodyTxid = Utils.toHex(Hash.hash256(raw).reverse());
    if (bodyTxid !== txid.toLowerCase()) {
      throw new Error(
        `GorillaPool ${method}: txid mismatch: response body hashes to ${bodyTxid}, requested ${txid}`,
      );
    }
    return raw;
  }
}

function inscriptionInfo(t: GpTxo): InscriptionInfo {
  const file = t.origin?.data?.insc?.file;
  return {
    txid: t.txid,
    vout: t.vout,
    origin: t.origin!.outpoint,
    contentType: file?.type ?? '',
    contentLength: file?.size ?? 0,
    height: t.height ?? 0,
  };
}

function bsv20Utxo(r: GpBsv20Txo, method: string): UTXO {
  const script = r.script ? Utils.toHex(Utils.toArray(r.script, 'base64')) : '';
  if (script === '') {
    throw new Error(`GorillaPool ${method}: no locking script for ${r.txid}_${r.vout}`);
  }
  assertScriptHexUnderLimit(script, InputLimits.MAX_SCRIPT_BYTES, `GorillaPoolProvider.${method}`);
  return { txid: r.txid, outputIndex: r.vout, satoshis: r.satoshis, script };
}
