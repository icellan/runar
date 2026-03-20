// ---------------------------------------------------------------------------
// runar-sdk/providers/rpc-provider.ts — JSON-RPC provider for Bitcoin nodes
// ---------------------------------------------------------------------------

import type { Transaction } from '@bsv/sdk';
import type { Provider } from './provider.js';
import type { TransactionData, TxOutput, UTXO } from '../types.js';

export interface RPCProviderOptions {
  /** Auto-mine 1 block after broadcast (for regtest). Default: false. */
  autoMine?: boolean;
  /** Mining address for generatetoaddress. If empty, uses `generate`. */
  mineAddress?: string;
  /** Network name. Default: 'testnet'. */
  network?: 'mainnet' | 'testnet';
}

/**
 * RPCProvider implements Provider by making JSON-RPC calls to a Bitcoin node.
 * Suitable for regtest/testnet integration testing.
 */
export class RPCProvider implements Provider {
  private url: string;
  private user: string;
  private pass: string;
  private network: 'mainnet' | 'testnet';
  private autoMine: boolean;
  private mineAddress: string;

  constructor(url: string, user: string, pass: string, options?: RPCProviderOptions) {
    this.url = url;
    this.user = user;
    this.pass = pass;
    this.network = options?.network ?? 'testnet';
    this.autoMine = options?.autoMine ?? false;
    this.mineAddress = options?.mineAddress ?? '';
  }

  private async rpcCall(method: string, ...params: unknown[]): Promise<unknown> {
    const body = JSON.stringify({
      jsonrpc: '1.0',
      id: 'runar',
      method,
      params,
    });

    const auth = Buffer.from(`${this.user}:${this.pass}`).toString('base64');
    const response = await fetch(this.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Basic ${auth}`,
      },
      body,
      signal: AbortSignal.timeout(600_000), // 10 minutes
    });

    const json = (await response.json()) as { result: unknown; error: unknown };
    if (json.error) {
      const err = json.error as { message?: string };
      throw new Error(`RPC ${method}: ${err.message ?? JSON.stringify(json.error)}`);
    }
    return json.result;
  }

  private async mine(blocks: number): Promise<void> {
    if (this.mineAddress) {
      await this.rpcCall('generatetoaddress', blocks, this.mineAddress);
    } else {
      await this.rpcCall('generate', blocks);
    }
  }

  async getTransaction(txid: string): Promise<TransactionData> {
    const raw = (await this.rpcCall('getrawtransaction', txid, true)) as Record<string, unknown>;
    const rawHex = raw.hex as string;

    const outputs: TxOutput[] = [];
    const vout = raw.vout as Array<Record<string, unknown>>;
    if (vout) {
      for (const o of vout) {
        const valBTC = o.value as number;
        const sats = Math.round(valBTC * 1e8);
        const sp = o.scriptPubKey as Record<string, unknown>;
        const scriptHex = (sp?.hex as string) ?? '';
        outputs.push({ satoshis: sats, script: scriptHex });
      }
    }

    return {
      txid,
      version: 1,
      inputs: [],
      outputs,
      locktime: 0,
      raw: rawHex,
    };
  }

  async broadcast(tx: Transaction): Promise<string> {
    const rawTx = tx.toHex();
    const txid = (await this.rpcCall('sendrawtransaction', rawTx)) as string;
    if (this.autoMine) {
      await this.mine(1);
    }
    return txid;
  }

  async getUtxos(address: string): Promise<UTXO[]> {
    const utxoList = (await this.rpcCall('listunspent', 0, 9999999, [address])) as Array<
      Record<string, unknown>
    >;

    return utxoList.map((u) => ({
      txid: u.txid as string,
      outputIndex: u.vout as number,
      satoshis: Math.round((u.amount as number) * 1e8),
      script: u.scriptPubKey as string,
    }));
  }

  async getContractUtxo(_scriptHash: string): Promise<UTXO | null> {
    return null;
  }

  getNetwork(): 'mainnet' | 'testnet' {
    return this.network;
  }

  async getRawTransaction(txid: string): Promise<string> {
    const rawHex = (await this.rpcCall('getrawtransaction', txid, false)) as string;
    return rawHex;
  }

  async getFeeRate(): Promise<number> {
    return 100;
  }
}
