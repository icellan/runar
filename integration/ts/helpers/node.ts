/**
 * Bitcoin regtest node helpers — JSON-RPC communication, mining, wallet funding.
 */

import { RPCProvider } from 'runar-sdk';
import type { Transaction } from '@bsv/sdk';

export const RPC_URL = process.env.RPC_URL ?? 'http://localhost:18332';
export const RPC_USER = process.env.RPC_USER ?? 'bitcoin';
export const RPC_PASS = process.env.RPC_PASS ?? 'bitcoin';

/**
 * Wrap an RPCProvider's broadcast method to log the raw tx size in bytes
 * before delegating to the SDK implementation. Mutates the provider in
 * place; returns the same instance for chaining.
 */
function instrumentBroadcast(provider: RPCProvider): RPCProvider {
  const original = provider.broadcast.bind(provider);
  provider.broadcast = async (tx: Transaction): Promise<string> => {
    const hex = tx.toHex();
    const sizeBytes = Math.floor(hex.length / 2);
    process.stderr.write(`[runar-integration] tx broadcast: ${sizeBytes} bytes\n`);
    return original(tx);
  };
  return provider;
}

/** Create an RPCProvider using env-configured credentials. */
export function createProvider(): RPCProvider {
  return instrumentBroadcast(
    new RPCProvider(RPC_URL, RPC_USER, RPC_PASS, { autoMine: true, network: 'testnet' }),
  );
}

/** Create a provider that does NOT mine after each broadcast. Call mine(1) manually. */
export function createBatchProvider(): RPCProvider {
  return instrumentBroadcast(
    new RPCProvider(RPC_URL, RPC_USER, RPC_PASS, { autoMine: false, network: 'testnet' }),
  );
}

export async function rpcCall(method: string, ...params: unknown[]): Promise<unknown> {
  const body = JSON.stringify({
    jsonrpc: '1.0',
    id: 'runar',
    method,
    params,
  });

  const auth = Buffer.from(`${RPC_USER}:${RPC_PASS}`).toString('base64');
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${auth}`,
    },
    body,
    signal: AbortSignal.timeout(600_000),
  });

  const json = (await response.json()) as { result: unknown; error: unknown };
  if (json.error) {
    const err = json.error as { message?: string };
    throw new Error(`RPC ${method}: ${err.message ?? JSON.stringify(json.error)}`);
  }
  return json.result;
}

export async function mine(blocks: number): Promise<void> {
  try {
    await rpcCall('generate', blocks);
  } catch {
    const addr = (await rpcCall('getnewaddress')) as string;
    await rpcCall('generatetoaddress', blocks, addr);
  }
}

/**
 * Mine until `txid` has at least one confirmation, or fail loudly.
 *
 * A bare `mine(1)` is a RACE: the node must have accepted the tx into its
 * mempool AND selected it for the block template before that block is built.
 * Under a full suite (many tests broadcasting and mining against one node)
 * that ordering is not guaranteed, so the block can land without the tx and a
 * `confirmations > 0` assertion fails on timing rather than on consensus.
 *
 * Observed exactly that: `bip143-crosstier` failed with "expected 0 to be
 * greater than 0" inside `run-all.sh` while passing 4/4 in isolation.
 *
 * This keeps the assertion's strength — the tx must really enter a block — and
 * only removes the assumption that one block suffices.
 */
export async function mineUntilConfirmed(txid: string, maxBlocks = 5): Promise<number> {
  for (let i = 0; i < maxBlocks; i++) {
    await mine(1);
    const tx = (await rpcCall('getrawtransaction', txid, true)) as {
      confirmations?: number;
    };
    const confirmations = tx.confirmations ?? 0;
    if (confirmations > 0) return confirmations;
  }
  throw new Error(
    `tx ${txid} still unconfirmed after mining ${maxBlocks} blocks — ` +
      `it was accepted to the mempool but never selected into a block\n` +
      (await describeUnmined(txid)),
  );
}

/**
 * Explain why a mempool tx is not being mined.
 *
 * On bitcoin-sv, mempool membership does NOT imply mining eligibility. The
 * block assembler builds from the *journal*, and `getmempoolinfo` reports the
 * two sizes separately — a tx below `minminingtxfee` is accepted by
 * `sendrawtransaction`, is visible to `getrawtransaction`, and is still never
 * selected into a block. (Observed on a live regtest node: a zero-fee tx sat
 * in the mempool for ~1000 blocks.) Non-final txs are held in a third pool and
 * are not even visible to `getrawtransaction`.
 *
 * Without this, the failure reads as an unexplained flake. With it, the
 * message names the pool, the fee, and the unconfirmed ancestors.
 *
 * Best-effort: every probe is individually guarded, because a diagnostic that
 * throws would replace the real failure with its own.
 */
export async function describeUnmined(txid: string): Promise<string> {
  const lines: string[] = [];
  const probe = async (label: string, fn: () => Promise<unknown>): Promise<void> => {
    try {
      lines.push(`  ${label}: ${JSON.stringify(await fn())}`);
    } catch (e) {
      lines.push(`  ${label}: <unavailable: ${(e as Error).message}>`);
    }
  };

  // size > journalsize means the node is holding txs back from block assembly.
  await probe('getmempoolinfo', () => rpcCall('getmempoolinfo'));
  // fee/modifiedfee vs size decides journal eligibility; depends lists ancestors.
  await probe('getmempoolentry', () => rpcCall('getmempoolentry', txid));
  await probe('in getrawmempool', async () =>
    ((await rpcCall('getrawmempool')) as string[]).includes(txid),
  );
  await probe('in getrawnonfinalmempool', async () =>
    ((await rpcCall('getrawnonfinalmempool')) as string[]).includes(txid),
  );

  // An unconfirmed ancestor that is itself unminable blocks the whole chain.
  try {
    const tx = (await rpcCall('getrawtransaction', txid, true)) as {
      vin?: Array<{ txid?: string }>;
    };
    for (const vin of tx.vin ?? []) {
      if (!vin.txid) continue;
      await probe(`parent ${vin.txid.slice(0, 12)} confirmations`, async () => {
        const p = (await rpcCall('getrawtransaction', vin.txid, true)) as {
          confirmations?: number;
        };
        return p.confirmations ?? 0;
      });
    }
  } catch (e) {
    lines.push(`  parents: <unavailable: ${(e as Error).message}>`);
  }

  return lines.join('\n');
}

export async function getBlockCount(): Promise<number> {
  return (await rpcCall('getblockcount')) as number;
}

export async function isNodeAvailable(): Promise<boolean> {
  try {
    await getBlockCount();
    return true;
  } catch {
    return false;
  }
}

export async function sendToAddress(address: string, amount: number): Promise<string> {
  return (await rpcCall('sendtoaddress', address, amount)) as string;
}

export async function fundAddress(address: string, btcAmount: number): Promise<void> {
  await rpcCall('importaddress', address, '', false);
  await sendToAddress(address, btcAmount);
  await mine(1);
}
