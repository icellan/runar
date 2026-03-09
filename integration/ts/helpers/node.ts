/**
 * Bitcoin regtest node helpers — JSON-RPC communication, mining, wallet funding.
 */

import { RPCProvider } from 'runar-sdk';

export const RPC_URL = process.env.RPC_URL ?? 'http://localhost:18332';
export const RPC_USER = process.env.RPC_USER ?? 'bitcoin';
export const RPC_PASS = process.env.RPC_PASS ?? 'bitcoin';

/** Create an RPCProvider using env-configured credentials. */
export function createProvider(): RPCProvider {
  return new RPCProvider(RPC_URL, RPC_USER, RPC_PASS, { autoMine: true, network: 'testnet' });
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
  await rpcCall('generate', blocks);
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
