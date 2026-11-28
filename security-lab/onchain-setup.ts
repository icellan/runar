/**
 * Global setup for the on-chain attack runs. Mirrors integration/ts/setup.ts:
 * refuse to run against anything that is not regtest, and make sure there are
 * coins to spend (coinbase maturity is 100 blocks).
 */
import { rpcCall, getBlockCount, mine, isNodeAvailable } from '../integration/ts/helpers/node.js';

export default async function setup(): Promise<void> {
  if (!(await isNodeAvailable())) {
    console.error('Regtest node is not reachable at ' + (process.env.RPC_URL ?? 'http://localhost:18332'));
    console.error('Start it with:  cd integration && ./regtest.sh start');
    process.exit(1);
  }
  const info = (await rpcCall('getblockchaininfo')) as { chain: string };
  if (info.chain !== 'regtest') {
    throw new Error(`SAFETY: connected to '${info.chain}', not regtest — refusing to run attack tests.`);
  }
  const needed = 101 - (await getBlockCount());
  if (needed > 0) {
    console.error(`Mining ${needed} blocks to unlock coinbase (current height ${await getBlockCount()})...`);
    await mine(needed);
  }
  const balance = (await rpcCall('getbalance')) as number;
  console.error(`regtest ok — height ${await getBlockCount()}, wallet ${balance} BTC`);
  if (balance < 1) {
    console.error('Wallet too low for attack tests. Reset: cd integration && ./regtest.sh clean && ./regtest.sh start');
    process.exit(1);
  }
}
