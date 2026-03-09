/**
 * Vitest globalSetup — checks node availability and mines initial blocks.
 *
 * BSV regtest halves the block reward every 150 blocks, so the total
 * mineable supply is finite (~15 000 BTC). After many test runs the
 * wallet can be depleted. This setup checks the balance and warns if
 * it is too low (the fix is: `./regtest.sh clean && ./regtest.sh start`).
 */

import { isNodeAvailable, getBlockCount, mine, rpcCall } from './helpers/node.js';

export default async function setup() {
  const available = await isNodeAvailable();
  if (!available) {
    console.error('Regtest node not running. Skipping integration tests.');
    console.error('Start with: cd integration && ./regtest.sh start');
    process.exit(0);
  }

  const height = await getBlockCount();
  const target = 101;
  const needed = target - height;
  if (needed > 0) {
    console.error(`Mining ${needed} blocks (current: ${height}, target: ${target})...`);
    await mine(needed);
  }

  // Check wallet balance — if depleted, warn the user to clean/restart.
  const balance = (await rpcCall('getbalance')) as number;
  if (balance < 10) {
    console.error('');
    console.error(`WARNING: Regtest wallet balance is only ${balance} BTC.`);
    console.error('BSV regtest exhausts coinbase rewards after ~150 halvings (150-block interval).');
    console.error('To reset: cd integration && ./regtest.sh clean && ./regtest.sh start');
    console.error('');
    if (balance < 1) {
      console.error('Balance too low to run integration tests. Exiting.');
      process.exit(1);
    }
  }
}
