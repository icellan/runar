/**
 * On-chain tests must run through `security-lab/vitest.config.ts`, which sets
 * `fileParallelism: false`. Two workers mining on one regtest tip build competing
 * blocks and the loser's transactions get dropped, which looks like a failed
 * attack rather than a scheduling race (measured in `integration/ts/vitest.config.ts`:
 * 10 of 16 funding transactions unconfirmed in parallel, 0 of 16 serialized).
 *
 * The repo-root config also collects `security-lab/onchain/**`, so those tests are
 * gated on an env var that only the on-chain config sets. Run them with:
 *
 *   cd integration && ./regtest.sh start
 *   cd ../security-lab && npx vitest run
 */
import { describe } from 'vitest';

export const ONCHAIN_ENABLED = process.env.RUNAR_ONCHAIN === '1';

let warned = false;
export function onchain(name: string, fn: () => void): void {
  if (ONCHAIN_ENABLED) {
    describe(name, fn);
    return;
  }
  if (!warned) {
    warned = true;
    console.log('  [skipped] on-chain tests: cd integration && ./regtest.sh start, then cd security-lab && npx vitest run');
  }
  describe.skip(name, fn);
}
