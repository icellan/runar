/**
 * On-chain (regtest) run of the security lab.
 *
 *   cd integration && ./regtest.sh start      # docker, RPC on 18332
 *   cd security-lab && npx vitest run          # only onchain/** is collected
 *
 * Kept separate from the repo-root vitest.config.ts so the offline, Spend-based
 * suite (`npx vitest run security-lab` from the repo root) stays runnable
 * without Docker.
 *
 * fileParallelism: false is not a style choice — every file mines against one
 * node, and two workers generating on the same tip build competing blocks, so
 * the loser's transactions are silently dropped (see the comment in
 * integration/ts/vitest.config.ts and commit 6e35f3752).
 */
import { defineConfig } from 'vitest/config';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

export default defineConfig({
  resolve: {
    alias: {
      'runar-compiler': resolve(root, 'packages/runar-compiler/src'),
      'runar-sdk': resolve(root, 'packages/runar-sdk/src'),
      'runar-lang': resolve(root, 'packages/runar-lang/src'),
      'runar-ir-schema': resolve(root, 'packages/runar-ir-schema/src'),
      'runar-testing': resolve(root, 'packages/runar-testing/src'),
    },
  },
  test: {
    include: ['onchain/**/*.test.ts'],
    env: { RUNAR_ONCHAIN: '1' }, // onchain/gate.ts requires this; the repo-root config collects these files too
    testTimeout: 600_000,
    hookTimeout: 600_000,
    fileParallelism: false,
    globalSetup: './onchain-setup.ts',
  },
});
