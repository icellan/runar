import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      'runar-compiler': path.resolve(__dirname, '../../packages/runar-compiler/src'),
      'runar-sdk': path.resolve(__dirname, '../../packages/runar-sdk/src'),
      'runar-lang': path.resolve(__dirname, '../../packages/runar-lang/src'),
      'runar-ir-schema': path.resolve(__dirname, '../../packages/runar-ir-schema/src'),
      'runar-testing': path.resolve(__dirname, '../../packages/runar-testing/src'),
    },
  },
  test: {
    testTimeout: 600_000,
    hookTimeout: 600_000,
    globalSetup: './setup.ts',
    // One regtest node, one miner. Vitest runs test FILES in parallel by
    // default, and every file mines via `generatetoaddress` — either directly
    // or through RPCProvider's autoMine. Two workers generating on the same tip
    // build competing blocks, and the loser's transactions are dropped from the
    // block that wins, so a transaction can miss block after block while being
    // perfectly valid.
    //
    // Measured on a live node: four concurrent workers, each funding an address
    // and then mining up to five blocks, left 10 of 16 funding transactions
    // unconfirmed. Serializing the mining calls alone dropped that to 0 of 16.
    // Serializing at the file level is what actually covers it, because
    // autoMine mines from inside the SDK where a test-side lock cannot reach.
    //
    // Costs ~2.5 min of wall time on this suite and removes chain reorgs as a
    // source of nondeterminism for every test in it.
    fileParallelism: false,
  },
});
