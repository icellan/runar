import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      'runar-testing': resolve(__dirname, 'packages/runar-testing/src/index.ts'),
      'runar-compiler': resolve(__dirname, 'packages/runar-compiler/src/index.ts'),
      'runar-ir-schema': resolve(__dirname, 'packages/runar-ir-schema/src/index.ts'),
      'runar-lang/runtime': resolve(__dirname, 'packages/runar-lang/src/runtime/index.ts'),
      'runar-lang': resolve(__dirname, 'packages/runar-lang/src/index.ts'),
      'runar-sdk': resolve(__dirname, 'packages/runar-sdk/src/index.ts'),
    },
  },
  test: {
    // `.worktrees/**` is excluded because CLAUDE.md tells contributors to do
    // their work in a git worktree there. Without this, a root `vitest run`
    // collects every test file from every checked-out worktree as well as the
    // main tree — the same suite runs two, three or four times, results are
    // attributed to the wrong tree, and removing a worktree mid-run fails a
    // thousand files at collection time with no assertion having run.
    exclude: [
      '**/node_modules/**',
      'integration/**',
      '**/dist/**',
      '**/.claude/**',
      '**/.worktrees/**',
    ],
    // Many suites spawn a real CLI or compiler per test. Under vitest 5 on a
    // 4-core CI runner (turbo runs several packages' suites at once) a 1 s
    // spawn took 7 s and tripped the 5 s default; a hang still fails here.
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
