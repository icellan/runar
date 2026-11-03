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
    // vitest 2 never failed a long SYNCHRONOUS test on its timeout; vitest 5
    // does. Many suites here are long and synchronous (full-corpus compiles,
    // ScriptVM sweeps, coverage-matrix --check): the longest single test ran
    // 127 s on CI under vitest 2, and spawn-per-test suites slow down further
    // when turbo runs several packages at once. A real hang still fails.
    testTimeout: 300_000,
    hookTimeout: 300_000,
  },
});
