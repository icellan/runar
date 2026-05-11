import { describe, it, expect, afterAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runConformanceTest, shutdownJavaDaemon } from '../runner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_TESTS_DIR = join(__dirname, '../../tests');

const FORBIDDEN_PREFIXES = [
  'TypeScript compiler failed',
  'Rust compiler failed',
  'Python compiler failed',
  'Zig compiler failed',
  'Ruby compiler failed',
  'Java compiler failed',
];

describe('runConformanceTest honours the per-fixture compilers allowlist', () => {
  afterAll(async () => {
    await shutdownJavaDaemon();
  });

  it(
    'does not invoke non-allowlisted compilers on the babybear (Go-only) fixture',
    async () => {
      const testDir = join(CONFORMANCE_TESTS_DIR, 'babybear');
      const result = await runConformanceTest(testDir);

      const forbidden = result.errors.filter((err) =>
        FORBIDDEN_PREFIXES.some((prefix) => err.startsWith(prefix)),
      );

      expect(
        forbidden,
        `runConformanceTest invoked a compiler that is not in the babybear ` +
          `source.json allowlist (compilers: ["go"]). Offending errors:\n` +
          forbidden.map((e) => `  - ${e}`).join('\n'),
      ).toEqual([]);
    },
    120_000,
  );
});
