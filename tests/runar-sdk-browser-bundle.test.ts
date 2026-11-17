/**
 * Issue #181: `runar-sdk`'s root entry must be bundleable for the browser.
 * It used to reach runar-ir-schema's Node-only validators (node:fs/path/url at
 * module load) through the root barrel, so esbuild/vite failed with an
 * unresolved `node:fs`. This bundles the BUILT entry (`pnpm run build`
 * first) for platform 'browser'; node: specifiers are NOT externalised, so any
 * reachable node: import fails the bundle.
 */
import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = resolve(ROOT, 'packages/runar-sdk/dist/index.js');

describe('runar-sdk root entry is browser-bundleable', () => {
  it('bundles with platform=browser', async () => {
    if (!existsSync(ENTRY)) {
      throw new Error(
        `${ENTRY} is missing. Build first: pnpm run build (or pnpm -F runar-sdk... build). ` +
          'This test never skips: a missing dist would hide the regression.',
      );
    }
    const result = await build({
      entryPoints: [ENTRY],
      bundle: true,
      platform: 'browser',
      format: 'esm',
      write: false,
      logLevel: 'silent',
    });
    expect(result.errors).toEqual([]);
    expect(result.outputFiles.length).toBeGreaterThan(0);
  });
});
