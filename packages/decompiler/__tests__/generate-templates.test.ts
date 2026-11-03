/**
 * N-088 (fail-open regen class): scripts/generate-templates.ts walked every
 * .runar.ts contract under examples/ts/, compiled it, and dropped any
 * contract that failed to compile into a `skipped` list that it only
 * PRINTED — the manifest was still written and the process still exited 0.
 * Every contract under examples/ts/ is expected to compile (there were 0
 * skips in the checked-in templates-data.json at the time this was found),
 * so a skip is a compiler regression, not a legitimate outcome, and must
 * fail the build rather than silently shrink the manifest.
 *
 * This spawns the real script against a scratch `--examples-dir` /
 * `--out` pair (never the real examples/ts/ or templates-data.json) so the
 * real tree is never touched by this test.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, '..');
const SCRIPT = resolve(PKG_ROOT, 'scripts', 'generate-templates.ts');

const VALID_SOURCE = `
import { SmartContract, assert } from 'runar-lang';

class Good extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint) {
    assert(x === this.limit);
  }
}
`;

const BROKEN_SOURCE = 'this is not { valid runar ts at all\n';

function run(examplesDir: string, out: string) {
  const r = spawnSync('npx', ['tsx', SCRIPT, '--examples-dir', examplesDir, '--out', out], {
    cwd: PKG_ROOT,
    encoding: 'utf8',
    env: process.env,
    timeout: 120_000,
  });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

describe('generate-templates.ts fails closed on a contract that does not compile', () => {
  it('exits non-zero and does not write the manifest when a contract is skipped', () => {
    const examplesDir = mkdtempSync(join(tmpdir(), 'runar-n088-templates-'));
    const outDir = mkdtempSync(join(tmpdir(), 'runar-n088-out-'));
    const outPath = join(outDir, 'templates-data.json');
    try {
      writeFileSync(join(examplesDir, 'Good.runar.ts'), VALID_SOURCE);
      writeFileSync(join(examplesDir, 'Broken.runar.ts'), BROKEN_SOURCE);

      const r = run(examplesDir, outPath);

      expect(r.status, `expected a non-zero exit code; output:\n${r.out}`).not.toBe(0);
      expect(r.out).toMatch(/Broken\.runar\.ts/);
      expect(existsSync(outPath), 'manifest must not be written when a contract was skipped').toBe(false);
    } finally {
      rmSync(examplesDir, { recursive: true, force: true });
      rmSync(outDir, { recursive: true, force: true });
    }
  }, 120_000);

  it('control: exits 0 and writes the manifest when every contract compiles', () => {
    const examplesDir = mkdtempSync(join(tmpdir(), 'runar-n088-templates-ok-'));
    const outDir = mkdtempSync(join(tmpdir(), 'runar-n088-out-ok-'));
    const outPath = join(outDir, 'templates-data.json');
    try {
      writeFileSync(join(examplesDir, 'Good.runar.ts'), VALID_SOURCE);

      const r = run(examplesDir, outPath);

      expect(r.status, `expected exit 0 for an all-compiling corpus; output:\n${r.out}`).toBe(0);
      expect(existsSync(outPath)).toBe(true);
    } finally {
      rmSync(examplesDir, { recursive: true, force: true });
      rmSync(outDir, { recursive: true, force: true });
    }
  }, 120_000);
});
