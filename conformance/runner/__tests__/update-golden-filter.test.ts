import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// `--update-golden` ignored `--filter`: the update branch in index.ts listed
// every subdirectory of --tests-dir itself instead of going through
// `discoverFixtureDirs`, so `--update-golden --filter foo` restamped EVERY
// golden in the suite. A filtered restamp must touch only the matching
// fixtures, and a filter that matches nothing must fail rather than silently
// succeed with zero updates.
//
// What this proves: with two compilable fixtures under one --tests-dir,
// `--update-golden --filter <one>` writes goldens for that fixture only and
// leaves the other untouched; a filter that matches nothing exits non-zero
// and writes nothing.
// What it does not prove: the content of the stamped goldens (that is the TS
// compiler's output, covered by the golden-provenance gate).

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../..');
const INDEX_TS = resolve(__dirname, '../index.ts');
const P2PKH_TS = join(ROOT, 'examples/ts/p2pkh/P2PKH.runar.ts');

function tsxLoader(): string | null {
  for (const p of [
    join(ROOT, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(ROOT, 'node_modules/tsx/dist/loader.mjs'),
  ]) {
    if (existsSync(p)) return pathToFileURL(p).href;
  }
  return null;
}

const sandboxes: string[] = [];
afterEach(() => {
  while (sandboxes.length > 0) rmSync(sandboxes.pop()!, { recursive: true, force: true });
});

function makeTestsDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'runar-update-filter-'));
  sandboxes.push(dir);
  const src = readFileSync(P2PKH_TS, 'utf-8');
  for (const name of ['alpha-picked', 'beta-other']) {
    mkdirSync(join(dir, name), { recursive: true });
    writeFileSync(join(dir, name, `${name}.runar.ts`), src);
  }
  return dir;
}

function runUpdate(testsDir: string, filter: string) {
  const loader = tsxLoader();
  expect(loader, 'no tsx loader found').not.toBeNull();
  return spawnSync(
    process.execPath,
    ['--import', loader!, INDEX_TS, '--update-golden', '--tests-dir', testsDir, '--filter', filter],
    { cwd: ROOT, encoding: 'utf-8', timeout: 120_000, maxBuffer: 64 * 1024 * 1024 },
  );
}

describe('--update-golden respects --filter', () => {
  it('stamps only the fixtures matching the filter', () => {
    const testsDir = makeTestsDir();
    const res = runUpdate(testsDir, 'alpha');
    const combined = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
    expect(res.status, combined).toBe(0);
    expect(existsSync(join(testsDir, 'alpha-picked', 'expected-script.hex')), combined).toBe(true);
    expect(existsSync(join(testsDir, 'beta-other', 'expected-script.hex')), combined).toBe(false);
    expect(existsSync(join(testsDir, 'beta-other', 'expected-ir.json')), combined).toBe(false);
  }, 120_000);

  it('fails and writes nothing when the filter matches no fixture', () => {
    const testsDir = makeTestsDir();
    const res = runUpdate(testsDir, 'no-such-fixture');
    const combined = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
    expect(res.status, combined).not.toBe(0);
    for (const name of ['alpha-picked', 'beta-other']) {
      expect(existsSync(join(testsDir, name, 'expected-script.hex')), combined).toBe(false);
    }
  }, 120_000);
});
