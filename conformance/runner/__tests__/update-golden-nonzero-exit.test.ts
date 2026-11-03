import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// N-088: `conformance/runner/index.ts --update-golden` caught each fixture's
// failure or F-051 allowlist refusal, printed `Failed: <dir>: <message>` and
// CONTINUED to the next fixture — the loop never recorded that one was
// skipped, so `main()` fell through to `return` with no `process.exit` call
// at all, i.e. exit code 0. A scripted golden regeneration (CI, a
// dispatcher, a dev running --update-golden over many fixtures) could not
// tell "every golden was refreshed" from "N of them were silently skipped"
// from the exit code alone — it had to scrape stdout for the word "Failed".
//
// What this proves: given one allowlist-refused fixture and one
// does-not-compile fixture under the same --tests-dir, `--update-golden`
// exits non-zero and names both in its output, and (unchanged, verified here
// as a sanity check, not the point of the test) writes no
// expected-ir.json/expected-script.hex for either.
//
// What it does not prove: anything about cross-tier parity during an
// update — `updateGoldenFiles` stamps goldens from the TS compiler only, by
// design (F-051, see update-golden-allowlist.test.ts); this item does not
// change that, and the dispatcher's "or cross-tier disagreement" phrasing is
// not implemented here — bolting a 7-tier parity pass onto the updater would
// be a design change, not this fix.

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../..');
const INDEX_TS = resolve(__dirname, '../index.ts');

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

/**
 * A --tests-dir containing exactly two fixtures: one the F-051 allowlist gate
 * refuses before any compile runs, one whose TS source fails to compile. No
 * other entries — `index.ts` treats every subdirectory of --tests-dir as a
 * fixture, so a stray folder here would be picked up as a third one.
 */
function makeTestsDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'runar-n088-'));
  sandboxes.push(dir);

  const refused = join(dir, 'refused-go-only');
  mkdirSync(refused, { recursive: true });
  writeFileSync(join(refused, 'source.json'), JSON.stringify({ compilers: ['go'] }, null, 2));

  const broken = join(dir, 'broken-source');
  mkdirSync(broken, { recursive: true });
  writeFileSync(join(broken, 'broken-source.runar.ts'), 'this is not { valid runar ts at all\n');

  return dir;
}

describe('N-088: --update-golden exits non-zero when a fixture fails or is refused', () => {
  it('exits non-zero, names both fixtures, and writes no goldens for either', () => {
    const testsDir = makeTestsDir();
    const loader = tsxLoader();
    expect(loader, 'no tsx loader found').not.toBeNull();

    const res = spawnSync(
      process.execPath,
      ['--import', loader!, INDEX_TS, '--update-golden', '--tests-dir', testsDir],
      { cwd: ROOT, encoding: 'utf-8', timeout: 120_000, maxBuffer: 64 * 1024 * 1024 },
    );

    const combined = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
    expect(res.status, `expected a non-zero exit code; output:\n${combined}`).not.toBe(0);
    expect(combined).toMatch(/refused-go-only/);
    expect(combined).toMatch(/broken-source/);

    expect(existsSync(join(testsDir, 'refused-go-only', 'expected-ir.json'))).toBe(false);
    expect(existsSync(join(testsDir, 'refused-go-only', 'expected-script.hex'))).toBe(false);
    expect(existsSync(join(testsDir, 'broken-source', 'expected-ir.json'))).toBe(false);
    expect(existsSync(join(testsDir, 'broken-source', 'expected-script.hex'))).toBe(false);
  }, 120_000);
});
