/**
 * N-420: packages/decompiler/fingerprints.json is derived from live compiles
 * (scripts/build-fingerprints.ts) but was not covered by the
 * derived-artifact freshness gate, so a byte-moving EC codegen change left
 * stale templates in it with every gate green.
 *
 * Proves: (1) the orchestrator lists a fingerprints corpus, (2)
 * `build-fingerprints.ts --check` exits non-zero and names fingerprints.json
 * when the committed file differs from a fresh build (perturbed COPY, never
 * the real file), (3) the committed file equals a fresh build, and (4) the
 * regeneration is deterministic (two builds, byte-identical).
 *
 * Does not prove: that the probes themselves cover every EC codegen shape,
 * nor that the CI step actually runs the orchestrator (see ci.yml).
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, '..');
const REPO_ROOT = resolve(PKG_ROOT, '..', '..');
const SCRIPT = resolve(PKG_ROOT, 'scripts', 'build-fingerprints.ts');
const COMMITTED = resolve(PKG_ROOT, 'fingerprints.json');
const ORCHESTRATOR = resolve(REPO_ROOT, 'conformance/scripts/check-derived-artifacts.ts');

function build(args: string[]) {
  const r = spawnSync('npx', ['tsx', SCRIPT, ...args], {
    cwd: PKG_ROOT,
    encoding: 'utf8',
    env: process.env,
    timeout: 120_000,
  });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

describe('N-420 fingerprints.json derived-artifact gate', () => {
  it('orchestrator lists a decompiler-fingerprints corpus', () => {
    const r = spawnSync(process.execPath, ['--import', 'tsx', ORCHESTRATOR, '--check', '--dry-run'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
    expect(r.status, `${r.stdout}${r.stderr}`).toBe(0);
    expect(r.stdout).toContain('decompiler-fingerprints');
  });

  it('--check fails and names fingerprints.json when the committed copy is stale', () => {
    const dir = mkdtempSync(join(tmpdir(), 'runar-n420-'));
    const copy = join(dir, 'fingerprints.json');
    const db = JSON.parse(readFileSync(COMMITTED, 'utf8')) as {
      entries: { normalizedHex: string }[];
    };
    db.entries[0]!.normalizedHex = db.entries[0]!.normalizedHex + '00';
    writeFileSync(copy, JSON.stringify(db, null, 2) + '\n');
    const before = readFileSync(copy, 'utf8');
    const r = build(['--check', '--out', copy]);
    expect(r.status, r.out).not.toBe(0);
    expect(r.out).toContain('fingerprints.json');
    expect(readFileSync(copy, 'utf8'), '--check must not rewrite the file').toBe(before);
  }, 120_000);

  it('committed fingerprints.json equals a fresh build, and the build is deterministic', () => {
    const dir = mkdtempSync(join(tmpdir(), 'runar-n420-'));
    const a = join(dir, 'a', 'fingerprints.json');
    const b = join(dir, 'b', 'fingerprints.json');
    // seed with the committed file so the preserved timestamp is comparable
    for (const p of [a, b]) {
      spawnSync('mkdir', ['-p', dirname(p)]);
      copyFileSync(COMMITTED, p);
    }
    expect(build(['--out', a]).status).toBe(0);
    expect(build(['--out', b]).status).toBe(0);
    expect(readFileSync(a, 'utf8')).toBe(readFileSync(b, 'utf8'));
    expect(readFileSync(a, 'utf8'), 'committed fingerprints.json is stale').toBe(
      readFileSync(COMMITTED, 'utf8'),
    );
    const r = build(['--check']);
    expect(r.status, r.out).toBe(0);
  }, 240_000);
});
