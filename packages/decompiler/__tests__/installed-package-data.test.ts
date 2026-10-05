/**
 * F-059 / CL-BUG-110 — the BUILT, installed decompiler must load its data.
 *
 * Every other test in this package imports `../src/*.ts`, so `__dirname`
 * is `<pkg>/src` and `resolve(__dirname, '..', <data>.json)` happens to hit
 * the package root. The published entry point is `dist/src/index.js`,
 * where the same expression resolves to `<pkg>/dist/`, which holds no
 * data files. On top of that `templates-data.json` was missing from
 * package.json `files`, so npm never shipped it. Both loaders swallowed
 * the miss and returned an empty set, so the installed tool fell back to
 * `raw_script` for nearly every input and still reported success.
 *
 * This test builds the package with its own tsconfig into a temp dir,
 * lays it out the way `npm install` would (the files `npm pack` lists,
 * plus the fresh `dist/`), and runs the compiled entry point in a child
 * `node` process.
 *
 * Proves: the files npm would publish include both data files; the
 * compiled loaders find them in that layout; a template-manifest script
 * (not the opcode-pattern P2PKH shape) is recovered via `template`; and a
 * missing data file makes the loader throw instead of degrading silently.
 *
 * Does not prove: a real registry publish/install (dependencies are
 * symlinked from the workspace, and `workspace:*` rewriting is not
 * exercised), or anything about recovery quality beyond one manifest hit.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadFingerprints } from '../src/fingerprints.js';

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '..');

interface PackFile { path: string }

let tmp = '';
let installed = '';

function packedFiles(): string[] {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: PKG,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  const parsed = JSON.parse(out) as Array<{ files: PackFile[] }>;
  return parsed[0]!.files.map((f) => f.path);
}

/** Lay out `<dest>` like an installed copy of this package. */
function install(dest: string, files: string[]): void {
  mkdirSync(dest, { recursive: true });
  for (const f of files) {
    if (f.startsWith('dist/')) continue; // replaced by a fresh build below
    mkdirSync(dirname(join(dest, f)), { recursive: true });
    cpSync(join(PKG, f), join(dest, f));
  }
  execFileSync(
    join(PKG, 'node_modules', '.bin', 'tsc'),
    ['-p', join(PKG, 'tsconfig.json'), '--outDir', join(dest, 'dist')],
    { cwd: PKG, stdio: 'pipe' },
  );
  symlinkSync(join(PKG, 'node_modules'), join(dest, 'node_modules'), 'dir');
}

function runInstalled(dir: string, body: string) {
  const main = (JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { main: string }).main;
  const script = `
    const m = await import(${JSON.stringify(join(dir, main))});
    ${body}
  `;
  return spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: dir,
    encoding: 'utf8',
  });
}

describe('installed package layout (F-059)', () => {
  let files: string[] = [];

  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'runar-decompiler-installed-'));
    files = packedFiles();
    installed = join(tmp, 'pkg');
    install(installed, files);
  }, 120_000);

  afterAll(() => {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  it('npm would publish both data files', () => {
    expect(files).toContain('templates-data.json');
    expect(files).toContain('fingerprints.json');
  });

  it('the built entry point loads templates + fingerprints and recovers a manifest script via template', () => {
    const manifest = JSON.parse(readFileSync(join(PKG, 'templates-data.json'), 'utf8')) as {
      entries: Array<{ hex: string; origin: string; source: string }>;
    };
    const entry = manifest.entries.find((e) => e.origin.endsWith('CountdownLoop.runar.ts'));
    expect(entry).toBeDefined();

    const r = runInstalled(installed, `
      const res = m.decompile(${JSON.stringify(entry!.hex)});
      console.log(JSON.stringify({
        fingerprints: m.loadFingerprints().entries.length,
        ok: res.ok,
        recoveryPath: res.recoveryPath,
        source: res.source,
      }));
    `);
    expect(r.stderr).toBe('');
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout.trim()) as {
      fingerprints: number; ok: boolean; recoveryPath: string; source: string;
    };
    expect(out.fingerprints).toBeGreaterThan(0);
    expect(out.ok).toBe(true);
    expect(out.recoveryPath).toBe('template');
    expect(out.source).toBe(entry!.source);
  });

  it('a missing templates-data.json makes the built package fail loudly', () => {
    const broken = join(tmp, 'no-templates');
    install(broken, files.filter((f) => f !== 'templates-data.json'));
    const r = runInstalled(broken, `console.log('loaded');`);
    expect(r.status).not.toBe(0);
    expect(r.stdout).not.toContain('loaded');
    expect(r.stderr).toContain('templates-data.json');
  }, 120_000);

  it('a missing fingerprints.json makes the built package fail loudly', () => {
    const broken = join(tmp, 'no-fingerprints');
    install(broken, files.filter((f) => f !== 'fingerprints.json'));
    const r = runInstalled(broken, `m.loadFingerprints(); console.log('loaded');`);
    expect(r.status).not.toBe(0);
    expect(r.stdout).not.toContain('loaded');
    expect(r.stderr).toContain('fingerprints.json');
  }, 120_000);
});

describe('loadFingerprints with an explicit path (F-059)', () => {
  it('throws on a missing file instead of returning an empty DB', () => {
    expect(() => loadFingerprints(join(PKG, 'does-not-exist.json'))).toThrow(/does-not-exist\.json/);
  });
});
