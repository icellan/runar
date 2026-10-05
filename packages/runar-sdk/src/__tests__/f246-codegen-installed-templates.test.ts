/**
 * F-246 / CL-BUG-138 — an INSTALLED runar-sdk's `./codegen` export must find
 * its Mustache templates.
 *
 * package.json publishes only `dist` and exports `./codegen`, but gen-all.ts
 * resolved its templates as `../../../../codegen/templates` from the module.
 * In the monorepo that lands on the repo-root `codegen/templates`; from
 * `node_modules/runar-sdk/dist/codegen/` it lands in the CONSUMER's project
 * root, where nothing exists, so every template-based generator threw ENOENT
 * (or, worse, would read whatever the consumer happened to keep there).
 *
 * Every other codegen test imports `../codegen/*.ts`, which runs from the
 * source tree and never sees the published layout. This test takes the files
 * `npm pack` would publish (the real, already-built `dist/`), installs them
 * as `<consumer>/node_modules/runar-sdk`, and imports `runar-sdk/codegen`
 * through the package `exports` map in a child `node` process.
 *
 * Proves: npm would publish all five templates; the published copies are
 * byte-identical to the canonical `codegen/templates/*.mustache` (so they are
 * derived from it, not a second hand-maintained copy — R-279 keeps guarding
 * the canonical file); the installed entry point generates Go / Rust /
 * Python / Zig / template-TS wrappers identical to the in-repo generators;
 * and a missing packaged template fails loudly, naming the file, without
 * falling back to a decoy `codegen/templates/` in the consumer's root.
 *
 * Does not prove: a real registry publish/install (dependencies are symlinked
 * from the workspace, `workspace:*` rewriting is not exercised); it relies on
 * `pnpm run build` having produced the current `dist/`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, mkdirSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateGo, generateRust, generatePython, generateZig, generateTypescriptFromTemplate,
} from '../codegen/index.js';

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const ROOT = resolve(PKG, '..', '..');
const EXTS = ['go', 'py', 'rs', 'ts', 'zig'] as const;
const ARTIFACT_PATH = join(ROOT, 'conformance/sdk-codegen/fixtures/counter.json');

let tmp = '';
let files: string[] = [];

function packedFiles(): string[] {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: PKG,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  const parsed = JSON.parse(out) as Array<{ files: Array<{ path: string }> }>;
  return parsed[0]!.files.map((f) => f.path);
}

/** Make `<consumer>/node_modules/runar-sdk` an installed copy holding `pkgFiles`. */
function installInto(consumer: string, pkgFiles: string[]): void {
  const dest = join(consumer, 'node_modules', 'runar-sdk');
  mkdirSync(dest, { recursive: true });
  for (const f of pkgFiles) {
    mkdirSync(dirname(join(dest, f)), { recursive: true });
    cpSync(join(PKG, f), join(dest, f));
  }
  symlinkSync(join(PKG, 'node_modules'), join(dest, 'node_modules'), 'dir');
  writeFileSync(join(consumer, 'package.json'), '{"name":"consumer","private":true,"type":"module"}');
}

function runConsumer(consumer: string, body: string) {
  const script = `
    const m = await import('runar-sdk/codegen');
    const artifact = JSON.parse(${JSON.stringify(readFileSync(ARTIFACT_PATH, 'utf8'))});
    ${body}
  `;
  return spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: consumer,
    encoding: 'utf8',
  });
}

describe('installed runar-sdk/codegen finds its templates (F-246)', () => {
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'runar-sdk-installed-'));
    files = packedFiles();
  }, 60_000);

  afterAll(() => {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  it('npm would publish every wrapper template', () => {
    for (const ext of EXTS) {
      expect(files).toContain(`dist/codegen/templates/wrapper.${ext}.mustache`);
    }
  });

  it('the published templates are byte-identical to the canonical codegen/templates', () => {
    for (const ext of EXTS) {
      expect(
        readFileSync(join(PKG, `dist/codegen/templates/wrapper.${ext}.mustache`), 'utf8'),
        `dist copy of wrapper.${ext}.mustache is stale — run pnpm run build`,
      ).toBe(readFileSync(join(ROOT, `codegen/templates/wrapper.${ext}.mustache`), 'utf8'));
    }
  });

  it('the installed entry point generates the same wrappers as the in-repo generators', () => {
    const consumer = join(tmp, 'consumer');
    installInto(consumer, files);
    const r = runConsumer(consumer, `
      console.log(JSON.stringify({
        go: m.generateGo(artifact),
        rust: m.generateRust(artifact),
        python: m.generatePython(artifact),
        zig: m.generateZig(artifact),
        ts: m.generateTypescriptFromTemplate(artifact),
      }));
    `);
    expect(r.stderr).toBe('');
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout) as Record<string, string>;
    const artifact = JSON.parse(readFileSync(ARTIFACT_PATH, 'utf8'));
    expect(out.go).toBe(generateGo(artifact));
    expect(out.rust).toBe(generateRust(artifact));
    expect(out.python).toBe(generatePython(artifact));
    expect(out.zig).toBe(generateZig(artifact));
    expect(out.ts).toBe(generateTypescriptFromTemplate(artifact));
    expect(out.go.length).toBeGreaterThan(500);
  }, 60_000);

  it('a missing packaged template fails loudly and never reads the consumer\'s codegen/templates', () => {
    const consumer = join(tmp, 'no-go-template');
    installInto(consumer, files.filter((f) => f !== 'dist/codegen/templates/wrapper.go.mustache'));
    // Decoy at exactly the path the old resolver landed on.
    mkdirSync(join(consumer, 'codegen', 'templates'), { recursive: true });
    writeFileSync(join(consumer, 'codegen', 'templates', 'wrapper.go.mustache'), 'DECOY-TEMPLATE');
    const r = runConsumer(consumer, `console.log(m.generateGo(artifact));`);
    expect(r.status).not.toBe(0);
    expect(r.stdout).not.toContain('DECOY-TEMPLATE');
    expect(r.stderr).toContain('runar-sdk: cannot load codegen template');
    expect(r.stderr).toContain(join('runar-sdk', 'dist', 'codegen', 'templates', 'wrapper.go.mustache'));
  }, 60_000);
});
