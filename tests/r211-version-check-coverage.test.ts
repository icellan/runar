/**
 * R-211 (CL-GAP-051): `bump-version.sh --check` does not verify the Zig package
 * version, the Ruby gemspec, or the six embedded compiler-version strings —
 * all of which `bump-version.sh <version>` itself rewrites.
 *
 * The gate and the mutation disagree about what "all versions" means:
 *
 *   bump  rewrites  ZIG_ZON, RUBY_GEMSPEC and COMPILER_VERSION_FILES (6 files)
 *   check reads     TS_FILES, RUST_TOMLS, inter-crate deps, Cargo.lock,
 *                   PY_FILES, and a stale-string sweep over the Java/README set
 *
 * So a hand-edit, a bad merge, or a partial bump that leaves
 * `packages/runar-rb/runar.gemspec` or `compilers/go/compiler/compiler.go`
 * behind passes the gate. The finding says "no drift found today, but the gate
 * cannot see it if it occurs" — which is the whole point of a gate.
 *
 * The compiler-version strings are the ones that matter beyond tidiness: they
 * are stamped INTO every artifact (`schemaVersion`, `compilerVersion`), so a
 * tier left a version behind produces artifacts labelled with a version that
 * was never released, and the seven tiers stop agreeing on a field the
 * conformance suite compares.
 *
 * The test builds a throwaway repo — a copy of the script plus the minimal file
 * tree it reads, ROOT being derived from the script's own location — so it can
 * drift one file at a time without touching the real one.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts/bump-version.sh');

const VERSION = '9.9.9';

/** Files the script's own `bump` path rewrites, with their version spelling. */
const COMPILER_VERSION_FILES: Array<{ path: string; body: (v: string) => string }> = [
  {
    path: 'packages/runar-compiler/src/artifact/assembler.ts',
    body: (v) => `const ARTIFACT_VERSION = 'runar-v${v}';\nconst DEFAULT_COMPILER_VERSION = '${v}';\n`,
  },
  {
    path: 'compilers/go/compiler/compiler.go',
    body: (v) => `const (\n\tschemaVersion   = "runar-v${v}"\n\tcompilerVersion = "${v}-go"\n)\n`,
  },
  {
    path: 'compilers/rust/src/artifact.rs',
    body: (v) =>
      `pub const SCHEMA_VERSION: &str = "runar-v${v}";\npub const COMPILER_VERSION: &str = "${v}-rust";\n`,
  },
  {
    path: 'compilers/zig/src/codegen/emit.zig',
    body: (v) => `const schema_version = "runar-v${v}";\nconst compiler_version = "${v}-zig";\n`,
  },
  {
    path: 'compilers/ruby/lib/runar_compiler/compiler.rb',
    body: (v) => `SCHEMA_VERSION = "runar-v${v}"\nCOMPILER_VERSION = "${v}-ruby"\n`,
  },
  {
    path: 'compilers/python/runar_compiler/compiler.py',
    body: (v) => `SCHEMA_VERSION = "runar-v${v}"\nCOMPILER_VERSION = "${v}-python"\n`,
  },
];

const MANIFESTS: Array<{ path: string; body: (v: string) => string; label: string }> = [
  {
    label: 'Zig package manifest',
    path: 'packages/runar-zig/build.zig.zon',
    body: (v) => `.{\n    .name = "runar",\n    .version = "${v}",\n}\n`,
  },
  {
    label: 'Ruby gemspec',
    path: 'packages/runar-rb/runar.gemspec',
    body: (v) => `Gem::Specification.new do |spec|\n  spec.name          = 'runar-lang'\n  spec.version       = '${v}'\nend\n`,
  },
];

let repo: string;

/** Write one file into the throwaway repo, creating parents. */
function put(rel: string, content: string): void {
  const abs = join(repo, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content);
}

/** Lay down a fully consistent tree at VERSION. */
function layDownConsistentRepo(): void {
  mkdirSync(join(repo, 'scripts'), { recursive: true });
  copyFileSync(SCRIPT, join(repo, 'scripts/bump-version.sh'));

  put('package.json', JSON.stringify({ name: 'runar', version: VERSION }, null, 2) + '\n');
  for (const p of [
    'packages/runar-lang',
    'packages/runar-compiler',
    'packages/runar-ir-schema',
    'packages/runar-testing',
    'packages/runar-sdk',
    'packages/runar-cli',
    'packages/decompiler',
  ]) {
    put(`${p}/package.json`, JSON.stringify({ version: VERSION }, null, 2) + '\n');
  }
  for (const p of ['compilers/rust', 'packages/runar-rs', 'packages/runar-rs-macros']) {
    put(`${p}/Cargo.toml`, `[package]\nversion = "${VERSION}"\n`);
  }
  put(
    'packages/runar-rs/Cargo.toml',
    `[package]\nversion = "${VERSION}"\n\n[dependencies]\n` +
      `runar-lang-macros = { version = "${VERSION}" }\n` +
      `runar-compiler-rust = { version = "${VERSION}" }\n`,
  );
  for (const p of ['packages/runar-py', 'compilers/python']) {
    put(`${p}/pyproject.toml`, `[project]\nversion = "${VERSION}"\n`);
  }
  for (const f of COMPILER_VERSION_FILES) put(f.path, f.body(VERSION));
  for (const m of MANIFESTS) put(m.path, m.body(VERSION));
}

function runCheck(): { status: number | null; out: string } {
  const res = spawnSync('bash', [join(repo, 'scripts/bump-version.sh'), '--check'], {
    encoding: 'utf-8',
  });
  return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

beforeAll(() => {
  repo = mkdtempSync(join(tmpdir(), 'r211-'));
});
afterAll(() => {
  rmSync(repo, { recursive: true, force: true });
});

describe('R-211: --check must cover every file --bump rewrites', () => {
  it('passes on a consistent tree (the control — without it every case below is vacuous)', () => {
    layDownConsistentRepo();
    const { status, out } = runCheck();
    expect(status, `--check rejected a consistent tree:\n${out}`).toBe(0);
    expect(out).toContain('All versions consistent');
  });

  it('catches drift in a file it already covered (the instrument works)', () => {
    layDownConsistentRepo();
    put('packages/runar-cli/package.json', JSON.stringify({ version: '1.2.3' }, null, 2) + '\n');
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
  });

  for (const m of MANIFESTS) {
    it(`catches drift in the ${m.label} (${m.path})`, () => {
      layDownConsistentRepo();
      put(m.path, m.body('1.2.3'));
      const { status, out } = runCheck();
      expect(
        status,
        `--check passed with ${m.path} left at 1.2.3 while everything else is ${VERSION}:\n${out}`,
      ).not.toBe(0);
      expect(out).toContain(m.path);
    });
  }

  /**
   * The deliberate exception, pinned so it cannot be "tightened" back into a
   * false alarm. assembler.ts documents the field as
   * `/** Schema version, e.g. "runar-v0.1.0" *\/` — an illustration, not a
   * stamped version. The first draft of this check flagged it and the real
   * repo failed a gate it should pass.
   */
  it('does not flag a version-shaped token inside a comment', () => {
    layDownConsistentRepo();
    put(
      'packages/runar-compiler/src/artifact/assembler.ts',
      `/** Schema version, e.g. "runar-v0.1.0" */\n` +
        `// historical: 0.2.0-go was the first tagged build\n` +
        `const ARTIFACT_VERSION = 'runar-v${VERSION}';\n` +
        `const DEFAULT_COMPILER_VERSION = '${VERSION}';\n`,
    );
    const { status, out } = runCheck();
    expect(status, `a comment tripped the gate:\n${out}`).toBe(0);
  });

  for (const f of COMPILER_VERSION_FILES) {
    it(`catches drift in the embedded compiler version (${f.path})`, () => {
      layDownConsistentRepo();
      put(f.path, f.body('1.2.3'));
      const { status, out } = runCheck();
      expect(
        status,
        `--check passed with ${f.path} stamping 1.2.3 into every artifact it emits:\n${out}`,
      ).not.toBe(0);
      expect(out).toContain(f.path);
    });
  }
});
