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

/**
 * F-085: the Java / gradle / README / fixture / ordinals family that the old
 * `0\.N\.M` substring sweep was the only check for. Each body mirrors the line
 * shape `bump_version` rewrites in the real file.
 */
const GENERIC_FILES: Array<{ path: string; body: (v: string) => string }> = [
  {
    path: 'compilers/java/src/main/java/runar/compiler/Version.java',
    body: (v) => `public final class Version {\n    public static final String VALUE = "${v}";\n}\n`,
  },
  { path: 'compilers/java/build.gradle.kts', body: (v) => `group = "build.runar"\nversion = "${v}"\n` },
  {
    path: 'packages/runar-java/build.gradle.kts',
    body: (v) =>
      `version = "${v}"\ndependencies {\n    implementation("build.runar:runar-java-compiler:${v}")\n}\n`,
  },
  ...[
    'examples/java',
    'examples/end2end-example/java',
    'integration/java',
    'conformance/anf-interpreter/drivers/java',
    'conformance/sdk-output/tools/java-driver',
  ].map((d) => ({
    path: `${d}/build.gradle.kts`,
    body: (v: string) =>
      `version = "${v}"\ndependencies {\n    implementation("build.runar:runar-java:${v}")\n}\n`,
  })),
  {
    path: 'packages/runar-java/README.md',
    body: (v) =>
      `published as \`build.runar:runar-java\`.\n` +
      `    implementation("build.runar:runar-java:${v}")\n` +
      `    implementation 'build.runar:runar-java:${v}'\n` +
      `    <version>${v}</version>\n`,
  },
  {
    path: 'packages/runar-java/src/test/resources/artifacts/stateful-counter.runar.json',
    body: (v) => `{\n  "version": "runar-v${v}",\n  "compilerVersion": "${v}",\n  "contractName": "Counter"\n}\n`,
  },
  {
    path: 'conformance/sdk-output/tests/stateful-counter/input.json',
    body: (v) => `{\n  "artifact": {\n    "version": "runar-v${v}",\n    "compilerVersion": "${v}"\n  }\n}\n`,
  },
  {
    path: 'conformance/sdk-output/runner/sdk-runner.ts',
    body: (v) => `const javaJar = join(javaToolDir, 'build', 'libs', 'java-sdk-driver-${v}-all.jar');\n`,
  },
  {
    path: 'packages/runar-sdk/src/__tests__/ordinals-contract.test.ts',
    // `version: 'runar-v0.1.0'` is a hand-written fixture field bump never
    // touches; it must not be compared.
    body: (v) => `const a = {\n  version: 'runar-v0.1.0',\n  compilerVersion: '${v}',\n};\n`,
  },
  {
    path: 'packages/runar-py/tests/test_ordinals.py',
    body: (v) => `a = RunarArtifact(\n    version='runar-v0.1.0',\n    compiler_version='${v}',\n)\n`,
  },
  {
    path: 'packages/runar-rb/spec/sdk/ordinals_spec.rb',
    body: (v) => `a = {\n  'version'          => 'runar-v0.1.0',\n  'compilerVersion'  => '${v}',\n}\n`,
  },
  {
    path: 'packages/runar-zig/README.md',
    // `.version = "0.1.0"` is the CONSUMER's manifest in the example, not ours.
    body: (v) =>
      `.{\n    .version = "0.1.0",\n` +
      `            .url = "https://github.com/icellan/runar/archive/refs/tags/runar-zig-v${v}.tar.gz",\n}\n` +
      `This SDK is at **v${v}** (see [build.zig.zon](build.zig.zon)).\n`,
  },
];

let repo: string;

/** Write one file into the throwaway repo, creating parents. */
function put(rel: string, content: string): void {
  const abs = join(repo, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content);
}

/** Lay down a fully consistent tree at `v` (default VERSION), from empty. */
function layDownConsistentRepo(v: string = VERSION): void {
  rmSync(repo, { recursive: true, force: true });
  mkdirSync(join(repo, 'scripts'), { recursive: true });
  copyFileSync(SCRIPT, join(repo, 'scripts/bump-version.sh'));

  put('package.json', JSON.stringify({ name: 'runar', version: v }, null, 2) + '\n');
  for (const p of [
    'packages/runar-lang',
    'packages/runar-compiler',
    'packages/runar-ir-schema',
    'packages/runar-testing',
    'packages/runar-sdk',
    'packages/runar-cli',
    'packages/decompiler',
  ]) {
    put(`${p}/package.json`, JSON.stringify({ version: v }, null, 2) + '\n');
  }
  for (const p of ['compilers/rust', 'packages/runar-rs', 'packages/runar-rs-macros']) {
    put(`${p}/Cargo.toml`, `[package]\nversion = "${v}"\n`);
  }
  put(
    'packages/runar-rs/Cargo.toml',
    `[package]\nversion = "${v}"\n\n[dependencies]\n` +
      `runar-lang-macros = { version = "${v}" }\n` +
      `runar-compiler-rust = { version = "${v}" }\n`,
  );
  for (const p of ['packages/runar-py', 'compilers/python']) {
    put(`${p}/pyproject.toml`, `[project]\nversion = "${v}"\n`);
  }
  for (const f of COMPILER_VERSION_FILES) put(f.path, f.body(v));
  for (const m of MANIFESTS) put(m.path, m.body(v));
  for (const g of GENERIC_FILES) put(g.path, g.body(v));
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

/**
 * F-085 (CL-BUG-238): the generic sweep over the Java / gradle / README /
 * fixture / ordinals files filtered every line through `0\.[0-9]+\.[0-9]+`, so
 * it only ever saw drift that happened to contain a `0.N.M` substring. In the
 * current `1.0.0-rc.1` family, `1.0.1` and `2.0.0` were invisible; and the
 * `grep -v "$expected"` substring test hid `1.0.0-rc.10`. The embedded
 * compiler-version token regex could not parse an rc version followed by a
 * `-<tier>` suffix, and never read the TS DEFAULT_COMPILER_VERSION at all.
 *
 * Proves: for every file family --check reads, a single drifted value in the
 * current version family fails the gate and names the file; a file where no
 * version string can be found fails it too (a rename cannot silently exit the
 * gate).
 * Does not prove: that the file list itself is complete against every file
 * that hard-codes a version (Gemfile.lock and the compiler test expectations
 * that bump rewrites are still not read by --check).
 */
describe('F-085: --check compares every versioned file exactly, in the rc family', () => {
  const RC = '1.0.0-rc.1';

  it('passes on a consistent rc tree (control)', () => {
    layDownConsistentRepo(RC);
    const { status, out } = runCheck();
    expect(status, `--check rejected a consistent tree:\n${out}`).toBe(0);
    expect(out).toContain('All versions consistent');
  });

  // The families that were already compared exactly (package.json, Cargo.toml,
  // pyproject, Zig manifest, gemspec), held to the same rc-family drift.
  const EXACT_FAMILIES: Array<{ path: string; body: (v: string) => string }> = [
    { path: 'packages/runar-cli/package.json', body: (v) => JSON.stringify({ version: v }, null, 2) + '\n' },
    { path: 'compilers/rust/Cargo.toml', body: (v) => `[package]\nversion = "${v}"\n` },
    { path: 'compilers/python/pyproject.toml', body: (v) => `[project]\nversion = "${v}"\n` },
    ...MANIFESTS,
  ];

  for (const g of [...GENERIC_FILES, ...EXACT_FAMILIES]) {
    for (const drift of ['1.0.1', '2.0.0', '1.0.0-rc.10']) {
      it(`catches ${drift} in ${g.path}`, () => {
        layDownConsistentRepo(RC);
        put(g.path, g.body(drift));
        const { status, out } = runCheck();
        expect(status, `--check passed with ${g.path} at ${drift} while expected is ${RC}:\n${out}`).not.toBe(0);
        expect(out).toContain(g.path);
      });
    }
  }

  it('catches rc-family drift in a Rust inter-crate dependency', () => {
    layDownConsistentRepo(RC);
    put(
      'packages/runar-rs/Cargo.toml',
      `[package]\nversion = "${RC}"\n\n[dependencies]\n` +
        `runar-lang-macros = { version = "${RC}" }\n` +
        `runar-compiler-rust = { version = "1.0.0-rc.10" }\n`,
    );
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-rs/Cargo.toml');
  });

  it('catches a single drifted line in a file that is otherwise current', () => {
    layDownConsistentRepo(RC);
    put(
      'packages/runar-java/README.md',
      `    implementation("build.runar:runar-java:${RC}")\n    <version>1.0.1</version>\n`,
    );
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-java/README.md');
  });

  it('fails when a versioned file no longer carries a recognisable version', () => {
    layDownConsistentRepo(RC);
    put(
      'compilers/java/src/main/java/runar/compiler/Version.java',
      `public final class Version {\n    public static final String CURRENT = "${RC}";\n}\n`,
    );
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('compilers/java/src/main/java/runar/compiler/Version.java');
  });

  for (const f of COMPILER_VERSION_FILES) {
    it(`catches rc-family drift in the embedded compiler version (${f.path})`, () => {
      layDownConsistentRepo(RC);
      put(f.path, f.body('1.0.0-rc.2'));
      const { status, out } = runCheck();
      expect(status, out).not.toBe(0);
      expect(out).toContain(f.path);
    });
  }

  it('catches drift in the tier-suffixed compilerVersion alone (schemaVersion still current)', () => {
    layDownConsistentRepo(RC);
    put('compilers/go/compiler/compiler.go', `const (\n\tschemaVersion   = "runar-v${RC}"\n\tcompilerVersion = "1.0.0-rc.2-go"\n)\n`);
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('compilers/go/compiler/compiler.go');
  });

  it('catches drift in the TS DEFAULT_COMPILER_VERSION alone', () => {
    layDownConsistentRepo(RC);
    put(
      'packages/runar-compiler/src/artifact/assembler.ts',
      `const ARTIFACT_VERSION = 'runar-v${RC}';\nconst DEFAULT_COMPILER_VERSION = '1.0.1';\n`,
    );
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-compiler/src/artifact/assembler.ts');
  });
});
