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

/**
 * RubyGems normalizes a hyphenated prerelease to dot-pre-dot form
 * (`Gem::Version.new("1.0.0-rc.1").to_s == "1.0.0.pre.rc.1"`), so a Gemfile.lock
 * that bundler wrote never carries the raw "X.Y.Z-rc.N" spelling the rest of
 * this script compares against. Mirrors the derivation in
 * scripts/bump-version.sh (`sed -E 's/-/.pre./'`) — replace only the first
 * hyphen; a version with none is unchanged.
 */
function rubygemsSpelling(v: string): string {
  const i = v.indexOf('-');
  return i === -1 ? v : `${v.slice(0, i)}.pre.${v.slice(i + 1)}`;
}

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
  // N-080: the 4 Ruby Gemfile.lock files bump_version rewrites, read with the
  // RubyGems spelling (see rubygemsSpelling above) rather than the raw string.
  ...[
    'packages/runar-rb/Gemfile.lock',
    'integration/ruby/Gemfile.lock',
    'examples/ruby/Gemfile.lock',
    'examples/end2end-example/ruby/Gemfile.lock',
  ].map((p) => ({
    path: p,
    body: (v: string) =>
      `PATH\n  remote: .\n  specs:\n    runar-lang (${rubygemsSpelling(v)})\n\n` +
      `GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\n` +
      `DEPENDENCIES\n  runar-lang!\n\nBUNDLED WITH\n   2.6.2\n`,
  })),
  // N-080: hard-coded version expectations in the Go / Rust / Python compiler
  // test suites that bump_version rewrites via a blind `runar-v$OLD` -> `runar-v$NEW`
  // substitution, but `--check` never read.
  {
    path: 'compilers/go/compiler/compiler_test.go',
    body: (v) =>
      `if parsed["version"] != "runar-v${v}" {\n\tt.Errorf("expected version runar-v${v}, got %v", parsed["version"])\n}\n`,
  },
  {
    path: 'compilers/go/compiler/integration_test.go',
    body: (v) =>
      `if artifact.Version != "runar-v${v}" {\n\tt.Errorf("expected version runar-v${v}, got %s", artifact.Version)\n}\n`,
  },
  {
    path: 'compilers/rust/tests/compiler_tests.rs',
    body: (v) => `assert_eq!(artifact.version, "runar-v${v}");\n`,
  },
  {
    path: 'compilers/python/tests/test_compiler.py',
    body: (v) => `assert d["version"] == "runar-v${v}"\n`,
  },
  {
    // N-080: mirrors the real file's `__tests__/assembler.test.ts` shape —
    // an `artifact.version` assertion AND two DIFFERENT `artifact.compilerVersion`
    // assertions: one tracking the DEFAULT (must equal $expected) and one
    // pinned to a fixed override fixture ('1.2.3') that must NEVER be compared
    // against $expected, since it tests the explicit-override code path, not
    // version drift. A regex that cannot tell these two apart would either miss
    // real drift in the default or cry wolf on the override.
    path: 'packages/runar-compiler/src/__tests__/assembler.test.ts',
    body: (v) =>
      `describe('compiler version', () => {\n` +
      `  it('stamps artifact.version', () => {\n` +
      `    expect(artifact.version).toBe('runar-v${v}');\n` +
      `  });\n` +
      `  it('uses default compiler version', () => {\n` +
      `    expect(artifact.compilerVersion).toBe('${v}');\n` +
      `  });\n` +
      `  it('allows overriding compiler version', () => {\n` +
      `    expect(artifact.compilerVersion).toBe('1.2.3');\n` +
      `  });\n` +
      `});\n`,
  },
  // N-172 (R87 user decision, 2026-10-12): the Go/Zig SDK unit-test fixtures
  // that pin a "runar-v<version>" / "<version>" artifact into a test literal.
  // Unlike the files above, bump_version does NOT rewrite these (R87: they
  // are golden-like and move only through the golden-provenance gate) — but
  // --check must still read and flag them, or a real release bump leaves
  // them silently stamped with a version nothing ships anymore.
  {
    path: 'packages/runar-go/sdk_unsound_primitives_test.go',
    body: (v) =>
      `func unsoundArtifact() *RunarArtifact {\n` +
      `\treturn &RunarArtifact{\n` +
      `\t\tVersion:         "runar-v${v}",\n` +
      `\t\tCompilerVersion: "${v}-go",\n` +
      `\t}\n}\n`,
  },
  {
    path: 'packages/runar-go/sdk_codepart_length_pin_test.go',
    body: (v) =>
      'func pinFixtureArtifactJSON() string {\n\treturn `{\n' +
      `  "version": "runar-v${v}",\n` +
      `  "compilerVersion": "${v}",\n` +
      '  "contractName": "PinFixture"\n}`\n}\n',
  },
  {
    // sdk_contract.zig pins the same artifact JSON TWICE (pinFixtureArtifactJson
    // and the N-051 deploy-time constant), both as escaped-quote string
    // literals. The real file also embeds many UNRELATED dummy schema values
    // ("version":"1", not escaped-quote, no "runar-v" prefix) used only to
    // exercise the artifact-JSON parser — see the dedicated test below that
    // those are never flagged.
    path: 'packages/runar-zig/src/sdk_contract.zig',
    body: (v) =>
      `fn pinFixtureArtifactJson() []const u8 {\n` +
      `    return "{\\"contractName\\":\\"PinFixture\\",\\"version\\":\\"runar-v${v}\\",\\"compilerVersion\\":\\"${v}\\"}";\n` +
      `}\n` +
      `const pin_fixture_deploy_time_json =\n` +
      `    "{\\"contractName\\":\\"PinFixture\\",\\"version\\":\\"runar-v${v}\\",\\"compilerVersion\\":\\"${v}\\"}";\n`,
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
 * that hard-codes a version (the Gemfile.lock and compiler test-expectation
 * gap this comment used to describe is closed by N-080 below).
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

/**
 * N-080 (dispatcher baseline finding): `--check` did not read the 4 Ruby
 * Gemfile.lock files, or the hard-coded version expectations in
 * assembler.test.ts / compiler_test.go / integration_test.go /
 * compiler_tests.rs / test_compiler.py — all of which bump_version rewrites.
 * The fixtures above were added to GENERIC_FILES so the consistent-tree
 * controls and the RC-family drift sweep (F-085) already exercise them; this
 * block adds the cases that sweep doesn't cover: the RubyGems-spelling
 * wrinkle in Gemfile.lock, and the compilerVersion-override ambiguity in
 * assembler.test.ts.
 *
 * Proves: a Gemfile.lock spelled with the raw (non-RubyGems) "-rc.N" form is
 * flagged even though it names the textually "right" version; and a drifted
 * default-compiler-version assertion in assembler.test.ts is caught WITHOUT
 * the unrelated override fixture ('1.2.3') ever being flagged, in either
 * direction.
 * Does not prove: that every file bump_version rewrites is now read — only
 * the files named in this item's brief.
 */
describe('N-080: --check covers Gemfile.lock (RubyGems spelling) and test-expectation files', () => {
  const RC = '1.0.0-rc.1';

  it('passes when every Gemfile.lock already uses the RubyGems-normalized spelling (control)', () => {
    layDownConsistentRepo(RC);
    const { status, out } = runCheck();
    expect(status, `--check rejected a consistent tree:\n${out}`).toBe(0);
  });

  it('catches a Gemfile.lock spelled with the raw "-rc.N" form instead of RubyGems\' ".pre.rc.N"', () => {
    layDownConsistentRepo(RC);
    // This is the exact defect found in examples/ruby/Gemfile.lock and
    // examples/end2end-example/ruby/Gemfile.lock at HEAD: the same version,
    // spelled the way a human would type it rather than the way bundler
    // normalizes and writes it.
    put(
      'examples/ruby/Gemfile.lock',
      `PATH\n  remote: .\n  specs:\n    runar-lang (${RC})\n\nDEPENDENCIES\n  runar-lang!\n`,
    );
    const { status, out } = runCheck();
    expect(status, `--check accepted the raw "-rc.N" spelling:\n${out}`).not.toBe(0);
    expect(out).toContain('examples/ruby/Gemfile.lock');
  });

  it('catches real version drift in a Gemfile.lock (both canonically spelled)', () => {
    layDownConsistentRepo(RC);
    put(
      'integration/ruby/Gemfile.lock',
      `PATH\n  remote: .\n  specs:\n    runar-lang (${rubygemsSpelling('1.2.3')})\n\nDEPENDENCIES\n  runar-lang!\n`,
    );
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('integration/ruby/Gemfile.lock');
  });

  it('fails when a Gemfile.lock no longer names the gem at all', () => {
    layDownConsistentRepo(RC);
    put('packages/runar-rb/Gemfile.lock', 'PATH\n  remote: .\n  specs:\n\nDEPENDENCIES\n');
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-rb/Gemfile.lock');
  });

  for (const f of [
    'compilers/go/compiler/compiler_test.go',
    'compilers/go/compiler/integration_test.go',
    'compilers/rust/tests/compiler_tests.rs',
    'compilers/python/tests/test_compiler.py',
  ]) {
    it(`catches drift in the hard-coded version expectation (${f})`, () => {
      layDownConsistentRepo(RC);
      const drifted = GENERIC_FILES.find((g) => g.path === f)!;
      put(f, drifted.body('1.0.0-rc.2'));
      const { status, out } = runCheck();
      expect(status, `--check passed with ${f} stuck at the old version:\n${out}`).not.toBe(0);
      expect(out).toContain(f);
    });
  }

  it('catches drift in the assembler.test.ts default-compiler-version assertion', () => {
    layDownConsistentRepo(RC);
    put(
      'packages/runar-compiler/src/__tests__/assembler.test.ts',
      `describe('compiler version', () => {\n` +
        `  it('stamps artifact.version', () => {\n` +
        `    expect(artifact.version).toBe('runar-v${RC}');\n` +
        `  });\n` +
        `  it('uses default compiler version', () => {\n` +
        `    expect(artifact.compilerVersion).toBe('1.0.0-rc.2');\n` + // drifted
        `  });\n` +
        `  it('allows overriding compiler version', () => {\n` +
        `    expect(artifact.compilerVersion).toBe('1.2.3');\n` +
        `  });\n` +
        `});\n`,
    );
    const { status, out } = runCheck();
    expect(status, `--check passed with the default compiler version stuck at the old value:\n${out}`).not.toBe(0);
    expect(out).toContain('packages/runar-compiler/src/__tests__/assembler.test.ts');
  });

  it('catches drift in the assembler.test.ts artifact.version assertion', () => {
    layDownConsistentRepo(RC);
    put(
      'packages/runar-compiler/src/__tests__/assembler.test.ts',
      `describe('compiler version', () => {\n` +
        `  it('stamps artifact.version', () => {\n` +
        `    expect(artifact.version).toBe('runar-v1.0.0-rc.2');\n` + // drifted
        `  });\n` +
        `  it('uses default compiler version', () => {\n` +
        `    expect(artifact.compilerVersion).toBe('${RC}');\n` +
        `  });\n` +
        `  it('allows overriding compiler version', () => {\n` +
        `    expect(artifact.compilerVersion).toBe('1.2.3');\n` +
        `  });\n` +
        `});\n`,
    );
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-compiler/src/__tests__/assembler.test.ts');
  });

  it('never flags the compilerVersion override fixture (1.2.3), even though it never equals $expected', () => {
    layDownConsistentRepo(RC);
    // Everything is consistent EXCEPT that the override fixture ('1.2.3') is
    // (deliberately) never equal to RC. A check that cannot distinguish the
    // override assertion from the default one would fail this tree.
    const { status, out } = runCheck();
    expect(
      status,
      `--check flagged the compilerVersion override fixture as drift:\n${out}`,
    ).toBe(0);
    expect(out).not.toContain('1.2.3');
  });
});

/**
 * N-172 (dispatcher baseline finding; R87 user decision, 2026-10-12): the
 * live project version is also pinned, as a `"version": "runar-v<v>"` /
 * `"compilerVersion": "<v>"` artifact field, into:
 *
 *   - every conformance/sdk-vertical/cases/<row>/input.json (40 at HEAD)
 *   - every conformance/sdk-vertical/artifacts/<Contract>.json (3 at HEAD)
 *   - packages/runar-go/sdk_unsound_primitives_test.go and
 *     sdk_codepart_length_pin_test.go
 *   - packages/runar-zig/src/sdk_contract.zig (the PinFixture artifact JSON,
 *     twice)
 *
 * The brief asked a DESIGN question: should `bump_version` rewrite these, or
 * are they frozen placeholders? R87 answers: frozen — they are golden-like
 * fixtures that may only move through the golden-provenance gate, so
 * `bump_version` must NOT blind-rewrite them (unchanged by this item). But
 * `--check` must still read them and fail, by name, when they drift from the
 * live version — otherwise a real release bump leaves them silently stamped
 * with a version nothing ships anymore, with no gate to catch it.
 *
 * The sdk-vertical fixtures are directories of many files (not a single path
 * like the GENERIC_FILES family above), so they get their own lay-down
 * helper rather than reusing `layDownConsistentRepo`'s per-file loop.
 */
describe('N-172: --check flags stale pins in sdk-vertical fixtures and the Go/Zig SDK pin tests', () => {
  const CASE_DIRS = ['bigint-128', 'bool-true'];
  const ARTIFACT_NAMES = ['SlotMatrix', 'CodeSepMatrix'];

  function caseInputJson(v: string): string {
    return (
      JSON.stringify({ artifact: { version: `runar-v${v}`, compilerVersion: v, contractName: 'SlotMatrix' } }, null, 2) +
      '\n'
    );
  }

  function artifactJson(v: string, contractName: string): string {
    return JSON.stringify({ version: `runar-v${v}`, compilerVersion: v, contractName }, null, 2) + '\n';
  }

  /** Lays down the sdk-vertical fixture tree at `v`, on top of layDownConsistentRepo. */
  function layDownSdkVertical(v: string): void {
    for (const c of CASE_DIRS) {
      put(`conformance/sdk-vertical/cases/${c}/input.json`, caseInputJson(v));
    }
    for (const name of ARTIFACT_NAMES) {
      put(`conformance/sdk-vertical/artifacts/${name}.json`, artifactJson(v, name));
    }
  }

  function goZigFile(path: string): { path: string; body: (v: string) => string } {
    return GENERIC_FILES.find((g) => g.path === path)!;
  }

  it('passes when the sdk-vertical fixtures and Go/Zig pin tests are all current (control)', () => {
    layDownConsistentRepo();
    layDownSdkVertical(VERSION);
    const { status, out } = runCheck();
    expect(status, `--check rejected a consistent tree:\n${out}`).toBe(0);
    expect(out).toContain('All versions consistent');
  });

  for (const c of CASE_DIRS) {
    it(`catches drift in conformance/sdk-vertical/cases/${c}/input.json`, () => {
      layDownConsistentRepo();
      layDownSdkVertical(VERSION);
      put(`conformance/sdk-vertical/cases/${c}/input.json`, caseInputJson('1.2.3'));
      const { status, out } = runCheck();
      expect(
        status,
        `--check passed with cases/${c}/input.json stuck at 1.2.3 while everything else is ${VERSION}:\n${out}`,
      ).not.toBe(0);
      expect(out).toContain(`conformance/sdk-vertical/cases/${c}/input.json`);
    });
  }

  for (const name of ARTIFACT_NAMES) {
    it(`catches drift in conformance/sdk-vertical/artifacts/${name}.json`, () => {
      layDownConsistentRepo();
      layDownSdkVertical(VERSION);
      put(`conformance/sdk-vertical/artifacts/${name}.json`, artifactJson('1.2.3', name));
      const { status, out } = runCheck();
      expect(status, `--check passed with artifacts/${name}.json stuck at 1.2.3:\n${out}`).not.toBe(0);
      expect(out).toContain(`conformance/sdk-vertical/artifacts/${name}.json`);
    });
  }

  it('catches drift in packages/runar-go/sdk_unsound_primitives_test.go', () => {
    layDownConsistentRepo();
    layDownSdkVertical(VERSION);
    const f = goZigFile('packages/runar-go/sdk_unsound_primitives_test.go');
    put(f.path, f.body('1.2.3'));
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-go/sdk_unsound_primitives_test.go');
  });

  it('catches drift in packages/runar-go/sdk_codepart_length_pin_test.go', () => {
    layDownConsistentRepo();
    layDownSdkVertical(VERSION);
    const f = goZigFile('packages/runar-go/sdk_codepart_length_pin_test.go');
    put(f.path, f.body('1.2.3'));
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-go/sdk_codepart_length_pin_test.go');
  });

  it('catches drift in packages/runar-zig/src/sdk_contract.zig', () => {
    layDownConsistentRepo();
    layDownSdkVertical(VERSION);
    const f = goZigFile('packages/runar-zig/src/sdk_contract.zig');
    put(f.path, f.body('1.2.3'));
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-zig/src/sdk_contract.zig');
  });

  it('catches drift in only ONE of the two sdk_contract.zig pin occurrences', () => {
    // pinFixtureArtifactJson() is current; the deploy-time constant is not.
    // Both occurrences must be read, not just the first one sed happens to see.
    layDownConsistentRepo();
    layDownSdkVertical(VERSION);
    put(
      'packages/runar-zig/src/sdk_contract.zig',
      `fn pinFixtureArtifactJson() []const u8 {\n` +
        `    return "{\\"contractName\\":\\"PinFixture\\",\\"version\\":\\"runar-v${VERSION}\\",\\"compilerVersion\\":\\"${VERSION}\\"}";\n` +
        `}\n` +
        `const pin_fixture_deploy_time_json =\n` +
        `    "{\\"contractName\\":\\"PinFixture\\",\\"version\\":\\"runar-v1.2.3\\",\\"compilerVersion\\":\\"1.2.3\\"}";\n`,
    );
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain('packages/runar-zig/src/sdk_contract.zig');
  });

  it('does not flag the unrelated dummy schema versions ("1", "1.0") embedded in sdk_contract.zig', () => {
    // These are plain (non-escaped-quote) JSON used only to exercise the
    // artifact-JSON parser in unrelated tests. Neither "1" nor "1.0" can
    // match the "runar-v<semver>" shape the gate looks for, and they don't
    // use the PinFixture's escaped-quote style either.
    layDownConsistentRepo();
    layDownSdkVertical(VERSION);
    put(
      'packages/runar-zig/src/sdk_contract.zig',
      `fn pinFixtureArtifactJson() []const u8 {\n` +
        `    return "{\\"contractName\\":\\"PinFixture\\",\\"version\\":\\"runar-v${VERSION}\\",\\"compilerVersion\\":\\"${VERSION}\\"}";\n` +
        `}\n` +
        `const pin_fixture_deploy_time_json =\n` +
        `    "{\\"contractName\\":\\"PinFixture\\",\\"version\\":\\"runar-v${VERSION}\\",\\"compilerVersion\\":\\"${VERSION}\\"}";\n` +
        `test "unrelated dummy fixture" {\n` +
        `    const json =\n` +
        `        \\\\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"76a914"};\n` +
        `}\n`,
    );
    const { status, out } = runCheck();
    expect(status, `--check flagged an unrelated dummy schema version as drift:\n${out}`).toBe(0);
  });

  it('fails when a sdk-vertical input.json no longer carries a recognisable version', () => {
    layDownConsistentRepo();
    layDownSdkVertical(VERSION);
    put(
      `conformance/sdk-vertical/cases/${CASE_DIRS[0]}/input.json`,
      JSON.stringify({ artifact: { contractName: 'SlotMatrix' } }, null, 2) + '\n',
    );
    const { status, out } = runCheck();
    expect(status, out).not.toBe(0);
    expect(out).toContain(`conformance/sdk-vertical/cases/${CASE_DIRS[0]}/input.json`);
  });
});
