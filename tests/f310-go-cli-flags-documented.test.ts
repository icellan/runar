/**
 * F-310 (CL-DOC-004) — `compilers/go/README.md` fell behind the real CLI:
 * `--parse-only`, `--emit-ir-to`, `--disable-constant-folding`,
 * `--emit-source-map`, `--groth16-wa-vk` (F-305) and the entire `debug`
 * subcommand (`--script`, `--unlock`, `--artifact`, `--max-stack-bytes`) are
 * real flags in `compilers/go/main.go` / `compilers/go/debug.go` that never
 * appeared in the README. The README's "Conformance Testing" section also
 * documented `go test -v -run TestSourceCompile ./...` as *the* conformance
 * command, but that only runs the example-based `TestSourceCompile_*` tests
 * -- it never runs `TestConformanceGoldens` (`conformance_goldens_test.go`),
 * the test that actually byte-compares every `conformance/tests/*` fixture
 * against the checked-in `expected-script.hex` / `expected-ir.json`.
 * Separately, the `--modulo-threshold` help text and the README disagreed
 * about the default script size (stale "~718 KB" vs. the measured, correct
 * "~1.4 MB" -- the 718 KB figure was for a verifier variant that predates
 * the MSM public-input binding; see `groth16_wa_test.go`'s
 * `TestCompileGroth16WA_DefaultsToThreshold0`, which already carries the
 * correct number).
 *
 * This test pins, by building the real `runar-go` binary and reading its
 * own `--help` output (never a hand-copied flag list that could itself
 * drift):
 *   1. every top-level flag advertises in README.md,
 *   2. every `debug` subcommand flag is documented,
 *   3. every `groth16-wa` subcommand flag is documented (already true;
 *      kept here so a future flag addition is caught too),
 *   4. the stale "718 KB" figure is gone from both the `--help` text and
 *      the README,
 *   5. the README's conformance section names `TestConformanceGoldens`,
 *   6. the README names all 8 non-TypeScript source formats the Go
 *      frontend actually parses (`frontend/parser.go`'s format dispatch).
 *
 * What this test does NOT prove: that the prose *around* each flag is
 * well-written, that `pnpm run conformance:go` itself was changed (it
 * still runs `TestSourceCompile` -- a separate, pre-existing script this
 * DOC item does not touch), or that every Go doc comment in the compiler
 * is accurate. It only pins flag-name coverage, the specific stale-number
 * regression, and the two concrete sentences cited above.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const GO_DIR = join(REPO, 'compilers', 'go');

let tmpDir: string;
let binPath: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'f310-'));
  binPath = join(tmpDir, 'runar-go');
  const build = spawnSync('go', ['build', '-o', binPath, '.'], { cwd: GO_DIR, encoding: 'utf8' });
  expect(build.status, `go build failed:\n${build.stderr}`).toBe(0);
}, 120_000);

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

/** Parses `  -flagname ...` lines out of a Go `flag` package usage dump. */
function parseFlagNames(helpText: string): string[] {
  const names: string[] = [];
  const re = /^ {2}-([A-Za-z0-9][A-Za-z0-9_-]*)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(helpText))) {
    names.push(m[1]!);
  }
  return names;
}

function readmeText(): string {
  return readFileSync(join(GO_DIR, 'README.md'), 'utf-8');
}

/** True if README documents `--<flagName>` as a whole token, not merely as
 *  a substring of a longer flag (`--out` must not match inside `--output`,
 *  `--emit-ir` must not match inside `--emit-ir-to`). */
function readmeDocumentsFlag(flagName: string): boolean {
  const escaped = flagName.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
  const re = new RegExp('--' + escaped + '(?![\\w-])');
  return re.test(readmeText());
}

describe('F-310: compilers/go/README.md documents every real runar-go CLI flag', () => {
  it('runar-go --help parses a non-empty, sane flag set', () => {
    const result = spawnSync(binPath, ['--help'], { encoding: 'utf8' });
    const names = parseFlagNames(result.stderr);
    expect(names.length, `parsed zero flags from --help output:\n${result.stderr}`).toBeGreaterThan(0);
    // Sanity: these two must be present on this branch (F-305, F-220) or the
    // parse itself is broken, not just the docs.
    expect(names).toContain('parse-only');
    expect(names).toContain('groth16-wa-vk');
  });

  it('every top-level flag in `runar-go --help` is documented in README.md', () => {
    const result = spawnSync(binPath, ['--help'], { encoding: 'utf8' });
    const names = parseFlagNames(result.stderr);
    const undocumented = names.filter((n) => !readmeDocumentsFlag(n));
    expect(undocumented, `flags missing from README.md: ${undocumented.join(', ')}`).toEqual([]);
  });

  it('every `debug` subcommand flag in `runar-go debug --help` is documented in README.md', () => {
    const result = spawnSync(binPath, ['debug', '--help'], { encoding: 'utf8' });
    const names = parseFlagNames(result.stderr);
    expect(names.length, `parsed zero flags from debug --help output:\n${result.stderr}`).toBeGreaterThan(0);
    const undocumented = names.filter((n) => !readmeDocumentsFlag(n));
    expect(undocumented, `debug flags missing from README.md: ${undocumented.join(', ')}`).toEqual([]);
  });

  it('every `groth16-wa` subcommand flag in `runar-go groth16-wa --help` is documented in README.md', () => {
    const result = spawnSync(binPath, ['groth16-wa', '--help'], { encoding: 'utf8' });
    const names = parseFlagNames(result.stderr);
    expect(names.length, `parsed zero flags from groth16-wa --help output:\n${result.stderr}`).toBeGreaterThan(0);
    const undocumented = names.filter((n) => !readmeDocumentsFlag(n));
    expect(undocumented, `groth16-wa flags missing from README.md: ${undocumented.join(', ')}`).toEqual([]);
  });

  it('the groth16-wa default script-size figure is not the stale "718 KB" number, in --help or README', () => {
    const result = spawnSync(binPath, ['groth16-wa', '--help'], { encoding: 'utf8' });
    expect(result.stderr, '--help text still claims the stale 718 KB figure').not.toMatch(/718 ?KB/i);
    expect(readmeText(), 'README still claims the stale 718 KB figure').not.toMatch(/718 ?KB/i);
  });

  it('the documented conformance command covers the byte-exact golden test (TestConformanceGoldens), not only TestSourceCompile', () => {
    expect(readmeText()).toMatch(/TestConformanceGoldens/);
  });

  it('documents all 8 non-TypeScript source formats the Go frontend parses', () => {
    const text = readmeText();
    for (const ext of ['sol', 'move', 'go', 'py', 'rs', 'zig', 'rb', 'java']) {
      expect(text, `README does not mention .runar.${ext}`).toMatch(new RegExp('\\.runar\\.' + ext + '\\b'));
    }
  });
});
