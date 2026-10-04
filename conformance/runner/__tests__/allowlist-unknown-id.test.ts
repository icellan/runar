import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  readFixtureCompilerAllowlist,
  runAllIrParityChecks,
  runConformanceTest,
  runConformanceTestForFormat,
  shutdownJavaDaemon,
} from '../runner.js';

// F-050 (CL-BUG-089): an unrecognised compiler id in a fixture's source.json
// `compilers` allowlist was cast straight to a Set<CompilerId>. A typo ("gp")
// matched no tier, so every tier was filtered out and the fixture compared
// nothing — the row was not a failure. The same happened for an empty list.
//
// What this proves: a scratch fixture whose allowlist names an unknown id, is
// empty, or holds a non-string entry is REJECTED, with an error naming the
// fixture and the bad value, by the reader and by all three runner modes that
// consume the allowlist (golden, multi-format, IR-parity); and every real
// fixture's source.json in conformance/tests still validates.
// What it does not prove: that an allowlist naming only real ids is the RIGHT
// set of tiers for its fixture — that is allowlist-audit.test.ts's job.

const __dirname = dirname(fileURLToPath(import.meta.url));
const REAL_TESTS_DIR = join(__dirname, '../../tests');
const DONOR = join(REAL_TESTS_DIR, 'basic-p2pkh');
const DONOR_SOURCE = resolve(__dirname, '../../../examples/ts/p2pkh/P2PKH.runar.ts');
const FIXTURE_NAME = 'typo-allowlist';

const sandboxes: string[] = [];
afterEach(() => {
  while (sandboxes.length > 0) rmSync(sandboxes.pop()!, { recursive: true, force: true });
});
afterAll(async () => {
  await shutdownJavaDaemon();
});

/** A scratch tests/ dir holding one fixture with the given `compilers` value. */
function makeFixture(compilers: unknown): { testsDir: string; fixtureDir: string } {
  const root = mkdtempSync(join(tmpdir(), 'runar-f050-'));
  sandboxes.push(root);
  const testsDir = join(root, 'tests');
  const fixtureDir = join(testsDir, FIXTURE_NAME);
  mkdirSync(fixtureDir, { recursive: true });
  copyFileSync(join(DONOR, 'expected-ir.json'), join(fixtureDir, 'expected-ir.json'));
  copyFileSync(join(DONOR, 'expected-script.hex'), join(fixtureDir, 'expected-script.hex'));
  writeFileSync(
    join(fixtureDir, 'source.json'),
    JSON.stringify({ sources: { '.runar.ts': DONOR_SOURCE }, compilers }, null, 2),
  );
  return { testsDir, fixtureDir };
}

const BAD_ALLOWLISTS: Array<[string, unknown, RegExp]> = [
  ['typo id', ['gp'], /typo-allowlist.*"gp"/s],
  ['renamed id beside a real one', ['go', 'golang'], /typo-allowlist.*"golang"/s],
  ['empty list', [], /typo-allowlist.*empty/s],
  ['non-string entry', ['go', 7], /typo-allowlist.*7/s],
];

describe('F-050: unknown compiler id in a fixture allowlist fails closed', () => {
  for (const [label, compilers, msg] of BAD_ALLOWLISTS) {
    it(`reader rejects: ${label}`, () => {
      const { fixtureDir } = makeFixture(compilers);
      expect(() => readFixtureCompilerAllowlist(fixtureDir)).toThrow(msg);
    });
  }

  it('golden mode (runConformanceTest) rejects a typo id', async () => {
    const { fixtureDir } = makeFixture(['gp']);
    await expect(runConformanceTest(fixtureDir)).rejects.toThrow(/typo-allowlist.*"gp"/s);
  }, 60_000);

  it('multi-format mode (runConformanceTestForFormat) rejects a typo id', async () => {
    const { fixtureDir } = makeFixture(['gp']);
    await expect(
      runConformanceTestForFormat(fixtureDir, { ext: '.runar.ts', sourceFile: DONOR_SOURCE }),
    ).rejects.toThrow(/typo-allowlist.*"gp"/s);
  }, 60_000);

  it('IR-parity mode (runAllIrParityChecks) rejects a typo id', async () => {
    const { testsDir } = makeFixture(['gp']);
    await expect(runAllIrParityChecks(testsDir)).rejects.toThrow(/typo-allowlist.*"gp"/s);
  }, 60_000);

  it('every real fixture source.json still validates', () => {
    const dirs = readdirSync(REAL_TESTS_DIR, { withFileTypes: true }).filter((d) => d.isDirectory());
    expect(dirs.length).toBeGreaterThan(0);
    for (const d of dirs) {
      expect(() => readFixtureCompilerAllowlist(join(REAL_TESTS_DIR, d.name)), d.name).not.toThrow();
    }
  });
});
