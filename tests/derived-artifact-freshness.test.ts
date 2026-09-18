/**
 * Derived-artifact freshness orchestrator.
 *
 * Compiler goldens (`expected-script.hex`) have several children that CI used
 * to refresh by hand: analyzer reports, sdk-output input.json / locking hex,
 * source-map goldens, decompiler templates + coverage, script-size baseline.
 * A codegen change that moved bytes could leave those children internally
 * consistent with each other and every existing job green — while they no
 * longer described the compiler. This is the same class of hole
 * `sdk-output/generate-inputs.ts --check` closed for one corpus.
 *
 * The orchestrator is the single `--check` that covers every listed corpus.
 * These tests pin (1) the corpus list so a corpus cannot be dropped by
 * deleting a spawn line, and (2) the analyzer check's failure path, which is
 * the one corpus that had no `--check` at all.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  cpSync,
} from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ORCHESTRATOR = join(ROOT, 'conformance/scripts/check-derived-artifacts.ts');
const GENERATE_GOLDENS = join(
  ROOT,
  'conformance/analyzer/scripts/generate-goldens.ts',
);

const REQUIRED_CORPORA = [
  'analyzer',
  'sdk-output',
  'source-map',
  'decompiler-templates',
  'decompiler-coverage',
  'script-size',
] as const;

function run(script: string, args: string[], cwd: string = ROOT) {
  const r = spawnSync(process.execPath, ['--import', 'tsx', script, ...args], {
    cwd,
    encoding: 'utf8',
    env: process.env,
  });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

describe('derived-artifact --check orchestrator', () => {
  it('dry-run lists every corpus the freshness gate is required to cover', () => {
    const r = run(ORCHESTRATOR, ['--check', '--dry-run']);
    expect(r.status, r.out).toBe(0);
    for (const id of REQUIRED_CORPORA) {
      expect(r.out, `missing corpus ${id}`).toContain(id);
    }
  });

  it('rejects an unknown --only corpus instead of silently skipping it', () => {
    const r = run(ORCHESTRATOR, ['--check', '--only', 'not-a-corpus']);
    expect(r.status, r.out).not.toBe(0);
    expect(r.out).toMatch(/unknown corpus|not-a-corpus/i);
  });
});

describe('analyzer goldens --check', () => {
  it('exits 0 against the checked-in reports', () => {
    const r = run(GENERATE_GOLDENS, ['--check']);
    expect(r.status, r.out).toBe(0);
  }, 30_000);

  it('exits non-zero when a report lags the hex it is derived from', () => {
    const dir = mkdtempSync(join(tmpdir(), 'runar-analyzer-fresh-'));
    const name = 'basic-p2pkh';
    const hexSrc = join(ROOT, 'conformance/tests', name, 'expected-script.hex');
    const reportSrc = join(
      ROOT,
      'conformance/analyzer',
      name,
      'expected-analyzer-report.json',
    );
    const hexDst = join(dir, 'conformance/tests', name, 'expected-script.hex');
    const reportDst = join(
      dir,
      'conformance/analyzer',
      name,
      'expected-analyzer-report.json',
    );
    mkdirSync(dirname(hexDst), { recursive: true });
    mkdirSync(dirname(reportDst), { recursive: true });
    cpSync(hexSrc, hexDst);
    const report = JSON.parse(readFileSync(reportSrc, 'utf8')) as {
      scriptSize: number;
    };
    report.scriptSize = report.scriptSize + 1;
    writeFileSync(reportDst, JSON.stringify(report, null, 2) + '\n');

    const r = run(GENERATE_GOLDENS, [
      '--check',
      '--root',
      dir,
      '--fixtures',
      name,
    ]);
    expect(r.status, r.out).not.toBe(0);
    expect(r.out).toContain(name);
  }, 30_000);
});
