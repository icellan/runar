/**
 * N-003 — `--anf --fold-on` was a no-op.
 *
 * The mode sent every program through each tier's `--ir` entry point, and all
 * seven tiers deliberately force constant folding OFF on IR input (so the IR
 * path stays byte-identical to the fold-OFF goldens). Dropping
 * `--disable-constant-folding` from that argv therefore changed nothing: the
 * "fold-ON" PR gate re-ran fold-OFF byte for byte, while the help text said it
 * ran "every tier with constant-folding ENABLED".
 *
 * The mode now renders each generated ANF program to `.runar.ts` and compiles
 * it from SOURCE in every tier with folding on (each CLI's default). These
 * tests pin that the bytes the mode compares are folded bytes.
 *
 * PROVES:
 *   - for a pinned program with a foldable constant subexpression
 *     (`p0 === 7n / 2n`), the source the mode renders compiles to DIFFERENT
 *     bytes with folding on than with folding off, in the real TS compiler;
 *   - the real harness (real generator, real in-process TS tier, no seam), run
 *     in fold-on mode at the CI seed, reports a non-zero count of programs
 *     whose compared bytes changed under folding — and reports that count as
 *     0 when run fold-OFF, so the counter is not a constant;
 *   - the CLI help text and the nightly workflow no longer claim the old
 *     behaviour.
 * DOES NOT PROVE: anything about the six native tiers (no binary runs here;
 * their fold-on agreement is what the CI gate itself checks), that the folded
 * bytes are correct (this is a parity harness, not an execution oracle), or
 * that the rendered corpus reaches every fold rule.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { compile } from 'runar-compiler';
import {
  renderAnfProgramToTypeScript,
  runAnfDifferential,
} from '../anf-differential.js';

const REPO = resolve(__dirname, '../../..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

// `p0 === 7n / 2n` — the division of two constants is what folds.
const FOLDABLE = {
  contractName: 'FuzzAnf',
  properties: [],
  methods: [
    {
      name: 'verify',
      params: [{ name: 'p0', type: 'bigint' }],
      isPublic: true,
      body: [
        { name: 't0', value: { kind: 'load_const', value: 7n } },
        { name: 't1', value: { kind: 'load_const', value: 2n } },
        { name: 't2', value: { kind: 'bin_op', op: '/', left: 't0', right: 't1' } },
        { name: 't3', value: { kind: 'load_param', name: 'p0' } },
        { name: 't4', value: { kind: 'bin_op', op: '===', left: 't3', right: 't2' } },
        { name: 't5', value: { kind: 'assert', value: 't4' } },
      ],
    },
  ],
};

function tsHex(source: string, disableConstantFolding: boolean): string {
  const r = compile(source, { fileName: 'FuzzAnf.runar.ts', disableConstantFolding });
  expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
  return r.artifact!.script;
}

describe('N-003: --anf --fold-on compiles folded bytes', () => {
  it('the rendered source of a foldable program compiles differently with folding on', () => {
    const source = renderAnfProgramToTypeScript(FOLDABLE as never);
    expect(tsHex(source, false)).not.toBe(tsHex(source, true));
  });

  it('the real harness counts folded programs in fold-on mode, and none in fold-off', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'anf-n003-'));
    const run = (disableConstantFolding: boolean) =>
      runAnfDifferential({
        numPrograms: 10,
        seed: 424242,
        tiers: ['ts'],
        disableConstantFolding,
        findingsDir: dir,
      });
    try {
      const on = await run(false);
      expect(on.foldedPrograms).toBeGreaterThan(0);
      expect(on.mismatchCount).toBe(0);
      const off = await run(true);
      expect(off.foldedPrograms).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it('the help text and the nightly workflow describe what the mode does', () => {
    const index = read('conformance/fuzzer/index.ts');
    expect(index).not.toContain('ENABLED (omit --disable-constant-folding)');
    expect(index).toMatch(/--fold-on[\s\S]{0,400}--source/);
    const yml = read('.github/workflows/fuzzer-nightly.yml');
    expect(yml).not.toMatch(/fold-ON\s*(#\s*-*\s*)?`--ir`\s*(#\s*-*\s*)?output is byte-identical/);
  });
});
