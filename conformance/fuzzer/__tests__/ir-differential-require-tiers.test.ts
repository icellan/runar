/**
 * A tier that failed on EVERY program must fail the run, not be written off as
 * uninstalled.
 *
 * `ir-differential.ts` tracked `everProduced` — tiers seen to emit output at
 * least once — to tell "this compiler is not installed" from "this compiler
 * rejected THIS program", and filtered the never-seen ones out of the
 * divergence report. A tier whose binary is present but which rejects or
 * crashes on all N generated programs therefore never entered the set, was
 * filtered out of every per-program report, left `match` true, and the run
 * printed `N programs, 0 mismatches` and exited 0. That is the PR gate
 * (`fuzz:ir:gate`, `--num 40`, seven tiers).
 *
 * `everProduced` was also consulted DURING the loop, so it was a prefix set:
 * a tier that rejected program 0 and accepted program 1 was not flagged on
 * program 0, because at that point nothing had proved it was installed.
 *
 * `canonical-json-differential.ts` already fixed exactly this with
 * `requireTiers` ("a gate meant to establish SEVEN-tier parity reporting
 * success having established six"). This pins the propagation: the same
 * requirement, the same default (every requested tier), and the classification
 * done once at the END of the run against the complete set.
 */
import { describe, it, expect } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  classifyIRRun,
  runIRDifferentialFuzzing,
  type CompilerName,
} from '../ir-differential.js';

const SEVEN: CompilerName[] = ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'];

/** One program in which `ok` produced output and `bad` did not. */
const prog = (ok: CompilerName[], bad: CompilerName[]) => ({ received: ok, failed: bad });

describe('ir-differential: a tier that produced nothing all run is a failure', () => {
  it('flags a requested tier that failed on every program', () => {
    // java is installed enough to be requested, and rejects all three.
    const others = SEVEN.filter((c) => c !== 'java');
    const r = classifyIRRun({
      programs: [prog(others, ['java']), prog(others, ['java']), prog(others, ['java'])],
      compilers: SEVEN,
      requireTiers: SEVEN,
    });

    expect(r.everProduced).not.toContain('java');
    expect(r.missingRequiredTiers).toEqual(['java']);
  });

  it('CONTROL: a healthy seven-tier run is not reddened', () => {
    const r = classifyIRRun({
      programs: [prog(SEVEN, []), prog(SEVEN, []), prog(SEVEN, [])],
      compilers: SEVEN,
      requireTiers: SEVEN,
    });

    expect(r.missingRequiredTiers).toEqual([]);
    expect(r.perProgram.every((p) => p.match)).toBe(true);
    expect(r.everProduced.slice().sort()).toEqual(SEVEN.slice().sort());
  });

  it('CONTROL: a tier that rejects SOME programs is a per-program divergence, not a missing tier', () => {
    const others = SEVEN.filter((c) => c !== 'zig');
    const r = classifyIRRun({
      programs: [prog(others, ['zig']), prog(SEVEN, [])],
      compilers: SEVEN,
      requireTiers: SEVEN,
    });

    expect(r.missingRequiredTiers).toEqual([]);
    expect(r.perProgram[0]!.match).toBe(false);
    expect(r.perProgram[0]!.details).toContain('zig');
    expect(r.perProgram[1]!.match).toBe(true);
  });

  it('classifies against the FINAL everProduced set, not a prefix of it', () => {
    // ruby rejects program 0 and accepts program 1. Consulting the set while
    // the loop is still running lets program 0 pass, because at that instant
    // nothing had yet proved ruby was installed.
    const others = SEVEN.filter((c) => c !== 'ruby');
    const r = classifyIRRun({
      programs: [prog(others, ['ruby']), prog(SEVEN, [])],
      compilers: SEVEN,
      requireTiers: SEVEN,
    });

    expect(r.perProgram[0]!.match, 'the first program is where ruby diverged').toBe(false);
    expect(r.perProgram[0]!.details).toContain('ruby');
  });

  it('a program only ONE tier compiled is not a comparison', () => {
    // `received.length >= 2` was the compare precondition, so a program with a
    // single survivor produced no comparison and still reported match = true.
    const r = classifyIRRun({
      programs: [prog(['ts'], SEVEN.filter((c) => c !== 'ts'))],
      compilers: SEVEN,
      requireTiers: SEVEN,
    });

    expect(r.noComparisonCount).toBe(1);
    expect(r.perProgram[0]!.match).toBe(false);
  });

  it('CONTROL: a program EVERY tier rejected is reported, not failed', () => {
    // Tier agreement genuinely holds here — this is the documented
    // `allRejectedCount` case and must stay out of the mismatch count.
    const r = classifyIRRun({
      programs: [prog(SEVEN, []), prog([], SEVEN)],
      compilers: SEVEN,
      requireTiers: SEVEN,
    });

    expect(r.allRejectedCount).toBe(1);
    expect(r.perProgram[1]!.match).toBe(true);
    expect(r.missingRequiredTiers).toEqual([]);
  });

  it('a tier required but never REQUESTED is missing too', () => {
    // Otherwise `--compilers ts,go --require-tiers all` claims seven-tier
    // parity from a two-tier run.
    const r = classifyIRRun({
      programs: [prog(['ts', 'go'], [])],
      compilers: ['ts', 'go'],
      requireTiers: SEVEN,
    });
    expect(r.missingRequiredTiers.slice().sort()).toEqual(
      SEVEN.filter((c) => c !== 'ts' && c !== 'go').sort(),
    );
  });

  it('the run report carries the tier requirement out to the caller', async () => {
    // End-to-end through the real driver, TS-only so it needs no native
    // toolchain: two programs, and a requirement the run cannot meet.
    const report = await runIRDifferentialFuzzing(2, {
      seed: 424242,
      compilers: ['ts'],
      requireTiers: ['ts', 'go'],
      findingsDir: join(tmpdir(), 'runar-ir-req-tiers'),
    });

    expect(report.results.length).toBe(2);
    expect(report.everProduced).toContain('ts');
    expect(report.missingRequiredTiers).toEqual(['go']);
  }, 120_000);

  it('CONTROL: the same run with an honest requirement is clean', async () => {
    const report = await runIRDifferentialFuzzing(2, {
      seed: 424242,
      compilers: ['ts'],
      requireTiers: ['ts'],
      findingsDir: join(tmpdir(), 'runar-ir-req-tiers'),
    });

    expect(report.missingRequiredTiers).toEqual([]);
    expect(report.mismatchCount).toBe(0);
  }, 120_000);
});
