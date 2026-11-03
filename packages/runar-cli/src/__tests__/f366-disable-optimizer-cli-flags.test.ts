/**
 * F-366 (CL-GAP-003): `disableEcOptimizer` / `disablePeephole` exist on the
 * compiler API's `CompileOptions` (packages/runar-compiler/src/index.ts) and
 * are read by `compile()`, but the `runar-cli compile` command only exposes
 * `--disable-constant-folding` (packages/runar-cli/src/bin.ts). The other two
 * optimizer switches are unreachable from the CLI: there is no
 * `--disable-peephole` or `--disable-ec-optimizer` option anywhere in
 * bin.ts/commands/compile.ts, so a user (or a bisection script trying to
 * localize a cross-tier byte divergence, same motivation as R-260's Go fix)
 * has no command-line way to turn either optimizer off.
 *
 * This test drives the REAL CLI binary (bin.ts, via spawnSync) rather than
 * calling compileCommand() directly, because the gap is in the commander
 * option registration itself — passing `disablePeephole` straight to
 * compileCommand() would bypass the exact thing that's missing.
 *
 * Pre-fix: commander has no such registered option, so both flags are
 * rejected with "unknown option" and a non-zero exit — the CLI cannot even
 * run the compile, let alone change its output.
 * Post-fix: both flags are accepted, exit 0, and produce DIFFERENT script
 * hex than the default (fully-optimized) compile — proving the flag actually
 * reaches the compiler, not just that it's silently swallowed.
 *
 * What this test proves: the TS CLI's --disable-peephole and
 * --disable-ec-optimizer flags are registered, parsed, and threaded through
 * to compile()'s CompileOptions, and each one measurably changes the emitted
 * bytes for a source chosen to exercise exactly that optimizer.
 * What it does NOT prove: that --disable-constant-folding, --disable-peephole
 * and --disable-ec-optimizer compose correctly in combination, or that any
 * other CLI (Go/Rust/...) exposes equivalent flags — this item is scoped to
 * the TS tier only (checked: Go's and Rust's CLIs also only expose
 * --disable-constant-folding, so this does not newly diverge TS from them).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../../..');
const CLI = join(ROOT, 'packages/runar-cli/src/bin.ts');

function loader(): string | null {
  for (const p of [
    join(ROOT, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(ROOT, 'node_modules/tsx/dist/loader.mjs'),
  ]) {
    if (existsSync(p)) return pathToFileURL(p).href;
  }
  return null;
}

function run(args: string[]): { status: number | null; out: string; err: string } {
  const l = loader();
  if (l === null) throw new Error('no tsx loader');
  const res = spawnSync(process.execPath, ['--import', l, CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf-8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { status: res.status, out: res.stdout ?? '', err: res.stderr ?? '' };
}

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'f366-'));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

// `x !== 0n` lowers to PUSH 0; OP_NUMEQUAL; OP_NOT, which the Stack-IR
// peephole pass rewrites. Chosen (same source as c17-not-composition.test.ts)
// because peephole ON vs OFF is known to change the emitted bytes while
// preserving the asserted outcome.
const PEEPHOLE_SOURCE = `
import { SmartContract, assert } from 'runar-lang';

export class NotComposition extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint): void {
    const nonZero: boolean = x !== 0n;
    assert(nonZero === true);
  }
}
`;

// `ecMul(p, 1n)` is an algebraic identity the ANF EC optimizer rewrites to
// `p` (removing a 256-iteration double-and-add loop). Chosen (same shape as
// Go's r260_optimizer_switches_test.go) because EC-optimizer ON vs OFF is
// known to change the emitted bytes by orders of magnitude.
const EC_SOURCE = `
import { SmartContract, assert, ecMul, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

export class F366EC extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }
  public unlock(expected: bigint) {
    const p2 = ecMul(this.pt, 1n);
    assert(ecPointX(p2) === expected);
  }
}
`;

describe('F-366: compile --disable-peephole / --disable-ec-optimizer CLI flags', () => {
  it('the CLI runs at all (without this the checks below prove nothing)', () => {
    const { out } = run(['--help']);
    expect(out).toMatch(/compile/);
  });

  it('--disable-peephole is accepted and changes the emitted script hex', () => {
    const src = join(dir, 'NotComposition.runar.ts');
    writeFileSync(src, PEEPHOLE_SOURCE);

    const baseline = run(['compile', src, '--hex']);
    expect(baseline.status, `baseline compile failed:\n${baseline.err}`).toBe(0);
    const baselineHex = baseline.out.trim();
    expect(baselineHex.length).toBeGreaterThan(0);

    const off = run(['compile', src, '--hex', '--disable-peephole']);
    expect(
      off.status,
      `--disable-peephole was rejected by the CLI (unknown option), proving ` +
        `the gap:\n${off.err}`,
    ).toBe(0);
    const offHex = off.out.trim();
    expect(offHex.length).toBeGreaterThan(0);

    expect(
      offHex,
      '--disable-peephole had no observable effect on the emitted bytes',
    ).not.toBe(baselineHex);
  }, 60_000);

  it('--disable-ec-optimizer is accepted and changes the emitted script hex', () => {
    const src = join(dir, 'F366EC.runar.ts');
    writeFileSync(src, EC_SOURCE);

    const baseline = run(['compile', src, '--hex']);
    expect(baseline.status, `baseline compile failed:\n${baseline.err}`).toBe(0);
    const baselineHex = baseline.out.trim();
    expect(baselineHex.length).toBeGreaterThan(0);

    const off = run(['compile', src, '--hex', '--disable-ec-optimizer']);
    expect(
      off.status,
      `--disable-ec-optimizer was rejected by the CLI (unknown option), ` +
        `proving the gap:\n${off.err}`,
    ).toBe(0);
    const offHex = off.out.trim();
    expect(offHex.length).toBeGreaterThan(0);

    expect(
      offHex,
      '--disable-ec-optimizer had no observable effect on the emitted bytes',
    ).not.toBe(baselineHex);
  }, 60_000);
});
