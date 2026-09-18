/**
 * R-166 (CL-BUG-147): the Rust tier ships an EMPTY source map.
 *
 * The finding blames the crypto/EC delegates — "bypass emit_op at fourteen
 * sites, so source_locs desynchronises". That is real and is half of it.
 * Measured, the tier emitted nothing for ANY contract, crypto or not:
 *
 *     contract with no crypto at all   contract calling ecMulGen
 *     go      2 mappings                60745
 *     ts      2                         60745
 *     python  3                         61261
 *     ruby    3                         61261
 *     rust    0                             0
 *
 * TWO INDEPENDENT CAUSES, both now fixed:
 *
 *  1. The CLI's `--source` route lands on the diagnostics-collecting compile
 *     path, which called the plain `optimize_stack_ops` and then blanked every
 *     location whenever the op count changed. The peephole almost always
 *     changes it — a two-line contract goes 8 ops to 3 — so the fallback fired
 *     on essentially every compile. The other Rust path already used the
 *     loc-preserving variant; one was fixed and the other was not.
 *
 *  2. The finding's own claim: fourteen delegate sites pushed straight onto
 *     `self.ops`, leaving `source_locs` short, so the loc-preserving variant
 *     blanked everything anyway. They now push through a helper that keeps both
 *     vectors in step.
 *
 * The assertion is deliberately a floor, not a count. Tiers legitimately differ
 * in granularity (go 2 where python 3 on the same contract), and pinning exact
 * numbers would turn ordinary codegen work into source-map churn. What must
 * hold is that no tier silently ships nothing.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findGoBinary,
  findRustBinary,
  findPythonBinary,
  findRubyBinary,
} from '../conformance/runner/runner.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const PLAIN = `import { SmartContract, assert } from 'runar-lang';

export class Plain extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint) {
    assert(x + 1n === this.limit);
  }
}
`;

/** Reaches the delegated EC codegen — cause 2's territory. */
const WITH_EC = `import { SmartContract, assert, ecMulGen, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

export class WithEc extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint) {
    const p: Point = ecMulGen(x);
    assert(ecPointX(p) === this.limit);
  }
}
`;

function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

interface Tier { id: string; binary: string | null; cwd: string }

const TIERS: Tier[] = [
  { id: 'go', binary: findGoBinary(), cwd: join(ROOT, 'compilers/go') },
  { id: 'rust', binary: findRustBinary(), cwd: join(ROOT, 'compilers/rust') },
  { id: 'python', binary: findPythonBinary(), cwd: join(ROOT, 'compilers/python') },
  { id: 'ruby', binary: findRubyBinary(), cwd: join(ROOT, 'compilers/ruby') },
];

const available = TIERS.filter((t) => t.binary !== null && existsSync(t.cwd));

function mappingCount(tier: Tier, name: string, src: string): number {
  const { cmd, args } = splitCmd(tier.binary);
  const dir = mkdtempSync(join(tmpdir(), `r166-${tier.id}-`));
  try {
    const file = join(dir, `${name}.runar.ts`);
    writeFileSync(file, src);
    const mapPath = join(dir, 'map.json');
    const res = spawnSync(
      cmd!,
      [...args, '--source', file, '--emit-source-map', mapPath, '--hex'],
      { cwd: tier.cwd, encoding: 'utf-8', timeout: 300_000, maxBuffer: 64 * 1024 * 1024 },
    );
    if (res.status !== 0) {
      throw new Error(`${tier.id} exited ${res.status}: ${(res.stderr || '').slice(0, 300)}`);
    }
    const parsed = JSON.parse(readFileSync(mapPath, 'utf-8')) as { mappings?: unknown[] };
    return (parsed.mappings ?? []).length;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('R-166: no tier ships an empty source map', () => {
  it('at least two tiers are built (a one-tier run proves nothing)', () => {
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  for (const tier of TIERS) {
    const maybe = available.includes(tier) ? it : it.skip;

    maybe(`${tier.id}: a contract with no crypto maps to its source`, () => {
      expect(
        mappingCount(tier, 'Plain', PLAIN),
        `${tier.id} emitted an empty source map for a contract with no delegated codegen in it`,
      ).toBeGreaterThan(0);
    }, 300_000);

    maybe(`${tier.id}: a contract reaching the EC delegates maps too`, () => {
      // Cause 2: the delegated modules emit through a callback, and an op
      // pushed without a location desynchronises the two vectors for the whole
      // method. An EC contract emits tens of thousands of ops, so "greater than
      // the plain contract" is the honest floor.
      const plain = mappingCount(tier, 'Plain', PLAIN);
      const ec = mappingCount(tier, 'WithEc', WITH_EC);
      expect(
        ec,
        `${tier.id} emitted an empty source map for a contract reaching delegated crypto codegen`,
      ).toBeGreaterThan(0);
      expect(
        ec,
        `${tier.id}: the EC contract should map more ops than the two-line one`,
      ).toBeGreaterThan(plain);
    }, 300_000);
  }
});
