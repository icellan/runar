/**
 * R-212 (CL-GAP-052): SOURCE_DATE_EPOCH was honoured in one function in one
 * tier. Six compilers stamped the wall clock into `buildTimestamp`, so six of
 * seven artifacts were not byte-reproducible across builds.
 *
 * Reproducible builds are the mechanism by which someone other than the author
 * can check that a published locking script really is what the published source
 * compiles to. A field that changes every second defeats `diff`, which is the
 * whole instrument — and the script bytes being identical does not help when
 * the artifact file is what gets published and compared.
 *
 * SOURCE_DATE_EPOCH is the cross-ecosystem standard for this
 * (https://reproducible-builds.org/specs/source-date-epoch/): when set to a Unix
 * seconds value, a build uses that instant instead of the clock.
 *
 * This test drives each tier's real CLI twice with the variable pinned and
 * requires the two artifacts to be byte-identical, and separately requires the
 * stamped instant to be the pinned one. Each tier keeps its own timestamp
 * FORMAT — the field is not compared across tiers, and changing a tier's
 * spelling would move its own goldens for no reason.
 *
 * The Zig tier is absent deliberately: its `Artifact.build_timestamp` is written
 * by `ir/json.zig` but never filled from a clock anywhere in the tier, so there
 * is nothing to pin. If a Zig CLI ever emits an artifact JSON, it inherits the
 * requirement through the shared list below.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pathToFileURL } from 'node:url';
import {
  findGoBinary,
  findJavaJarPath,
  findPythonBinary,
  findRubyBinary,
  findRustBinary,
} from '../conformance/runner/runner.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** 2023-11-14T22:13:20Z — a fixed instant, far from any test clock. */
const EPOCH = '1700000000';
const EPOCH_SECONDS = 1700000000;

const SOURCE = `
import { SmartContract, assert } from 'runar-lang';

class EpochProbe extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint) {
    assert(x === this.limit);
  }
}
`;

function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

function tsxLoader(): string | null {
  for (const p of [
    join(ROOT, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(ROOT, 'node_modules/tsx/dist/loader.mjs'),
  ]) {
    if (existsSync(p)) return pathToFileURL(p).href;
  }
  return null;
}

interface Tier {
  id: string;
  cmd: string | null;
  /**
   * argv that writes an artifact JSON for `src`. Each CLI spells this
   * differently — a file path for the native tiers, a directory for the TS CLI,
   * `--emit-artifact` for Java — so the tier says where its artifact lands.
   */
  argsFor: (src: string, out: string) => string[];
  /** Where the artifact ends up, given the `out` handed to argsFor. */
  artifactAt: (out: string) => string;
  /** `out` is a directory for this tier rather than a file path. */
  outIsDir?: boolean;
  cwd: string;
}

function buildTiers(): Tier[] {
  const go = splitCmd(findGoBinary());
  const rust = splitCmd(findRustBinary());
  const python = splitCmd(findPythonBinary());
  const ruby = splitCmd(findRubyBinary());
  const jar = findJavaJarPath();
  const loader = tsxLoader();
  const tsCli = join(ROOT, 'packages/runar-cli/src/bin.ts');

  return [
    {
      id: 'ts',
      cmd: loader && existsSync(tsCli) ? process.execPath : null,
      argsFor: (src, out) => ['--import', loader!, tsCli, 'compile', src, '--output', out],
      artifactAt: (out) => join(out, 'EpochProbe.runar.json'),
      outIsDir: true,
      cwd: ROOT,
    },
    {
      id: 'go',
      cmd: go.cmd,
      argsFor: (src, out) => [...go.args, '--source', src, '--output', out],
      artifactAt: (out) => out,
      cwd: join(ROOT, 'compilers/go'),
    },
    {
      id: 'rust',
      cmd: rust.cmd,
      argsFor: (src, out) => [...rust.args, '--source', src, '--output', out],
      artifactAt: (out) => out,
      cwd: join(ROOT, 'compilers/rust'),
    },
    {
      id: 'python',
      cmd: python.cmd,
      argsFor: (src, out) => [...python.args, '--source', src, '--output', out],
      artifactAt: (out) => out,
      cwd: join(ROOT, 'compilers/python'),
    },
    {
      id: 'ruby',
      cmd: ruby.cmd,
      argsFor: (src, out) => [...ruby.args, '--source', src, '--output', out],
      artifactAt: (out) => out,
      cwd: join(ROOT, 'compilers/ruby'),
    },
    {
      id: 'java',
      cmd: jar ? 'java' : null,
      argsFor: (src, out) => ['-jar', jar!, '--source', src, '--emit-artifact', out],
      artifactAt: (out) => out,
      cwd: ROOT,
    },
  ];
}

const TIERS = buildTiers().filter((t) => t.cmd !== null);

/**
 * Compile with SOURCE_DATE_EPOCH pinned; return the artifact JSON text.
 *
 * `dir` is supplied by the caller so the reproducibility case can build TWICE
 * from the same path. Artifacts embed the absolute source path in their source
 * map, so two builds from two temp directories differ for a reason that has
 * nothing to do with the clock — the first version of this test did exactly
 * that and reported a fixed tier as still broken.
 */
function compileAt(tier: Tier, epoch: string, dir: string): string {
  const src = join(dir, 'EpochProbe.runar.ts');
  writeFileSync(src, SOURCE);
  const out = tier.outIsDir ? join(dir, 'artifacts') : join(dir, 'artifact.json');
  const res = spawnSync(tier.cmd!, tier.argsFor(src, out), {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: 180_000,
    env: { ...process.env, SOURCE_DATE_EPOCH: epoch },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.status !== 0) {
    throw new Error(
      `${tier.id} exited ${res.status}: ${(res.stderr || res.stdout || '').slice(0, 500)}`,
    );
  }
  const at = tier.artifactAt(out);
  if (!existsSync(at)) {
    throw new Error(`${tier.id} wrote no artifact at ${at}`);
  }
  return readFileSync(at, 'utf-8');
}

/** Run `f` with a throwaway directory that is cleaned up afterwards. */
function inTempDir<T>(tier: Tier, f: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), `r212-${tier.id}-`));
  try {
    return f(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The field, whatever the tier calls it. */
function stampOf(json: string): string {
  const obj = JSON.parse(json) as Record<string, unknown>;
  const v = obj.buildTimestamp ?? obj.build_timestamp;
  expect(typeof v, `artifact has no buildTimestamp: ${Object.keys(obj).join(', ')}`).toBe('string');
  return v as string;
}

describe('R-212: SOURCE_DATE_EPOCH is honoured by every tier that stamps a time', () => {
  it('at least two tiers are built (a one-tier run proves nothing)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
  });

  for (const tier of buildTiers()) {
    const run = tier.cmd === null ? it.skip : it;

    run(`${tier.id}: stamps the pinned instant, not the clock`, () => {
      const stamp = inTempDir(tier, (dir) => stampOf(compileAt(tier, EPOCH, dir)));
      const parsed = Date.parse(stamp);
      expect(Number.isNaN(parsed), `${tier.id} stamped an unparseable "${stamp}"`).toBe(false);
      expect(
        Math.floor(parsed / 1000),
        `${tier.id} ignored SOURCE_DATE_EPOCH: stamped ${stamp}`,
      ).toBe(EPOCH_SECONDS);
    });

    run(`${tier.id}: two builds at the same epoch are byte-identical`, () => {
      inTempDir(tier, (dir) => {
        const first = compileAt(tier, EPOCH, dir);
        // Cross a wall-clock second. Without this the case passes whenever both
        // builds land in the same second, which is most of the time on a fast
        // tier — it would have reported rust and java as reproducible while
        // they were still stamping the clock.
        const until = Date.now() + 1100;
        while (Date.now() < until) { /* spin: the child processes are sync */ }
        const second = compileAt(tier, EPOCH, dir);
        expect(second, `${tier.id} artifacts differ between two pinned builds`).toBe(first);
      });
    });
  }
});
