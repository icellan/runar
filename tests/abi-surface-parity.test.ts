/**
 * The artifact ABI must not depend on which surface syntax a contract was
 * written in (N-304).
 *
 * `abi-cross-tier-parity.test.ts` compares only the `.runar.ts` ABI of two
 * fixtures across tiers. Nothing compared the ABI of the OTHER eight surfaces
 * of a multi-format fixture. The TypeScript `.runar.zig` parser kept the
 * `ctx: runar.StatefulContext` parameter in the method's param list, so the
 * artifact ABI of a stateful Zig contract read `bump: [ctx, txPreimage]` while
 * the same contract in every other surface (and in the six native tiers' Zig
 * parsers) read `bump: [txPreimage]`. `ctx` is a surface artifact — the
 * compiler re-injects the context itself — not a spending parameter, so an SDK
 * that read the TS-produced artifact would have asked a caller for a value the
 * script never consumes. Hex and ANF were unaffected (pass 04 strips the
 * param), which is why every existing gate stayed green.
 *
 * Scope:
 *  - TypeScript tier, in-process: EVERY conformance fixture that has more than
 *    one surface, EVERY surface, compared with that fixture's `.runar.ts` ABI.
 *  - Native tiers (go, rust, python, ruby, zig, java), spawned: every surface
 *    of each fixture whose `.runar.zig` source declares a `StatefulContext`
 *    parameter — the construct this defect lives in — compared with the same
 *    `.runar.ts` reference. Spawning 6 compilers x 9 surfaces x 80 fixtures
 *    would take far longer than a unit test should; the all-fixture native
 *    sweep was measured once by hand when this test was written and the only
 *    divergences were the TS-tier `.runar.zig` ones this test now pins.
 *
 * Proves: the ABI (method names, visibility, param names and types, in order)
 * of every surface equals the `.runar.ts` ABI in the tiers covered above.
 * Does not prove: parity for fixtures outside the native-tier scope above, nor
 * anything about the script bytes (the conformance golden gates those).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findGoBinary,
  findRustBinary,
  findPythonBinary,
  findZigBinary,
  findRubyBinary,
  findJavaBinary,
} from '../conformance/runner/runner.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TESTS_DIR = join(ROOT, 'conformance/tests');

interface Fixture {
  name: string;
  /** extension -> absolute source path (only sources that exist on disk). */
  sources: Map<string, string>;
  compilers: string[] | null;
}

function loadFixtures(): Fixture[] {
  const out: Fixture[] = [];
  for (const name of readdirSync(TESTS_DIR).sort()) {
    const sj = join(TESTS_DIR, name, 'source.json');
    if (!existsSync(sj)) continue;
    const j = JSON.parse(readFileSync(sj, 'utf-8')) as {
      sources?: Record<string, string>;
      compilers?: string[];
    };
    const sources = new Map<string, string>();
    for (const [ext, rel] of Object.entries(j.sources ?? {})) {
      const p = resolve(dirname(sj), rel);
      if (existsSync(p)) sources.set(ext, p);
    }
    if (sources.size < 2 || !sources.has('.runar.ts')) continue;
    out.push({ name, sources, compilers: j.compilers ?? null });
  }
  return out;
}

interface AbiLike {
  abi?: {
    methods?: Array<{
      name: string;
      isPublic?: boolean;
      params?: Array<{ name: string; type: string }>;
    }>;
  };
}

/** Canonical, order-preserving rendering of the ABI methods. */
function renderAbi(a: AbiLike): string[] {
  return (a.abi?.methods ?? []).map(
    (m) =>
      `${m.name}${m.isPublic === false ? ' (private)' : ''}(${(m.params ?? [])
        .map((p) => `${p.name}: ${p.type}`)
        .join(', ')})`,
  );
}

function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

interface Tier {
  id: string;
  binary: string | null;
  cwd: string;
  java: boolean;
}

const NATIVE_TIERS: Tier[] = [
  { id: 'go', binary: findGoBinary(), cwd: join(ROOT, 'compilers/go'), java: false },
  { id: 'rust', binary: findRustBinary(), cwd: join(ROOT, 'compilers/rust'), java: false },
  { id: 'python', binary: findPythonBinary(), cwd: join(ROOT, 'compilers/python'), java: false },
  { id: 'ruby', binary: findRubyBinary(), cwd: join(ROOT, 'compilers/ruby'), java: false },
  { id: 'zig', binary: findZigBinary(), cwd: join(ROOT, 'compilers/zig'), java: false },
  { id: 'java', binary: findJavaBinary(), cwd: join(ROOT, 'compilers/java'), java: true },
];

function nativeAbi(tier: Tier, source: string): string[] {
  const dir = mkdtempSync(join(tmpdir(), `abi-surface-${tier.id}-`));
  const art = join(dir, 'artifact.json');
  const { cmd, args } = splitCmd(tier.binary);
  const argv = tier.java ? ['--source', source, '--emit-artifact', art] : ['--source', source];
  const res = spawnSync(cmd!, [...args, ...argv], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: 300_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  expect(res.status, `${tier.id} failed on ${source}: ${(res.stderr ?? '').slice(0, 400)}`).toBe(0);
  return renderAbi(JSON.parse(tier.java ? readFileSync(art, 'utf-8') : (res.stdout ?? '')) as AbiLike);
}

const FIXTURES = loadFixtures();
const TS_IDS = ['ts', 'typescript'];
const tsIncluded = (f: Fixture) => f.compilers === null || f.compilers.some((c) => TS_IDS.includes(c));

describe('artifact ABI is identical across every surface of a fixture (TypeScript tier)', () => {
  it('enumerates the multi-format fixtures', () => {
    expect(FIXTURES.length).toBeGreaterThan(50);
  });

  for (const f of FIXTURES.filter(tsIncluded)) {
    it(`${f.name}: every surface has the .runar.ts ABI`, async () => {
      const { compile } = await import('runar-compiler');
      const abiOf = (path: string) => {
        const r = compile(readFileSync(path, 'utf-8'), { fileName: path.split('/').pop()! });
        expect(r.success, `${path}: ${r.diagnostics.map((d) => d.message).join('\n')}`).toBe(true);
        return renderAbi({ abi: r.artifact!.abi });
      };
      const reference = abiOf(f.sources.get('.runar.ts')!);
      const diverging: string[] = [];
      for (const [ext, path] of f.sources) {
        if (ext === '.runar.ts') continue;
        const got = abiOf(path);
        if (JSON.stringify(got) !== JSON.stringify(reference)) {
          diverging.push(`${ext}: ${JSON.stringify(got)} !== ${JSON.stringify(reference)}`);
        }
      }
      expect(diverging, `${f.name}: surfaces whose ABI differs from .runar.ts`).toEqual([]);
    }, 300_000);
  }
});

/** Fixtures whose Zig surface threads a `StatefulContext` parameter. */
const CTX_FIXTURES = FIXTURES.filter((f) => {
  const z = f.sources.get('.runar.zig');
  return z !== undefined && /StatefulContext/.test(readFileSync(z, 'utf-8'));
});
const availableNative = NATIVE_TIERS.filter((t) => t.binary !== null && existsSync(t.cwd));

describe('artifact ABI is identical across every surface of a StatefulContext fixture (native tiers)', () => {
  it('finds the StatefulContext fixtures and at least two built native tiers', () => {
    expect(CTX_FIXTURES.map((f) => f.name)).toEqual(
      expect.arrayContaining(['auction', 'sighash-single-stateful', 'token-ft', 'token-nft']),
    );
    expect(availableNative.length).toBeGreaterThanOrEqual(2);
  });

  for (const f of CTX_FIXTURES) {
    for (const tier of NATIVE_TIERS) {
      // Fail closed under CI: a missing binary must not turn into a silent skip.
      const missing = !availableNative.includes(tier);
      const maybe = missing && !process.env.CI ? it.skip : it;
      maybe(`${f.name}: ${tier.id} gives every surface the TypeScript .runar.ts ABI`, async () => {
        if (missing) {
          throw new Error(`${tier.id} compiler binary not built (CI is set, so this is a failure, not a skip)`);
        }
        const { compile } = await import('runar-compiler');
        const ref = compile(readFileSync(f.sources.get('.runar.ts')!, 'utf-8'), {
          fileName: 'ref.runar.ts',
        });
        expect(ref.success).toBe(true);
        const reference = renderAbi({ abi: ref.artifact!.abi });
        const diverging: string[] = [];
        for (const [ext, path] of f.sources) {
          const got = nativeAbi(tier, path);
          if (JSON.stringify(got) !== JSON.stringify(reference)) {
            diverging.push(`${ext}: ${JSON.stringify(got)} !== ${JSON.stringify(reference)}`);
          }
        }
        expect(diverging, `${tier.id}/${f.name}: surfaces whose ABI differs from .runar.ts`).toEqual([]);
      }, 600_000);
    }
  }
});
