/**
 * N-112 — the EC optimizer's constant-scalar fusion helper gets the same name
 * in every tier.
 *
 * Rules 9, 10 and 11 (ecMul∘ecMul, ecAdd of two ecMulGen, ecAdd of two ecMul
 * of the same point) fold the two scalars into one constant and bind it under
 * a newly minted name just before the rewritten binding. TS names it
 * `freshName(`${binding.name}_k`, usedNames)` (optimizer/anf-ec.ts): `<b>_k`,
 * else the first unused `<b>_k_<i>` against the method's used names. Other
 * tiers minted `<b>_sum` with a `_r10_<i>` collision suffix (Go) or a counter
 * `__ec_opt_<n>` (Python, Ruby, Zig, Java; Ruby's counter was also process-global).
 * The bytes never differed — names do not reach the script — but `--emit-ir`
 * did, so the optimized ANF was not comparable across tiers.
 *
 * PROVES: for a source that fires Rules 10, 9 and 11 (each helper survives DCE)
 * and for the same source with user locals named `<b>_k` and `<b>_k_1` (so the
 * minted name must skip to `<b>_k_2`), each native tier's `--emit-ir` equals
 * the TS reference ANF — every binding name, value and order — in both fold
 * modes, after normalising only sourceLoc and the bigint JSON encoding.
 *
 * DOES NOT PROVE: script bytes (unchanged; the golden suite pins them), or naming of
 * rewrites other than the three fusing rules (the N-104 operand-gate names are
 * pinned by n104-ec-operand-gate-parity.test.ts). The per-process determinism
 * of a single tier is pinned by that tier's own test (Ruby:
 * test_n112_ec_fresh_name_determinism.rb; Python: F-191; Java: F-185).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import { writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { compile } from '../index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

// Rule 10 fires on t6 (ecAdd(ecMulGen(2), ecMulGen(3))), Rule 9 on t13
// (ecMul(ecMul(p, 2), 3)) and Rule 11 on t23 (ecAdd(ecMul(g, 2), ecMul(g, 3))).
// ecOnCurve + assert keep each fused binding (and its helper) alive.
// N-397: `a` and `b` are compared with the parameter `n`, not a literal. The
// folder now sees through `a = @ref:t`, so `a == 999n` would fold to true, the
// prune would drop the locals, and the collision probe would no longer collide
// under fold-ON.
const FUSION_SOURCE = `import { SmartContract, assert, ecAdd, ecMul, ecMulGen, ecOnCurve, Point } from 'runar-lang';

class EcFusion extends SmartContract {
    constructor() {
        super();
    }

    public spend(p: Point, n: bigint) {
        const a: bigint = 999n;
        const b: bigint = 998n;
        assert(ecOnCurve(ecAdd(ecMulGen(2n), ecMulGen(3n))));
        assert(ecOnCurve(ecMul(ecMul(p, 2n), 3n)));
        const g: Point = ecMul(p, 7n);
        assert(ecOnCurve(ecAdd(ecMul(g, 2n), ecMul(g, 3n))));
        assert(a == n);
        assert(b == n - 1n);
    }
}
`;

// Same program with the two locals renamed to collide with Rule 10's helper.
const COLLISION_SOURCE = FUSION_SOURCE
  .replace('class EcFusion', 'class EcFusionCollision')
  .replace(/\ba\b(?=:| ==)/g, 't6_k')
  .replace(/\bb\b(?=:| ==)/g, 't6_k_1');

interface Probe { id: string; source: string; helpers: string[] }
const PROBES: Probe[] = [
  { id: 'fusion', source: FUSION_SOURCE, helpers: ['t6_k', 't13_k', 't23_k'] },
  { id: 'collision', source: COLLISION_SOURCE, helpers: ['t6_k_2', 't13_k', 't23_k'] },
];

type FoldMode = 'fold-off' | 'fold-on';
const FOLD_MODES: FoldMode[] = ['fold-off', 'fold-on'];

/**
 * Canonical form for comparison: drop sourceLoc, and encode every integer the
 * same way whatever the tier wrote (TS bigint, JSON number, or "<n>n" string).
 */
function normalise(value: unknown): unknown {
  if (typeof value === 'bigint') return { $int: value.toString() };
  if (typeof value === 'number' && Number.isInteger(value)) return { $int: String(value) };
  if (typeof value === 'string' && /^-?\d+n$/.test(value)) return { $int: value.slice(0, -1) };
  if (Array.isArray(value)) return value.map(normalise);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      if (k === 'sourceLoc') continue;
      const v = (value as Record<string, unknown>)[k];
      if (v === undefined) continue;
      out[k] = normalise(v);
    }
    return out;
  }
  return value;
}

function tsAnf(source: string, fileName: string, fold: FoldMode): unknown {
  const r = compile(source, { fileName, disableConstantFolding: fold === 'fold-off' });
  if (!r.anf) throw new Error(`TS produced no ANF for ${fileName}: ${JSON.stringify(r.diagnostics)}`);
  return normalise(r.anf);
}

function spendNames(anf: unknown): string[] {
  const methods = (anf as { methods: Array<{ name: string; body: Array<{ name: string }> }> }).methods;
  return methods.find((m) => m.name === 'spend')!.body.map((x) => x.name);
}

// ---------------------------------------------------------------------------
// Native tier invocation (same discovery as n104-ec-operand-gate-parity.test.ts)
// ---------------------------------------------------------------------------

function toolchainPresent(probe: string): boolean {
  try {
    execSync(probe, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function firstExisting(...paths: string[]): string | null {
  for (const p of paths) if (existsSync(p)) return p;
  return null;
}

function cargoAwareEnv(): NodeJS.ProcessEnv {
  const home = process.env.HOME ?? '';
  const cargoBin = home ? `${home}/.cargo/bin` : '';
  const currentPath = process.env.PATH ?? '';
  return { ...process.env, PATH: cargoBin ? `${cargoBin}:${currentPath}` : currentPath };
}

function findJavaBinary(): string | null {
  const libsDir = join(REPO_ROOT, 'compilers', 'java', 'build', 'libs');
  if (!existsSync(libsDir)) return null;
  const jar = firstExisting(
    join(libsDir, 'runar-java.jar'),
    ...readdirSync(libsDir)
      .filter((e) => e.startsWith('runar-java-compiler-') && e.endsWith('.jar'))
      .map((e) => join(libsDir, e)),
  );
  if (!jar) return null;
  return toolchainPresent('java -version') ? `java -jar ${jar}` : null;
}

interface Tier { id: string; binary: string | null; cwd: string; env?: NodeJS.ProcessEnv }

const TIERS: Tier[] = [
  {
    id: 'go',
    binary: firstExisting(join(REPO_ROOT, 'compilers', 'go', 'runar-go')) ?? (toolchainPresent('go version') ? 'go run .' : null),
    cwd: join(REPO_ROOT, 'compilers', 'go'),
  },
  {
    id: 'rust',
    binary: firstExisting(
      join(REPO_ROOT, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'),
      join(REPO_ROOT, 'compilers', 'rust', 'target', 'debug', 'runar-compiler-rust'),
    ),
    cwd: join(REPO_ROOT, 'compilers', 'rust'),
    env: cargoAwareEnv(),
  },
  {
    id: 'python',
    binary: existsSync(join(REPO_ROOT, 'compilers', 'python', 'runar_compiler', '__main__.py')) && toolchainPresent('python3 --version')
      ? 'python3 -m runar_compiler' : null,
    cwd: join(REPO_ROOT, 'compilers', 'python'),
  },
  {
    id: 'zig',
    binary: firstExisting(join(REPO_ROOT, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig')),
    cwd: join(REPO_ROOT, 'compilers', 'zig'),
  },
  {
    id: 'ruby',
    binary: existsSync(join(REPO_ROOT, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')) && toolchainPresent('ruby --version')
      ? `ruby ${join(REPO_ROOT, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')}` : null,
    cwd: join(REPO_ROOT, 'compilers', 'ruby'),
  },
  { id: 'java', binary: findJavaBinary(), cwd: join(REPO_ROOT, 'compilers', 'java') },
];

function nativeAnf(tier: Tier, sourcePath: string, fold: FoldMode): unknown {
  const parts = tier.binary!.split(/\s+/);
  const args = [...parts.slice(1), '--source', sourcePath, '--emit-ir'];
  if (fold === 'fold-off') args.push('--disable-constant-folding');
  const out = execFileSync(parts[0]!, args, {
    cwd: tier.cwd,
    env: tier.env,
    timeout: 600_000,
    maxBuffer: 128 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  }).toString();
  return normalise(JSON.parse(out));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('N-112 EC fusion helper names: the TS reference', () => {
  for (const probe of PROBES) {
    for (const fold of FOLD_MODES) {
      it(`${probe.id} (${fold}) mints ${probe.helpers.join(', ')}`, () => {
        const names = spendNames(tsAnf(probe.source, `${probe.id}.runar.ts`, fold));
        for (const h of probe.helpers) expect(names, h).toContain(h);
      });
    }
  }
});

describe('N-112 EC fusion helper names: cross-tier --emit-ir parity', () => {
  let tempDir: string;
  const paths: Record<string, string> = {};
  const expected: Record<string, unknown> = {};

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-n112-'));
    for (const probe of PROBES) {
      const p = join(tempDir, `${probe.id}.runar.ts`);
      writeFileSync(p, probe.source);
      paths[probe.id] = p;
      for (const fold of FOLD_MODES) expected[`${probe.id}/${fold}`] = tsAnf(probe.source, `${probe.id}.runar.ts`, fold);
    }
  });

  afterAll(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  for (const tier of TIERS) {
    describe.skipIf(tier.binary === null)(tier.id, () => {
      for (const probe of PROBES) {
        for (const fold of FOLD_MODES) {
          it(`${probe.id} (${fold}) --emit-ir equals TS`, () => {
            const got = nativeAnf(tier, paths[probe.id]!, fold);
            const want = expected[`${probe.id}/${fold}`];
            // Names first: the readable failure for this item.
            expect(spendNames(got)).toEqual(spendNames(want));
            expect(got).toEqual(want);
          });
        }
      }
    });
  }
});
