/**
 * R-034 / CL-BUG-028 — cross-tier hex parity for the two negate-cancel rules.
 *
 *     ec-add-negate-cancel           ecAdd($x, ecNegate($x))  -> INFINITY
 *     ec-add-negate-cancel-reversed  ecAdd(ecNegate($x), $x)  -> INFINITY
 *
 * `optimizer/ec-rules.json` declares both with no "supported" tag, i.e. every
 * tier must implement both and implement them identically. The Go engine is
 * data-driven off that file and did; the six hand-ported tiers implemented only
 * the forward one. Feeding the aliased ANF shape to both produced a 14x script
 * size difference (Go 1808 bytes, TS 26140 bytes) for the same input.
 *
 * REACHABILITY — the reason this sat undetected, and the reason the severity is
 * "cross-tier byte divergence" and not "wrong answer":
 *
 *  1. NOT reachable from source, in any tier. ANF lowering (pass 04) gives every
 *     OCCURRENCE of a variable its own `load_param` / `load_prop` binding, so
 *     `ecAdd(ecNegate(p), p)` written in TypeScript lowers to
 *     `t0 = load_param p; t1 = ecNegate(t0); t2 = load_param p; t3 = ecAdd(t1, t2)`.
 *     `$x` therefore binds to two DIFFERENT names and no tier's matcher unifies
 *     them — not even the Go engine, whose `sameResolvedValue` only equates two
 *     `load_const` payloads. BOTH negate-cancel rules are inert from source.
 *     Confirmed: TS and Go emit byte-identical hex for both spellings compiled
 *     from `.runar.ts`.
 *  2. Reachable through the `--ir` / `compileFromANF` path, which accepts
 *     arbitrary ANF — the same "unreachable from the frontend, reachable via
 *     --ir" surface as `repeated-operand-consume.test.ts`. That is what these
 *     probes exercise.
 *  3. Value-preserving either way. The unfolded codegen already returns the
 *     point at infinity for P + (-P): `emitEcAdd` masks the result to the
 *     all-zero blob in the `P == -Q` case (see the header comment in
 *     `passes/ec-codegen.ts`). Executed on the real ScriptVM with p = G, the
 *     UNFOLDED script yields x = 0 and y = 0 — exactly the constant the rule
 *     substitutes. So the rule is an optimisation, and the defect is that six
 *     tiers took the slow path while the seventh took the fast one.
 *
 * The tests below pin all three claims.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import { writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
// @ts-expect-error vitest resolves this via the root alias
import { ScriptVM } from 'runar-testing';
import { compile, compileFromANF } from '../index.js';
import type { ANFProgram, ANFBinding, ANFValue } from '../ir/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

// ---------------------------------------------------------------------------
// Probe ANF — the aliased shape the frontend cannot produce
// ---------------------------------------------------------------------------

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

/**
 * `ecAdd` over a point and its negation, with BOTH operands referring to the
 * single binding `t0`. Written by hand on purpose: see REACHABILITY note 1 —
 * the `const p = ...` / repeated-variable spellings lower to two distinct
 * bindings and make every tier decline, which would make this test prove
 * nothing while looking green.
 */
function constructorMethod() {
  // Byte-for-byte the shape pass 04 emits for `constructor(tag) { super(tag); this.tag = tag; }`
  // — hand-rolling a different spelling makes the native `--ir` loaders reject
  // the file and the whole test skip for the wrong reason.
  return {
    name: 'constructor',
    params: [{ name: 'tag', type: 'bigint' }],
    body: [
      b('c0', { kind: 'load_prop', name: 'tag' }),
      b('c1', { kind: 'call', func: 'super', args: ['c0'] }),
      b('c2', { kind: 'load_prop', name: 'tag' }),
      b('c3', { kind: 'update_prop', name: 'tag', value: 'c2' }),
    ],
    isPublic: false,
  };
}

function aliasedProgram(order: 'forward' | 'reversed'): ANFProgram {
  const addArgs = order === 'forward' ? ['t0', 't1'] : ['t1', 't0'];
  return {
    contractName: 'ECNegCancel',
    properties: [{ name: 'tag', type: 'bigint', readonly: true }],
    methods: [
      constructorMethod(),
      {
        name: 'spend',
        params: [{ name: 'p', type: 'Point' }],
        body: [
          b('t0', { kind: 'load_param', name: 'p' }),
          b('t1', { kind: 'call', func: 'ecNegate', args: ['t0'] }),
          b('t2', { kind: 'call', func: 'ecAdd', args: addArgs }),
          b('t3', { kind: 'call', func: 'ecOnCurve', args: ['t2'] }),
          b('t4', { kind: 'assert', value: 't3' }),
        ],
        isPublic: true,
      },
    ],
  };
}

/** Same bigint encoding the cross-compiler suite uses for the native IR decoders. */
function anfToJson(anf: ANFProgram): string {
  return JSON.stringify(anf, (_key, value) => {
    if (typeof value === 'bigint') {
      if (value >= Number.MIN_SAFE_INTEGER && value <= Number.MAX_SAFE_INTEGER) return Number(value);
      return value.toString() + 'n';
    }
    return value;
  }, 2);
}

// ---------------------------------------------------------------------------
// Native tier invocation
// ---------------------------------------------------------------------------

interface Tier {
  id: string;
  /** Resolved command, or null when the toolchain is not installed locally. */
  binary: string | null;
  cwd: string;
  /** Zig's IR consumer is a positional subcommand and takes no fold flag. */
  args: (irPath: string) => string[];
  /** Zig interleaves allocator diagnostics; keep only the first line. */
  firstLineOnly?: boolean;
  env?: NodeJS.ProcessEnv;
}

/** Mirrors `cargoAwareEnv` in the conformance runner (not exported there). */
function cargoAwareEnv(): NodeJS.ProcessEnv {
  const home = process.env.HOME ?? '';
  const cargoBin = home ? `${home}/.cargo/bin` : '';
  const currentPath = process.env.PATH ?? '';
  return { ...process.env, PATH: cargoBin ? `${cargoBin}:${currentPath}` : currentPath };
}

// Binary discovery. `conformance/runner/runner.ts` is the project's source of
// truth for this (findGoBinary / findRustBinary / ...), but importing it from a
// packages/ test drags in conformance's standalone npm install and makes the
// TS toolchain emit compiled .js next to the runner. These are the same
// candidate paths, reduced to what an `--ir --hex` invocation needs. A tier
// whose toolchain is absent returns null and its two tests skip.

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

function findGoBinary(): string | null {
  const built = firstExisting(join(REPO_ROOT, 'compilers', 'go', 'runar-go'));
  if (built) return built;
  return toolchainPresent('go version') ? 'go run .' : null;
}

function findRustBinary(): string | null {
  return firstExisting(
    join(REPO_ROOT, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'),
    join(REPO_ROOT, 'compilers', 'rust', 'target', 'debug', 'runar-compiler-rust'),
  );
}

function findPythonBinary(): string | null {
  if (!existsSync(join(REPO_ROOT, 'compilers', 'python', 'runar_compiler', '__main__.py'))) return null;
  return toolchainPresent('python3 --version') ? 'python3 -m runar_compiler' : null;
}

function findZigBinary(): string | null {
  return firstExisting(join(REPO_ROOT, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'));
}

function findRubyBinary(): string | null {
  const script = join(REPO_ROOT, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby');
  if (!existsSync(script)) return null;
  return toolchainPresent('ruby --version') ? `ruby ${script}` : null;
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

function irArgs(irPath: string): string[] {
  return ['--ir', irPath, '--hex', '--disable-constant-folding'];
}

const TIERS: Tier[] = [
  { id: 'go', binary: findGoBinary(), cwd: join(REPO_ROOT, 'compilers', 'go'), args: irArgs },
  { id: 'rust', binary: findRustBinary(), cwd: join(REPO_ROOT, 'compilers', 'rust'), args: irArgs, env: cargoAwareEnv() },
  { id: 'python', binary: findPythonBinary(), cwd: join(REPO_ROOT, 'compilers', 'python'), args: irArgs },
  {
    id: 'zig',
    binary: findZigBinary(),
    cwd: join(REPO_ROOT, 'compilers', 'zig'),
    args: (p) => ['compile-ir', p, '--hex'],
    firstLineOnly: true,
  },
  { id: 'ruby', binary: findRubyBinary(), cwd: join(REPO_ROOT, 'compilers', 'ruby'), args: irArgs },
  { id: 'java', binary: findJavaBinary(), cwd: join(REPO_ROOT, 'compilers', 'java'), args: irArgs },
];

function runTier(tier: Tier, irPath: string): string {
  const parts = tier.binary!.split(/\s+/);
  const out = execFileSync(parts[0]!, [...parts.slice(1), ...tier.args(irPath)], {
    cwd: tier.cwd,
    env: tier.env,
    timeout: 600_000,
    maxBuffer: 128 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  }).toString();
  const raw = tier.firstLineOnly ? (out.split('\n')[0] ?? '') : out;
  return raw.replace(/\s/g, '').toLowerCase();
}

/** Compare without handing vitest two ~26 KB hex strings to diff. */
function expectSameHex(label: string, a: string, bHex: string): void {
  if (a === bHex) return;
  let i = 0;
  while (i < a.length && i < bHex.length && a[i] === bHex[i]) i++;
  throw new Error(
    `${label}: hex differs. lenA=${a.length} lenB=${bHex.length} firstDiffAt=${i}\n` +
    `  a: ...${a.slice(Math.max(0, i - 16), i + 16)}...\n` +
    `  b: ...${bHex.slice(Math.max(0, i - 16), i + 16)}...`,
  );
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ec-add-negate-cancel{,-reversed}: cross-tier parity via --ir', () => {
  let tempDir: string;
  const irPaths: Record<string, string> = {};
  const tsHex: Record<string, string> = {};

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-r034-'));
    for (const order of ['forward', 'reversed'] as const) {
      const anf = aliasedProgram(order);
      const p = join(tempDir, `${order}.anf.json`);
      writeFileSync(p, anfToJson(anf));
      irPaths[order] = p;
      tsHex[order] = (compileFromANF(anf, { disableConstantFolding: true }).scriptHex as string).toLowerCase();
    }
  });

  afterAll(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('the rule fires in TS: the ecAdd is replaced by the INFINITY constant', () => {
    for (const order of ['forward', 'reversed'] as const) {
      const r = compileFromANF(aliasedProgram(order), { disableConstantFolding: true });
      const spend = r.anf.methods.find((m) => m.name === 'spend')!;
      const funcs = spend.body.filter((x) => x.value.kind === 'call').map((x) => (x.value as { func: string }).func);
      // Proof the fold happened, not merely that two tiers agree: no ecAdd
      // survives, and the folded script is an order of magnitude smaller than
      // the ~26 KB one an emitted ecAdd produces.
      expect(funcs, `${order}: ecAdd survived, the rule did not fire`).not.toContain('ecAdd');
      expect(tsHex[order]!.length).toBeLessThan(8000);
    }
  });

  // Control: expressions that must NOT fold. `ecAdd(x, ecNegate(y))` with x != y
  // is a real point addition; folding it would be a wrong answer, not a slow one.
  it('CONTROL: ecAdd over two different points does not fold', () => {
    const anf: ANFProgram = {
      contractName: 'ECNoCancel',
      properties: [{ name: 'tag', type: 'bigint', readonly: true }],
      methods: [
        constructorMethod(),
        {
          name: 'spend',
          params: [{ name: 'p', type: 'Point' }, { name: 'q', type: 'Point' }],
          body: [
            b('t0', { kind: 'load_param', name: 'p' }),
            b('t1', { kind: 'load_param', name: 'q' }),
            b('t2', { kind: 'call', func: 'ecNegate', args: ['t1'] }),
            b('t3', { kind: 'call', func: 'ecAdd', args: ['t2', 't0'] }),
            b('t4', { kind: 'call', func: 'ecOnCurve', args: ['t3'] }),
            b('t5', { kind: 'assert', value: 't4' }),
          ],
          isPublic: true,
        },
      ],
    };
    const r = compileFromANF(anf, { disableConstantFolding: true });
    const spend = r.anf.methods.find((m) => m.name === 'spend')!;
    const funcs = spend.body.filter((x) => x.value.kind === 'call').map((x) => (x.value as { func: string }).func);
    expect(funcs).toContain('ecAdd');
    expect((r.scriptHex as string).length).toBeGreaterThan(20000);
  });

  for (const tier of TIERS) {
    describe.skipIf(tier.binary === null)(`${tier.id}`, () => {
      it('forward (control — already implemented everywhere) matches TS', () => {
        expectSameHex(`ts vs ${tier.id} forward`, tsHex.forward!, runTier(tier, irPaths.forward!));
      });
      it('reversed matches TS', () => {
        expectSameHex(`ts vs ${tier.id} reversed`, tsHex.reversed!, runTier(tier, irPaths.reversed!));
      });
    });
  }
});

describe('ec-add-negate-cancel: reachability and value preservation', () => {
  const SRC = `
class NegCancelSrc extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public spend(p: Point) {
    const s = ecAdd(ecNegate(p), p);
    assert(ecPointX(s) === 0n);
    assert(ecPointY(s) === 0n);
  }
}
`;

  it('the rule is INERT from source: pass 04 gives each occurrence its own binding', () => {
    const r = compile(SRC, { disableConstantFolding: true });
    expect(r.success).toBe(true);
    const spend = r.anf!.methods.find((m) => m.name === 'spend')!;
    const loads = spend.body.filter(
      (x) => x.value.kind === 'load_param' && (x.value as { name: string }).name === 'p',
    );
    // Two separate bindings for the single parameter `p` — this, not a missing
    // rule, is why no tier folds the source spelling.
    expect(loads.length).toBeGreaterThanOrEqual(2);
    const funcs = spend.body.filter((x) => x.value.kind === 'call').map((x) => (x.value as { func: string }).func);
    expect(funcs).toContain('ecAdd');
  });

  it('VALUE PRESERVATION: the UNFOLDED script really returns the point at infinity', () => {
    const r = compile(SRC, { disableConstantFolding: true });
    expect(r.success).toBe(true);
    // p = G, pushed as the 64-byte x||y Point encoding.
    const GX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    const GY = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
    const unlock = new Uint8Array([0x4c, 0x40, ...hexToBytes(GX + GY)]);
    const vm = new ScriptVM();
    const res = vm.execute(unlock, hexToBytes(r.scriptHex as string));
    // The contract asserts x === 0 && y === 0 on the unfolded ecAdd result, so
    // success here IS the proof that folding to INFINITY changes no value.
    expect(res.error).toBeUndefined();
    expect(res.success).toBe(true);
  });
});
