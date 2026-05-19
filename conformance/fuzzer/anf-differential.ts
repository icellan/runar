/**
 * Item 7 — Property-based cross-tier ANF differential fuzzer.
 *
 * Generates random *valid* ANF IR programs (using the TS schema as
 * authority) and asserts that all 7 compiler tiers (TS, Go, Rust,
 * Python, Zig, Ruby, Java) produce **byte-identical**
 * Stack-lowered Bitcoin Script hex for the same input.
 *
 * Two existing harnesses in this directory generate Rúnar SOURCE
 * (TypeScript / Solidity-like / per-language native sources) and feed
 * it through every compiler's frontend + backend (`differential.ts`,
 * `ir-differential.ts`). This module is the third leg: it skips the
 * frontends entirely and exercises the *ANF loader + stack-lowering
 * passes* across all 7 tiers — the path that the existing source
 * fuzzers cannot reach unambiguously because two frontends may legally
 * lower the same source to slightly different (but conformant) ANF.
 *
 * Cross-cutting coverage achieved:
 *   - All 7 ANF loaders (`--ir <path>` parsers) accept the canonical
 *     JSON produced by `runar-ir-schema`'s `canonicalJsonStringify`.
 *   - All 7 stack-lowering passes produce identical hex for the same
 *     program (the "Stack IR + hex parity (scoped)" invariant from
 *     CLAUDE.md, exercised on a property-based program corpus instead
 *     of the small hand-written conformance fixtures).
 *   - Canonical JSON byte-identity is verified *via* the loader: if
 *     all 7 loaders accept the same canonical bytes and all 7 lowerers
 *     produce the same hex, the bytes are by construction a fixed
 *     point of every tier's loader + re-serializer. (No tier currently
 *     exposes a stand-alone `--canonicalise` CLI, so this is the most
 *     practical cross-tier byte-parity probe today.)
 *
 * Determinism: fast-check carries a `seed`; running with the same
 * `--seed` reproduces the exact same program corpus. Failing cases are
 * persisted under `conformance/fuzz-findings-anf/<timestamp>/` so the
 * source program + per-tier hex output can be replayed offline.
 */

import fc from 'fast-check';
import {
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
  unlinkSync,
} from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(__dirname, '../..');

// ---------------------------------------------------------------------------
// Tier identifiers
// ---------------------------------------------------------------------------

export type CompilerName = 'ts' | 'go' | 'rust' | 'python' | 'zig' | 'ruby' | 'java';
export const ALL_TIERS: readonly CompilerName[] = [
  'ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java',
];

// ---------------------------------------------------------------------------
// Minimal schema mirrors (avoid hard-importing the compiler's TS types so
// this module stays usable from a plain tsx invocation even before the
// workspace is built).
// ---------------------------------------------------------------------------

interface AnfParam { name: string; type: string }
interface AnfProperty {
  name: string;
  type: string;
  readonly: boolean;
  initialValue?: string | number | boolean | bigint;
}
interface AnfBinding { name: string; value: AnfValue }
interface AnfMethod {
  name: string;
  params: AnfParam[];
  body: AnfBinding[];
  isPublic: boolean;
}
interface AnfProgram {
  contractName: string;
  properties: AnfProperty[];
  methods: AnfMethod[];
}

// Subset of the 19 ANF kinds the generator emits. We exclude `if` /
// `loop` (nested bindings — generator quickly blows up combinatorially)
// and the stateful-contract-only kinds (`get_state_script`,
// `check_preimage`, `deserialize_state`, `add_output`,
// `add_raw_output`, `add_data_output`) which need a coordinating
// preimage parameter + state-continuation discipline that's not worth
// the generator complexity for an in-the-loop fuzzer. The kinds we
// keep — load_const / load_param / load_prop / bin_op / unary_op /
// call / array_literal / assert / update_prop — already exercise every
// loader + every stack-lowering dispatch site touched by the
// non-stateful program shape used by 80+% of the conformance corpus.
// Stateful + control-flow kinds are covered by the source-based
// fuzzers in `ir-differential.ts` and the hand-written conformance
// fixtures.
type AnfValue =
  | { kind: 'load_param'; name: string }
  | { kind: 'load_prop'; name: string }
  | { kind: 'load_const'; value: bigint | boolean }
  | { kind: 'bin_op'; op: string; left: string; right: string }
  | { kind: 'unary_op'; op: string; operand: string }
  | { kind: 'call'; func: string; args: string[] }
  | { kind: 'array_literal'; elements: string[] }
  | { kind: 'assert'; value: string }
  | { kind: 'update_prop'; name: string; value: string };

// ---------------------------------------------------------------------------
// Per-binding type, tracked during generation so `bin_op` operands and
// `assert` values are typed correctly. The Rúnar stack-lowering
// expects a single concrete type per value reference.
// ---------------------------------------------------------------------------

type ValType = 'bigint' | 'boolean';
interface TypedBinding extends AnfBinding {
  ty: ValType;
}

// ---------------------------------------------------------------------------
// Random-program generator
// ---------------------------------------------------------------------------

/**
 * Deterministic, seeded RNG. We use a small mulberry32 implementation
 * inline so the fuzzer doesn't depend on any specific fast-check
 * internal (`fc.Random` / `fc.mersenne` are not stable cross-version).
 * fast-check is still used for the top-level `fc.sample` driver — that
 * gives the harness reproducibility from a `--seed` value — and each
 * sampled integer is fed into Mulberry32 as the per-program seed.
 */
interface Rng {
  nextInt(min: number, max: number): number;
  nextBoolean(): boolean;
}

function mulberry32(a: number): Rng {
  let state = a >>> 0;
  function next(): number {
    state = (state + 0x6D2B79F5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 0x100000000;
  }
  return {
    nextInt(min, max) {
      if (max < min) throw new Error('nextInt: max < min');
      return min + Math.floor(next() * (max - min + 1));
    },
    nextBoolean() {
      return next() < 0.5;
    },
  };
}

interface GenContext {
  /** Body order — every emitted binding appears here, in declaration order. */
  body: TypedBinding[];
  /** Subset of `body` whose values are safe to reference from later bindings
   *  (scalar bigints/booleans on the stack). Terminator-shaped kinds like
   *  `update_prop` / `array_literal` / `assert` are added to `body` but
   *  NOT to `bindings`. */
  bindings: TypedBinding[];
  /** Properties on the contract (referenced by `load_prop` / `update_prop`). */
  properties: AnfProperty[];
  /** Method parameter names + types (referenced by `load_param`). */
  params: AnfParam[];
  /** Monotonic counter for fresh temp names. */
  nextId: number;
}

function freshName(ctx: GenContext): string {
  const n = `t${ctx.nextId}`;
  ctx.nextId += 1;
  return n;
}

/** Push a binding that produces a stack-resident scalar; safe to reference
 * from later bindings. */
function pushRef(ctx: GenContext, b: TypedBinding): TypedBinding {
  ctx.body.push(b);
  ctx.bindings.push(b);
  return b;
}

/** Push a statement-shaped binding (update_prop / array_literal / assert
 * / add_*output) that should NOT be referenced by later bindings. */
function pushStmt(ctx: GenContext, b: TypedBinding): TypedBinding {
  ctx.body.push(b);
  return b;
}

function pickAny<T>(rng: Rng, xs: readonly T[]): T {
  if (xs.length === 0) {
    throw new Error('pickAny: empty array');
  }
  return xs[rng.nextInt(0, xs.length - 1)]!;
}

function priorOf(rng: Rng, ctx: GenContext, ty: ValType): TypedBinding | null {
  const candidates = ctx.bindings.filter((b) => b.ty === ty);
  if (candidates.length === 0) return null;
  return pickAny(rng, candidates);
}

function emitConst(rng: Rng, ctx: GenContext, ty: ValType): TypedBinding {
  const name = freshName(ctx);
  const value: bigint | boolean = ty === 'bigint'
    ? BigInt(rng.nextInt(-1024, 1024))
    : rng.nextBoolean();
  const b: TypedBinding = { name, ty, value: { kind: 'load_const', value } };
  return pushRef(ctx, b);
}

function ensureBigint(rng: Rng, ctx: GenContext): TypedBinding {
  return priorOf(rng, ctx, 'bigint') ?? emitConst(rng, ctx, 'bigint');
}

function ensureBool(rng: Rng, ctx: GenContext): TypedBinding {
  return priorOf(rng, ctx, 'boolean') ?? emitConst(rng, ctx, 'boolean');
}

// Bigint ops we know all 7 stack-lowerers accept. Restricted to a
// commutative-arith / cmp subset to maximise lower-success on random
// inputs. `safediv` / `safemod` are routed through `call` rather than
// `bin_op` because the AST uses `/`/`%` only when the typechecker has
// previously stamped a non-zero divisor.
const BIGINT_BIN_OPS = ['+', '-', '*'] as const;
const CMP_BIN_OPS = ['===', '!==', '<', '>', '<=', '>='] as const;
const BOOL_BIN_OPS = ['&&', '||'] as const;

function emitBinOp(rng: Rng, ctx: GenContext, kind: 'bigint' | 'cmp' | 'bool'): TypedBinding {
  if (kind === 'bigint') {
    const { left, right } = twoDistinct(rng, ctx, 'bigint');
    const op = pickAny(rng, BIGINT_BIN_OPS);
    const name = freshName(ctx);
    const b: TypedBinding = {
      name,
      ty: 'bigint',
      value: { kind: 'bin_op', op, left: left.name, right: right.name },
    };
    return pushRef(ctx, b);
  }
  if (kind === 'cmp') {
    const { left, right } = twoDistinct(rng, ctx, 'bigint');
    const op = pickAny(rng, CMP_BIN_OPS);
    const name = freshName(ctx);
    const b: TypedBinding = {
      name,
      ty: 'boolean',
      value: { kind: 'bin_op', op, left: left.name, right: right.name },
    };
    return pushRef(ctx, b);
  }
  // bool
  const { left, right } = twoDistinct(rng, ctx, 'boolean');
  const op = pickAny(rng, BOOL_BIN_OPS);
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty: 'boolean',
    value: { kind: 'bin_op', op, left: left.name, right: right.name },
  };
  return pushRef(ctx, b);
}

/**
 * Pick two distinct prior bindings of the given type, materialising new
 * `load_const` bindings as needed. We avoid `left == right` because the
 * stack-lowerer's use analysis cannot keep a value alive across a
 * bin_op that references the same binding twice (the second reference
 * is also the "last use" — which consumes the slot before the bin_op
 * can read the second copy). This is a generator-side constraint, not
 * a compiler bug: source-level expressions like `a + a` lower to
 * `let t0 = a; let t1 = a; let t2 = t0 + t1` — i.e. two distinct
 * bindings — so the constraint matches how every conformant frontend
 * produces ANF in the first place.
 */
function twoDistinct(
  rng: Rng,
  ctx: GenContext,
  ty: ValType,
): { left: TypedBinding; right: TypedBinding } {
  const ensure = ty === 'bigint' ? ensureBigint : ensureBool;
  const left = ensure(rng, ctx);
  // Try a few times to find a different right; if we keep hitting left,
  // emit a fresh constant.
  for (let i = 0; i < 4; i++) {
    const right = ensure(rng, ctx);
    if (right.name !== left.name) return { left, right };
  }
  const right = emitConst(rng, ctx, ty);
  return { left, right };
}

function emitUnaryOp(rng: Rng, ctx: GenContext, kind: 'bigint' | 'bool'): TypedBinding {
  if (kind === 'bigint') {
    const operand = ensureBigint(rng, ctx);
    const name = freshName(ctx);
    const b: TypedBinding = {
      name,
      ty: 'bigint',
      value: { kind: 'unary_op', op: '-', operand: operand.name },
    };
    return pushRef(ctx, b);
  }
  const operand = ensureBool(rng, ctx);
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty: 'boolean',
    value: { kind: 'unary_op', op: '!', operand: operand.name },
  };
  return pushRef(ctx, b);
}

function emitLoadParam(_rng: Rng, ctx: GenContext, param: AnfParam): TypedBinding {
  const ty: ValType = param.type === 'boolean' ? 'boolean' : 'bigint';
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty,
    value: { kind: 'load_param', name: param.name },
  };
  return pushRef(ctx, b);
}

function emitLoadProp(_rng: Rng, ctx: GenContext, prop: AnfProperty): TypedBinding {
  const ty: ValType = prop.type === 'boolean' ? 'boolean' : 'bigint';
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty,
    value: { kind: 'load_prop', name: prop.name },
  };
  return pushRef(ctx, b);
}

function emitCallAbs(rng: Rng, ctx: GenContext): TypedBinding {
  const arg = ensureBigint(rng, ctx);
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty: 'bigint',
    value: { kind: 'call', func: 'abs', args: [arg.name] },
  };
  return pushRef(ctx, b);
}

function emitArrayLiteral(rng: Rng, ctx: GenContext): TypedBinding {
  // Bigint-element array literal — Stack-lowered specifically for use
  // with `checkMultiSig` (which expects two arrays in a precise stack
  // layout). Because it's a "terminator" in our generator (the value
  // isn't a typed scalar that subsequent bindings can reference), we
  // append it WITHOUT growing the typed-ref pool.
  //
  // Element references must be DISTINCT bindings. The stack-lowering
  // of array_literal calls bringToTop(elem, isLast)+pop() per element;
  // repeating the same binding inside the array confuses the use-count
  // analysis (the second repeated reference is also the "last use",
  // so the binding is consumed before the third bringToTop can find
  // it). Same generator-side constraint as twoDistinct() for bin_op.
  // Real frontend-emitted ANF never has duplicate refs in an
  // array_literal — `[a, a, a]` source lowers to three distinct
  // load_const bindings first.
  const len = rng.nextInt(1, 3);
  const elements: string[] = [];
  for (let i = 0; i < len; i++) {
    // Always emit a fresh const so element refs are guaranteed distinct.
    const fresh = emitConst(rng, ctx, 'bigint');
    elements.push(fresh.name);
  }
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty: 'bigint', // type is fictitious; the binding isn't referenced
    value: { kind: 'array_literal', elements },
  };
  return pushStmt(ctx, b);
}

function emitUpdateProp(rng: Rng, ctx: GenContext, prop: AnfProperty): TypedBinding {
  // update_prop is a STATEMENT — it pops a value from the stack but
  // doesn't push anything back. Treat it as a terminator: emit the
  // binding but do NOT add it to ctx.bindings (so no later binding
  // can mistakenly reference t<n> as if it were on the stack).
  const ty: ValType = prop.type === 'boolean' ? 'boolean' : 'bigint';
  const value = ty === 'boolean' ? ensureBool(rng, ctx) : ensureBigint(rng, ctx);
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty,
    value: { kind: 'update_prop', name: prop.name, value: value.name },
  };
  return pushStmt(ctx, b);
}

function emitAssert(rng: Rng, ctx: GenContext): TypedBinding {
  // Always rooted in a bool — either reuse a prior cmp / bool, or
  // freshly cmp two bigints. assert is a STATEMENT; the binding is
  // not safely referenceable.
  const cond = priorOf(rng, ctx, 'boolean') ?? emitBinOp(rng, ctx, 'cmp');
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty: 'boolean',
    value: { kind: 'assert', value: cond.name },
  };
  return pushStmt(ctx, b);
}

// ---------------------------------------------------------------------------
// fast-check arbitrary: random ANF program
// ---------------------------------------------------------------------------

interface GenOpts {
  maxMethods: number;
  maxBindingsPerMethod: number;
  maxProperties: number;
  maxParamsPerMethod: number;
}

function generateProgram(rng: Rng, opts: GenOpts): AnfProgram {
  const numProps = rng.nextInt(0, opts.maxProperties);
  const properties: AnfProperty[] = [];
  for (let i = 0; i < numProps; i++) {
    properties.push({
      name: `prop${i}`,
      type: 'bigint',
      readonly: false,
    });
  }

  const numMethods = rng.nextInt(1, opts.maxMethods);
  const methods: AnfMethod[] = [];
  for (let m = 0; m < numMethods; m++) {
    const numParams = rng.nextInt(0, opts.maxParamsPerMethod);
    const params: AnfParam[] = [];
    for (let p = 0; p < numParams; p++) {
      params.push({ name: `p${p}`, type: 'bigint' });
    }

    const ctx: GenContext = {
      body: [],
      bindings: [],
      properties,
      params,
      nextId: 0,
    };

    // Seed the body with at least one of every "always-available"
    // primitive so each method touches load_const + bin_op + assert.
    emitConst(rng, ctx, 'bigint');

    const numBindings = rng.nextInt(1, opts.maxBindingsPerMethod);
    for (let b = 0; b < numBindings; b++) {
      const choice = rng.nextInt(0, 11);
      try {
        if (choice === 0) emitConst(rng, ctx, 'bigint');
        else if (choice === 1) emitConst(rng, ctx, 'boolean');
        else if (choice === 2) emitBinOp(rng, ctx, 'bigint');
        else if (choice === 3) emitBinOp(rng, ctx, 'cmp');
        else if (choice === 4) emitBinOp(rng, ctx, 'bool');
        else if (choice === 5) emitUnaryOp(rng, ctx, 'bigint');
        else if (choice === 6) emitUnaryOp(rng, ctx, 'bool');
        else if (choice === 7 && params.length > 0) emitLoadParam(rng, ctx, pickAny(rng, params));
        else if (choice === 8 && properties.length > 0) emitLoadProp(rng, ctx, pickAny(rng, properties));
        else if (choice === 9) emitCallAbs(rng, ctx);
        else if (choice === 10) emitArrayLiteral(rng, ctx);
        else if (choice === 11 && properties.length > 0) emitUpdateProp(rng, ctx, pickAny(rng, properties));
        else emitConst(rng, ctx, 'bigint');
      } catch {
        // Defensive: a generation primitive that can't satisfy its
        // preconditions just falls back to a const. Keeps the
        // generator total.
        emitConst(rng, ctx, 'bigint');
      }
    }

    // Always end with an assert so the method has a meaningful
    // semantic effect and the stack-lowerer's terminator path is
    // exercised.
    emitAssert(rng, ctx);

    methods.push({
      name: m === 0 ? 'verify' : `m${m}`,
      params,
      body: ctx.body.map((b) => ({ name: b.name, value: b.value })),
      isPublic: true,
    });
  }

  return {
    contractName: 'FuzzAnf',
    properties,
    methods,
  };
}

const DEFAULT_GEN_OPTS: GenOpts = {
  maxMethods: 3,
  maxBindingsPerMethod: 15,
  maxProperties: 3,
  maxParamsPerMethod: 3,
};

/** fast-check arbitrary that emits a random ANF program. We use
 * fast-check ONLY for top-level reproducible sampling (seed +
 * `fc.sample`) — the per-program generation runs through our own
 * Mulberry32 PRNG so the harness doesn't depend on any specific
 * fast-check internal class (`fc.Random`, `fc.mersenne` are not
 * stable cross-version). The integer drawn from fast-check is the
 * per-program seed; identical `--seed` → identical corpus. */
function arbAnfProgram(opts: GenOpts = DEFAULT_GEN_OPTS): fc.Arbitrary<AnfProgram> {
  return fc.integer({ min: 0, max: 2 ** 31 - 1 }).map((seed) => {
    const rng = mulberry32(seed);
    return generateProgram(rng, opts);
  });
}

// ---------------------------------------------------------------------------
// Canonical JSON (loaded lazily from runar-ir-schema to avoid bootstrapping
// the workspace before the fuzzer starts).
// ---------------------------------------------------------------------------

type CanonicalJsonFn = (value: unknown) => string;
let _cachedCanon: CanonicalJsonFn | null = null;
async function loadCanonical(): Promise<CanonicalJsonFn> {
  if (_cachedCanon) return _cachedCanon;
  const entry = resolve(ROOT, 'packages/runar-ir-schema/src/index.ts');
  const mod = (await import(pathToFileURL(entry).href)) as Record<string, unknown>;
  const fn = mod.canonicalJsonStringify;
  if (typeof fn !== 'function') {
    throw new Error('runar-ir-schema does not export canonicalJsonStringify');
  }
  _cachedCanon = fn as CanonicalJsonFn;
  return _cachedCanon;
}

// ---------------------------------------------------------------------------
// TS in-process compile (skips passes 1–4 and runs only ANF→Stack→hex).
// ---------------------------------------------------------------------------

interface TsCompileFromAnf {
  (program: AnfProgram, opts?: { disableConstantFolding?: boolean }): { scriptHex: string };
}
let _cachedTsCompile: TsCompileFromAnf | null | undefined;
async function loadTsCompileFromAnf(): Promise<TsCompileFromAnf | null> {
  if (_cachedTsCompile !== undefined) return _cachedTsCompile;
  try {
    const entry = resolve(ROOT, 'packages/runar-compiler/src/index.ts');
    const mod = (await import(pathToFileURL(entry).href)) as Record<string, unknown>;
    if (typeof mod.compileFromANF === 'function') {
      _cachedTsCompile = mod.compileFromANF as TsCompileFromAnf;
      return _cachedTsCompile;
    }
  } catch {
    // fall through
  }
  _cachedTsCompile = null;
  return _cachedTsCompile;
}

// ---------------------------------------------------------------------------
// Native compiler binary discovery (mirrors `ir-differential.ts` /
// `runner.ts`).
// ---------------------------------------------------------------------------

function findExe(rel: string): string | null {
  const p = resolve(ROOT, rel);
  if (!existsSync(p)) return null;
  try {
    execFileSync(p, ['--help'], { stdio: 'pipe', timeout: 5000 });
    return p;
  } catch {
    return null;
  }
}

function findJavaJar(): string | null {
  const libs = resolve(ROOT, 'compilers/java/build/libs');
  if (!existsSync(libs)) return null;
  try {
    execFileSync('java', ['-version'], { stdio: 'pipe', timeout: 5000 });
  } catch {
    return null;
  }
  const preferred = join(libs, 'runar-java.jar');
  if (existsSync(preferred)) return preferred;
  try {
    for (const e of readdirSync(libs)) {
      if (e.startsWith('runar-java-compiler-') && e.endsWith('.jar')) {
        return join(libs, e);
      }
    }
  } catch { /* ignore */ }
  return null;
}

function hasRuby(): boolean {
  try {
    execFileSync('ruby', ['--version'], { stdio: 'pipe', timeout: 5000 });
    return existsSync(resolve(ROOT, 'compilers/ruby/bin/runar-compiler-ruby'));
  } catch {
    return false;
  }
}

function hasPython(): boolean {
  try {
    execFileSync('python3', ['--version'], { stdio: 'pipe', timeout: 5000 });
    return existsSync(resolve(ROOT, 'compilers/python/runar_compiler'));
  } catch {
    return false;
  }
}

function runProc(cmd: string, args: string[], opts: { cwd?: string; timeoutMs?: number } = {}): { stdout: string; stderr: string; code: number } {
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd ?? ROOT,
    timeout: opts.timeoutMs ?? 30_000,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    code: r.status ?? -1,
  };
}

// ---------------------------------------------------------------------------
// Per-tier compile-from-IR dispatch. Each returns the hex script (lowercase,
// trimmed) on success or `null` on failure.
// ---------------------------------------------------------------------------

interface TierContext {
  goBin: string | null;
  rustBin: string | null;
  zigBin: string | null;
  rubyBin: string | null;
  pythonAvail: boolean;
  javaJar: string | null;
  tsCompile: TsCompileFromAnf | null;
}

async function initTierContext(): Promise<TierContext> {
  return {
    goBin: findExe('compilers/go/runar-go'),
    rustBin: findExe('compilers/rust/target/release/runar-compiler-rust'),
    zigBin: findExe('compilers/zig/zig-out/bin/runar-zig'),
    rubyBin: hasRuby() ? resolve(ROOT, 'compilers/ruby/bin/runar-compiler-ruby') : null,
    pythonAvail: hasPython(),
    javaJar: findJavaJar(),
    tsCompile: await loadTsCompileFromAnf(),
  };
}

function runIrFile(tier: CompilerName, irFile: string, ctx: TierContext): string | null {
  const fold = '--disable-constant-folding';
  if (tier === 'go') {
    if (!ctx.goBin) return null;
    const r = runProc(ctx.goBin, ['--ir', irFile, '--hex', fold]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'rust') {
    if (!ctx.rustBin) return null;
    const r = runProc(ctx.rustBin, ['--ir', irFile, '--hex', fold]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'zig') {
    if (!ctx.zigBin) return null;
    // The Zig compiler doesn't ship a top-level `--ir` flag; it
    // dispatches by file extension under `--source` (`.json` →
    // ANF-IR consumer mode). Filename matters, so write to a `.json`
    // path. We re-use the same canonical IR bytes from `irFile`.
    const r = runProc(ctx.zigBin, ['--source', irFile, '--hex', fold]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'python') {
    if (!ctx.pythonAvail) return null;
    const r = runProc('python3', ['-m', 'runar_compiler', '--ir', irFile, '--hex', fold], {
      cwd: resolve(ROOT, 'compilers/python'),
    });
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'ruby') {
    if (!ctx.rubyBin) return null;
    const r = runProc('ruby', [ctx.rubyBin, '--ir', irFile, '--hex', fold]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'java') {
    if (!ctx.javaJar) return null;
    const r = runProc('java', ['-jar', ctx.javaJar, '--ir', irFile, '--hex', fold]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  // 'ts'
  return null;
}

function runTsInProcess(program: AnfProgram, ctx: TierContext): string | null {
  if (!ctx.tsCompile) return null;
  try {
    const r = ctx.tsCompile(program, { disableConstantFolding: true });
    return r.scriptHex ? r.scriptHex.toLowerCase() : null;
  } catch (e) {
    if (process.env.FUZZ_DEBUG) console.error('ts-compile throw:', (e as Error).message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Findings persistence
// ---------------------------------------------------------------------------

interface Finding {
  seed: number | undefined;
  programIndex: number;
  programJson: string;
  outputs: Partial<Record<CompilerName, string>>;
  reason: string;
}

function saveFinding(dir: string, f: Finding): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const out = join(dir, ts);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'program.json'), f.programJson, 'utf-8');
  for (const [tier, hex] of Object.entries(f.outputs)) {
    if (hex !== undefined) writeFileSync(join(out, `hex-${tier}.txt`), hex + '\n', 'utf-8');
  }
  writeFileSync(
    join(out, 'finding.json'),
    JSON.stringify(
      { seed: f.seed, programIndex: f.programIndex, reason: f.reason },
      null,
      2,
    ) + '\n',
    'utf-8',
  );
  return out;
}

// ---------------------------------------------------------------------------
// Public harness
// ---------------------------------------------------------------------------

export interface AnfDifferentialOptions {
  numPrograms: number;
  seed?: number;
  /** Defaults to all 7 tiers. Skipped tiers are silently ignored. */
  tiers?: readonly CompilerName[];
  /** Treat tiers with no installed binary as "skip", not "fail". Default: true. */
  skipMissingTiers?: boolean;
  /** Where to dump failing cases. */
  findingsDir?: string;
  /** Wall-clock budget in ms; harness returns early once exceeded. */
  timeBudgetMs?: number;
  /** Verbose per-program log. */
  verbose?: boolean;
  /** Generator knobs. */
  genOpts?: Partial<GenOpts>;
}

export interface AnfDifferentialReport {
  totalPrograms: number;
  programsRun: number;
  mismatchCount: number;
  earlyStop: boolean;
  perTierAvailable: Partial<Record<CompilerName, boolean>>;
  findings: string[];
  durationMs: number;
}

export async function runAnfDifferential(
  opts: AnfDifferentialOptions,
): Promise<AnfDifferentialReport> {
  const tiers = opts.tiers ?? ALL_TIERS;
  const findingsDir = opts.findingsDir ?? join(__dirname, '..', 'fuzz-findings-anf');
  const tmpDir = join(__dirname, '..', '.tmp', 'fuzz-anf');
  if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });

  const canon = await loadCanonical();
  const ctx = await initTierContext();
  const perTierAvailable: Partial<Record<CompilerName, boolean>> = {
    ts: !!ctx.tsCompile,
    go: !!ctx.goBin,
    rust: !!ctx.rustBin,
    python: ctx.pythonAvail,
    zig: !!ctx.zigBin,
    ruby: !!ctx.rubyBin,
    java: !!ctx.javaJar,
  };

  const genOpts: GenOpts = { ...DEFAULT_GEN_OPTS, ...opts.genOpts };

  // Build the program corpus eagerly using fc.sample so a `--seed` value
  // is reproducible. fast-check's `numRuns` controls sample size.
  const programs = fc.sample(arbAnfProgram(genOpts), {
    numRuns: opts.numPrograms,
    seed: opts.seed,
  });

  const start = Date.now();
  let mismatchCount = 0;
  const findings: string[] = [];
  let programsRun = 0;
  let earlyStop = false;

  for (let i = 0; i < programs.length; i++) {
    if (opts.timeBudgetMs !== undefined && Date.now() - start > opts.timeBudgetMs) {
      earlyStop = true;
      break;
    }

    const program = programs[i]!;
    programsRun += 1;

    // 1) canonicalise to bytes
    let canonical: string;
    try {
      canonical = canon(program);
    } catch (e) {
      // A generator bug producing un-canonicalisable IR; surface it as a
      // mismatch so it can't silently disappear.
      mismatchCount += 1;
      const dir = saveFinding(findingsDir, {
        seed: opts.seed,
        programIndex: i,
        programJson: jsonReplacerStringify(program),
        outputs: {},
        reason: `canonicalJsonStringify threw: ${(e as Error).message}`,
      });
      findings.push(dir);
      continue;
    }

    // Convenience: canonical bytes go straight to disk so any failure
    // can be replayed via `--ir <findings/.../program.json>` against any
    // tier offline.
    const irFile = join(tmpDir, `program-${process.pid}-${i}.json`);
    writeFileSync(irFile, canonical, 'utf-8');

    // 2) collect per-tier hex
    const outputs: Partial<Record<CompilerName, string>> = {};
    const skipped: CompilerName[] = [];
    const failed: CompilerName[] = [];

    for (const tier of tiers) {
      let hex: string | null;
      if (tier === 'ts') {
        hex = runTsInProcess(program, ctx);
      } else {
        hex = runIrFile(tier, irFile, ctx);
      }

      if (hex === null) {
        // Distinguish "no binary" (skip) from "binary present, rejected"
        // (failure). perTierAvailable tells us the difference.
        if (perTierAvailable[tier] === false) {
          if (!opts.skipMissingTiers && opts.skipMissingTiers !== undefined) {
            failed.push(tier);
          } else {
            skipped.push(tier);
          }
        } else {
          failed.push(tier);
        }
      } else {
        outputs[tier] = hex;
      }
    }

    // 3) compare
    const tierKeys = Object.keys(outputs) as CompilerName[];
    if (tierKeys.length >= 2) {
      const ref = outputs[tierKeys[0]!]!;
      const divergent: CompilerName[] = [];
      for (let j = 1; j < tierKeys.length; j++) {
        if (outputs[tierKeys[j]!] !== ref) divergent.push(tierKeys[j]!);
      }
      if (divergent.length > 0) {
        mismatchCount += 1;
        const dir = saveFinding(findingsDir, {
          seed: opts.seed,
          programIndex: i,
          programJson: canonical,
          outputs,
          reason: `hex divergence: ${tierKeys[0]} vs ${divergent.join(',')}`,
        });
        findings.push(dir);
        if (opts.verbose) {
          console.log(`  [${i}] MISMATCH: ${tierKeys[0]} vs ${divergent.join(',')} -> ${dir}`);
        }
      } else if (opts.verbose) {
        console.log(`  [${i}] OK (${tierKeys.join(',')})`);
      }
    } else if (failed.length > 0) {
      // Less than 2 tiers produced output AND one or more tier with an
      // installed binary failed — flag it.
      mismatchCount += 1;
      const dir = saveFinding(findingsDir, {
        seed: opts.seed,
        programIndex: i,
        programJson: canonical,
        outputs,
        reason: `tier(s) rejected program: ${failed.join(',')}; accepted: ${tierKeys.join(',')}`,
      });
      findings.push(dir);
      if (opts.verbose) {
        console.log(`  [${i}] REJECTED by ${failed.join(',')} -> ${dir}`);
      }
    } else if (opts.verbose) {
      console.log(`  [${i}] SKIPPED (only ${tierKeys.length} tier(s) available)`);
    }

    // Best-effort cleanup of the per-program IR temp file. If the
    // program produced a finding, the canonical bytes are already
    // copied into the findings dir (`program.json`), so the temp can
    // always be removed.
    try { unlinkSync(irFile); } catch { /* ignore */ }
  }

  return {
    totalPrograms: programs.length,
    programsRun,
    mismatchCount,
    earlyStop,
    perTierAvailable,
    findings,
    durationMs: Date.now() - start,
  };
}

// JSON.stringify can't serialise bigint; provide a replacer-aware stringify
// used only for finding artifacts (the canonical path uses canonicalJsonStringify).
function jsonReplacerStringify(v: unknown): string {
  return JSON.stringify(v, (_k, val) => (typeof val === 'bigint' ? val.toString() + 'n' : val), 2);
}
