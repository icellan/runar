/**
 * SCOPE (testing-gap remediation, plan design principle P8): this fuzzer is
 * HORIZONTAL — its oracle is TIER AGREEMENT, not correctness. Seven tiers that
 * share one bug agree with each other perfectly and this mode stays green;
 * both 2026-08 fund-safety bugs were of exactly that shape. It is necessary and
 * it is NOT fund-safety-complete on its own. The absolute oracles are
 * `--execute` / `--tri-modal` (stateless fragments) and `--spend-oracle`
 * (full deploy->call transaction context + an independent post-state pin).
 * See `conformance/fuzzer/README.md`.
 *
 * GENERATOR REACH (2026-08-06). `this.addOutput(...)` used to be unreachable
 * from every IR-based generator: `spend-shapes.ts` exercised it under the
 * ABSOLUTE post-state oracle, but that harness renders TypeScript only and
 * therefore said nothing about the other six frontends. `contract-ir.ts` now
 * carries an `add_output` node, all seven renderers emit it, and the stateful
 * generator draws it on roughly three quarters of stateful methods — so the
 * intrinsic's CROSS-TIER parity is gated for the first time, by the
 * `--ir --hex --stateful` PR gate added in `.github/workflows/fuzzer-nightly.yml`.
 * It is load-bearing, not decorative: removing the node from a generated
 * contract changes the emitted script in every tier.
 *
 * That node lives in the CONTRACT-level generator, not here. This module
 * generates raw ANF directly and feeds it to each tier's `--ir <json>` loader,
 * a different entry point; `add_output` is already in all seven loaders'
 * known-kinds sets, so extending THIS generator to emit it needs no compiler
 * change if someone wants that coverage too.
 */

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
 * passes* across all 7 tiers (fold-OFF; `--fold-on` compiles rendered
 * source instead — see `renderAnfProgramToTypeScript`) — the path that the existing source
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
 * persisted under `conformance/fuzz-findings-anf/<timestamp>-<programIndex>/`
 * (the `programIndex` suffix keeps two findings in the same millisecond from
 * colliding — N-228) so the source program + per-tier hex output can be
 * replayed offline.
 */

import fc from 'fast-check';
import {
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
  readFileSync,
  unlinkSync,
} from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { reduceAnfProgram, type AnfProgram as ReducibleAnfProgram } from './reduce.js';

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
//
// WHERE THE EXCLUDED KINDS ACTUALLY GET COVERED (corrected 2026-08-06 — the
// previous blanket hand-off to "the source-based fuzzers in
// `ir-differential.ts`" was FALSE for every kind listed here):
//
//   * `if` / `loop` — true as of 2026-08-06, and NOT before it. Until then
//     `arbIfStmtIR` emitted branch arms containing a single `assert` and
//     nothing else, and no method generator emitted a `ForStmt` at all, so
//     the contract-level `--ir` fuzzer had compiled zero loops and zero
//     assigning branch arms in any tier. `arbGeneratedContract` now draws
//     from `BRANCH_SHAPES` and `IR_LOOP_SHAPES`
//     (`packages/runar-testing/src/fuzzer/generator.ts`), proved reachable
//     at a fixed seed by
//     `packages/runar-testing/src/__tests__/fuzzer-branch-shapes.test.ts`.
//
//   * four of the six STATEFUL-only kinds ARE covered, now that
//     `ir-differential.ts`'s `--ir --hex --stateful` PR gate
//     (`.github/workflows/fuzzer-nightly.yml:301-314`) runs
//     `arbGeneratedStatefulContract` in CI. `add_output` is covered
//     directly (see the header at the top of this file: `contract-ir.ts`
//     carries an `add_output` node and all seven renderers emit it).
//     `check_preimage`, `deserialize_state`, and `get_state_script` are
//     covered INDIRECTLY: the compiler auto-injects all three into every
//     StatefulSmartContract method's lowering regardless of what the
//     generator itself emits (`04-anf-lower.ts`), so any generated stateful
//     contract compiled through that gate exercises them cross-tier too.
//     `add_raw_output` and `add_data_output` remain uncovered — neither
//     `contract-ir.ts` nor any other generator emits either kind, and
//     nothing auto-injects them. Their real coverage is (a) the
//     hand-written conformance fixtures, which do give 9-format / 7-tier
//     parity, and (b) for `add_output` specifically,
//     `conformance/fuzzer/spend-shapes.ts`, whose randomized `addOutput`
//     shapes additionally get an ABSOLUTE post-state oracle but are
//     rendered to TypeScript only — one tier, not seven.
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
// Division / modulo — routed through a DEDICATED emitter (emitDivModOp)
// with a guaranteed non-zero RHS rather than the generic twoDistinct()
// picker, so `x / 0` / `x % 0` never appear in the generated corpus.
const DIV_MOD_OPS = ['/', '%'] as const;
// Shift ops — RHS is a small non-negative literal amount (emitShiftOp),
// matching the consensus rule that OP_LSHIFT/OP_RSHIFT's shift-amount
// operand must be non-negative (see @bsv/sdk Spend.ts, which hard-rejects
// a negative shift amount).
const SHIFT_OPS = ['<<', '>>'] as const;
// Bitwise ops — plain twoDistinct() operands, same as BIGINT_BIN_OPS.
const BITWISE_BIN_OPS = ['&', '|', '^'] as const;

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

/**
 * A fresh, guaranteed-non-zero `load_const` bigint binding (small magnitude,
 * either sign). Used as the RHS of `/` / `%` so a generated program's
 * division is always well-defined — never routed through `twoDistinct()`
 * (which can pick an existing `load_const 0` binding).
 */
function emitNonZeroConst(rng: Rng, ctx: GenContext): TypedBinding {
  const name = freshName(ctx);
  const mag = rng.nextInt(1, 20);
  const value = rng.nextBoolean() ? BigInt(mag) : BigInt(-mag);
  const b: TypedBinding = { name, ty: 'bigint', value: { kind: 'load_const', value } };
  return pushRef(ctx, b);
}

/** `/` or `%` with a guaranteed non-zero literal RHS (see DIV_MOD_OPS). */
function emitDivModOp(rng: Rng, ctx: GenContext): TypedBinding {
  const left = ensureBigint(rng, ctx);
  const right = emitNonZeroConst(rng, ctx);
  const op = pickAny(rng, DIV_MOD_OPS);
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty: 'bigint',
    value: { kind: 'bin_op', op, left: left.name, right: right.name },
  };
  return pushRef(ctx, b);
}

/**
 * `<<` or `>>` with a small non-negative literal shift amount (see
 * SHIFT_OPS) — a fresh `load_const` rather than a `twoDistinct()` pick so
 * the amount can never be negative (a negative shift amount is a hard
 * consensus-level reject, uninteresting for a byte-parity probe).
 */
function emitShiftOp(rng: Rng, ctx: GenContext): TypedBinding {
  const left = ensureBigint(rng, ctx);
  const amtName = freshName(ctx);
  const amt: TypedBinding = pushRef(ctx, {
    name: amtName,
    ty: 'bigint',
    value: { kind: 'load_const', value: BigInt(rng.nextInt(0, 7)) },
  });
  const op = pickAny(rng, SHIFT_OPS);
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty: 'bigint',
    value: { kind: 'bin_op', op, left: left.name, right: amt.name },
  };
  return pushRef(ctx, b);
}

/** `&`, `|`, or `^` — plain twoDistinct() operands (see BITWISE_BIN_OPS). */
function emitBitwiseOp(rng: Rng, ctx: GenContext): TypedBinding {
  const { left, right } = twoDistinct(rng, ctx, 'bigint');
  const op = pickAny(rng, BITWISE_BIN_OPS);
  const name = freshName(ctx);
  const b: TypedBinding = {
    name,
    ty: 'bigint',
    value: { kind: 'bin_op', op, left: left.name, right: right.name },
  };
  return pushRef(ctx, b);
}

function emitUnaryOp(rng: Rng, ctx: GenContext, kind: 'bigint' | 'bool'): TypedBinding {
  if (kind === 'bigint') {
    const operand = ensureBigint(rng, ctx);
    const name = freshName(ctx);
    // '~' (bitwise NOT) alongside the existing '-' (negate) — both are
    // legal Rúnar unary ops on bigint (UnaryOp = '!' | '-' | '~').
    const op = rng.nextBoolean() ? '-' : '~';
    const b: TypedBinding = {
      name,
      ty: 'bigint',
      value: { kind: 'unary_op', op, operand: operand.name },
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
      const choice = rng.nextInt(0, 14);
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
        else if (choice === 12) emitDivModOp(rng, ctx);
        else if (choice === 13) emitShiftOp(rng, ctx);
        else if (choice === 14) emitBitwiseOp(rng, ctx);
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
// Fold-ON mode: render the ANF program to `.runar.ts` (N-003).
//
// Every tier forces constant folding OFF on `--ir` input — deliberately, so the
// IR path stays byte-identical to the fold-OFF goldens — so fold-ON cannot be
// exercised through `--ir` at all. Running the `--ir` argv without
// `--disable-constant-folding` used to be this harness's "fold-ON" mode, and it
// re-ran fold-OFF byte for byte. Fold-ON instead renders each generated program
// to TypeScript source and compiles it from SOURCE in every tier with folding
// on (each CLI's default), which is the only path on which folding runs.
//
// The rendered program is DERIVED from the ANF corpus, not the same IR: each
// frontend re-lowers it. Leaves (constants, params, props no method writes) and
// single-use pure expressions are inlined into their use, because the folder
// does not see through a named local (`const v = 2n` lowers to an `@ref:`
// alias it skips), so naming every binding would hide every fold. A binding
// used more than once, or never, becomes a `const v<n>` (`t<n>` is reserved for
// compiler temps). A prop some method writes is read into a local where the ANF
// read it, so moving the read cannot reorder it past the write. Any
// `update_prop` makes the contract a StatefulSmartContract with that prop
// mutable; everything else is readonly.
// ---------------------------------------------------------------------------

function anfValueRefs(v: AnfValue): string[] {
  switch (v.kind) {
    case 'bin_op': return [v.left, v.right];
    case 'unary_op': return [v.operand];
    case 'call': return v.args;
    case 'array_literal': return v.elements;
    case 'assert': return [v.value];
    case 'update_prop': return [v.value];
    default: return [];
  }
}

const BOOL_RESULT_OPS = new Set(['===', '!==', '<', '>', '<=', '>=', '&&', '||']);

export function renderAnfProgramToTypeScript(program: AnfProgram): string {
  const written = new Set<string>();
  for (const m of program.methods) {
    for (const b of m.body) if (b.value.kind === 'update_prop') written.add(b.value.name);
  }
  const parentClass = written.size > 0 ? 'StatefulSmartContract' : 'SmartContract';
  const propType = new Map(program.properties.map((p) => [p.name, p.type]));
  let usesAbs = false;

  const methods = program.methods.map((m) => {
    const uses = new Map<string, number>();
    for (const b of m.body) {
      for (const r of anfValueRefs(b.value)) uses.set(r, (uses.get(r) ?? 0) + 1);
    }
    const paramType = new Map(m.params.map((p) => [p.name, p.type]));
    const types = new Map<string, string>();
    const inlined = new Map<string, string>();
    const ref = (name: string): string => inlined.get(name) ?? name.replace(/^t(?=\d+$)/, 'v');
    const lines: string[] = [];

    for (const b of m.body) {
      const v = b.value;
      let expr: string;
      let ty = 'bigint';
      let leaf = false;
      switch (v.kind) {
        case 'load_const': {
          if (typeof v.value === 'boolean') {
            expr = String(v.value);
            ty = 'boolean';
          } else {
            const n = BigInt(v.value);
            expr = n < 0n ? `(${n}n)` : `${n}n`;
          }
          leaf = true;
          break;
        }
        case 'load_param':
          expr = v.name;
          ty = paramType.get(v.name) ?? 'bigint';
          leaf = true;
          break;
        case 'load_prop':
          expr = `this.${v.name}`;
          ty = propType.get(v.name) ?? 'bigint';
          leaf = !written.has(v.name);
          break;
        case 'bin_op':
          expr = `(${ref(v.left)} ${v.op} ${ref(v.right)})`;
          ty = BOOL_RESULT_OPS.has(v.op) ? 'boolean' : 'bigint';
          break;
        case 'unary_op':
          expr = `(${v.op}${ref(v.operand)})`;
          ty = v.op === '!' ? 'boolean' : 'bigint';
          break;
        case 'call':
          if (v.func === 'abs') usesAbs = true;
          expr = `${v.func}(${v.args.map(ref).join(', ')})`;
          break;
        case 'array_literal':
          lines.push(`    const ${ref(b.name)} = [${v.elements.map(ref).join(', ')}];`);
          continue;
        case 'assert':
          lines.push(`    assert(${ref(v.value)});`);
          continue;
        case 'update_prop':
          lines.push(`    this.${v.name} = ${ref(v.value)};`);
          continue;
      }
      types.set(b.name, ty);
      const n = uses.get(b.name) ?? 0;
      if (n > 0 && (leaf || (n === 1 && v.kind !== 'load_prop'))) {
        inlined.set(b.name, expr);
      } else {
        lines.push(`    const ${ref(b.name)}: ${ty} = ${expr};`);
      }
    }
    const params = m.params.map((p) => `${p.name}: ${p.type}`).join(', ');
    return [`  public ${m.name}(${params}) {`, ...lines, '  }'].join('\n');
  });

  const imports = [parentClass, 'assert', ...(usesAbs ? ['abs'] : [])];
  const props = program.properties.map(
    (p) => `  ${written.has(p.name) ? '' : 'readonly '}${p.name}: ${p.type};`,
  );
  const ctorParams = program.properties.map((p) => `${p.name}: ${p.type}`).join(', ');
  const ctor = [
    `  constructor(${ctorParams}) {`,
    `    super(${program.properties.map((p) => p.name).join(', ')});`,
    ...program.properties.map((p) => `    this.${p.name} = ${p.name};`),
    '  }',
  ];
  return [
    `import { ${imports.join(', ')} } from 'runar-lang';`,
    '',
    `class ${program.contractName} extends ${parentClass} {`,
    ...props,
    ...(props.length > 0 ? [''] : []),
    ...ctor,
    '',
    methods.join('\n\n'),
    '}',
    '',
  ].join('\n');
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

/** TS in-process compile from SOURCE — the fold-ON path (N-003). */
interface TsCompileSource {
  (source: string, opts: { fileName: string; disableConstantFolding: boolean }): {
    success: boolean;
    artifact?: { script?: string };
  };
}
let _cachedTsSource: TsCompileSource | null | undefined;
async function loadTsCompileSource(): Promise<TsCompileSource | null> {
  if (_cachedTsSource !== undefined) return _cachedTsSource;
  try {
    const entry = resolve(ROOT, 'packages/runar-compiler/src/index.ts');
    const mod = (await import(pathToFileURL(entry).href)) as Record<string, unknown>;
    _cachedTsSource = typeof mod.compile === 'function' ? (mod.compile as TsCompileSource) : null;
  } catch {
    _cachedTsSource = null;
  }
  return _cachedTsSource;
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
  tsCompileSource: TsCompileSource | null;
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
    tsCompileSource: await loadTsCompileSource(),
  };
}

function runIrFile(
  tier: CompilerName,
  irFile: string,
  ctx: TierContext,
  disableConstantFolding: boolean,
): string | null {
  // fold-OFF: pass `--disable-constant-folding`. fold-ON: omit it so each
  // native tier runs its default (folding-enabled) pipeline. The flag is
  // spliced into argv only when set so the empty case doesn't leave a
  // stray `''` arg.
  const foldArgs = disableConstantFolding ? ['--disable-constant-folding'] : [];
  if (tier === 'go') {
    if (!ctx.goBin) return null;
    const r = runProc(ctx.goBin, ['--ir', irFile, '--hex', ...foldArgs]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'rust') {
    if (!ctx.rustBin) return null;
    const r = runProc(ctx.rustBin, ['--ir', irFile, '--hex', ...foldArgs]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'zig') {
    if (!ctx.zigBin) return null;
    // The Zig compiler doesn't ship a top-level `--ir` flag; it
    // dispatches by file extension under `--source` (`.json` →
    // ANF-IR consumer mode). Filename matters, so write to a `.json`
    // path. We re-use the same canonical IR bytes from `irFile`.
    const r = runProc(ctx.zigBin, ['--source', irFile, '--hex', ...foldArgs]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'python') {
    if (!ctx.pythonAvail) return null;
    const r = runProc('python3', ['-m', 'runar_compiler', '--ir', irFile, '--hex', ...foldArgs], {
      cwd: resolve(ROOT, 'compilers/python'),
    });
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'ruby') {
    if (!ctx.rubyBin) return null;
    const r = runProc('ruby', [ctx.rubyBin, '--ir', irFile, '--hex', ...foldArgs]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  if (tier === 'java') {
    if (!ctx.javaJar) return null;
    const r = runProc('java', ['-jar', ctx.javaJar, '--ir', irFile, '--hex', ...foldArgs]);
    return r.code === 0 ? r.stdout.trim().toLowerCase() : null;
  }
  // 'ts'
  return null;
}

function runTsInProcess(
  program: AnfProgram,
  ctx: TierContext,
  disableConstantFolding: boolean,
): string | null {
  if (!ctx.tsCompile) return null;
  try {
    const r = ctx.tsCompile(program, { disableConstantFolding });
    return r.scriptHex ? r.scriptHex.toLowerCase() : null;
  } catch (e) {
    if (process.env.FUZZ_DEBUG) console.error('ts-compile throw:', (e as Error).message);
    return null;
  }
}

/**
 * Fold-ON (N-003): compile a rendered `.runar.ts` from SOURCE with each tier's
 * default pipeline, i.e. constant folding ON (no `--disable-constant-folding`).
 */
function runSourceFile(tier: CompilerName, srcFile: string, ctx: TierContext): string | null {
  let r: { stdout: string; code: number } | null = null;
  if (tier === 'go' && ctx.goBin) r = runProc(ctx.goBin, ['--source', srcFile, '--hex']);
  if (tier === 'rust' && ctx.rustBin) r = runProc(ctx.rustBin, ['--source', srcFile, '--hex']);
  if (tier === 'zig' && ctx.zigBin) r = runProc(ctx.zigBin, ['--source', srcFile, '--hex']);
  if (tier === 'python' && ctx.pythonAvail) {
    r = runProc('python3', ['-m', 'runar_compiler', '--source', srcFile, '--hex'], {
      cwd: resolve(ROOT, 'compilers/python'),
    });
  }
  if (tier === 'ruby' && ctx.rubyBin) r = runProc('ruby', [ctx.rubyBin, '--source', srcFile, '--hex']);
  if (tier === 'java' && ctx.javaJar) r = runProc('java', ['-jar', ctx.javaJar, '--source', srcFile, '--hex']);
  if (tier === 'ts') return runTsSource(srcFile, ctx.tsCompileSource, false);
  return r && r.code === 0 ? r.stdout.trim().toLowerCase() : null;
}

function runTsSource(
  srcFile: string,
  compile: TsCompileSource | null,
  disableConstantFolding: boolean,
): string | null {
  if (!compile) return null;
  try {
    const r = compile(readFileSync(srcFile, 'utf-8'), { fileName: srcFile, disableConstantFolding });
    return r.success && r.artifact?.script ? r.artifact.script.toLowerCase() : null;
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
  /** Fold-ON mode: the rendered `.runar.ts` every tier compiled (N-003). */
  source?: string;
  outputs: Partial<Record<CompilerName, string>>;
  reason: string;
  /** Delta-debugged reproducer (F-173); absent if shrinking failed. */
  reduced?: {
    programJson: string;
    /** Fold-ON mode: the reduced program's rendered `.runar.ts`. */
    source?: string;
    outputs: Partial<Record<CompilerName, string>>;
    reason: string;
    originalBindings: number;
    reducedBindings: number;
  };
}

function countBindings(program: AnfProgram): number {
  return program.methods.reduce((n, m) => n + m.body.length, 0);
}

function saveFinding(dir: string, f: Finding): string {
  // N-228: the millisecond-resolution timestamp alone collides when the
  // harness's tight synchronous per-program loop produces two mismatches
  // inside the same millisecond — `mkdirSync(..., {recursive: true})` doesn't
  // fail on an existing dir, so the second finding's files would silently
  // overwrite the first's. `programIndex` is unique within a single run, so
  // appending it guarantees a distinct directory per finding.
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const out = join(dir, `${ts}-${f.programIndex}`);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'program.json'), f.programJson, 'utf-8');
  if (f.source !== undefined) writeFileSync(join(out, 'program.runar.ts'), f.source, 'utf-8');
  for (const [tier, hex] of Object.entries(f.outputs)) {
    if (hex !== undefined) writeFileSync(join(out, `hex-${tier}.txt`), hex + '\n', 'utf-8');
  }
  writeFindingJson(out, f);
  return out;
}

/**
 * Add the shrunk reproducer to an already-saved finding dir. Called AFTER
 * `saveFinding` so the original is on disk before a (possibly long) shrink
 * starts and survives the job being killed mid-reduction.
 */
function saveReduced(out: string, f: Finding): void {
  if (!f.reduced) return;
  writeFileSync(join(out, 'program-reduced.json'), f.reduced.programJson, 'utf-8');
  if (f.reduced.source !== undefined) {
    writeFileSync(join(out, 'program-reduced.runar.ts'), f.reduced.source, 'utf-8');
  }
  for (const [tier, hex] of Object.entries(f.reduced.outputs)) {
    if (hex !== undefined) writeFileSync(join(out, `hex-${tier}-reduced.txt`), hex + '\n', 'utf-8');
  }
  writeFindingJson(out, f);
}

function writeFindingJson(out: string, f: Finding): void {
  writeFileSync(
    join(out, 'finding.json'),
    JSON.stringify(
      {
        seed: f.seed,
        programIndex: f.programIndex,
        reason: f.reason,
        ...(f.reduced
          ? {
              reducedReason: f.reduced.reason,
              originalBindings: f.reduced.originalBindings,
              reducedBindings: f.reduced.reducedBindings,
            }
          : {}),
      },
      null,
      2,
    ) + '\n',
    'utf-8',
  );
}

// ---------------------------------------------------------------------------
// Per-program tier-result classification (finding #16).
//
// Pulled out of the main loop so the "is this program a mismatch?" decision
// is independently unit-testable with synthetic tier outputs, instead of
// only reachable by driving the full generate-and-compile pipeline.
//
// A program is a mismatch when EITHER:
//   - two or more tiers produced output and they disagree (existing hex-
//     divergence check), OR
//   - one or more tiers with an installed binary FAILED/rejected the
//     program, REGARDLESS of how many other tiers agreed. Previously this
//     was only checked when fewer than 2 tiers produced output, so a tier
//     that crashed while >=2 OTHER tiers agreed was silently dropped —
//     contradicting the harness's documented contract ("fails the job on
//     ... any compiler crash that doesn't reproduce on every other tier").
//
// `failed` (binary present, rejected the program) is intentionally
// distinct from tiers that were never run (no installed binary /
// `skipMissingTiers`) — see the `perTierAvailable` / `skipped` split in the
// caller. Only `failed` tiers count toward a mismatch.
// ---------------------------------------------------------------------------

export type ProgramClassification =
  | { status: 'ok' }
  | { status: 'mismatch'; reason: string }
  | { status: 'insufficient' };

export function classifyTierResults(
  outputs: Partial<Record<CompilerName, string>>,
  failed: readonly CompilerName[],
): ProgramClassification {
  const tierKeys = Object.keys(outputs) as CompilerName[];

  if (tierKeys.length >= 2) {
    const ref = outputs[tierKeys[0]!]!;
    const divergent: CompilerName[] = [];
    for (let j = 1; j < tierKeys.length; j++) {
      if (outputs[tierKeys[j]!] !== ref) divergent.push(tierKeys[j]!);
    }

    const reasons: string[] = [];
    if (divergent.length > 0) {
      reasons.push(`hex divergence: ${tierKeys[0]} vs ${divergent.join(',')}`);
    }
    if (failed.length > 0) {
      reasons.push(
        `tier(s) crashed/rejected while ${tierKeys.length} other tier(s) agreed: ${failed.join(',')}`,
      );
    }
    if (reasons.length > 0) {
      return { status: 'mismatch', reason: reasons.join('; ') };
    }
    return { status: 'ok' };
  }

  if (failed.length > 0) {
    // Fewer than 2 tiers produced output AND one or more tier with an
    // installed binary failed — flag it.
    return {
      status: 'mismatch',
      reason: `tier(s) rejected program: ${failed.join(',')}; accepted: ${tierKeys.join(',')}`,
    };
  }

  return { status: 'insufficient' };
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
  /**
   * `true` (default): fold-OFF — every tier compiles the canonical ANF through
   * its `--ir` entry point with `--disable-constant-folding`, matching the
   * checked-in fold-OFF goldens.
   * `false`: fold-ON — every tier compiles `renderAnfProgramToTypeScript(program)`
   * from SOURCE (`--source <file>.runar.ts --hex`, TS via `compile()`) with
   * folding on. Not via `--ir`: every tier forces folding off on IR input, so
   * that path cannot fold (N-003). Either mode must produce byte-identical hex
   * across every available tier.
   */
  disableConstantFolding?: boolean;
  /** Verbose per-program log. */
  verbose?: boolean;
  /** Generator knobs. */
  genOpts?: Partial<GenOpts>;
  /**
   * Test seam: compile one program in one tier, returning lowercase hex or
   * `null` (rejected). When set it replaces EVERY tier's real compiler
   * (including the in-process TS one), every requested tier counts as
   * available, and no binary discovery runs. Lets a hermetic test inject a
   * known divergence; production callers leave it unset.
   */
  compileTier?: (
    tier: CompilerName,
    program: AnfProgram,
    /** fold-OFF: the canonical IR `.json`; fold-ON: the rendered `.runar.ts`. */
    inputFile: string,
    disableConstantFolding: boolean,
  ) => string | null;
}

export interface AnfDifferentialReport {
  totalPrograms: number;
  programsRun: number;
  mismatchCount: number;
  earlyStop: boolean;
  perTierAvailable: Partial<Record<CompilerName, boolean>>;
  findings: string[];
  durationMs: number;
  /**
   * Fold-ON mode: programs whose TS bytes changed when folding was switched on
   * (same rendered source, TS compiler, fold-ON vs fold-OFF). Zero across a
   * whole fold-ON run means the mode folded nothing. Always 0 in fold-OFF mode.
   */
  foldedPrograms: number;
}

/**
 * Decide whether a requested tier that produced no output (`hex === null`) is a
 * FAILURE or a SKIP. A tier whose binary is genuinely unavailable
 * (`available === false`) FAILS the run by default — silently dropping it means
 * cross-tier divergences involving that tier go untested (audit #18); only an
 * EXPLICIT `skipMissingTiers === true` (e.g. local dev without every toolchain)
 * downgrades it to a skip. If the binary IS available (or availability is
 * unknown), null output means the tier ran and rejected the program = a failure.
 */
export function classifyUnavailableTier(
  available: boolean | undefined,
  skipMissingTiers: boolean | undefined,
): 'failed' | 'skipped' {
  if (available === false) {
    return skipMissingTiers === true ? 'skipped' : 'failed';
  }
  return 'failed';
}

export async function runAnfDifferential(
  opts: AnfDifferentialOptions,
): Promise<AnfDifferentialReport> {
  const tiers = opts.tiers ?? ALL_TIERS;
  // Default fold-OFF (matches the checked-in goldens). fold-ON is opt-in
  // via `disableConstantFolding: false`.
  const disableConstantFolding = opts.disableConstantFolding ?? true;
  const findingsDir = opts.findingsDir ?? join(__dirname, '..', 'fuzz-findings-anf');
  const tmpDir = join(__dirname, '..', '.tmp', 'fuzz-anf');
  if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true });

  const canon = await loadCanonical();
  let compileTier: NonNullable<AnfDifferentialOptions['compileTier']>;
  let perTierAvailable: Partial<Record<CompilerName, boolean>>;
  if (opts.compileTier) {
    compileTier = opts.compileTier;
    perTierAvailable = Object.fromEntries(tiers.map((t) => [t, true]));
  } else {
    const ctx = await initTierContext();
    compileTier = (tier, program, inputFile, fold) => {
      if (!fold) return runSourceFile(tier, inputFile, ctx);
      return tier === 'ts' ? runTsInProcess(program, ctx, fold) : runIrFile(tier, inputFile, ctx, fold);
    };
    perTierAvailable = {
      ts: disableConstantFolding ? !!ctx.tsCompile : !!ctx.tsCompileSource,
      go: !!ctx.goBin,
      rust: !!ctx.rustBin,
      python: ctx.pythonAvail,
      zig: !!ctx.zigBin,
      ruby: !!ctx.rubyBin,
      java: !!ctx.javaJar,
    };
  }

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

  // Compile one program in every requested tier and classify the results.
  // Shared by the main loop and the finding shrinker, so a reduced program is
  // judged by exactly the oracle check that flagged the original.
  const foldOn = !disableConstantFolding;
  const tsCompileSource = foldOn ? await loadTsCompileSource() : null;
  const sourceFileFor = (irFile: string) => irFile.replace(/\.json$/, '.runar.ts');
  const evaluate = (prog: AnfProgram, canonicalBytes: string, irFile: string) => {
    let inputFile = irFile;
    if (foldOn) {
      inputFile = sourceFileFor(irFile);
      writeFileSync(inputFile, renderAnfProgramToTypeScript(prog), 'utf-8');
    } else {
      writeFileSync(irFile, canonicalBytes, 'utf-8');
    }
    const outputs: Partial<Record<CompilerName, string>> = {};
    const failed: CompilerName[] = [];
    for (const tier of tiers) {
      const hex = compileTier(tier, prog, inputFile, disableConstantFolding);
      if (hex === null) {
        // Distinguish "no binary" from "binary present, rejected" (always a
        // failure). perTierAvailable tells us the difference.
        if (classifyUnavailableTier(perTierAvailable[tier], opts.skipMissingTiers) !== 'skipped') {
          failed.push(tier);
        }
      } else {
        outputs[tier] = hex;
      }
    }
    return { outputs, classification: classifyTierResults(outputs, failed) };
  };

  // Shrink a mismatching program with `reduceAnfProgram` (F-173). A candidate
  // counts as a reproduction only if it fails with the byte-identical reason
  // string (same divergent / rejecting tiers). Past the run's time budget every
  // candidate is refused, which stops the shrink at the last reproducing
  // program instead of overrunning. The result is re-evaluated once more and
  // dropped if it no longer reproduces, so a written reduced program always
  // fails the original check.
  const shrink = (
    program: AnfProgram,
    reason: string,
    irFile: string,
  ): Finding['reduced'] => {
    const deadline = opts.timeBudgetMs !== undefined ? start + opts.timeBudgetMs : undefined;
    const reproduces = (p: AnfProgram): { outputs: Partial<Record<CompilerName, string>> } | null => {
      const r = evaluate(p, canon(p), irFile);
      return r.classification.status === 'mismatch' && r.classification.reason === reason ? r : null;
    };
    try {
      const reducedProgram = reduceAnfProgram(
        program as ReducibleAnfProgram,
        (cand) =>
          (deadline === undefined || Date.now() <= deadline) &&
          reproduces(cand as unknown as AnfProgram) !== null,
      ) as unknown as AnfProgram;
      const confirmed = reproduces(reducedProgram);
      if (!confirmed) return undefined;
      return {
        programJson: canon(reducedProgram),
        source: foldOn ? renderAnfProgramToTypeScript(reducedProgram) : undefined,
        outputs: confirmed.outputs,
        reason,
        originalBindings: countBindings(program),
        reducedBindings: countBindings(reducedProgram),
      };
    } catch (e) {
      if (opts.verbose) console.log(`  shrink failed: ${(e as Error).message}`);
      return undefined;
    }
  };
  let programsRun = 0;
  let earlyStop = false;
  let foldedPrograms = 0;

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

    // 2) collect per-tier hex, 3) compare
    const { outputs, classification } = evaluate(program, canonical, irFile);
    const tierKeys = Object.keys(outputs) as CompilerName[];
    let source: string | undefined;
    if (foldOn) {
      // Did folding change the bytes this mode compares? Same rendered source,
      // TS compiler, folding on vs off — counted only when the bytes the TS
      // tier was compared on ARE the folded ones.
      const srcFile = sourceFileFor(irFile);
      source = renderAnfProgramToTypeScript(program);
      const on = runTsSource(srcFile, tsCompileSource, false);
      const off = runTsSource(srcFile, tsCompileSource, true);
      const compared = tiers.includes('ts') ? outputs.ts : on;
      if (on !== null && off !== null && on !== off && compared === on) foldedPrograms += 1;
    }
    if (classification.status === 'mismatch') {
      mismatchCount += 1;
      const finding: Finding = {
        seed: opts.seed,
        programIndex: i,
        programJson: canonical,
        source,
        outputs,
        reason: classification.reason,
      };
      const dir = saveFinding(findingsDir, finding);
      finding.reduced = shrink(program, classification.reason, irFile);
      saveReduced(dir, finding);
      findings.push(dir);
      if (opts.verbose) {
        console.log(`  [${i}] MISMATCH: ${classification.reason} -> ${dir}`);
      }
    } else if (classification.status === 'ok') {
      if (opts.verbose) {
        console.log(`  [${i}] OK (${tierKeys.join(',')})`);
      }
    } else if (opts.verbose) {
      console.log(`  [${i}] SKIPPED (only ${tierKeys.length} tier(s) available)`);
    }

    // Best-effort cleanup of the per-program IR temp file. If the
    // program produced a finding, the canonical bytes are already
    // copied into the findings dir (`program.json`), so the temp can
    // always be removed.
    try { unlinkSync(irFile); } catch { /* ignore */ }
    if (foldOn) {
      try { unlinkSync(sourceFileFor(irFile)); } catch { /* ignore */ }
    }
  }

  return {
    totalPrograms: programs.length,
    programsRun,
    mismatchCount,
    earlyStop,
    perTierAvailable,
    findings,
    durationMs: Date.now() - start,
    foldedPrograms,
  };
}

// JSON.stringify can't serialise bigint; provide a replacer-aware stringify
// used only for finding artifacts (the canonical path uses canonicalJsonStringify).
function jsonReplacerStringify(v: unknown): string {
  return JSON.stringify(v, (_k, val) => (typeof val === 'bigint' ? val.toString() + 'n' : val), 2);
}
