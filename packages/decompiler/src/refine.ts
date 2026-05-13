/**
 * Refinement loop strategies for the decompiler.
 *
 * When a recovery layer (template, assert-recognizer, symexec) produces a
 * candidate source that re-compiles byte-DIFFERENT from the target, the
 * v0 behavior fell straight through to the raw_script floor. That floor
 * is byte-canonical but loses structural information.
 *
 * `applyRefinement` runs up to `maxAttempts` rescue strategies in order:
 *
 *   1. **Alternative fingerprint** — when the divergent span was previously
 *      recognized as a `BuiltinCall` and the matcher recorded other
 *      fingerprints that also matched at that offset (`alternatives`),
 *      swap the chosen builtin name and re-lift. Today the lifter doesn't
 *      structurally consume BuiltinCall annotations (the assert-recognizer
 *      uses raw bytes, the symexec lifter walks ops directly), so the
 *      strategy is wired but only fires when a future codegen path
 *      threads `BuiltinCall.alternatives` through the lifter. Skipped
 *      cleanly when no alternatives are available.
 *
 *   2. **Type variant swap** — when the divergent byte is inside the push
 *      that encodes a method parameter, cycle the param's TS surface type
 *      through `Sig → PubKey → ByteString → bigint`. Different surface
 *      types lower to different push opcodes (e.g. `Sig` literal is
 *      encoded as a tagged hex bytestring whereas `bigint` is a numeric
 *      push), so a type swap can recover byte-identity when the lifter's
 *      inference picked a wrong-but-plausible type.
 *
 *   3. **Branch swap** — when the divergence falls inside an OP_IF body,
 *      walk the recovered ANF and swap `then` / `else` on each `if`
 *      binding (one at a time, outer-first), re-render, and retry. The
 *      lifter assigns THEN to the first byte-range and ELSE to the
 *      second; for an inverted comparison the assignment is right but the
 *      semantics need a flip. We don't currently tag bindings with byte
 *      ranges, so the implementation tries swaps in DFS order against a
 *      shared attempt budget — bounded by `maxAttempts`.
 *
 *   4. **Annotate-and-emit raw fallback** — already implemented by the
 *      caller as the raw_script floor; not part of `applyRefinement`.
 *
 * Each strategy returns a fresh candidate source string OR `null` to
 * indicate "give up on this strategy, try the next one". The caller drives
 * the loop and stops on either a verified byte-match or `maxAttempts`
 * exhaustion.
 */

import type {
  ANFBinding,
  ANFProgram,
  ANFValue,
  ANFMethod,
  ANFParam,
} from 'runar-compiler';
import type { VerifyResult, VerifyDiff } from './types.js';
import type { LiftResult } from './symexec-lift.js';
import { renderTsSource } from './symexec-lift.js';

/**
 * Refinement strategy identifiers, in the order `applyRefinement` cycles
 * through them. Exposed for tests.
 */
export type RefinementStrategy =
  | 'alt-fingerprint'
  | 'type-swap'
  | 'branch-swap';

export const REFINEMENT_STRATEGY_ORDER: RefinementStrategy[] = [
  'alt-fingerprint',
  'type-swap',
  'branch-swap',
];

/**
 * Per-attempt context passed into `applyRefinement`. The caller maintains
 * a small amount of mutable state across attempts:
 *
 *   - `attempt`            — 1-based attempt counter (matches the
 *                            DecompileResult.attempts contract).
 *   - `strategyCursor`     — index into REFINEMENT_STRATEGY_ORDER pointing
 *                            at the NEXT strategy to try. The caller
 *                            advances this on a `null` return so a fresh
 *                            strategy is tried.
 *   - `lastDiff`           — the verification diff that triggered this
 *                            refinement.
 *   - `liftResult`         — the LiftResult that produced the failing
 *                            candidate (required for type-swap / branch-
 *                            swap; null for non-symexec layers).
 *   - `paramTypeCycleStep` — per-param cycle index for type-swap; lets
 *                            the strategy progress monotonically across
 *                            repeated attempts.
 *   - `branchSwapsTried`   — set of "if-binding path" identifiers already
 *                            swapped, so each retry picks a different
 *                            if binding to invert.
 */
export interface RefineContext {
  attempt: number;
  strategyCursor: number;
  candidate: string;
  lastDiff: VerifyDiff;
  liftResult?: LiftResult;
  className?: string;
  paramTypeCycleStep?: number;
  branchSwapsTried?: Set<string>;
}

/**
 * Run the strategy currently pointed to by `ctx.strategyCursor`. Returns:
 *
 *   - a fresh candidate source string — caller must re-verify it.
 *   - `null` — strategy declined (no applicable mutation); caller should
 *     advance `strategyCursor` and either retry with the next strategy or
 *     terminate when all strategies have been exhausted at this attempt.
 *
 * The function is intentionally pure-ish: it never mutates the
 * RefineContext directly. Callers update `strategyCursor`, `attempt`, and
 * the per-strategy state (`paramTypeCycleStep`, `branchSwapsTried`) based
 * on the return value.
 */
export function applyRefinement(ctx: RefineContext): string | null {
  const strategy = REFINEMENT_STRATEGY_ORDER[ctx.strategyCursor];
  if (strategy === undefined) return null;
  switch (strategy) {
    case 'alt-fingerprint': return tryAltFingerprint(ctx);
    case 'type-swap':       return tryTypeSwap(ctx);
    case 'branch-swap':     return tryBranchSwap(ctx);
  }
}

// ---------------------------------------------------------------------------
// Strategy 1 — alternative fingerprint
// ---------------------------------------------------------------------------

/**
 * Strategy 1: when the divergent byte offset falls within a span that the
 * fingerprint matcher recognized as a `BuiltinCall` with one or more
 * `alternatives`, swap to the next alternative builtin name and rebuild
 * the candidate.
 *
 * The current symexec lifter walks raw `Op[]` streams directly and does
 * not consume `BuiltinCall.alternatives`. (BuiltinCalls flow into the
 * `runSymbolic` path that drives the assert-recognizer, and the
 * recognizer's outputs don't depend on which alternative was chosen.) As
 * a result, this strategy always returns null today — the fingerprint
 * matcher records alternatives faithfully (see `match.ts`) so the
 * infrastructure is in place for a later lifter that performs builtin-
 * level lowering.
 */
function tryAltFingerprint(_ctx: RefineContext): string | null {
  // Documented no-op — alternatives are recorded on BuiltinCall but the
  // lift path doesn't currently fork on them. Returning null lets the
  // caller advance to strategy 2 immediately, which costs nothing.
  return null;
}

// ---------------------------------------------------------------------------
// Strategy 2 — type variant swap
// ---------------------------------------------------------------------------

/**
 * Surface-type cycle used by Strategy 2. The lifter's most common
 * mis-inference is between bytes-family siblings (`Sig` ↔ `PubKey` ↔
 * `ByteString`) and the numeric family (`bigint`). Cycling visits each
 * of the four siblings in turn.
 */
const TYPE_CYCLE: ReadonlyArray<string> = ['Sig', 'PubKey', 'ByteString', 'bigint', 'boolean'];

/**
 * Return the next type in the cycle AFTER `current`, wrapping around.
 * If `current` isn't in the cycle, start from the head.
 */
function nextTypeInCycle(current: string): string {
  const idx = TYPE_CYCLE.indexOf(current);
  const next = idx < 0 ? 0 : (idx + 1) % TYPE_CYCLE.length;
  return TYPE_CYCLE[next]!;
}

/**
 * Strategy 2 — swap one param's inferred type for the next type in the
 * cycle and re-render. Picks the param whose load_param push covers the
 * divergence offset; falls back to params[0] when the lifter didn't tag
 * byte ranges (today's default).
 */
function tryTypeSwap(ctx: RefineContext): string | null {
  if (!ctx.liftResult) return null;
  const lr = ctx.liftResult;
  const method = lr.program.methods[0];
  if (!method) return null;
  if (method.params.length === 0) return null;

  // Choose the param to swap. Without an exact byte-range tag on bindings,
  // we use a deterministic rotation driven by `paramTypeCycleStep` so
  // repeated attempts try a different (param, next-type) pair each time
  // and the strategy can't loop in place.
  const step = ctx.paramTypeCycleStep ?? 0;
  const paramCount = method.params.length;
  const paramIdx = step % paramCount;
  const target = method.params[paramIdx]!;
  const newType = nextTypeInCycle(target.type);
  if (newType === target.type) return null;

  // Clone the program + LiftResult with the swapped type so the original
  // remains untouched (the caller may want to fall through after refinement
  // exhausts).
  const swappedParams: ANFParam[] = method.params.map((p, i) =>
    i === paramIdx ? { ...p, type: newType } : p,
  );
  const swappedMethod: ANFMethod = { ...method, params: swappedParams };
  const swappedProgram: ANFProgram = {
    ...lr.program,
    methods: [swappedMethod, ...lr.program.methods.slice(1)],
  };

  // Imports must reflect the new type — drop the old one's import if it's
  // no longer referenced, and add the new one.
  const swappedImports = recomputeImports(lr.imports, swappedParams);

  const swappedResult: LiftResult = {
    ok: true,
    program: swappedProgram,
    paramTypes: lr.paramTypes, // internal inferred enum stays for parity
    imports: swappedImports,
  };

  try {
    return renderTsSource(swappedResult, { className: ctx.className });
  } catch {
    // Renderer threw — strategy declines, caller advances.
    return null;
  }
}

/**
 * Rebuild the import list to reflect the current param types. Keeps
 * non-type imports (`assert`, `SmartContract`, callable builtins) and
 * adds Sig/PubKey/ByteString as needed.
 */
function recomputeImports(existing: string[], params: ReadonlyArray<ANFParam>): string[] {
  const out = new Set(existing);
  // Drop type aliases that might no longer be referenced.
  out.delete('Sig');
  out.delete('PubKey');
  out.delete('ByteString');
  for (const p of params) {
    if (p.type === 'Sig') out.add('Sig');
    else if (p.type === 'PubKey') out.add('PubKey');
    else if (p.type === 'ByteString') out.add('ByteString');
  }
  return Array.from(out);
}

// ---------------------------------------------------------------------------
// Strategy 3 — branch swap
// ---------------------------------------------------------------------------

/**
 * Strategy 3 — invert THEN / ELSE on a single `if` binding in the
 * recovered ANF and re-render. Walks the binding tree in pre-order
 * (outer-most first, then DFS into each branch); skips bindings already
 * tried (tracked by `ctx.branchSwapsTried`).
 */
function tryBranchSwap(ctx: RefineContext): string | null {
  if (!ctx.liftResult) return null;
  const lr = ctx.liftResult;
  const method = lr.program.methods[0];
  if (!method) return null;

  const tried = ctx.branchSwapsTried ?? new Set<string>();
  const target = pickIfToSwap(method.body, '', tried);
  if (target === null) return null;

  // Build a fresh body with the target if's branches swapped.
  const swappedBody = swapIfAtPath(method.body, target.path);
  if (swappedBody === null) return null;

  const swappedMethod: ANFMethod = { ...method, body: swappedBody };
  const swappedProgram: ANFProgram = {
    ...lr.program,
    methods: [swappedMethod, ...lr.program.methods.slice(1)],
  };
  const swappedResult: LiftResult = {
    ok: true,
    program: swappedProgram,
    paramTypes: lr.paramTypes,
    imports: lr.imports,
  };

  // Record the path so subsequent invocations don't re-swap the same node.
  tried.add(target.path);
  ctx.branchSwapsTried = tried;

  try {
    return renderTsSource(swappedResult, { className: ctx.className });
  } catch {
    return null;
  }
}

/** Walk bindings DFS, returning the path of the first `if` not already tried. */
function pickIfToSwap(
  bindings: ReadonlyArray<ANFBinding>,
  prefix: string,
  tried: Set<string>,
): { path: string } | null {
  for (let i = 0; i < bindings.length; i++) {
    const b = bindings[i]!;
    if (b.value.kind !== 'if') continue;
    const path = `${prefix}/${i}`;
    if (!tried.has(path)) return { path };
    // Try inside the (potentially-already-swapped) branches.
    const thenHit = pickIfToSwap(b.value.then, `${path}/then`, tried);
    if (thenHit !== null) return thenHit;
    const elseHit = pickIfToSwap(b.value.else, `${path}/else`, tried);
    if (elseHit !== null) return elseHit;
  }
  return null;
}

/**
 * Return a deep-cloned binding list with the `if` at `path` swapped.
 * Returns null if the path doesn't resolve to an `if` value (caller bug
 * or stale path — strategy declines).
 */
function swapIfAtPath(bindings: ReadonlyArray<ANFBinding>, path: string): ANFBinding[] | null {
  // Path format: /idx[/then|/else/idx]*
  const segments = path.split('/').filter(s => s.length > 0);
  if (segments.length === 0) return null;
  const head = Number(segments[0]);
  if (!Number.isInteger(head) || head < 0 || head >= bindings.length) return null;
  const target = bindings[head]!;

  const out: ANFBinding[] = bindings.map(b => b);
  if (segments.length === 1) {
    if (target.value.kind !== 'if') return null;
    const swapped: ANFValue = {
      kind: 'if',
      cond: target.value.cond,
      then: target.value.else.map(b => b),
      else: target.value.then.map(b => b),
    };
    out[head] = { ...target, value: swapped };
    return out;
  }

  // Recurse into the named branch. segments[1] is 'then' | 'else',
  // segments[2..] addresses the sub-path.
  const branchName = segments[1];
  if (target.value.kind !== 'if') return null;
  const subPath = '/' + segments.slice(2).join('/');
  if (branchName === 'then') {
    const newThen = swapIfAtPath(target.value.then, subPath);
    if (newThen === null) return null;
    out[head] = { ...target, value: { ...target.value, then: newThen } };
    return out;
  }
  if (branchName === 'else') {
    const newElse = swapIfAtPath(target.value.else, subPath);
    if (newElse === null) return null;
    out[head] = { ...target, value: { ...target.value, else: newElse } };
    return out;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Driver — wraps a recovery layer in the refinement loop.
// ---------------------------------------------------------------------------

/**
 * Verifier callback supplied by the caller. Returns the verify result for
 * a refined candidate source (so the refinement loop doesn't need to know
 * about `runar-compiler`'s `compile` entry point directly).
 */
export type Verifier = (source: string) => VerifyResult;

export interface RunRefinementOptions {
  maxAttempts: number;
  initialDiff: VerifyDiff;
  initialCandidate: string;
  liftResult?: LiftResult;
  className?: string;
  verify: Verifier;
}

export interface RunRefinementResult {
  /** Final accepted source, or null if every refinement diverged. */
  source: string | null;
  /** Number of attempts consumed (1-based; matches DecompileResult.attempts). */
  attempts: number;
  /** Last byte-diff observed, if any (useful for the caller's fall-through path). */
  lastDiff?: VerifyDiff;
}

/**
 * Drive the refinement loop. Returns the first byte-matching candidate or
 * exhausts `maxAttempts` and returns null. The loop is bounded by both
 * `maxAttempts` AND the per-strategy budgets (each strategy gets its own
 * counter; the cursor only advances when the current strategy returns
 * null OR when a diff is still seen after applying it).
 *
 * The first attempt is the initial candidate (passed in). Subsequent
 * attempts consume one strategy each. Strategies that return null don't
 * consume an attempt slot.
 */
export function runRefinement(opts: RunRefinementOptions): RunRefinementResult {
  let attempts = 1;
  let lastDiff: VerifyDiff = opts.initialDiff;
  let strategyCursor = 0;
  const ctx: RefineContext = {
    attempt: 1,
    strategyCursor: 0,
    candidate: opts.initialCandidate,
    lastDiff,
    liftResult: opts.liftResult,
    className: opts.className,
    paramTypeCycleStep: 0,
    branchSwapsTried: new Set(),
  };

  while (attempts < opts.maxAttempts) {
    // Try strategies in order until one produces a candidate.
    let candidate: string | null = null;
    while (strategyCursor < REFINEMENT_STRATEGY_ORDER.length) {
      ctx.strategyCursor = strategyCursor;
      ctx.lastDiff = lastDiff;
      candidate = applyRefinement(ctx);
      if (candidate !== null) break;
      strategyCursor++;
    }
    if (candidate === null) {
      // All strategies exhausted at this layer.
      return { source: null, attempts, lastDiff };
    }
    attempts++;
    ctx.attempt = attempts;
    const verify = opts.verify(candidate);
    if (verify.ok) {
      return { source: candidate, attempts };
    }
    if (verify.kind === 'compile-error') {
      // Compile-error is unrecoverable for this strategy; advance.
      strategyCursor++;
      // Reset per-strategy progress so the next strategy starts fresh.
      ctx.paramTypeCycleStep = 0;
      continue;
    }
    // byte-diff — keep going. For type-swap, advance the cycle pointer
    // so the next attempt tries the next type. For branch-swap, the
    // tried-set already moved forward inside `tryBranchSwap`.
    lastDiff = verify;
    if (REFINEMENT_STRATEGY_ORDER[strategyCursor] === 'type-swap') {
      ctx.paramTypeCycleStep = (ctx.paramTypeCycleStep ?? 0) + 1;
    }
  }

  return { source: null, attempts, lastDiff };
}
