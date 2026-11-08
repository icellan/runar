/**
 * Dead Code Elimination pass for ANF IR.
 *
 * Removes bindings whose results are never referenced by other bindings,
 * preserving bindings with observable side effects (assert, update_prop,
 * check_preimage, add_output, add_raw_output, add_data_output, call,
 * method_call, raw_script), any `bin_op` that can abort (`/ % & | ^ << >>`),
 * and any `if` / `loop` whose nested bindings carry one. Iterates to a fixed point so transitively dead bindings are also
 * removed.
 *
 * "Results" is plural on purpose (N-140). A binding does not only define its
 * own `name`: an `if` that merges branch locals also defines every name in
 * `results`, and both an `if` and a `loop` define the names their nested
 * bindings bind. Liveness used to test `refs.has(binding.name)` alone, so an
 * `if` named `t9` carrying `results: ['a','b']` — a name nothing ever
 * references, because callers reference `a` and `b` — was deleted whenever its
 * arms happened to be pure. The merged locals then kept their pre-branch
 * values and the contract compiled to a locking script that cannot be
 * satisfied. See `conformance/dce/live-if.test.ts` for the executable proof;
 * the defect was identical in all seven tiers, so cross-tier byte parity held
 * the whole time.
 *
 * This module is the canonical DEFINITION of DCE — one implementation, mirrored
 * by `compilers/zig/src/passes/dce.zig` and its five peers, and re-exported by
 * `optimizer/constant-fold.ts` (where it used to live inline) to preserve that
 * module's public API.
 *
 * It is NOT a standalone pipeline pass, and the header used to say it was
 * (R-194). The only caller is `optimizer/anf-ec.ts`, at the end of `optimizeEC`
 * and AFTER its `if (!anyChanged) return program;` early exit — so a program
 * the EC optimizer does not touch is never DCE'd. Go's `anf_optimize.go` does
 * the same thing, so there is no cross-tier divergence; the claim was simply
 * false.
 *
 * That gate is load-bearing, not an oversight. Measured by moving the call
 * ahead of the early exit so DCE runs on every program: the TypeScript tier
 * then FAILS TO COMPILE 11 of the 78 conformance fixtures —
 * all-readonly-cleanstack, bounded-loop, branch-merged-locals,
 * function-patterns, if-else, if-without-else, loop-if-merged-locals,
 * loop-shapes, merge-locals-prop-updates, merge-locals-shapes, multi-method.
 * Not byte movement: outright compilation failure. So this pass, run
 * unconditionally, removes bindings that stack lowering still needs, and
 * "make DCE standalone" is a defect to fix in DCE before it is a wiring change
 * (filed as N-140).
 *
 * Pinned by `r194-dce-invocation.test.ts` so this description and the call site
 * cannot drift apart again.
 *
 * Behaviour: byte-for-byte identical, at the time of that extraction, to the
 * previous in-place DCE inside `constant-fold.ts`. Verified by the conformance
 * suite (cross-tier hex parity) and the optimizer unit tests.
 *
 * N-140 is a deliberate behaviour change since: liveness considers the
 * names a binding DEFINES, not only its own `name`. F-108 is the other: a
 * private method's last binding (its return value) is a liveness root.
 */

import type {
  ANFProgram,
  ANFMethod,
  ANFBinding,
  ANFValue,
} from '../ir/index.js';
import { PRESERVE } from '../ir/index.js';
import { UnknownANFKindError } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Eliminate dead bindings across every method in the program.
 * Returns a new program; the input is not mutated.
 */
export function eliminateDeadBindings(program: ANFProgram): ANFProgram {
  return {
    ...program,
    methods: program.methods.map(eliminateDeadInMethod),
  };
}

function eliminateDeadInMethod(method: ANFMethod): ANFMethod {
  const live = filterLiveBindings(method.body, returnsLastBinding(method));
  return { ...method, body: live };
}

/**
 * N-138: dead-binding elimination restricted to `candidates[i]` for method `i`.
 *
 * Only a binding whose name is in the candidate set may be removed; everything
 * else is kept as if live. The constant folder uses it to drop the operand
 * bindings its own rewrites orphaned (the `1` under a folded `-1n`) without
 * also deleting bindings that were already dead before folding — those are the
 * unconditional-DCE question N-140 left open, and fold-ON output must not move
 * for programs the folder did not change.
 */
export function eliminateDeadBindingsAmong(
  program: ANFProgram,
  candidates: ReadonlyArray<ReadonlySet<string>>,
): ANFProgram {
  return {
    ...program,
    methods: program.methods.map((method, i) => {
      const keepLast = returnsLastBinding(method);
      const cands = candidates[i];
      let body = filterLiveBindings(method.body, keepLast, cands);
      // N-446: the fold also orphans operands INSIDE `if` arms and loop
      // bodies (`-5n` in an else arm). Filtering only the top level left them
      // there, stack lowering pushed them, and the arms ended at different
      // depths. Prune the nested scopes too, then re-filter the top level, to
      // a fixed point (a nested removal can orphan a top-level operand).
      if (cands !== undefined) {
        for (;;) {
          const nested = pruneNestedOrphans(body, cands);
          if (nested === body) break;
          body = filterLiveBindings(nested, keepLast, cands);
        }
      }
      return { ...method, body };
    }),
  };
}

/**
 * N-446: remove fold-orphaned pure bindings from every nested scope (`if`
 * arms, `loop` bodies, recursively). Returns `bindings` itself when nothing
 * was removed.
 *
 * A nested binding is removed only if it is a candidate (referenced before
 * folding), is referenced by NO binding anywhere in the method now (arm
 * bindings can be read after the `if` by name, so an arm is never filtered
 * against its own references alone), is not one of its `if`'s declared
 * `results` (stack lowering requires those slots in both arms), is side-effect
 * free, and is not itself an `if` / `loop` (those are recursed into instead).
 * Only the candidate-restricted fold prune calls this; the EC-gated DCE stays
 * top-level, so fold-OFF output cannot move.
 */
function pruneNestedOrphans(
  bindings: ANFBinding[],
  candidates: ReadonlySet<string>,
): ANFBinding[] {
  let current = bindings;
  for (;;) {
    const refs = new Set<string>();
    for (const b of current) collectRefsFromValue(b.value, refs);
    let changed = false;
    const filterScope = (scope: ANFBinding[], protect: ReadonlySet<string>): ANFBinding[] => {
      const out: ANFBinding[] = [];
      let scopeChanged = false;
      for (const b of scope) {
        const v = b.value;
        if (v.kind === 'if') {
          const protectedResults = new Set(v.results ?? []);
          const thenB = filterScope(v.then, protectedResults);
          const elseB = filterScope(v.else, protectedResults);
          if (thenB !== v.then || elseB !== v.else) {
            out.push({ ...b, value: { ...v, then: thenB, else: elseB } });
            scopeChanged = true;
          } else {
            out.push(b);
          }
        } else if (v.kind === 'loop') {
          const body = filterScope(v.body, new Set());
          if (body !== v.body) {
            out.push({ ...b, value: { ...v, body } });
            scopeChanged = true;
          } else {
            out.push(b);
          }
        } else if (
          protect !== TOP_LEVEL &&
          candidates.has(b.name) &&
          !refs.has(b.name) &&
          !protect.has(b.name) &&
          !hasSideEffect(v)
        ) {
          scopeChanged = true;
        } else {
          out.push(b);
        }
      }
      if (!scopeChanged) return scope;
      changed = true;
      return out;
    };
    const next = filterScope(current, TOP_LEVEL);
    if (!changed) return current;
    current = next;
  }
}

/** Sentinel: the method's own body, which `filterLiveBindings` owns. */
const TOP_LEVEL: ReadonlySet<string> = new Set<string>();

/**
 * F-108: a private method's LAST binding is its return value — stack lowering
 * inlines the helper at each `method_call` and takes that binding as the
 * call's result — so it is a liveness root even though nothing inside the
 * method references it. Without this root a pure return expression
 * (`return n + 1n`) was deleted and the helper emptied. The predicate is the
 * one stack lowering uses to collect inlinable private methods. A public
 * method's last binding is never a return value and stays freely eliminable.
 */
function returnsLastBinding(method: ANFMethod): boolean {
  return method.name !== 'constructor' && !method.isPublic;
}

// ---------------------------------------------------------------------------
// Core algorithm
// ---------------------------------------------------------------------------

export function collectRefsFromValue(value: ANFValue, refs: Set<string>): void {
  switch (value.kind) {
    case 'load_param':
      // N-356: a reassigned parameter (`p = q`) is bound under the
      // parameter's own name, and every later read stays `load_param p`,
      // which stack lowering resolves by name to that binding. Count the read
      // as a reference, or the rebinding is deleted and the read falls back to
      // the caller's argument. A name with no binding is a no-op here.
      refs.add(value.name);
      break;
    case 'load_prop':
    case 'get_state_script':
      break;
    case 'load_const':
      // Track @ref: aliases as references to prevent DCE
      if (typeof value.value === 'string' && value.value.startsWith('@ref:')) {
        refs.add(value.value.slice(5));
      }
      break;
    case 'bin_op':
      refs.add(value.left);
      refs.add(value.right);
      break;
    case 'unary_op':
      refs.add(value.operand);
      break;
    case 'call':
      for (const arg of value.args) refs.add(arg);
      break;
    case 'method_call':
      refs.add(value.object);
      for (const arg of value.args) refs.add(arg);
      break;
    case 'if':
      refs.add(value.cond);
      for (const b of value.then) collectRefsFromValue(b.value, refs);
      for (const b of value.else) collectRefsFromValue(b.value, refs);
      break;
    case 'loop':
      for (const b of value.body) collectRefsFromValue(b.value, refs);
      break;
    case 'assert':
      refs.add(value.value);
      break;
    case 'update_prop':
      refs.add(value.value);
      break;
    case 'check_preimage':
      refs.add(value.preimage);
      break;
    case 'deserialize_state':
      refs.add(value.preimage);
      break;
    case 'add_output':
      refs.add(value.satoshis);
      for (const sv of value.stateValues) refs.add(sv);
      refs.add(value.preimage);
      break;
    case 'add_raw_output':
      refs.add(value.satoshis);
      refs.add(value.scriptBytes);
      break;
    case 'add_data_output':
      refs.add(value.satoshis);
      refs.add(value.scriptBytes);
      break;
    case 'array_literal':
      for (const elem of value.elements) refs.add(elem);
      break;
    case 'raw_script':
      // Opaque: no SSA operand refs.
      break;
    default: {
      const unknown = value as { kind: string };
      throw new UnknownANFKindError(unknown.kind, 'constant-fold.collectRefsFromValue');
    }
  }
}

/** `bin_op` operators whose opcode can fail at runtime (see `hasSideEffect`). */
const PARTIAL_BIN_OPS: ReadonlySet<string> = new Set(['/', '%', '&', '|', '^', '<<', '>>']);

export function hasSideEffect(value: ANFValue): boolean {
  switch (value.kind) {
    case 'assert':
    case 'update_prop':
    case 'check_preimage':
    case 'deserialize_state':
    case 'add_output':
    case 'add_raw_output':
    case 'add_data_output':
    case 'call':        // calls may have side effects (e.g. assert)
    case 'method_call': // method calls may have side effects
    case 'raw_script':  // opaque byte span — DCE must never eliminate it
      return true;
    // `if` / `loop` are effectful iff some NESTED binding is. Nested bindings
    // live inside the parent node rather than flattened into the method body,
    // so retention is all-or-nothing: dropping an unreferenced `if` would take
    // every nested `assert` / `check_preimage` / `add_output` with it. Mirrors
    // the Go tier's `frontend.HasSideEffect` and the Rust tier's
    // `frontend::dce::has_side_effect`.
    case 'if':
      return (
        value.then.some((b) => hasSideEffect(b.value)) ||
        value.else.some((b) => hasSideEffect(b.value))
      );
    case 'loop':
      return value.body.some((b) => hasSideEffect(b.value));
    // Issue #109 (`@embedAlways`): a `load_prop` injected to force a readonly
    // field into the deployed locking script carries `[PRESERVE]: true`, so
    // DCE must keep it even though nothing references it. Ordinary load_props
    // leave the flag unset and remain freely eliminable. Mirrors
    // `compilers/zig/src/passes/dce.zig`.
    case 'load_prop':
      return value[PRESERVE] === true;
    // A `bin_op` that can ABORT the script is not removable: purity is not
    // totality (spec/semantics.md §3.7). `& | ^` fail on operands of unequal
    // byte length, `<< >>` on a negative count, `/ %` on a zero divisor. The
    // source evaluates the binding, so deleting it turns an abort into an
    // accept — the fold-ON prune did exactly that to `let m = 41n & p; m = …`
    // (execution-fuzzer seed 1351961626). Kept regardless of operands.
    case 'bin_op':
      return PARTIAL_BIN_OPS.has(value.op);
    // Pure, total ANF kinds — safe to DCE if unreferenced.
    case 'load_param':
    case 'load_const':
    case 'get_state_script':
    case 'unary_op':
    case 'array_literal':
      return false;
    default: {
      const unknown = value as { kind: string };
      throw new UnknownANFKindError(unknown.kind, 'constant-fold.hasSideEffect');
    }
  }
}

/**
 * Every SSA name this binding brings into scope.
 *
 * Its own `name`, plus — for the two nesting kinds — the names it defines on
 * behalf of the enclosing method: an `if`'s declared `results` (the merged
 * branch locals / property slots both arms leave behind) and the names bound
 * inside `if.then`, `if.else` and `loop.body`, recursively.
 *
 * `loop.iterVar` is deliberately NOT here. It is the loop's own induction
 * variable, referenced only from inside the body, so counting it as defined
 * would make every non-trivial loop unconditionally live.
 */
export function collectDefinedNames(binding: ANFBinding, out: Set<string>): void {
  out.add(binding.name);
  collectDefinedNamesFromValue(binding.value, out);
}

function collectDefinedNamesFromValue(value: ANFValue, out: Set<string>): void {
  if (value.kind === 'if') {
    for (const r of value.results ?? []) out.add(r);
    for (const b of value.then) collectDefinedNames(b, out);
    for (const b of value.else) collectDefinedNames(b, out);
  } else if (value.kind === 'loop') {
    for (const b of value.body) collectDefinedNames(b, out);
  }
}

/**
 * Is `binding` referenced from OUTSIDE itself?
 *
 * `refCount` maps a name to the number of DISTINCT bindings that reference it;
 * `ownRefs` is the set this binding contributes. Subtracting its own
 * contribution is what keeps the rule from degenerating into "never delete an
 * `if` or a `loop`": an arm's bindings almost always reference each other, and
 * counting those self-references would make every nesting node immortal. Only
 * a reference from a sibling — the `a + b` after the branch — keeps it alive.
 *
 * For a non-nesting binding this is exactly the old `refs.has(binding.name)`:
 * ANF has no self-reference, so `ownRefs` never contains the binding's own
 * name and the subtraction is a no-op.
 */
function isReferencedExternally(
  binding: ANFBinding,
  ownRefs: Set<string>,
  refCount: Map<string, number>,
): boolean {
  const defined = new Set<string>();
  collectDefinedNames(binding, defined);
  for (const name of defined) {
    const external = (refCount.get(name) ?? 0) - (ownRefs.has(name) ? 1 : 0);
    if (external > 0) return true;
  }
  return false;
}

function filterLiveBindings(
  bindings: ANFBinding[],
  keepLast: boolean,
  candidates?: ReadonlySet<string>,
): ANFBinding[] {
  // Iterate to a fixed point so transitively dead bindings are removed too.
  let current = bindings;
  let changed = true;

  while (changed) {
    changed = false;
    const ownRefs = current.map((b) => {
      const s = new Set<string>();
      collectRefsFromValue(b.value, s);
      return s;
    });
    const refCount = new Map<string, number>();
    for (const s of ownRefs) {
      for (const name of s) refCount.set(name, (refCount.get(name) ?? 0) + 1);
    }
    const filtered: ANFBinding[] = [];

    for (let i = 0; i < current.length; i++) {
      const binding = current[i]!;
      if (
        (keepLast && i === current.length - 1) ||
        (candidates !== undefined && !candidates.has(binding.name)) ||
        isReferencedExternally(binding, ownRefs[i]!, refCount) ||
        hasSideEffect(binding.value)
      ) {
        filtered.push(binding);
      } else {
        changed = true;
      }
    }

    current = filtered;
  }

  return current;
}
