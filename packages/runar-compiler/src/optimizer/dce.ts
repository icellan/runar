/**
 * Dead Code Elimination pass for ANF IR.
 *
 * Removes bindings whose results are never referenced by other bindings,
 * preserving bindings with observable side effects (assert, update_prop,
 * check_preimage, add_output, add_raw_output, add_data_output, call,
 * method_call, raw_script) and any `if` / `loop` whose nested bindings carry
 * one. Iterates to a fixed point so transitively dead bindings are also
 * removed.
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
 * Behaviour: byte-for-byte identical to the previous in-place DCE inside
 * `constant-fold.ts`. Verified by the conformance suite (cross-tier hex
 * parity) and the optimizer unit tests.
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
  const live = filterLiveBindings(method.body);
  return { ...method, body: live };
}

// ---------------------------------------------------------------------------
// Core algorithm
// ---------------------------------------------------------------------------

function collectAllRefs(bindings: ANFBinding[]): Set<string> {
  const refs = new Set<string>();
  for (const binding of bindings) {
    collectRefsFromValue(binding.value, refs);
  }
  return refs;
}

export function collectRefsFromValue(value: ANFValue, refs: Set<string>): void {
  switch (value.kind) {
    case 'load_param':
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
    // Pure ANF kinds — no side effect, safe to DCE if unreferenced.
    case 'load_param':
    case 'load_const':
    case 'get_state_script':
    case 'bin_op':
    case 'unary_op':
    case 'array_literal':
      return false;
    default: {
      const unknown = value as { kind: string };
      throw new UnknownANFKindError(unknown.kind, 'constant-fold.hasSideEffect');
    }
  }
}

function filterLiveBindings(bindings: ANFBinding[]): ANFBinding[] {
  // Iterate to a fixed point so transitively dead bindings are removed too.
  let current = bindings;
  let changed = true;

  while (changed) {
    changed = false;
    const refs = collectAllRefs(current);
    const filtered: ANFBinding[] = [];

    for (const binding of current) {
      if (refs.has(binding.name) || hasSideEffect(binding.value)) {
        filtered.push(binding);
      } else {
        changed = true;
      }
    }

    current = filtered;
  }

  return current;
}
