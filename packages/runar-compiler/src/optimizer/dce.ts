/**
 * Dead Code Elimination pass for ANF IR.
 *
 * Removes bindings whose results are never referenced by other bindings,
 * preserving bindings with observable side effects (assert, update_prop,
 * check_preimage, add_output, add_raw_output, add_data_output, call,
 * method_call, raw_script). Iterates to a fixed point so transitively
 * dead bindings are also removed.
 *
 * This module is the canonical, standalone DCE pass. It mirrors the
 * Zig reference implementation in `compilers/zig/src/passes/dce.zig`.
 * The earlier inline implementation in `optimizer/constant-fold.ts`
 * has been surgically extracted here — `eliminateDeadBindings` in
 * `constant-fold.ts` re-exports this module to preserve its public API.
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
    // Pure ANF kinds — no side effect, safe to DCE if unreferenced.
    case 'load_param':
    case 'load_prop':
    case 'load_const':
    case 'get_state_script':
    case 'bin_op':
    case 'unary_op':
    case 'if':
    case 'loop':
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
