// ---------------------------------------------------------------------------
// Delta-debugging reducer for ANF fuzzer findings (TS-GAP-007).
//
// The ANF differential fuzzer (`anf-differential.ts`) reports findings as
// whole generated programs. `fc.sample` bypasses fast-check's shrinker, so
// findings arrive at full size (up to 3 methods x 15 bindings). This module
// shrinks a finding to a locally-minimal program that STILL triggers a
// caller-supplied "interesting" predicate (e.g. "still diverges across
// tiers"), so a human debugs the smallest reproducer instead of the raw
// generated blob.
//
// Algorithm: ddmin-lite. Greedily attempt to delete each binding (and any
// unused param / property / method), keeping a deletion only if the candidate
//   (a) stays WELL-FORMED — every referenced binding/param/property still
//       exists — and
//   (b) still satisfies `isInteresting`.
// Iterate to a fixed point.
//
// Schema note: the ANF shapes below mirror the generator's emitted schema
// (see `anf-differential.ts`): method bindings live in `method.body`, each
// binding is `{ name, value }` (keyed by `name`), and values reference prior
// bindings by `name`. This module intentionally re-declares a minimal mirror
// (rather than importing `anf-differential.ts`, whose types are module-private)
// so it stays a standalone, dependency-free reducer.
// ---------------------------------------------------------------------------

export type AnfValue =
  | { kind: 'load_param'; name: string }
  | { kind: 'load_prop'; name: string }
  | { kind: 'load_const'; value: bigint | boolean }
  | { kind: 'bin_op'; op: string; left: string; right: string }
  | { kind: 'unary_op'; op: string; operand: string }
  | { kind: 'call'; func: string; args: string[] }
  | { kind: 'array_literal'; elements: string[] }
  | { kind: 'assert'; value: string }
  | { kind: 'update_prop'; name: string; value: string }
  // Tolerate unknown kinds so the reducer never crashes on a schema the
  // generator grows later; such values are treated as referencing nothing.
  | { kind: string; [k: string]: unknown };

export interface AnfParam {
  name: string;
  type: string;
}

export interface AnfProperty {
  name: string;
  type: string;
  readonly: boolean;
  initialValue?: string | number | boolean | bigint;
}

export interface AnfBinding {
  name: string;
  value: AnfValue;
}

export interface AnfMethod {
  name: string;
  params: AnfParam[];
  body: AnfBinding[];
  isPublic: boolean;
}

export interface AnfProgram {
  contractName: string;
  properties: AnfProperty[];
  methods: AnfMethod[];
}

export type InterestingPredicate = (program: AnfProgram) => boolean;

/**
 * Evaluate `isInteresting` defensively. A candidate that deletes the very
 * method/property a predicate inspects can make an unguarded predicate throw;
 * per delta-debugging convention, a candidate whose interestingness test
 * errors is treated as NOT a valid reproduction (deletion rejected).
 */
function interestingSafe(pred: InterestingPredicate, program: AnfProgram): boolean {
  try {
    return pred(program);
  } catch {
    return false;
  }
}

// --- reference extraction ---------------------------------------------------

/** Binding-names a value references (must resolve to a sibling binding). */
function bindingRefs(value: AnfValue): string[] {
  switch (value.kind) {
    case 'bin_op':
      return [(value as { left: string }).left, (value as { right: string }).right];
    case 'unary_op':
      return [(value as { operand: string }).operand];
    case 'call':
      return (value as { args?: string[] }).args ?? [];
    case 'array_literal':
      return (value as { elements?: string[] }).elements ?? [];
    case 'assert':
      return [(value as { value: string }).value];
    case 'update_prop':
      return [(value as { value: string }).value];
    default:
      // load_param / load_prop / load_const (and unknown kinds) reference no
      // sibling bindings.
      return [];
  }
}

/** Param-name a value references (`load_param`), else null. */
function paramRef(value: AnfValue): string | null {
  return value.kind === 'load_param' ? (value as { name: string }).name : null;
}

/** Property-name a value references (`load_prop` / `update_prop`), else null. */
function propRef(value: AnfValue): string | null {
  if (value.kind === 'load_prop' || value.kind === 'update_prop') {
    return (value as { name: string }).name;
  }
  return null;
}

// --- well-formedness --------------------------------------------------------

/**
 * A program is well-formed iff every binding reference resolves to a binding
 * in the same method, every `load_param` resolves to one of that method's
 * params, and every property reference resolves to a declared property.
 * Because reduction only DELETES (never reorders) bindings, existence implies
 * the ANF "def precedes use" ordering is preserved.
 */
export function isWellFormed(program: AnfProgram): boolean {
  const propNames = new Set(program.properties.map((p) => p.name));
  for (const method of program.methods) {
    const bindingNames = new Set(method.body.map((b) => b.name));
    const paramNames = new Set(method.params.map((p) => p.name));
    for (const b of method.body) {
      for (const r of bindingRefs(b.value)) {
        if (!bindingNames.has(r)) return false;
      }
      const pr = paramRef(b.value);
      if (pr !== null && !paramNames.has(pr)) return false;
      const pp = propRef(b.value);
      if (pp !== null && !propNames.has(pp)) return false;
    }
  }
  return true;
}

// --- cloning ----------------------------------------------------------------

function clone(program: AnfProgram): AnfProgram {
  // structuredClone (Node 17+) deep-copies bigint `load_const` values that a
  // JSON round-trip would drop.
  return structuredClone(program);
}

// --- candidate generation ---------------------------------------------------

/**
 * Yield every single-item-deletion candidate of `program`, one clone each.
 * Order (most→least impactful for shrink size): bindings, then unused params,
 * then unused properties, then whole methods. Each candidate is a fresh clone
 * so the caller may keep or discard it without aliasing `program`.
 */
function* deletionCandidates(program: AnfProgram): Generator<AnfProgram> {
  // 1. Delete one binding.
  for (let mi = 0; mi < program.methods.length; mi++) {
    const body = program.methods[mi].body;
    for (let bi = 0; bi < body.length; bi++) {
      const cand = clone(program);
      cand.methods[mi].body.splice(bi, 1);
      yield cand;
    }
  }
  // 2. Delete one param.
  for (let mi = 0; mi < program.methods.length; mi++) {
    const params = program.methods[mi].params;
    for (let pi = 0; pi < params.length; pi++) {
      const cand = clone(program);
      cand.methods[mi].params.splice(pi, 1);
      yield cand;
    }
  }
  // 3. Delete one property.
  for (let pi = 0; pi < program.properties.length; pi++) {
    const cand = clone(program);
    cand.properties.splice(pi, 1);
    yield cand;
  }
  // 4. Delete one whole method.
  for (let mi = 0; mi < program.methods.length; mi++) {
    const cand = clone(program);
    cand.methods.splice(mi, 1);
    yield cand;
  }
}

// --- driver -----------------------------------------------------------------

/**
 * Shrink `program` to a locally-minimal well-formed program that still
 * satisfies `isInteresting`. Greedy fixed-point: on each pass, apply the first
 * deletion that keeps the program well-formed AND interesting, then restart;
 * stop when no single deletion helps.
 *
 * The input is never mutated. If the input itself is not interesting, a clone
 * of it is returned unchanged (ddmin's precondition is that the seed is
 * interesting; we degrade gracefully rather than throw).
 */
export function reduceAnfProgram(
  program: AnfProgram,
  isInteresting: InterestingPredicate,
): AnfProgram {
  let current = clone(program);
  if (!interestingSafe(isInteresting, current)) return current;

  let changed = true;
  while (changed) {
    changed = false;
    for (const candidate of deletionCandidates(current)) {
      if (isWellFormed(candidate) && interestingSafe(isInteresting, candidate)) {
        current = candidate;
        changed = true;
        break; // restart the pass from the smaller program
      }
    }
  }
  return current;
}
