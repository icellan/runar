/**
 * D15: the preimage rules on the IR (`--ir` / compileFromANF) path.
 *
 * IR input skips 02-validate and 03-typecheck, so neither D9 (no property may
 * hold a SigHashPreimage), GK-GAP-010 (a public method's SigHashPreimage
 * parameter is asserted with checkPreimage on every path) nor D14 (an
 * extractor reads only a checked preimage) ran on it. This re-derives what
 * the ANF still carries, failing closed where it cannot prove the rule:
 *
 *  1. a property typed SigHashPreimage is refused (D9 text). FixedArray
 *     properties reach ANF already expanded into scalar leaves, so the leaf
 *     name is reported;
 *  2. every SigHashPreimage parameter of a public method must be checked on
 *     every path by a must-analysis over the bindings (GK-010 text):
 *     `assert(t)` checks what `t` being truthy implies was checked; a
 *     `check_preimage` of the parameter implies it; a value `if` whose arm
 *     ends in the constant `false` (the lowering of `a && b`) implies what its
 *     condition and its other arm imply; an `if` statement checks what both
 *     arms check; a loop body checks nothing; a top-level `method_call` to a
 *     private method checks the arguments that method checks at its own top
 *     level;
 *  3. every extractor argument, and every argument passed to a private
 *     method's SigHashPreimage parameter, must resolve (through `@ref:`
 *     aliases of names bound exactly once in the method) to a `load_param` of
 *     a SigHashPreimage parameter of that method, or, in a private method of
 *     a program whose every public method declares `txPreimage:
 *     SigHashPreimage` (the stateful shape) and that has no property of that
 *     name, to the implicit `txPreimage` (`load_param` / `load_prop`) (D14
 *     text).
 *
 * What ANF cannot carry, and so this cannot check: the source-level type of
 * a value (a ByteString parameter retyped SigHashPreimage in hand-written IR
 * is simply a SigHashPreimage parameter here, and rule 2 then requires its
 * check), and source shapes whose check the lowering moved somewhere this
 * analysis does not follow (a check only inside a loop body, or only in a
 * multi-result `if`) — those are refused here even where the source compiler
 * accepts them.
 */

import type { ANFBinding, ANFMethod, ANFProgram, ANFValue } from '../ir/index.js';
import { preimagePropertyMessage } from './02-validate.js';
import { PREIMAGE_EXTRACTORS, preimageNotCheckedMessage, uncheckedPreimageArgMessage } from './03-typecheck.js';

const SHP = 'SigHashPreimage';

/** A set where `null` stands for "everything" (a constant-false arm). */
type Checks = Set<string> | null;
const union = (a: Checks, b: Checks): Checks => (a === null || b === null ? null : new Set([...a, ...b]));
const intersect = (a: Checks, b: Checks): Checks =>
  a === null ? b : b === null ? a : new Set([...a].filter((x) => b.has(x)));

interface MethodView {
  defs: Map<string, ANFValue>;
  dup: Set<string>;
  resolve(name: string | undefined): string | undefined;
}

export function irPreimageRuleErrors(program: ANFProgram): string[] {
  const errors: string[] = [];
  for (const p of program.properties) {
    if (p.type === SHP) errors.push(preimagePropertyMessage(p.name));
  }
  const methods = new Map(program.methods.map((m) => [m.name, m]));
  const publics = program.methods.filter((m) => m.isPublic && m.name !== 'constructor');
  const implicitTxPreimage =
    publics.length > 0 &&
    publics.every((m) => m.params.some((p) => p.name === 'txPreimage' && p.type === SHP)) &&
    !program.properties.some((p) => p.name === 'txPreimage');

  const view = (m: ANFMethod): MethodView => {
    const defs = new Map<string, ANFValue>();
    const dup = new Set<string>();
    const collect = (b: readonly ANFBinding[]): void => {
      for (const x of b) {
        if (defs.has(x.name)) dup.add(x.name);
        defs.set(x.name, x.value);
        if (x.value.kind === 'if') {
          collect(x.value.then);
          collect(x.value.else ?? []);
        } else if (x.value.kind === 'loop') collect(x.value.body);
      }
    };
    collect(m.body);
    const own = new Set(m.params.map((p) => p.name));
    const shp = new Set(m.params.filter((p) => p.type === SHP).map((p) => p.name));
    const implicit = !m.isPublic && implicitTxPreimage && !own.has('txPreimage');
    const resolve = (name: string | undefined, seen: Set<string> = new Set()): string | undefined => {
      if (name === undefined || dup.has(name) || seen.has(name)) return undefined;
      seen.add(name);
      const v = defs.get(name);
      if (v === undefined) return undefined;
      if (v.kind === 'load_param') {
        if (shp.has(v.name)) return v.name;
        return implicit && v.name === 'txPreimage' ? v.name : undefined;
      }
      if (v.kind === 'load_prop') return implicit && v.name === 'txPreimage' ? v.name : undefined;
      if (v.kind === 'load_const' && typeof v.value === 'string' && v.value.startsWith('@ref:')) {
        return resolve(v.value.slice(5), seen);
      }
      return undefined;
    };
    return { defs, dup, resolve: (n) => resolve(n) };
  };

  // What a truthy `name` implies was checked.
  const truthChecks = (name: string, mv: MethodView, seen: Set<string> = new Set()): Checks => {
    if (mv.dup.has(name) || seen.has(name)) return new Set();
    seen.add(name);
    const v = mv.defs.get(name);
    if (v === undefined) return new Set();
    if (v.kind === 'check_preimage') {
      const o = mv.resolve(v.preimage);
      return new Set(o === undefined ? [] : [o]);
    }
    if (v.kind === 'load_const') {
      if (v.value === false) return null;
      if (typeof v.value === 'string' && v.value.startsWith('@ref:')) return truthChecks(v.value.slice(5), mv, seen);
      return new Set();
    }
    if (v.kind === 'if' && (v.results === undefined || v.results.length === 0)) {
      const thenLast = v.then[v.then.length - 1];
      const elseLast = (v.else ?? [])[(v.else ?? []).length - 1];
      if (thenLast === undefined || elseLast === undefined) return new Set();
      const t = union(truthChecks(v.cond, mv, seen), truthChecks(thenLast.name, mv, seen));
      return intersect(t, truthChecks(elseLast.name, mv, seen));
    }
    return new Set();
  };

  const memo = new Map<string, Set<string>>();
  const mustChecked = (m: ANFMethod, stack: ReadonlySet<string>): Set<string> => {
    const cached = memo.get(m.name);
    if (cached) return cached;
    if (stack.has(m.name)) return new Set();
    const mv = view(m);
    const inner = new Set([...stack, m.name]);
    const walk = (b: readonly ANFBinding[], doneIn: Set<string>): Set<string> => {
      let done = new Set(doneIn);
      for (const x of b) {
        const v = x.value;
        if (v.kind === 'assert') {
          const c = truthChecks(v.value, mv);
          if (c !== null) done = new Set([...done, ...c]);
        } else if (v.kind === 'if') {
          const t = walk(v.then, done);
          const e = walk(v.else ?? [], done);
          done = new Set([...t].filter((n) => e.has(n)));
        } else if (v.kind === 'method_call') {
          const target = methods.get(v.method);
          if (target && !target.isPublic) {
            const checked = mustChecked(target, inner);
            target.params.forEach((p, i) => {
              if (!checked.has(p.name)) return;
              const o = mv.resolve(v.args[i]);
              if (o !== undefined) done.add(o);
            });
          }
        }
      }
      return done;
    };
    const result = walk(m.body, new Set());
    memo.set(m.name, result);
    return result;
  };

  for (const m of program.methods) {
    if (m.name === 'constructor') continue;
    const mv = view(m);
    const visit = (b: readonly ANFBinding[]): void => {
      for (const x of b) {
        const v = x.value;
        if (v.kind === 'call' && PREIMAGE_EXTRACTORS.has(v.func)) {
          if (mv.resolve(v.args[0]) === undefined) errors.push(uncheckedPreimageArgMessage(v.func));
        } else if (v.kind === 'method_call') {
          const target = methods.get(v.method);
          if (target && !target.isPublic) {
            const bad = target.params.some((p, i) => p.type === SHP && mv.resolve(v.args[i]) === undefined);
            if (bad) errors.push(uncheckedPreimageArgMessage(target.name));
          }
        } else if (v.kind === 'if') {
          visit(v.then);
          visit(v.else ?? []);
        } else if (v.kind === 'loop') visit(v.body);
      }
    };
    visit(m.body);
    if (m.isPublic) {
      const done = mustChecked(m, new Set());
      for (const p of m.params) {
        if (p.type === SHP && !done.has(p.name)) errors.push(preimageNotCheckedMessage(m.name, p.name));
      }
    }
  }
  return errors;
}

/** Throws the first D9 / GK-GAP-010 / D14 violation on the IR path. */
export function assertIrPreimageRules(program: ANFProgram): void {
  const errors = irPreimageRuleErrors(program);
  if (errors.length > 0) throw new Error(`IR validation: ${errors.join('; ')}`);
}
