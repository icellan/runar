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

/**
 * Where a binding sits: its index in each enclosing list, with an arm marker
 * (THEN / ELSE / BODY) after each `if` / `loop` index.
 */
type Path = readonly number[];
const THEN = -1;
const ELSE = -2;
const BODY = -3;

/**
 * Is the binding at `def` in scope at `from`? Only if it sits earlier in the
 * same list as `from` or in a list enclosing it. A binding inside an `if` arm
 * or a loop body is never visible after it, and a later binding never answers
 * for an earlier use: stack lowering resolves names by position, so an
 * order-blind lookup would let a decoy bound AFTER (or beside) a use vouch for
 * it.
 */
function visible(def: Path, from: Path): boolean {
  const n = def.length;
  if (from.length < n) return false;
  for (let i = 0; i < n - 1; i++) if (def[i] !== from[i]) return false;
  return def[n - 1]! < from[n - 1]!;
}

interface Def {
  value: ANFValue;
  path: Path;
}

interface MethodView {
  /** What a reference to `name` made at `from` resolves to, or undefined. */
  resolve(name: string | undefined, from: Path): string | undefined;
  /** What a truthy reference to `name` made at `from` implies was checked. */
  truthOf(name: string, from: Path): Checks;
}

export function irPreimageRuleErrors(program: ANFProgram): string[] {
  const errors: string[] = [];
  for (const p of program.properties) {
    if (p.type === SHP) errors.push(preimagePropertyMessage(p.name));
  }
  // A method_call resolves exactly as stack lowering inlines it: to the LAST
  // non-public, non-constructor method of that name (05-stack-lower.ts
  // lowerToStack). The loaders refuse duplicate names first
  // (assertIrUniqueMethodNames); this never relies on that alone.
  const privates = new Map<string, ANFMethod>();
  for (const m of program.methods) if (m.name !== 'constructor' && !m.isPublic) privates.set(m.name, m);
  const publics = program.methods.filter((m) => m.isPublic && m.name !== 'constructor');
  const implicitTxPreimage =
    publics.length > 0 &&
    publics.every((m) => m.params.some((p) => p.name === 'txPreimage' && p.type === SHP)) &&
    !program.properties.some((p) => p.name === 'txPreimage');

  const view = (m: ANFMethod): MethodView => {
    const defs = new Map<string, Def>();
    // Names that never resolve: bound more than once, or bound under a
    // parameter's name (a parameter slot answers to its own name too).
    const poisoned = new Set(m.params.map((p) => p.name));
    const collect = (b: readonly ANFBinding[], at: Path): void => {
      b.forEach((x, i) => {
        const path = [...at, i];
        if (defs.has(x.name)) poisoned.add(x.name);
        defs.set(x.name, { value: x.value, path });
        if (x.value.kind === 'if') {
          collect(x.value.then, [...path, THEN]);
          collect(x.value.else ?? [], [...path, ELSE]);
        } else if (x.value.kind === 'loop') collect(x.value.body, [...path, BODY]);
      });
    };
    collect(m.body, []);
    const shp = new Set(m.params.filter((p) => p.type === SHP).map((p) => p.name));
    const implicit = !m.isPublic && implicitTxPreimage && !m.params.some((p) => p.name === 'txPreimage');
    const lookup = (name: string | undefined, from: Path): Def | undefined => {
      if (name === undefined || poisoned.has(name)) return undefined;
      const d = defs.get(name);
      return d !== undefined && visible(d.path, from) ? d : undefined;
    };
    const refOf = (v: ANFValue): string | undefined =>
      v.kind === 'load_const' && typeof v.value === 'string' && v.value.startsWith('@ref:') ? v.value.slice(5) : undefined;
    const resolve = (name: string | undefined, from: Path, depth = 0): string | undefined => {
      const d = lookup(name, from);
      if (d === undefined || depth > defs.size) return undefined;
      const v = d.value;
      if (v.kind === 'load_param') {
        if (shp.has(v.name)) return v.name;
        return implicit && v.name === 'txPreimage' ? v.name : undefined;
      }
      if (v.kind === 'load_prop') return implicit && v.name === 'txPreimage' ? v.name : undefined;
      const next = refOf(v);
      return next === undefined ? undefined : resolve(next, d.path, depth + 1);
    };
    const truthValue = (v: ANFValue, path: Path, depth: number): Checks => {
      if (depth > defs.size) return new Set();
      if (v.kind === 'check_preimage') {
        const o = resolve(v.preimage, path);
        return new Set(o === undefined ? [] : [o]);
      }
      if (v.kind === 'load_const') {
        if (v.value === false) return null;
        const next = refOf(v);
        return next === undefined ? new Set() : truthOf(next, path, depth + 1);
      }
      if (v.kind === 'if' && (v.results === undefined || v.results.length === 0)) {
        const thenArm = v.then;
        const elseArm = v.else ?? [];
        if (thenArm.length === 0 || elseArm.length === 0) return new Set();
        const t = union(
          truthOf(v.cond, path, depth + 1),
          truthValue(thenArm[thenArm.length - 1]!.value, [...path, THEN, thenArm.length - 1], depth + 1),
        );
        return intersect(t, truthValue(elseArm[elseArm.length - 1]!.value, [...path, ELSE, elseArm.length - 1], depth + 1));
      }
      return new Set();
    };
    const truthOf = (name: string, from: Path, depth = 0): Checks => {
      const d = lookup(name, from);
      return d === undefined ? new Set() : truthValue(d.value, d.path, depth);
    };
    return { resolve: (n, from) => resolve(n, from), truthOf: (n, from) => truthOf(n, from) };
  };

  // Keyed by method identity, never by name.
  const memo = new Map<ANFMethod, Set<string>>();
  const mustChecked = (m: ANFMethod, stack: ReadonlySet<ANFMethod>): Set<string> => {
    const cached = memo.get(m);
    if (cached) return cached;
    if (stack.has(m)) return new Set();
    const mv = view(m);
    const inner = new Set([...stack, m]);
    const walk = (b: readonly ANFBinding[], at: Path, doneIn: Set<string>): Set<string> => {
      let done = new Set(doneIn);
      b.forEach((x, i) => {
        const path = [...at, i];
        const v = x.value;
        if (v.kind === 'assert') {
          const c = mv.truthOf(v.value, path);
          if (c !== null) done = new Set([...done, ...c]);
        } else if (v.kind === 'if') {
          const t = walk(v.then, [...path, THEN], done);
          const e = walk(v.else ?? [], [...path, ELSE], done);
          done = new Set([...t].filter((n) => e.has(n)));
        } else if (v.kind === 'method_call') {
          const target = privates.get(v.method);
          if (target) {
            const checked = mustChecked(target, inner);
            target.params.forEach((p, k) => {
              if (!checked.has(p.name)) return;
              const o = mv.resolve(v.args[k], path);
              if (o !== undefined) done.add(o);
            });
          }
        }
      });
      return done;
    };
    const result = walk(m.body, [], new Set());
    memo.set(m, result);
    return result;
  };

  for (const m of program.methods) {
    if (m.name === 'constructor') continue;
    const mv = view(m);
    const visit = (b: readonly ANFBinding[], at: Path): void => {
      b.forEach((x, i) => {
        const path = [...at, i];
        const v = x.value;
        if (v.kind === 'call' && PREIMAGE_EXTRACTORS.has(v.func)) {
          if (mv.resolve(v.args[0], path) === undefined) errors.push(uncheckedPreimageArgMessage(v.func));
        } else if (v.kind === 'method_call') {
          const target = privates.get(v.method);
          if (target) {
            const bad = target.params.some((p, k) => p.type === SHP && mv.resolve(v.args[k], path) === undefined);
            if (bad) errors.push(uncheckedPreimageArgMessage(target.name));
          }
        } else if (v.kind === 'if') {
          visit(v.then, [...path, THEN]);
          visit(v.else ?? [], [...path, ELSE]);
        } else if (v.kind === 'loop') visit(v.body, [...path, BODY]);
      });
    };
    visit(m.body, []);
    if (m.isPublic) {
      const done = mustChecked(m, new Set());
      for (const p of m.params) {
        if (p.type === SHP && !done.has(p.name)) errors.push(preimageNotCheckedMessage(m.name, p.name));
      }
    }
  }
  return errors;
}

/** GK-BUG-015's shared diagnostic (02-validate), on the IR path. */
export function duplicateMethodMessage(name: string): string {
  return `method '${name}' is already declared in this contract and cannot be re-declared`;
}

/**
 * The source path refuses a repeated method name (GK-BUG-015); `--ir` did
 * not, so two bodies could share a name and a name-keyed lookup answer for
 * the wrong one. Refused on the IR path with the same text.
 */
export function assertIrUniqueMethodNames(program: ANFProgram): void {
  const seen = new Set<string>();
  for (const m of program.methods) {
    if (seen.has(m.name)) throw new Error(`IR validation: ${duplicateMethodMessage(m.name)}`);
    seen.add(m.name);
  }
}

/** Throws the first D9 / GK-GAP-010 / D14 violation on the IR path. */
export function assertIrPreimageRules(program: ANFProgram): void {
  const errors = irPreimageRuleErrors(program);
  if (errors.length > 0) throw new Error(`IR validation: ${errors.join('; ')}`);
}
