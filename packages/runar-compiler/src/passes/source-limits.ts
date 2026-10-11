/**
 * The input-size guard, shared by `parse()` and by each per-format parser.
 *
 * R-146 / CL-BUG-055: the limit used to live only in `01-parse.ts`'s
 * dispatcher, while all eight `parse<Format>Source` functions are exported from
 * the package index AND documented in the compiler README as the way to target
 * a specific surface. Measured on a 4,400,037-byte `.runar.sol` source against
 * the 4,194,304-byte limit:
 *
 *     parse()           REFUSED: source exceeds MAX_SOURCE_BYTES
 *     parseSolSource()  ACCEPTED
 *
 * So the guard was present and reachable-around through the advertised door.
 * Same shape as CL-BUG-057, where Python's CLI goes around its own guarded
 * dispatcher.
 *
 * Withdrawing the exports would fix the bug by breaking a documented API for a
 * reason that has nothing to do with the API's shape. Putting the guard where
 * every entry point passes through costs one call per parser.
 */

import { InputLimits, CanonicalJsonError } from 'runar-ir-schema';
import type { ContractNode, Expression, SourceLocation, Statement, TypeNode } from '../ir/index.js';
import { makeDiagnostic } from '../errors.js';
import type { ParseResult } from './01-parse.js';

/**
 * Throw unless `source` is within `InputLimits.MAX_SOURCE_BYTES`.
 *
 * `where` names the caller so the message says which door the oversize input
 * came through — `parse` for the dispatcher, `parseSolSource` for a direct
 * call. The limit and the error shape are the dispatcher's, unchanged, so a
 * caller already catching `CanonicalJsonError` from `parse()` needs no change.
 */
export function assertSourceWithinLimits(source: string, where: string): void {
  const sourceBytes = Buffer.byteLength(source, 'utf8');
  if (sourceBytes > InputLimits.MAX_SOURCE_BYTES) {
    throw new CanonicalJsonError(
      'bytes',
      `${where}: source exceeds MAX_SOURCE_BYTES (limit=${InputLimits.MAX_SOURCE_BYTES}, actual=${sourceBytes})`,
      { limit: InputLimits.MAX_SOURCE_BYTES, actual: sourceBytes },
    );
  }
}

// ---------------------------------------------------------------------------
// F-213: source nesting limit
// ---------------------------------------------------------------------------
//
// MAX_SOURCE_BYTES never bounded recursion: 2,000 nested parens is a 4 KB file.
// `InputLimits.MAX_SOURCE_NESTING` does, on the two measures its comment in
// runar-ir-schema/src/input-limits.ts defines — (A) parse nesting, counted by
// the parsers themselves through `NestingCounter`, and (B) AST nesting, checked
// on the finished tree by `astNestingViolation`. Every tier computes both the
// same way and refuses with the same message.

const MAX_NESTING = InputLimits.MAX_SOURCE_NESTING;

/** The one diagnostic every tier emits for an over-nested source. */
export const SOURCE_NESTING_MESSAGE =
  `source nesting depth exceeds MAX_SOURCE_NESTING (limit=${MAX_NESTING})`;

/** Thrown by `NestingCounter` to unwind a parser at the limit. */
export class SourceNestingError extends Error {
  constructor(readonly loc?: SourceLocation) {
    super(SOURCE_NESTING_MESSAGE);
    this.name = 'SourceNestingError';
  }
}

/**
 * Measure (A): the parse-nesting counter. A parser calls `enter` on entry to
 * each counted construct (a statement, a full-expression parse, a prefix-unary
 * operand, a nested type argument) and `exit` when it leaves; going past the
 * limit throws `SourceNestingError`, so recursion never gets deeper than
 * MAX_SOURCE_NESTING counted frames.
 */
export class NestingCounter {
  private depth = 0;

  enter(loc?: SourceLocation): void {
    this.depth++;
    if (this.depth > MAX_NESTING) throw new SourceNestingError(loc);
  }

  exit(): void {
    this.depth--;
  }

  /** Run `fn` one level deeper. */
  nested<T>(loc: SourceLocation | undefined, fn: () => T): T {
    this.enter(loc);
    try {
      return fn();
    } finally {
      this.exit();
    }
  }
}

function exprChildren(e: Expression): Expression[] {
  switch (e.kind) {
    case 'binary_expr': return [e.left, e.right];
    case 'unary_expr': return [e.operand];
    case 'call_expr': return [e.callee, ...e.args];
    case 'member_expr': return [e.object];
    case 'ternary_expr': return [e.condition, e.consequent, e.alternate];
    case 'index_access': return [e.object, e.index];
    case 'increment_expr':
    case 'decrement_expr': return [e.operand];
    case 'array_literal': return e.elements;
    default: return [];
  }
}

/**
 * True iff some node of `e`, sitting at nesting `level`, is deeper than the
 * limit. Never recurses more than MAX_SOURCE_NESTING + 1 frames: it stops the
 * moment `level` passes the limit.
 */
function exprTooDeep(e: Expression, level: number): boolean {
  if (level > MAX_NESTING) return true;
  for (const c of exprChildren(e)) if (exprTooDeep(c, level + 1)) return true;
  return false;
}

/** Type nesting: a fixed-array type is one deeper than its element. */
function typeTooDeep(t: TypeNode | undefined): boolean {
  let depth = 0;
  for (let cur = t; cur; cur = cur.kind === 'fixed_array_type' ? cur.element : undefined) {
    if (++depth > MAX_NESTING) return true;
  }
  return false;
}

/** The statement whose subtree breaks the limit, or undefined. */
function stmtsTooDeep(stmts: readonly Statement[], level: number): Statement | undefined {
  for (const st of stmts) {
    if (level > MAX_NESTING) return st;
    if (st.kind === 'variable_decl' && typeTooDeep(st.type)) return st;
    const slots: Expression[] = [];
    const nested: Array<[readonly Statement[], number]> = [];
    switch (st.kind) {
      case 'variable_decl': slots.push(st.init); break;
      case 'assignment': slots.push(st.target, st.value); break;
      case 'expression_statement': slots.push(st.expression); break;
      case 'return_statement': if (st.value) slots.push(st.value); break;
      case 'if_statement':
        slots.push(st.condition);
        nested.push([st.then, level + 1]);
        if (st.else) nested.push([st.else, level + 1]);
        break;
      case 'for_statement':
        slots.push(st.condition);
        nested.push([[st.init, st.update], level + 1], [st.body, level + 1]);
        break;
    }
    for (const e of slots) if (exprTooDeep(e, level + 1)) return st;
    for (const [list, lvl] of nested) {
      const bad = stmtsTooDeep(list, lvl);
      if (bad) return bad;
    }
  }
  return undefined;
}

/**
 * Measure (B): AST nesting. Returns `null` when the contract is within the
 * limit, else the location to report (possibly undefined when the offending
 * node carries none).
 */
export function astNestingViolation(contract: ContractNode): SourceLocation | undefined | null {
  for (const p of contract.properties) {
    if (typeTooDeep(p.type)) return p.sourceLocation;
    if (p.initializer && exprTooDeep(p.initializer, 1)) return p.sourceLocation;
  }
  for (const m of [contract.constructor, ...contract.methods]) {
    if (m.params.some((p) => typeTooDeep(p.type))) return m.sourceLocation;
    const bad = stmtsTooDeep(m.body, 1);
    if (bad) return bad.sourceLocation ?? m.sourceLocation;
  }
  return null;
}

/**
 * Run a parser and apply both nesting measures to it: a `SourceNestingError`
 * from measure (A) becomes the shared diagnostic, and so does a `RangeError`
 * (JS stack exhaustion) — with (A) bounding every parser's own recursion, the
 * only way to exhaust the stack is a tree thousands of levels deep, far past
 * the limit, met by a recursive pass before measure (B) ran. On success,
 * measure (B) is checked before the AST is handed back.
 */
export function withNestingLimit(file: string, run: () => ParseResult): ParseResult {
  let result: ParseResult;
  try {
    result = run();
  } catch (e) {
    if (e instanceof SourceNestingError) {
      return { contract: null, errors: [makeDiagnostic(SOURCE_NESTING_MESSAGE, 'error', e.loc)] };
    }
    if (e instanceof RangeError && /call stack/i.test(e.message)) {
      return {
        contract: null,
        errors: [makeDiagnostic(SOURCE_NESTING_MESSAGE, 'error', { file, line: 1, column: 0 })],
      };
    }
    throw e;
  }
  if (result.contract) {
    const at = astNestingViolation(result.contract);
    if (at !== null) {
      return {
        contract: null,
        errors: [...result.errors, makeDiagnostic(SOURCE_NESTING_MESSAGE, 'error', at)],
      };
    }
  }
  return result;
}
