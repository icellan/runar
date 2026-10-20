/**
 * N-342 — a `const` local on the `.runar.ts` surface cannot be reassigned.
 *
 * spec/grammar.md §9: "`const` variables cannot be reassigned." The parser
 * recorded `mutable: false` for `const` and nothing ever read it, so
 * `const s = 1n; s = s + x;` compiled. The check runs on the `.runar.ts`
 * parse result and, since N-344, on `.runar.rs` (`let` without `mut`) and
 * `.runar.zig` (`const`), whose parsers record `mutable` faithfully. Other
 * surfaces spell immutability differently (or not at all) and several of
 * their parsers record `mutable` as a constant.
 *
 * Refused, with one diagnostic in all seven tiers:
 *   - `x = e`, and the compound forms the parser desugars to it (`x += e`);
 *   - `x++`, `++x`, `x--`, `--x`;
 *   - a `const` for-initializer, which the loop's own `i++` then advances.
 * Element writes (`x[0] = e`) are not touched: TypeScript allows them on a
 * `const`.
 *
 * Scoping follows blocks: a declaration is visible to the rest of its block
 * and to nested blocks; a sibling or enclosing block never sees it.
 */

import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import type { ContractNode, Expression, SourceLocation, Statement } from '../ir/index.js';

/** The one sentence every tier emits; `name` is the local's source name. */
export function constReassignMessage(name: string): string {
  return `Cannot assign to '${name}' because it is a constant.`;
}

type Scope = Map<string, boolean>;

function lookup(scopes: Scope[], name: string): boolean | undefined {
  for (let i = scopes.length - 1; i >= 0; i--) {
    const m = scopes[i]!.get(name);
    if (m !== undefined) return m;
  }
  return undefined;
}

function checkTarget(
  target: Expression,
  scopes: Scope[],
  loc: SourceLocation,
  out: CompilerDiagnostic[],
): void {
  if (target.kind !== 'identifier') return;
  if (lookup(scopes, target.name) === false) {
    out.push(makeDiagnostic(constReassignMessage(target.name), 'error', loc));
  }
}

function checkExpr(e: Expression, scopes: Scope[], loc: SourceLocation, out: CompilerDiagnostic[]): void {
  if (e.kind === 'increment_expr' || e.kind === 'decrement_expr') {
    checkTarget(e.operand, scopes, e.sourceLocation ?? loc, out);
  }
}

function walk(stmts: Statement[], scopes: Scope[], out: CompilerDiagnostic[]): void {
  const here: Scope = new Map();
  scopes.push(here);
  for (const stmt of stmts) {
    switch (stmt.kind) {
      case 'variable_decl':
        here.set(stmt.name, stmt.mutable);
        break;
      case 'assignment':
        checkTarget(stmt.target, scopes, stmt.sourceLocation, out);
        break;
      case 'expression_statement':
        checkExpr(stmt.expression, scopes, stmt.sourceLocation, out);
        break;
      case 'if_statement':
        walk(stmt.then, scopes, out);
        if (stmt.else) walk(stmt.else, scopes, out);
        break;
      case 'for_statement': {
        const loopScope: Scope = new Map([[stmt.init.name, stmt.init.mutable]]);
        scopes.push(loopScope);
        if (stmt.update.kind === 'expression_statement') {
          checkExpr(stmt.update.expression, scopes, stmt.update.sourceLocation, out);
        } else if (stmt.update.kind === 'assignment') {
          checkTarget(stmt.update.target, scopes, stmt.update.sourceLocation, out);
        }
        walk(stmt.body, scopes, out);
        scopes.pop();
        break;
      }
      default:
        break;
    }
  }
  scopes.pop();
}

/** Diagnostics for every reassigned `const` local in `contract`. */
export function checkConstReassignment(contract: ContractNode): CompilerDiagnostic[] {
  const out: CompilerDiagnostic[] = [];
  walk(contract.constructor.body, [], out);
  for (const method of contract.methods) walk(method.body, [], out);
  return out;
}
