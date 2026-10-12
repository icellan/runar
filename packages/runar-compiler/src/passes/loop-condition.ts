/**
 * N-115 — normalise a reversed loop comparison to the canonical spelling.
 *
 * Every later pass reads a loop's iterator off the LEFT-hand side of its
 * condition (W4, `validateForConditionTestsIterator`) and its bound off the
 * right. `for (let i = 0n; 10n > i; i++)` says the same thing as `i < 10n`,
 * so instead of teaching validation, type checking, ANF lowering and the
 * interpreters a second spelling, the parser rewrites it once:
 *
 *   N >  i  ->  i <  N        N <  i  ->  i >  N
 *   N >= i  ->  i <= N        N <= i  ->  i >= N
 *
 * The rule, identical in all seven tiers: the condition is a `<`/`<=`/`>`/`>=`
 * comparison, its RIGHT operand is the loop variable, and its LEFT operand is
 * not -> swap the operands and mirror the operator. Nothing else is touched,
 * so the W4 refusals keep firing: `i + 1n < 2n` (N40) and `j < 3n` (N41) have
 * no iterator on the right, and a mirrored `5n < i` under `i++` becomes
 * `i > 5n`, which the direction rule (N42) still refuses.
 */

import type { ContractNode, Expression, Statement, BinaryOp } from '../ir/index.js';

const MIRRORED: Partial<Record<BinaryOp, BinaryOp>> = {
  '<': '>',
  '<=': '>=',
  '>': '<',
  '>=': '<=',
};

/** The canonical form of `cond` for a loop over `iter` (or `cond` itself). */
export function normalizeLoopCondition(cond: Expression, iter: string): Expression {
  if (cond.kind !== 'binary_expr') return cond;
  const mirrored = MIRRORED[cond.op];
  if (mirrored === undefined) return cond;
  const isIter = (e: Expression): boolean => e.kind === 'identifier' && e.name === iter;
  if (!isIter(cond.right) || isIter(cond.left)) return cond;
  return { ...cond, op: mirrored, left: cond.right, right: cond.left };
}

function normalizeStatements(stmts: Statement[]): void {
  for (const stmt of stmts) {
    switch (stmt.kind) {
      case 'for_statement':
        stmt.condition = normalizeLoopCondition(stmt.condition, stmt.init.name);
        normalizeStatements(stmt.body);
        break;
      case 'if_statement':
        normalizeStatements(stmt.then);
        if (stmt.else) normalizeStatements(stmt.else);
        break;
      default:
        break;
    }
  }
}

/** Rewrite every loop condition in `contract` to its canonical spelling. */
export function normalizeLoopConditions(contract: ContractNode): void {
  normalizeStatements(contract.constructor.body);
  for (const method of contract.methods) normalizeStatements(method.body);
}
