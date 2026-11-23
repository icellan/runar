import type { Statement } from '../ir/runar-ast.js';

/**
 * N-511: on the surfaces whose trailing expression IS the value (.runar.rs and
 * .runar.move with a declared return type, .runar.rb private helpers), turn
 * that expression into an explicit `return`, recursively through the arms of
 * a trailing if/else (`if c { x } else { 0 }`). The return keeps the
 * expression statement's own source location, so the lowered ANF is the same
 * as before; the type checker then needs no tail-value heuristic.
 * `intoArms: false` promotes only the top-level trailing expression.
 */
export function promoteTailReturns(stmts: Statement[], intoArms = true): void {
  const last = stmts[stmts.length - 1];
  if (!last) return;
  if (last.kind === 'expression_statement') {
    stmts[stmts.length - 1] = {
      kind: 'return_statement',
      value: last.expression,
      sourceLocation: last.sourceLocation,
    };
  } else if (intoArms && last.kind === 'if_statement' && last.else) {
    promoteTailReturns(last.then);
    promoteTailReturns(last.else);
  }
}

/** N-511: whether a `return <value>` appears anywhere in the list. */
export function hasValueReturn(stmts: Statement[]): boolean {
  return stmts.some((s) => {
    if (s.kind === 'return_statement') return s.value !== undefined && s.value !== null;
    if (s.kind === 'if_statement') return hasValueReturn(s.then) || (s.else !== undefined && hasValueReturn(s.else));
    if (s.kind === 'for_statement') return hasValueReturn(s.body);
    return false;
  });
}
