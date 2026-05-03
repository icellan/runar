/**
 * Side-effect summary pass.
 *
 * Classifies each method on a `ContractNode` by the side effects it has
 * on the contract's continuation requirements. Walks the private-method
 * call graph so that effects buried inside private helpers surface to
 * their public callers.
 *
 * Consumed by:
 *   - `04-anf-lower.ts` for auto-injecting continuation parameters
 *     (`_changePKH`, `_changeAmount`, `_newAmount`, `txPreimage`) and
 *     gating emission of the `hashOutputs` continuation assertion.
 *   - `artifact/assembler.ts` for declaring the matching ABI parameters
 *     and `isTerminal` flag.
 *
 * Both consumers must read from one source of truth so the deployed ABI
 * cannot drift from the locking script's actual parameter expectations.
 *
 * Recursion across private methods is forbidden by the language
 * validator (`02-validate.ts`), so the call-graph walk terminates.
 */
import type { ContractNode, MethodNode, Statement, Expression } from '../ir/index.js';

/**
 * Effects a method has on the contract's continuation. Each flag is
 * `true` if the effect occurs anywhere reachable from the method body,
 * including transitively via private-method calls.
 */
export interface MethodEffects {
  /** Mutates a non-readonly property (assignment or `++`/`--`). */
  mutatesState: boolean;
  /** Calls `this.addOutput(...)` or `this.addRawOutput(...)`. */
  hasStateOutput: boolean;
  /** Calls `this.addDataOutput(...)`. */
  hasDataOutput: boolean;
  /** Calls `checkPreimage(...)` (manually, outside the auto-injected one). */
  usesPreimage: boolean;
}

/** Map from method name to that method's effects. Includes the constructor under the key 'constructor'. */
export type SideEffectSummary = Map<string, MethodEffects>;

const STATE_OUTPUT_INTRINSICS = new Set(['addOutput', 'addRawOutput']);
const DATA_OUTPUT_INTRINSICS = new Set(['addDataOutput']);

function emptyEffects(): MethodEffects {
  return {
    mutatesState: false,
    hasStateOutput: false,
    hasDataOutput: false,
    usesPreimage: false,
  };
}

function unionInto(target: MethodEffects, source: MethodEffects): void {
  target.mutatesState ||= source.mutatesState;
  target.hasStateOutput ||= source.hasStateOutput;
  target.hasDataOutput ||= source.hasDataOutput;
  target.usesPreimage ||= source.usesPreimage;
}

/**
 * Compute side-effect summary for every method on the contract.
 *
 * The walk is memoized: each method is classified once, then reused if
 * referenced by another method. Visit ordering is on-demand DFS — the
 * caller does not need a topological sort.
 */
export function computeSideEffectSummary(contract: ContractNode): SideEffectSummary {
  const summary: SideEffectSummary = new Map();
  const mutablePropNames = new Set(
    contract.properties.filter(p => !p.readonly).map(p => p.name),
  );
  const privateMethodsByName = new Map<string, MethodNode>();
  for (const method of contract.methods) {
    if (method.visibility === 'private') {
      privateMethodsByName.set(method.name, method);
    }
  }

  // Memoization with an in-progress sentinel. Validation forbids
  // recursion so the sentinel should never actually be hit, but we
  // keep it as a defensive guard against stack overflow on
  // mis-validated input.
  const inProgress = new Set<string>();

  function effectsFor(methodName: string, body: Statement[]): MethodEffects {
    const cached = summary.get(methodName);
    if (cached) return cached;
    if (inProgress.has(methodName)) {
      // Treat in-progress (cyclic) calls as having no extra effects;
      // validation should have rejected the contract before we got
      // here. Returning empty avoids infinite recursion.
      return emptyEffects();
    }
    inProgress.add(methodName);
    const effects = computeBodyEffects(body);
    inProgress.delete(methodName);
    summary.set(methodName, effects);
    return effects;
  }

  function computeBodyEffects(stmts: Statement[]): MethodEffects {
    const effects = emptyEffects();
    for (const stmt of stmts) {
      collectStmt(stmt, effects);
    }
    return effects;
  }

  function collectStmt(stmt: Statement, into: MethodEffects): void {
    switch (stmt.kind) {
      case 'assignment':
        if (
          stmt.target.kind === 'property_access' &&
          mutablePropNames.has(stmt.target.property)
        ) {
          into.mutatesState = true;
        }
        // Right-hand side may still contain calls.
        collectExpr(stmt.value, into);
        return;
      case 'expression_statement':
        collectExpr(stmt.expression, into);
        return;
      case 'if_statement':
        collectExpr(stmt.condition, into);
        for (const inner of stmt.then) collectStmt(inner, into);
        if (stmt.else) for (const inner of stmt.else) collectStmt(inner, into);
        return;
      case 'for_statement':
        collectStmt(stmt.update, into);
        for (const inner of stmt.body) collectStmt(inner, into);
        return;
      case 'return_statement':
        if (stmt.value) collectExpr(stmt.value, into);
        return;
      case 'variable_decl':
        collectExpr(stmt.init, into);
        return;
      default:
        return;
    }
  }

  function collectExpr(expr: Expression, into: MethodEffects): void {
    switch (expr.kind) {
      case 'increment_expr':
      case 'decrement_expr':
        if (
          expr.operand.kind === 'property_access' &&
          mutablePropNames.has(expr.operand.property)
        ) {
          into.mutatesState = true;
        }
        return;
      case 'call_expr': {
        const callee = expr.callee;

        // this.X(...) or member.X(...) — output intrinsics or private method calls.
        if (callee.kind === 'property_access' || callee.kind === 'member_expr') {
          const name = callee.property;
          if (STATE_OUTPUT_INTRINSICS.has(name)) into.hasStateOutput = true;
          if (DATA_OUTPUT_INTRINSICS.has(name)) into.hasDataOutput = true;
          const target = privateMethodsByName.get(name);
          if (target) {
            unionInto(into, effectsFor(target.name, target.body));
          }
        }

        // Bareword calls: identifiers that resolve to private methods (Go/Rust
        // surface formats route private helpers as bare identifiers) or to
        // builtins like `checkPreimage`.
        if (callee.kind === 'identifier') {
          if (callee.name === 'checkPreimage') into.usesPreimage = true;
          const target = privateMethodsByName.get(callee.name);
          if (target) {
            unionInto(into, effectsFor(target.name, target.body));
          }
        }

        // Walk subexpressions for nested calls / property accesses.
        for (const arg of expr.args) collectExpr(arg, into);
        if (callee.kind !== 'identifier') collectExpr(callee, into);
        return;
      }
      case 'binary_expr':
        collectExpr(expr.left, into);
        collectExpr(expr.right, into);
        return;
      case 'unary_expr':
        collectExpr(expr.operand, into);
        return;
      case 'ternary_expr':
        collectExpr(expr.condition, into);
        collectExpr(expr.consequent, into);
        collectExpr(expr.alternate, into);
        return;
      case 'index_access':
        collectExpr(expr.object, into);
        collectExpr(expr.index, into);
        return;
      case 'member_expr':
        collectExpr(expr.object, into);
        return;
      case 'array_literal':
        for (const el of expr.elements) collectExpr(el, into);
        return;
      default:
        return;
    }
  }

  // Classify constructor + every method up front so callers do not
  // need to know about lazy evaluation order.
  effectsFor('constructor', contract.constructor.body);
  for (const method of contract.methods) {
    effectsFor(method.name, method.body);
  }

  return summary;
}

/**
 * Classify a method's continuation requirements based on its effects.
 *
 * `needsChange` controls injection of `_changePKH` and `_changeAmount`.
 * `needsNewAmount` controls injection of `_newAmount`. The pair maps
 * directly to ANF auto-param insertion and ABI param declaration; both
 * sites must agree for a deployed contract to be spendable.
 *
 * `isTerminal` is the inverse of `needsChange` for stateful public
 * methods — a method is terminal iff it produces no continuation.
 */
export interface ContinuationShape {
  needsChange: boolean;
  needsNewAmount: boolean;
  isTerminal: boolean;
}

export function continuationShape(effects: MethodEffects): ContinuationShape {
  const needsChange =
    effects.mutatesState || effects.hasStateOutput || effects.hasDataOutput;
  // `addOutput`/`addRawOutput` already specify per-output amounts, so
  // when those are present the single-output `_newAmount` is redundant.
  // Otherwise (mutating-only or data-only methods) the single-output
  // continuation path needs `_newAmount` to size the new state UTXO.
  const needsNewAmount =
    (effects.mutatesState || effects.hasDataOutput) && !effects.hasStateOutput;
  return {
    needsChange,
    needsNewAmount,
    isTerminal: !needsChange,
  };
}
