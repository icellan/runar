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
 *   - `03-typecheck.ts` for the `requireOutputP2PKH` output-layout guards
 *     (Crit-3, R-300, index-0 continuation collision). F-075: those guards
 *     must see the same effects the continuation is injected from.
 *
 * Both consumers must read from one source of truth so the deployed ABI
 * cannot drift from the locking script's actual parameter expectations.
 *
 * Recursion across private methods is forbidden by the language
 * validator (`02-validate.ts`), so the call-graph walk terminates.
 */
import type { ContractNode, MethodNode, Statement, Expression } from '../ir/index.js';
import { BASE_SINGLE, BASE_TYPE_MASK, SIGHASH_DEFAULT } from './sighash-directive.js';

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
  /** Calls `requireOutputP2PKH(...)` with any output index. */
  callsRequireOutputP2PKH: boolean;
  /** Calls `requireOutputP2PKH(0n, ...)` (literal index 0). */
  requiresOutputP2PKHZero: boolean;
  /** Calls `extractPrevOutputScript(...)` (N-315). */
  callsExtractPrevOutputScript: boolean;
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
    callsRequireOutputP2PKH: false,
    requiresOutputP2PKHZero: false,
    callsExtractPrevOutputScript: false,
  };
}

function unionInto(target: MethodEffects, source: MethodEffects): void {
  target.mutatesState ||= source.mutatesState;
  target.hasStateOutput ||= source.hasStateOutput;
  target.hasDataOutput ||= source.hasDataOutput;
  target.usesPreimage ||= source.usesPreimage;
  target.callsRequireOutputP2PKH ||= source.callsRequireOutputP2PKH;
  target.requiresOutputP2PKHZero ||= source.requiresOutputP2PKHZero;
  target.callsExtractPrevOutputScript ||= source.callsExtractPrevOutputScript;
}

/** Raised by a body walk that needs a callee computed first (N-264). */
class NeedCallee {
  constructor(readonly name: string, readonly body: Statement[]) {}
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

  // N-264: the walk is ITERATIVE across calls. It used to compute a callee's
  // effects by recursing from inside the caller's statement walk, so the host
  // stack held every caller's nesting at once: a chain of D helpers that each
  // call the next under K nested ifs (both within their own bounds) needed
  // D*K frames and overflowed at D=32 x 120. Now a body walk that meets an
  // uncomputed callee abandons itself (`NeedCallee`), the callee is computed
  // first on an explicit work stack, and the caller's walk restarts. The walk
  // is pure, so a restart yields exactly what the recursive walk did, in the
  // same visit order with the same in-progress set — results (including the
  // empty effects a cyclic call gets) are unchanged.
  function effectsFor(methodName: string, body: Statement[]): MethodEffects {
    const cached = summary.get(methodName);
    if (cached) return cached;
    if (inProgress.has(methodName)) {
      // Treat in-progress (cyclic) calls as having no extra effects;
      // validation should have rejected the contract before we got
      // here. Returning empty avoids infinite recursion.
      return emptyEffects();
    }
    const work: { name: string; body: Statement[] }[] = [{ name: methodName, body }];
    inProgress.add(methodName);
    while (work.length > 0) {
      const top = work[work.length - 1]!;
      let effects: MethodEffects;
      try {
        effects = computeBodyEffects(top.body);
      } catch (e) {
        if (!(e instanceof NeedCallee)) throw e;
        inProgress.add(e.name);
        work.push({ name: e.name, body: e.body });
        continue;
      }
      work.pop();
      inProgress.delete(top.name);
      summary.set(top.name, effects);
    }
    return summary.get(methodName)!;
  }

  /** A callee's effects for the walk in progress; see `effectsFor`. */
  function calleeEffects(target: MethodNode): MethodEffects {
    const cached = summary.get(target.name);
    if (cached) return cached;
    if (inProgress.has(target.name)) return emptyEffects();
    throw new NeedCallee(target.name, target.body);
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
        // Both sides may still contain calls (output intrinsics could hide in
        // the target's index/object as well as the value).
        collectExpr(stmt.target, into);
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
        // Walk the full loop header: an output intrinsic can hide in init or
        // condition, not only in update/body.
        collectStmt(stmt.init, into);
        collectExpr(stmt.condition, into);
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
            unionInto(into, calleeEffects(target));
          }
        }

        // Bareword calls: identifiers that resolve to private methods (Go/Rust
        // surface formats route private helpers as bare identifiers) or to
        // builtins like `checkPreimage`.
        if (callee.kind === 'identifier') {
          if (callee.name === 'checkPreimage') into.usesPreimage = true;
          if (callee.name === 'requireOutputP2PKH') {
            into.callsRequireOutputP2PKH = true;
            const idx = expr.args[0];
            if (idx && idx.kind === 'bigint_literal' && idx.value === 0n) {
              into.requiresOutputP2PKHZero = true;
            }
          }
          if (callee.name === 'extractPrevOutputScript') into.callsExtractPrevOutputScript = true;
          const target = privateMethodsByName.get(callee.name);
          if (target) {
            unionInto(into, calleeEffects(target));
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
 * `needsChange` is true when the method produces a continuation.
 * `includesChange` controls injection of `_changePKH` and `_changeAmount`
 * and the change segment of the continuation hash: it equals `needsChange`
 * except under a SIGHASH_SINGLE base, where BIP-143 commits hashOutputs to
 * the same-index output ONLY, so the change output is not part of the
 * committed set and the method takes no change params (N-038).
 * `needsNewAmount` controls injection of `_newAmount`. These map
 * directly to ANF auto-param insertion and ABI param declaration; both
 * sites must agree for a deployed contract to be spendable.
 *
 * `isTerminal` is the inverse of `needsChange` for stateful public
 * methods — a method is terminal iff it produces no continuation.
 */
export interface ContinuationShape {
  needsChange: boolean;
  includesChange: boolean;
  needsNewAmount: boolean;
  isTerminal: boolean;
}

export function continuationShape(
  effects: MethodEffects,
  sighashType: number = SIGHASH_DEFAULT,
): ContinuationShape {
  const needsChange =
    effects.mutatesState || effects.hasStateOutput || effects.hasDataOutput;
  const includesChange = needsChange && (sighashType & BASE_TYPE_MASK) !== BASE_SINGLE;
  // `addOutput`/`addRawOutput` already specify per-output amounts, so
  // when those are present the single-output `_newAmount` is redundant.
  // Otherwise (mutating-only or data-only methods) the single-output
  // continuation path needs `_newAmount` to size the new state UTXO.
  const needsNewAmount =
    (effects.mutatesState || effects.hasDataOutput) && !effects.hasStateOutput;
  return {
    needsChange,
    includesChange,
    needsNewAmount,
    isTerminal: !needsChange,
  };
}
