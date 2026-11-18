/**
 * Two rules about where a StatefulSmartContract's satoshis can go, both read
 * off the side-effect summary (`side-effect-summary.ts`), so they see exactly
 * the effects the continuation is injected from. The six native tiers carry
 * the same rules and the same texts.
 *
 * #199 (warning). A public stateful method is terminal iff it writes no state
 * and declares no output (`continuationShape().isTerminal`). Every other
 * method either sizes its own outputs (`addOutput` / `addRawOutput`, directly
 * or through an inlined private helper) or takes the default single-output
 * continuation, whose F-024 floor (`_newAmount >= extractAmount(txPreimage)`,
 * `emitStatefulContinuation`) lets the value grow but never shrink. A contract
 * none of whose public methods is terminal or sizes its own outputs therefore
 * keeps every satoshi locked in its instances forever. That is sometimes
 * meant (a perpetual counter), so it is a warning, not an error.
 *
 * D18 (error), PER PATH. Any `addOutput` / `addRawOutput` anywhere in a
 * method (directly or in an inlined helper, on any branch) replaces the
 * auto-injected continuation for the WHOLE method: the multi-output path hashes
 * exactly the outputs the taken path declared, then change. Only `addOutput`
 * carries state. So in such a method, a path that writes state and reaches no
 * `addOutput` drops its write: the spend is valid, the contract's remaining
 * value goes to the spender's change, and the SDK tracks a raw output as if it
 * were the contract's UTXO. Shapes: a write with only raw outputs; a write on
 * a raw-output branch whose sibling branch calls `addOutput`; a write before
 * an `addOutput` that only one branch reaches. A path that writes nothing is a
 * terminal path by design and is accepted. `addDataOutput` does not replace
 * the continuation and is no trigger.
 *
 * The analysis tracks, per path, two flags (state written, addOutput reached),
 * so a statement list has at most four distinct path states and nothing
 * explodes: `if` unions its arms, a loop body unions with skipping it, a
 * private helper call composes the caller's states with the helper's exit
 * states (a helper `return` ends the helper's path, not the caller's), and an
 * expression is walked in full as if every call in it runs (a write or an
 * addOutput inside a condition counts on every path through it; output
 * intrinsics in ternaries and loops are refused elsewhere).
 */
import type { ANFBinding, ANFMethod, ANFProgram } from '../ir/index.js';
import type { ContractNode, Expression, MethodNode, Statement } from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import { continuationShape } from './side-effect-summary.js';
import type { MethodEffects, SideEffectSummary } from './side-effect-summary.js';

/** #199: the shared warning text. */
export function releaseTrapMessage(contract: string): string {
  return (
    `contract '${contract}' has no terminal method and no public method that calls ` +
    `addOutput/addRawOutput; its satoshis can never leave instances of '${contract}'`
  );
}

/** D18: the shared error text. */
export function droppedContinuationMessage(method: string): string {
  return (
    `method '${method}' writes contract state on a path that reaches no addOutput(): a method ` +
    `that declares its own outputs (addOutput/addRawOutput) gets no auto-injected continuation, ` +
    `so on that path the state write would be lost and the contract's satoshis would leave with ` +
    `the spend. Add this.addOutput(satoshis, ...) on every path that writes state, or stop ` +
    `writing state on a path meant to end the contract`
  );
}

/** Path-state bits: state written / addOutput reached. */
const W = 1;
const A = 2;
/** A path that wrote state and reached no addOutput. */
const dropped = (states: Iterable<number>): boolean => [...states].some((x) => (x & W) !== 0 && (x & A) === 0);
const orAll = (states: Set<number>, bits: number): Set<number> => new Set([...states].map((x) => x | bits));

/**
 * D18 (source path): `effects` is the method's side-effect summary entry. True
 * iff the method declares a state output somewhere (so it gets no
 * auto-continuation) and some path through it writes state without reaching
 * an addOutput.
 */
export function dropsContinuation(contract: ContractNode, method: MethodNode, effects: MethodEffects): boolean {
  if (!effects.hasStateOutput) return false;
  return dropped(new SourcePaths(contract).exits(method.body));
}

class SourcePaths {
  private readonly mutable: Set<string>;
  private readonly privates = new Map<string, MethodNode>();
  private readonly helperExits = new Map<string, Set<number>>();
  private readonly inProgress = new Set<string>();

  constructor(contract: ContractNode) {
    this.mutable = new Set(contract.properties.filter((p) => !p.readonly).map((p) => p.name));
    for (const m of contract.methods) if (m.visibility === 'private') this.privates.set(m.name, m);
  }

  /** Exit states (fallthrough and return) of a body entered with a fresh path. */
  exits(body: Statement[]): Set<number> {
    const { live, returned } = this.stmts(body, new Set([0]));
    return new Set([...live, ...returned]);
  }

  private stmts(stmts: Statement[], states: Set<number>): { live: Set<number>; returned: Set<number> } {
    let live = states;
    const returned = new Set<number>();
    for (const st of stmts) {
      if (live.size === 0) break;
      const r = this.stmt(st, live);
      for (const x of r.returned) returned.add(x);
      live = r.live;
    }
    return { live, returned };
  }

  private stmt(st: Statement, states: Set<number>): { live: Set<number>; returned: Set<number> } {
    const none = new Set<number>();
    switch (st.kind) {
      case 'assignment': {
        let s = this.expr(st.target, states);
        s = this.expr(st.value, s);
        if (this.writesMutable(st.target)) s = orAll(s, W);
        return { live: s, returned: none };
      }
      case 'expression_statement':
        return { live: this.expr(st.expression, states), returned: none };
      case 'variable_decl':
        return { live: this.expr(st.init, states), returned: none };
      case 'return_statement':
        return { live: none, returned: st.value ? this.expr(st.value, states) : states };
      case 'if_statement': {
        const c = this.expr(st.condition, states);
        const t = this.stmts(st.then, c);
        const e = st.else ? this.stmts(st.else, c) : { live: c, returned: none };
        return { live: new Set([...t.live, ...e.live]), returned: new Set([...t.returned, ...e.returned]) };
      }
      case 'for_statement': {
        const init = this.stmt(st.init, states);
        const c = this.expr(st.condition, init.live);
        const body = this.stmts(st.body, c);
        const upd = this.stmt(st.update, body.live);
        return {
          live: new Set([...c, ...upd.live]),
          returned: new Set([...init.returned, ...body.returned, ...upd.returned]),
        };
      }
      default:
        return { live: states, returned: none };
    }
  }

  private writesMutable(target: Expression): boolean {
    let t = target;
    while (t.kind === 'index_access') t = t.object;
    return t.kind === 'property_access' && this.mutable.has(t.property);
  }

  /** Every call in `e` runs, in evaluation order. */
  private expr(e: Expression, states: Set<number>): Set<number> {
    switch (e.kind) {
      case 'increment_expr':
      case 'decrement_expr': {
        const s = this.expr(e.operand, states);
        return this.writesMutable(e.operand) ? orAll(s, W) : s;
      }
      case 'call_expr': {
        let s = states;
        if (e.callee.kind !== 'identifier') s = this.expr(e.callee, s);
        for (const a of e.args) s = this.expr(a, s);
        const callee = e.callee;
        const name =
          callee.kind === 'property_access' || callee.kind === 'member_expr' ? callee.property
            : callee.kind === 'identifier' ? callee.name
              : undefined;
        if ((callee.kind === 'property_access' || callee.kind === 'member_expr') && name === 'addOutput') {
          return orAll(s, A);
        }
        const helper = name !== undefined ? this.privates.get(name) : undefined;
        if (helper) {
          const ex = this.helper(helper);
          const out = new Set<number>();
          for (const x of s) for (const y of ex) out.add(x | y);
          return out;
        }
        return s;
      }
      case 'binary_expr':
        return this.expr(e.right, this.expr(e.left, states));
      case 'unary_expr':
        return this.expr(e.operand, states);
      case 'ternary_expr': {
        const c = this.expr(e.condition, states);
        return new Set([...this.expr(e.consequent, c), ...this.expr(e.alternate, c)]);
      }
      case 'index_access':
        return this.expr(e.index, this.expr(e.object, states));
      case 'member_expr':
        return this.expr(e.object, states);
      case 'array_literal': {
        let s = states;
        for (const el of e.elements) s = this.expr(el, s);
        return s;
      }
      default:
        return states;
    }
  }

  private helper(m: MethodNode): Set<number> {
    const cached = this.helperExits.get(m.name);
    if (cached) return cached;
    // Recursion is refused by the validator; a cycle contributes nothing.
    if (this.inProgress.has(m.name)) return new Set([0]);
    this.inProgress.add(m.name);
    const ex = this.exits(m.body);
    this.inProgress.delete(m.name);
    this.helperExits.set(m.name, ex);
    return ex;
  }
}

/** #199: the contract-level warning, when it applies (stateful contracts only). */
export function releaseTrapWarning(
  contract: ContractNode,
  summary: SideEffectSummary,
): CompilerDiagnostic | undefined {
  if (contract.parentClass !== 'StatefulSmartContract') return undefined;
  const publics = contract.methods.filter((m) => m.visibility === 'public');
  if (publics.length === 0) return undefined;
  const trapped = publics.every((m) => {
    const effects = summary.get(m.name);
    if (!effects) return false;
    return !continuationShape(effects).isTerminal && !effects.hasStateOutput;
  });
  if (!trapped) return undefined;
  // Contract-level: ContractNode carries no source location of its own.
  return makeDiagnostic(releaseTrapMessage(contract.name), 'warning');
}

/**
 * D18 on the --ir path: compileFromANF skips typecheck, so the rule is
 * re-derived from the ANF (update_prop = state write, add_output /
 * add_raw_output = declared outputs, through method_calls to private methods).
 * Called for StatefulSmartContract programs after the N-101 scaffolding check.
 */
export function assertIrNoDroppedContinuation(program: ANFProgram): void {
  const privates = new Map(
    program.methods.filter((m) => !m.isPublic && m.name !== 'constructor').map((m) => [m.name, m]),
  );
  for (const method of program.methods) {
    if (!method.isPublic || method.name === 'constructor') continue;
    if (irDropsContinuation(method, privates)) {
      throw new Error(droppedContinuationMessage(method.name));
    }
  }
}

/**
 * The per-path rule on ANF: update_prop = state write, add_output = addOutput,
 * add_raw_output / add_output = a declared output (suppresses the
 * auto-continuation). `if` unions its arms, a loop body unions with skipping
 * it, a method_call to a private method composes with that method's exits.
 */
function irDropsContinuation(method: ANFMethod, privates: Map<string, ANFMethod>): boolean {
  const declares = (bs: ANFBinding[], seen: Set<string>): boolean =>
    bs.some((b) => {
      const v = b.value;
      if (v.kind === 'add_output' || v.kind === 'add_raw_output') return true;
      if (v.kind === 'method_call') {
        const t = privates.get(v.method);
        if (t && !seen.has(t.name)) {
          seen.add(t.name);
          if (declares(t.body, seen)) return true;
        }
      }
      const n = v as { then?: ANFBinding[]; else?: ANFBinding[]; body?: ANFBinding[] };
      return [n.then, n.else, n.body].some((x) => Array.isArray(x) && declares(x, seen));
    });
  if (!declares(method.body, new Set())) return false;

  const exitsOf = new Map<string, Set<number>>();
  const inProgress = new Set<string>();
  const run = (bs: ANFBinding[], states: Set<number>): Set<number> => {
    let s = states;
    for (const b of bs) {
      const v = b.value;
      if (v.kind === 'update_prop') s = orAll(s, W);
      else if (v.kind === 'add_output') s = orAll(s, A);
      else if (v.kind === 'method_call') {
        const t = privates.get(v.method);
        if (t) {
          let ex = exitsOf.get(t.name);
          if (!ex) {
            if (inProgress.has(t.name)) ex = new Set([0]);
            else {
              inProgress.add(t.name);
              ex = run(t.body, new Set([0]));
              inProgress.delete(t.name);
              exitsOf.set(t.name, ex);
            }
          }
          const out = new Set<number>();
          for (const x of s) for (const y of ex) out.add(x | y);
          s = out;
        }
      } else {
        const n = v as { then?: ANFBinding[]; else?: ANFBinding[]; body?: ANFBinding[] };
        if (Array.isArray(n.then) || Array.isArray(n.else)) {
          const t = Array.isArray(n.then) ? run(n.then, s) : s;
          const e = Array.isArray(n.else) ? run(n.else, s) : s;
          s = new Set([...t, ...e]);
        } else if (Array.isArray(n.body)) {
          s = new Set([...s, ...run(n.body, s)]);
        }
      }
    }
    return s;
  };
  return dropped(run(method.body, new Set([0])));
}
