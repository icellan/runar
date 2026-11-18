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
 * D18 (error). Any `addOutput` / `addRawOutput` in a method replaces the
 * auto-injected continuation (the multi-output path hashes exactly the
 * declared outputs, then change). `addRawOutput` writes caller-chosen script
 * bytes, never the contract's state, so a method that writes state and calls
 * `addRawOutput` but never `addOutput` drops its state write: the spend is
 * valid, the contract's remaining value goes to the spender's change, and the
 * SDK tracks the raw output as if it were the contract's UTXO. `addDataOutput`
 * does not replace the continuation and is no trigger. The rule is per method,
 * not per path (a write on a branch whose sibling calls `addOutput` passes).
 */
import type { ANFBinding, ANFMethod, ANFProgram } from '../ir/index.js';
import type { ContractNode } from '../ir/index.js';
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
    `method '${method}' writes contract state but emits no state continuation: it calls ` +
    `addRawOutput() without addOutput(), and a method that declares its own outputs gets no ` +
    `auto-injected continuation, so the state write would be lost and the contract's satoshis ` +
    `would leave with the spend. Add this.addOutput(satoshis, ...) to carry the new state, or ` +
    `stop writing state in a method meant to end the contract`
  );
}

/** D18: the method writes state and only raw outputs replace its continuation. */
export function dropsContinuation(effects: MethodEffects): boolean {
  return effects.mutatesState && effects.hasStateOutput && !effects.callsAddOutput;
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

function irDropsContinuation(method: ANFMethod, privates: Map<string, ANFMethod>): boolean {
  let writes = false;
  let raw = false;
  let add = false;
  const visited = new Set<string>();
  const walk = (bindings: ANFBinding[]): void => {
    for (const b of bindings) {
      const v = b.value;
      if (v.kind === 'update_prop') writes = true;
      if (v.kind === 'add_raw_output') raw = true;
      if (v.kind === 'add_output') add = true;
      if (v.kind === 'method_call') {
        const target = privates.get(v.method);
        if (target && !visited.has(target.name)) {
          visited.add(target.name);
          walk(target.body);
        }
      }
      const n = v as { then?: ANFBinding[]; else?: ANFBinding[]; body?: ANFBinding[] };
      for (const inner of [n.then, n.else, n.body]) if (Array.isArray(inner)) walk(inner);
    }
  };
  walk(method.body);
  return writes && raw && !add;
}
