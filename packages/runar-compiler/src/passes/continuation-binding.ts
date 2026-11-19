/**
 * D25 — bind every state continuation to the input that made it.
 *
 * SECURITY CORE (fund safety). Before D25 every stateful covenant checked
 * `hash256(continuation || change) == hashOutputs` over the WHOLE output list,
 * and the BIP-143 preimage carries no input position. Two UTXOs of one
 * contract spent in the same transaction that reach the same post-state
 * therefore rebuilt the identical list and were BOTH satisfied by ONE
 * continuation output: the second input's value left as the spender's change
 * ("twin-input theft"; D12 PRE-F1, mined on regtest for Counter).
 *
 * The binding is a property of the CONTRACT, not of a method: one method that
 * still commits the whole list under ALL lets its input reuse a sibling's
 * output (design §4.1). So the contract is classified once:
 *
 *   'single'    every continuation-producing public method is mutate-only (no
 *               addOutput / addRawOutput / addDataOutput) and reads nothing
 *               SINGLE zeroes or redefines. Those methods default to
 *               SIGHASH_SINGLE|FORKID (an ALL|ANYONECANPAY|FORKID directive
 *               becomes SINGLE|ANYONECANPAY|FORKID). BIP-143 SINGLE commits
 *               hashOutputs to output[inputIndex] alone, so consensus gives
 *               every input its own output, and the F-024 floor
 *               (`_newAmount >= extractAmount`) pins its value. An explicit
 *               `@sighash ALL|FORKID` on such a method is refused: it is the
 *               sibling that would reopen the twin.
 *   'bind'      the contract has at least one auto-continuation method (no
 *               addOutput / addRawOutput) but is not 'single' (it mixes them
 *               with addOutput methods, has data outputs, or a method that
 *               cannot run under SINGLE). Every continuation of the contract
 *               carries `sha256(extractOutpoint(txPreimage))` in a hidden last
 *               state field, so two inputs can never rebuild the same output
 *               list. +32 bytes of state on every UTXO.
 *   'explicit'  every continuation-producing method sizes its own outputs
 *               (addOutput / addRawOutput). The author owns conservation there
 *               (as `FungibleToken.merge`'s deliberate many-to-one shows); the
 *               aliasing is documented and an unsigned
 *               `addOutput(extractAmount(...))` is warned about.
 *   'none'      stateless, or no public method produces a continuation.
 *
 * The six native tiers carry the same classification, the same field name and
 * the same diagnostics.
 */
import type {
  ContractNode,
  Expression,
  MethodNode,
  PropertyNode,
  Statement,
  SourceLocation,
} from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import { computeSideEffectSummary, continuationShape } from './side-effect-summary.js';
import {
  BASE_ALL,
  BASE_SINGLE,
  BASE_TYPE_MASK,
  FLAG_ANYONECANPAY,
  FLAG_FORKID,
} from './sighash-directive.js';

/** The hidden state field of a 'bind' contract (reserved; last mutable property). */
export const TWIN_BINDING_FIELD = '_spentOutpointHash';

/** SIGHASH_SINGLE|FORKID. */
export const SIGHASH_SINGLE_FORKID = BASE_SINGLE | FLAG_FORKID;

export type ContinuationClass = 'none' | 'single' | 'bind' | 'explicit';

/** Builtins whose meaning SINGLE zeroes or redefines (a mutate-only method reading one keeps ALL). */
const SINGLE_INCOMPATIBLE_READS = new Set([
  'extractHashSequence',
  'extractOutputHash',
  'extractOutputs',
  'extractSigHashType',
  'requireOutputP2PKH',
]);

/** D25: the shared error text for an explicit ALL sibling in a 'single' contract. */
export function explicitAllSiblingMessage(method: string): string {
  return (
    `method '${method}': @sighash ALL|FORKID on a state-continuation method of a contract whose ` +
    `continuation methods are all mutate-only reopens twin-input theft: such a contract commits each ` +
    `continuation under SIGHASH_SINGLE (one output per input), and one ALL method lets its input reuse ` +
    `a sibling's output while its own value leaves as change. Remove the directive (the default is ` +
    `SINGLE|FORKID) or write @sighash SINGLE|FORKID`
  );
}

/** D25: the shared warning text for an unsigned value-conserving addOutput (D12 C1). */
export function unsignedAddOutputMessage(method: string): string {
  return (
    `method '${method}' re-creates the contract with addOutput(extractAmount(...), ...) and checks no ` +
    `signature: two UTXOs of this contract spent in one transaction that reach the same state are both ` +
    `satisfied by ONE such output, and the other input's value leaves as anyone's change (twin-input ` +
    `aliasing). A method that sizes its own outputs is not bound to its input; require a signature, or ` +
    `let the compiler size the continuation (write state instead of calling addOutput)`
  );
}

function calleeName(callee: Expression): string | undefined {
  if (callee.kind === 'identifier') return callee.name;
  if (callee.kind === 'property_access' || callee.kind === 'member_expr') return callee.property;
  return undefined;
}

/** Every call name reachable from `body`, through private helpers (cycle-guarded). */
function reachableCalls(body: Statement[], privates: Map<string, MethodNode>): Set<string> {
  const names = new Set<string>();
  const visiting = new Set<string>();
  const stmts = (ss: Statement[]): void => { for (const s of ss) stmt(s); };
  const stmt = (s: Statement): void => {
    switch (s.kind) {
      case 'assignment': expr(s.target); expr(s.value); return;
      case 'expression_statement': expr(s.expression); return;
      case 'if_statement': expr(s.condition); stmts(s.then); if (s.else) stmts(s.else); return;
      case 'for_statement': stmt(s.init); expr(s.condition); stmt(s.update); stmts(s.body); return;
      case 'return_statement': if (s.value) expr(s.value); return;
      case 'variable_decl': expr(s.init); return;
      default: return;
    }
  };
  const expr = (e: Expression): void => {
    switch (e.kind) {
      case 'call_expr': {
        const n = calleeName(e.callee);
        if (n !== undefined) {
          names.add(n);
          const t = privates.get(n);
          if (t && !visiting.has(n)) { visiting.add(n); stmts(t.body); visiting.delete(n); }
        }
        for (const a of e.args) expr(a);
        if (e.callee.kind !== 'identifier') expr(e.callee);
        return;
      }
      case 'binary_expr': expr(e.left); expr(e.right); return;
      case 'unary_expr': expr(e.operand); return;
      case 'ternary_expr': expr(e.condition); expr(e.consequent); expr(e.alternate); return;
      case 'index_access': expr(e.object); expr(e.index); return;
      case 'member_expr': expr(e.object); return;
      case 'array_literal': for (const x of e.elements) expr(x); return;
      default: return;
    }
  };
  stmts(body);
  return names;
}

interface Classification {
  cls: ContinuationClass;
  /** Public continuation methods (produce a state continuation), in declaration order. */
  continuationMethods: MethodNode[];
}

function privatesOf(contract: ContractNode): Map<string, MethodNode> {
  const m = new Map<string, MethodNode>();
  for (const x of contract.methods) if (x.visibility === 'private') m.set(x.name, x);
  return m;
}

/** Classify a contract (see the module comment). */
function classify(contract: ContractNode): Classification {
  if (contract.parentClass !== 'StatefulSmartContract') return { cls: 'none', continuationMethods: [] };
  const effects = computeSideEffectSummary(contract);
  const privates = privatesOf(contract);
  const continuationMethods: MethodNode[] = [];
  let anyAuto = false;
  let allSingleEligible = true;
  for (const m of contract.methods) {
    if (m.visibility !== 'public') continue;
    const e = effects.get(m.name);
    if (!e || !continuationShape(e).needsChange) continue;
    continuationMethods.push(m);
    if (!e.hasStateOutput) anyAuto = true;
    const mode = m.sighashType;
    const base = mode === undefined ? BASE_ALL : mode & BASE_TYPE_MASK;
    const modeOk = base === BASE_ALL || base === BASE_SINGLE;
    const reads = reachableCalls(m.body, privates);
    const readsOk = ![...reads].some((n) => SINGLE_INCOMPATIBLE_READS.has(n));
    if (e.hasStateOutput || e.hasDataOutput || !modeOk || !readsOk) allSingleEligible = false;
  }
  if (continuationMethods.length === 0) return { cls: 'none', continuationMethods };
  if (!anyAuto) return { cls: 'explicit', continuationMethods };
  return { cls: allSingleEligible ? 'single' : 'bind', continuationMethods };
}

/** The contract's D25 class (read by the injection pass and tests). */
export function continuationClass(contract: ContractNode): ContinuationClass {
  return classify(contract).cls;
}

/**
 * D25 resolution, run by pass 2 (validate) right before the `@sighash` field
 * checks so every later pass (sighash validation, typecheck guards, ANF
 * lowering, the assembler's ABI) sees the effective mode. In a 'single'
 * contract it sets each continuation method's `sighashType`; it refuses an
 * explicit pure-ALL directive there; in an 'explicit' contract it warns about
 * unsigned value-conserving addOutput methods. Idempotent.
 */
export function resolveContinuationBinding(contract: ContractNode): CompilerDiagnostic[] {
  const diags: CompilerDiagnostic[] = [];
  const { cls, continuationMethods } = classify(contract);
  if (cls === 'single') {
    for (const m of continuationMethods) {
      const mode = m.sighashType;
      if (mode === undefined) {
        m.sighashType = SIGHASH_SINGLE_FORKID;
      } else if ((mode & BASE_TYPE_MASK) === BASE_ALL) {
        if ((mode & FLAG_ANYONECANPAY) !== 0) {
          m.sighashType = (mode & ~BASE_TYPE_MASK) | BASE_SINGLE;
        } else {
          diags.push(makeDiagnostic(explicitAllSiblingMessage(m.name), 'error', m.sourceLocation));
        }
      }
    }
  } else if (cls === 'explicit') {
    const privates = privatesOf(contract);
    for (const m of continuationMethods) {
      const mode = m.sighashType;
      if (mode !== undefined && (mode & BASE_TYPE_MASK) !== BASE_ALL) continue;
      const loc = unsignedValueConservingAddOutput(m, privates);
      if (loc !== null) diags.push(makeDiagnostic(unsignedAddOutputMessage(m.name), 'warning', loc ?? m.sourceLocation));
    }
  }
  return diags;
}

/** A call name that verifies a signature (any scheme). */
function isSignatureCheck(name: string): boolean {
  return name === 'checkSig' || name === 'checkMultiSig' || name.startsWith('verify');
}

/**
 * D12 C1: the location of an `addOutput` whose satoshis argument reads
 * `extractAmount` (directly, or through a local initialised from it) in a
 * method that verifies no signature; `null` when there is none.
 */
function unsignedValueConservingAddOutput(
  method: MethodNode,
  privates: Map<string, MethodNode>,
): SourceLocation | undefined | null {
  const calls = reachableCalls(method.body, privates);
  if ([...calls].some(isSignatureCheck)) return null;
  const amountLocals = new Set<string>();
  const readsAmount = (e: Expression): boolean => {
    switch (e.kind) {
      case 'call_expr':
        return calleeName(e.callee) === 'extractAmount' || e.args.some(readsAmount);
      case 'identifier': return amountLocals.has(e.name);
      case 'binary_expr': return readsAmount(e.left) || readsAmount(e.right);
      case 'unary_expr': return readsAmount(e.operand);
      case 'ternary_expr': return readsAmount(e.condition) || readsAmount(e.consequent) || readsAmount(e.alternate);
      default: return false;
    }
  };
  let found: SourceLocation | undefined | null = null;
  const visiting = new Set<string>();
  const stmts = (ss: Statement[]): void => { for (const s of ss) stmt(s); };
  const stmt = (s: Statement): void => {
    switch (s.kind) {
      case 'variable_decl':
        if (readsAmount(s.init)) amountLocals.add(s.name);
        expr(s.init);
        return;
      case 'assignment': expr(s.value); return;
      case 'expression_statement': expr(s.expression); return;
      case 'if_statement': expr(s.condition); stmts(s.then); if (s.else) stmts(s.else); return;
      case 'for_statement': stmts(s.body); return;
      case 'return_statement': if (s.value) expr(s.value); return;
      default: return;
    }
  };
  const expr = (e: Expression): void => {
    if (e.kind !== 'call_expr') return;
    const n = calleeName(e.callee);
    if (n === 'addOutput' && e.args.length > 0 && readsAmount(e.args[0]!) && found === null) {
      found = e.sourceLocation;
    }
    const t = n !== undefined ? privates.get(n) : undefined;
    if (t && !visiting.has(t.name)) { visiting.add(t.name); stmts(t.body); visiting.delete(t.name); }
    for (const a of e.args) expr(a);
  };
  stmts(method.body);
  return found;
}

/**
 * D25 injection, run after typecheck (before fixed-array expansion): a 'bind'
 * contract gains the hidden `_spentOutpointHash: Sha256 = 0x00..00` as its
 * LAST property. ANF lowering then writes it in every auto-continuation and
 * appends it to every addOutput (`stateful-scaffold.ts`). The zero initializer
 * keeps it out of the constructor ABI. Returns the contract unchanged for any
 * other class.
 */
export function injectContinuationBinding(contract: ContractNode): ContractNode {
  if (classify(contract).cls !== 'bind') return contract;
  if (contract.properties.some((p) => p.name === TWIN_BINDING_FIELD)) return contract;
  const loc = contract.constructor.sourceLocation;
  const field: PropertyNode = {
    kind: 'property',
    name: TWIN_BINDING_FIELD,
    type: { kind: 'primitive_type', name: 'Sha256' },
    readonly: false,
    initializer: { kind: 'bytestring_literal', value: '00'.repeat(32) },
    sourceLocation: loc,
  };
  return { ...contract, properties: [...contract.properties, field] };
}
