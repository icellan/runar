/**
 * The scaffolding StatefulSmartContract lowering injects into every public
 * method, and (N-101) the check that an `--ir` program carries exactly it.
 *
 * `04-anf-lower.ts` builds each public stateful method as
 *
 *   prologue      checkPreimage(txPreimage), the sighash-type assert and, when
 *                 the contract has mutable properties, deserialize_state
 *   user code     free
 *   continuation  when the method mutates state or declares outputs: the
 *                 `_newAmount` floor (single-output form), the change output
 *                 and the hashOutputs comparison over every output in order
 *
 * and both halves are emitted by the two functions below, so the frontend and
 * the `--ir` check cannot drift apart.
 *
 * N-101: `--ir` input skips the frontend, so a program labelled (or, per
 * N-087, inferred) StatefulSmartContract could omit or fake this scaffolding
 * and compile to an anyone-can-spend script — F-107's attack body compiled to
 * `76767b8777`. `assertIrStatefulScaffolding` re-derives, per public method,
 * the scaffolding the frontend would inject (the continuation shape from the
 * method's own update_prop / output nodes, followed through private
 * `method_call`s) and refuses the program when the declared parameters or the
 * bindings differ. The six native tiers carry the same check and diagnostics.
 */
import type { ANFBinding, ANFMethod, ANFProgram, ANFValue } from '../ir/index.js';
import { continuationShape } from './side-effect-summary.js';
import type { ContinuationShape } from './side-effect-summary.js';
import { SIGHASH_DEFAULT } from './sighash-directive.js';

/** What the two emitters need from a lowering context. */
export interface ScaffoldContext<C> {
  emit(value: ANFValue): string;
  subContext(): C;
  syncCounter(sub: C): void;
  readonly bindings: ANFBinding[];
}

/**
 * The prologue: `assert(checkPreimage(txPreimage))`, the sighash-type assert
 * and, when the contract has mutable properties, `deserialize_state`.
 */
export function emitStatefulPrologue<C extends ScaffoldContext<C>>(
  ctx: C,
  sighashMode: number,
  hasMutableState: boolean,
): void {
  const isDefaultSighash = sighashMode === SIGHASH_DEFAULT;

  // Inject checkPreimage(txPreimage) at the start
  const preimageRef = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
  const checkResult = ctx.emit({
    kind: 'check_preimage',
    preimage: preimageRef,
    // Omit for the default so the ANF (and pinned binding blob) is unchanged.
    ...(isDefaultSighash ? {} : { sighashFlag: sighashMode }),
  });
  ctx.emit({ kind: 'assert', value: checkResult });

  // GAP-302 / #123: pin the sighash type to the declared mode. The
  // auto-injected covenant verifies a real tx preimage, but without this
  // check the spend could use a DIFFERENT sighash flag than declared that
  // zeroes out preimage fields the contract (or its continuation) relies on
  // (hashOutputs / hashPrevouts / hashSequence). The value defaults to 0x41
  // (SIGHASH_ALL|FORKID) so existing contracts emit byte-identical ANF.
  const sigHashPreimageRef = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
  const sigHashTypeRef = ctx.emit({ kind: 'call', func: 'extractSigHashType', args: [sigHashPreimageRef] });
  const expectedSigHashRef = ctx.emit({ kind: 'load_const', value: BigInt(sighashMode) });
  const sigHashOkRef = ctx.emit({ kind: 'bin_op', op: '===', left: sigHashTypeRef, right: expectedSigHashRef });
  ctx.emit({ kind: 'assert', value: sigHashOkRef });

  // Deserialize mutable state from the preimage's scriptCode.
  if (hasMutableState) {
    const preimageRef3 = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
    ctx.emit({ kind: 'deserialize_state', preimage: preimageRef3 });
  }
}

/**
 * The state continuation, emitted after the user's code when the method's
 * shape needs one (nothing otherwise).
 *
 * === Continuation-hash construction (reference for other compilers) ===
 *
 * The auto-injected continuation assertion verifies that the spending
 * transaction's hashOutputs field matches a compiler-constructed hash
 * over the outputs this method declares. Outputs are concatenated in
 * the following order before hashing with hash256:
 *
 *   1. state outputs       (from this.addOutput / this.addRawOutput,
 *                           tracked via addOutputRef)
 *   2. data outputs        (from this.addDataOutput, tracked via
 *                           addDataOutputRef) — NEW
 *   3. change output       (P2PKH to _changePKH, value = _changeAmount)
 *
 * For the "single-output" fast path (no addOutput used, but state is
 * mutated), the state output is computed on the fly from
 * (preimage, stateScript, _newAmount) instead of coming from
 * addOutputRefs. Data outputs may still be declared in this mode and
 * are inserted BETWEEN the single state output and the change output.
 *
 * If no state output and no data output is present, the legacy
 * single-output path applies (no data-output insertion needed).
 */
export function emitStatefulContinuation<C extends ScaffoldContext<C>>(
  ctx: C,
  shape: ContinuationShape,
  addOutputRefs: readonly string[],
  addDataOutputRefs: readonly string[],
): void {
  if (!shape.needsChange) return;

  // F-024 (R14): the default single-output continuation carries the
  // spender-chosen `_newAmount` into the new state UTXO. Without this
  // check a spender sets `_newAmount = 1` and pays the rest of the
  // input value to their own change output — the committed outputs
  // then match the covenant's hash exactly. Value may grow (a deposit
  // paid by a funding input) but never shrink below the input amount.
  // addOutput/addRawOutput methods size their outputs explicitly and
  // terminal methods have no continuation, so neither gets the check.
  if (addOutputRefs.length === 0) {
    const amountPreimageRef = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
    const inputAmountRef = ctx.emit({ kind: 'call', func: 'extractAmount', args: [amountPreimageRef] });
    const newAmountCheckRef = ctx.emit({ kind: 'load_param', name: '_newAmount' });
    const amountOkRef = ctx.emit({ kind: 'bin_op', op: '>=', left: newAmountCheckRef, right: inputAmountRef });
    ctx.emit({ kind: 'assert', value: amountOkRef });
  }

  // Build the P2PKH change output for hashOutputs verification.
  //
  // Issue #116: the SDK's buildCallTransaction OMITS the change output
  // when `change <= 0` (an exact-cover call) and passes `_changeAmount =
  // 0`. Gate the change segment on `_changeAmount != 0` at runtime so the
  // hashed output set matches the SDK at the exact-zero boundary — the
  // segment is the P2PKH change output when non-zero, and empty bytes
  // (cat with empty is a no-op) when zero, reproducing the omission. For
  // any change > 0 the hashed bytes are unchanged; only the emitted
  // script gains the guard.
  const changePKHRef = ctx.emit({ kind: 'load_param', name: '_changePKH' });
  const changeAmountRef = ctx.emit({ kind: 'load_param', name: '_changeAmount' });
  const zeroRef = ctx.emit({ kind: 'load_const', value: 0n });
  const changeNonZeroRef = ctx.emit({ kind: 'bin_op', op: '!==', left: changeAmountRef, right: zeroRef });
  const changeThenCtx = ctx.subContext();
  changeThenCtx.emit({ kind: 'call', func: 'buildChangeOutput', args: [changePKHRef, changeAmountRef] });
  ctx.syncCounter(changeThenCtx);
  const changeElseCtx = ctx.subContext();
  changeElseCtx.emit({ kind: 'load_const', value: '' });
  ctx.syncCounter(changeElseCtx);
  const changeOutputRef = ctx.emit({
    kind: 'if',
    cond: changeNonZeroRef,
    then: changeThenCtx.bindings,
    else: changeElseCtx.bindings,
  });

  if (addOutputRefs.length > 0) {
    // Multi-output continuation: concat all state outputs, then all
    // data outputs, then change output, then hash.
    let accumulated = addOutputRefs[0]!;
    for (let i = 1; i < addOutputRefs.length; i++) {
      accumulated = ctx.emit({ kind: 'call', func: 'cat', args: [accumulated, addOutputRefs[i]!] });
    }
    for (const dataRef of addDataOutputRefs) {
      accumulated = ctx.emit({ kind: 'call', func: 'cat', args: [accumulated, dataRef] });
    }
    accumulated = ctx.emit({ kind: 'call', func: 'cat', args: [accumulated, changeOutputRef] });
    const hashRef = ctx.emit({ kind: 'call', func: 'hash256', args: [accumulated] });
    const preimageRef2 = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
    const outputHashRef = ctx.emit({ kind: 'call', func: 'extractOutputHash', args: [preimageRef2] });
    const eqRef = ctx.emit({ kind: 'bin_op', op: '===', left: hashRef, right: outputHashRef, result_type: 'bytes' });
    ctx.emit({ kind: 'assert', value: eqRef, isAutoInjectedStateCheck: true });
  } else {
    // Single-output continuation: build raw output bytes, then splice in
    // any declared data outputs, then concat with change, then hash.
    const stateScriptRef = ctx.emit({ kind: 'get_state_script' });
    const preimageRef2 = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
    const newAmountRef = ctx.emit({ kind: 'load_param', name: '_newAmount' });
    const contractOutputRef = ctx.emit({ kind: 'call', func: 'computeStateOutput', args: [preimageRef2, stateScriptRef, newAmountRef] });
    let accumulated = contractOutputRef;
    for (const dataRef of addDataOutputRefs) {
      accumulated = ctx.emit({ kind: 'call', func: 'cat', args: [accumulated, dataRef] });
    }
    const allOutputs = ctx.emit({ kind: 'call', func: 'cat', args: [accumulated, changeOutputRef] });
    const hashRef = ctx.emit({ kind: 'call', func: 'hash256', args: [allOutputs] });
    const preimageRef4 = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
    const outputHashRef = ctx.emit({ kind: 'call', func: 'extractOutputHash', args: [preimageRef4] });
    const eqRef = ctx.emit({ kind: 'bin_op', op: '===', left: hashRef, right: outputHashRef, result_type: 'bytes' });
    ctx.emit({ kind: 'assert', value: eqRef, isAutoInjectedStateCheck: true });
  }
}

// ---------------------------------------------------------------------------
// N-101: the --ir check
// ---------------------------------------------------------------------------

/** Mints binding names no actual binding of the method uses. */
class ExpectedContext implements ScaffoldContext<ExpectedContext> {
  readonly bindings: ANFBinding[] = [];
  constructor(private readonly names: { taken: ReadonlySet<string>; next: number; minted: Set<string> }) {}
  emit(value: ANFValue): string {
    let name: string;
    do name = `$scaffold${this.names.next++}`; while (this.names.taken.has(name));
    this.names.minted.add(name);
    this.bindings.push({ name, value });
    return name;
  }
  subContext(): ExpectedContext {
    return new ExpectedContext(this.names);
  }
  syncCounter(): void {}
}

const OUTPUT_STATE_KINDS = new Set(['add_output', 'add_raw_output']);
const DATA_OUTPUT_KINDS = new Set(['add_data_output']);

function nested(v: ANFValue): ANFBinding[][] {
  const n = v as { then?: ANFBinding[]; else?: ANFBinding[]; body?: ANFBinding[] };
  return [n.then, n.else, n.body].filter((b): b is ANFBinding[] => Array.isArray(b));
}

function containsKind(bindings: ANFBinding[], kinds: ReadonlySet<string>): boolean {
  return bindings.some((b) => kinds.has(b.value.kind) || nested(b.value).some((n) => containsKind(n, kinds)));
}

/**
 * The frontend's side-effect summary, read off the IR: update_prop is a state
 * mutation (N-087 has refused readonly and undeclared writes by now),
 * add_output / add_raw_output a state output, add_data_output a data output,
 * at any depth and through `method_call`s to private methods.
 */
function irMethodShape(program: ANFProgram, method: ANFMethod): ContinuationShape {
  const effects = {
    mutatesState: false, hasStateOutput: false, hasDataOutput: false,
    usesPreimage: false, callsRequireOutputP2PKH: false, requiresOutputP2PKHZero: false,
  };
  const privates = new Map(
    program.methods.filter((m) => !m.isPublic && m.name !== 'constructor').map((m) => [m.name, m]),
  );
  const visited = new Set<string>();
  const walk = (bindings: ANFBinding[]): void => {
    for (const b of bindings) {
      const v = b.value;
      if (v.kind === 'update_prop') effects.mutatesState = true;
      if (OUTPUT_STATE_KINDS.has(v.kind)) effects.hasStateOutput = true;
      if (v.kind === 'add_data_output') effects.hasDataOutput = true;
      if (v.kind === 'method_call') {
        const target = privates.get(v.method);
        if (target && !visited.has(target.name)) {
          visited.add(target.name);
          walk(target.body);
        }
      }
      for (const n of nested(v)) walk(n);
    }
  };
  walk(method.body);
  return continuationShape(effects);
}

function describe(v: ANFValue): string {
  switch (v.kind) {
    case 'load_param': return `load_param ${v.name}`;
    case 'load_const': return `load_const ${typeof v.value === 'string' ? JSON.stringify(v.value) : String(v.value)}`;
    case 'call': return `call ${v.func}`;
    case 'bin_op': return `bin_op ${v.op}`;
    default: return v.kind;
  }
}

/** Structural equality of one expected scaffolding binding with the actual one. */
function sameBinding(exp: ANFBinding, act: ANFBinding, map: Map<string, string>, mapped: Set<string>): boolean {
  const e = exp.value as unknown as Record<string, unknown>;
  const a = act.value as unknown as Record<string, unknown>;
  const ref = (er: unknown, ar: unknown): boolean =>
    typeof er === 'string' && typeof ar === 'string' && (map.has(er) ? map.get(er) === ar : er === ar);
  if (e.kind !== a.kind) return false;
  let ok: boolean;
  switch (e.kind) {
    case 'load_param':
      ok = e.name === a.name;
      break;
    case 'load_const':
      ok = typeof e.value === typeof a.value && e.value === a.value;
      break;
    case 'check_preimage':
      ok = ref(e.preimage, a.preimage)
        && (e.sighashFlag ?? SIGHASH_DEFAULT) === (a.sighashFlag ?? SIGHASH_DEFAULT);
      break;
    case 'assert':
      ok = ref(e.value, a.value);
      break;
    case 'call': {
      const ea = e.args as string[];
      const aa = a.args;
      ok = e.func === a.func && Array.isArray(aa) && aa.length === ea.length && ea.every((r, i) => ref(r, aa[i]));
      break;
    }
    case 'bin_op':
      ok = e.op === a.op && ref(e.left, a.left) && ref(e.right, a.right)
        // An empty result_type reads as absent, as in the six native tiers.
        && (e.result_type || null) === (a.result_type || null);
      break;
    case 'deserialize_state':
      ok = ref(e.preimage, a.preimage);
      break;
    case 'get_state_script':
      ok = true;
      break;
    case 'if': {
      const results = a.results as unknown[] | undefined;
      ok = ref(e.cond, a.cond) && (results === undefined || results.length === 0)
        && sameSequence(e.then as ANFBinding[], a.then as ANFBinding[], map, mapped) === -1
        && sameSequence(e.else as ANFBinding[], a.else as ANFBinding[], map, mapped) === -1;
      break;
    }
    default:
      ok = false;
  }
  if (!ok || mapped.has(act.name)) return false;
  map.set(exp.name, act.name);
  mapped.add(act.name);
  return true;
}

/** Index of the first binding that differs (a missing one included), or -1. */
function sameSequence(
  exp: ANFBinding[], act: ANFBinding[] | undefined, map: Map<string, string>, mapped: Set<string>,
): number {
  const actual = Array.isArray(act) ? act : [];
  for (let i = 0; i < exp.length; i++) {
    const a = actual[i];
    if (a === undefined || !sameBinding(exp[i]!, a, map, mapped)) return i;
  }
  return actual.length === exp.length ? -1 : exp.length;
}

function collectNames(bindings: ANFBinding[], counts: Map<string, number>): void {
  const bump = (n: string): void => { counts.set(n, (counts.get(n) ?? 0) + 1); };
  for (const b of bindings) {
    bump(b.name);
    const v = b.value as { results?: unknown; iterVar?: unknown };
    if (Array.isArray(v.results)) for (const r of v.results) if (typeof r === 'string') bump(r);
    if (typeof v.iterVar === 'string') bump(v.iterVar);
    for (const n of nested(b.value)) collectNames(n, counts);
  }
}

function scaffoldError(method: string, detail: string): Error {
  return new Error(
    `IR validation: stateful method '${method}' does not carry the scaffolding StatefulSmartContract lowering injects: ${detail}`,
  );
}

/**
 * N-101: refuse a StatefulSmartContract `--ir` program any of whose public
 * methods lacks, reorders or alters the scaffolding the frontend injects.
 * Checked per public method, in program order: (1) the auto-injected
 * parameters; (2) the prologue; (3) the continuation; (4) every scaffolding
 * binding, and every output the continuation commits to, is bound exactly once
 * and shares no property or parameter name.
 */
export function assertIrStatefulScaffolding(program: ANFProgram): void {
  const hasMutableState = program.properties.some((p) => !p.readonly);
  const propNames = new Set(program.properties.map((p) => p.name));

  for (const method of program.methods) {
    if (!method.isPublic || method.name === 'constructor') continue;
    const shape = irMethodShape(program, method);

    // (1) the parameters, contiguous and once each.
    const required: Array<[string, string]> = [];
    if (shape.needsChange) required.push(['_changePKH', 'Ripemd160'], ['_changeAmount', 'bigint']);
    if (shape.needsNewAmount) required.push(['_newAmount', 'bigint']);
    required.push(['txPreimage', 'SigHashPreimage']);
    const params = method.params;
    const start = params.findIndex((p) => p.name === required[0]![0]);
    const paramsOk = start >= 0
      && required.every(([n, t], i) => params[start + i]?.name === n && params[start + i]?.type === t)
      && required.every(([n]) => params.filter((p) => p.name === n).length === 1);
    if (!paramsOk) {
      const list = required.map(([n, t]) => `${n}: ${t}`).join(', ');
      throw new Error(
        `IR validation: stateful method '${method.name}' must declare the auto-injected parameters (${list}) contiguously and once each, as StatefulSmartContract lowering does`,
      );
    }

    const counts = new Map<string, number>();
    collectNames(method.body, counts);
    const names = { taken: new Set(counts.keys()), next: 0, minted: new Set<string>() };
    const map = new Map<string, string>();
    const mapped = new Set<string>();

    // (2) the prologue.
    const prologue = new ExpectedContext(names);
    emitStatefulPrologue(prologue, method.sigHashType ?? SIGHASH_DEFAULT, hasMutableState);
    const head = method.body.slice(0, prologue.bindings.length);
    const pi = sameSequence(prologue.bindings, head, map, mapped);
    if (pi !== -1) {
      throw scaffoldError(method.name, `prologue binding ${pi} must be ${describe(prologue.bindings[pi]!.value)}`);
    }

    // (3) the continuation, over the outputs the method's own top-level
    // bindings declare (an `if` counts once, as a state output when either
    // arm holds one, else as a data output), in order.
    const rest = method.body.slice(prologue.bindings.length);
    const stateOutputs: ANFBinding[] = [];
    const dataOutputs: ANFBinding[] = [];
    for (const b of rest) {
      const k = b.value.kind;
      if (OUTPUT_STATE_KINDS.has(k)) stateOutputs.push(b);
      else if (k === 'add_data_output') dataOutputs.push(b);
      else if (k === 'if') {
        if (nested(b.value).some((n) => containsKind(n, OUTPUT_STATE_KINDS))) stateOutputs.push(b);
        else if (nested(b.value).some((n) => containsKind(n, DATA_OUTPUT_KINDS))) dataOutputs.push(b);
      }
    }
    const tail = new ExpectedContext(names);
    emitStatefulContinuation(tail, shape, stateOutputs.map((b) => b.name), dataOutputs.map((b) => b.name));
    const offset = rest.length - tail.bindings.length;
    for (let i = 0; i < tail.bindings.length; i++) {
      const act = offset + i >= 0 ? rest[offset + i] : undefined;
      if (act === undefined || !sameBinding(tail.bindings[i]!, act, map, mapped)) {
        throw scaffoldError(method.name, `continuation binding ${i} must be ${describe(tail.bindings[i]!.value)}`);
      }
    }

    // (4) unique, unshadowed names for what the scaffolding binds or commits
    // to: the prologue's and the continuation's bindings in order (an `if`
    // before its arms), then the committed state outputs, then data outputs.
    // A binding's own arms may reuse its name (an output-carrying `if` is
    // named after its arm's last binding); nothing else may.
    const paramNames = new Set(params.map((p) => p.name));
    const checked: ANFBinding[] = [];
    const preorder = (bindings: ANFBinding[]): void => {
      for (const b of bindings) {
        checked.push(b);
        for (const n of nested(b.value)) preorder(n);
      }
    };
    preorder(head);
    preorder(rest.slice(offset));
    checked.push(...stateOutputs, ...dataOutputs);
    for (const b of checked) {
      const inner = new Map<string, number>();
      for (const n of nested(b.value)) collectNames(n, inner);
      if ((counts.get(b.name) ?? 0) - (inner.get(b.name) ?? 0) !== 1 || propNames.has(b.name) || paramNames.has(b.name)) {
        throw new Error(
          `IR validation: stateful method '${method.name}' must bind '${b.name}' exactly once, under a name no property or parameter uses: the injected scaffolding binds it or the continuation commits to it`,
        );
      }
    }
  }
}
