/**
 * Pass 4: ANF Lower
 *
 * Lowers the Rúnar AST to A-Normal Form (ANF) IR. This is the critical
 * transformation pass -- it flattens all nested expressions into a
 * sequence of let-bindings where every right-hand side is a simple value.
 *
 * Example:
 *   assert(checkSig(sig, this.pk))
 * becomes:
 *   let t0 = load_param("sig")
 *   let t1 = load_prop("pk")
 *   let t2 = call("checkSig", [t0, t1])
 *   let t3 = assert(t2)
 */

import type {
  ContractNode,
  ParamNode,
  Statement,
  Expression,
  TypeNode,
} from '../ir/index.js';
import type {
  ANFProgram,
  ANFMethod,
  ANFParam,
  ANFBinding,
  ANFValue,
  ANFProperty,
  BinOp,
  ANFUnaryOp,
} from '../ir/index.js';
import { MERGED_LOCAL_TEMP_PREFIX } from '../ir/index.js';
import { computeSideEffectSummary, continuationShape } from './side-effect-summary.js';
import type { SideEffectSummary } from './side-effect-summary.js';
import { SIGHASH_DEFAULT } from './sighash-directive.js';
import type { MethodNode, PropertyNode } from '../ir/runar-ast.js';
import { UnknownANFKindError } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Lower a validated Rúnar AST to ANF IR.
 */
export function lowerToANF(contract: ContractNode): ANFProgram {
  const properties = lowerProperties(contract);
  const methods = lowerMethods(contract);

  // Post-pass: lift update_prop from if-else branches into flat conditionals.
  // This prevents phantom stack entries in stack lowering for patterns like
  // position dispatch (different properties updated in different branches).
  for (const method of methods) {
    method.body = liftBranchUpdateProps(method.body);
  }

  return {
    contractName: contract.name,
    properties,
    methods,
  };
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

function lowerProperties(contract: ContractNode): ANFProperty[] {
  const ctorAssigned = constructorAssignedProperties(contract);

  return contract.properties.map(prop => {
    const anfProp: ANFProperty = {
      name: prop.name,
      type: typeNodeToString(prop.type),
      readonly: prop.readonly,
    };

    // Extract literal value from property initializer. A property the
    // constructor assigns a PARAMETER to carries no compile-time value: the
    // constructor argument wins and the initializer degrades to a default.
    if (prop.initializer && !ctorAssigned.has(prop.name)) {
      anfProp.initialValue = extractLiteralValue(prop.initializer);
      checkStateBigintMagnitude(anfProp);
    }

    return anfProp;
  });
}

/**
 * Properties the constructor assigns a constructor PARAMETER to.
 *
 * These get their value from the deploy-time argument, so any initializer on
 * them is a default that the argument overrides — carrying it into
 * `initialValue` would bake the default into the artifact and silently discard
 * the argument (NEW-001). The property must instead stay in the constructor
 * slot list (`initialValue === undefined`) so the SDK writes the argument.
 *
 * This is the shared form of a rule the Zig surface has always applied in its
 * own parser, where `count: i64 = 0` beside `init(count: i64)` is the idiomatic
 * struct declaration and five conformance fixtures depend on the strip. Keying
 * on the ASSIGNMENT rather than on a name match generalises it to the shape
 * that actually occurs in-repo, `constructor(seed) { this.p = seed; }`.
 *
 * Deliberately narrow in three ways.
 *
 * 1. Only a BARE parameter reference counts. `this.a = 5n` assigns a literal,
 *    not an argument, and keeps its initializer; a computed form like
 *    `this.p = seed + 1n` is left alone because the constructor body is never
 *    lowered to script, so no tier could honour the arithmetic anyway.
 *
 * 2. The property↔parameter mapping must be ONE-TO-ONE. The artifact model is
 *    positional — the properties with no `initialValue` correspond in order to
 *    `abi.constructor.params` — so a parameter feeding two properties
 *    (`constructor(seed) { this.a = seed; this.b = seed; }`) has no
 *    representation: two state fields would face one argument and the SDK
 *    would leave the second undefined. That shape is ALREADY undeployable
 *    today when written without initializers (`deploy()` throws "Cannot
 *    convert undefined to a BigInt"), so stripping there would convert a
 *    wrong-state bug into a crash rather than fixing anything. It is left at
 *    today's behaviour and belongs to NEW-002, which is about making that
 *    correspondence explicit instead of positional.
 *
 * 3. A property assigned more than once in the constructor is skipped for the
 *    same reason — there is no single argument it corresponds to.
 */
function constructorAssignedProperties(contract: ContractNode): Set<string> {
  const out = new Set<string>();
  const ctor = contract.constructor;
  if (!ctor) return out;

  const params = new Set(ctor.params.map(p => p.name));
  // property -> the parameters assigned to it; parameter -> properties it feeds
  const propToParams = new Map<string, Set<string>>();
  const paramToProps = new Map<string, Set<string>>();

  for (const stmt of ctor.body) {
    if (stmt.kind !== 'assignment') continue;
    if (stmt.target.kind !== 'property_access') continue;
    const prop = stmt.target.property;
    if (stmt.value.kind !== 'identifier' || !params.has(stmt.value.name)) {
      // Assigned something that is not a constructor argument: the property
      // does not correspond to a slot, so never strip it.
      propToParams.set(prop, new Set());
      continue;
    }
    const param = stmt.value.name;
    if (!propToParams.has(prop)) propToParams.set(prop, new Set());
    propToParams.get(prop)!.add(param);
    if (!paramToProps.has(param)) paramToProps.set(param, new Set());
    paramToProps.get(param)!.add(prop);
  }

  for (const [prop, ps] of propToParams) {
    if (ps.size !== 1) continue;
    const param = [...ps][0]!;
    if (paramToProps.get(param)!.size !== 1) continue;
    out.add(prop);
  }
  return out;
}

/**
 * Magnitude bits a bigint state field gets: `num2bin-le8` is a fixed 8-byte
 * little-endian SIGN-MAGNITUDE word, so bytes 0..6 plus the low 7 bits of byte
 * 7 carry the magnitude and 0x80 of byte 7 carries the sign.
 */
const STATE_BIGINT_MAGNITUDE_LIMIT = 1n << 63n;

/**
 * Reject a MUTABLE bigint property initialised beyond the 8-byte state word.
 *
 * The state section writes every bigint field with OP_NUM2BIN 8, which cannot
 * represent a magnitude of 2^63 or more. Nothing used to check: the compiler
 * stamped `encoding: "num2bin-le8"` on the field and carried the initializer
 * verbatim, the SDK wrote the low 8 bytes of it into the deployed state
 * section, and the covenant then rebuilt the continuation with its own
 * OP_NUM2BIN 8 — which produces different bytes — so hash256(outputs) never
 * matched and the UTXO was permanently unspendable. It deployed cleanly, with
 * no diagnostic at compile time or deploy time.
 *
 * This catches the statically-known half. Values that only exist at call time
 * are stopped by the SDK serializer (`encodeNum2Bin`, runar-sdk/src/state.ts).
 *
 * READONLY properties are deliberately exempt: they are baked into the locking
 * script as script-number pushes, never into the state section, and BSV script
 * numbers are arbitrary-precision after Genesis.
 */
function checkStateBigintMagnitude(prop: ANFProperty): void {
  if (prop.readonly) return;
  if (prop.type !== 'bigint' && prop.type !== 'int') return;
  const v = prop.initialValue;
  if (typeof v !== 'bigint') return;
  if (v < STATE_BIGINT_MAGNITUDE_LIMIT && v > -STATE_BIGINT_MAGNITUDE_LIMIT) return;

  throw new Error(
    `Cannot compile state property '${prop.name}' initialised to ${v}: it does ` +
    `not fit the fixed 8-byte sign-magnitude state word (magnitude must be ` +
    `< 2^63). Reduce the value, or make the property readonly if it is a ` +
    `constant rather than state.`,
  );
}

/** Extract a literal value from an Expression for ANFProperty.initialValue. */
function extractLiteralValue(expr: Expression): string | bigint | boolean | undefined {
  switch (expr.kind) {
    case 'bigint_literal':
      return expr.value;
    case 'bool_literal':
      return expr.value;
    case 'bytestring_literal':
      return expr.value;
    case 'unary_expr':
      if (expr.op === '-' && expr.operand.kind === 'bigint_literal') {
        return -expr.operand.value;
      }
      return undefined;
    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

function lowerMethods(contract: ContractNode): ANFMethod[] {
  const result: ANFMethod[] = [];

  // Single source of truth for "does this method (transitively) mutate
  // state, emit outputs, or use the preimage?" Shared with the artifact
  // assembler so ABI declarations cannot drift from ANF auto-injection.
  const sideEffects = computeSideEffectSummary(contract);

  // Issue #109: readonly fields carrying a `/** @embedAlways */` directive
  // must survive DCE into the locking script. A readonly field no method
  // references lowers to no `load_prop`, so no constructor slot is emitted
  // and the field's deploy-time bytes vanish. We inject a `load_prop` + a
  // `@ref:` alias (the exact shape the `const _bind = this.field;` idiom
  // produces) into the first public method's body — the alias keeps the
  // `load_prop` alive through dead-binding DCE, and stack lowering threads
  // the pushed value through and cleans it up (OP_NIP) at method end. One
  // slot in the deployed script suffices; every spending branch shares it.
  const embedFields = contract.properties.filter(p => p.readonly && p.embedAlways);
  let embedInjected = false;

  // Lower constructor
  const ctorCtx = new LoweringContext(contract, sideEffects);
  ctorCtx.setMethodParamTypes(contract.constructor.params);
  lowerStatements(contract.constructor.body, ctorCtx);
  result.push({
    name: 'constructor',
    params: lowerParams(contract.constructor.params),
    body: ctorCtx.bindings,
    isPublic: false,
  });

  // Lower each method
  for (const method of contract.methods) {
    const methodCtx = new LoweringContext(contract, sideEffects);
    methodCtx.setMethodParamTypes(method.params);
    // Issue #123: non-default @sighash mode drives the OP_PUSH_TX binding flag
    // for any checkPreimage (auto-injected below, or a manual call) in this method.
    if (method.sighashType !== undefined && method.sighashType !== SIGHASH_DEFAULT) {
      methodCtx.sighashFlag = method.sighashType;
    }

    // Register the declared param NAMES so a bare identifier resolves to
    // `load_param` before falling through to `load_prop` (issue #130). Without
    // this, a param whose name collides with a mutable state property lowered
    // to the stale deserialized property value instead of the witness param.
    // Explicit `this.x` is unaffected: it lowers via lowerMemberExpr, which
    // always emits `load_prop` regardless of param registration.
    for (const p of method.params) {
      methodCtx.addParam(p.name);
    }

    if (contract.parentClass === 'StatefulSmartContract' && method.visibility === 'public') {
      // Continuation requirements come from the side-effect summary,
      // which walks the private-method call graph. A public method that
      // calls a private helper which mutates state or emits an output
      // must therefore inject the same continuation params as if the
      // public body did so directly.
      const effects = sideEffects.get(method.name) ?? { mutatesState: false, hasStateOutput: false, hasDataOutput: false, usesPreimage: false };
      const shape = continuationShape(effects);
      const needsChangeOutput = shape.needsChange;

      // Register implicit parameters (with types, so the method-scoped
      // type table — issue #34 — knows them for byte-type analysis).
      if (needsChangeOutput) {
        methodCtx.addParam('_changePKH', 'Ripemd160');
        methodCtx.addParam('_changeAmount', 'bigint');
      }
      // Single-output continuation needs _newAmount to allow changing the UTXO satoshis.
      // Multi-output (addOutput) methods already specify amounts explicitly per output.
      // Methods that emit only data outputs (no addOutput) still run the single-output
      // continuation path for their state continuation, so they also need _newAmount.
      const needsNewAmount = shape.needsNewAmount;
      if (needsNewAmount) {
        methodCtx.addParam('_newAmount', 'bigint');
      }
      methodCtx.addParam('txPreimage', 'SigHashPreimage');

      // Issue #123: the declared per-method sighash mode (default ALL|FORKID).
      // Drives BOTH the OP_PUSH_TX binding flag (so the derived sig re-computes
      // the tx sighash under this mode) AND the runtime preimage-type assert.
      const sighashMode = method.sighashType ?? SIGHASH_DEFAULT;
      const isDefaultSighash = sighashMode === SIGHASH_DEFAULT;

      // Inject checkPreimage(txPreimage) at the start
      const preimageRef = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
      const checkResult = methodCtx.emit({
        kind: 'check_preimage',
        preimage: preimageRef,
        // Omit for the default so the ANF (and pinned binding blob) is unchanged.
        ...(isDefaultSighash ? {} : { sighashFlag: sighashMode }),
      });
      methodCtx.emit({ kind: 'assert', value: checkResult });

      // GAP-302 / #123: pin the sighash type to the declared mode. The
      // auto-injected covenant verifies a real tx preimage, but without this
      // check the spend could use a DIFFERENT sighash flag than declared that
      // zeroes out preimage fields the contract (or its continuation) relies on
      // (hashOutputs / hashPrevouts / hashSequence). The value defaults to 0x41
      // (SIGHASH_ALL|FORKID) so existing contracts emit byte-identical ANF.
      const sigHashPreimageRef = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
      const sigHashTypeRef = methodCtx.emit({ kind: 'call', func: 'extractSigHashType', args: [sigHashPreimageRef] });
      const expectedSigHashRef = methodCtx.emit({ kind: 'load_const', value: BigInt(sighashMode) });
      const sigHashOkRef = methodCtx.emit({ kind: 'bin_op', op: '===', left: sigHashTypeRef, right: expectedSigHashRef });
      methodCtx.emit({ kind: 'assert', value: sigHashOkRef });

      // Deserialize mutable state from the preimage's scriptCode.
      const stateProps = contract.properties.filter(p => p.kind === 'property' && !p.readonly);
      if (stateProps.length > 0) {
        const preimageRef3 = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
        methodCtx.emit({ kind: 'deserialize_state', preimage: preimageRef3 });
      }

      // Issue #109: preserve @embedAlways fields at the first user-statement
      // position (after the checkPreimage/deserialize preamble), mirroring
      // where a `const _bind = this.field;` idiom would sit.
      if (!embedInjected && embedFields.length > 0) {
        emitEmbedAlwaysPreservation(methodCtx, embedFields);
        embedInjected = true;
      }

      // Lower the developer's method body
      lowerStatements(method.body, methodCtx);

      // Determine state continuation type.
      //
      // === Continuation-hash construction (reference for other compilers) ===
      //
      // The auto-injected continuation assertion verifies that the spending
      // transaction's hashOutputs field matches a compiler-constructed hash
      // over the outputs this method declares. Outputs are concatenated in
      // the following order before hashing with hash256:
      //
      //   1. state outputs       (from this.addOutput / this.addRawOutput,
      //                           tracked via addOutputRef)
      //   2. data outputs        (from this.addDataOutput, tracked via
      //                           addDataOutputRef) — NEW
      //   3. change output       (P2PKH to _changePKH, value = _changeAmount)
      //
      // For the "single-output" fast path (no addOutput used, but state is
      // mutated), the state output is computed on the fly from
      // (preimage, stateScript, _newAmount) instead of coming from
      // addOutputRefs. Data outputs may still be declared in this mode and
      // are inserted BETWEEN the single state output and the change output.
      //
      // If no state output and no data output is present, the legacy
      // single-output path applies (no data-output insertion needed).
      const addOutputRefs = methodCtx.getAddOutputRefs();
      const addDataOutputRefs = methodCtx.getAddDataOutputRefs();
      // Gate the continuation assertion on the same shape used for
      // param injection. Both must agree or the deployed locking
      // script will not match the ABI's declared parameter list.
      //
      // Private-helper outputs ARE seen here: a public method that
      // delegates `addOutput` / `addRawOutput` / `addDataOutput` to a
      // private helper has that helper inlined into its binding stream
      // at ANF time (driven by `computeSideEffectSummary` above and
      // `inlinePrivateMethodCall`), so the helper's `add_output` /
      // `add_data_output` ANF nodes register on this context's
      // `addOutputRefs` / `addDataOutputRefs` lists before the
      // continuation hash is built. The continuation therefore commits
      // to the full runtime output set. Locked in by the all-tier
      // `private-helper-outputs` conformance fixture (its `partition`
      // and `log` methods route outputs through private helpers).
      if (needsChangeOutput) {
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
        const changePKHRef = methodCtx.emit({ kind: 'load_param', name: '_changePKH' });
        const changeAmountRef = methodCtx.emit({ kind: 'load_param', name: '_changeAmount' });
        const zeroRef = methodCtx.emit({ kind: 'load_const', value: 0n });
        const changeNonZeroRef = methodCtx.emit({ kind: 'bin_op', op: '!==', left: changeAmountRef, right: zeroRef });
        const changeThenCtx = methodCtx.subContext();
        changeThenCtx.emit({ kind: 'call', func: 'buildChangeOutput', args: [changePKHRef, changeAmountRef] });
        methodCtx.syncCounter(changeThenCtx);
        const changeElseCtx = methodCtx.subContext();
        changeElseCtx.emit({ kind: 'load_const', value: '' });
        methodCtx.syncCounter(changeElseCtx);
        const changeOutputRef = methodCtx.emit({
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
            accumulated = methodCtx.emit({ kind: 'call', func: 'cat', args: [accumulated, addOutputRefs[i]!] });
          }
          for (const dataRef of addDataOutputRefs) {
            accumulated = methodCtx.emit({ kind: 'call', func: 'cat', args: [accumulated, dataRef] });
          }
          accumulated = methodCtx.emit({ kind: 'call', func: 'cat', args: [accumulated, changeOutputRef] });
          const hashRef = methodCtx.emit({ kind: 'call', func: 'hash256', args: [accumulated] });
          const preimageRef2 = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
          const outputHashRef = methodCtx.emit({ kind: 'call', func: 'extractOutputHash', args: [preimageRef2] });
          const eqRef = methodCtx.emit({ kind: 'bin_op', op: '===', left: hashRef, right: outputHashRef, result_type: 'bytes' });
          methodCtx.emit({ kind: 'assert', value: eqRef, isAutoInjectedStateCheck: true });
        } else {
          // Single-output continuation: build raw output bytes, then splice in
          // any declared data outputs, then concat with change, then hash.
          const stateScriptRef = methodCtx.emit({ kind: 'get_state_script' });
          const preimageRef2 = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
          const newAmountRef = methodCtx.emit({ kind: 'load_param', name: '_newAmount' });
          const contractOutputRef = methodCtx.emit({ kind: 'call', func: 'computeStateOutput', args: [preimageRef2, stateScriptRef, newAmountRef] });
          let accumulated = contractOutputRef;
          for (const dataRef of addDataOutputRefs) {
            accumulated = methodCtx.emit({ kind: 'call', func: 'cat', args: [accumulated, dataRef] });
          }
          const allOutputs = methodCtx.emit({ kind: 'call', func: 'cat', args: [accumulated, changeOutputRef] });
          const hashRef = methodCtx.emit({ kind: 'call', func: 'hash256', args: [allOutputs] });
          const preimageRef4 = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
          const outputHashRef = methodCtx.emit({ kind: 'call', func: 'extractOutputHash', args: [preimageRef4] });
          const eqRef = methodCtx.emit({ kind: 'bin_op', op: '===', left: hashRef, right: outputHashRef, result_type: 'bytes' });
          methodCtx.emit({ kind: 'assert', value: eqRef, isAutoInjectedStateCheck: true });
        }
      }

      // Build augmented params list for ABI
      const augmentedParams: ParamNode[] = method.params.filter(param => !isStatefulContextParam(param));
      if (needsChangeOutput) {
        augmentedParams.push(
          { kind: 'param', name: '_changePKH', type: { kind: 'primitive_type', name: 'Ripemd160' } },
          { kind: 'param', name: '_changeAmount', type: { kind: 'primitive_type', name: 'bigint' } },
        );
      }
      if (needsNewAmount) {
        augmentedParams.push(
          { kind: 'param', name: '_newAmount', type: { kind: 'primitive_type', name: 'bigint' } },
        );
      }
      augmentedParams.push(
        { kind: 'param', name: 'txPreimage', type: { kind: 'primitive_type', name: 'SigHashPreimage' } },
      );

      // Intent-covenant intrinsic auto-injected witness params:
      // extractPrevOutputScript adds `_prevOutScript_<inputIndex>` (one per
      // distinct literal index referenced in the method); requireOutputP2PKH
      // adds a single `_serialisedOutputs`. Order follows insertion order
      // via methodScope.autoInjectedParams. Appended AFTER txPreimage so
      // unlocking scripts push them adjacent to the preimage (matches the
      // existing _changePKH / _changeAmount / _newAmount convention of
      // trailing the user args before the preimage anchor).
      const finalParams = lowerParams(augmentedParams);
      for (const p of methodCtx.methodScope.autoInjectedParams) {
        finalParams.push(p);
      }

      result.push({
        name: method.name,
        params: finalParams,
        body: methodCtx.bindings,
        isPublic: true,
      });
    } else {
      // Issue #109: stateless public methods (and stateless contracts'
      // spending entry points) are lowered here — inject @embedAlways
      // preservation into the first PUBLIC one before its body.
      if (!embedInjected && embedFields.length > 0 && method.visibility === 'public') {
        emitEmbedAlwaysPreservation(methodCtx, embedFields);
        embedInjected = true;
      }
      lowerStatements(method.body, methodCtx);
      // Private methods can also call the intent intrinsics; capture
      // their auto-injected witness params. Public callers that inline
      // this private pick them up via the shared methodScope (see
      // inlinePrivateMethodCall), so the auto-injection registers at
      // the public method's ABI augmentation step above. The private's
      // own ABI is still informative for non-inlined callees.
      const params = lowerParams(method.params);
      for (const p of methodCtx.methodScope.autoInjectedParams) {
        params.push(p);
      }
      result.push({
        name: method.name,
        params,
        body: methodCtx.bindings,
        isPublic: method.visibility === 'public',
      });
    }
  }

  return result;
}

function lowerParams(params: ParamNode[]): ANFParam[] {
  return params.map(p => ({
    name: p.name,
    type: typeNodeToString(p.type),
  }));
}

/**
 * Issue #109: emit the DCE-surviving preservation pair for each
 * `@embedAlways` readonly field, into the given (public) method context.
 *
 * Reproduces exactly what a hand-written `const _bind = this.field;` lowers
 * to: a `load_prop` followed by a `load_const("@ref:<t>")` alias. The alias
 * marks the `load_prop` as referenced (see `collectRefsFromValue` in
 * `optimizer/dce.ts`), so dead-binding DCE keeps it; stack lowering then
 * emits the field's constructor-slot placeholder and NIPs the unused value
 * off the stack at method end. The field's bytes therefore remain in the
 * deployed locking script for downstream recovery.
 */
function emitEmbedAlwaysPreservation(ctx: LoweringContext, fields: PropertyNode[]): void {
  for (const field of fields) {
    const loadRef = ctx.emit({ kind: 'load_prop', name: field.name });
    ctx.emitNamed(`__embedAlways_${field.name}`, {
      kind: 'load_const',
      value: `@ref:${loadRef}`,
    });
  }
}

// ---------------------------------------------------------------------------
// Lowering context: manages temp variable generation
// ---------------------------------------------------------------------------

/**
 * Per-method bookkeeping shared by a public method's top-level
 * LoweringContext and every sub-context it spawns (if/else, ternary,
 * inlined private bodies). Tracks the witness parameters that the
 * intent-covenant intrinsics (extractPrevOutputScript,
 * requireOutputP2PKH) auto-inject into the method's ABI regardless of
 * which nested scope the intrinsic call lives in. Mirrors Go's
 * methodScopeT.
 */
class MethodScope {
  /** Append-only, insertion order. */
  readonly autoInjectedParams: ANFParam[] = [];
  /** Dedup set keyed by param name. */
  private readonly autoInjectedSet: Set<string> = new Set();
  /**
   * Idempotency flag: requireOutputP2PKH emits its
   * `hash256(_serialisedOutputs) === extractOutputHash(txPreimage)`
   * check at most once per method body, even if called multiple times.
   */
  didEmitHashOutputsCheck = false;

  /** Idempotent — second call with the same name is a no-op. */
  recordAutoInjectedParam(name: string, type: string): void {
    if (this.autoInjectedSet.has(name)) return;
    this.autoInjectedSet.add(name);
    this.autoInjectedParams.push({ name, type });
  }
}

class LoweringContext {
  bindings: ANFBinding[] = [];
  private counter = 0;
  private readonly contract: ContractNode;
  private readonly paramNames: Set<string> = new Set();
  /**
   * Param types for the CURRENT method being lowered, keyed by name.
   * Method-scoped (not contract-scoped) so a parameter named `x` in one
   * method does not bleed into the byte-type analysis of a different
   * method's same-named local. See issue #34.
   */
  private readonly methodParamTypes: Map<string, string> = new Map();
  private readonly localNames: Set<string> = new Set();
  private readonly localByteVars: Set<string> = new Set();
  private readonly _addOutputRefs: string[] = [];
  private readonly _addDataOutputRefs: string[] = [];
  /**
   * Per-method state shared with all sub-contexts via the same object
   * reference, so an auto-injection that fires inside an if-branch
   * still registers on the parent method's ABI augmentation list.
   */
  methodScope: MethodScope = new MethodScope();
  /**
   * Issue #123: the declared non-default `@sighash` flag for the method being
   * lowered, so a MANUAL `checkPreimage(pre)` call (stateless / explicit) binds
   * under the same mode as the method's declared sighash. `undefined` = default
   * ALL|FORKID, keeping the pinned binding blob unchanged.
   */
  sighashFlag: number | undefined;
  /** Maps local variable names to their current ANF binding name.
   *  Updated after if-statements that reassign locals in both branches. */
  private readonly localAliases: Map<string, string> = new Map();
  /**
   * Param substitution stack used when inlining a private method's body
   * directly into this context. Entry on top is the active alias for
   * the named param. When the inlined body references that param, the
   * lowered identifier resolves to the aliased ref instead of emitting
   * a `load_param`. Stacked so nested inlines compose correctly.
   */
  private readonly paramAliasStack: Map<string, string[]> = new Map();
  /**
   * Side-effect summary shared with the assembler. Used at lowering time
   * to decide whether a `this.privateHelper(...)` call should inline its
   * body into the caller's context (so that the helper's
   * `add_output`/`add_data_output` ANF nodes register output refs on the
   * caller's continuation hash) or remain a `method_call` for stack
   * lowering to inline later.
   */
  private readonly sideEffects: SideEffectSummary | null;
  /** Debug: source location to attach to emitted ANF bindings. */
  currentSourceLoc: { file: string; line: number; column: number } | undefined;
  /**
   * True in every context created by `subContext()` — i.e. inside an if arm,
   * a loop body, or an inlined helper's block — and false only in the context
   * a method's own body is lowered into.
   *
   * `liftBranchUpdateProps` walks `method.body` and does NOT recurse: a `loop`
   * body or a surviving `if` arm is passed through untouched. So an `if` that
   * the lift's recogniser accepts is only actually REWRITTEN when it sits at
   * method top level. `lowerIfStatement` needs the same distinction before it
   * defers to that pass, otherwise a dispatch chain one `for` deeper is
   * recognised-but-not-rewritten AND excluded from declaring its results —
   * which leaves it with no correct lowering at all.
   */
  nested = false;

  constructor(contract: ContractNode, sideEffects: SideEffectSummary | null = null) {
    this.contract = contract;
    this.sideEffects = sideEffects;
  }

  /** Generate a fresh temporary name. */
  freshTemp(): string {
    return `t${this.counter++}`;
  }

  /** Emit a binding and return the bound name. */
  emit(value: ANFValue): string {
    const name = this.freshTemp();
    const binding: ANFBinding = { name, value };
    if (this.currentSourceLoc) binding.sourceLoc = this.currentSourceLoc;
    this.bindings.push(binding);
    return name;
  }

  /** Emit a binding with a specific name (for named variables). */
  emitNamed(name: string, value: ANFValue): void {
    const binding: ANFBinding = { name, value };
    if (this.currentSourceLoc) binding.sourceLoc = this.currentSourceLoc;
    this.bindings.push(binding);
  }

  /** Record a parameter name so we know to use load_param for it.
   *  Optionally records the param's type in the method-scoped type table. */
  addParam(name: string, type?: string): void {
    this.paramNames.add(name);
    if (type !== undefined) this.methodParamTypes.set(name, type);
  }

  /** Record the current method's parameter types in the method-scoped table.
   *  Must be called once per method/constructor before lowering its body so
   *  `getParamType` only sees THIS method's params (issue #34). */
  setMethodParamTypes(params: ParamNode[]): void {
    this.methodParamTypes.clear();
    for (const p of params) {
      this.methodParamTypes.set(p.name, typeNodeToString(p.type));
    }
  }

  /** Record a local variable name so we know it's a local ref. */
  addLocal(name: string): void {
    this.localNames.add(name);
  }

  /** Record a local variable as byte-typed. */
  addLocalByteVar(name: string): void {
    this.localByteVars.add(name);
  }

  /** Check if a local variable is byte-typed. */
  isLocalByteVar(name: string): boolean {
    return this.localByteVars.has(name);
  }

  isParam(name: string): boolean {
    return this.paramNames.has(name);
  }

  isLocal(name: string): boolean {
    return this.localNames.has(name);
  }

  /** Set the current ANF binding for a local variable (after if-statement reassignment). */
  setLocalAlias(localName: string, bindingName: string): void {
    this.localAliases.set(localName, bindingName);
  }

  /** Get the current ANF binding for a local variable, or undefined if not aliased. */
  getLocalAlias(localName: string): string | undefined {
    return this.localAliases.get(localName);
  }

  isProperty(name: string): boolean {
    return this.contract.properties.some(p => p.name === name);
  }

  /** Contract property names in declaration order. */
  propertyNames(): string[] {
    return this.contract.properties.map(p => p.name);
  }

  /** Check if name matches a private method on the contract. */
  isPrivateMethod(name: string): boolean {
    return this.contract.methods.some(m => m.name === name && m.visibility === 'private');
  }

  /** Look up a private method by name. */
  getPrivateMethod(name: string): MethodNode | undefined {
    return this.contract.methods.find(m => m.name === name && m.visibility === 'private');
  }

  /**
   * Whether a call to `name` should be ANF-inlined rather than emitted
   * as a `method_call`. True iff `name` is a private method that
   * (transitively) emits state outputs (`addOutput` / `addRawOutput`)
   * or data outputs (`addDataOutput`). Those refs MUST appear in the
   * caller's binding stream so they participate in the continuation
   * hash; without ANF-level inlining they would live in a sibling
   * ANF method and the public method's continuation hash would miss
   * them.
   *
   * Mutation-only private helpers (no output intrinsics) are
   * intentionally NOT inlined here — state mutation flows through
   * state continuity (the continuation hash reads state via
   * `get_state_script` after all mutations apply), not through
   * output refs. Keeping the existing `method_call` + stack-lowering
   * inlining path for those preserves byte-equality with the
   * pre-fix corpus on contracts that mix state-mutating helpers
   * with public methods that already mutate state directly (e.g.
   * TicTacToe).
   */
  shouldInlinePrivate(name: string): boolean {
    if (!this.sideEffects) return false;
    const method = this.getPrivateMethod(name);
    if (!method) return false;
    const effects = this.sideEffects.get(name);
    if (!effects) return false;
    return effects.hasStateOutput || effects.hasDataOutput;
  }

  /**
   * Push a param alias frame. Subsequent identifier lookups for `name`
   * will resolve to `aliasRef` until the matching pop. Stacked so
   * nested inlines compose: pop returns the previous frame.
   */
  pushParamAlias(name: string, aliasRef: string): void {
    const stack = this.paramAliasStack.get(name) ?? [];
    stack.push(aliasRef);
    this.paramAliasStack.set(name, stack);
  }

  popParamAlias(name: string): void {
    const stack = this.paramAliasStack.get(name);
    if (!stack || stack.length === 0) return;
    stack.pop();
    if (stack.length === 0) this.paramAliasStack.delete(name);
  }

  getParamAlias(name: string): string | undefined {
    const stack = this.paramAliasStack.get(name);
    if (!stack || stack.length === 0) return undefined;
    return stack[stack.length - 1];
  }

  /** Track an addOutput binding ref for multi-output continuation. */
  addOutputRef(ref: string): void {
    this._addOutputRefs.push(ref);
  }

  /** Get all addOutput refs collected during lowering. */
  getAddOutputRefs(): string[] {
    return this._addOutputRefs;
  }

  /** Track an addDataOutput binding ref — distinct from state outputs. */
  addDataOutputRef(ref: string): void {
    this._addDataOutputRefs.push(ref);
  }

  /** Get all addDataOutput refs collected during lowering. */
  getAddDataOutputRefs(): string[] {
    return this._addDataOutputRefs;
  }

  /** Look up the type of a method parameter by name. Returns the type string or null. */
  getParamType(name: string): string | null {
    // Restricted to the CURRENT method's parameters (issue #34). A cross-method
    // lookup poisoned the byte-type analysis when two methods shared a parameter
    // name (e.g. one method's local `x: bigint` collided with another method's
    // `x: ByteString` parameter), which flipped `result_type` to 'bytes' and
    // made stack lowering emit OP_CAT for an integer add.
    return this.methodParamTypes.get(name) ?? null;
  }

  isStatefulContextParam(name: string): boolean {
    return this.getParamType(name) === 'StatefulContext';
  }

  /** Look up the type of a contract property by name. Returns the type string or null. */
  getPropertyType(name: string): string | null {
    for (const p of this.contract.properties) {
      if (p.name === name) {
        return typeNodeToString(p.type);
      }
    }
    return null;
  }

  /** Create a sub-context for nested blocks (if/else, loops). */
  subContext(): LoweringContext {
    const sub = new LoweringContext(this.contract);
    sub.counter = this.counter;
    // Share the parameter, local name sets, and aliases
    for (const p of this.paramNames) sub.paramNames.add(p);
    for (const [k, v] of this.methodParamTypes) sub.methodParamTypes.set(k, v);
    for (const l of this.localNames) sub.localNames.add(l);
    for (const b of this.localByteVars) sub.localByteVars.add(b);
    for (const [k, v] of this.localAliases) sub.localAliases.set(k, v);
    // Share the method scope so auto-injection from intrinsics called
    // inside the nested block bubbles up to the parent's ABI list.
    sub.methodScope = this.methodScope;
    sub.nested = true;
    return sub;
  }

  /** Sync the counter back from a sub-context. */
  syncCounter(sub: LoweringContext): void {
    this.counter = Math.max(this.counter, sub.counter);
  }
}

// ---------------------------------------------------------------------------
// Statement lowering
// ---------------------------------------------------------------------------

/** Shared empty read-set, so the common call sites allocate nothing. */
const NO_READS: ReadonlySet<string> = new Set<string>();

function lowerStatements(
  stmts: Statement[],
  ctx: LoweringContext,
  readsAfterBlock: ReadonlySet<string> = NO_READS,
): void {
  for (let i = 0; i < stmts.length; i++) {
    const stmt = stmts[i]!;

    // Early-return nesting: when an if-statement's then-block ends with a
    // return and there is no else-branch, the remaining statements after the
    // if are unreachable from the then-branch.  Nest them into the else-branch
    // so that only one value ends up on the stack (the return value from
    // whichever branch executes).  Without this, both branches produce values
    // and the stack becomes misaligned.
    if (
      stmt.kind === 'if_statement' &&
      !stmt.else &&
      i + 1 < stmts.length &&
      branchEndsWithReturn(stmt.then)
    ) {
      const remaining = stmts.slice(i + 1);
      const modifiedIf: typeof stmt = {
        ...stmt,
        else: remaining,
      };
      lowerStatement(modifiedIf, ctx, readsAfterBlock);
      return; // remaining stmts are now inside the else branch
    }

    // Only the block-forming statements need to know what the code after them
    // still reads; computing it for every statement would be quadratic for no
    // benefit.
    const readsAfter =
      stmt.kind === 'if_statement' || stmt.kind === 'for_statement'
        ? readsAfterStatement(stmts, i, readsAfterBlock)
        : NO_READS;
    lowerStatement(stmt, ctx, readsAfter);
  }
}

/**
 * The identifiers still readable once statement `index` of this block has run:
 * everything the following statements in this block read, plus whatever the
 * enclosing blocks read after this block.
 *
 * Used by `lowerIfStatement` to tell a branch-merged local that is dead after
 * the `if` (safe) from one that is still live (not representable alongside a
 * branch output — see `branchOutputRejectionReason`).
 */
function readsAfterStatement(
  stmts: Statement[],
  index: number,
  readsAfterBlock: ReadonlySet<string>,
): ReadonlySet<string> {
  const reads = new Set(readsAfterBlock);
  for (let j = index + 1; j < stmts.length; j++) {
    collectStatementReads(stmts[j]!, reads);
  }
  return reads;
}

/**
 * Collect every identifier a statement READS. The `x` in `x = expr` is a write,
 * not a read, so a plain identifier assignment target is skipped; every other
 * target form (index access, member access) can still read locals.
 */
function collectStatementReads(stmt: Statement, out: Set<string>): void {
  switch (stmt.kind) {
    case 'variable_decl':
      collectExpressionReads(stmt.init, out);
      break;

    case 'assignment':
      if (stmt.target.kind !== 'identifier') collectExpressionReads(stmt.target, out);
      collectExpressionReads(stmt.value, out);
      break;

    case 'if_statement':
      collectExpressionReads(stmt.condition, out);
      for (const s of stmt.then) collectStatementReads(s, out);
      if (stmt.else) for (const s of stmt.else) collectStatementReads(s, out);
      break;

    case 'for_statement':
      collectExpressionReads(stmt.init.init, out);
      collectExpressionReads(stmt.condition, out);
      collectStatementReads(stmt.update, out);
      for (const s of stmt.body) collectStatementReads(s, out);
      break;

    case 'return_statement':
      if (stmt.value) collectExpressionReads(stmt.value, out);
      break;

    case 'expression_statement':
      collectExpressionReads(stmt.expression, out);
      break;
  }
}

/** Collect every identifier an expression reads. */
function collectExpressionReads(expr: Expression, out: Set<string>): void {
  switch (expr.kind) {
    case 'identifier':
      out.add(expr.name);
      break;
    case 'binary_expr':
      collectExpressionReads(expr.left, out);
      collectExpressionReads(expr.right, out);
      break;
    case 'unary_expr':
      collectExpressionReads(expr.operand, out);
      break;
    case 'call_expr':
      collectExpressionReads(expr.callee, out);
      for (const a of expr.args) collectExpressionReads(a, out);
      break;
    case 'member_expr':
      collectExpressionReads(expr.object, out);
      break;
    case 'ternary_expr':
      collectExpressionReads(expr.condition, out);
      collectExpressionReads(expr.consequent, out);
      collectExpressionReads(expr.alternate, out);
      break;
    case 'index_access':
      collectExpressionReads(expr.object, out);
      collectExpressionReads(expr.index, out);
      break;
    case 'increment_expr':
    case 'decrement_expr':
      collectExpressionReads(expr.operand, out);
      break;
    case 'array_literal':
      for (const e of expr.elements) collectExpressionReads(e, out);
      break;
    default:
      // Literals and `this.x` property access read no locals.
      break;
  }
}

/** Check whether a statement list always terminates with a return_statement. */
function branchEndsWithReturn(stmts: Statement[]): boolean {
  if (stmts.length === 0) return false;
  const last = stmts[stmts.length - 1]!;
  if (last.kind === 'return_statement') return true;
  // Also handle if-else where both branches return:
  // if (A) { return X; } else { return Y; }
  if (last.kind === 'if_statement' && last.else) {
    return branchEndsWithReturn(last.then) && branchEndsWithReturn(last.else);
  }
  return false;
}

function lowerStatement(
  stmt: Statement,
  ctx: LoweringContext,
  readsAfter: ReadonlySet<string> = NO_READS,
): void {
  // Propagate source location to emitted ANF bindings
  ctx.currentSourceLoc = stmt.sourceLocation;

  switch (stmt.kind) {
    case 'variable_decl':
      lowerVariableDecl(stmt, ctx);
      break;

    case 'assignment':
      lowerAssignment(stmt, ctx);
      break;

    case 'if_statement':
      lowerIfStatement(stmt, ctx, readsAfter);
      break;

    case 'for_statement':
      lowerForStatement(stmt, ctx, readsAfter);
      break;

    case 'expression_statement':
      lowerExpressionStatement(stmt, ctx);
      break;

    case 'return_statement':
      lowerReturnStatement(stmt, ctx);
      break;
  }

  ctx.currentSourceLoc = undefined;
}

function lowerVariableDecl(
  stmt: Extract<Statement, { kind: 'variable_decl' }>,
  ctx: LoweringContext,
): void {
  const valueRef = lowerExprToRef(stmt.init, ctx);
  ctx.addLocal(stmt.name);

  // Track byte-typed locals so equality comparisons use OP_EQUAL
  if (isByteTypedExpr(stmt.init, ctx)) {
    ctx.addLocalByteVar(stmt.name);
  }

  // Emit a binding that aliases the variable name to the computed value.
  // We load the temp as a const reference to the computed value.
  ctx.emitNamed(stmt.name, { kind: 'load_const', value: `@ref:${valueRef}` });
}

function lowerAssignment(
  stmt: Extract<Statement, { kind: 'assignment' }>,
  ctx: LoweringContext,
): void {
  const valueRef = lowerExprToRef(stmt.value, ctx);

  // this.x = expr -> update_prop
  if (stmt.target.kind === 'property_access') {
    ctx.emit({ kind: 'update_prop', name: stmt.target.property, value: valueRef });
    return;
  }

  // local = expr -> re-bind (in ANF, this is just a new binding with the same name)
  if (stmt.target.kind === 'identifier') {
    ctx.emitNamed(stmt.target.name, { kind: 'load_const', value: `@ref:${valueRef}` });
    return;
  }

  // For other targets (index access, etc.), lower the target and emit.
  // In practice, index-access assignment would need more sophisticated lowering.
  lowerExprToRef(stmt.target, ctx);
}

function lowerIfStatement(
  stmt: Extract<Statement, { kind: 'if_statement' }>,
  ctx: LoweringContext,
  readsAfter: ReadonlySet<string> = NO_READS,
): void {
  const condRef = lowerExprToRef(stmt.condition, ctx);

  // Lower then-block into sub-context
  const thenCtx = ctx.subContext();
  lowerStatements(stmt.then, thenCtx, readsAfter);
  ctx.syncCounter(thenCtx);

  // Lower else-block into sub-context
  const elseCtx = ctx.subContext();
  if (stmt.else) {
    lowerStatements(stmt.else, elseCtx, readsAfter);
  }
  ctx.syncCounter(elseCtx);

  // 2026-04-30 audit finding F2: when a branch contains output
  // intrinsics (addOutput / addRawOutput / addDataOutput), the
  // current implementation registered a single `ifName` as the
  // parent's addOutputRef regardless of how many outputs each branch
  // produced. That collapsed cardinality and ordering, and for
  // branches that mixed kinds it left the runtime stack
  // unbalanced (different number of bindings between then and
  // else). The fix: at the END of each branch with output refs,
  // append a cat-chain that concatenates that branch's outputs
  // (state then data, in declaration order) into a single
  // bytes-ref. Each branch then leaves exactly one item on the
  // stack — the concat — and the if-expression's value is the
  // concat of whichever branch ran. The parent's continuation hash
  // sees a single addOutputRef whose runtime value already contains
  // the correctly-ordered output bytes for the chosen branch.
  const thenOutputRefs = thenCtx.getAddOutputRefs();
  const elseOutputRefs = elseCtx.getAddOutputRefs();
  const thenDataRefs = thenCtx.getAddDataOutputRefs();
  const elseDataRefs = elseCtx.getAddDataOutputRefs();
  const branchHasOutputs =
    thenOutputRefs.length > 0 || elseOutputRefs.length > 0
    || thenDataRefs.length > 0 || elseDataRefs.length > 0;

  let thenOutputBytes = '';
  let elseOutputBytes = '';
  if (branchHasOutputs) {
    thenOutputBytes = appendBranchOutputConcat(thenCtx);
    elseOutputBytes = appendBranchOutputConcat(elseCtx);
  }

  // Branch-merged locals (2 or more). An `if` expression carries exactly ONE
  // value, so the alias trick further down can only rewire post-branch
  // references for a SINGLE merged local. With two or more — or with the arms
  // reassigning DIFFERENT locals — every later reference kept naming the
  // pre-branch binding, i.e. the dead initial value, and stack lowering then
  // registered one stackMap slot for N physical results and resolved every
  // later operand one slot off. Both faces produced a script the real
  // interpreter rejects (OP_NUM2BIN / OP_ADD landing on a pubkey) or, worse,
  // a continuation committing stale state that the off-chain interpreter
  // agreed with. Reported privately 2026-08-03; see
  // packages/runar-testing/src/__tests__/branch-merged-locals-vm.test.ts.
  //
  // Fix: give both arms the SAME result set in the SAME order by appending an
  // explicit rebind of every merged local to each arm. In an arm that already
  // reassigned the local this re-binds its own new value (stack lowering rolls
  // the slot up); in an arm that did not, it re-binds the outer value (stack
  // lowering picks a copy). Both arms then leave exactly N equally-named
  // results, which `lowerIf`'s N>=2 reconcile adopts by name — so a reference
  // after the `if` resolves to the merged value whichever branch ran.
  const mergedLocals = collectBranchMergedLocals(thenCtx, elseCtx, ctx);

  if (branchHasOutputs) {
    const reason = branchOutputRejectionReason(
      thenCtx, elseCtx, thenOutputBytes, elseOutputBytes, mergedLocals, readsAfter,
    );
    if (reason !== null) {
      throw new Error(
        `Cannot compile conditional that both declares outputs and ${reason}. ` +
        `Move the addOutput/addRawOutput/addDataOutput call after the ` +
        `if-statement.`,
      );
    }
  }

  // The `if`'s multi-result contract. Locals first, in the canonical merge
  // order both arms agree on, then the properties either arm writes, in
  // contract declaration order — so all seven tiers derive the same list from
  // the same source. `results[0]` is the deepest slot of the block.
  const armProps = new Set<string>();
  collectUpdatedProps(thenCtx.bindings, armProps);
  collectUpdatedProps(elseCtx.bindings, armProps);
  const resultNames = [
    ...mergedLocals,
    ...ctx.propertyNames().filter((name) => armProps.has(name)),
  ];

  // The result list is keyed by NAME everywhere downstream: `appendBranchResults`
  // picks the local path or the property path per entry with `props.has(name)`,
  // and 05-stack-lower's layout assertion compares the arm's top-N slot names
  // against this list. A local that shares a contract property's name therefore
  // appears TWICE — once as a merged local, once as an arm-written property —
  // and both entries take the PROPERTY path, so the local's value is silently
  // replaced by the property's. The layout assertion cannot catch it: both
  // slots are legitimately named `count`, so comparing names is satisfied by
  // coincidence.
  //
  // Refuse instead. Only the exact collision is refused — a local shadowing a
  // property is otherwise fine, and stays fine, as long as the two are not both
  // results of the same `if`.
  const shadowed = mergedLocals.filter((name) => armProps.has(name));
  if (shadowed.length > 0) {
    throw new Error(
      `Local variable '${shadowed[0]}' shadows contract property ` +
      `'this.${shadowed[0]}', and the conditional assigns both. The branch's ` +
      `result slots are identified by name, so the two cannot be told apart ` +
      `and the local's value would be silently replaced by the property's. ` +
      `Rename the local.`,
    );
  }

  // When to materialise the contract instead of leaving the arms to the
  // stack-lowerer's inference:
  //
  //   - two or more merged locals — the pre-existing normalisation. Kept on
  //     exactly its old trigger so the four `__merge$` goldens do not move.
  //   - any result at all when the ELSE arm carries code. This is the new
  //     case, and it is where every measured miscompile lives: one arm rebinds
  //     its local IN PLACE (net depth 0) while the other pushes a fresh slot
  //     (net +1), or an arm writes a property beside a rebound local, or the
  //     two arms write the same properties in a different order. The arms then
  //     leave different LAYOUTS, which no depth or liveness predicate can see.
  //
  // An `if` WITHOUT an else keeps the preserve-the-old-value path in `lowerIf`
  // (phase 3 copies each missing slot's same-named parent value), which already
  // produces exactly these results by construction — deliberately left intact.
  // An arm that emits outputs is excluded: its single value is the serialised
  // output bytes, and `branchOutputRejectionReason` above already refuses every
  // combination that would need a second result.
  //
  // EXCLUDED: an `if` that `liftBranchUpdateProps` will rewrite. That pass
  // (deep-review finding C20) turns a conditional-property-assignment chain —
  // `if (p==0) { this.c0 = v } else if (p==1) { this.c1 = v } ... else
  // { assert(false) }` — into one flat single-valued `if` per property plus a
  // top-level `update_prop`, so the surviving `if`s carry no property result
  // and need no declaration. Appending the normalisation block first would
  // ALSO silently disable that pass: its recogniser requires the arm's last
  // binding to be the `update_prop` with everything before it side-effect
  // free, and the block adds a second `update_prop` behind it. TicTacToe's
  // position dispatch is exactly that shape, and losing the lift there
  // produced an unspendable `move` script.
  //
  // The exclusion must be exactly "the lift WILL rewrite this `if`", and that
  // is narrower than "the lift's recogniser accepts this `if`" in TWO ways.
  // Both gaps were live defects: the shape fell through the exclusion AND
  // through the rewrite, so it declared no results and got no flattening, and
  // stack lowering fell back to inference that puts the property's STALE slot
  // on top. `lowerGetStateScript` resolves properties by name through
  // `findDepth`, which returns the TOPMOST slot, so the continuation committed
  // the pre-call value and the UTXO was permanently unspendable.
  //
  //   1. `liftBranchUpdateProps` only rewrites chains of TWO OR MORE branches.
  //      `collectUpdateBranches` returns a ONE-element list for the
  //      `isAssertFalseElse` path, so `if (n > 0n) { this.count = ... } else
  //      { assert(false) }` — the idiomatic guard — was recognised, excluded,
  //      and then left alone.
  //   2. `liftBranchUpdateProps` only walks `method.body`, and passes `loop`
  //      bodies and surviving `if` arms through untouched. The same chain one
  //      `for` deeper, or nested in another arm, is recognised at every depth
  //      by `lowerIfStatement` but rewritten at none.
  //
  // Gating on `!ctx.nested` closes (2) byte-neutrally: every `if` the lift
  // actually rewrites today is a top-level binding of `method.body`, so no
  // currently-lifted chain changes behaviour, and the nested ones that were
  // silently broken now take the declared-results path like any other `if`.
  //
  // A chain's DEEPEST `if` is never at top level, so it now declares results
  // and carries a normalisation block — which is why `collectUpdateBranches`
  // strips a declared block before matching (see `stripDeclaredResults`). The
  // enclosing chain is still recognised and still lifted, and the lift
  // discards the inner node (block and all), so the chain's bytes do not move.
  const lifted = collectUpdateBranches(condRef, thenCtx.bindings, elseCtx.bindings);
  const willBeLifted = !ctx.nested && lifted !== null && lifted.length >= 2;
  const declaresResults =
    !branchHasOutputs &&
    !willBeLifted &&
    (mergedLocals.length >= 2 || (resultNames.length >= 1 && elseCtx.bindings.length > 0));

  if (declaresResults) {
    appendBranchResults(thenCtx, resultNames, armProps);
    ctx.syncCounter(thenCtx);
    appendBranchResults(elseCtx, resultNames, armProps);
    ctx.syncCounter(elseCtx);
  }

  const ifName = ctx.emit({
    kind: 'if',
    cond: condRef,
    then: thenCtx.bindings,
    else: elseCtx.bindings,
    ...(declaresResults ? { results: resultNames } : {}),
  });

  if (branchHasOutputs) {
    // Register the if's value once with the parent's continuation
    // tracker. Both state and data bytes from the chosen branch are
    // already concatenated into this single ref in declaration order.
    //
    // CRITICAL: pick the right tracker. If either branch produces a
    // STATE output (addOutput / addRawOutput), the parent must take
    // the multi-output continuation path, so we register as a state
    // output ref. If neither branch produces a state output and at
    // least one branch produces a data output, we register as a DATA
    // output ref so the parent keeps its single-output
    // `computeStateOutput` continuation and the data-output bytes
    // splice in BETWEEN the state output and the change output.
    //
    // Without this distinction, a stateful method whose branch
    // contains only `addDataOutput` was forced onto the multi-output
    // path — silently dropping the canonical state continuation and
    // producing an incorrect hashOutputs commitment.
    const branchHasStateOutput =
      thenOutputRefs.length > 0 || elseOutputRefs.length > 0;
    if (branchHasStateOutput) {
      ctx.addOutputRef(ifName);
    } else {
      ctx.addDataOutputRef(ifName);
    }
  }

  // If both branches end by reassigning the same single local variable,
  // alias that variable to the if-expression result so that subsequent
  // references resolve to the branch output, not the dead initial value.
  //
  // Skipped when the arms were normalised above: there the `if` DECLARES its
  // results, and each one keeps its OWN name through the reconcile in
  // `lowerIf`. Aliasing here would point every merged local at the single
  // if-binding name — the last result slot — so N-1 of them would silently
  // read the wrong value.
  if (!declaresResults) {
    const thenLast = thenCtx.bindings[thenCtx.bindings.length - 1];
    const elseLast = elseCtx.bindings[elseCtx.bindings.length - 1];
    if (thenLast && elseLast &&
        thenLast.name === elseLast.name &&
        ctx.isLocal(thenLast.name)) {
      ctx.setLocalAlias(thenLast.name, ifName);
    }
  }
}

/**
 * Append the canonical result block to one arm of an if-statement: a copy of
 * every declared result, in the declared order, rebound under its own name.
 *
 * This is what makes the `if` node's `results` contract true rather than
 * hoped-for. After it, the arm's top `results.length` slots ARE the results,
 * in `results` order, whichever arm ran and whichever of them this arm
 * actually assigned.
 *
 * Done in two passes on purpose. The first pass copies each live value to a
 * fresh branch-local temp; the second rebinds each result from its temp. That
 * makes the arm's stack effect exactly +N regardless of which results this
 * particular arm reassigned:
 *
 *   - pass 1 always COPIES. For a LOCAL, `@ref:<local>` resolves to the arm's
 *     own new value if it rebound one, else to the enclosing scope's value,
 *     and either way stack lowering picks (never rolls) it, because a declared
 *     result is in `outerProtectedRefs`. For a PROPERTY, `load_prop` picks the
 *     arm's updated slot when the arm wrote it, and otherwise the enclosing
 *     value (or the deploy-time placeholder when the property has never been
 *     on the stack).
 *   - pass 2 always CONSUMES, because the temps are bound in this arm and this
 *     is their last use, so each rolls into place.
 *
 * A single-pass `<result> = @ref:<result>` cannot do this: the same protection
 * that stops an arm from rolling away a still-needed parent slot also forces a
 * copy when the arm is rebinding its OWN value, so arms that assigned
 * different results ended up at different depths with the results in different
 * orders — which is exactly what `lowerIf`'s reconcile compares.
 *
 * Semantically a no-op for the off-chain ANF interpreters in all seven SDKs:
 * every binding is an ordinary read-then-write of a value the arm already
 * holds, so they need no knowledge of `results` at all.
 */
function appendBranchResults(
  branchCtx: LoweringContext,
  resultNames: string[],
  props: ReadonlySet<string>,
): void {
  resultNames.forEach((name, i) => {
    branchCtx.emitNamed(
      `${MERGED_LOCAL_TEMP_PREFIX}${i}`,
      props.has(name)
        ? { kind: 'load_prop', name }
        : { kind: 'load_const', value: `@ref:${name}` },
    );
  });
  resultNames.forEach((name, i) => {
    const temp = `${MERGED_LOCAL_TEMP_PREFIX}${i}`;
    if (props.has(name)) {
      branchCtx.emit({ kind: 'update_prop', name, value: temp });
    } else {
      branchCtx.emitNamed(name, { kind: 'load_const', value: `@ref:${temp}` });
    }
  });
}

/**
 * The locals from the enclosing scope that either arm of an if-statement
 * reassigns, in a canonical order both arms can agree on: the then-arm's
 * reassignments in order of last rebind, then the else-only ones in the same
 * order.
 *
 * Only names the PARENT already knows as locals count — `ctx.subContext()`
 * copies `localNames` by value, so a `let` declared inside a branch never
 * reaches the parent's set and is correctly excluded (it is not live after
 * the if).
 */
function collectBranchMergedLocals(
  thenCtx: LoweringContext,
  elseCtx: LoweringContext,
  ctx: LoweringContext,
): string[] {
  const lastRebindOrder = (branch: LoweringContext): string[] => {
    const seen = new Map<string, number>();
    branch.bindings.forEach((b, i) => {
      if (ctx.isLocal(b.name)) seen.set(b.name, i);
    });
    return [...seen.entries()].sort((a, b) => a[1] - b[1]).map(([name]) => name);
  };
  const merged = lastRebindOrder(thenCtx);
  for (const name of lastRebindOrder(elseCtx)) {
    if (!merged.includes(name)) merged.push(name);
  }
  return merged;
}

/**
 * Why an `if` whose arms declare outputs cannot be represented — or `null` when
 * it can. Returns the reason clause the diagnostic embeds.
 *
 * An `if` expression carries exactly ONE value, and when an arm emits an output
 * that value is already spoken for: it is the output bytes the continuation
 * hash consumes (`appendBranchOutputConcat`). Anything ELSE the arm leaves
 * behind breaks one of two invariants that nothing downstream enforces:
 *
 *   INV-A  the parent registers the if-expression's value as the branch's
 *          contribution to the continuation hash, so "the branch's output
 *          bytes" really means "whatever the arm's LAST binding is". A binding
 *          that lands after the output — a rebound local, a property write —
 *          silently replaces the serialized output with an unrelated value,
 *          and `drainBranchPrivateResidue` then physically drops the real
 *          output because it is no longer on top.
 *   INV-B  an arm that emits an output AND leaves any other slot the parent
 *          can still name — a property write anywhere in the arm, or a rebound
 *          local that is still read after the `if` — leaves 2+ results against
 *          the ONE stackMap name `lowerIf` registers, desyncing the parent
 *          stack by a slot from there on. `drainBranchPrivateResidue` cannot
 *          save it: it filters BY NAME and those names are all pre-`if` names.
 *
 * Neither is visible off-chain — the ANF interpreter copies branch bindings
 * back into the parent env and skips the auto-injected continuation assert
 * outright — so both shipped as permanently unspendable locking scripts.
 * Refuse at compile time rather than emit one. See
 * packages/runar-testing/src/__tests__/branch-output-terminal-value-vm.test.ts
 * for the real-Script-VM proof of each shape.
 *
 * The clauses are checked in a fixed order so all seven tiers report the same
 * reason for a source that trips more than one.
 */
function branchOutputRejectionReason(
  thenCtx: LoweringContext,
  elseCtx: LoweringContext,
  thenOutputBytes: string,
  elseOutputBytes: string,
  mergedLocals: string[],
  readsAfter: ReadonlySet<string>,
): string | null {
  // 1. Two or more merged locals: normalising them would need a multi-result
  //    `if` node, and the arms' single value is already the output concat.
  if (mergedLocals.length >= 2) {
    return `merges ${mergedLocals.length} local variables (${mergedLocals.join(', ')})`;
  }

  // 2. INV-A: the arm's terminal binding must BE its output bytes.
  const arms: Array<[string, LoweringContext, string]> = [
    ['then', thenCtx, thenOutputBytes],
    ['else', elseCtx, elseOutputBytes],
  ];
  for (const [label, branchCtx, outputBytes] of arms) {
    const last = branchCtx.bindings[branchCtx.bindings.length - 1];
    if (!last || last.name !== outputBytes) {
      return `continues past its output in the ${label}-branch`;
    }
  }

  // 3. INV-B: a property write leaves a slot the parent can still name,
  //    wherever in the arm it sits.
  const writtenProps = new Set<string>();
  for (const [, branchCtx] of arms) {
    collectUpdatedProps(branchCtx.bindings, writtenProps);
  }
  if (writtenProps.size > 0) {
    return `assigns contract properties (${[...writtenProps].join(', ')}) inside the branch`;
  }

  // 4. INV-B: a rebound local that survives the `if` is protected from being
  //    rolled away, so the arm ends one slot deeper than lowerIf accounts for.
  const liveMerged = mergedLocals.filter((name) => readsAfter.has(name));
  if (liveMerged.length > 0) {
    return `reassigns local variables read after it (${liveMerged.join(', ')})`;
  }

  return null;
}

/**
 * Every property name an ANF binding list assigns, including the ones nested
 * inside an `if` arm or a `loop` body — a nested write is just as much a named
 * slot the enclosing arm leaves behind.
 */
function collectUpdatedProps(bindings: ANFBinding[], out: Set<string>): void {
  for (const binding of bindings) {
    const value = binding.value;
    switch (value.kind) {
      case 'update_prop':
        out.add(value.name);
        break;
      case 'if':
        collectUpdatedProps(value.then, out);
        collectUpdatedProps(value.else, out);
        break;
      case 'loop':
        collectUpdatedProps(value.body, out);
        break;
      default:
        break;
    }
  }
}

/**
 * Concatenate a branch's collected output refs (state then data, in
 * declaration order) into a single bytes-ref appended to the
 * branch's bindings. If the branch has no outputs, emits an empty
 * `load_const` so the branch still leaves one item on the stack —
 * required to balance the if's branch shapes.
 *
 * Returns the name of the resulting binding (always a binding in
 * `branchCtx.bindings`).
 */
function appendBranchOutputConcat(branchCtx: LoweringContext): string {
  const allRefs = [
    ...branchCtx.getAddOutputRefs(),
    ...branchCtx.getAddDataOutputRefs(),
  ];
  if (allRefs.length === 0) {
    return branchCtx.emit({ kind: 'load_const', value: '' });
  }
  if (allRefs.length === 1) {
    return allRefs[0]!;
  }
  let accumulated = allRefs[0]!;
  for (let i = 1; i < allRefs.length; i++) {
    accumulated = branchCtx.emit({ kind: 'call', func: 'cat', args: [accumulated, allRefs[i]!] });
  }
  return accumulated;
}

function lowerForStatement(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
  ctx: LoweringContext,
  readsAfter: ReadonlySet<string> = NO_READS,
): void {
  // Resolve the loop's compile-time shape: start value, step direction, and
  // iteration count. Rúnar requires bounded loops, so all three must be
  // statically determinable (issue #121).
  const { start, step, count } = extractLoopShape(stmt);

  // Lower body into sub-context. The body repeats, so every read anywhere in
  // it is a read that happens after any given statement inside it.
  const bodyReads = new Set(readsAfter);
  for (const s of stmt.body) collectStatementReads(s, bodyReads);

  const bodyCtx = ctx.subContext();
  lowerStatements(stmt.body, bodyCtx, bodyReads);
  ctx.syncCounter(bodyCtx);

  ctx.emit({
    kind: 'loop',
    count,
    body: bodyCtx.bindings,
    iterVar: stmt.init.name,
    start,
    step,
  });
}

/**
 * Resolve a for-statement's compile-time loop shape (issue #121).
 *
 * Supports counting-up and counting-down loops:
 *   for (let i = 0n; i < 10n; i++)     -> start 0,  step +1, count 10
 *   for (let i = 1n; i <= 3n; i++)     -> start 1,  step +1, count 3
 *   for (let i = 3n; i > 0n; i--)      -> start 3,  step -1, count 3
 *   for (let i = 3n; i >= 1n; i--)     -> start 3,  step -1, count 3
 *
 * The loop is unrolled `count` times; on iteration `i` the iterator holds
 * `start + i * step`. Start and bound must be compile-time integer literals.
 */
function extractLoopShape(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
): { start: bigint; step: 1 | -1; count: number } {
  const start = extractBigIntValue(stmt.init.init);
  if (start === null) {
    throw new Error(
      'Cannot determine loop start at compile time. For-loop iterators must start at an integer literal.',
    );
  }

  if (stmt.condition.kind !== 'binary_expr') {
    throw new Error('Cannot determine loop bound at compile time. For-loop bounds must be integer literals.');
  }
  const op = stmt.condition.op;
  const bound = extractBigIntValue(stmt.condition.right);
  if (bound === null) {
    throw new Error('Cannot determine loop bound at compile time. For-loop bounds must be integer literals.');
  }

  const step = extractLoopStep(stmt);

  // Count = number of iterations before the condition first turns false.
  let count: bigint;
  if (step === 1) {
    if (op === '<') count = bound - start;
    else if (op === '<=') count = bound - start + 1n;
    else {
      throw new Error(
        `For loop counting up (i${'++'}) must use '<' or '<=' (got '${op}').`,
      );
    }
  } else {
    if (op === '>') count = start - bound;
    else if (op === '>=') count = start - bound + 1n;
    else {
      throw new Error(
        `For loop counting down (i--) must use '>' or '>=' (got '${op}').`,
      );
    }
  }

  return { start, step, count: Math.max(0, Number(count)) };
}

/**
 * Determine the iterator step direction (+1 / -1) from the for-statement's
 * update clause, falling back to the condition direction. Only unit steps are
 * supported; a non-unit update (e.g. `i += 2`) is out of the loop model.
 */
function extractLoopStep(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
): 1 | -1 {
  const update = stmt.update;
  if (update.kind === 'expression_statement') {
    const e = update.expression;
    if (e.kind === 'increment_expr') return 1;
    if (e.kind === 'decrement_expr') return -1;
  }
  // Fall back to the comparison direction for other unit-step spellings
  // (e.g. `i = i + 1n`): `<`/`<=` counts up, `>`/`>=` counts down.
  if (stmt.condition.kind === 'binary_expr') {
    const op = stmt.condition.op;
    if (op === '>' || op === '>=') return -1;
  }
  return 1;
}

function extractBigIntValue(expr: Expression): bigint | null {
  if (expr.kind === 'bigint_literal') return expr.value;
  if (expr.kind === 'unary_expr' && expr.op === '-') {
    const inner = extractBigIntValue(expr.operand);
    return inner !== null ? -inner : null;
  }
  return null;
}

function lowerExpressionStatement(
  stmt: Extract<Statement, { kind: 'expression_statement' }>,
  ctx: LoweringContext,
): void {
  lowerExprToRef(stmt.expression, ctx);
}

function lowerReturnStatement(
  stmt: Extract<Statement, { kind: 'return_statement' }>,
  ctx: LoweringContext,
): void {
  if (stmt.value) {
    const ref = lowerExprToRef(stmt.value, ctx);
    // If the returned ref is not the name of the last emitted binding, emit
    // an explicit load so the return value is the last (top-of-stack) binding.
    // This matters when a local variable is returned after control flow (e.g.,
    // `let count = 0n; if (...) { count += 1n; } return count;`).  Without
    // this, the last binding is the if, not `count`, so inlineMethodCall in
    // stack lowering can't find the return value.
    const lastBinding = ctx.bindings[ctx.bindings.length - 1];
    if (lastBinding && lastBinding.name !== ref) {
      ctx.emit({ kind: 'load_const', value: `@ref:${ref}` });
    }
  }
}

// ---------------------------------------------------------------------------
// Expression lowering -- the heart of ANF conversion
// ---------------------------------------------------------------------------

/**
 * Lower an expression to ANF form and return the name of the temp variable
 * holding its value.
 */
function lowerExprToRef(expr: Expression, ctx: LoweringContext): string {
  switch (expr.kind) {
    case 'bigint_literal':
      return ctx.emit({ kind: 'load_const', value: expr.value });

    case 'bool_literal':
      return ctx.emit({ kind: 'load_const', value: expr.value });

    case 'bytestring_literal':
      return ctx.emit({ kind: 'load_const', value: expr.value });

    case 'identifier':
      return lowerIdentifier(expr, ctx);

    case 'property_access':
      // Explicit `this.x`: a real contract property always wins, even when a
      // method param shares the name (issue #130). Now that declared params are
      // registered, the isParam branch below must not shadow a stored property.
      if (ctx.isProperty(expr.property)) {
        return ctx.emit({ kind: 'load_prop', name: expr.property });
      }
      // this.txPreimage in StatefulSmartContract -> load_param (it's an
      // implicit injected param, not a stored property).
      if (ctx.isParam(expr.property)) {
        return ctx.emit({ kind: 'load_param', name: expr.property });
      }
      // this.x -> load_prop
      return ctx.emit({ kind: 'load_prop', name: expr.property });

    case 'member_expr':
      return lowerMemberExpr(expr, ctx);

    case 'binary_expr':
      return lowerBinaryExpr(expr, ctx);

    case 'unary_expr':
      return lowerUnaryExpr(expr, ctx);

    case 'call_expr':
      return lowerCallExpr(expr, ctx);

    case 'ternary_expr':
      return lowerTernaryExpr(expr, ctx);

    case 'index_access':
      return lowerIndexAccess(expr, ctx);

    case 'increment_expr':
      return lowerIncrementExpr(expr, ctx);

    case 'decrement_expr':
      return lowerDecrementExpr(expr, ctx);

    case 'array_literal': {
      const elementRefs = expr.elements.map(elem => lowerExprToRef(elem, ctx));
      return ctx.emit({ kind: 'array_literal', elements: elementRefs });
    }
  }
}

function lowerIdentifier(
  expr: Extract<Expression, { kind: 'identifier' }>,
  ctx: LoweringContext,
): string {
  const name = expr.name;

  // 'this' is not a value in ANF -- it's handled at the member level
  if (name === 'this') {
    return ctx.emit({ kind: 'load_const', value: '@this' });
  }

  // Param alias takes precedence over normal param lookup. Set when a
  // private method's body is being inlined into this context — the
  // private's param names map to the caller's arg refs.
  const aliased = ctx.getParamAlias(name);
  if (aliased !== undefined) {
    return aliased;
  }

  // Check if it's a parameter
  if (ctx.isParam(name)) {
    return ctx.emit({ kind: 'load_param', name });
  }

  // Check if it's a local variable -- reference it directly
  // (or use its alias if reassigned by an if-statement)
  if (ctx.isLocal(name)) {
    return ctx.getLocalAlias(name) ?? name;
  }

  // Check if it's a contract property
  if (ctx.isProperty(name)) {
    return ctx.emit({ kind: 'load_prop', name });
  }

  // Assume it's a parameter (method params are the most common case
  // and the context may not have them all registered)
  return ctx.emit({ kind: 'load_param', name });
}

function lowerMemberExpr(
  expr: Extract<Expression, { kind: 'member_expr' }>,
  ctx: LoweringContext,
): string {
  // this.x -> load_prop
  if (expr.object.kind === 'identifier' && expr.object.name === 'this') {
    return ctx.emit({ kind: 'load_prop', name: expr.property });
  }

  // SigHash.ALL etc. -> load constant
  if (expr.object.kind === 'identifier' && expr.object.name === 'SigHash') {
    const sigHashValues: Record<string, bigint> = {
      ALL: 0x01n,
      NONE: 0x02n,
      SINGLE: 0x03n,
      FORKID: 0x40n,
      ANYONECANPAY: 0x80n,
    };
    const val = sigHashValues[expr.property];
    if (val !== undefined) {
      return ctx.emit({ kind: 'load_const', value: val });
    }
  }

  if (expr.object.kind === 'identifier' &&
      ctx.isStatefulContextParam(expr.object.name) &&
      expr.property === 'txPreimage') {
    return ctx.emit({ kind: 'load_param', name: 'txPreimage' });
  }

  // General member access: lower the object, then emit a method_call placeholder
  const objRef = lowerExprToRef(expr.object, ctx);
  return ctx.emit({ kind: 'method_call', object: objRef, method: expr.property, args: [] });
}

function lowerBinaryExpr(
  expr: Extract<Expression, { kind: 'binary_expr' }>,
  ctx: LoweringContext,
): string {
  // NEW-014: `&&` and `||` SHORT-CIRCUIT. They desugar to the ternary, which
  // 05-stack-lower already emits as real OP_IF / OP_ELSE control flow:
  //
  //     a && b   ==>   a ? b : false
  //     a || b   ==>   a ? true : b
  //
  // They used to lower to `bin_op`, i.e. OP_BOOLAND / OP_BOOLOR — binary stack
  // ops, so BOTH operands were pushed and therefore both evaluated.
  // `spec/semantics.md` §3.7 licensed that with "This is safe in Rúnar because
  // all expressions are pure (no side effects beyond `assert`)". Purity is not
  // TOTALITY: the same document's §10 and §11.3 list division by zero as a
  // runtime failure, and OP_SPLIT / OP_NUM2BIN abort out of range. Evaluating
  // the operand the source skipped therefore aborted the script, and the
  // ordinary defensive guard —
  //
  //     assert(d === 0n || (100n / d) > 1n);
  //
  // — compiled to a locking script the chain rejects for exactly the input the
  // guard exists to protect, while `TestContract` (which short-circuits, like
  // every surface syntax the frontends accept) reported success. §3.9 already
  // specifies the ternary's untaken arm as unevaluated, so laziness was
  // already in the language; `&&` / `||` were the sole eager outlier.
  //
  // Only SOURCE-level `&&` / `||` desugar here. The compiler still synthesises
  // `bin_op` `&&` / `||` internally to fold if/else-chain guard conditions
  // (see `lowerIfStatement`); those operands are already-bound refs to plain
  // comparison results, so they cannot abort and stay on the cheap opcodes.
  if (expr.op === '&&' || expr.op === '||') {
    const constant: Expression = { kind: 'bool_literal', value: expr.op === '||' };
    return lowerTernaryExpr(
      {
        kind: 'ternary_expr',
        condition: expr.left,
        consequent: expr.op === '||' ? constant : expr.right,
        alternate: expr.op === '||' ? expr.right : constant,
        ...(expr.sourceLocation !== undefined ? { sourceLocation: expr.sourceLocation } : {}),
      },
      ctx,
    );
  }

  const leftRef = lowerExprToRef(expr.left, ctx);
  const rightRef = lowerExprToRef(expr.right, ctx);

  // For equality operators, annotate with operand type so stack lowering
  // can choose OP_EQUAL vs OP_NUMEQUAL.
  const binOp: BinOp = { kind: 'bin_op', op: expr.op, left: leftRef, right: rightRef };
  if (expr.op === '===' || expr.op === '!==') {
    if (isByteTypedExpr(expr.left, ctx) || isByteTypedExpr(expr.right, ctx)) {
      binOp.result_type = 'bytes';
    }
  }
  // For +, annotate byte-typed operands so stack lowering can emit OP_CAT.
  if (expr.op === '+') {
    if (isByteTypedExpr(expr.left, ctx) || isByteTypedExpr(expr.right, ctx)) {
      binOp.result_type = 'bytes';
    }
  }
  // For bitwise &, |, ^, annotate byte-typed operands.
  if (expr.op === '&' || expr.op === '|' || expr.op === '^') {
    if (isByteTypedExpr(expr.left, ctx) || isByteTypedExpr(expr.right, ctx)) {
      binOp.result_type = 'bytes';
    }
  }
  return ctx.emit(binOp);
}

function lowerUnaryExpr(
  expr: Extract<Expression, { kind: 'unary_expr' }>,
  ctx: LoweringContext,
): string {
  const operandRef = lowerExprToRef(expr.operand, ctx);
  const unaryOp: ANFUnaryOp = { kind: 'unary_op', op: expr.op, operand: operandRef };
  // For ~, annotate byte-typed operands so downstream passes know the result is bytes.
  if (expr.op === '~' && isByteTypedExpr(expr.operand, ctx)) {
    unaryOp.result_type = 'bytes';
  }
  return ctx.emit(unaryOp);
}

function lowerCallExpr(
  expr: Extract<Expression, { kind: 'call_expr' }>,
  ctx: LoweringContext,
): string {
  const callee = expr.callee;
  const normalizedAddOutputArgs = flattenAddOutputArgs(expr.args);

  // super(...) call -- emit property initializations
  if (callee.kind === 'identifier' && callee.name === 'super') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    return ctx.emit({ kind: 'call', func: 'super', args: argRefs });
  }

  // assert(expr) -> flatten to assert value
  if (callee.kind === 'identifier' && callee.name === 'assert') {
    if (expr.args.length >= 1) {
      const valueRef = lowerExprToRef(expr.args[0]!, ctx);
      return ctx.emit({ kind: 'assert', value: valueRef });
    }
    // assert() with no args -- should have been caught by validator
    return ctx.emit({ kind: 'assert', value: ctx.emit({ kind: 'load_const', value: false }) });
  }

  // checkPreimage(preimage) -> special node
  if (callee.kind === 'identifier' && callee.name === 'checkPreimage') {
    if (expr.args.length >= 1) {
      const preimageRef = lowerExprToRef(expr.args[0]!, ctx);
      return ctx.emit({
        kind: 'check_preimage',
        preimage: preimageRef,
        // Issue #123: honour the method's declared @sighash on manual calls.
        ...(ctx.sighashFlag !== undefined ? { sighashFlag: ctx.sighashFlag } : {}),
      });
    }
  }

  // extractPrevOutputScript(inputIndex_literal, expectedScriptHash) -> ByteString.
  // extractPrevOutputScript(inputIndex_literal, expectedScriptPrefixHash, prefixLen_literal) -> ByteString.
  //
  // Witness-bridge sugar (BSVM Phase 13). Auto-injects a hidden method
  // parameter named `_prevOutScript_<inputIndex>` (one per distinct index
  // in the method body), emits a hash assertion, and returns the witness
  // ref for caller substring extraction.
  //
  // 2-arg form: hash256(witness) === expectedScriptHash. Pins the full
  //   prev-output script byte-for-byte.
  // 3-arg form (Crit-2): hash256(substr(witness, 0, prefixLen)) ===
  //   expectedScriptPrefixHash. Pins the policy prefix only, leaving the
  //   pushdata tail free to vary. Required for the intent-template
  //   matching use case where each successor intent UTXO has a unique
  //   tail (BSVM Mode 3 permissionless step-in).
  if (callee.kind === 'identifier' && callee.name === 'extractPrevOutputScript') {
    if (expr.args.length !== 2 && expr.args.length !== 3) {
      return ctx.emit({ kind: 'load_const', value: '' });
    }
    const idxArg = expr.args[0]!;
    if (idxArg.kind !== 'bigint_literal') {
      // typecheck has already emitted the diagnostic; emit a placeholder
      // so lowering doesn't crash.
      return ctx.emit({ kind: 'load_const', value: '' });
    }
    const idx = idxArg.value;
    const paramName = `_prevOutScript_${idx.toString()}`;
    ctx.methodScope.recordAutoInjectedParam(paramName, 'ByteString');
    ctx.addParam(paramName);
    const witnessRef = ctx.emit({ kind: 'load_param', name: paramName });
    const expectedHashRef = lowerExprToRef(expr.args[1]!, ctx);

    // Determine which bytes to hash: full witness (2-arg) or
    // prefix (3-arg). The substr happens at script-execution time;
    // the literal prefixLen is baked into the emitted Stack-IR.
    let bytesToHashRef: string;
    if (expr.args.length === 3) {
      const prefixLenArg = expr.args[2]!;
      if (prefixLenArg.kind !== 'bigint_literal') {
        // typecheck has already emitted the diagnostic; emit a placeholder.
        return ctx.emit({ kind: 'load_const', value: '' });
      }
      const zeroRef = ctx.emit({ kind: 'load_const', value: 0n });
      const prefixLenRef = ctx.emit({ kind: 'load_const', value: prefixLenArg.value });
      bytesToHashRef = ctx.emit({
        kind: 'call', func: 'substr',
        args: [witnessRef, zeroRef, prefixLenRef],
      });
    } else {
      bytesToHashRef = witnessRef;
    }

    const actualHashRef = ctx.emit({ kind: 'call', func: 'hash256', args: [bytesToHashRef] });
    const eqRef = ctx.emit({
      kind: 'bin_op', op: '===',
      left: actualHashRef, right: expectedHashRef,
      result_type: 'bytes',
    });
    ctx.emit({ kind: 'assert', value: eqRef });
    return witnessRef;
  }

  // requireOutputP2PKH(outputIndex_literal, pubkeyHash, amount) -> void.
  // Asserts that the tx's output at outputIndex is a standard P2PKH paying
  // `amount` satoshis to `pubkeyHash`. Auto-injects `_serialisedOutputs`
  // (once per method) and emits hash256(serialisedOutputs) ==
  // extractOutputHash(txPreimage) the first time the intrinsic is called
  // in a method body. Subsequent calls in the same method skip the
  // hashOutputs check (already established) and emit only the per-output
  // substring assertion.
  //
  // v1 assumes all outputs in the serialised set are exactly 34 bytes
  // (8-byte LE amount ‖ 0x19 length ‖ 25-byte P2PKH script). Byte offset
  // of output i is i*34. If the method also calls this.addDataOutput(...)
  // the assumption breaks (variable-length OP_RETURN) — typecheck
  // rejects that mix; see checkMethod in 03-typecheck.ts (Crit-3).
  if (callee.kind === 'identifier' && callee.name === 'requireOutputP2PKH') {
    if (expr.args.length !== 3) {
      return ctx.emit({ kind: 'load_const', value: '' });
    }
    const idxArg = expr.args[0]!;
    if (idxArg.kind !== 'bigint_literal') {
      return ctx.emit({ kind: 'load_const', value: '' });
    }
    const idx = idxArg.value;

    ctx.methodScope.recordAutoInjectedParam('_serialisedOutputs', 'ByteString');
    ctx.addParam('_serialisedOutputs');

    // Emit the hashOutputs(preimage) check exactly once per method.
    if (!ctx.methodScope.didEmitHashOutputsCheck) {
      ctx.methodScope.didEmitHashOutputsCheck = true;
      const serialisedRef = ctx.emit({ kind: 'load_param', name: '_serialisedOutputs' });
      const actualOutHashRef = ctx.emit({ kind: 'call', func: 'hash256', args: [serialisedRef] });
      const preimageRef = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
      const expectedOutHashRef = ctx.emit({ kind: 'call', func: 'extractOutputHash', args: [preimageRef] });
      const hashEqRef = ctx.emit({
        kind: 'bin_op', op: '===',
        left: actualOutHashRef, right: expectedOutHashRef,
        result_type: 'bytes',
      });
      ctx.emit({ kind: 'assert', value: hashEqRef });
    }

    // Lower the user-supplied args (pubkeyHash, amount).
    const pubkeyHashRef = lowerExprToRef(expr.args[1]!, ctx);
    const amountRef = lowerExprToRef(expr.args[2]!, ctx);

    // Construct expected P2PKH output bytes:
    //   <amount: 8-byte LE> ‖ 0x19 0x76 0xa9 0x14 ‖ <pubkeyHash: 20 bytes> ‖ 0x88 0xac
    const eightRef = ctx.emit({ kind: 'load_const', value: 8n });
    const amountBytesRef = ctx.emit({ kind: 'call', func: 'num2bin', args: [amountRef, eightRef] });
    // 0x19 0x76 0xa9 0x14 — script length byte + OP_DUP OP_HASH160 OP_PUSH20
    const prefixRef = ctx.emit({ kind: 'load_const', value: '1976a914' });
    // 0x88 0xac — OP_EQUALVERIFY OP_CHECKSIG
    const suffixRef = ctx.emit({ kind: 'load_const', value: '88ac' });
    const cat1Ref = ctx.emit({ kind: 'call', func: 'cat', args: [amountBytesRef, prefixRef] });
    const cat2Ref = ctx.emit({ kind: 'call', func: 'cat', args: [cat1Ref, pubkeyHashRef] });
    const expectedOutputRef = ctx.emit({ kind: 'call', func: 'cat', args: [cat2Ref, suffixRef] });

    // Substring extract at idx*34 length 34, assert equal.
    const serialisedRef2 = ctx.emit({ kind: 'load_param', name: '_serialisedOutputs' });
    const offsetRef = ctx.emit({ kind: 'load_const', value: idx * 34n });
    const lengthRef = ctx.emit({ kind: 'load_const', value: 34n });
    const extractedRef = ctx.emit({ kind: 'call', func: 'substr', args: [serialisedRef2, offsetRef, lengthRef] });
    const outEqRef = ctx.emit({
      kind: 'bin_op', op: '===',
      left: extractedRef, right: expectedOutputRef,
      result_type: 'bytes',
    });
    return ctx.emit({ kind: 'assert', value: outEqRef });
  }

  // currentBlockHeight() -> bigint. Pure source-level desugar to
  // extractLocktime(this.txPreimage). Only valid in StatefulSmartContract
  // methods (typecheck enforces). No new ANF kind or stack codegen needed.
  if (callee.kind === 'identifier' && callee.name === 'currentBlockHeight') {
    const preimageRef = ctx.emit({ kind: 'load_param', name: 'txPreimage' });
    return ctx.emit({ kind: 'call', func: 'extractLocktime', args: [preimageRef] });
  }

  // asm({ body, in_arity?, out_arity? }) — parser has already normalised
  // the object-literal argument into three positional args
  // (body: bytestring_literal, in_arity: bigint_literal, out_arity:
  // bigint_literal). Lower directly to a raw_script ANF binding so the
  // bytes pass through stack-lower / emit verbatim. Phase-3 follow-ups
  // (array-body form, generic-expression form, multi-output) will reuse
  // this same ANF node with different parser shapes.
  if (callee.kind === 'identifier' && callee.name === 'asm') {
    return lowerAsmCall(expr, ctx);
  }

  // this.addOutput(satoshis, val1, val2, ...) -> special node
  if (callee.kind === 'property_access' && callee.property === 'addOutput') {
    const argRefs = normalizedAddOutputArgs.map(arg => lowerExprToRef(arg, ctx));
    const satoshis = argRefs[0]!;
    const stateValues = argRefs.slice(1);
    const ref = ctx.emit({ kind: 'add_output', satoshis, stateValues, preimage: '' });
    ctx.addOutputRef(ref);
    return ref;
  }

  // this.addRawOutput(satoshis, scriptBytes) -> special node
  if (callee.kind === 'property_access' && callee.property === 'addRawOutput') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    const satoshis = argRefs[0]!;
    const scriptBytes = argRefs[1]!;
    const ref = ctx.emit({ kind: 'add_raw_output', satoshis, scriptBytes });
    ctx.addOutputRef(ref);
    return ref;
  }

  // this.addDataOutput(satoshis, scriptBytes) -> special node. Like
  // addRawOutput in wire shape, but included in the continuation hash
  // AFTER state outputs and BEFORE the change output.
  if (callee.kind === 'property_access' && callee.property === 'addDataOutput') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    const satoshis = argRefs[0]!;
    const scriptBytes = argRefs[1]!;
    const ref = ctx.emit({ kind: 'add_data_output', satoshis, scriptBytes });
    ctx.addDataOutputRef(ref);
    return ref;
  }

  // this.getStateScript() -> special node
  if (callee.kind === 'property_access' && callee.property === 'getStateScript') {
    return ctx.emit({ kind: 'get_state_script' });
  }
  // member_expr handlers for addOutput/addRawOutput/getStateScript.
  // Matches both StatefulContext param style (Go/Move: `ctx.addOutput(...)`) and
  // this-style (Python/Ruby: `this.addOutput(...)` after snake_case conversion).
  if (callee.kind === 'member_expr' &&
      callee.object.kind === 'identifier' &&
      (callee.object.name === 'this' || ctx.isStatefulContextParam(callee.object.name)) &&
      callee.property === 'addOutput') {
    const argRefs = normalizedAddOutputArgs.map(arg => lowerExprToRef(arg, ctx));
    const satoshis = argRefs[0]!;
    const stateValues = argRefs.slice(1);
    const ref = ctx.emit({ kind: 'add_output', satoshis, stateValues, preimage: '' });
    ctx.addOutputRef(ref);
    return ref;
  }
  if (callee.kind === 'member_expr' &&
      callee.object.kind === 'identifier' &&
      (callee.object.name === 'this' || ctx.isStatefulContextParam(callee.object.name)) &&
      callee.property === 'addRawOutput') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    const satoshis = argRefs[0]!;
    const scriptBytes = argRefs[1]!;
    const ref = ctx.emit({ kind: 'add_raw_output', satoshis, scriptBytes });
    ctx.addOutputRef(ref);
    return ref;
  }
  if (callee.kind === 'member_expr' &&
      callee.object.kind === 'identifier' &&
      (callee.object.name === 'this' || ctx.isStatefulContextParam(callee.object.name)) &&
      callee.property === 'addDataOutput') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    const satoshis = argRefs[0]!;
    const scriptBytes = argRefs[1]!;
    const ref = ctx.emit({ kind: 'add_data_output', satoshis, scriptBytes });
    ctx.addDataOutputRef(ref);
    return ref;
  }
  if (callee.kind === 'member_expr' &&
      callee.object.kind === 'identifier' &&
      (callee.object.name === 'this' || ctx.isStatefulContextParam(callee.object.name)) &&
      callee.property === 'getStateScript') {
    return ctx.emit({ kind: 'get_state_script' });
  }

  // this.method(...) -> method_call (or inlined if the target is a
  // private method with continuation-relevant side effects).
  if (callee.kind === 'property_access') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    if (ctx.shouldInlinePrivate(callee.property)) {
      return inlinePrivateMethodCall(callee.property, argRefs, ctx);
    }
    return ctx.emit({
      kind: 'method_call',
      object: ctx.emit({ kind: 'load_const', value: '@this' }),
      method: callee.property,
      args: argRefs,
    });
  }
  if (callee.kind === 'member_expr' &&
      callee.object.kind === 'identifier' &&
      callee.object.name === 'this') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    if (ctx.shouldInlinePrivate(callee.property)) {
      return inlinePrivateMethodCall(callee.property, argRefs, ctx);
    }
    return ctx.emit({
      kind: 'method_call',
      object: ctx.emit({ kind: 'load_const', value: '@this' }),
      method: callee.property,
      args: argRefs,
    });
  }

  // Direct function call: sha256(x), checkSig(sig, pk), etc.
  // Standalone private functions (e.g., Go package-level helpers) that match a
  // contract method name are emitted as method_call so they get inlined by
  // the stack lowering pass instead of being treated as unknown builtins.
  if (callee.kind === 'identifier') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    const isPrivateMethod = ctx.isPrivateMethod(callee.name);
    if (isPrivateMethod) {
      if (ctx.shouldInlinePrivate(callee.name)) {
        return inlinePrivateMethodCall(callee.name, argRefs, ctx);
      }
      const thisRef = ctx.emit({ kind: 'load_const', value: '@this' });
      return ctx.emit({ kind: 'method_call', object: thisRef, method: callee.name, args: argRefs });
    }
    return ctx.emit({ kind: 'call', func: callee.name, args: argRefs });
  }

  // General call expression
  const calleeRef = lowerExprToRef(callee, ctx);
  const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
  return ctx.emit({ kind: 'method_call', object: calleeRef, method: 'call', args: argRefs });
}

function isStatefulContextParam(param: ParamNode): boolean {
  return param.type.kind === 'custom_type' && param.type.name === 'StatefulContext';
}

/**
 * Inline a private method's body directly into the caller's context.
 *
 * Used when the private has continuation-relevant side effects (state
 * mutation, addOutput, addRawOutput, addDataOutput) so that the
 * helper's emitted ANF nodes register output refs on the caller. This
 * is what makes the public method's continuation hash include outputs
 * declared in private helpers — without it, the helper's
 * `add_output`/`add_data_output` refs live in a sibling ANF method and
 * the public's `addOutputRefs`/`addDataOutputRefs` lists miss them, so
 * the runtime hashOutputs check would diverge from actual outputs.
 *
 * Caller's arg refs are mapped onto the private's parameter names via
 * `pushParamAlias`. While the private's body lowers, any identifier
 * expression matching one of those param names resolves to the
 * caller's ref (see `lowerIdentifier`). The aliases are popped
 * afterwards so subsequent lowering in the caller's body sees its own
 * scope.
 *
 * Recursion across private helpers is forbidden by validation, so this
 * always terminates. Nested inlining (private A calls private B) works
 * naturally: when we lower A's body and hit the call to B, the same
 * `lowerCallExpr` path runs and inlines B too.
 */
function inlinePrivateMethodCall(
  methodName: string,
  argRefs: string[],
  ctx: LoweringContext,
): string {
  const method = ctx.getPrivateMethod(methodName);
  if (!method) {
    // Should not happen — caller checked shouldInlinePrivate which
    // requires the method to exist. Fall back to a method_call so the
    // stack lowering pass surfaces a clear error.
    const thisRef = ctx.emit({ kind: 'load_const', value: '@this' });
    return ctx.emit({ kind: 'method_call', object: thisRef, method: methodName, args: argRefs });
  }

  // Bind caller arg refs to the private's parameter names.
  const aliasedParams: string[] = [];
  for (let i = 0; i < method.params.length && i < argRefs.length; i++) {
    const paramName = method.params[i]!.name;
    ctx.pushParamAlias(paramName, argRefs[i]!);
    aliasedParams.push(paramName);
  }

  const startIndex = ctx.bindings.length;
  lowerStatements(method.body, ctx);
  const endIndex = ctx.bindings.length;

  // Pop aliases in reverse order so nested inlines compose correctly.
  for (let i = aliasedParams.length - 1; i >= 0; i--) {
    ctx.popParamAlias(aliasedParams[i]!);
  }

  // Method's "return value" is the last binding emitted by the body.
  // Void methods (e.g., a private helper that just calls addOutput)
  // still produce a binding (the addOutput result) which the caller
  // expression-statement path will discard.
  if (endIndex > startIndex) {
    return ctx.bindings[endIndex - 1]!.name;
  }
  // Empty body — emit a load_const placeholder so the caller has a ref.
  return ctx.emit({ kind: 'load_const', value: '@void' });
}

function flattenAddOutputArgs(args: Expression[]): Expression[] {
  if (args.length === 2 && args[1]?.kind === 'array_literal') {
    return [args[0]!, ...args[1].elements];
  }
  return args;
}

/**
 * Lower an asm({...}) call (already parser-normalised to three
 * positional args (body, in_arity, out_arity)) into a single
 * `raw_script` ANF binding. The hex body passes through unchanged
 * — stack-lower decodes it and emits a `raw_bytes` StackOp, which the
 * emit pass writes verbatim. The peephole optimizer treats it as a
 * hard barrier, so adjacent bindings never fold across it.
 *
 * Diagnostics for malformed args (wrong arity, non-literal arities,
 * odd-length / non-hex body) have already been pushed by 02-validate;
 * here we defensively coerce missing values to safe defaults so a
 * downstream pass error doesn't mask the earlier validator error.
 */
function lowerAsmCall(
  expr: Extract<Expression, { kind: 'call_expr' }>,
  ctx: LoweringContext,
): string {
  const [bodyArg, inArityArg, outArityArg] = expr.args;

  const bytes =
    bodyArg && bodyArg.kind === 'bytestring_literal' ? bodyArg.value : '';
  const inArity =
    inArityArg && inArityArg.kind === 'bigint_literal' ? Number(inArityArg.value) : 0;
  const outArity =
    outArityArg && outArityArg.kind === 'bigint_literal' ? Number(outArityArg.value) : 1;

  return ctx.emit({
    kind: 'raw_script',
    bytes,
    in_arity: inArity,
    out_arity: outArity,
  });
}

/**
 * Lower one arm of a ternary, guaranteeing the arm ENDS with the binding that
 * holds its result.
 *
 * NEW-016: `lowerExprToRef` returns an existing ref without emitting anything
 * when the arm is a bare identifier — `g ? f : c === 0n` produced
 * `then: []`, an `if` arm with no bindings at all. 05-stack-lower reads an
 * arm's result off its stack effect, so a +0 arm has no result to adopt and
 * the depth reconcile padded the shortfall with an EMPTY push. The contract
 * compiled clean, `TestContract` accepted it, and the real engine rejected the
 * spend with "OP_VERIFY requires the top stack value to be truthy" over a
 * stack of `[01, ]` — the arm's `true` replaced by an empty (false) value.
 * An ordinary contract deployed to a permanently unspendable UTXO.
 *
 * Aliasing through `load_const @ref:` — the same idiom `let x = y` and the
 * increment/decrement lowerings already use — makes the arm's stack effect +1
 * and copies the parent slot instead of trying to move it. The alias is only
 * emitted when the result was NOT produced inside the arm, so every arm that
 * already ended on its own result keeps its exact bytes.
 */
function lowerTernaryArm(expr: Expression, armCtx: LoweringContext): void {
  const ref = lowerExprToRef(expr, armCtx);
  const last = armCtx.bindings[armCtx.bindings.length - 1];
  if (last === undefined || last.name !== ref) {
    armCtx.emit({ kind: 'load_const', value: `@ref:${ref}` });
  }
}

function lowerTernaryExpr(
  expr: Extract<Expression, { kind: 'ternary_expr' }>,
  ctx: LoweringContext,
): string {
  const condRef = lowerExprToRef(expr.condition, ctx);

  const thenCtx = ctx.subContext();
  lowerTernaryArm(expr.consequent, thenCtx);
  ctx.syncCounter(thenCtx);

  const elseCtx = ctx.subContext();
  lowerTernaryArm(expr.alternate, elseCtx);
  ctx.syncCounter(elseCtx);

  return ctx.emit({
    kind: 'if',
    cond: condRef,
    then: thenCtx.bindings,
    else: elseCtx.bindings,
  });
}

function lowerIndexAccess(
  expr: Extract<Expression, { kind: 'index_access' }>,
  ctx: LoweringContext,
): string {
  const objRef = lowerExprToRef(expr.object, ctx);
  const indexRef = lowerExprToRef(expr.index, ctx);

  // Index access is lowered as a call to an internal accessor function
  return ctx.emit({
    kind: 'call',
    func: '__array_access',
    args: [objRef, indexRef],
  });
}

function lowerIncrementExpr(
  expr: Extract<Expression, { kind: 'increment_expr' }>,
  ctx: LoweringContext,
): string {
  const operandRef = lowerExprToRef(expr.operand, ctx);
  const oneRef = ctx.emit({ kind: 'load_const', value: 1n });
  const result = ctx.emit({ kind: 'bin_op', op: '+', left: operandRef, right: oneRef });

  // If the operand is a named variable, update it
  if (expr.operand.kind === 'identifier') {
    ctx.emitNamed(expr.operand.name, { kind: 'load_const', value: `@ref:${result}` });
  }
  if (expr.operand.kind === 'property_access') {
    ctx.emit({ kind: 'update_prop', name: expr.operand.property, value: result });
  }

  // Prefix: return new value. Postfix: return original value.
  return expr.prefix ? result : operandRef;
}

function lowerDecrementExpr(
  expr: Extract<Expression, { kind: 'decrement_expr' }>,
  ctx: LoweringContext,
): string {
  const operandRef = lowerExprToRef(expr.operand, ctx);
  const oneRef = ctx.emit({ kind: 'load_const', value: 1n });
  const result = ctx.emit({ kind: 'bin_op', op: '-', left: operandRef, right: oneRef });

  // If the operand is a named variable, update it
  if (expr.operand.kind === 'identifier') {
    ctx.emitNamed(expr.operand.name, { kind: 'load_const', value: `@ref:${result}` });
  }
  if (expr.operand.kind === 'property_access') {
    ctx.emit({ kind: 'update_prop', name: expr.operand.property, value: result });
  }

  return expr.prefix ? result : operandRef;
}

// ---------------------------------------------------------------------------
// Type inference helpers for equality semantics
// ---------------------------------------------------------------------------

/** Byte-typed primitive names — values that are already byte sequences. */
const BYTE_TYPES = new Set([
  'ByteString', 'PubKey', 'Sig', 'Sha256', 'Ripemd160', 'Addr', 'SigHashPreimage', 'Point',
  'P256Point', 'P384Point',
]);

/** Builtin functions that return byte-typed values. */
const BYTE_RETURNING_FUNCTIONS = new Set([
  'sha256', 'ripemd160', 'hash160', 'hash256', 'cat', 'num2bin', 'int2str',
  'reverseBytes', 'substr', 'left', 'right',
  'ecAdd', 'ecMul', 'ecMulGen', 'ecNegate', 'ecMakePoint', 'ecEncodeCompressed',
  'p256Add', 'p256Mul', 'p256MulGen', 'p256Negate', 'p256EncodeCompressed',
  'p384Add', 'p384Mul', 'p384MulGen', 'p384Negate', 'p384EncodeCompressed',
  'extractOutpoint', 'extractHashPrevouts', 'extractHashSequence', 'extractOutputHash',
  'extractVersion', 'extractLocktime', 'extractSigHashType',
  'blake3Compress', 'blake3Hash',
]);

/**
 * Determine whether an expression is byte-typed (ByteString, PubKey, Sig, etc.).
 * This is a best-effort heuristic used to annotate equality operators.
 */
function isByteTypedExpr(expr: Expression, ctx: LoweringContext): boolean {
  switch (expr.kind) {
    case 'bytestring_literal':
      return true;

    case 'identifier': {
      // Check if it's a parameter or property with a byte type
      const paramType = ctx.getParamType(expr.name);
      if (paramType && BYTE_TYPES.has(paramType)) return true;
      const propType = ctx.getPropertyType(expr.name);
      if (propType && BYTE_TYPES.has(propType)) return true;
      // Check if it's a local variable known to be byte-typed
      if (ctx.isLocalByteVar(expr.name)) return true;
      return false;
    }

    case 'property_access': {
      // this.x — check the property type
      const propType = ctx.getPropertyType(expr.property);
      if (propType && BYTE_TYPES.has(propType)) return true;
      return false;
    }

    case 'member_expr': {
      if (expr.object.kind === 'identifier' && expr.object.name === 'this') {
        const propType = ctx.getPropertyType(expr.property);
        if (propType && BYTE_TYPES.has(propType)) return true;
      }
      return false;
    }

    case 'call_expr': {
      // sha256(x), hash160(x), etc.
      if (expr.callee.kind === 'identifier' && BYTE_RETURNING_FUNCTIONS.has(expr.callee.name)) {
        return true;
      }
      return false;
    }

    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function typeNodeToString(node: TypeNode): string {
  switch (node.kind) {
    case 'primitive_type':
      return node.name;
    case 'fixed_array_type':
      return `FixedArray<${typeNodeToString(node.element)}, ${node.length}>`;
    case 'custom_type':
      return node.name;
  }
}

// ---------------------------------------------------------------------------
// Post-ANF pass: lift update_prop from if-else branches
// ---------------------------------------------------------------------------
//
// Transforms if-else chains where each branch ends with update_prop into
// flat conditional assignments. This prevents phantom stack entries in
// stack lowering.
//
// Before:
//   if (pos === 0) { this.c0 = turn; }
//   else if (pos === 1) { this.c1 = turn; }
//   else { this.c4 = turn; }
//
// After:
//   this.c0 = (pos === 0) ? turn : this.c0;
//   this.c1 = (!cond0 && pos === 1) ? turn : this.c1;
//   this.c4 = (!cond0 && !cond1) ? turn : this.c4;

interface UpdateBranch {
  /** Bindings that compute this branch's condition (hoisted from nested else). */
  condSetupBindings: ANFBinding[];
  /** Temp holding this branch's local condition (null for final else). */
  condRef: string | null;
  /** Property being updated. */
  propName: string;
  /** Bindings that compute the new value (everything before update_prop in the branch). */
  valueBindings: ANFBinding[];
  /** Temp holding the new value (from the update_prop). */
  valueRef: string;
}

/**
 * An arm with its declared-results block removed.
 *
 * `appendBranchResults` adds exactly `2 * results.length` trailing bindings to
 * each arm of an `if` that declares results: K copies to `__merge$i` temps,
 * then K rebinds off those temps. Those bindings are a materialisation
 * mechanism, not program logic, and they hide the arm's real shape from this
 * pass — the second `update_prop` becomes the arm's last binding and the
 * original one lands in the "everything before must be side-effect free"
 * prefix, so the recogniser rejects the arm.
 *
 * That matters because a dispatch chain's DEEPEST `if` is nested by
 * definition, so it declares results, so its arms carry a block — and without
 * this the enclosing chain stops being recognised and TicTacToe's position
 * dispatch loses the C20 lift (an unspendable `move` script). Stripping by the
 * declared count is exact: the block's length is `results.length * 2` and it is
 * always the arm's tail.
 */
function stripDeclaredResults(
  bindings: ANFBinding[],
  results: string[] | undefined,
): ANFBinding[] {
  const n = results?.length ?? 0;
  if (n === 0) return bindings;
  return bindings.slice(0, Math.max(0, bindings.length - 2 * n));
}

/**
 * Recursively collect branches from a nested if-else chain where every
 * branch ends with exactly one update_prop.
 */
function collectUpdateBranches(
  ifCond: string,
  thenBindings: ANFBinding[],
  elseBindings: ANFBinding[],
): UpdateBranch[] | null {
  const thenUpdate = extractBranchUpdate(thenBindings);
  if (!thenUpdate) return null;

  const branches: UpdateBranch[] = [{
    condSetupBindings: [],
    condRef: ifCond,
    ...thenUpdate,
  }];

  if (elseBindings.length === 0) return null;

  // Check if else is another if (else-if chain)
  const lastElse = elseBindings[elseBindings.length - 1]!;
  if (lastElse.value.kind === 'if') {
    const innerIf = lastElse.value;
    const condSetup = elseBindings.slice(0, -1);
    if (!allBindingsSideEffectFree(condSetup)) return null;

    const innerBranches = collectUpdateBranches(
      innerIf.cond,
      stripDeclaredResults(innerIf.then, innerIf.results),
      stripDeclaredResults(innerIf.else, innerIf.results),
    );
    if (!innerBranches) return null;

    // Prepend condition setup to first inner branch
    innerBranches[0]!.condSetupBindings = [
      ...condSetup,
      ...innerBranches[0]!.condSetupBindings,
    ];
    branches.push(...innerBranches);
    return branches;
  }

  // Otherwise, else branch should end with update_prop (final else)
  const elseUpdate = extractBranchUpdate(elseBindings);
  if (elseUpdate) {
    branches.push({
      condSetupBindings: [],
      condRef: null,
      ...elseUpdate,
    });
    return branches;
  }

  // Handle unreachable else: assert(false) as the final else is dead code.
  // We can still transform the preceding branches — each branch's condition
  // fully guards its update, and the else path never executes.
  if (isAssertFalseElse(elseBindings)) {
    return branches;
  }

  return null;
}

function extractBranchUpdate(
  bindings: ANFBinding[],
): { propName: string; valueBindings: ANFBinding[]; valueRef: string } | null {
  if (bindings.length === 0) return null;
  const last = bindings[bindings.length - 1]!;
  if (last.value.kind !== 'update_prop') return null;
  const valueBindings = bindings.slice(0, -1);
  if (!allBindingsSideEffectFree(valueBindings)) return null;
  return {
    propName: last.value.name,
    valueRef: last.value.value,
    valueBindings,
  };
}

/**
 * Check if an else branch is just `assert(false)` — unreachable dead code
 * that acts as a safety net in position dispatch chains.
 */
function isAssertFalseElse(bindings: ANFBinding[]): boolean {
  if (bindings.length === 0) return false;
  const last = bindings[bindings.length - 1]!;
  if (last.value.kind !== 'assert') return false;

  // The assert's value should reference a binding that is load_const false
  const assertRef = last.value.value;
  const refBinding = bindings.find(b => b.name === assertRef);
  if (refBinding && refBinding.value.kind === 'load_const' && refBinding.value.value === false) {
    return true;
  }

  return false;
}

function allBindingsSideEffectFree(bindings: ANFBinding[]): boolean {
  return bindings.every(b => {
    const k = b.value.kind;
    return k === 'load_prop' || k === 'load_param' || k === 'load_const' ||
           k === 'bin_op' || k === 'unary_op';
  });
}

/**
 * Find the max temp index in a binding tree (e.g. t47 → 47).
 */
function maxTempIndex(bindings: ANFBinding[]): number {
  let max = -1;
  for (const b of bindings) {
    const m = b.name.match(/^t(\d+)$/);
    if (m) max = Math.max(max, parseInt(m[1]!));
    if (b.value.kind === 'if') {
      max = Math.max(max, maxTempIndex(b.value.then), maxTempIndex(b.value.else));
    } else if (b.value.kind === 'loop') {
      max = Math.max(max, maxTempIndex(b.value.body));
    }
  }
  return max;
}

/**
 * Remap temp references in an ANF value according to a name mapping.
 *
 * Exported for the F-003 regression test in `__tests__/unknown-anf-kind.test.ts`
 * which drives the dispatch with a synthetic ANF kind to verify it throws
 * `UnknownANFKindError` instead of silently dropping the binding.
 */
export function remapValueRefs(value: ANFValue, map: Record<string, string>): ANFValue {
  const r = (ref: string) => map[ref] || ref;
  switch (value.kind) {
    case 'load_param':
    case 'load_prop':
    case 'get_state_script':
      return value;
    case 'load_const': {
      if (typeof value.value === 'string' && value.value.startsWith('@ref:')) {
        const target = value.value.slice(5);
        const remapped = map[target];
        if (remapped) return { ...value, value: `@ref:${remapped}` };
      }
      return value;
    }
    case 'bin_op':
      return { ...value, left: r(value.left), right: r(value.right) };
    case 'unary_op':
      return { ...value, operand: r(value.operand) };
    case 'call':
      return { ...value, args: value.args.map(r) };
    case 'method_call':
      return { ...value, object: r(value.object), args: value.args.map(r) };
    case 'assert':
      return { ...value, value: r(value.value) };
    case 'update_prop':
      return { ...value, value: r(value.value) };
    case 'check_preimage':
      return { ...value, preimage: r(value.preimage) };
    case 'deserialize_state':
      return { ...value, preimage: r(value.preimage) };
    case 'add_output':
      return { ...value, satoshis: r(value.satoshis), stateValues: value.stateValues.map(r), preimage: r(value.preimage) };
    case 'add_raw_output':
      return { ...value, satoshis: r(value.satoshis), scriptBytes: r(value.scriptBytes) };
    case 'add_data_output':
      return { ...value, satoshis: r(value.satoshis), scriptBytes: r(value.scriptBytes) };
    case 'if':
      return { ...value, cond: r(value.cond) };
    case 'loop':
      return value;
    case 'array_literal':
      return { ...value, elements: value.elements.map(r) };
    case 'raw_script':
      // Opaque byte span — no SSA inputs to remap.
      return value;
    default: {
      const unknown = value as { kind: string };
      throw new UnknownANFKindError(unknown.kind, 'anf-lower.remapValueRefs');
    }
  }
}

/**
 * Walk a method body and transform if-bindings whose branches all end
 * with update_prop into flat conditional assignments.
 */
function liftBranchUpdateProps(bindings: ANFBinding[]): ANFBinding[] {
  let nextIdx = maxTempIndex(bindings) + 1;
  const fresh = () => `t${nextIdx++}`;

  const result: ANFBinding[] = [];

  for (const binding of bindings) {
    if (binding.value.kind !== 'if') {
      result.push(binding);
      continue;
    }

    const ifVal = binding.value;
    const branches = collectUpdateBranches(
      ifVal.cond,
      stripDeclaredResults(ifVal.then, ifVal.results),
      stripDeclaredResults(ifVal.else, ifVal.results),
    );

    if (!branches || branches.length < 2) {
      result.push(binding);
      continue;
    }

    // --- Transform: flatten into conditional assignments ---

    // 1. Hoist condition setup bindings with fresh names
    const nameMap: Record<string, string> = {};
    const condRefs: (string | null)[] = [];

    for (const branch of branches) {
      for (const csb of branch.condSetupBindings) {
        const newName = fresh();
        nameMap[csb.name] = newName;
        result.push({ name: newName, value: remapValueRefs(csb.value, nameMap) });
      }
      condRefs.push(
        branch.condRef
          ? (nameMap[branch.condRef] || branch.condRef)
          : null,
      );
    }

    // 2. Compute effective condition for each branch
    //    Branch 0: cond0
    //    Branch k>0: !cond0 && !cond1 && ... && !cond(k-1) && cond_k
    //    Final else: !cond0 && !cond1 && ... && !cond(N-2)
    const effectiveConds: string[] = [];
    const negatedConds: string[] = [];

    for (let i = 0; i < branches.length; i++) {
      if (i === 0) {
        effectiveConds.push(condRefs[0]!);
        continue;
      }

      // Negate any prior conditions not yet negated
      for (let j = negatedConds.length; j < i; j++) {
        if (condRefs[j] === null) continue;
        const negName = fresh();
        result.push({
          name: negName,
          value: { kind: 'unary_op', op: '!', operand: condRefs[j]! },
        });
        negatedConds.push(negName);
      }

      // AND all negated conditions together
      let andRef = negatedConds[0]!;
      for (let j = 1; j < Math.min(i, negatedConds.length); j++) {
        const andName = fresh();
        result.push({
          name: andName,
          value: { kind: 'bin_op', op: '&&', left: andRef, right: negatedConds[j]! },
        });
        andRef = andName;
      }

      if (condRefs[i] !== null) {
        // Middle branch: AND with own condition
        const finalName = fresh();
        result.push({
          name: finalName,
          value: { kind: 'bin_op', op: '&&', left: andRef, right: condRefs[i]! },
        });
        effectiveConds.push(finalName);
      } else {
        // Final else: just the AND of negations
        effectiveConds.push(andRef);
      }
    }

    // 2b. C20 — preserve a dropped terminal `assert(false)` else.
    //
    // `collectUpdateBranches` transforms a dispatch chain whose branches each
    // end in a single `update_prop` into this flat conditional-assignment form.
    // When the chain's terminal else is `assert(false)` it returns the branches
    // WITHOUT a catch-all final branch (every branch keeps a non-null condRef),
    // dropping the abort. But that assert(false) is the ONLY thing rejecting a
    // selector value that matches no branch: without it, an unmatched selector
    // leaves every property at its old value — a spendable NO-OP state
    // continuation instead of a failed script (a funds-safety bug).
    //
    // A real final else (`else { prop = ... }`) instead yields a catch-all
    // branch with condRef === null, and needs no guard because every selector
    // value maps to some branch. So the presence of a null-condRef terminal
    // branch exactly distinguishes the two cases.
    //
    // Re-introduce the abort as `assert(cond0 || cond1 || ... || cond_{N-1})`:
    // if no branch condition held, the OR is false and the script aborts —
    // byte-identical to the original `assert(false)` semantics for the
    // unmatched position, and a no-op (`assert(true)`) whenever a branch runs.
    const hasCatchAllElse = branches[branches.length - 1]!.condRef === null;
    if (!hasCatchAllElse) {
      // Every branch here has a non-null condRef (only a catch-all final else
      // is null, and there is none), so the OR fully covers the selector space.
      let orRef = condRefs[0]!;
      for (let i = 1; i < condRefs.length; i++) {
        const orName = fresh();
        result.push({
          name: orName,
          value: { kind: 'bin_op', op: '||', left: orRef, right: condRefs[i]! },
        });
        orRef = orName;
      }
      result.push({
        name: fresh(),
        value: { kind: 'assert', value: orRef },
      });
    }

    // 3. For each branch, emit: load_old, conditional if-expression, update_prop
    for (let i = 0; i < branches.length; i++) {
      const branch = branches[i]!;

      // Load old property value
      const oldPropRef = fresh();
      result.push({
        name: oldPropRef,
        value: { kind: 'load_prop', name: branch.propName },
      });

      // Remap value bindings for the then-branch
      const branchMap: Record<string, string> = { ...nameMap };
      const thenBindings: ANFBinding[] = [];
      for (const vb of branch.valueBindings) {
        const newName = fresh();
        branchMap[vb.name] = newName;
        thenBindings.push({
          name: newName,
          value: remapValueRefs(vb.value, branchMap),
        });
      }

      // Else branch: keep old property value
      const keepName = fresh();
      const elseBindings: ANFBinding[] = [
        { name: keepName, value: { kind: 'load_const', value: `@ref:${oldPropRef}` } },
      ];

      // Emit conditional if-expression
      const condIfRef = fresh();
      result.push({
        name: condIfRef,
        value: {
          kind: 'if',
          cond: effectiveConds[i]!,
          then: thenBindings,
          else: elseBindings,
        },
      });

      // Emit update_prop
      result.push({
        name: fresh(),
        value: { kind: 'update_prop', name: branch.propName, value: condIfRef },
      });
    }
  }

  return result;
}
