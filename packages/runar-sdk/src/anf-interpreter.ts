/**
 * Lightweight ANF interpreter for auto-computing state transitions.
 *
 * Given a compiled artifact's ANF IR, the current contract state, and
 * method arguments, this interpreter walks the ANF bindings and computes
 * the new state. It handles `update_prop` nodes to track state mutations,
 * while skipping on-chain-only operations like `check_preimage`,
 * `deserialize_state`, `get_state_script`, `add_output`, and `add_raw_output`.
 *
 * Three execution modes:
 *
 *  1. **Lenient** (`computeNewState`, `computeNewStateAndDataOutputs`) —
 *     skips `assert` predicates so the SDK can pre-compute the post-state
 *     even when arguments wouldn't actually pass the on-chain script. This
 *     is the canonical use: auto-deriving `newState` for the next call.
 *  2. **Strict** (`executeStrict`) — evaluates every `assert` predicate and
 *     throws `AssertionFailureError` (carrying the contract method + ANF
 *     binding name of the failing predicate) on the first false assert. Use
 *     for "will this call go through?" / "would the asserts hold" smoke
 *     tests off-chain before paying broadcast fees. Crypto built-ins
 *     (`checkSig`, `checkMultiSig`, `checkPreimage`) still mock-return
 *     `true` — only explicit `assert(...)` predicates are enforced.
 *  3. **On-chain authoritative** (`executeOnChainAuthoritative`) — strict
 *     assert enforcement PLUS real ECDSA / SHA-256 preimage verification
 *     against a caller-supplied `sighash`. The signature shape requires the
 *     caller to provide the sighash up front, so it is impossible to invoke
 *     this mode accidentally without the cryptographic inputs. Use this to
 *     validate the exact transaction the caller intends to broadcast: a
 *     `checkSig(sig, pk)` only passes if the supplied DER signature
 *     verifies against the supplied compressed public key over the
 *     supplied sighash, and `checkPreimage(preimage)` only passes if
 *     `SHA256(SHA256(preimage)) === sighash` (the canonical BIP-143
 *     `OP_PUSH_TX` semantic).
 */

import type {
  ANFProgram,
  ANFBinding,
  ANFValue,
} from 'runar-ir-schema';
import { Hash, Utils, PublicKey, Signature, BigNumber } from '@bsv/sdk';
// `verify` from @bsv/sdk's ECDSA module performs raw ECDSA verification
// against an already-hashed digest. We use this rather than
// `pubKey.verify(...)` (which internally sha256s its first arg) so the
// `sighash` passed by the caller is treated as the actual ECDSA digest,
// matching the on-chain CHECKSIG semantic where ECDSA verifies against
// the BIP-143 sighash directly with no extra hashing.
import { verify as ecdsaVerifyRaw } from '@bsv/sdk/primitives/ECDSA';
import { decodeScriptNumber } from './script-utils.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute the new state after executing a contract method.
 *
 * @param anf         The ANF IR from the compiled artifact.
 * @param methodName  The method to execute (must be a public method).
 * @param currentState  Current contract state (property name → value).
 * @param args        Method arguments (param name → value).
 * @param constructorArgs  Constructor arg values (declaration order) for readonly fields.
 * @returns The updated state (merged with currentState).
 */
export interface DataOutputEntry {
  satoshis: bigint | number;
  script: string;
}

/**
 * Raw outputs produced by `this.addRawOutput(satoshis, scriptBytes)` in the
 * method body. `script` is the **caller-supplied** locking-script bytes
 * (hex-encoded), in contrast to `DataOutputEntry.script`, which is the hex
 * payload that becomes part of an `OP_RETURN` data output. The simulator
 * cannot introspect these bytes — it surfaces them so a caller building
 * the broadcast transaction off-chain can splice them in at the correct
 * position. Entries appear in declaration order, after the state output
 * and after `dataOutputs`.
 */
export interface RawOutputEntry {
  satoshis: bigint | number;
  script: string;
}

/**
 * A single state-class output in the exact SOURCE order the method body emits
 * it, capturing the interleaving of `this.addOutput(...)` (state continuation)
 * and `this.addRawOutput(...)` (caller-supplied script). The compiler folds
 * these into the continuation `hashOutputs` in this same order (see
 * `packages/runar-compiler/src/passes/04-anf-lower.ts` — `add_output` and
 * `add_raw_output` share one `addOutputRefs` list), so a transaction builder
 * MUST emit them in this order or the on-chain state-check OP_VERIFY rejects
 * (finding G1). `script` is populated for `raw` entries only; `state` entries
 * take the freshly computed continuation locking script from the caller.
 * Data outputs (`add_data_output`) are NOT included here — they are always
 * emitted after every state-class output, in their own `dataOutputs` list.
 */
export interface OrderedOutputEntry {
  kind: 'state' | 'raw';
  satoshis: bigint;
  script?: string;
}

/**
 * The full result envelope produced by
 * {@link computeNewStateAndDataOutputs}, {@link executeStrict}, and
 * {@link executeOnChainAuthoritative}. All three modes return the same
 * shape; mode-specific behaviour only changes whether asserts and crypto
 * primitives are enforced or mocked, not what fields are populated.
 */
export interface ExecutionResult {
  state: Record<string, unknown>;
  dataOutputs: DataOutputEntry[];
  rawOutputs: RawOutputEntry[];
  /** State-class outputs (state continuation + raw) in source order. */
  outputs: OrderedOutputEntry[];
}

export function computeNewState(
  anf: ANFProgram,
  methodName: string,
  currentState: Record<string, unknown>,
  args: Record<string, unknown>,
  constructorArgs: unknown[] = [],
): Record<string, unknown> {
  return computeNewStateAndDataOutputs(
    anf, methodName, currentState, args, constructorArgs,
  ).state;
}

/**
 * Like {@link computeNewState} but also returns data outputs resolved
 * from `this.addDataOutput(...)` and raw outputs resolved from
 * `this.addRawOutput(...)` in the method body. Entries appear in
 * declaration order and are what `buildCallTransaction` should emit
 * between state outputs and the change output so the on-chain
 * continuation-hash check passes.
 */
export function computeNewStateAndDataOutputs(
  anf: ANFProgram,
  methodName: string,
  currentState: Record<string, unknown>,
  args: Record<string, unknown>,
  constructorArgs: unknown[] = [],
): ExecutionResult {
  return runMethod(anf, methodName, currentState, args, constructorArgs, null);
}

/**
 * Thrown by {@link executeStrict} on the first failing `assert` predicate.
 * Carries enough context to point a developer at the exact ANF binding
 * that aborted: the method being executed and the binding name (e.g.
 * `assertPositive` from the source `assert(amount > 0)`).
 */
export class AssertionFailureError extends Error {
  readonly methodName: string;
  readonly bindingName: string;
  constructor(methodName: string, bindingName: string) {
    super(
      `assert failed in ${methodName}: binding '${bindingName}' evaluated to false`,
    );
    this.name = 'AssertionFailureError';
    this.methodName = methodName;
    this.bindingName = bindingName;
  }
}

/**
 * Strict-mode counterpart to {@link computeNewStateAndDataOutputs}: walks
 * the same ANF body but throws {@link AssertionFailureError} on the first
 * `assert(predicate)` whose predicate evaluates to a falsy value. Use this
 * before broadcasting a transaction to surface guard failures off-chain
 * instead of relying on a node rejection. Crypto built-ins (`checkSig`,
 * `checkMultiSig`, `checkPreimage`) still mock-return `true` — strict mode
 * only enforces explicit `assert(...)` predicates.
 */
export function executeStrict(
  anf: ANFProgram,
  methodName: string,
  currentState: Record<string, unknown>,
  args: Record<string, unknown>,
  constructorArgs: unknown[] = [],
): ExecutionResult {
  return runMethod(anf, methodName, currentState, args, constructorArgs, {
    methodName,
  });
}

/**
 * Required cryptographic context for {@link executeOnChainAuthoritative}.
 *
 * `sighash` is the 32-byte BIP-143 sighash digest the on-chain VM would
 * verify signatures against (and that the caller would have signed with
 * `LocalSigner.sign(...)` before broadcasting). The interpreter:
 *
 *  - verifies `checkSig(sig, pk)` by parsing `pk` as a compressed/uncompressed
 *    secp256k1 point, parsing `sig` as DER (with optional trailing sighash byte
 *    stripped), and calling `pubKey.verify(sighash, signature)` — a real
 *    ECDSA verification. Any mismatch returns `false`, which then trips the
 *    enclosing `assert(...)` and throws.
 *  - verifies `checkMultiSig(sigs, pks)` by iterating signatures left-to-right
 *    and consuming pubkeys greedily, mirroring Bitcoin's `OP_CHECKMULTISIG`.
 *  - verifies `checkPreimage(preimage)` by computing `hash256(preimage)`
 *    (i.e. `SHA256(SHA256(preimage))`) and comparing it to `sighash`
 *    byte-for-byte — the on-chain `OP_PUSH_TX` semantic.
 */
export interface OnChainCryptoContext {
  /** 32-byte BIP-143 sighash, as a hex string or `Uint8Array`. */
  sighash: string | Uint8Array;
}

/**
 * Like {@link executeStrict} but also performs real cryptographic
 * verification of `checkSig`, `checkMultiSig`, and `checkPreimage` against
 * the supplied `sighash`. Throws {@link AssertionFailureError} when any
 * `assert(...)` (including the implicit one wrapping a failed crypto
 * built-in) fires.
 *
 * The `ctx` parameter is mandatory and carries the sighash, so it is
 * impossible to call this entry point accidentally without supplying the
 * cryptographic inputs the verification needs.
 */
export function executeOnChainAuthoritative(
  anf: ANFProgram,
  methodName: string,
  currentState: Record<string, unknown>,
  args: Record<string, unknown>,
  constructorArgs: unknown[],
  ctx: OnChainCryptoContext,
): ExecutionResult {
  const sighash = normalizeSighash(ctx.sighash);
  return runMethod(anf, methodName, currentState, args, constructorArgs, {
    methodName,
    realCrypto: { sighash },
  });
}

interface StrictCtx {
  methodName: string;
  /** When set, crypto built-ins verify against this 32-byte sighash. */
  realCrypto?: { sighash: number[] };
}

function normalizeSighash(sighash: string | Uint8Array): number[] {
  let bytes: number[];
  if (typeof sighash === 'string') {
    bytes = Utils.toArray(sighash, 'hex');
  } else {
    bytes = Array.from(sighash);
  }
  if (bytes.length !== 32) {
    throw new Error(
      `executeOnChainAuthoritative: sighash must be exactly 32 bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

function runMethod(
  anf: ANFProgram,
  methodName: string,
  currentState: Record<string, unknown>,
  args: Record<string, unknown>,
  constructorArgs: unknown[],
  strict: StrictCtx | null,
): ExecutionResult {
  // Find the method in ANF
  const method = anf.methods.find(
    (m) => m.name === methodName && m.isPublic,
  );
  if (!method) {
    throw new Error(
      `computeNewState: method '${methodName}' not found in ANF IR`,
    );
  }

  // Initialize the environment with property values and method params
  const env: Record<string, unknown> = {};

  // Load properties: mutable fields from currentState, readonly fields
  // from constructorArgs (matched by constructor param index, which excludes
  // initialized properties).
  // Build the constructor param index: position among non-initialized properties.
  const ctorParamNames = anf.properties
    .filter((p: { initialValue?: unknown }) => p.initialValue === undefined)
    .map((p: { name: string }) => p.name);
  for (const prop of anf.properties) {
    if (prop.name in currentState) {
      env[prop.name] = currentState[prop.name];
    } else if (prop.initialValue !== undefined) {
      env[prop.name] = prop.initialValue;
    } else {
      const ctorIdx = ctorParamNames.indexOf(prop.name);
      if (ctorIdx >= 0 && ctorIdx < constructorArgs.length) {
        env[prop.name] = constructorArgs[ctorIdx];
      }
    }
  }

  // Load method params (skip implicit ones injected by the compiler)
  const implicitParams = new Set([
    '_changePKH', '_changeAmount', '_newAmount', 'txPreimage',
  ]);
  for (const param of method.params) {
    if (implicitParams.has(param.name)) continue;
    if (param.name in args) {
      env[param.name] = args[param.name];
    }
  }

  // Track state mutations, data outputs, and raw outputs.
  // `rawOutputs` holds entries from `add_raw_output` ANF kinds, which the
  // simulator does NOT introspect (the script is caller-supplied). They
  // are surfaced in the result envelope so an off-chain transaction
  // builder can splice them in at the correct index.
  const stateDelta: Record<string, unknown> = {};
  const dataOutputs: DataOutputEntry[] = [];
  const rawOutputs: RawOutputEntry[] = [];
  // Ordered state-class outputs (state continuation + raw) in source order.
  const outputs: OrderedOutputEntry[] = [];

  // Walk bindings
  evalBindings(method.body, env, stateDelta, dataOutputs, rawOutputs, outputs, anf, strict);

  return { state: { ...currentState, ...stateDelta }, dataOutputs, rawOutputs, outputs };
}

// ---------------------------------------------------------------------------
// Binding evaluation
// ---------------------------------------------------------------------------

function evalBindings(
  bindings: ANFBinding[],
  env: Record<string, unknown>,
  stateDelta: Record<string, unknown>,
  dataOutputs: DataOutputEntry[],
  rawOutputs: RawOutputEntry[],
  outputs: OrderedOutputEntry[],
  anf?: ANFProgram,
  strict: StrictCtx | null = null,
  // Per-binding raw stack bytes for byte-array-op results (& | ^ << >> ~). Keyed
  // by binding name; lets a chained op read the real (possibly non-minimal)
  // length of a prior op's result instead of re-minimizing its numeric value.
  // `env` stays pure (decoded values) so state serialization is unaffected.
  scriptBytes: Record<string, number[]> = {},
): void {
  for (const binding of bindings) {
    const val = evalValue(
      binding.value, env, stateDelta, dataOutputs, rawOutputs, outputs, anf, strict, binding.name, scriptBytes,
    );
    env[binding.name] = val;
  }
}

function evalValue(
  value: ANFValue,
  env: Record<string, unknown>,
  stateDelta: Record<string, unknown>,
  dataOutputs: DataOutputEntry[],
  rawOutputs: RawOutputEntry[],
  outputs: OrderedOutputEntry[],
  anf?: ANFProgram,
  strict: StrictCtx | null = null,
  bindingName: string = '<anonymous>',
  scriptBytes: Record<string, number[]> = {},
): unknown {
  switch (value.kind) {
    case 'load_param':
      return env[value.name];

    case 'load_prop':
      return env[value.name];

    case 'load_const': {
      const v = value.value;
      // Handle @ref: aliases (load_const with "@ref:targetName")
      if (typeof v === 'string' && v.startsWith('@ref:')) {
        const target = v.slice(5);
        aliasScriptBytes(scriptBytes, target, bindingName);
        return env[target];
      }
      // On-disk ANF spells every bigint as a `"<decimal>n"` STRING (see
      // `jsonWithBigInt` in runar-cli's compile command) — that is the artifact
      // every SDK loads with a bare `JSON.parse`. Decode it here so a const
      // operand is a `bigint`, not a `string`: the byte-op paths below gate on
      // `typeof !== 'string'`, so leaving it a string silently routes `<< >> &
      // | ^ ~` down the ByteString branch and the SDK builds a continuation the
      // deployed script disagrees with (NEW-008). Go / Rust / Zig already
      // decode this shape; this makes all seven agree with the script.
      //
      // Unambiguous: ANF ByteString literals are hex and `n` is not a hex
      // digit, so `^-?\d+n$` cannot be a bytestring.
      if (typeof v === 'string' && /^-?\d+n$/.test(v)) {
        return BigInt(v.slice(0, -1));
      }
      return v;
    }

    case 'bin_op': {
      // Numeric byte-array ops (& | ^ << >>) thread the operands' real stack
      // bytes so chained expressions match the deployed script (a shift/bitwise
      // result can be non-minimal; the next length-sensitive op must see that).
      // ByteString ops (result_type 'bytes' / string operands) fall through to
      // evalBinOp, which keeps the minimal-operand path for everything else.
      const isNumericByteOp =
        (value.op === '&' || value.op === '|' || value.op === '^' ||
          value.op === '<<' || value.op === '>>') &&
        value.result_type !== 'bytes' &&
        typeof env[value.left] !== 'string' &&
        typeof env[value.right] !== 'string';
      if (isNumericByteOp) {
        const ab = scriptBytes[value.left] ?? minimalScriptNumberBytes(toBigInt(env[value.left]));
        let rb: number[];
        if (value.op === '<<' || value.op === '>>') {
          // Shift count is read as a number on-chain — only `ab`'s length matters.
          rb = scriptNumberShiftBytes(value.op, ab, toBigInt(env[value.right]));
        } else {
          const bb = scriptBytes[value.right] ?? minimalScriptNumberBytes(toBigInt(env[value.right]));
          rb = scriptNumberBitwiseBytes(value.op as '&' | '|' | '^', ab, bb);
        }
        scriptBytes[bindingName] = rb;
        return decodeScriptNumber(Utils.toHex(rb));
      }
      // NUMERIC consumption: a node decodes with fRequireMinimal=true and
      // ABORTS on a non-minimal operand. Only the byte-array ops above may
      // take one. `&& !isNumericByteOp` is implicit — we only reach here when
      // the op is not one of them.
      assertMinimalNumericOperand(scriptBytes[value.left], env[value.left], value.op);
      assertMinimalNumericOperand(scriptBytes[value.right], env[value.right], value.op);
      return evalBinOp(
        value.op,
        env[value.left],
        env[value.right],
        value.result_type,
      );
    }

    case 'unary_op': {
      if (value.op === '~' && value.result_type !== 'bytes' && typeof env[value.operand] !== 'string') {
        const ab = scriptBytes[value.operand] ?? minimalScriptNumberBytes(toBigInt(env[value.operand]));
        const rb = scriptNumberInvertBytes(ab);
        scriptBytes[bindingName] = rb;
        return decodeScriptNumber(Utils.toHex(rb));
      }
      assertMinimalNumericOperand(scriptBytes[value.operand], env[value.operand], value.op);
      return evalUnaryOp(value.op, env[value.operand], value.result_type);
    }

    case 'call': {
      // Strict mode: a `call(assert, x)` lowering path must enforce the
      // predicate the same way the dedicated `assert` ANF node does.
      if (strict && value.func === 'assert') {
        const arg = env[value.args[0] ?? ''];
        if (!isTruthy(arg)) {
          throw new AssertionFailureError(strict.methodName, bindingName);
        }
        return undefined;
      }
      return evalCall(
        value.func,
        value.args.map((a) => env[a]),
        strict?.realCrypto,
      );
    }

    case 'method_call':
      return evalMethodCall(
        env,
        value.method,
        value.args.map((a: string) => env[a]),
        stateDelta,
        dataOutputs,
        rawOutputs,
        outputs,
        anf,
      );

    case 'if': {
      const cond = env[value.cond];
      const branch = isTruthy(cond) ? value.then : value.else;
      // Create a child env for the branch
      const childEnv = { ...env };
      evalBindings(branch, childEnv, stateDelta, dataOutputs, rawOutputs, outputs, anf, strict, scriptBytes);
      // Copy any new bindings back (the last binding is typically the branch result)
      Object.assign(env, childEnv);
      // Return the last binding's value from the branch
      if (branch.length > 0) {
        const lastName = branch[branch.length - 1]!.name;
        aliasScriptBytes(scriptBytes, lastName, bindingName);
        return childEnv[lastName];
      }
      return undefined;
    }

    case 'loop': {
      const { count, body, iterVar } = value;
      // Iteration `i` binds `iterVar = start + i*step` (issue #121). Older ANF
      // payloads without start/step describe zero-start counting-up loops.
      const start = (value as { start?: bigint }).start ?? 0n;
      const step = BigInt((value as { step?: number }).step ?? 1);
      let lastVal: unknown;
      for (let i = 0; i < count; i++) {
        env[iterVar] = start + BigInt(i) * step;
        const loopEnv = { ...env };
        evalBindings(body, loopEnv, stateDelta, dataOutputs, rawOutputs, outputs, anf, strict, scriptBytes);
        // Copy loop bindings back
        Object.assign(env, loopEnv);
        if (body.length > 0) {
          const lastName = body[body.length - 1]!.name;
          aliasScriptBytes(scriptBytes, lastName, bindingName);
          lastVal = loopEnv[lastName];
        }
      }
      return lastVal;
    }

    case 'assert': {
      if (strict) {
        // Marker-based skip: the auto-injected stateful-continuation
        // `assert(hash256(_) === extractOutputHash(_))` carries
        // `isAutoInjectedStateCheck: true` (set in
        // `packages/runar-compiler/src/passes/04-anf-lower.ts`). The
        // on-chain VM is authoritative for that check; off-chain we
        // have no realistic continuation hash. Developer-written
        // covenant asserts with the identical IR shape carry no
        // marker and ARE enforced (see BUG-002).
        if ((value as { isAutoInjectedStateCheck?: boolean }).isAutoInjectedStateCheck === true) {
          return undefined;
        }
        const predicate = env[value.value];
        if (!isTruthy(predicate)) {
          throw new AssertionFailureError(strict.methodName, bindingName);
        }
      }
      // Lenient: skip asserts (the on-chain script handles enforcement)
      return undefined;
    }

    case 'update_prop': {
      const newVal = env[value.value];
      env[value.name] = newVal;
      stateDelta[value.name] = newVal;
      return undefined;
    }

    case 'add_output': {
      // Extract implicit state changes from stateValues array.
      // stateValues[i] maps to the i-th mutable property (declaration order).
      if (anf && value.stateValues && value.stateValues.length > 0) {
        const mutableProps = anf.properties.filter((p) => !p.readonly);
        for (let i = 0; i < value.stateValues.length && i < mutableProps.length; i++) {
          const propName = mutableProps[i]!.name;
          const ref = value.stateValues[i]!;
          const newVal = env[ref];
          env[propName] = newVal;
          stateDelta[propName] = newVal;
        }
      }
      // Record the state continuation output in source order (finding G1): a
      // method may interleave raw outputs around it, and the on-chain covenant
      // folds them into hashOutputs in exactly this order.
      outputs.push({ kind: 'state', satoshis: toBigInt(env[value.satoshis]) });
      return undefined;
    }

    case 'add_data_output': {
      // Resolve the two arg refs from env and record the data output.
      const sats = toBigInt(env[value.satoshis]);
      const script = env[value.scriptBytes];
      dataOutputs.push({
        satoshis: sats,
        script: typeof script === 'string' ? script : '',
      });
      return undefined;
    }

    case 'add_raw_output': {
      // `addRawOutput(satoshis, scriptBytes)`. The simulator does not
      // introspect the script bytes (they're caller-supplied raw locking
      // script); it simply forwards them in the result envelope so an
      // off-chain transaction builder can emit the output at the correct
      // index. Crypto built-ins remain mocked even in strict mode.
      const sats = toBigInt(env[value.satoshis]);
      const script = env[value.scriptBytes];
      rawOutputs.push({
        satoshis: sats,
        script: typeof script === 'string' ? script : '',
      });
      // Also record in the ordered state-class output list so a transaction
      // builder can emit it at the correct source-order index (finding G1).
      outputs.push({
        kind: 'raw',
        satoshis: sats,
        script: typeof script === 'string' ? script : '',
      });
      return undefined;
    }

    // On-chain-only operations — skip in simulation. These ANF kinds are
    // markers consumed by the codegen, not by the off-chain interpreter.
    case 'check_preimage':
    case 'deserialize_state':
    case 'get_state_script':
      return undefined;

    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// Script-number bitwise / shift semantics (byte-array ops, NOT numeric)
// ---------------------------------------------------------------------------
//
// OP_AND/OP_OR/OP_XOR/OP_INVERT/OP_LSHIFT/OP_RSHIFT operate on the RAW BYTES
// of the operands' minimal script-number encoding, not on their numeric
// value (spec/opcodes.md). AND/OR/XOR require equal-length operands and
// fail otherwise; shifts treat the byte array as a big-endian bit string
// and preserve its length. This reproduces EXACTLY what
// packages/runar-testing/src/vm/utils.ts's
// scriptNumberBitwise/scriptNumberInvert/scriptNumberShift do, so the SDK's
// off-chain state derivation agrees with the deployed script byte-for-byte.
// runar-sdk does not depend on runar-testing, so this is a local port using
// this package's own script-number decoder (`decodeScriptNumber` from
// ./script-utils.js). Note: `encodeScriptNumber` in ./contract.js is NOT
// reusable here — it returns the full *script push* encoding (with
// OP_0/OP_1..OP_16/OP_1NEGATE shortcuts), not the raw minimal bytes the
// bitwise/shift opcodes operate on, so `minimalScriptNumberBytes` below
// re-derives just the raw-byte core of that algorithm.

/** Minimal sign-magnitude bytes of a script-number-valued bigint
 *  (little-endian, no push-opcode wrapping). */
/**
 * Mirror the on-chain minimal-encoding rule for a NUMERIC operand.
 *
 * Only values produced by the byte-array ops carry threaded `scriptBytes`, and
 * only those can be non-minimal (`1 >> 1` is `[0x00]`, whose minimal encoding
 * is EMPTY). Everything else is minimal by construction, so this is a no-op.
 *
 * Without it this interpreter re-minimises such a value and reports a spend
 * valid that the deployed covenant aborts on — and since
 * `RunarContract.prepareCall` uses this interpreter to compute the
 * continuation state, it would build a broadcast against a state no node
 * accepts.
 */
function assertMinimalNumericOperand(
  bytes: number[] | undefined,
  value: unknown,
  op: string,
): void {
  if (bytes === undefined || typeof value !== 'bigint') return;
  const minimal = minimalScriptNumberBytes(value);
  if (bytes.length === minimal.length && bytes.every((b, i) => b === minimal[i])) return;
  throw new Error(
    `non-minimally encoded script number consumed by '${op}': stack bytes [` +
      bytes.map((b) => b.toString(16).padStart(2, '0')).join(' ') +
      `] decode to ${value}, whose minimal encoding is [` +
      minimal.map((b) => b.toString(16).padStart(2, '0')).join(' ') +
      `]. A node aborts here.`,
  );
}

function minimalScriptNumberBytes(n: bigint): number[] {
  if (n === 0n) return [];
  const negative = n < 0n;
  let abs = negative ? -n : n;
  const bytes: number[] = [];
  while (abs > 0n) {
    bytes.push(Number(abs & 0xffn));
    abs >>= 8n;
  }
  const last = bytes[bytes.length - 1]!;
  if (last & 0x80) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1] = last | 0x80;
  }
  return bytes;
}

// The *Bytes helpers operate on RAW stack bytes (the exact byte array a value
// would occupy on the deployed script's stack), NOT a value's minimal encoding.
// This matters for CHAINED expressions: a shift/bitwise RESULT can be a
// non-minimal byte array (e.g. `2 << 8` leaves a 1-byte 0x00), and feeding it to
// a length-sensitive `& | ^`/shift must see that real length to agree with the
// deployed script. The interpreter threads these bytes via a per-binding side
// map (see `evalBindings`); values from other sources are minimal on-chain.

/**
 * Carry a binding's raw stack bytes across an ALIAS — a binding whose value IS
 * another binding's slot: the `load_const "@ref:<name>"` every local rebind
 * lowers to, an `if` adopting its taken arm's last value, a `loop` adopting its
 * body's. Without this, a chained length-sensitive op re-minimises the aliased
 * value and disagrees with the deployed script (NEW-006: `(4n ^ 4n)` is a
 * 1-byte `0x00` on the stack but `[]` when re-minimised from `0n`).
 *
 * Mirrors `05-stack-lower.ts`, which carries its `rawSlots` marker across the
 * same two constructs.
 *
 * CLEARS when the source has no entry: the alias target is a freshly pushed,
 * minimal value, so a stale entry left by an earlier binding of the SAME name
 * (`let m0 = 4n ^ 4n; m0 = 300n;`) would otherwise be read as this slot's width.
 */
function aliasScriptBytes(
  scriptBytes: Record<string, number[]>,
  from: string,
  to: string,
): void {
  const bytes = scriptBytes[from];
  if (bytes !== undefined) {
    scriptBytes[to] = bytes;
  } else {
    delete scriptBytes[to];
  }
}

/** OP_AND/OP_OR/OP_XOR on raw stack bytes. Throws on length mismatch. */
function scriptNumberBitwiseBytes(op: '&' | '|' | '^', av: number[], bv: number[]): number[] {
  if (av.length !== bv.length) {
    const name = op === '&' ? 'OP_AND' : op === '|' ? 'OP_OR' : 'OP_XOR';
    throw new Error(`${name}: operands must be same length`);
  }
  const result: number[] = new Array(av.length);
  for (let i = 0; i < av.length; i++) {
    const x = av[i]!;
    const y = bv[i]!;
    result[i] = op === '&' ? x & y : op === '|' ? x | y : x ^ y;
  }
  return result;
}

/** OP_INVERT: flip every bit of the operand's raw stack bytes (length-preserving). */
function scriptNumberInvertBytes(av: number[]): number[] {
  return av.map((b) => ~b & 0xff);
}

/** OP_LSHIFT/OP_RSHIFT on raw stack bytes as a big-endian bit string, preserving
 *  byte length. `shift` is the numeric shift count (read as a number on-chain,
 *  so only `val`'s bytes are length-significant). Negative shifts fail. */
function scriptNumberShiftBytes(op: '<<' | '>>', val: number[], shift: bigint): number[] {
  if (shift < 0n) {
    throw new Error(op === '<<' ? 'OP_LSHIFT: negative shift' : 'OP_RSHIFT: negative shift');
  }
  const n = Number(shift);
  if (val.length === 0 || n === 0) return val.slice();
  let num = 0n;
  for (let i = 0; i < val.length; i++) num = (num << 8n) | BigInt(val[i]!);
  if (op === '<<') {
    const bitLen = BigInt(val.length * 8);
    num = (num << BigInt(n)) & ((1n << bitLen) - 1n);
  } else {
    num >>= BigInt(n);
  }
  const result: number[] = new Array(val.length);
  for (let i = val.length - 1; i >= 0; i--) {
    result[i] = Number(num & 0xffn);
    num >>= 8n;
  }
  return result;
}

// bigint -> bigint wrappers (minimal operands) — used by the single-op
// truth-table tests. The interpreter uses the *Bytes helpers directly so it can
// thread non-minimal chained intermediates via the side map.
function scriptNumberBitwise(op: '&' | '|' | '^', a: bigint, b: bigint): bigint {
  return decodeScriptNumber(Utils.toHex(scriptNumberBitwiseBytes(op, minimalScriptNumberBytes(a), minimalScriptNumberBytes(b))));
}

function scriptNumberInvert(a: bigint): bigint {
  return decodeScriptNumber(Utils.toHex(scriptNumberInvertBytes(minimalScriptNumberBytes(a))));
}

function scriptNumberShift(op: '<<' | '>>', a: bigint, shift: bigint): bigint {
  return decodeScriptNumber(Utils.toHex(scriptNumberShiftBytes(op, minimalScriptNumberBytes(a), shift)));
}

// ---------------------------------------------------------------------------
// Binary operations
// ---------------------------------------------------------------------------

function evalBinOp(
  op: string,
  left: unknown,
  right: unknown,
  resultType?: string,
): unknown {
  if (resultType === 'bytes' || (typeof left === 'string' && typeof right === 'string')) {
    return evalBytesBinOp(op, String(left ?? ''), String(right ?? ''));
  }

  const l = toBigInt(left);
  const r = toBigInt(right);

  switch (op) {
    case '+': return l + r;
    case '-': return l - r;
    case '*': return l * r;
    case '/': return r === 0n ? 0n : l / r;
    case '%': return r === 0n ? 0n : l % r;
    case '==': case '===': return l === r;
    case '!=': case '!==': return l !== r;
    case '<': return l < r;
    case '<=': return l <= r;
    case '>': return l > r;
    case '>=': return l >= r;
    case '&&': return isTruthy(left) && isTruthy(right);
    case '||': return isTruthy(left) || isTruthy(right);
    case '&': return scriptNumberBitwise('&', l, r);
    case '|': return scriptNumberBitwise('|', l, r);
    case '^': return scriptNumberBitwise('^', l, r);
    case '<<': return scriptNumberShift('<<', l, r);
    case '>>': return scriptNumberShift('>>', l, r);
    default: return 0n;
  }
}

function evalBytesBinOp(op: string, left: string, right: string): unknown {
  switch (op) {
    case '+':  // cat
      return left + right;
    case '==': case '===':
      return left === right;
    case '!=': case '!==':
      return left !== right;
    default:
      return '';
  }
}

// ---------------------------------------------------------------------------
// Unary operations
// ---------------------------------------------------------------------------

function evalUnaryOp(op: string, operand: unknown, resultType?: string): unknown {
  if (resultType === 'bytes') {
    // Bitwise NOT on bytes
    if (op === '~') {
      const hex = String(operand ?? '');
      const bytes = Utils.toArray(hex, 'hex');
      for (let i = 0; i < bytes.length; i++) bytes[i] = ~bytes[i]! & 0xff;
      return Utils.toHex(bytes);
    }
    return operand;
  }

  const val = toBigInt(operand);
  switch (op) {
    case '-': return -val;
    case '!': return !isTruthy(operand);
    case '~': return scriptNumberInvert(val);
    default: return val;
  }
}

// ---------------------------------------------------------------------------
// Built-in function calls
// ---------------------------------------------------------------------------

function evalCall(
  func: string,
  args: unknown[],
  realCrypto?: { sighash: number[] },
): unknown {
  switch (func) {
    // Crypto — mocked unless real-crypto context is present.
    case 'checkSig': {
      if (!realCrypto) return true;
      return verifyEcdsa(args[0], args[1], realCrypto.sighash);
    }
    case 'checkMultiSig': {
      if (!realCrypto) return true;
      return verifyMultiSig(args[0], args[1], realCrypto.sighash);
    }
    case 'checkPreimage': {
      if (!realCrypto) return true;
      return verifyPreimage(args[0], realCrypto.sighash);
    }

    // Crypto — real hashes
    case 'sha256': return hashFn('sha256', args[0]);
    case 'hash256': return hashFn('hash256', args[0]);
    case 'hash160': return hashFn('hash160', args[0]);
    case 'ripemd160': return hashFn('ripemd160', args[0]);

    // Assert — skip (on-chain handles it)
    case 'assert': return undefined;

    // Byte operations
    case 'num2bin': {
      const n = toBigInt(args[0]);
      const len = Number(toBigInt(args[1]));
      return num2binHex(n, len);
    }
    case 'bin2num': {
      return bin2numBigInt(String(args[0] ?? ''));
    }
    case 'cat': {
      return String(args[0] ?? '') + String(args[1] ?? '');
    }
    case 'substr': {
      const hex = String(args[0] ?? '');
      const start = Number(toBigInt(args[1]));
      const len = Number(toBigInt(args[2]));
      return hex.slice(start * 2, (start + len) * 2);
    }
    case 'reverseBytes': {
      const hex = String(args[0] ?? '');
      const pairs: string[] = [];
      for (let i = 0; i < hex.length; i += 2) pairs.push(hex.slice(i, i + 2));
      return pairs.reverse().join('');
    }
    case 'len': {
      const hex = String(args[0] ?? '');
      return BigInt(hex.length / 2);
    }

    // Math builtins
    case 'abs': return toBigInt(args[0]) < 0n ? -toBigInt(args[0]) : toBigInt(args[0]);
    case 'min': return toBigInt(args[0]) < toBigInt(args[1]) ? toBigInt(args[0]) : toBigInt(args[1]);
    case 'max': return toBigInt(args[0]) > toBigInt(args[1]) ? toBigInt(args[0]) : toBigInt(args[1]);
    case 'within': {
      const x = toBigInt(args[0]);
      return x >= toBigInt(args[1]) && x < toBigInt(args[2]);
    }
    case 'safediv': {
      const d = toBigInt(args[1]);
      return d === 0n ? 0n : toBigInt(args[0]) / d;
    }
    case 'safemod': {
      const d = toBigInt(args[1]);
      return d === 0n ? 0n : toBigInt(args[0]) % d;
    }
    case 'clamp': {
      const v = toBigInt(args[0]);
      const lo = toBigInt(args[1]);
      const hi = toBigInt(args[2]);
      return v < lo ? lo : v > hi ? hi : v;
    }
    case 'sign': {
      const v = toBigInt(args[0]);
      return v > 0n ? 1n : v < 0n ? -1n : 0n;
    }
    case 'pow': {
      const base = toBigInt(args[0]);
      const exp = toBigInt(args[1]);
      if (exp < 0n) return 0n;
      let result = 1n;
      for (let i = 0n; i < exp; i++) result *= base;
      return result;
    }
    case 'sqrt': {
      const v = toBigInt(args[0]);
      if (v <= 0n) return 0n;
      let x = v;
      let y = (x + 1n) / 2n;
      while (y < x) { x = y; y = (x + v / x) / 2n; }
      return x;
    }
    case 'gcd': {
      let a = toBigInt(args[0]);
      let b = toBigInt(args[1]);
      if (a < 0n) a = -a;
      if (b < 0n) b = -b;
      while (b !== 0n) { const t = b; b = a % b; a = t; }
      return a;
    }
    case 'divmod': {
      const a = toBigInt(args[0]);
      const b = toBigInt(args[1]);
      if (b === 0n) return 0n;
      // Returns quotient; in ANF the second result is in a separate binding
      return a / b;
    }
    case 'log2': {
      const v = toBigInt(args[0]);
      if (v <= 0n) return 0n;
      let bits = 0n;
      let x = v;
      while (x > 1n) { x >>= 1n; bits++; }
      return bits;
    }
    case 'bool': return isTruthy(args[0]) ? 1n : 0n;
    case 'mulDiv': {
      return (toBigInt(args[0]) * toBigInt(args[1])) / toBigInt(args[2]);
    }
    case 'percentOf': {
      return (toBigInt(args[0]) * toBigInt(args[1])) / 10000n;
    }

    // Preimage intrinsics — return dummy values in simulation
    case 'extractOutputHash':
    case 'extractAmount':
      return '00'.repeat(32);
    case 'extractLocktime':
      return 0n;

    default:
      return undefined;
  }
}

function evalMethodCall(
  callerEnv: Record<string, unknown>,
  methodName: string,
  args: unknown[],
  stateDelta: Record<string, unknown>,
  dataOutputs: DataOutputEntry[],
  rawOutputs: RawOutputEntry[],
  outputs: OrderedOutputEntry[],
  anf?: ANFProgram,
): unknown {
  // Private method calls appear in the ANF with their bodies available
  // in anf.methods. Execute the method body to compute its return value.
  if (anf) {
    const method = anf.methods.find(
      (m) => m.name === methodName && !m.isPublic,
    );
    if (method) {
      // Build env for the private method: copy property values for load_prop
      const methodEnv: Record<string, unknown> = {};
      for (const prop of anf.properties) {
        if (prop.name in callerEnv) {
          methodEnv[prop.name] = callerEnv[prop.name];
        }
      }

      // Map method params to passed args
      for (let i = 0; i < method.params.length && i < args.length; i++) {
        methodEnv[method.params[i]!.name] = args[i];
      }

      // Execute the method body — pass real stateDelta so update_prop
      // mutations in private methods are captured
      evalBindings(method.body, methodEnv, stateDelta, dataOutputs, rawOutputs, outputs, anf);

      // Propagate property changes back to the caller's env
      for (const prop of anf.properties) {
        if (prop.name in methodEnv) {
          callerEnv[prop.name] = methodEnv[prop.name];
        }
      }

      // Return the last binding's value (the method's return value)
      if (method.body.length > 0) {
        return methodEnv[method.body[method.body.length - 1]!.name];
      }
      return undefined;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

function hashFn(
  name: 'sha256' | 'hash256' | 'hash160' | 'ripemd160',
  input: unknown,
): string {
  const hex = String(input ?? '');
  const bytes = Utils.toArray(hex, 'hex');
  let result: number[];
  switch (name) {
    case 'sha256': result = Hash.sha256(bytes); break;
    case 'hash256': result = Hash.hash256(bytes); break;
    case 'hash160': result = Hash.hash160(bytes); break;
    case 'ripemd160': result = Hash.ripemd160(bytes); break;
  }
  return Utils.toHex(result);
}

// ---------------------------------------------------------------------------
// Numeric helpers
// ---------------------------------------------------------------------------

function toBigInt(v: unknown): bigint {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(v);
  if (typeof v === 'boolean') return v ? 1n : 0n;
  if (typeof v === 'string') {
    // Handle "42n" format from JSON
    if (/^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    // Handle plain numeric strings
    if (/^-?\d+$/.test(v)) return BigInt(v);
    return 0n;
  }
  return 0n;
}

function isTruthy(v: unknown): boolean {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'bigint') return v !== 0n;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'string') return v !== '' && v !== '0' && v !== 'false';
  return false;
}

// ---------------------------------------------------------------------------
// Byte encoding helpers
// ---------------------------------------------------------------------------

/**
 * `num2bin(n, byteLen)` — exactly what OP_NUM2BIN computes (NEW-013).
 *
 * The order of the two steps below is load-bearing. This function used to set
 * the sign bit on the last MAGNITUDE byte and pad zeros AFTER it, so
 * `num2bin(-1n, 2n)` produced `8100` while the script produces `0180`. The
 * result is the bytes the SDK puts in the call transaction, so the wrong order
 * built continuations the deployed script rejects — and six of the seven SDKs
 * shared the mistake, which is why tier-vs-tier parity never caught it.
 *
 * The engine (`@bsv/sdk` `Spend`, and BSV consensus) pads FIRST and then puts
 * the sign bit on the new most-significant byte.
 */
function num2binHex(n: bigint, byteLen: number): string {
  // 1. Minimal BSV script-number encoding: little-endian magnitude with the
  //    sign in bit 7 of the top byte, growing one byte when magnitude data
  //    already occupies that bit.
  const negative = n < 0n;
  let abs = negative ? -n : n;

  const bytes: number[] = [];
  while (abs > 0n) {
    bytes.push(Number(abs & 0xffn));
    abs >>= 8n;
  }
  if (bytes.length > 0) {
    if ((bytes[bytes.length - 1]! & 0x80) !== 0) {
      bytes.push(negative ? 0x80 : 0x00);
    } else if (negative) {
      bytes[bytes.length - 1]! |= 0x80;
    }
  }

  // 2a. Field too narrow for the value: OP_NUM2BIN rejects this outright
  //     ("impossible encoding"). The interpreter keeps its historical
  //     truncation rather than growing a new failure mode here; an equal-length
  //     encoding is already final and needs no sign-bit move.
  if (bytes.length >= byteLen) {
    return bytes
      .slice(0, byteLen)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // 2b. Padded: lift the sign bit off the magnitude, zero-extend, and re-apply
  //     it to the byte that is now most significant.
  let signBit = 0;
  if (bytes.length > 0) {
    signBit = bytes[bytes.length - 1]! & 0x80;
    bytes[bytes.length - 1]! &= 0x7f;
  }
  while (bytes.length < byteLen) bytes.push(0x00);
  if (signBit !== 0) bytes[byteLen - 1]! |= 0x80;

  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Real ECDSA / preimage verification (used by executeOnChainAuthoritative)
// ---------------------------------------------------------------------------

function toByteArray(v: unknown): number[] | null {
  if (typeof v === 'string') {
    if (v.length % 2 !== 0) return null;
    if (!/^[0-9a-fA-F]*$/.test(v)) return null;
    return Utils.toArray(v, 'hex');
  }
  if (v instanceof Uint8Array) return Array.from(v);
  if (Array.isArray(v)) return v as number[];
  return null;
}

function parseDerSignatureMaybeWithSighashByte(bytes: number[]): InstanceType<typeof Signature> | null {
  if (bytes.length < 8 || bytes[0] !== 0x30) return null;
  const declared = bytes[1]!;
  const expected = declared + 2;
  let pure: number[];
  if (bytes.length === expected) {
    pure = bytes;
  } else if (bytes.length === expected + 1) {
    // Drop trailing sighash type byte (e.g. 0x41 SIGHASH_ALL|FORKID).
    pure = bytes.slice(0, expected);
  } else {
    pure = bytes;
  }
  try {
    return Signature.fromDER(pure);
  } catch {
    return null;
  }
}

function verifyEcdsa(
  sigVal: unknown,
  pkVal: unknown,
  sighash: number[],
): boolean {
  const sigBytes = toByteArray(sigVal);
  const pkBytes = toByteArray(pkVal);
  if (!sigBytes || !pkBytes) return false;
  try {
    const pubKey = PublicKey.fromDER(pkBytes);
    const sig = parseDerSignatureMaybeWithSighashByte(sigBytes);
    if (!sig) return false;
    // Raw ECDSA verify: treat `sighash` as the message digest directly,
    // matching the on-chain CHECKSIG semantic (and the cross-tier real-
    // crypto fixture convention). `pubKey.verify(msg, sig)` would re-hash
    // `msg` with sha256 internally, which makes the TS verification
    // disagree with every other SDK that simply ECDSA-verifies the
    // supplied 32-byte digest.
    const msgBN = new BigNumber(sighash);
    return ecdsaVerifyRaw(msgBN, sig, pubKey);
  } catch {
    return false;
  }
}

function verifyMultiSig(
  sigsVal: unknown,
  pksVal: unknown,
  sighash: number[],
): boolean {
  if (!Array.isArray(sigsVal) || !Array.isArray(pksVal)) return false;
  if (sigsVal.length > pksVal.length) return false;
  let pkIdx = 0;
  for (const sig of sigsVal) {
    let matched = false;
    while (pkIdx < pksVal.length) {
      const ok = verifyEcdsa(sig, pksVal[pkIdx], sighash);
      pkIdx++;
      if (ok) { matched = true; break; }
    }
    if (!matched) return false;
  }
  return true;
}

/**
 * BIP-143 / OP_PUSH_TX semantic: the on-chain check is
 * `hash256(preimage) === sighash`. We replicate that: the supplied preimage
 * is the serialised BIP-143 message; its double-SHA-256 must equal the
 * sighash the caller provided to {@link executeOnChainAuthoritative}.
 */
function verifyPreimage(preimageVal: unknown, sighash: number[]): boolean {
  const preBytes = toByteArray(preimageVal);
  if (!preBytes) return false;
  const computed = Hash.hash256(preBytes);
  if (computed.length !== sighash.length) return false;
  for (let i = 0; i < sighash.length; i++) {
    if (computed[i] !== sighash[i]) return false;
  }
  return true;
}

function bin2numBigInt(hex: string): bigint {
  if (!hex || hex.length === 0) return 0n;
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  if (bytes.length === 0) return 0n;

  const negative = (bytes[bytes.length - 1]! & 0x80) !== 0;
  if (negative) {
    bytes[bytes.length - 1]! &= 0x7f;
  }

  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]!);
  }

  return negative ? -result : result;
}
