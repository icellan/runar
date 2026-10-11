/**
 * ANF EC Optimizer (Pass 4.5) — algebraic simplification of EC operations.
 *
 * Runs on ANF IR BEFORE stack lowering. Each eliminated ecMul saves ~1500 bytes,
 * each eliminated ecAdd saves ~800 bytes. Always-on.
 *
 * Rules are defined in optimizer/ec-rules.json and implemented procedurally here
 * because they require resolving ANF binding references (not simple pattern matching).
 */

import type {
  ANFProgram,
  ANFMethod,
  ANFBinding,
  ANFValue,
  Call,
  LoadConst,
} from '../ir/index.js';
import { eliminateDeadBindings } from './dce.js';

// ---------------------------------------------------------------------------
// EC constants
// ---------------------------------------------------------------------------

/** secp256k1 curve order */
const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** secp256k1 field prime */
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

/** Generator x-coordinate */
const GEN_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
/** Generator y-coordinate */
const GEN_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

function bigintToHex32(n: bigint): string {
  return n.toString(16).padStart(64, '0');
}

/** 64 zero bytes = point at infinity */
const INFINITY_HEX = '0'.repeat(128);

/** Generator G as 64-byte hex (x || y) */
const G_HEX = bigintToHex32(GEN_X) + bigintToHex32(GEN_Y);

// ---------------------------------------------------------------------------
// Value resolution helpers
// ---------------------------------------------------------------------------

type ValueMap = Map<string, ANFValue>;

function isCallTo(value: ANFValue, func: string): value is Call {
  return value.kind === 'call' && value.func === func;
}

function isConstInt(value: ANFValue, n: bigint): boolean {
  return value.kind === 'load_const' && typeof value.value === 'bigint' && value.value === n;
}

function isConstHex(value: ANFValue, hex: string): boolean {
  return value.kind === 'load_const' && typeof value.value === 'string' && value.value === hex;
}

function getConstInt(value: ANFValue): bigint | undefined {
  if (value.kind === 'load_const' && typeof value.value === 'bigint') return value.value;
  return undefined;
}

function isInfinity(value: ANFValue): boolean {
  return isConstHex(value, INFINITY_HEX);
}

function isGeneratorPoint(value: ANFValue): boolean {
  return isConstHex(value, G_HEX);
}

/** Resolve a binding name to its value, following through the map */
function resolveArg(argName: string, valueMap: ValueMap): ANFValue | undefined {
  return valueMap.get(argName);
}

/** Check if a resolved arg represents the infinity point (zero-scalar ecMulGen or direct constant) */
function argIsInfinity(argName: string, valueMap: ValueMap): boolean {
  const v = resolveArg(argName, valueMap);
  if (!v) return false;
  if (isInfinity(v)) return true;
  // ecMulGen(0) = infinity
  if (isCallTo(v, 'ecMulGen') && v.args.length === 1) {
    const scalarVal = resolveArg(v.args[0]!, valueMap);
    if (scalarVal && isConstInt(scalarVal, 0n)) return true;
  }
  return false;
}

/** Check if a resolved arg represents the generator point G */
function argIsG(argName: string, valueMap: ValueMap): boolean {
  const v = resolveArg(argName, valueMap);
  if (!v) return false;
  if (isGeneratorPoint(v)) return true;
  // ecMulGen(1) = G
  if (isCallTo(v, 'ecMulGen') && v.args.length === 1) {
    const scalarVal = resolveArg(v.args[0]!, valueMap);
    if (scalarVal && isConstInt(scalarVal, 1n)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Rewrite engine
// ---------------------------------------------------------------------------

function makeLoadConst(value: string | bigint | boolean): LoadConst {
  return { kind: 'load_const', value };
}

/**
 * F-086: every name the method already uses — binding names at any depth
 * (if/loop arms included), loop iteration variables, params, and the
 * contract's properties. A scalar-fusing rewrite mints a new binding; ANF is
 * single-assignment and stack lowering resolves a name to its shallowest
 * slot, so a minted name that is already in use silently aliases the two
 * values. `--ir` input chooses these names freely.
 */
function collectUsedNames(method: ANFMethod, properties: readonly { name: string }[]): Set<string> {
  const used = new Set<string>();
  for (const p of properties) used.add(p.name);
  for (const p of method.params) used.add(p.name);
  const walk = (bindings: readonly ANFBinding[]): void => {
    for (const bnd of bindings) {
      used.add(bnd.name);
      const v = bnd.value;
      if (v.kind === 'load_param' || v.kind === 'load_prop') used.add(v.name);
      if (v.kind === 'if') { walk(v.then); walk(v.else); }
      if (v.kind === 'loop') { used.add(v.iterVar); walk(v.body); }
    }
  };
  walk(method.body);
  return used;
}

/**
 * F-086: `base` when the method does not use it (every non-colliding program
 * keeps its historical name), else the first unused `base_<i>`. Reserves the
 * returned name.
 */
function freshName(base: string, usedNames: Set<string>): string {
  let name = base;
  for (let i = 1; usedNames.has(name); i++) name = `${base}_${i}`;
  usedNames.add(name);
  return name;
}

/**
 * N-104 — the operand gate a rewrite must leave behind.
 *
 * R1-R4 (`ecAdd(q, O) → q`, `ecAdd(O, q) → q`, `ecMul(q, 1) → q`,
 * `ecMul(q, 0) → O`) replace a builtin whose FIRST act is to validate `q`, and
 * the answer they substitute is only the builtin's answer for a q that passes
 * that validation. Dropping it made a malformed or off-curve q accepted by the
 * default compile and aborted by `disableEcOptimizer`. So each rewrite still
 * elides the add/mul but emits the validation, as plain ANF ahead of the
 * rewritten binding. Each gate ends in an `assert`, which DCE keeps, and the
 * assert keeps everything it reads.
 *
 * The gate is built only from forms no EC rule matches (ecPointX/Y, ecOnCurve,
 * bin_op, assert). Every tier runs this optimizer to a fixed point (TS since
 * F-115), so a gate a later sweep could rewrite (an `ecNegate(q)`, say, under
 * ec-negate-negate) would be rewritten again rather than kept as emitted.
 *
 * `ecAdd` operand gate (CL-BUG-095 width + R-117 coordinate canonicity):
 * `assert(ecPointX(q) < p && ecPointY(q) < p)`. ecPointX/Y abort unless q is
 * exactly 64 bytes, as decomposePoint does inside `ecAdd`; the two compares are
 * emitCoordCanonVerify. `ecAdd` does NOT require on-curve (R-157 explains
 * why), so neither may this.
 */
function emitAddOperandGate(base: string, q: string, out: ANFBinding[], usedNames: Set<string>): void {
  const px = freshName(`${base}_px`, usedNames);
  out.push({ name: px, value: { kind: 'call', func: 'ecPointX', args: [q] } });
  const py = freshName(`${base}_py`, usedNames);
  out.push({ name: py, value: { kind: 'call', func: 'ecPointY', args: [q] } });
  const fp = freshName(`${base}_fp`, usedNames);
  out.push({ name: fp, value: makeLoadConst(FIELD_P) });
  const xOk = freshName(`${base}_pxok`, usedNames);
  out.push({ name: xOk, value: { kind: 'bin_op', op: '<', left: px, right: fp } });
  const yOk = freshName(`${base}_pyok`, usedNames);
  out.push({ name: yOk, value: { kind: 'bin_op', op: '<', left: py, right: fp } });
  const ok = freshName(`${base}_ok`, usedNames);
  out.push({ name: ok, value: { kind: 'bin_op', op: '&&', left: xOk, right: yOk } });
  out.push({ name: freshName(`${base}_gate`, usedNames), value: { kind: 'assert', value: ok } });
}

/**
 * `ecMul` operand gate (R-157): `assert(q === O || ecOnCurve(q))` — the same
 * predicate, in the same order, as `emitPointGate` in ec-codegen.ts. ecOnCurve
 * already folds in the width and canonicity checks, so this subsumes the
 * `ecAdd` gate exactly as R-157 subsumes it inside `ecMul`.
 */
function emitMulOperandGate(base: string, q: string, out: ANFBinding[], usedNames: Set<string>): void {
  const inf = freshName(`${base}_inf`, usedNames);
  out.push({ name: inf, value: makeLoadConst(INFINITY_HEX) });
  const isInf = freshName(`${base}_isinf`, usedNames);
  out.push({ name: isInf, value: { kind: 'bin_op', op: '===', left: q, right: inf, result_type: 'bytes' } });
  const onCurve = freshName(`${base}_oncurve`, usedNames);
  out.push({ name: onCurve, value: { kind: 'call', func: 'ecOnCurve', args: [q] } });
  const ok = freshName(`${base}_ok`, usedNames);
  out.push({ name: ok, value: { kind: 'bin_op', op: '||', left: isInf, right: onCurve } });
  out.push({ name: freshName(`${base}_gate`, usedNames), value: { kind: 'assert', value: ok } });
}

/**
 * Try to rewrite a single binding. Returns the new value if rewritten, or null.
 */
function tryRewrite(
  binding: ANFBinding,
  valueMap: ValueMap,
  newBindings: ANFBinding[],
  usedNames: Set<string>,
): ANFValue | null {
  const { value } = binding;
  if (value.kind !== 'call') return null;

  const { func, args } = value;

  switch (func) {
    case 'ecMulGen': {
      if (args.length !== 1) return null;
      const scalarVal = resolveArg(args[0]!, valueMap);
      if (!scalarVal) return null;

      // Rule 5: ecMulGen(0) → INFINITY
      if (isConstInt(scalarVal, 0n)) {
        return makeLoadConst(INFINITY_HEX);
      }

      // Rule 6: ecMulGen(1) → G
      if (isConstInt(scalarVal, 1n)) {
        return makeLoadConst(G_HEX);
      }

      return null;
    }

    case 'ecMul': {
      if (args.length !== 2) return null;
      const pointArg = args[0]!;
      const scalarArg = args[1]!;
      const scalarVal = resolveArg(scalarArg, valueMap);
      if (!scalarVal) return null;

      // Rule 4: ecMul(x, 0) → INFINITY, keeping ecMul's operand gate (N-104)
      if (isConstInt(scalarVal, 0n)) {
        emitMulOperandGate(binding.name, pointArg, newBindings, usedNames);
        return makeLoadConst(INFINITY_HEX);
      }

      // Rule 3: ecMul(x, 1) → x (alias), keeping ecMul's operand gate (N-104)
      if (isConstInt(scalarVal, 1n)) {
        emitMulOperandGate(binding.name, pointArg, newBindings, usedNames);
        // Return a reference to the point argument
        return { kind: 'load_const', value: `@ref:${pointArg}` } as ANFValue;
      }

      // Rule 12: ecMul(k, G) → ecMulGen(k)
      if (argIsG(pointArg, valueMap)) {
        return { kind: 'call', func: 'ecMulGen', args: [scalarArg] };
      }

      // Rule 9: ecMul(ecMul(p, k1), k2) → ecMul(p, k1*k2)
      const pointVal = resolveArg(pointArg, valueMap);
      if (pointVal && isCallTo(pointVal, 'ecMul') && pointVal.args.length === 2) {
        const innerPoint = pointVal.args[0]!;
        const innerScalar = pointVal.args[1]!;
        const k1Val = resolveArg(innerScalar, valueMap);
        const k2Val = scalarVal;
        const k1 = k1Val ? getConstInt(k1Val) : undefined;
        const k2 = getConstInt(k2Val);
        if (k1 !== undefined && k2 !== undefined) {
          // Normalise into [0, CURVE_N). JavaScript's `%` is truncated, so a
          // negative constant scalar would otherwise fuse to a negative value
          // while every other tier (Go/Rust/Python/Zig/Ruby/Java) reduces
          // Euclidean-style — a cross-tier hex divergence. Rules 10 and 11
          // below use the same normalisation.
          const product = ((k1 * k2) % CURVE_N + CURVE_N) % CURVE_N;
          const newScalarName = freshName(`${binding.name}_k`, usedNames);
          newBindings.push({ name: newScalarName, value: makeLoadConst(product) });
          return { kind: 'call', func: 'ecMul', args: [innerPoint, newScalarName] };
        }
      }

      return null;
    }

    case 'ecAdd': {
      if (args.length !== 2) return null;
      const leftArg = args[0]!;
      const rightArg = args[1]!;

      // Rule 1: ecAdd(x, INFINITY) → x, keeping ecAdd's operand gate (N-104)
      if (argIsInfinity(rightArg, valueMap)) {
        emitAddOperandGate(binding.name, leftArg, newBindings, usedNames);
        return { kind: 'load_const', value: `@ref:${leftArg}` } as ANFValue;
      }

      // Rule 2: ecAdd(INFINITY, x) → x, keeping ecAdd's operand gate (N-104)
      if (argIsInfinity(leftArg, valueMap)) {
        emitAddOperandGate(binding.name, rightArg, newBindings, usedNames);
        return { kind: 'load_const', value: `@ref:${rightArg}` } as ANFValue;
      }

      // Rule 8: ecAdd(x, ecNegate(x)) → INFINITY
      const rightVal = resolveArg(rightArg, valueMap);
      if (rightVal && isCallTo(rightVal, 'ecNegate') && rightVal.args.length === 1) {
        if (rightVal.args[0] === leftArg) {
          return makeLoadConst(INFINITY_HEX);
        }
      }

      const leftVal = resolveArg(leftArg, valueMap);

      // Rule 8r (`ec-add-negate-cancel-reversed`): ecAdd(ecNegate(x), x) → INFINITY
      //
      // The mirror of Rule 8. It was in optimizer/ec-rules.json from the start
      // and the Go tier — whose engine executes that file directly — performed
      // it; the six hand-ported tiers implemented only the forward direction,
      // so the same ANF compiled to a 1808-byte script in Go and a 26140-byte
      // one everywhere else (R-034 / CL-BUG-028).
      //
      // Placed AFTER Rule 8 and BEFORE Rules 10/11 to match the JSON's rule
      // order, which is the order the Go engine tries them in. The shapes do
      // not overlap (the left operand here must be an ecNegate call), but rule
      // order is the thing that decides output bytes when they ever do.
      //
      // Name equality, not value equality, exactly as Rule 8 above: $x must
      // bind to the same ANF binding on both sides.
      if (leftVal && isCallTo(leftVal, 'ecNegate') && leftVal.args.length === 1) {
        if (leftVal.args[0] === rightArg) {
          return makeLoadConst(INFINITY_HEX);
        }
      }

      // Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) → ecMulGen(k1+k2)
      if (leftVal && rightVal && isCallTo(leftVal, 'ecMulGen') && isCallTo(rightVal, 'ecMulGen')
          && leftVal.args.length === 1 && rightVal.args.length === 1) {
        const k1Val = resolveArg(leftVal.args[0]!, valueMap);
        const k2Val = resolveArg(rightVal.args[0]!, valueMap);
        const k1 = k1Val ? getConstInt(k1Val) : undefined;
        const k2 = k2Val ? getConstInt(k2Val) : undefined;
        if (k1 !== undefined && k2 !== undefined) {
          const sum = ((k1 + k2) % CURVE_N + CURVE_N) % CURVE_N;
          const newScalarName = freshName(`${binding.name}_k`, usedNames);
          newBindings.push({ name: newScalarName, value: makeLoadConst(sum) });
          return { kind: 'call', func: 'ecMulGen', args: [newScalarName] };
        }
      }

      // Rule 11: ecAdd(ecMul(k1,p), ecMul(k2,p)) → ecMul(k1+k2, p)
      if (leftVal && rightVal && isCallTo(leftVal, 'ecMul') && isCallTo(rightVal, 'ecMul')
          && leftVal.args.length === 2 && rightVal.args.length === 2) {
        // Check same point argument
        if (leftVal.args[0] === rightVal.args[0]) {
          const k1Val = resolveArg(leftVal.args[1]!, valueMap);
          const k2Val = resolveArg(rightVal.args[1]!, valueMap);
          const k1 = k1Val ? getConstInt(k1Val) : undefined;
          const k2 = k2Val ? getConstInt(k2Val) : undefined;
          if (k1 !== undefined && k2 !== undefined) {
            const sum = ((k1 + k2) % CURVE_N + CURVE_N) % CURVE_N;
            const newScalarName = freshName(`${binding.name}_k`, usedNames);
            newBindings.push({ name: newScalarName, value: makeLoadConst(sum) });
            return { kind: 'call', func: 'ecMul', args: [leftVal.args[0]!, newScalarName] };
          }
        }
      }

      return null;
    }

    case 'ecNegate': {
      if (args.length !== 1) return null;
      const innerVal = resolveArg(args[0]!, valueMap);
      if (!innerVal) return null;

      // Rule 7: ecNegate(ecNegate(x)) → x
      if (isCallTo(innerVal, 'ecNegate') && innerVal.args.length === 1) {
        return { kind: 'load_const', value: `@ref:${innerVal.args[0]!}` } as ANFValue;
      }

      return null;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Method optimizer
// ---------------------------------------------------------------------------

/**
 * One left-to-right sweep: each binding is tried once, against the values of
 * the bindings before it as already rewritten in this sweep. Returns null when
 * no rule fired.
 */
function optimizeBodyOnce(body: readonly ANFBinding[], usedNames: Set<string>): ANFBinding[] | null {
  const valueMap: ValueMap = new Map();
  const result: ANFBinding[] = [];
  let changed = false;

  for (const binding of body) {
    // Register binding value for lookups
    valueMap.set(binding.name, binding.value);

    const extraBindings: ANFBinding[] = [];
    const rewritten = tryRewrite(binding, valueMap, extraBindings, usedNames);

    if (rewritten !== null) {
      // F-343: the rewritten binding keeps its source location, and every
      // helper minted for it (fused scalar, N-104 operand gate) takes the
      // same one, so the source map still covers their opcodes. Debug-only
      // metadata: it never reaches the script bytes.
      const loc = binding.sourceLoc ? { sourceLoc: binding.sourceLoc } : {};
      // Add any new helper bindings (e.g., computed scalars)
      for (const extra of extraBindings) {
        result.push({ ...extra, ...loc });
        valueMap.set(extra.name, extra.value);
      }
      const newBinding = { name: binding.name, value: rewritten, ...loc };
      result.push(newBinding);
      valueMap.set(binding.name, rewritten);
      changed = true;
    } else {
      result.push(binding);
    }
  }

  return changed ? result : null;
}

/**
 * F-115: sweep until no rule fires, as the other six tiers do (Go's
 * `for changed {}` in frontend/anf_optimize.go). `tryRewrite` applies one rule
 * per binding per sweep, and a rewritten value can match another rule — e.g.
 * Rule 10's `ecMulGen(k1+k2)` with k1+k2 ≡ 0 is Rule 5's `ecMulGen(0)` — so a
 * single sweep left that binding half-reduced in TS only. `usedNames` spans all
 * sweeps so a later sweep never re-mints an earlier helper's name.
 */
function optimizeMethodEC(method: ANFMethod, properties: readonly { name: string }[]): ANFMethod {
  const usedNames = collectUsedNames(method, properties);
  let body: ANFBinding[] = method.body;
  let anyChanged = false;

  for (;;) {
    const next = optimizeBodyOnce(body, usedNames);
    if (next === null) break;
    body = next;
    anyChanged = true;
  }

  if (!anyChanged) return method;
  return { ...method, body };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Optimize EC operations in an ANF program (Pass 4.5).
 *
 * Applies algebraic simplification rules to EC function calls,
 * then eliminates dead bindings. Always-on, runs before stack lowering.
 */
export function optimizeEC(program: ANFProgram): ANFProgram {
  const optimizedMethods = program.methods.map(m => optimizeMethodEC(m, program.properties));

  // Check if anything changed
  const anyChanged = optimizedMethods.some(
    (m, i) => m !== program.methods[i],
  );

  if (!anyChanged) return program;

  const result: ANFProgram = {
    ...program,
    methods: optimizedMethods,
  };

  // Run dead binding elimination to clean up orphaned bindings
  return eliminateDeadBindings(result);
}
