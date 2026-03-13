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
import { eliminateDeadBindings } from './constant-fold.js';

// ---------------------------------------------------------------------------
// EC constants
// ---------------------------------------------------------------------------

/** secp256k1 curve order */
const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

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
 * Try to rewrite a single binding. Returns the new value if rewritten, or null.
 */
function tryRewrite(
  binding: ANFBinding,
  valueMap: ValueMap,
  newBindings: ANFBinding[],
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

      // Rule 4: ecMul(x, 0) → INFINITY
      if (isConstInt(scalarVal, 0n)) {
        return makeLoadConst(INFINITY_HEX);
      }

      // Rule 3: ecMul(x, 1) → x (alias)
      if (isConstInt(scalarVal, 1n)) {
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
          const product = (k1 * k2) % CURVE_N;
          const newScalarName = `${binding.name}_k`;
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

      // Rule 1: ecAdd(x, INFINITY) → x
      if (argIsInfinity(rightArg, valueMap)) {
        return { kind: 'load_const', value: `@ref:${leftArg}` } as ANFValue;
      }

      // Rule 2: ecAdd(INFINITY, x) → x
      if (argIsInfinity(leftArg, valueMap)) {
        return { kind: 'load_const', value: `@ref:${rightArg}` } as ANFValue;
      }

      // Rule 8: ecAdd(x, ecNegate(x)) → INFINITY
      const rightVal = resolveArg(rightArg, valueMap);
      if (rightVal && isCallTo(rightVal, 'ecNegate') && rightVal.args.length === 1) {
        if (rightVal.args[0] === leftArg) {
          return makeLoadConst(INFINITY_HEX);
        }
      }

      // Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) → ecMulGen(k1+k2)
      const leftVal = resolveArg(leftArg, valueMap);
      if (leftVal && rightVal && isCallTo(leftVal, 'ecMulGen') && isCallTo(rightVal, 'ecMulGen')
          && leftVal.args.length === 1 && rightVal.args.length === 1) {
        const k1Val = resolveArg(leftVal.args[0]!, valueMap);
        const k2Val = resolveArg(rightVal.args[0]!, valueMap);
        const k1 = k1Val ? getConstInt(k1Val) : undefined;
        const k2 = k2Val ? getConstInt(k2Val) : undefined;
        if (k1 !== undefined && k2 !== undefined) {
          const sum = ((k1 + k2) % CURVE_N + CURVE_N) % CURVE_N;
          const newScalarName = `${binding.name}_k`;
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
            const newScalarName = `${binding.name}_k`;
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

function optimizeMethodEC(method: ANFMethod): ANFMethod {
  const valueMap: ValueMap = new Map();
  const result: ANFBinding[] = [];
  let changed = false;

  for (const binding of method.body) {
    // Register binding value for lookups
    valueMap.set(binding.name, binding.value);

    const extraBindings: ANFBinding[] = [];
    const rewritten = tryRewrite(binding, valueMap, extraBindings);

    if (rewritten !== null) {
      // Add any new helper bindings (e.g., computed scalars)
      for (const extra of extraBindings) {
        result.push(extra);
        valueMap.set(extra.name, extra.value);
      }
      const newBinding = { name: binding.name, value: rewritten };
      result.push(newBinding);
      valueMap.set(binding.name, rewritten);
      changed = true;
    } else {
      result.push(binding);
    }
  }

  if (!changed) return method;
  return { ...method, body: result };
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
  const optimizedMethods = program.methods.map(optimizeMethodEC);

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
