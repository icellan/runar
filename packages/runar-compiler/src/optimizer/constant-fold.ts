/**
 * Constant folding — evaluates compile-time-known expressions in ANF IR.
 *
 * If both operands of a binary operation are `load_const`, the result is
 * computed at compile time and the binding is replaced with a `load_const`.
 * Similarly, unary operations on constants are folded. Folded constants
 * are propagated through subsequent bindings.
 */

import type {
  ANFProgram,
  ANFMethod,
  ANFBinding,
  ANFValue,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Constant value type
// ---------------------------------------------------------------------------

type ConstValue = string | bigint | boolean;

// ---------------------------------------------------------------------------
// Binary operation evaluation
// ---------------------------------------------------------------------------

function evalBinOp(op: string, left: ConstValue, right: ConstValue): ConstValue | null {
  // Arithmetic operations (bigint only)
  if (typeof left === 'bigint' && typeof right === 'bigint') {
    switch (op) {
      case '+': return left + right;
      case '-': return left - right;
      case '*': return left * right;
      case '/':
        if (right === 0n) return null; // division by zero — leave it
        return left / right;
      case '%':
        if (right === 0n) return null;
        return left % right;
      case '===': return left === right;
      case '!==': return left !== right;
      case '<': return left < right;
      case '>': return left > right;
      case '<=': return left <= right;
      case '>=': return left >= right;
      case '&': return left & right;
      case '|': return left | right;
      case '^': return left ^ right;
      case '<<':
        // Bitcoin Script's OP_LSHIFT operates on raw byte arrays (big-endian
        // unsigned shift), not Script numbers. Skip folding for negative left
        // operands to avoid producing incorrect results at compile time.
        if (left < 0n) return null;
        return left << right;
      case '>>':
        // JavaScript's >> is arithmetic (sign-extending) but Bitcoin Script's
        // OP_RSHIFT is logical. Skip folding for negative left operands to
        // avoid producing incorrect results at compile time.
        if (left < 0n) return null;
        return left >> right;
      default: return null;
    }
  }

  // Boolean operations
  if (typeof left === 'boolean' && typeof right === 'boolean') {
    switch (op) {
      case '&&': return left && right;
      case '||': return left || right;
      case '===': return left === right;
      case '!==': return left !== right;
      default: return null;
    }
  }

  // String (ByteString) operations
  if (typeof left === 'string' && typeof right === 'string') {
    switch (op) {
      case '+':
        // Validate both operands are valid hex before concatenating
        if (!/^[0-9a-fA-F]*$/.test(left) || !/^[0-9a-fA-F]*$/.test(right)) return null;
        return left + right; // concatenation
      case '===': return left === right;
      case '!==': return left !== right;
      default: return null;
    }
  }

  // Cross-type equality
  if (op === '===') return false;
  if (op === '!==') return true;

  return null;
}

// ---------------------------------------------------------------------------
// Unary operation evaluation
// ---------------------------------------------------------------------------

function evalUnaryOp(op: string, operand: ConstValue): ConstValue | null {
  if (typeof operand === 'boolean') {
    switch (op) {
      case '!': return !operand;
      default: return null;
    }
  }

  if (typeof operand === 'bigint') {
    switch (op) {
      case '-': return -operand;
      case '~': return ~operand;
      case '!': return operand === 0n;
      default: return null;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Builtin call evaluation (pure math functions only)
// ---------------------------------------------------------------------------

function evalBuiltinCall(func: string, args: ConstValue[]): ConstValue | null {
  // Only fold pure math builtins with bigint arguments
  const bigintArgs = args.filter((a): a is bigint => typeof a === 'bigint');
  if (bigintArgs.length !== args.length) return null;

  switch (func) {
    case 'abs':
      if (bigintArgs.length !== 1) return null;
      return bigintArgs[0]! < 0n ? -bigintArgs[0]! : bigintArgs[0]!;
    case 'min':
      if (bigintArgs.length !== 2) return null;
      return bigintArgs[0]! < bigintArgs[1]! ? bigintArgs[0]! : bigintArgs[1]!;
    case 'max':
      if (bigintArgs.length !== 2) return null;
      return bigintArgs[0]! > bigintArgs[1]! ? bigintArgs[0]! : bigintArgs[1]!;
    case 'safediv':
      if (bigintArgs.length !== 2 || bigintArgs[1]! === 0n) return null;
      return bigintArgs[0]! / bigintArgs[1]!;
    case 'safemod':
      if (bigintArgs.length !== 2 || bigintArgs[1]! === 0n) return null;
      return bigintArgs[0]! % bigintArgs[1]!;
    case 'clamp': {
      if (bigintArgs.length !== 3) return null;
      const [val, lo, hi] = bigintArgs as [bigint, bigint, bigint];
      return val < lo ? lo : val > hi ? hi : val;
    }
    case 'sign': {
      if (bigintArgs.length !== 1) return null;
      const n = bigintArgs[0]!;
      return n > 0n ? 1n : n < 0n ? -1n : 0n;
    }
    case 'pow': {
      if (bigintArgs.length !== 2) return null;
      const [base, exp] = bigintArgs as [bigint, bigint];
      if (exp < 0n || exp > 256n) return null;
      let result = 1n;
      for (let i = 0n; i < exp; i++) result *= base;
      return result;
    }
    case 'mulDiv': {
      if (bigintArgs.length !== 3) return null;
      const [a, b, c] = bigintArgs as [bigint, bigint, bigint];
      if (c === 0n) return null;
      return (a * b) / c;
    }
    case 'percentOf': {
      if (bigintArgs.length !== 2) return null;
      return (bigintArgs[0]! * bigintArgs[1]!) / 10000n;
    }
    case 'sqrt': {
      if (bigintArgs.length !== 1) return null;
      const n = bigintArgs[0]!;
      if (n < 0n) return null;
      if (n === 0n) return 0n;
      let guess = n;
      for (let i = 0; i < 256; i++) {
        const next = (guess + n / guess) / 2n;
        if (next >= guess) break;
        guess = next;
      }
      return guess;
    }
    case 'gcd': {
      if (bigintArgs.length !== 2) return null;
      let a = bigintArgs[0]! < 0n ? -bigintArgs[0]! : bigintArgs[0]!;
      let b = bigintArgs[1]! < 0n ? -bigintArgs[1]! : bigintArgs[1]!;
      while (b !== 0n) { const t = b; b = a % b; a = t; }
      return a;
    }
    case 'divmod': {
      if (bigintArgs.length !== 2 || bigintArgs[1]! === 0n) return null;
      return bigintArgs[0]! / bigintArgs[1]!;
    }
    case 'log2': {
      if (bigintArgs.length !== 1) return null;
      const n = bigintArgs[0]!;
      if (n <= 0n) return 0n;
      let bits = 0n;
      let val = n;
      while (val > 1n) { val >>= 1n; bits++; }
      return bits;
    }
    case 'bool': {
      if (bigintArgs.length !== 1) return null;
      return bigintArgs[0]! !== 0n;
    }
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Constant propagation environment
// ---------------------------------------------------------------------------

class ConstEnv {
  private constants = new Map<string, ConstValue>();

  set(name: string, value: ConstValue): void {
    this.constants.set(name, value);
  }

  get(name: string): ConstValue | undefined {
    return this.constants.get(name);
  }

  has(name: string): boolean {
    return this.constants.has(name);
  }

  /** Clone the environment (for if-branch isolation). */
  clone(): ConstEnv {
    const env = new ConstEnv();
    for (const [k, v] of this.constants) {
      env.constants.set(k, v);
    }
    return env;
  }
}

// ---------------------------------------------------------------------------
// Fold bindings
// ---------------------------------------------------------------------------

function foldBindings(bindings: ANFBinding[], env: ConstEnv): ANFBinding[] {
  const result: ANFBinding[] = [];

  for (const binding of bindings) {
    const folded = foldBinding(binding, env);
    result.push(folded);
  }

  return result;
}

function foldBinding(binding: ANFBinding, env: ConstEnv): ANFBinding {
  const { name, value } = binding;
  const foldedValue = foldValue(value, env);

  // If the folded value is a load_const, register in the environment.
  // Skip @ref: prefixed strings — they are binding aliases, not real constants.
  if (foldedValue.kind === 'load_const') {
    const v = foldedValue.value;
    if (!(typeof v === 'string' && v.startsWith('@ref:'))) {
      env.set(name, v);
    }
  }

  const result: ANFBinding = { name, value: foldedValue };
  if (binding.sourceLoc) result.sourceLoc = binding.sourceLoc;
  return result;
}

function foldValue(value: ANFValue, env: ConstEnv): ANFValue {
  switch (value.kind) {
    case 'load_const':
      return value;

    case 'load_param':
      return value;

    case 'load_prop':
      return value;

    case 'bin_op': {
      const leftConst = env.get(value.left);
      const rightConst = env.get(value.right);

      if (leftConst !== undefined && rightConst !== undefined) {
        const result = evalBinOp(value.op, leftConst, rightConst);
        if (result !== null) {
          return { kind: 'load_const', value: result };
        }
      }

      return value;
    }

    case 'unary_op': {
      const operandConst = env.get(value.operand);

      if (operandConst !== undefined) {
        const result = evalUnaryOp(value.op, operandConst);
        if (result !== null) {
          return { kind: 'load_const', value: result };
        }
      }

      return value;
    }

    case 'call': {
      // Fold pure math builtins when all args are constants
      const allConst = value.args.every(a => env.has(a));
      if (allConst) {
        const constArgs = value.args.map(a => env.get(a)!);
        const folded = evalBuiltinCall(value.func, constArgs);
        if (folded !== null) {
          return { kind: 'load_const', value: folded };
        }
      }
      return value;
    }

    case 'method_call':
      return value;

    case 'if': {
      // Check if condition is a known constant
      const condConst = env.get(value.cond);

      if (condConst !== undefined && typeof condConst === 'boolean') {
        // Branch is statically known — fold to just one branch
        if (condConst) {
          const thenEnv = env.clone();
          const foldedThen = foldBindings(value.then, thenEnv);
          // Merge constants from the taken branch back into env
          for (const b of foldedThen) {
            if (b.value.kind === 'load_const') {
              env.set(b.name, b.value.value);
            }
          }
          return { ...value, then: foldedThen, else: [] };
        } else {
          const elseEnv = env.clone();
          const foldedElse = foldBindings(value.else, elseEnv);
          for (const b of foldedElse) {
            if (b.value.kind === 'load_const') {
              env.set(b.name, b.value.value);
            }
          }
          return { ...value, then: [], else: foldedElse };
        }
      }

      // Condition not known — fold both branches independently
      const thenEnv = env.clone();
      const elseEnv = env.clone();
      const foldedThen = foldBindings(value.then, thenEnv);
      const foldedElse = foldBindings(value.else, elseEnv);

      return { ...value, then: foldedThen, else: foldedElse };
    }

    case 'loop': {
      // Fold loop body
      const bodyEnv = env.clone();
      const foldedBody = foldBindings(value.body, bodyEnv);
      return { ...value, body: foldedBody };
    }

    case 'assert': {
      // Check if assertion is a known constant
      const assertConst = env.get(value.value);
      if (assertConst === true) {
        // Assertion is always true — it's a no-op, but we keep it for safety.
        // A more aggressive optimizer could remove it.
        return value;
      }
      if (assertConst === false) {
        // Assertion is always false — this is a compile-time error.
        // We leave it in; the runtime will fail.
        return value;
      }
      return value;
    }

    case 'update_prop':
      return value;

    case 'get_state_script':
      return value;

    case 'check_preimage':
      return value;

    case 'deserialize_state':
      return value;

    case 'add_output':
      return value;

    case 'add_raw_output':
      return value;

    case 'array_literal':
      return value;
  }
}

// ---------------------------------------------------------------------------
// Fold a method
// ---------------------------------------------------------------------------

function foldMethod(method: ANFMethod): ANFMethod {
  const env = new ConstEnv();
  const foldedBody = foldBindings(method.body, env);

  return {
    ...method,
    body: foldedBody,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Apply constant folding to an ANF program.
 *
 * For each method, evaluates compile-time-known expressions and replaces
 * them with `load_const` bindings. Also propagates constants through
 * the binding chain so that downstream operations can be folded too.
 */
export function foldConstants(program: ANFProgram): ANFProgram {
  const foldedMethods = program.methods.map(foldMethod);

  return {
    ...program,
    methods: foldedMethods,
  };
}

// ---------------------------------------------------------------------------
// Dead binding elimination (bonus pass)
// ---------------------------------------------------------------------------

/**
 * Remove bindings whose results are never referenced.
 *
 * This is a simple pass that counts references to each binding name
 * and removes those with zero references, unless the binding has
 * side effects (assert, update_prop, check_preimage).
 */
export function eliminateDeadBindings(program: ANFProgram): ANFProgram {
  return {
    ...program,
    methods: program.methods.map(eliminateDeadInMethod),
  };
}

function eliminateDeadInMethod(method: ANFMethod): ANFMethod {
  const refs = collectAllRefs(method.body);
  const live = filterLiveBindings(method.body, refs);
  return { ...method, body: live };
}

function collectAllRefs(bindings: ANFBinding[]): Set<string> {
  const refs = new Set<string>();

  for (const binding of bindings) {
    collectRefsFromValue(binding.value, refs);
  }

  return refs;
}

function collectRefsFromValue(value: ANFValue, refs: Set<string>): void {
  switch (value.kind) {
    case 'load_param':
    case 'load_prop':
    case 'get_state_script':
      break;
    case 'load_const':
      // Track @ref: aliases as references to prevent DCE
      if (typeof value.value === 'string' && value.value.startsWith('@ref:')) {
        refs.add(value.value.slice(5));
      }
      break;
    case 'bin_op':
      refs.add(value.left);
      refs.add(value.right);
      break;
    case 'unary_op':
      refs.add(value.operand);
      break;
    case 'call':
      for (const arg of value.args) refs.add(arg);
      break;
    case 'method_call':
      refs.add(value.object);
      for (const arg of value.args) refs.add(arg);
      break;
    case 'if':
      refs.add(value.cond);
      for (const b of value.then) collectRefsFromValue(b.value, refs);
      for (const b of value.else) collectRefsFromValue(b.value, refs);
      break;
    case 'loop':
      for (const b of value.body) collectRefsFromValue(b.value, refs);
      break;
    case 'assert':
      refs.add(value.value);
      break;
    case 'update_prop':
      refs.add(value.value);
      break;
    case 'check_preimage':
      refs.add(value.preimage);
      break;
    case 'deserialize_state':
      refs.add(value.preimage);
      break;
    case 'add_output':
      refs.add(value.satoshis);
      for (const sv of value.stateValues) refs.add(sv);
      refs.add(value.preimage);
      break;
    case 'add_raw_output':
      refs.add(value.satoshis);
      refs.add(value.scriptBytes);
      break;
    case 'array_literal':
      for (const elem of value.elements) refs.add(elem);
      break;
  }
}

function hasSideEffect(value: ANFValue): boolean {
  switch (value.kind) {
    case 'assert':
    case 'update_prop':
    case 'check_preimage':
    case 'deserialize_state':
    case 'add_output':
    case 'add_raw_output':
    case 'call':        // calls may have side effects (e.g. assert)
    case 'method_call': // method calls may have side effects
      return true;
    default:
      return false;
  }
}

function filterLiveBindings(bindings: ANFBinding[], _refs: Set<string>): ANFBinding[] {
  // Multiple passes to handle transitive dead code
  let current = bindings;
  let changed = true;

  while (changed) {
    changed = false;
    const newRefs = collectAllRefs(current);
    const filtered: ANFBinding[] = [];

    for (const binding of current) {
      if (newRefs.has(binding.name) || hasSideEffect(binding.value)) {
        filtered.push(binding);
      } else {
        changed = true;
      }
    }

    current = filtered;
  }

  return current;
}
