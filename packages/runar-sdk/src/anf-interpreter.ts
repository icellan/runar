/**
 * Lightweight ANF interpreter for auto-computing state transitions.
 *
 * Given a compiled artifact's ANF IR, the current contract state, and
 * method arguments, this interpreter walks the ANF bindings and computes
 * the new state. It handles `update_prop` nodes to track state mutations,
 * while skipping on-chain-only operations like `check_preimage`,
 * `deserialize_state`, `get_state_script`, `add_output`, and `add_raw_output`.
 *
 * This enables the SDK to auto-compute `newState` for stateful contract
 * calls, so callers don't need to duplicate contract logic.
 */

import type {
  ANFProgram,
  ANFBinding,
  ANFValue,
} from 'runar-ir-schema';
import { Hash, Utils } from '@bsv/sdk';

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
 * @returns The updated state (merged with currentState).
 */
export function computeNewState(
  anf: ANFProgram,
  methodName: string,
  currentState: Record<string, unknown>,
  args: Record<string, unknown>,
): Record<string, unknown> {
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

  // Load properties
  for (const prop of anf.properties) {
    env[prop.name] = currentState[prop.name] ?? prop.initialValue;
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

  // Track state mutations
  const stateDelta: Record<string, unknown> = {};

  // Walk bindings
  evalBindings(method.body, env, stateDelta, anf);

  return { ...currentState, ...stateDelta };
}

// ---------------------------------------------------------------------------
// Binding evaluation
// ---------------------------------------------------------------------------

function evalBindings(
  bindings: ANFBinding[],
  env: Record<string, unknown>,
  stateDelta: Record<string, unknown>,
  anf?: ANFProgram,
): void {
  for (const binding of bindings) {
    const val = evalValue(binding.value, env, stateDelta, anf);
    env[binding.name] = val;
  }
}

function evalValue(
  value: ANFValue,
  env: Record<string, unknown>,
  stateDelta: Record<string, unknown>,
  anf?: ANFProgram,
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
        return env[v.slice(5)];
      }
      return v;
    }

    case 'bin_op':
      return evalBinOp(
        value.op,
        env[value.left],
        env[value.right],
        value.result_type,
      );

    case 'unary_op':
      return evalUnaryOp(value.op, env[value.operand], value.result_type);

    case 'call':
      return evalCall(value.func, value.args.map((a) => env[a]));

    case 'method_call':
      return evalMethodCall(
        env,
        value.method,
        value.args.map((a: string) => env[a]),
        stateDelta,
        anf,
      );

    case 'if': {
      const cond = env[value.cond];
      const branch = isTruthy(cond) ? value.then : value.else;
      // Create a child env for the branch
      const childEnv = { ...env };
      evalBindings(branch, childEnv, stateDelta, anf);
      // Copy any new bindings back (the last binding is typically the branch result)
      Object.assign(env, childEnv);
      // Return the last binding's value from the branch
      if (branch.length > 0) {
        return childEnv[branch[branch.length - 1]!.name];
      }
      return undefined;
    }

    case 'loop': {
      const { count, body, iterVar } = value;
      let lastVal: unknown;
      for (let i = 0; i < count; i++) {
        env[iterVar] = BigInt(i);
        const loopEnv = { ...env };
        evalBindings(body, loopEnv, stateDelta, anf);
        // Copy loop bindings back
        Object.assign(env, loopEnv);
        if (body.length > 0) {
          lastVal = loopEnv[body[body.length - 1]!.name];
        }
      }
      return lastVal;
    }

    case 'assert': {
      // In simulation, we skip asserts (the on-chain script handles enforcement)
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
      return undefined;
    }

    // On-chain-only operations — skip in simulation
    case 'check_preimage':
    case 'deserialize_state':
    case 'get_state_script':
    case 'add_raw_output':
      return undefined;

    default:
      return undefined;
  }
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
    case '&': return l & r;
    case '|': return l | r;
    case '^': return l ^ r;
    case '<<': return l << r;
    case '>>': return l >> r;
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
    case '~': return ~val;
    default: return val;
  }
}

// ---------------------------------------------------------------------------
// Built-in function calls
// ---------------------------------------------------------------------------

function evalCall(func: string, args: unknown[]): unknown {
  switch (func) {
    // Crypto — mock
    case 'checkSig': return true;
    case 'checkMultiSig': return true;
    case 'checkPreimage': return true;

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

    default:
      return undefined;
  }
}

function evalMethodCall(
  callerEnv: Record<string, unknown>,
  methodName: string,
  args: unknown[],
  stateDelta: Record<string, unknown>,
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
      evalBindings(method.body, methodEnv, stateDelta, anf);

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

function num2binHex(n: bigint, byteLen: number): string {
  if (n === 0n) return '00'.repeat(byteLen);

  const negative = n < 0n;
  let abs = negative ? -n : n;

  const bytes: number[] = [];
  while (abs > 0n) {
    bytes.push(Number(abs & 0xffn));
    abs >>= 8n;
  }

  // Sign bit handling: if MSB has sign bit set and number is positive,
  // or vice versa, add a padding byte
  if (bytes.length > 0) {
    if (negative) {
      if ((bytes[bytes.length - 1]! & 0x80) === 0) {
        bytes[bytes.length - 1]! |= 0x80;
      } else {
        bytes.push(0x80);
      }
    } else {
      if ((bytes[bytes.length - 1]! & 0x80) !== 0) {
        bytes.push(0x00);
      }
    }
  }

  // Pad or truncate to requested length
  while (bytes.length < byteLen) bytes.push(0x00);
  bytes.length = byteLen;

  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
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
