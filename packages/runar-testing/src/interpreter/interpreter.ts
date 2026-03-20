/**
 * Rúnar Reference Interpreter — a definitional interpreter that directly
 * executes the Rúnar AST without compiling to Bitcoin Script.
 *
 * This serves as a semantic oracle for testing: given the same inputs,
 * the interpreter and the compiled+executed Bitcoin Script should produce
 * equivalent results.
 *
 * We import types from runar-ir-schema (the Rúnar AST definitions).
 */

import { createHash } from 'node:crypto';
import { wotsVerify as wotsVerifyImpl } from '../crypto/wots.js';
import {
  slhVerify as slhVerifyImpl,
  SLH_SHA2_128s, SLH_SHA2_128f,
  SLH_SHA2_192s, SLH_SHA2_192f,
  SLH_SHA2_256s, SLH_SHA2_256f,
} from '../crypto/slh-dsa.js';
import { verifyTestMessageSig } from '../crypto/ecdsa.js';
import { rabinVerify as rabinVerifyImpl } from '../crypto/rabin.js';
import type {
  ContractNode,
  MethodNode,
  Statement,
  Expression,
  BinaryOp,
  UnaryOp,
} from 'runar-ir-schema';
import { hexToBytes } from '../vm/utils.js';

// ---------------------------------------------------------------------------
// Interpreter value types
// ---------------------------------------------------------------------------

export type RunarValue =
  | { kind: 'bigint'; value: bigint }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'bytes'; value: Uint8Array }
  | { kind: 'void' };

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface InterpreterResult {
  success: boolean;
  error?: string;
  returnValue?: RunarValue;
}

// ---------------------------------------------------------------------------
// Internal exceptions for control flow
// ---------------------------------------------------------------------------

class AssertionError extends Error {
  constructor(message?: string) {
    super(message ?? 'assert failed');
    this.name = 'AssertionError';
  }
}

class ReturnException {
  constructor(public readonly value: RunarValue | undefined) {}
}

// ---------------------------------------------------------------------------
// Environment (lexical scope)
// ---------------------------------------------------------------------------

class Environment {
  private readonly scopes: Map<string, RunarValue>[] = [];

  constructor(initial?: Map<string, RunarValue>) {
    this.scopes.push(initial ?? new Map());
  }

  pushScope(): void {
    this.scopes.push(new Map());
  }

  popScope(): void {
    if (this.scopes.length <= 1) {
      throw new Error('Cannot pop the root scope');
    }
    this.scopes.pop();
  }

  get(name: string): RunarValue {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const scope = this.scopes[i]!;
      if (scope.has(name)) {
        return scope.get(name)!;
      }
    }
    throw new Error(`Undefined variable: ${name}`);
  }

  set(name: string, value: RunarValue): void {
    // Try to find and update in existing scopes first (assignment).
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const scope = this.scopes[i]!;
      if (scope.has(name)) {
        scope.set(name, value);
        return;
      }
    }
    // Otherwise define in the current (innermost) scope.
    this.scopes[this.scopes.length - 1]!.set(name, value);
  }

  define(name: string, value: RunarValue): void {
    this.scopes[this.scopes.length - 1]!.set(name, value);
  }
}

// ---------------------------------------------------------------------------
// RunarInterpreter
// ---------------------------------------------------------------------------

export class RunarInterpreter {
  private readonly props: Map<string, RunarValue>;
  private _outputs: { satoshis: RunarValue; stateValues: Record<string, RunarValue> }[] = [];
  private _contract: ContractNode | null = null;
  private _mockPreimage: Record<string, bigint> = {
    locktime: 0n,
    amount: 10000n,
    version: 1n,
    sequence: 0xfffffffen,
  };
  private _mockPreimageBytes: Record<string, Uint8Array> = {};

  /**
   * @param properties - Contract constructor properties (name -> value).
   */
  constructor(properties: Record<string, RunarValue>) {
    this.props = new Map();
    for (const [k, v] of Object.entries(properties)) {
      this.props.set(k, v);
    }
  }

  setContract(contract: ContractNode): void { this._contract = contract; }
  setMockPreimage(overrides: Record<string, bigint>): void { Object.assign(this._mockPreimage, overrides); }
  setMockPreimageBytes(overrides: Record<string, Uint8Array>): void { Object.assign(this._mockPreimageBytes, overrides); }
  resetOutputs(): void { this._outputs = []; }
  getOutputs(): { satoshis: RunarValue; stateValues: Record<string, RunarValue> }[] { return [...this._outputs]; }
  getState(): Record<string, RunarValue> {
    const state: Record<string, RunarValue> = {};
    for (const [k, v] of this.props) state[k] = v;
    return state;
  }

  /**
   * Execute a public method on a parsed Rúnar contract AST.
   *
   * @param contract  - The parsed ContractNode (Rúnar AST).
   * @param methodName - Name of the public method to execute.
   * @param args      - Method arguments (name -> value).
   */
  executeMethod(
    contract: ContractNode,
    methodName: string,
    args: Record<string, RunarValue>,
  ): InterpreterResult {
    const method = contract.methods.find(
      (m) => m.name === methodName && m.visibility === 'public',
    );
    if (!method) {
      return { success: false, error: `Method not found: ${methodName}` };
    }

    // Build the initial environment with method parameters.
    const initMap = new Map<string, RunarValue>();
    for (const param of method.params) {
      const arg = args[param.name];
      if (arg === undefined) {
        return {
          success: false,
          error: `Missing argument: ${param.name}`,
        };
      }
      initMap.set(param.name, arg);
    }

    const env = new Environment(initMap);

    try {
      const returnValue = this.executeStatements(method.body, env, contract.methods);
      return { success: true, returnValue: returnValue ?? { kind: 'void' } };
    } catch (e) {
      if (e instanceof AssertionError) {
        return { success: false, error: e.message };
      }
      if (e instanceof Error) {
        return { success: false, error: e.message };
      }
      return { success: false, error: String(e) };
    }
  }

  // -------------------------------------------------------------------------
  // Statement execution
  // -------------------------------------------------------------------------

  private executeStatements(
    stmts: Statement[],
    env: Environment,
    methods: MethodNode[],
  ): RunarValue | undefined {
    for (const stmt of stmts) {
      try {
        this.executeStatement(stmt, env, methods);
      } catch (e) {
        if (e instanceof ReturnException) {
          return e.value ?? { kind: 'void' };
        }
        throw e;
      }
    }
    return undefined;
  }

  private executeStatement(
    stmt: Statement,
    env: Environment,
    methods: MethodNode[],
  ): void {
    switch (stmt.kind) {
      case 'variable_decl': {
        const value = this.evalExpr(stmt.init, env, methods);
        env.define(stmt.name, value);
        break;
      }

      case 'assignment': {
        const value = this.evalExpr(stmt.value, env, methods);
        if (stmt.target.kind === 'identifier') {
          env.set(stmt.target.name, value);
        } else if (stmt.target.kind === 'property_access') {
          this.props.set(stmt.target.property, value);
        } else {
          throw new Error(`Cannot assign to expression of kind: ${stmt.target.kind}`);
        }
        break;
      }

      case 'if_statement': {
        const cond = this.evalExpr(stmt.condition, env, methods);
        let ifReturnVal: RunarValue | undefined;
        if (this.toBool(cond)) {
          env.pushScope();
          try {
            ifReturnVal = this.executeStatements(stmt.then, env, methods);
          } finally {
            env.popScope();
          }
        } else if (stmt.else) {
          env.pushScope();
          try {
            ifReturnVal = this.executeStatements(stmt.else, env, methods);
          } finally {
            env.popScope();
          }
        }
        if (ifReturnVal !== undefined) {
          throw new ReturnException(ifReturnVal);
        }
        break;
      }

      case 'for_statement': {
        env.pushScope();
        try {
          // Init
          this.executeStatement(stmt.init, env, methods);
          // Bounded loop: evaluate condition, execute body, update
          const MAX_ITERATIONS = 100_000;
          let iterations = 0;
          while (this.toBool(this.evalExpr(stmt.condition, env, methods))) {
            if (iterations++ > MAX_ITERATIONS) {
              throw new Error('Loop iteration limit exceeded');
            }
            env.pushScope();
            let forReturnVal: RunarValue | undefined;
            try {
              forReturnVal = this.executeStatements(stmt.body, env, methods);
            } finally {
              env.popScope();
            }
            if (forReturnVal !== undefined) {
              throw new ReturnException(forReturnVal);
            }
            this.executeStatement(stmt.update, env, methods);
          }
        } finally {
          env.popScope();
        }
        break;
      }

      case 'return_statement': {
        const value = stmt.value
          ? this.evalExpr(stmt.value, env, methods)
          : undefined;
        throw new ReturnException(value);
      }

      case 'expression_statement': {
        this.evalExpr(stmt.expression, env, methods);
        break;
      }

      default: {
        const _exhaustive: never = stmt;
        throw new Error(`Unknown statement kind: ${(_exhaustive as Statement).kind}`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Expression evaluation
  // -------------------------------------------------------------------------

  private evalExpr(
    expr: Expression,
    env: Environment,
    methods: MethodNode[],
  ): RunarValue {
    switch (expr.kind) {
      case 'bigint_literal':
        return { kind: 'bigint', value: expr.value };

      case 'bool_literal':
        return { kind: 'boolean', value: expr.value };

      case 'bytestring_literal':
        return { kind: 'bytes', value: hexToBytes(expr.value) };

      case 'identifier':
        return env.get(expr.name);

      case 'property_access': {
        if (expr.property === 'txPreimage') {
          // Return mock preimage bytes (181 zero bytes — valid BIP-143 length)
          return { kind: 'bytes', value: new Uint8Array(181) };
        }
        const val = this.props.get(expr.property);
        if (val === undefined) {
          throw new Error(`Undefined property: this.${expr.property}`);
        }
        return val;
      }

      case 'binary_expr':
        return this.evalBinaryExpr(expr.op, expr.left, expr.right, env, methods);

      case 'unary_expr':
        return this.evalUnaryExpr(expr.op, expr.operand, env, methods);

      case 'call_expr':
        return this.evalCallExpr(expr.callee, expr.args, env, methods);

      case 'member_expr': {
        // Evaluate the object and access a member.
        const obj = this.evalExpr(expr.object, env, methods);
        // For bytes, support `.length`
        if (obj.kind === 'bytes' && expr.property === 'length') {
          return { kind: 'bigint', value: BigInt(obj.value.length) };
        }
        throw new Error(
          `Cannot access property '${expr.property}' on ${obj.kind}`,
        );
      }

      case 'ternary_expr': {
        const cond = this.evalExpr(expr.condition, env, methods);
        if (this.toBool(cond)) {
          return this.evalExpr(expr.consequent, env, methods);
        }
        return this.evalExpr(expr.alternate, env, methods);
      }

      case 'index_access': {
        const obj = this.evalExpr(expr.object, env, methods);
        const idx = this.evalExpr(expr.index, env, methods);
        if (obj.kind === 'bytes' && idx.kind === 'bigint') {
          const i = Number(idx.value);
          if (i < 0 || i >= obj.value.length) {
            throw new Error(`Index out of bounds: ${i}`);
          }
          return { kind: 'bigint', value: BigInt(obj.value[i]!) };
        }
        throw new Error(`Cannot index ${obj.kind} with ${idx.kind}`);
      }

      case 'increment_expr': {
        const operand = this.evalExpr(expr.operand, env, methods);
        if (operand.kind !== 'bigint') {
          throw new Error('Increment requires bigint');
        }
        const newVal: RunarValue = { kind: 'bigint', value: operand.value + 1n };
        this.assignTarget(expr.operand, newVal, env);
        return expr.prefix ? newVal : operand;
      }

      case 'decrement_expr': {
        const operand = this.evalExpr(expr.operand, env, methods);
        if (operand.kind !== 'bigint') {
          throw new Error('Decrement requires bigint');
        }
        const newVal: RunarValue = { kind: 'bigint', value: operand.value - 1n };
        this.assignTarget(expr.operand, newVal, env);
        return expr.prefix ? newVal : operand;
      }

      case 'array_literal': {
        // Array literals are not supported at runtime — they exist for
        // compile-time constructs only. Throw if encountered during interpretation.
        throw new Error('Array literals are not supported in the interpreter');
      }

      default: {
        const _exhaustive: never = expr;
        throw new Error(`Unknown expression kind: ${(_exhaustive as Expression).kind}`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Binary expression evaluation
  // -------------------------------------------------------------------------

  private evalBinaryExpr(
    op: BinaryOp,
    leftExpr: Expression,
    rightExpr: Expression,
    env: Environment,
    methods: MethodNode[],
  ): RunarValue {
    // Short-circuit for logical operators.
    if (op === '&&') {
      const left = this.evalExpr(leftExpr, env, methods);
      if (!this.toBool(left)) return { kind: 'boolean', value: false };
      const right = this.evalExpr(rightExpr, env, methods);
      return { kind: 'boolean', value: this.toBool(right) };
    }

    if (op === '||') {
      const left = this.evalExpr(leftExpr, env, methods);
      if (this.toBool(left)) return { kind: 'boolean', value: true };
      const right = this.evalExpr(rightExpr, env, methods);
      return { kind: 'boolean', value: this.toBool(right) };
    }

    const left = this.evalExpr(leftExpr, env, methods);
    const right = this.evalExpr(rightExpr, env, methods);

    // Arithmetic operations (bigint, bigint) -> bigint
    if (left.kind === 'bigint' && right.kind === 'bigint') {
      switch (op) {
        case '+': return { kind: 'bigint', value: left.value + right.value };
        case '-': return { kind: 'bigint', value: left.value - right.value };
        case '*': return { kind: 'bigint', value: left.value * right.value };
        case '/': {
          if (right.value === 0n) throw new Error('Division by zero');
          return { kind: 'bigint', value: left.value / right.value };
        }
        case '%': {
          if (right.value === 0n) throw new Error('Modulo by zero');
          return { kind: 'bigint', value: left.value % right.value };
        }
        case '&': return { kind: 'bigint', value: left.value & right.value };
        case '|': return { kind: 'bigint', value: left.value | right.value };
        case '^': return { kind: 'bigint', value: left.value ^ right.value };
        case '<<': return { kind: 'bigint', value: left.value << right.value };
        case '>>': return { kind: 'bigint', value: left.value >> right.value };
        case '===': return { kind: 'boolean', value: left.value === right.value };
        case '!==': return { kind: 'boolean', value: left.value !== right.value };
        case '<': return { kind: 'boolean', value: left.value < right.value };
        case '<=': return { kind: 'boolean', value: left.value <= right.value };
        case '>': return { kind: 'boolean', value: left.value > right.value };
        case '>=': return { kind: 'boolean', value: left.value >= right.value };
      }
    }

    // Boolean comparisons
    if (left.kind === 'boolean' && right.kind === 'boolean') {
      switch (op) {
        case '===': return { kind: 'boolean', value: left.value === right.value };
        case '!==': return { kind: 'boolean', value: left.value !== right.value };
      }
    }

    // Bytes comparisons
    if (left.kind === 'bytes' && right.kind === 'bytes') {
      switch (op) {
        case '===': return { kind: 'boolean', value: bytesEqual(left.value, right.value) };
        case '!==': return { kind: 'boolean', value: !bytesEqual(left.value, right.value) };
        case '+': {
          // Concatenation
          const result = new Uint8Array(left.value.length + right.value.length);
          result.set(left.value, 0);
          result.set(right.value, left.value.length);
          return { kind: 'bytes', value: result };
        }
      }
    }

    throw new Error(
      `Unsupported binary operation: ${left.kind} ${op} ${right.kind}`,
    );
  }

  // -------------------------------------------------------------------------
  // Unary expression evaluation
  // -------------------------------------------------------------------------

  private evalUnaryExpr(
    op: UnaryOp,
    operandExpr: Expression,
    env: Environment,
    methods: MethodNode[],
  ): RunarValue {
    const operand = this.evalExpr(operandExpr, env, methods);

    switch (op) {
      case '!': {
        return { kind: 'boolean', value: !this.toBool(operand) };
      }
      case '-': {
        if (operand.kind !== 'bigint') {
          throw new Error(`Cannot negate ${operand.kind}`);
        }
        return { kind: 'bigint', value: -operand.value };
      }
      case '~': {
        if (operand.kind !== 'bigint') {
          throw new Error(`Cannot bitwise-not ${operand.kind}`);
        }
        // Bitwise NOT for bigint: ~n = -(n + 1)
        return { kind: 'bigint', value: ~operand.value };
      }
    }
  }

  // -------------------------------------------------------------------------
  // Function call evaluation
  // -------------------------------------------------------------------------

  private evalCallExpr(
    callee: Expression,
    argExprs: Expression[],
    env: Environment,
    methods: MethodNode[],
  ): RunarValue {
    // Handle this.method() where callee is property_access
    if (callee.kind === 'property_access') {
      const methodName = callee.property;

      if (methodName === 'addOutput') {
        const evaluatedArgs = argExprs.map(a => this.evalExpr(a, env, methods));
        const satoshis = evaluatedArgs[0]!;
        const stateValues: Record<string, RunarValue> = {};
        if (this._contract) {
          const mutableProps = this._contract.properties.filter(p => !p.readonly);
          for (let i = 0; i < mutableProps.length && i + 1 < evaluatedArgs.length; i++) {
            stateValues[mutableProps[i]!.name] = evaluatedArgs[i + 1]!;
          }
        }
        this._outputs.push({ satoshis, stateValues });
        return { kind: 'void' };
      }

      if (methodName === 'addRawOutput') {
        const evaluatedArgs = argExprs.map(a => this.evalExpr(a, env, methods));
        const satoshis = evaluatedArgs[0]!;
        const scriptBytes = evaluatedArgs[1]!;
        this._outputs.push({ satoshis, stateValues: { _rawScript: scriptBytes } });
        return { kind: 'void' };
      }

      if (methodName === 'getStateScript') {
        return { kind: 'bytes', value: new Uint8Array(0) };
      }

      if (methodName === 'buildP2PKH') {
        return { kind: 'bytes', value: new Uint8Array(25) };
      }

      // Fall through to regular method resolution — set funcName and continue
      // Actually, private method calls via this.method() come through here too.
      // Evaluate args and try to find the private method.
      const evaluatedArgs = argExprs.map(a => this.evalExpr(a, env, methods));
      const method = methods.find(m => m.name === methodName);
      if (method) {
        return this.executePrivateMethod(method, evaluatedArgs, env, methods);
      }
      throw new Error(`Unknown method: this.${methodName}`);
    }

    // Determine function name.
    let funcName: string;
    if (callee.kind === 'identifier') {
      funcName = callee.name;
    } else if (callee.kind === 'member_expr') {
      // e.g. this.somePrivateMethod(...)
      // For now, only support method calls on 'this'.
      if (callee.object.kind === 'identifier' && callee.object.name === 'this') {
        funcName = callee.property;
      } else {
        throw new Error('Only this.method() calls are supported');
      }
    } else {
      throw new Error(`Cannot call expression of kind: ${callee.kind}`);
    }

    const args = argExprs.map((a) => this.evalExpr(a, env, methods));

    // Built-in functions.
    switch (funcName) {
      case 'assert': {
        if (args.length < 1) throw new Error('assert requires at least one argument');
        if (!this.toBool(args[0]!)) {
          const msg =
            args.length > 1 && args[1]!.kind === 'bytes'
              ? new TextDecoder().decode(args[1]!.value)
              : 'assert failed';
          throw new AssertionError(msg);
        }
        return { kind: 'void' };
      }

      case 'exit': {
        if (args.length < 1) throw new Error('exit requires at least one argument');
        if (!this.toBool(args[0]!)) {
          throw new AssertionError('exit(false)');
        }
        return { kind: 'void' };
      }

      case 'pack': {
        // Convert bigint to its byte representation
        return { kind: 'bytes', value: this.toBytes(args[0]!) };
      }

      case 'unpack': {
        // Convert byte representation to bigint
        return { kind: 'bigint', value: this.toBigInt(args[0]!) };
      }

      case 'toByteString': {
        // Identity — already a ByteString
        return args[0]!;
      }

      case 'sha256': {
        const data = this.toBytes(args[0]!);
        const hash = createHash('sha256').update(data).digest();
        return { kind: 'bytes', value: new Uint8Array(hash) };
      }

      case 'ripemd160': {
        const data = this.toBytes(args[0]!);
        const hash = createHash('ripemd160').update(data).digest();
        return { kind: 'bytes', value: new Uint8Array(hash) };
      }

      case 'hash160': {
        const data = this.toBytes(args[0]!);
        const sha = createHash('sha256').update(data).digest();
        const hash = createHash('ripemd160').update(sha).digest();
        return { kind: 'bytes', value: new Uint8Array(hash) };
      }

      case 'hash256': {
        const data = this.toBytes(args[0]!);
        const sha1 = createHash('sha256').update(data).digest();
        const sha2 = createHash('sha256').update(sha1).digest();
        return { kind: 'bytes', value: new Uint8Array(sha2) };
      }

      case 'checkSig': {
        // Real ECDSA verification over the fixed TEST_MESSAGE.
        const sig = this.toBytes(args[0]!);
        const pubKey = this.toBytes(args[1]!);
        return { kind: 'boolean', value: verifyTestMessageSig(sig, pubKey) };
      }

      case 'checkMultiSig': {
        // checkMultiSig is not currently used in any contracts.
        // When array types are added to the interpreter, this should
        // verify each sig against the pubkeys using verifyTestMessageSig.
        return { kind: 'boolean', value: false };
      }

      case 'len': {
        const data = this.toBytes(args[0]!);
        return { kind: 'bigint', value: BigInt(data.length) };
      }

      case 'cat': {
        const a = this.toBytes(args[0]!);
        const b = this.toBytes(args[1]!);
        const result = new Uint8Array(a.length + b.length);
        result.set(a, 0);
        result.set(b, a.length);
        return { kind: 'bytes', value: result };
      }

      case 'substr': {
        const data = this.toBytes(args[0]!);
        const start = this.toBigInt(args[1]!);
        const length = this.toBigInt(args[2]!);
        return {
          kind: 'bytes',
          value: data.slice(Number(start), Number(start) + Number(length)),
        };
      }

      case 'left': {
        const data = this.toBytes(args[0]!);
        const length = this.toBigInt(args[1]!);
        return { kind: 'bytes', value: data.slice(0, Number(length)) };
      }

      case 'right': {
        const data = this.toBytes(args[0]!);
        const length = this.toBigInt(args[1]!);
        return {
          kind: 'bytes',
          value: data.slice(data.length - Number(length)),
        };
      }

      case 'split': {
        // OP_SPLIT pushes [left, right] on the stack. The compiler's
        // stack-lower.ts binds the top-of-stack (right part) as the
        // result. The interpreter must match this convention.
        const data = this.toBytes(args[0]!);
        const index = this.toBigInt(args[1]!);
        return { kind: 'bytes', value: data.slice(Number(index)) };
      }

      case 'reverseBytes': {
        const data = this.toBytes(args[0]!);
        const reversed = new Uint8Array(data.length);
        for (let j = 0; j < data.length; j++) {
          reversed[j] = data[data.length - 1 - j]!;
        }
        return { kind: 'bytes', value: reversed };
      }

      case 'num2bin': {
        const value = this.toBigInt(args[0]!);
        const byteLen = this.toBigInt(args[1]!);
        // Simple implementation: encode as script number, then pad/trim.
        const { encodeScriptNumber: encode } = await_import_utils();
        const encoded = encode(value);
        const result = new Uint8Array(Number(byteLen));
        result.set(encoded.slice(0, Math.min(encoded.length, result.length)), 0);
        if (encoded.length > 0 && encoded.length < result.length) {
          const lastByte = encoded[encoded.length - 1]!;
          if (lastByte & 0x80) {
            result[encoded.length - 1] = lastByte & 0x7f;
            result[result.length - 1] = 0x80;
          }
        }
        return { kind: 'bytes', value: result };
      }

      case 'bin2num': {
        const data = this.toBytes(args[0]!);
        const { decodeScriptNumber: decode } = await_import_utils();
        return { kind: 'bigint', value: decode(data) };
      }

      case 'int2str': {
        // Alias for num2bin.
        const value = this.toBigInt(args[0]!);
        const byteLen = this.toBigInt(args[1]!);
        const { encodeScriptNumber: encode } = await_import_utils();
        const encoded = encode(value);
        const result = new Uint8Array(Number(byteLen));
        result.set(encoded.slice(0, Math.min(encoded.length, result.length)), 0);
        if (encoded.length > 0 && encoded.length < result.length) {
          const lastByte = encoded[encoded.length - 1]!;
          if (lastByte & 0x80) {
            result[encoded.length - 1] = lastByte & 0x7f;
            result[result.length - 1] = 0x80;
          }
        }
        return { kind: 'bytes', value: result };
      }

      case 'abs': {
        const n = this.toBigInt(args[0]!);
        return { kind: 'bigint', value: n < 0n ? -n : n };
      }

      case 'min': {
        const a = this.toBigInt(args[0]!);
        const b = this.toBigInt(args[1]!);
        return { kind: 'bigint', value: a < b ? a : b };
      }

      case 'max': {
        const a = this.toBigInt(args[0]!);
        const b = this.toBigInt(args[1]!);
        return { kind: 'bigint', value: a > b ? a : b };
      }

      case 'within': {
        const value = this.toBigInt(args[0]!);
        const min = this.toBigInt(args[1]!);
        const max = this.toBigInt(args[2]!);
        return { kind: 'boolean', value: value >= min && value < max };
      }

      case 'safediv': {
        const a = this.toBigInt(args[0]!);
        const b = this.toBigInt(args[1]!);
        if (b === 0n) throw new Error('safediv: division by zero');
        return { kind: 'bigint', value: a / b };
      }

      case 'safemod': {
        const a = this.toBigInt(args[0]!);
        const b = this.toBigInt(args[1]!);
        if (b === 0n) throw new Error('safemod: modulo by zero');
        return { kind: 'bigint', value: a % b };
      }

      case 'clamp': {
        const val = this.toBigInt(args[0]!);
        const lo = this.toBigInt(args[1]!);
        const hi = this.toBigInt(args[2]!);
        return { kind: 'bigint', value: val < lo ? lo : val > hi ? hi : val };
      }

      case 'sign': {
        const n = this.toBigInt(args[0]!);
        return { kind: 'bigint', value: n > 0n ? 1n : n < 0n ? -1n : 0n };
      }

      case 'pow': {
        const base = this.toBigInt(args[0]!);
        const exp = this.toBigInt(args[1]!);
        if (exp < 0n) throw new Error('pow: negative exponent');
        let result = 1n;
        for (let i = 0n; i < exp; i++) result *= base;
        return { kind: 'bigint', value: result };
      }

      case 'mulDiv': {
        const a = this.toBigInt(args[0]!);
        const b = this.toBigInt(args[1]!);
        const c = this.toBigInt(args[2]!);
        if (c === 0n) throw new Error('mulDiv: division by zero');
        return { kind: 'bigint', value: (a * b) / c };
      }

      case 'percentOf': {
        const amount = this.toBigInt(args[0]!);
        const bps = this.toBigInt(args[1]!);
        return { kind: 'bigint', value: (amount * bps) / 10000n };
      }

      case 'sqrt': {
        const n = this.toBigInt(args[0]!);
        if (n < 0n) throw new Error('sqrt: negative input');
        if (n === 0n) return { kind: 'bigint', value: 0n };
        let guess = n;
        for (let i = 0; i < 256; i++) {
          const next = (guess + n / guess) / 2n;
          if (next >= guess) break;
          guess = next;
        }
        return { kind: 'bigint', value: guess };
      }

      case 'gcd': {
        let a = this.toBigInt(args[0]!);
        let b = this.toBigInt(args[1]!);
        a = a < 0n ? -a : a;
        b = b < 0n ? -b : b;
        while (b !== 0n) {
          const temp = b;
          b = a % b;
          a = temp;
        }
        return { kind: 'bigint', value: a };
      }

      case 'divmod': {
        const a = this.toBigInt(args[0]!);
        const b = this.toBigInt(args[1]!);
        if (b === 0n) throw new Error('divmod: division by zero');
        return { kind: 'bigint', value: a / b };
      }

      case 'log2': {
        const n = this.toBigInt(args[0]!);
        if (n <= 0n) return { kind: 'bigint', value: 0n };
        let bits = 0n;
        let val = n;
        while (val > 1n) { val >>= 1n; bits++; }
        return { kind: 'bigint', value: bits };
      }

      case 'bool': {
        const n = this.toBigInt(args[0]!);
        return { kind: 'boolean', value: n !== 0n };
      }

      case 'checkPreimage':
        return { kind: 'boolean', value: true };

      case 'verifyRabinSig': {
        // Real Rabin verification: (sig² + padding) mod n === SHA256(msg) mod n
        const rabinMsg = this.toBytes(args[0]!);
        const rabinSig = this.toBigInt(args[1]!);
        const rabinPad = this.toBytes(args[2]!);
        const rabinPk = this.toBigInt(args[3]!);
        return { kind: 'boolean', value: rabinVerifyImpl(rabinMsg, rabinSig, rabinPad, rabinPk) };
      }

      case 'verifyWOTS': {
        const wotsMsg = this.toBytes(args[0]!);
        const wotsSig = this.toBytes(args[1]!);
        const wotsPk = this.toBytes(args[2]!);
        return { kind: 'boolean', value: wotsVerifyImpl(wotsMsg, wotsSig, wotsPk) };
      }

      case 'verifySLHDSA_SHA2_128s':
      case 'verifySLHDSA_SHA2_128f':
      case 'verifySLHDSA_SHA2_192s':
      case 'verifySLHDSA_SHA2_192f':
      case 'verifySLHDSA_SHA2_256s':
      case 'verifySLHDSA_SHA2_256f': {
        const slhParamsMap: Record<string, typeof SLH_SHA2_128s> = {
          verifySLHDSA_SHA2_128s: SLH_SHA2_128s,
          verifySLHDSA_SHA2_128f: SLH_SHA2_128f,
          verifySLHDSA_SHA2_192s: SLH_SHA2_192s,
          verifySLHDSA_SHA2_192f: SLH_SHA2_192f,
          verifySLHDSA_SHA2_256s: SLH_SHA2_256s,
          verifySLHDSA_SHA2_256f: SLH_SHA2_256f,
        };
        const slhMsg = this.toBytes(args[0]!);
        const slhSig = this.toBytes(args[1]!);
        const slhPk = this.toBytes(args[2]!);
        const params = slhParamsMap[funcName]!;
        return { kind: 'boolean', value: slhVerifyImpl(params, slhMsg, slhSig, slhPk) };
      }

      case 'extractLocktime':
        return { kind: 'bigint', value: this._mockPreimage.locktime ?? 0n };

      case 'extractAmount':
        return { kind: 'bigint', value: this._mockPreimage.amount ?? 10000n };

      case 'extractVersion':
        return { kind: 'bigint', value: this._mockPreimage.version ?? 1n };

      case 'extractSequence':
        return { kind: 'bigint', value: this._mockPreimage.sequence ?? 0xfffffffen };

      case 'extractOutputHash':
      case 'extractOutputs':
        return { kind: 'bytes', value: this._mockPreimageBytes['outputHash'] ?? new Uint8Array(32) };

      case 'extractHashPrevouts':
        return { kind: 'bytes', value: this._mockPreimageBytes['hashPrevouts'] ?? new Uint8Array(32) };

      case 'extractHashSequence':
        return { kind: 'bytes', value: this._mockPreimageBytes['hashSequence'] ?? new Uint8Array(32) };

      case 'extractOutpoint':
        return { kind: 'bytes', value: this._mockPreimageBytes['outpoint'] ?? new Uint8Array(36) };

      case 'extractInputIndex':
        return { kind: 'bigint', value: 0n };

      case 'extractScriptCode':
        return { kind: 'bytes', value: new Uint8Array(0) };

      case 'extractSigHashType':
        return { kind: 'bigint', value: 0x41n };

      // EC builtins
      case 'ecAdd': {
        const pa = this.toBytes(args[0]!);
        const pb = this.toBytes(args[1]!);
        return { kind: 'bytes', value: ecAddImpl(pa, pb) };
      }
      case 'ecMul': {
        const pt = this.toBytes(args[0]!);
        const k = this.toBigInt(args[1]!);
        return { kind: 'bytes', value: ecMulImpl(pt, k) };
      }
      case 'ecMulGen': {
        const k = this.toBigInt(args[0]!);
        return { kind: 'bytes', value: ecMulGenImpl(k) };
      }
      case 'ecNegate': {
        const pt = this.toBytes(args[0]!);
        return { kind: 'bytes', value: ecNegateImpl(pt) };
      }
      case 'ecOnCurve': {
        const pt = this.toBytes(args[0]!);
        return { kind: 'boolean', value: ecOnCurveImpl(pt) };
      }
      case 'ecModReduce': {
        const val = this.toBigInt(args[0]!);
        const mod = this.toBigInt(args[1]!);
        const r = ((val % mod) + mod) % mod;
        return { kind: 'bigint', value: r };
      }
      case 'ecEncodeCompressed': {
        const pt = this.toBytes(args[0]!);
        return { kind: 'bytes', value: ecEncodeCompressedImpl(pt) };
      }
      case 'ecMakePoint': {
        const x = this.toBigInt(args[0]!);
        const y = this.toBigInt(args[1]!);
        return { kind: 'bytes', value: ecMakePointImpl(x, y) };
      }
      case 'ecPointX': {
        const pt = this.toBytes(args[0]!);
        return { kind: 'bigint', value: ecPointXImpl(pt) };
      }
      case 'ecPointY': {
        const pt = this.toBytes(args[0]!);
        return { kind: 'bigint', value: ecPointYImpl(pt) };
      }

      case 'blake3Compress': {
        const cv = this.toBytes(args[0]!);
        const block = this.toBytes(args[1]!);
        return { kind: 'bytes', value: blake3CompressImpl(cv, block) };
      }

      case 'blake3Hash': {
        const msg = this.toBytes(args[0]!);
        // Zero-pad to 64 bytes, use IV as chaining value
        const padded = new Uint8Array(64);
        padded.set(msg.subarray(0, 64));
        return { kind: 'bytes', value: blake3CompressImpl(BLAKE3_IV_BYTES, padded) };
      }

      default: {
        // Try to find a private method in the contract.
        const method = methods.find((m) => m.name === funcName);
        if (method) {
          return this.executePrivateMethod(method, args, env, methods);
        }
        throw new Error(`Unknown function: ${funcName}`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Private method execution
  // -------------------------------------------------------------------------

  private executePrivateMethod(
    method: MethodNode,
    args: RunarValue[],
    _parentEnv: Environment,
    methods: MethodNode[],
  ): RunarValue {
    const methodEnv = new Map<string, RunarValue>();
    for (let j = 0; j < method.params.length; j++) {
      const param = method.params[j]!;
      const arg = args[j];
      if (arg === undefined) {
        throw new Error(`Missing argument for ${param.name}`);
      }
      methodEnv.set(param.name, arg);
    }

    const env = new Environment(methodEnv);
    const result = this.executeStatements(method.body, env, methods);
    return result ?? { kind: 'void' };
  }

  // -------------------------------------------------------------------------
  // Value conversion helpers
  // -------------------------------------------------------------------------

  private toBool(val: RunarValue): boolean {
    switch (val.kind) {
      case 'boolean':
        return val.value;
      case 'bigint':
        return val.value !== 0n;
      case 'bytes':
        return val.value.length > 0 && val.value.some((b) => b !== 0);
      case 'void':
        return false;
    }
  }

  private toBytes(val: RunarValue): Uint8Array {
    switch (val.kind) {
      case 'bytes':
        return val.value;
      case 'bigint': {
        const { encodeScriptNumber: encode } = await_import_utils();
        return encode(val.value);
      }
      case 'boolean':
        return val.value ? new Uint8Array([1]) : new Uint8Array(0);
      case 'void':
        return new Uint8Array(0);
    }
  }

  private toBigInt(val: RunarValue): bigint {
    switch (val.kind) {
      case 'bigint':
        return val.value;
      case 'boolean':
        return val.value ? 1n : 0n;
      case 'bytes': {
        const { decodeScriptNumber: decode } = await_import_utils();
        return decode(val.value);
      }
      case 'void':
        return 0n;
    }
  }

  // -------------------------------------------------------------------------
  // Assignment target helper
  // -------------------------------------------------------------------------

  private assignTarget(expr: Expression, value: RunarValue, env: Environment): void {
    if (expr.kind === 'identifier') {
      env.set(expr.name, value);
    } else if (expr.kind === 'property_access') {
      this.props.set(expr.property, value);
    } else {
      throw new Error(`Cannot assign to expression of kind: ${expr.kind}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Lazy import helper for utils (avoids circular issues at module scope)
// ---------------------------------------------------------------------------

let _utils: {
  encodeScriptNumber: (n: bigint) => Uint8Array;
  decodeScriptNumber: (bytes: Uint8Array) => bigint;
} | undefined;

function await_import_utils() {
  if (!_utils) {
    // Synchronous re-import since utils is already loaded.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    _utils = {
      encodeScriptNumber: encodeScriptNumberLocal,
      decodeScriptNumber: decodeScriptNumberLocal,
    };
  }
  return _utils;
}

/**
 * Local copy of encodeScriptNumber to avoid any import order issues.
 */
function encodeScriptNumberLocal(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0);
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
  return new Uint8Array(bytes);
}

function decodeScriptNumberLocal(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result |= BigInt(bytes[i]!) << BigInt(8 * i);
  }
  const lastByte = bytes[bytes.length - 1]!;
  if (lastByte & 0x80) {
    result &= ~(0x80n << BigInt(8 * (bytes.length - 1)));
    result = -result;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// EC (secp256k1) interpreter helpers
// ---------------------------------------------------------------------------

const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const EC_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const EC_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function ecMod(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

function ecModInv(a: bigint, m: bigint): bigint {
  // Extended Euclidean algorithm
  let [old_r, r] = [ecMod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ecMod(old_s, m);
}

function ecDecodePoint(bytes: Uint8Array): [bigint, bigint] {
  if (bytes.length !== 64) throw new Error(`EC point must be 64 bytes, got ${bytes.length}`);
  let x = 0n;
  let y = 0n;
  for (let i = 0; i < 32; i++) {
    x = (x << 8n) | BigInt(bytes[i]!);
  }
  for (let i = 32; i < 64; i++) {
    y = (y << 8n) | BigInt(bytes[i]!);
  }
  return [x, y];
}

function ecEncodePoint(x: bigint, y: bigint): Uint8Array {
  const bytes = new Uint8Array(64);
  let vx = x;
  let vy = y;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(vx & 0xFFn);
    vx >>= 8n;
  }
  for (let i = 63; i >= 32; i--) {
    bytes[i] = Number(vy & 0xFFn);
    vy >>= 8n;
  }
  return bytes;
}

function ecPointAddCoords(
  x1: bigint, y1: bigint, x2: bigint, y2: bigint,
): [bigint, bigint] {
  const p = EC_P;
  if (x1 === x2 && y1 === y2) {
    // Point doubling
    const s = ecMod(3n * x1 * x1 * ecModInv(2n * y1, p), p);
    const rx = ecMod(s * s - 2n * x1, p);
    const ry = ecMod(s * (x1 - rx) - y1, p);
    return [rx, ry];
  }
  const s = ecMod((y2 - y1) * ecModInv(x2 - x1, p), p);
  const rx = ecMod(s * s - x1 - x2, p);
  const ry = ecMod(s * (x1 - rx) - y1, p);
  return [rx, ry];
}

function ecScalarMul(x: bigint, y: bigint, k: bigint): [bigint, bigint] {
  const n = EC_N;
  k = ecMod(k, n);
  if (k === 0n) throw new Error('ecMul: scalar is 0');
  let rx = x;
  let ry = y;
  let started = false;
  for (let i = 255; i >= 0; i--) {
    if (started) {
      [rx, ry] = ecPointAddCoords(rx, ry, rx, ry); // double
    }
    if ((k >> BigInt(i)) & 1n) {
      if (!started) {
        rx = x;
        ry = y;
        started = true;
      } else {
        [rx, ry] = ecPointAddCoords(rx, ry, x, y); // add
      }
    }
  }
  return [rx, ry];
}

function ecAddImpl(a: Uint8Array, b: Uint8Array): Uint8Array {
  const [ax, ay] = ecDecodePoint(a);
  const [bx, by] = ecDecodePoint(b);
  const [rx, ry] = ecPointAddCoords(ax, ay, bx, by);
  return ecEncodePoint(rx, ry);
}

function ecMulImpl(pt: Uint8Array, k: bigint): Uint8Array {
  const [x, y] = ecDecodePoint(pt);
  const [rx, ry] = ecScalarMul(x, y, k);
  return ecEncodePoint(rx, ry);
}

function ecMulGenImpl(k: bigint): Uint8Array {
  const [rx, ry] = ecScalarMul(EC_GX, EC_GY, k);
  return ecEncodePoint(rx, ry);
}

function ecNegateImpl(pt: Uint8Array): Uint8Array {
  const [x, y] = ecDecodePoint(pt);
  return ecEncodePoint(x, ecMod(EC_P - y, EC_P));
}

function ecOnCurveImpl(pt: Uint8Array): boolean {
  const [x, y] = ecDecodePoint(pt);
  const lhs = ecMod(y * y, EC_P);
  const rhs = ecMod(x * x * x + 7n, EC_P);
  return lhs === rhs;
}

function ecEncodeCompressedImpl(pt: Uint8Array): Uint8Array {
  const [x, y] = ecDecodePoint(pt);
  const prefix = (y & 1n) === 0n ? 0x02 : 0x03;
  const result = new Uint8Array(33);
  result[0] = prefix;
  let vx = x;
  for (let i = 32; i >= 1; i--) {
    result[i] = Number(vx & 0xFFn);
    vx >>= 8n;
  }
  return result;
}

function ecMakePointImpl(x: bigint, y: bigint): Uint8Array {
  return ecEncodePoint(x, y);
}

function ecPointXImpl(pt: Uint8Array): bigint {
  const [x] = ecDecodePoint(pt);
  return x;
}

function ecPointYImpl(pt: Uint8Array): bigint {
  const [, y] = ecDecodePoint(pt);
  return y;
}

// ---------------------------------------------------------------------------
// BLAKE3 interpreter helpers
// ---------------------------------------------------------------------------

const BLAKE3_IV_WORDS = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const BLAKE3_IV_BYTES = new Uint8Array(32);
for (let i = 0; i < 8; i++) {
  BLAKE3_IV_BYTES[i * 4] = (BLAKE3_IV_WORDS[i]! >>> 24) & 0xff;
  BLAKE3_IV_BYTES[i * 4 + 1] = (BLAKE3_IV_WORDS[i]! >>> 16) & 0xff;
  BLAKE3_IV_BYTES[i * 4 + 2] = (BLAKE3_IV_WORDS[i]! >>> 8) & 0xff;
  BLAKE3_IV_BYTES[i * 4 + 3] = BLAKE3_IV_WORDS[i]! & 0xff;
}

const BLAKE3_MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

function blake3Rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function blake3G(
  s: number[], a: number, b: number, c: number, d: number,
  mx: number, my: number,
): void {
  s[a] = (s[a]! + s[b]! + mx) >>> 0;
  s[d] = blake3Rotr32(s[d]! ^ s[a]!, 16);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = blake3Rotr32(s[b]! ^ s[c]!, 12);
  s[a] = (s[a]! + s[b]! + my) >>> 0;
  s[d] = blake3Rotr32(s[d]! ^ s[a]!, 8);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = blake3Rotr32(s[b]! ^ s[c]!, 7);
}

function blake3Round(s: number[], m: number[]): void {
  blake3G(s, 0, 4, 8, 12, m[0]!, m[1]!);
  blake3G(s, 1, 5, 9, 13, m[2]!, m[3]!);
  blake3G(s, 2, 6, 10, 14, m[4]!, m[5]!);
  blake3G(s, 3, 7, 11, 15, m[6]!, m[7]!);
  blake3G(s, 0, 5, 10, 15, m[8]!, m[9]!);
  blake3G(s, 1, 6, 11, 12, m[10]!, m[11]!);
  blake3G(s, 2, 7, 8, 13, m[12]!, m[13]!);
  blake3G(s, 3, 4, 9, 14, m[14]!, m[15]!);
}

/**
 * BLAKE3 single-block compression. Matches the on-chain codegen which
 * hardcodes blockLen=64, counter=0, flags=11 (CHUNK_START|CHUNK_END|ROOT).
 */
function blake3CompressImpl(cv: Uint8Array, block: Uint8Array): Uint8Array {
  // Parse chaining value as 8 big-endian u32 words
  const h: number[] = [];
  for (let i = 0; i < 8; i++) {
    h.push(
      ((cv[i * 4]! << 24) | (cv[i * 4 + 1]! << 16) |
       (cv[i * 4 + 2]! << 8) | cv[i * 4 + 3]!) >>> 0,
    );
  }

  // Parse block as 16 big-endian u32 words
  const m: number[] = [];
  for (let i = 0; i < 16; i++) {
    m.push(
      ((block[i * 4]! << 24) | (block[i * 4 + 1]! << 16) |
       (block[i * 4 + 2]! << 8) | block[i * 4 + 3]!) >>> 0,
    );
  }

  // Initialize 16-word state
  const state: number[] = [
    h[0]!, h[1]!, h[2]!, h[3]!,
    h[4]!, h[5]!, h[6]!, h[7]!,
    BLAKE3_IV_WORDS[0]!, BLAKE3_IV_WORDS[1]!, BLAKE3_IV_WORDS[2]!, BLAKE3_IV_WORDS[3]!,
    0,  // counter low
    0,  // counter high
    64, // blockLen
    11, // flags = CHUNK_START | CHUNK_END | ROOT
  ];

  // 7 rounds with message permutation between rounds
  let msg = [...m];
  for (let r = 0; r < 7; r++) {
    blake3Round(state, msg);
    if (r < 6) msg = BLAKE3_MSG_PERM.map(i => msg[i]!);
  }

  // Output: XOR first 8 with last 8, encode as big-endian bytes
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const w = (state[i]! ^ state[i + 8]!) >>> 0;
    out[i * 4] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>> 8) & 0xff;
    out[i * 4 + 3] = w & 0xff;
  }
  return out;
}
