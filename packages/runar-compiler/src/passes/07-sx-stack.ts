/**
 * Pass 7 helper: SX Stack Scheduler.
 *
 * Tracks named values on a virtual stack and emits BitcoinSX text tokens.
 * Modeled on the StackMap + LoweringContext from 05-stack-lower.ts, but
 * outputs SX text instead of StackOp objects.
 *
 * Key differences from 05-stack-lower:
 * - method_call to private methods emits bare macro name (NOT inline)
 * - loop emits `repeat Nn ... end` with stack-managed counter
 * - Specialized codegen (EC, SHA-256, etc.) goes through the bridge
 */

import type {
  ANFBinding,
  ANFMethod,
  ANFProperty,
  ANFValue,
} from '../ir/index.js';
import type { StackOp } from '../ir/index.js';
import { stackOpsToSX } from './07-sx-codegen-bridge.js';
import { lowerBindingsToOps } from './05-stack-lower.js';
import { emitSha256Compress, emitSha256Finalize } from './sha256-codegen.js';
import { emitBlake3Compress, emitBlake3Hash } from './blake3-codegen.js';
import {
  emitEcAdd, emitEcMul, emitEcMulGen, emitEcNegate,
  emitEcOnCurve, emitEcModReduce, emitEcEncodeCompressed,
  emitEcMakePoint, emitEcPointX, emitEcPointY,
} from './ec-codegen.js';
import { emitVerifySLHDSA } from './slh-dsa-codegen.js';
import {
  emitBBFieldAdd, emitBBFieldSub, emitBBFieldMul, emitBBFieldInv,
  emitBBExt4Mul0, emitBBExt4Mul1, emitBBExt4Mul2, emitBBExt4Mul3,
  emitBBExt4Inv0, emitBBExt4Inv1, emitBBExt4Inv2, emitBBExt4Inv3,
} from './babybear-codegen.js';
import { emitMerkleRootSha256, emitMerkleRootHash256 } from './merkle-codegen.js';

// ---------------------------------------------------------------------------
// Builtin function → SX opcode mapping
// ---------------------------------------------------------------------------

const BUILTIN_SX: Record<string, string[]> = {
  sha256: ['sha256'],
  ripemd160: ['ripemd160'],
  hash160: ['hash160'],
  hash256: ['hash256'],
  checkSig: ['checkSig'],
  checkMultiSig: ['checkMultiSig'],
  len: ['size'],
  cat: ['cat'],
  num2bin: ['num2bin'],
  bin2num: ['bin2num'],
  abs: ['abs'],
  min: ['min'],
  max: ['max'],
  within: ['within'],
  split: ['split'],
  left: ['split', 'drop'],
  int2str: ['num2bin'],
  bool: ['0notEqual'],
  unpack: ['bin2num'],
};

const BINOP_SX: Record<string, string[]> = {
  '+': ['add'],
  '-': ['sub'],
  '*': ['mul'],
  '/': ['div'],
  '%': ['mod'],
  '===': ['numEqual'],
  '!==': ['numEqual', 'not'],
  '<': ['lessThan'],
  '>': ['greaterThan'],
  '<=': ['lessThanOrEqual'],
  '>=': ['greaterThanOrEqual'],
  '&&': ['boolAnd'],
  '||': ['boolOr'],
  '&': ['and'],
  '|': ['or'],
  '^': ['xor'],
  '<<': ['lshift'],
  '>>': ['rshift'],
};

const UNARYOP_SX: Record<string, string[]> = {
  '!': ['not'],
  '-': ['negate'],
  '~': ['invert'],
};

// ---------------------------------------------------------------------------
// Stack map — tracks named values on the stack
// ---------------------------------------------------------------------------

class StackMap {
  private slots: (string | null)[];

  constructor(initial: string[] = []) {
    this.slots = [...initial];
  }

  get depth(): number {
    return this.slots.length;
  }

  push(name: string | null): void {
    this.slots.push(name);
  }

  pop(): string | null {
    if (this.slots.length === 0) throw new Error('Stack underflow');
    return this.slots.pop()!;
  }

  findDepth(name: string): number {
    for (let i = this.slots.length - 1; i >= 0; i--) {
      if (this.slots[i] === name) return this.slots.length - 1 - i;
    }
    throw new Error(`Value '${name}' not found on stack`);
  }

  has(name: string): boolean {
    return this.slots.includes(name);
  }

  removeAtDepth(depthFromTop: number): string | null {
    const index = this.slots.length - 1 - depthFromTop;
    if (index < 0 || index >= this.slots.length) throw new Error(`Invalid stack depth: ${depthFromTop}`);
    const [removed] = this.slots.splice(index, 1);
    return removed ?? null;
  }

  peekAtDepth(depthFromTop: number): string | null {
    const index = this.slots.length - 1 - depthFromTop;
    if (index < 0 || index >= this.slots.length) throw new Error(`Invalid stack depth: ${depthFromTop}`);
    return this.slots[index] ?? null;
  }

  clone(): StackMap {
    const m = new StackMap();
    m.slots = [...this.slots];
    return m;
  }

  swap(): void {
    const len = this.slots.length;
    if (len < 2) throw new Error('Stack underflow on swap');
    const tmp = this.slots[len - 1]!;
    this.slots[len - 1] = this.slots[len - 2]!;
    this.slots[len - 2] = tmp;
  }

  dup(): void {
    if (this.slots.length < 1) throw new Error('Stack underflow on dup');
    this.slots.push(this.slots[this.slots.length - 1]!);
  }

  namedSlots(): Set<string> {
    const names = new Set<string>();
    for (const s of this.slots) {
      if (s !== null) names.add(s);
    }
    return names;
  }

  renameAtDepth(depthFromTop: number, newName: string | null): void {
    const index = this.slots.length - 1 - depthFromTop;
    if (index < 0 || index >= this.slots.length) throw new Error(`Invalid stack depth for rename: ${depthFromTop}`);
    this.slots[index] = newName;
  }
}

// ---------------------------------------------------------------------------
// Use analysis
// ---------------------------------------------------------------------------

function computeLastUses(bindings: ANFBinding[]): Map<string, number> {
  const lastUse = new Map<string, number>();
  for (let i = 0; i < bindings.length; i++) {
    const refs = collectRefs(bindings[i]!.value);
    for (const ref of refs) {
      lastUse.set(ref, i);
    }
  }
  return lastUse;
}

function collectRefs(value: ANFValue): string[] {
  const refs: string[] = [];
  switch (value.kind) {
    case 'load_param':
      refs.push(value.name);
      break;
    case 'load_prop':
    case 'get_state_script':
      break;
    case 'load_const':
      if (typeof value.value === 'string' && value.value.startsWith('@ref:')) {
        refs.push(value.value.slice(5));
      }
      break;
    case 'add_output':
      refs.push(value.satoshis, ...value.stateValues);
      if (value.preimage) refs.push(value.preimage);
      break;
    case 'add_raw_output':
      refs.push(value.satoshis, value.scriptBytes);
      break;
    case 'bin_op':
      refs.push(value.left, value.right);
      break;
    case 'unary_op':
      refs.push(value.operand);
      break;
    case 'call':
      refs.push(...value.args);
      break;
    case 'method_call':
      refs.push(value.object, ...value.args);
      break;
    case 'if':
      refs.push(value.cond);
      for (const b of value.then) refs.push(...collectRefs(b.value));
      for (const b of value.else) refs.push(...collectRefs(b.value));
      break;
    case 'loop':
      for (const b of value.body) refs.push(...collectRefs(b.value));
      break;
    case 'assert':
      refs.push(value.value);
      break;
    case 'update_prop':
      refs.push(value.value);
      break;
    case 'check_preimage':
      refs.push(value.preimage);
      break;
    case 'deserialize_state':
      refs.push(value.preimage);
      break;
    case 'array_literal':
      refs.push(...value.elements);
      break;
  }
  return refs;
}

// ---------------------------------------------------------------------------
// SX value formatting
// ---------------------------------------------------------------------------

function formatSXValue(value: string | bigint | boolean): string {
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'bigint') return `${value}n`;
  // String — hex-encoded ByteString
  if (value === '') return 'false'; // empty = OP_0
  return `0x${value}`;
}

// ---------------------------------------------------------------------------
// Private method stack effect
// ---------------------------------------------------------------------------

export interface MethodStackEffect {
  consumes: number; // number of args consumed
  produces: number; // 0 or 1 result values
}

/**
 * Pre-analyze a private method to determine its stack effect.
 * Consumes = param count. Produces = 1 unless the method is void
 * (ends in assert or update_prop without producing a value).
 */
export function analyzeMethodStackEffect(method: ANFMethod): MethodStackEffect {
  const consumes = method.params.length;
  const body = method.body;
  if (body.length === 0) return { consumes, produces: 0 };

  const lastValue = body[body.length - 1]!.value;
  // Methods ending in assert or update_prop are void (produce no result)
  if (lastValue.kind === 'assert' || lastValue.kind === 'update_prop') {
    return { consumes, produces: 0 };
  }
  return { consumes, produces: 1 };
}

// ---------------------------------------------------------------------------
// SX Stack Scheduler
// ---------------------------------------------------------------------------

export class SXStackScheduler {
  private stackMap: StackMap;
  private tokens: string[] = [];
  private _properties: ANFProperty[];
  private privateMethods: Map<string, ANFMethod>;
  private methodEffects: Map<string, MethodStackEffect>;
  private localBindings: Set<string> = new Set();
  private outerProtectedRefs: Set<string> | null = null;
  private _insideBranch = false;
  private arrayLengths: Map<string, number> = new Map();
  private constValues: Map<string, bigint | string | boolean> = new Map();
  private _indent: string;

  constructor(
    params: string[],
    properties: ANFProperty[],
    privateMethods: Map<string, ANFMethod> = new Map(),
    indent: string = '',
  ) {
    this.stackMap = new StackMap(params);
    this._properties = properties;
    this.privateMethods = privateMethods;
    this._indent = indent;

    // Pre-analyze stack effects for all private methods
    this.methodEffects = new Map();
    for (const [name, method] of privateMethods) {
      this.methodEffects.set(name, analyzeMethodStackEffect(method));
    }
  }

  /** Get accumulated SX text as a single string, with peephole cleanup. */
  getOutput(): string {
    return peepholeSX(this.tokens).join('\n');
  }

  /** Emit an SX text token. */
  private emit(token: string): void {
    this.tokens.push(`${this._indent}${token}`);
  }

  /** Emit a raw token without indent (for nested structures). */
  private emitRaw(token: string): void {
    this.tokens.push(token);
  }

  // -----------------------------------------------------------------------
  // Stack manipulation → SX text
  // -----------------------------------------------------------------------

  private bringToTop(name: string, consume: boolean): void {
    const depth = this.stackMap.findDepth(name);

    if (depth === 0) {
      if (!consume) {
        this.emit('dup');
        this.stackMap.dup();
      }
      return;
    }

    if (depth === 1 && consume) {
      this.emit('swap');
      this.stackMap.swap();
      return;
    }

    if (consume) {
      if (depth === 2) {
        this.emit('rot');
        const name2 = this.stackMap.removeAtDepth(2);
        this.stackMap.push(name2);
      } else {
        this.emit(`${depth}n roll`);
        const rolled = this.stackMap.removeAtDepth(depth);
        this.stackMap.push(rolled);
      }
    } else {
      if (depth === 1) {
        this.emit('over');
        const name2 = this.stackMap.peekAtDepth(1);
        this.stackMap.push(name2);
      } else {
        this.emit(`${depth}n pick`);
        const picked = this.stackMap.peekAtDepth(depth);
        this.stackMap.push(picked);
      }
    }
  }

  private isLastUse(ref: string, currentIndex: number, lastUses: Map<string, number>): boolean {
    const last = lastUses.get(ref);
    return last === undefined || last <= currentIndex;
  }

  // -----------------------------------------------------------------------
  // Main lowering entry points
  // -----------------------------------------------------------------------

  /**
   * Lower a sequence of ANF bindings to SX text.
   * When terminalAssert is true, the final assert leaves its value on stack.
   */
  lowerBindings(bindings: ANFBinding[], terminalAssert = false): void {
    this.localBindings = new Set(bindings.map(b => b.name));
    const lastUses = computeLastUses(bindings);

    if (this.outerProtectedRefs) {
      for (const ref of this.outerProtectedRefs) {
        lastUses.set(ref, bindings.length);
      }
    }

    let lastAssertIdx = -1;
    let terminalIfIdx = -1;
    if (terminalAssert) {
      const lastBinding = bindings[bindings.length - 1];
      if (lastBinding && lastBinding.value.kind === 'if') {
        terminalIfIdx = bindings.length - 1;
      } else {
        for (let i = bindings.length - 1; i >= 0; i--) {
          if (bindings[i]!.value.kind === 'assert') {
            lastAssertIdx = i;
            break;
          }
        }
      }
    }

    for (let i = 0; i < bindings.length; i++) {
      const binding = bindings[i]!;
      if (binding.value.kind === 'assert' && i === lastAssertIdx) {
        this.lowerAssert(binding.value.value, i, lastUses, true);
      } else if (binding.value.kind === 'if' && i === terminalIfIdx) {
        this.lowerIf(binding.name, binding.value.cond, binding.value.then, binding.value.else, i, lastUses, true);
      } else {
        this.lowerBinding(binding, i, lastUses);
      }
    }
  }

  /** Clean up excess stack items below the result. */
  cleanupExcessStack(): void {
    if (this.stackMap.depth > 1) {
      const excess = this.stackMap.depth - 1;
      for (let i = 0; i < excess; i++) {
        this.emit('nip');
        this.stackMap.removeAtDepth(1);
      }
    }
  }

  private lowerBinding(
    binding: ANFBinding,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    const { name, value } = binding;

    switch (value.kind) {
      case 'load_param':
        this.lowerLoadParam(name, value.name, bindingIndex, lastUses);
        break;
      case 'load_prop':
        this.lowerLoadProp(name, value.name);
        break;
      case 'load_const':
        this.lowerLoadConst(name, value.value, bindingIndex, lastUses);
        break;
      case 'bin_op':
        this.lowerBinOp(name, value.op, value.left, value.right, bindingIndex, lastUses, value.result_type);
        break;
      case 'unary_op':
        this.lowerUnaryOp(name, value.op, value.operand, bindingIndex, lastUses);
        break;
      case 'call':
        this.lowerCall(name, value.func, value.args, bindingIndex, lastUses);
        break;
      case 'method_call':
        this.lowerMethodCall(name, value.object, value.method, value.args, bindingIndex, lastUses);
        break;
      case 'if':
        this.lowerIf(name, value.cond, value.then, value.else, bindingIndex, lastUses);
        break;
      case 'loop':
        this.lowerLoop(name, value.count, value.body, value.iterVar);
        break;
      case 'assert':
        this.lowerAssert(value.value, bindingIndex, lastUses);
        break;
      case 'update_prop':
        this.lowerUpdateProp(value.name, value.value, bindingIndex, lastUses);
        break;
      case 'get_state_script':
        this.lowerGetStateScript(name);
        break;
      case 'check_preimage':
        this.lowerCheckPreimage(name, value.preimage, bindingIndex, lastUses);
        break;
      case 'deserialize_state':
        this.lowerDeserializeState(name, value.preimage, bindingIndex, lastUses);
        break;
      case 'add_output':
        this.lowerAddOutput(name, value.satoshis, value.stateValues, value.preimage, bindingIndex, lastUses);
        break;
      case 'add_raw_output':
        this.lowerAddRawOutput(name, value.satoshis, value.scriptBytes, bindingIndex, lastUses);
        break;
      case 'array_literal':
        this.lowerArrayLiteral(name, value.elements, bindingIndex, lastUses);
        break;
    }
  }

  // -----------------------------------------------------------------------
  // Individual lowering methods
  // -----------------------------------------------------------------------

  private lowerLoadParam(
    bindingName: string,
    paramName: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (this.stackMap.has(paramName)) {
      const isLast = this.isLastUse(paramName, bindingIndex, lastUses);
      this.bringToTop(paramName, isLast);
      this.stackMap.pop();
      this.stackMap.push(bindingName);
    } else {
      this.emit('false');
      this.stackMap.push(bindingName);
    }
  }

  private lowerLoadProp(bindingName: string, propName: string): void {
    const prop = this._properties.find(p => p.name === propName);
    if (this.stackMap.has(propName)) {
      this.bringToTop(propName, false);
      this.stackMap.pop();
    } else if (prop && prop.initialValue !== undefined) {
      this.emit(formatSXValue(prop.initialValue));
    } else {
      // Constructor parameter → SX .variable
      this.emit(`.${propName}`);
    }
    this.stackMap.push(bindingName);
  }

  private lowerLoadConst(
    bindingName: string,
    value: string | bigint | boolean,
    bindingIndex: number = 0,
    lastUses: Map<string, number> = new Map(),
  ): void {
    if (typeof value === 'string' && value.startsWith('@ref:')) {
      const refName = value.slice(5);
      if (this.stackMap.has(refName)) {
        const consume = this.localBindings.has(refName)
          && this.isLastUse(refName, bindingIndex, lastUses);
        this.bringToTop(refName, consume);
        this.stackMap.pop();
        this.stackMap.push(bindingName);
      } else {
        this.emit('false');
        this.stackMap.push(bindingName);
      }
      return;
    }
    if (typeof value === 'string' && (value === '@this' || value === 'this')) {
      this.emit('false');
      this.stackMap.push(bindingName);
      return;
    }
    this.emit(formatSXValue(value));
    this.stackMap.push(bindingName);
    this.constValues.set(bindingName, value);
  }

  private lowerBinOp(
    bindingName: string,
    op: string,
    left: string,
    right: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
    resultType?: string,
  ): void {
    this.bringToTop(left, this.isLastUse(left, bindingIndex, lastUses));
    this.bringToTop(right, this.isLastUse(right, bindingIndex, lastUses));
    this.stackMap.pop();
    this.stackMap.pop();

    if (resultType === 'bytes' && (op === '===' || op === '!==')) {
      this.emit('equal');
      if (op === '!==') this.emit('not');
    } else if (resultType === 'bytes' && op === '+') {
      this.emit('cat');
    } else {
      const sxOps = BINOP_SX[op];
      if (!sxOps) throw new Error(`Unknown binary operator: ${op}`);
      for (const s of sxOps) this.emit(s);
    }

    this.stackMap.push(bindingName);
  }

  private lowerUnaryOp(
    bindingName: string,
    op: string,
    operand: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    this.bringToTop(operand, this.isLastUse(operand, bindingIndex, lastUses));
    this.stackMap.pop();

    const sxOps = UNARYOP_SX[op];
    if (!sxOps) throw new Error(`Unknown unary operator: ${op}`);
    for (const s of sxOps) this.emit(s);

    this.stackMap.push(bindingName);
  }

  private lowerCall(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // assert / exit → value + verify
    if (func === 'assert' || func === 'exit') {
      if (args.length >= 1) {
        this.bringToTop(args[0]!, this.isLastUse(args[0]!, bindingIndex, lastUses));
        this.stackMap.pop();
        this.emit('verify');
        this.stackMap.push(bindingName);
      }
      return;
    }

    // No-op type casts
    if (func === 'pack' || func === 'toByteString') {
      if (args.length >= 1) {
        this.bringToTop(args[0]!, this.isLastUse(args[0]!, bindingIndex, lastUses));
        this.stackMap.pop();
        this.stackMap.push(bindingName);
      }
      return;
    }

    if (func === 'super') {
      this.stackMap.push(bindingName);
      return;
    }

    if (func === '__array_access') {
      this.delegateToHexBackend([{ name: bindingName, value: { kind: 'call', func, args } }]);
      return;
    }

    // Specialized codegen — collect StackOps via bridge
    if (this.trySpecializedCodegen(bindingName, func, args, bindingIndex, lastUses)) {
      return;
    }

    // Complex string/math builtins — delegate to hex backend
    if (func === 'reverseBytes' || func === 'substr' || func === 'right' ||
        func === 'safediv' || func === 'safemod') {
      this.delegateToHexBackend([{ name: bindingName, value: { kind: 'call', func, args } }]);
      return;
    }

    // len() needs special handling (OP_SIZE + OP_NIP)
    if (func === 'len') {
      this.bringToTop(args[0]!, this.isLastUse(args[0]!, bindingIndex, lastUses));
      this.stackMap.pop();
      this.emit('size');
      this.emit('nip');
      this.stackMap.push(bindingName);
      return;
    }

    // split() produces two stack values
    if (func === 'split') {
      for (const arg of args) {
        this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
      }
      for (let j = 0; j < args.length; j++) this.stackMap.pop();
      this.emit('split');
      this.stackMap.push(null);  // left part
      this.stackMap.push(bindingName); // right part (top)
      return;
    }

    // Complex builtins — delegate to hex backend to avoid code duplication.
    // This covers: math builtins, preimage extractors, output builders,
    // multi-sig, and post-quantum signature verification.
    if (func === 'computeStateOutputHash' || func === 'computeStateOutput' ||
        func === 'buildChangeOutput' || func.startsWith('extract') ||
        func === 'verifyWOTS' || func === 'verifyRabinSig' ||
        func === 'pow' || func === 'sqrt' || func === 'gcd' ||
        func === 'divmod' || func === 'log2' ||
        func === 'clamp' || func === 'mulDiv' || func === 'percentOf' || func === 'sign' ||
        func === 'checkMultiSig') {
      this.delegateToHexBackend([{
        name: bindingName,
        value: { kind: 'call', func, args },
      }]);
      return;
    }

    // General builtin — lookup in the SX opcode table
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    for (let j = 0; j < args.length; j++) this.stackMap.pop();

    const sxOps = BUILTIN_SX[func];
    if (!sxOps) {
      // Unknown builtin — emit as comment rather than crashing
      this.emit(`// ${func}() — unknown builtin`);
      this.stackMap.push(bindingName);
      return;
    }
    for (const s of sxOps) this.emit(s);

    this.stackMap.push(bindingName);
  }


  // -----------------------------------------------------------------------
  // Method call → macro invocation
  // -----------------------------------------------------------------------

  private lowerMethodCall(
    bindingName: string,
    object: string,
    method: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (method === 'getStateScript') {
      if (this.stackMap.has(object)) {
        this.bringToTop(object, true);
        this.emit('drop');
        this.stackMap.pop();
      }
      this.lowerGetStateScript(bindingName);
      return;
    }

    const privateMethod = this.privateMethods.get(method);
    if (privateMethod) {
      // Consume @this object reference
      if (this.stackMap.has(object)) {
        this.bringToTop(object, true);
        this.emit('drop');
        this.stackMap.pop();
      }

      // Push all args onto stack in parameter order
      for (const arg of args) {
        this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
      }

      // Emit the macro name (bare call in SX)
      this.emit(method);

      // Update stack tracking: pop args, push result (if any)
      const effect = this.methodEffects.get(method)!;
      for (let i = 0; i < effect.consumes; i++) this.stackMap.pop();
      if (effect.produces > 0) {
        this.stackMap.push(bindingName);
      }
      // Void methods (ending in assert/verify) don't push a result —
      // don't create a phantom binding that would desync the StackMap.
      return;
    }

    // Fallback — treat as builtin
    this.lowerCall(bindingName, method, args, bindingIndex, lastUses);
  }

  // -----------------------------------------------------------------------
  // Loop → repeat Nn ... end
  // -----------------------------------------------------------------------

  private lowerLoop(
    _bindingName: string,
    count: number,
    body: ANFBinding[],
    iterVar: string,
  ): void {
    // Check if iterVar is referenced in the body
    const bodyRefs = new Set<string>();
    for (const b of body) {
      for (const r of collectRefs(b.value)) bodyRefs.add(r);
    }
    const usesIterVar = bodyRefs.has(iterVar);

    if (usesIterVar) {
      // Stack-managed counter: push 0 before repeat, body dups + uses it,
      // increments at end of each iteration
      this.emit(`0n`);
      this.stackMap.push(iterVar);
    }

    this.emit(`repeat ${count}n`);

    // Lower the body with a nested scheduler at increased indent
    const bodyScheduler = new SXStackScheduler(
      [], // no params — the parent stack is implicit
      this._properties,
      this.privateMethods,
      this._indent + '  ',
    );
    // Copy parent stack state into body scheduler
    bodyScheduler.stackMap = this.stackMap.clone();
    bodyScheduler.localBindings = new Set(body.map(b => b.name));
    bodyScheduler.outerProtectedRefs = new Set<string>();
    bodyScheduler.arrayLengths = new Map(this.arrayLengths);
    bodyScheduler.constValues = new Map(this.constValues);

    // Protect outer-scope refs from being consumed
    for (const name of this.stackMap.namedSlots()) {
      if (!body.some(b => b.name === name)) {
        bodyScheduler.outerProtectedRefs!.add(name);
      }
    }

    const lastUses = computeLastUses(body);
    // Protect outer refs
    if (bodyScheduler.outerProtectedRefs) {
      for (const ref of bodyScheduler.outerProtectedRefs) {
        lastUses.set(ref, body.length);
      }
    }

    for (let j = 0; j < body.length; j++) {
      bodyScheduler.lowerBinding(body[j]!, j, lastUses);
    }

    // Clean up iterVar if still on stack
    if (usesIterVar && bodyScheduler.stackMap.has(iterVar)) {
      // After body, increment counter for next iteration
      bodyScheduler.bringToTop(iterVar, true);
      bodyScheduler.emit('1add');
      bodyScheduler.stackMap.pop();
      bodyScheduler.stackMap.push(iterVar);
    }

    for (const t of bodyScheduler.tokens) this.emitRaw(t);
    this.emit('end');

    // After the repeat, update our stack state
    // The body may have produced/consumed values — sync from body scheduler
    this.stackMap = bodyScheduler.stackMap;
    this.arrayLengths = bodyScheduler.arrayLengths;
    this.constValues = bodyScheduler.constValues;

    if (usesIterVar && this.stackMap.has(iterVar)) {
      // Drop the final counter value
      this.bringToTop(iterVar, true);
      this.emit('drop');
      this.stackMap.pop();
    }

    // Loop is a statement, not an expression — don't push a result
  }

  // -----------------------------------------------------------------------
  // If / else → SX control flow
  // -----------------------------------------------------------------------

  private lowerIf(
    bindingName: string,
    cond: string,
    thenBindings: ANFBinding[],
    elseBindings: ANFBinding[],
    bindingIndex: number,
    lastUses: Map<string, number>,
    terminalAssert = false,
  ): void {
    // Bring condition to top and consume it
    this.bringToTop(cond, this.isLastUse(cond, bindingIndex, lastUses));
    this.stackMap.pop();

    this.emit('if');

    // Then branch
    const thenScheduler = new SXStackScheduler(
      [], this._properties, this.privateMethods, this._indent + '  ',
    );
    thenScheduler.stackMap = this.stackMap.clone();
    thenScheduler._insideBranch = true;
    thenScheduler.outerProtectedRefs = new Set<string>();
    thenScheduler.arrayLengths = new Map(this.arrayLengths);
    thenScheduler.constValues = new Map(this.constValues);
    for (const ref of lastUses.keys()) {
      const lastIdx = lastUses.get(ref)!;
      if (lastIdx > bindingIndex && this.stackMap.has(ref)) {
        thenScheduler.outerProtectedRefs!.add(ref);
      }
    }
    thenScheduler.lowerBindings(thenBindings, terminalAssert);
    for (const t of thenScheduler.tokens) this.emitRaw(t);

    // Else branch
    if (elseBindings.length > 0) {
      this.emit('else');
      const elseScheduler = new SXStackScheduler(
        [], this._properties, this.privateMethods, this._indent + '  ',
      );
      elseScheduler.stackMap = this.stackMap.clone();
      elseScheduler._insideBranch = true;
      elseScheduler.outerProtectedRefs = new Set<string>();
      elseScheduler.arrayLengths = new Map(this.arrayLengths);
      elseScheduler.constValues = new Map(this.constValues);
      for (const ref of lastUses.keys()) {
        const lastIdx = lastUses.get(ref)!;
        if (lastIdx > bindingIndex && this.stackMap.has(ref)) {
          elseScheduler.outerProtectedRefs!.add(ref);
        }
      }
      elseScheduler.lowerBindings(elseBindings, terminalAssert);
      for (const t of elseScheduler.tokens) this.emitRaw(t);

      // Reconcile: use else branch stack state (both should be symmetric)
      this.stackMap = elseScheduler.stackMap;
    } else {
      // No else — use then branch stack state
      this.stackMap = thenScheduler.stackMap;
    }

    this.emit('endIf');

    // If both branches produce a value, rename top to bindingName
    if (this.stackMap.depth > 0) {
      const top = this.stackMap.peekAtDepth(0);
      if (top !== null && top !== bindingName) {
        this.stackMap.renameAtDepth(0, bindingName);
      }
    }
  }

  // -----------------------------------------------------------------------
  // Assert
  // -----------------------------------------------------------------------

  private lowerAssert(
    valueRef: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
    terminal = false,
  ): void {
    this.bringToTop(valueRef, this.isLastUse(valueRef, bindingIndex, lastUses));
    if (!terminal) {
      this.stackMap.pop();
      this.emit('verify');
      this.stackMap.push(null);
    }
    // terminal: leave value on stack (Bitcoin Script checks TOS)
  }

  // -----------------------------------------------------------------------
  // Property update
  // -----------------------------------------------------------------------

  private lowerUpdateProp(
    propName: string,
    valueRef: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    this.bringToTop(valueRef, this.isLastUse(valueRef, bindingIndex, lastUses));
    this.stackMap.pop();

    // If the property already exists on the stack, remove the old value
    if (this.stackMap.has(propName) && !this._insideBranch) {
      const oldDepth = this.stackMap.findDepth(propName);
      if (oldDepth === 0) {
        // Old is on top, new was just popped — swap and nip
        // Actually: we popped the value, we need to re-push and remove old
      }
      // Remove old entry from stack
      this.stackMap.removeAtDepth(oldDepth);
      // Emit cleanup
      if (oldDepth === 0) {
        this.emit('nip');
      } else {
        this.emit(`${oldDepth + 1}n roll`);
        this.emit('drop');
      }
    }

    this.stackMap.push(propName);
  }

  // -----------------------------------------------------------------------
  // Stateful contract intrinsics + complex builtins — delegated to hex backend
  // -----------------------------------------------------------------------

  /**
   * Delegate a set of ANF bindings to the hex backend's stack lowerer,
   * convert the resulting StackOps to SX text via the bridge, and sync
   * the SX scheduler's StackMap from the hex backend's final state.
   *
   * This avoids duplicating the complex opcode sequences for stateful
   * intrinsics (checkPreimage, deserializeState, addOutput, extractors, etc.)
   * and complex math builtins (pow, sqrt, gcd, log2, etc.).
   */
  private delegateToHexBackend(bindings: ANFBinding[]): void {
    // Build the current stack state as a string[] (bottom to top)
    const stackState: string[] = [];
    for (let i = this.stackMap.depth - 1; i >= 0; i--) {
      stackState.unshift(this.stackMap.peekAtDepth(i) ?? `__anon_${i}`);
    }

    const result = lowerBindingsToOps(
      bindings,
      stackState,
      this._properties,
      this.privateMethods,
      false,
    );

    // Convert StackOps to SX text
    const sxText = stackOpsToSX(result.ops, this._indent);
    if (sxText) this.emitRaw(sxText);

    // Sync our StackMap from the hex backend's final state
    // Clear current and rebuild from finalStack
    while (this.stackMap.depth > 0) this.stackMap.pop();
    for (const name of result.finalStack) {
      this.stackMap.push(name);
    }
  }

  private lowerGetStateScript(bindingName: string): void {
    this.delegateToHexBackend([{ name: bindingName, value: { kind: 'get_state_script' } }]);
  }

  private lowerCheckPreimage(
    bindingName: string,
    preimageRef: string,
    _bindingIndex: number,
    _lastUses: Map<string, number>,
  ): void {
    this.delegateToHexBackend([{ name: bindingName, value: { kind: 'check_preimage', preimage: preimageRef } }]);
  }

  private lowerDeserializeState(
    bindingName: string,
    preimageRef: string,
    _bindingIndex: number,
    _lastUses: Map<string, number>,
  ): void {
    this.delegateToHexBackend([{ name: bindingName, value: { kind: 'deserialize_state', preimage: preimageRef } }]);
  }

  private lowerAddOutput(
    bindingName: string,
    satoshisRef: string,
    stateValues: string[],
    preimageRef: string,
    _bindingIndex: number,
    _lastUses: Map<string, number>,
  ): void {
    this.delegateToHexBackend([{
      name: bindingName,
      value: { kind: 'add_output', satoshis: satoshisRef, stateValues, preimage: preimageRef },
    }]);
  }

  private lowerAddRawOutput(
    bindingName: string,
    satoshisRef: string,
    scriptBytesRef: string,
    _bindingIndex: number,
    _lastUses: Map<string, number>,
  ): void {
    this.delegateToHexBackend([{
      name: bindingName,
      value: { kind: 'add_raw_output', satoshis: satoshisRef, scriptBytes: scriptBytesRef },
    }]);
  }

  // -----------------------------------------------------------------------
  // Array literal
  // -----------------------------------------------------------------------

  private lowerArrayLiteral(
    bindingName: string,
    elements: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    for (const elem of elements) {
      this.bringToTop(elem, this.isLastUse(elem, bindingIndex, lastUses));
    }
    for (let i = 0; i < elements.length; i++) this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.arrayLengths.set(bindingName, elements.length);
  }

  // -----------------------------------------------------------------------
  // Specialized codegen via bridge
  // -----------------------------------------------------------------------

  private trySpecializedCodegen(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): boolean {
    // Map function names to their codegen emitters
    type CodegenEntry = {
      emitter: (emit: (op: StackOp) => void) => void;
      argCount: number;
    };

    let entry: CodegenEntry | null = null;

    if (func === 'sha256Compress' && args.length === 2) {
      entry = { emitter: emitSha256Compress, argCount: 2 };
    } else if (func === 'sha256Finalize' && args.length === 3) {
      entry = { emitter: emitSha256Finalize, argCount: 3 };
    } else if (func === 'blake3Compress') {
      entry = { emitter: emitBlake3Compress, argCount: args.length };
    } else if (func === 'blake3Hash') {
      entry = { emitter: emitBlake3Hash, argCount: args.length };
    } else if (func === 'ecAdd') {
      entry = { emitter: emitEcAdd, argCount: 2 };
    } else if (func === 'ecMul') {
      entry = { emitter: emitEcMul, argCount: 2 };
    } else if (func === 'ecMulGen') {
      entry = { emitter: emitEcMulGen, argCount: 1 };
    } else if (func === 'ecNegate') {
      entry = { emitter: emitEcNegate, argCount: 1 };
    } else if (func === 'ecOnCurve') {
      entry = { emitter: emitEcOnCurve, argCount: 1 };
    } else if (func === 'ecModReduce') {
      entry = { emitter: emitEcModReduce, argCount: 1 };
    } else if (func === 'ecEncodeCompressed') {
      entry = { emitter: emitEcEncodeCompressed, argCount: 1 };
    } else if (func === 'ecMakePoint') {
      entry = { emitter: emitEcMakePoint, argCount: 2 };
    } else if (func === 'ecPointX') {
      entry = { emitter: emitEcPointX, argCount: 1 };
    } else if (func === 'ecPointY') {
      entry = { emitter: emitEcPointY, argCount: 1 };
    } else if (func === 'bbFieldAdd') {
      entry = { emitter: emitBBFieldAdd, argCount: 2 };
    } else if (func === 'bbFieldSub') {
      entry = { emitter: emitBBFieldSub, argCount: 2 };
    } else if (func === 'bbFieldMul') {
      entry = { emitter: emitBBFieldMul, argCount: 2 };
    } else if (func === 'bbFieldInv') {
      entry = { emitter: emitBBFieldInv, argCount: 1 };
    } else if (func === 'bbExt4Mul0') {
      entry = { emitter: emitBBExt4Mul0, argCount: 8 };
    } else if (func === 'bbExt4Mul1') {
      entry = { emitter: emitBBExt4Mul1, argCount: 8 };
    } else if (func === 'bbExt4Mul2') {
      entry = { emitter: emitBBExt4Mul2, argCount: 8 };
    } else if (func === 'bbExt4Mul3') {
      entry = { emitter: emitBBExt4Mul3, argCount: 8 };
    } else if (func === 'bbExt4Inv0') {
      entry = { emitter: emitBBExt4Inv0, argCount: 4 };
    } else if (func === 'bbExt4Inv1') {
      entry = { emitter: emitBBExt4Inv1, argCount: 4 };
    } else if (func === 'bbExt4Inv2') {
      entry = { emitter: emitBBExt4Inv2, argCount: 4 };
    } else if (func === 'bbExt4Inv3') {
      entry = { emitter: emitBBExt4Inv3, argCount: 4 };
    } else if (func === 'merkleRootSha256') {
      entry = { emitter: (emit) => emitMerkleRootSha256(emit, Number(this.constValues.get(args[2]!) ?? 0n)), argCount: 3 };
    } else if (func === 'merkleRootHash256') {
      entry = { emitter: (emit) => emitMerkleRootHash256(emit, Number(this.constValues.get(args[2]!) ?? 0n)), argCount: 3 };
    } else if (func.startsWith('verifySLHDSA_SHA2_')) {
      const paramKey = func.replace('verifySLHDSA_', '');
      entry = { emitter: (emit) => emitVerifySLHDSA(emit, paramKey), argCount: args.length };
    }

    if (!entry) return false;

    // Push args onto stack
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    for (let i = 0; i < args.length; i++) this.stackMap.pop();

    // Collect StackOps from the codegen emitter
    const ops: StackOp[] = [];
    entry.emitter((op) => ops.push(op));

    // Convert to SX text via bridge
    this.emit(`// ${func}() — specialized codegen`);
    const sxText = stackOpsToSX(ops, this._indent);
    if (sxText) this.emitRaw(sxText);

    this.stackMap.push(bindingName);
    return true;
  }
}

// ---------------------------------------------------------------------------
// SX peephole optimizer — removes redundant token patterns
// ---------------------------------------------------------------------------

function peepholeSX(tokens: string[]): string[] {
  let changed = true;
  let result = tokens;

  while (changed) {
    changed = false;
    const next: string[] = [];
    let i = 0;

    while (i < result.length) {
      const t1 = result[i]!.trim();
      const t2 = i + 1 < result.length ? result[i + 1]!.trim() : '';

      // Remove swap swap (no-op)
      if (t1 === 'swap' && t2 === 'swap') {
        i += 2;
        changed = true;
        continue;
      }

      // Remove dup drop (no-op)
      if (t1 === 'dup' && t2 === 'drop') {
        i += 2;
        changed = true;
        continue;
      }

      // Remove push-then-drop (no-op: false drop, true drop, Nn drop, 0xHH drop)
      if (t2 === 'drop' && (t1 === 'false' || t1 === 'true' || /^-?\d+n$/.test(t1) || /^0x[0-9a-f]+$/i.test(t1))) {
        i += 2;
        changed = true;
        continue;
      }

      // Remove rot rot rot (no-op: 3 rotations = identity for 3 items)
      if (t1 === 'rot' && t2 === 'rot' && i + 2 < result.length && result[i + 2]!.trim() === 'rot') {
        i += 3;
        changed = true;
        continue;
      }

      next.push(result[i]!);
      i++;
    }

    result = next;
  }

  return result;
}
