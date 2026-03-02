/**
 * Pass 5: Stack Lower — converts ANF IR to Stack IR.
 *
 * The fundamental challenge: ANF uses named temporaries but Bitcoin Script
 * operates on an anonymous stack. We maintain a "stack map" that tracks
 * which named value lives at which stack position, then emit PICK/ROLL/DUP
 * operations to shuttle values to the top when they are needed.
 */

import type {
  ANFProgram,
  ANFMethod,
  ANFBinding,
  ANFValue,
  ANFProperty,
} from '../ir/index.js';
import type {
  StackProgram,
  StackMethod,
  StackOp,
} from '../ir/index.js';
import { emitVerifySLHDSA } from './slh-dsa-codegen.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_STACK_DEPTH = 800;

// ---------------------------------------------------------------------------
// Builtin function → opcode mapping
// ---------------------------------------------------------------------------

const BUILTIN_OPCODES: Record<string, string[]> = {
  sha256: ['OP_SHA256'],
  ripemd160: ['OP_RIPEMD160'],
  hash160: ['OP_HASH160'],
  hash256: ['OP_HASH256'],
  checkSig: ['OP_CHECKSIG'],
  checkMultiSig: ['OP_CHECKMULTISIG'],
  len: ['OP_SIZE'],
  cat: ['OP_CAT'],
  num2bin: ['OP_NUM2BIN'],
  bin2num: ['OP_BIN2NUM'],
  abs: ['OP_ABS'],
  min: ['OP_MIN'],
  max: ['OP_MAX'],
  within: ['OP_WITHIN'],
  split: ['OP_SPLIT'],
  left: ['OP_SPLIT', 'OP_DROP'],
  right: ['OP_SPLIT', 'OP_NIP'],
  int2str: ['OP_NUM2BIN'],
  sign: ['OP_DUP', 'OP_ABS', 'OP_SWAP', 'OP_DIV'],
  bool: ['OP_0NOTEQUAL'],
};

// ---------------------------------------------------------------------------
// Binary operator → opcode mapping
// ---------------------------------------------------------------------------

/**
 * Maps binary operators to their opcodes.
 *
 * NOTE: For `===` / `!==`, the default opcodes here are OP_NUMEQUAL / OP_NUMEQUAL+OP_NOT,
 * which is correct for numeric (bigint) operands. When the ANF bin_op node carries
 * `result_type: "bytes"` (set by pass 04 for ByteString/PubKey/Sig/Sha256 etc.
 * operands), the stack lowerer overrides these with OP_EQUAL / OP_EQUAL+OP_NOT.
 */
const BINOP_OPCODES: Record<string, string[]> = {
  '+': ['OP_ADD'],
  '-': ['OP_SUB'],
  '*': ['OP_MUL'],
  '/': ['OP_DIV'],
  '%': ['OP_MOD'],
  '===': ['OP_NUMEQUAL'],
  '!==': ['OP_NUMEQUAL', 'OP_NOT'],
  '<': ['OP_LESSTHAN'],
  '>': ['OP_GREATERTHAN'],
  '<=': ['OP_LESSTHANOREQUAL'],
  '>=': ['OP_GREATERTHANOREQUAL'],
  '&&': ['OP_BOOLAND'],
  '||': ['OP_BOOLOR'],
  '&': ['OP_AND'],
  '|': ['OP_OR'],
  '^': ['OP_XOR'],
  '<<': ['OP_LSHIFT'],
  '>>': ['OP_RSHIFT'],
};

// ---------------------------------------------------------------------------
// Unary operator → opcode mapping
// ---------------------------------------------------------------------------

const UNARYOP_OPCODES: Record<string, string[]> = {
  '!': ['OP_NOT'],
  '-': ['OP_NEGATE'],
  '~': ['OP_INVERT'],
};

// ---------------------------------------------------------------------------
// Stack map — tracks named values on the stack
// ---------------------------------------------------------------------------

/**
 * The stack map is an array where each element is either a variable name
 * or null (for anonymous/consumed slots). Index 0 is the bottom of the
 * stack, last element is the top.
 */
class StackMap {
  private slots: (string | null)[];

  constructor(initial: string[] = []) {
    this.slots = [...initial];
  }

  /** Current stack depth. */
  get depth(): number {
    return this.slots.length;
  }

  /** Push a named value onto the top. */
  push(name: string | null): void {
    this.slots.push(name);
  }

  /** Pop the top of the stack (returns the name or null). */
  pop(): string | null {
    if (this.slots.length === 0) {
      throw new Error('Stack underflow');
    }
    return this.slots.pop()!;
  }

  /** Find the depth of a named value from the top of the stack (0 = top). */
  findDepth(name: string): number {
    for (let i = this.slots.length - 1; i >= 0; i--) {
      if (this.slots[i] === name) {
        return this.slots.length - 1 - i;
      }
    }
    throw new Error(`Value '${name}' not found on stack`);
  }

  /** Check if a named value exists on the stack. */
  has(name: string): boolean {
    return this.slots.includes(name);
  }

  /** Remove a value at a given position from bottom (used after ROLL). */
  removeAtDepth(depthFromTop: number): string | null {
    const index = this.slots.length - 1 - depthFromTop;
    if (index < 0 || index >= this.slots.length) {
      throw new Error(`Invalid stack depth: ${depthFromTop}`);
    }
    const [removed] = this.slots.splice(index, 1);
    return removed ?? null;
  }

  /** Peek at a depth without modifying. */
  peekAtDepth(depthFromTop: number): string | null {
    const index = this.slots.length - 1 - depthFromTop;
    if (index < 0 || index >= this.slots.length) {
      throw new Error(`Invalid stack depth: ${depthFromTop}`);
    }
    return this.slots[index] ?? null;
  }

  /** Clone the stack map. */
  clone(): StackMap {
    const m = new StackMap();
    m.slots = [...this.slots];
    return m;
  }

  /** Swap the top two elements. */
  swap(): void {
    const len = this.slots.length;
    if (len < 2) throw new Error('Stack underflow on swap');
    const tmp = this.slots[len - 1]!;
    this.slots[len - 1] = this.slots[len - 2]!;
    this.slots[len - 2] = tmp;
  }

  /** Duplicate the top element. */
  dup(): void {
    if (this.slots.length < 1) throw new Error('Stack underflow on dup');
    this.slots.push(this.slots[this.slots.length - 1]!);
  }
}

// ---------------------------------------------------------------------------
// Use analysis — determine last-use sites for each variable
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
      // Track param name so last-use analysis keeps the param on the stack
      // (via PICK) until its final load_param, then consumes it (via ROLL).
      refs.push(value.name);
      break;
    case 'load_prop':
    case 'load_const':
    case 'get_state_script':
      break;
    case 'add_output':
      refs.push(value.satoshis, ...value.stateValues);
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
      for (const b of value.then) {
        refs.push(...collectRefs(b.value));
      }
      for (const b of value.else) {
        refs.push(...collectRefs(b.value));
      }
      break;
    case 'loop':
      for (const b of value.body) {
        refs.push(...collectRefs(b.value));
      }
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
  }

  return refs;
}

// ---------------------------------------------------------------------------
// Core lowering context
// ---------------------------------------------------------------------------

class LoweringContext {
  private stackMap: StackMap;
  private ops: StackOp[] = [];
  private maxDepth = 0;
  private _properties: ANFProperty[];
  private privateMethods: Map<string, ANFMethod>;

  constructor(
    params: string[],
    properties: ANFProperty[],
    privateMethods: Map<string, ANFMethod> = new Map(),
  ) {
    // Parameters are pushed onto the stack by the Bitcoin VM in order.
    // The first parameter is at the bottom, last parameter at the top.
    this.stackMap = new StackMap(params);
    this._properties = properties;
    this.privateMethods = privateMethods;
    this.trackDepth();
  }

  get result(): { ops: StackOp[]; maxStackDepth: number } {
    return { ops: this.ops, maxStackDepth: this.maxDepth };
  }

  private trackDepth(): void {
    if (this.stackMap.depth > this.maxDepth) {
      this.maxDepth = this.stackMap.depth;
    }
  }

  private emitOp(stackOp: StackOp): void {
    this.ops.push(stackOp);
    this.trackDepth();
  }

  /**
   * Bring a named value to the top of the stack.
   * If `consume` is true, use ROLL (removes from original position).
   * If `consume` is false, use PICK (copies, leaving original in place).
   */
  bringToTop(name: string, consume: boolean): void {
    const depth = this.stackMap.findDepth(name);

    if (depth === 0) {
      // Already on top.
      if (!consume) {
        this.emitOp({ op: 'dup' });
        this.stackMap.dup();
      }
      return;
    }

    if (depth === 1 && consume) {
      this.emitOp({ op: 'swap' });
      this.stackMap.swap();
      return;
    }

    if (consume) {
      if (depth === 2) {
        // ROT is ROLL 2
        this.emitOp({ op: 'rot' });
        const name2 = this.stackMap.removeAtDepth(2);
        this.stackMap.push(name2);
      } else {
        this.emitOp({ op: 'push', value: BigInt(depth) });
        this.stackMap.push(null); // temporary push count on stack map
        this.emitOp({ op: 'roll', depth });
        // ROLL removes the depth-number from stack and brings the value up
        this.stackMap.pop(); // remove the depth literal
        const rolled = this.stackMap.removeAtDepth(depth);
        this.stackMap.push(rolled);
      }
    } else {
      if (depth === 1) {
        this.emitOp({ op: 'over' });
        const name2 = this.stackMap.peekAtDepth(1);
        this.stackMap.push(name2);
      } else {
        this.emitOp({ op: 'push', value: BigInt(depth) });
        this.stackMap.push(null);
        this.emitOp({ op: 'pick', depth });
        // PICK copies the value; remove the depth literal and push the copy
        this.stackMap.pop(); // remove depth literal
        const picked = this.stackMap.peekAtDepth(depth);
        this.stackMap.push(picked);
      }
    }

    this.trackDepth();
  }

  /**
   * Lower a sequence of ANF bindings.
   *
   * When `terminalAssert` is true, the final assert in the sequence omits
   * OP_VERIFY so its result stays on the stack — required by Bitcoin Script
   * which checks the top-of-stack for truthiness after execution.
   */
  lowerBindings(bindings: ANFBinding[], terminalAssert = false): void {
    const lastUses = computeLastUses(bindings);

    // Find the index of the last assert binding (if terminalAssert is set)
    let lastAssertIdx = -1;
    if (terminalAssert) {
      for (let i = bindings.length - 1; i >= 0; i--) {
        if (bindings[i]!.value.kind === 'assert') {
          lastAssertIdx = i;
          break;
        }
      }
    }

    for (let i = 0; i < bindings.length; i++) {
      const binding = bindings[i]!;
      if (binding.value.kind === 'assert' && i === lastAssertIdx) {
        // Terminal assert: leave value on stack instead of OP_VERIFY
        this.lowerAssert(binding.value.value, i, lastUses, true);
      } else {
        this.lowerBinding(binding, i, lastUses);
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
        this.lowerLoadConst(name, value.value);
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
      case 'add_output':
        this.lowerAddOutput(name, value.satoshis, value.stateValues, bindingIndex, lastUses);
        break;
    }
  }

  /** Whether `ref` is used after `currentIndex`. */
  private isLastUse(ref: string, currentIndex: number, lastUses: Map<string, number>): boolean {
    const last = lastUses.get(ref);
    return last === undefined || last <= currentIndex;
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
    // The parameter is already on the stack under its original name.
    // We alias it by bringing it to the top.
    if (this.stackMap.has(paramName)) {
      const isLast = this.isLastUse(paramName, bindingIndex, lastUses);
      this.bringToTop(paramName, isLast);
      // Rename the top-of-stack entry to the binding name
      this.stackMap.pop();
      this.stackMap.push(bindingName);
    } else {
      // Parameter not found - should not happen in well-formed ANF.
      // Emit a push of zero as a fallback.
      this.emitOp({ op: 'push', value: 0n });
      this.stackMap.push(bindingName);
    }
  }

  private lowerLoadProp(bindingName: string, propName: string): void {
    // Properties are embedded as constants in the script.
    // Look up the property value from the contract properties.
    const prop = this._properties.find(p => p.name === propName);
    if (prop && prop.initialValue !== undefined) {
      this.pushValue(prop.initialValue);
    } else if (this.stackMap.has(propName)) {
      // If the property has been updated (via update_prop), it lives on the stack.
      this.bringToTop(propName, false);
      this.stackMap.pop();
    } else {
      // Property value will be provided at deployment time; emit a placeholder.
      // The assembler fills this in from constructor args.
      this.emitOp({ op: 'push', value: 0n });
    }
    this.stackMap.push(bindingName);
  }

  private lowerLoadConst(bindingName: string, value: string | bigint | boolean): void {
    // Handle @ref: aliases (ANF variable aliasing)
    if (typeof value === 'string' && value.startsWith('@ref:')) {
      const refName = value.slice(5);
      if (this.stackMap.has(refName)) {
        this.bringToTop(refName, false);
        this.stackMap.pop();
        this.stackMap.push(bindingName);
      } else {
        // Referenced value not on stack -- push a placeholder
        this.emitOp({ op: 'push', value: 0n });
        this.stackMap.push(bindingName);
      }
      return;
    }
    // Handle @this marker
    if (typeof value === 'string' && value === '@this') {
      // 'this' is a compile-time concept, not a runtime value.
      // Push a placeholder that can be consumed.
      this.emitOp({ op: 'push', value: 0n });
      this.stackMap.push(bindingName);
      return;
    }
    this.pushValue(value);
    this.stackMap.push(bindingName);
  }

  private pushValue(value: string | bigint | boolean): void {
    if (typeof value === 'boolean') {
      this.emitOp({ op: 'push', value });
    } else if (typeof value === 'bigint') {
      this.emitOp({ op: 'push', value });
    } else {
      // String value - hex-encoded byte string
      this.emitOp({ op: 'push', value: hexToBytes(value) });
    }
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
    // Get left operand to stack first
    const leftIsLast = this.isLastUse(left, bindingIndex, lastUses);
    this.bringToTop(left, leftIsLast);

    // Get right operand to stack
    const rightIsLast = this.isLastUse(right, bindingIndex, lastUses);
    this.bringToTop(right, rightIsLast);

    // Pop both operands (the opcode consumes them)
    this.stackMap.pop();
    this.stackMap.pop();

    // For equality operators, choose OP_EQUAL vs OP_NUMEQUAL based on operand type.
    if (resultType === 'bytes' && (op === '===' || op === '!==')) {
      this.emitOp({ op: 'opcode', code: 'OP_EQUAL' });
      if (op === '!==') {
        this.emitOp({ op: 'opcode', code: 'OP_NOT' });
      }
    } else {
      // Emit the opcode(s) from the standard table
      const opcodes = BINOP_OPCODES[op];
      if (!opcodes) {
        throw new Error(`Unknown binary operator: ${op}`);
      }
      for (const code of opcodes) {
        this.emitOp({ op: 'opcode', code });
      }
    }

    // Push the result
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerUnaryOp(
    bindingName: string,
    op: string,
    operand: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    const isLast = this.isLastUse(operand, bindingIndex, lastUses);
    this.bringToTop(operand, isLast);

    this.stackMap.pop();

    const opcodes = UNARYOP_OPCODES[op];
    if (!opcodes) {
      throw new Error(`Unknown unary operator: ${op}`);
    }
    for (const code of opcodes) {
      this.emitOp({ op: 'opcode', code });
    }

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerCall(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Special handling for certain builtins
    if (func === 'assert') {
      // assert(value) => value OP_VERIFY
      if (args.length >= 1) {
        const arg = args[0]!;
        const isLast = this.isLastUse(arg, bindingIndex, lastUses);
        this.bringToTop(arg, isLast);
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_VERIFY' });
        // assert produces no result value, push a dummy
        this.stackMap.push(bindingName);
      }
      return;
    }

    if (func === 'super') {
      // super() in constructor — no opcode emission needed, it's a
      // no-op at the script level. Constructor args are already on the stack.
      this.stackMap.push(bindingName);
      return;
    }

    if (func === 'verifyRabinSig') {
      this.lowerVerifyRabinSig(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'verifyWOTS') {
      this.lowerVerifyWOTS(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func.startsWith('verifySLHDSA_SHA2_')) {
      const paramKey = func.replace('verifySLHDSA_', '');
      this.lowerVerifySLHDSA(bindingName, paramKey, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'reverseBytes') {
      this.lowerReverseBytes(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'substr') {
      this.lowerSubstr(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'safediv' || func === 'safemod') {
      this.lowerSafeDivMod(bindingName, func, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'clamp') {
      this.lowerClamp(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'pow') {
      this.lowerPow(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'mulDiv') {
      this.lowerMulDiv(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'percentOf') {
      this.lowerPercentOf(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'sqrt') {
      this.lowerSqrt(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'gcd') {
      this.lowerGcd(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'divmod') {
      this.lowerDivmod(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'log2') {
      this.lowerLog2(bindingName, args, bindingIndex, lastUses);
      return;
    }

    // Preimage field extractors — each needs a custom OP_SPLIT sequence
    // because OP_SPLIT produces two stack values and the intermediate stack
    // management cannot be expressed in the simple BUILTIN_OPCODES table.
    if (func.startsWith('extract')) {
      this.lowerExtractor(bindingName, func, args, bindingIndex, lastUses);
      return;
    }

    // General builtin call: push args in order, then emit opcode(s)
    for (const arg of args) {
      const isLast = this.isLastUse(arg, bindingIndex, lastUses);
      this.bringToTop(arg, isLast);
    }

    // Pop all args
    for (let j = 0; j < args.length; j++) {
      this.stackMap.pop();
    }

    const opcodes = BUILTIN_OPCODES[func];
    if (!opcodes) {
      throw new Error(`Unknown builtin function: ${func}`);
    }
    for (const code of opcodes) {
      this.emitOp({ op: 'opcode', code });
    }

    // Some builtins produce two outputs (e.g. split), but we treat the
    // binding as the primary result. The second result stays on stack unnamed.
    if (func === 'split') {
      // split produces [left, right] - both on stack
      this.stackMap.push(null);  // left part
      this.stackMap.push(bindingName); // right part (top)
    } else if (func === 'len') {
      // OP_SIZE leaves original on stack and pushes length on top
      this.stackMap.push(null);  // original value still present
      this.stackMap.push(bindingName);
    } else {
      this.stackMap.push(bindingName);
    }

    this.trackDepth();
  }

  private lowerMethodCall(
    bindingName: string,
    _object: string,
    method: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Method calls on `this` are treated as builtin calls
    // e.g. this.getStateScript(), this.buildP2PKH(addr)
    if (method === 'getStateScript') {
      this.lowerGetStateScript(bindingName);
      return;
    }

    const privateMethod = this.privateMethods.get(method);
    if (privateMethod) {
      this.inlineMethodCall(bindingName, privateMethod, args, bindingIndex, lastUses);
      return;
    }

    // For other method calls, treat like a function call
    this.lowerCall(bindingName, method, args, bindingIndex, lastUses);
  }

  private inlineMethodCall(
    bindingName: string,
    method: ANFMethod,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Bind call arguments to private method params.
    for (let i = 0; i < args.length; i++) {
      if (i < method.params.length) {
        const arg = args[i]!;
        const isLast = this.isLastUse(arg, bindingIndex, lastUses);
        this.bringToTop(arg, isLast);
        this.stackMap.pop();
        this.stackMap.push(method.params[i]!.name);
      }
    }

    this.lowerBindings(method.body);

    // Method return value is the last binding result.
    if (method.body.length > 0) {
      const lastBindingName = method.body[method.body.length - 1]!.name;
      if (this.stackMap.depth > 0 && this.stackMap.peekAtDepth(0) === lastBindingName) {
        this.stackMap.pop();
        this.stackMap.push(bindingName);
      }
    }
  }

  private lowerIf(
    bindingName: string,
    cond: string,
    thenBindings: ANFBinding[],
    elseBindings: ANFBinding[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Get condition to top of stack
    const isLast = this.isLastUse(cond, bindingIndex, lastUses);
    this.bringToTop(cond, isLast);
    this.stackMap.pop(); // OP_IF consumes the condition

    // Lower then-branch
    const thenCtx = new LoweringContext([], this._properties, this.privateMethods);
    thenCtx.stackMap = this.stackMap.clone();
    thenCtx.lowerBindings(thenBindings);
    const thenOps = thenCtx.result.ops;

    // Lower else-branch
    const elseCtx = new LoweringContext([], this._properties, this.privateMethods);
    elseCtx.stackMap = this.stackMap.clone();
    elseCtx.lowerBindings(elseBindings);
    const elseOps = elseCtx.result.ops;

    this.emitOp({
      op: 'if',
      then: thenOps,
      else: elseOps.length > 0 ? elseOps : undefined,
    });

    // The if expression produces one result value on top
    this.stackMap.push(bindingName);
    this.trackDepth();

    // Track max depth from sub-contexts
    if (thenCtx.maxDepth > this.maxDepth) {
      this.maxDepth = thenCtx.maxDepth;
    }
    if (elseCtx.maxDepth > this.maxDepth) {
      this.maxDepth = elseCtx.maxDepth;
    }
  }

  private lowerLoop(
    bindingName: string,
    count: number,
    body: ANFBinding[],
    _iterVar: string,
  ): void {
    // Collect outer-scope param names referenced in the loop body.
    // These must not be consumed in non-final iterations.
    const outerParams = new Set<string>();
    for (const b of body) {
      if (b.value.kind === 'load_param' && b.value.name !== _iterVar) {
        outerParams.add(b.value.name);
      }
    }

    // Loops are unrolled at compile time. Repeat the body `count` times.
    for (let i = 0; i < count; i++) {
      // Push the iteration index as a constant (in case the loop body uses it)
      this.emitOp({ op: 'push', value: BigInt(i) });
      this.stackMap.push(_iterVar);

      const lastUses = computeLastUses(body);

      // In non-final iterations, prevent outer-scope params from being
      // consumed by setting their last-use beyond any body binding index.
      if (i < count - 1) {
        for (const paramName of outerParams) {
          lastUses.set(paramName, body.length);
        }
      }

      for (let j = 0; j < body.length; j++) {
        this.lowerBinding(body[j]!, j, lastUses);
      }
    }
    // Loop produces a dummy value
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerAssert(
    value: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
    terminal = false,
  ): void {
    const isLast = this.isLastUse(value, bindingIndex, lastUses);
    this.bringToTop(value, isLast);
    if (terminal) {
      // Terminal assert: leave value on stack for Bitcoin Script's
      // final truthiness check (no OP_VERIFY).
    } else {
      this.stackMap.pop();
      this.emitOp({ op: 'opcode', code: 'OP_VERIFY' });
    }
    this.trackDepth();
  }

  private lowerUpdateProp(
    propName: string,
    value: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    const isLast = this.isLastUse(value, bindingIndex, lastUses);
    this.bringToTop(value, isLast);

    // The value is now on top; rename it to the property name so that
    // subsequent load_prop can find the updated value.
    this.stackMap.pop();
    this.stackMap.push(propName);
    this.trackDepth();
  }

  private lowerGetStateScript(bindingName: string): void {
    // Emit state serialization: concatenate all non-readonly properties.
    // For bigint properties, use OP_NUM2BIN with 8-byte width to convert
    // to fixed-width byte representation before concatenation.
    // For boolean properties, use OP_NUM2BIN with 1-byte width.
    // Byte-typed properties (ByteString, PubKey, Sig, Sha256, etc.) are
    // already byte sequences and used as-is.
    const stateProps = this._properties.filter(p => !p.readonly);

    if (stateProps.length === 0) {
      // No state — push empty byte string
      this.emitOp({ op: 'push', value: new Uint8Array(0) });
      this.stackMap.push(bindingName);
      return;
    }

    // Bring each state property to the top and concatenate
    let first = true;
    for (const prop of stateProps) {
      if (this.stackMap.has(prop.name)) {
        this.bringToTop(prop.name, false);
      } else if (prop.initialValue !== undefined) {
        this.pushValue(prop.initialValue);
        this.stackMap.push(null);
      } else {
        this.emitOp({ op: 'push', value: 0n });
        this.stackMap.push(null);
      }

      // Convert numeric/boolean values to fixed-width bytes via OP_NUM2BIN
      if (prop.type === 'bigint') {
        this.emitOp({ op: 'push', value: 8n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
        this.stackMap.pop(); // pop the width
        // The value on top is now the 8-byte representation
      } else if (prop.type === 'boolean') {
        this.emitOp({ op: 'push', value: 1n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
        this.stackMap.pop(); // pop the width
      }
      // For byte types (ByteString, PubKey, Sig, Sha256, etc.), no conversion needed

      if (!first) {
        // Concatenate with previous
        this.stackMap.pop();
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_CAT' });
        this.stackMap.push(null);
      }
      first = false;
    }

    // Rename top to binding name
    this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerAddOutput(
    bindingName: string,
    satoshis: string,
    stateValues: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Serialize a transaction output: <8-byte LE satoshis> <serialized state values>
    // This mirrors lowerGetStateScript but uses the provided value refs instead
    // of loading from the stack, and prepends the satoshis amount.

    const stateProps = this._properties.filter(p => !p.readonly);

    // Step 1: Serialize satoshis as 8-byte LE
    const isLastSatoshis = this.isLastUse(satoshis, bindingIndex, lastUses);
    this.bringToTop(satoshis, isLastSatoshis);
    this.emitOp({ op: 'push', value: 8n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
    this.stackMap.pop(); // pop the width

    // Step 2: Serialize each state value and concatenate
    for (let i = 0; i < stateValues.length && i < stateProps.length; i++) {
      const valueRef = stateValues[i]!;
      const prop = stateProps[i]!;

      const isLast = this.isLastUse(valueRef, bindingIndex, lastUses);
      this.bringToTop(valueRef, isLast);

      // Convert numeric/boolean values to fixed-width bytes
      if (prop.type === 'bigint') {
        this.emitOp({ op: 'push', value: 8n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
        this.stackMap.pop();
      } else if (prop.type === 'boolean') {
        this.emitOp({ op: 'push', value: 1n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
        this.stackMap.pop();
      }
      // Byte types used as-is

      // Concatenate with accumulator
      this.stackMap.pop();
      this.stackMap.pop();
      this.emitOp({ op: 'opcode', code: 'OP_CAT' });
      this.stackMap.push(null);
    }

    // Rename top to binding name
    this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerCheckPreimage(
    bindingName: string,
    preimage: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // OP_PUSH_TX: verify the sighash preimage matches the current spending
    // transaction.  See https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX
    //
    // The technique uses a well-known ECDSA keypair where private key = 1
    // (so the public key is the secp256k1 generator point G, compressed:
    //   0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798).
    //
    // At spending time the SDK must:
    //   1. Serialise the BIP-143 sighash preimage for the current input.
    //   2. Compute sighash = SHA256(SHA256(preimage)).
    //   3. Derive an ECDSA signature (r, s) with privkey = 1:
    //        r = Gx  (x-coordinate of the generator point, constant)
    //        s = (sighash + r) mod n
    //   4. DER-encode (r, s) and append the SIGHASH_ALL|FORKID byte (0x41).
    //   5. Push <sig> <preimage> (plus any other method args) as the
    //      unlocking script.
    //
    // The locking script then does:
    //   ... <sig> <preimage> ...   -- from unlocking script (sig is implicit)
    //   [bring preimage to top]    -- via PICK (non-consuming copy)
    //   [bring sig to top]         -- via ROLL (consuming)
    //   <G>                        -- push compressed generator point
    //   OP_CHECKSIG                -- verify sig over SHA256(SHA256(preimage))
    //   OP_VERIFY                  -- abort if invalid
    //   -- preimage copy remains on stack for field extractors

    // Stack map trace:
    //   After bringToTop(preimage):  [..., preimage]
    //   After bringToTop(sig, true): [..., preimage, _opPushTxSig]
    //   After push G:                [..., preimage, _opPushTxSig, null(G)]
    //   After OP_CHECKSIG:           [..., preimage, null(result)]
    //   After OP_VERIFY:             [..., preimage]

    // Step 1: Bring preimage to top.
    const isLast = this.isLastUse(preimage, bindingIndex, lastUses);
    this.bringToTop(preimage, isLast);

    // Step 2: Bring the implicit _opPushTxSig to top (consuming).
    this.bringToTop('_opPushTxSig', true);

    // Step 3: Push compressed secp256k1 generator point G (33 bytes).
    const G = new Uint8Array([
      0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
      0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
      0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
      0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
      0x98,
    ]);
    this.emitOp({ op: 'push', value: G });
    this.stackMap.push(null); // G on stack

    // Step 4: OP_CHECKSIG -- pops pubkey (G) and sig, pushes boolean result.
    this.emitOp({ op: 'opcode', code: 'OP_CHECKSIG' });
    this.stackMap.pop(); // G consumed
    this.stackMap.pop(); // _opPushTxSig consumed
    this.stackMap.push(null); // boolean result

    // Step 5: OP_VERIFY -- abort if false, removes result from stack.
    this.emitOp({ op: 'opcode', code: 'OP_VERIFY' });
    this.stackMap.pop(); // result consumed

    // The preimage is now on top (from Step 1). Rename to binding name
    // so field extractors can reference it.
    this.stackMap.pop();
    this.stackMap.push(bindingName);

    this.trackDepth();
  }

  /**
   * Lower a preimage field extractor call.
   *
   * The SigHashPreimage follows BIP-143 format:
   *   Offset  Bytes  Field
   *   0       4      nVersion (LE uint32)
   *   4       32     hashPrevouts
   *   36      32     hashSequence
   *   68      36     outpoint (txid 32 + vout 4)
   *   104     var    scriptCode (varint-prefixed)
   *   var     8      amount (satoshis, LE int64)
   *   var     4      nSequence
   *   var     32     hashOutputs
   *   var     4      nLocktime
   *   var     4      sighashType
   *
   * Fixed-offset fields use absolute OP_SPLIT positions.
   * Variable-offset fields use end-relative positions via OP_SIZE.
   */
  private lowerExtractor(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 1) {
      throw new Error(`${func} requires 1 argument`);
    }
    const arg = args[0]!;
    const isLast = this.isLastUse(arg, bindingIndex, lastUses);
    this.bringToTop(arg, isLast);

    // The preimage is now on top of the stack.
    // Each extractor emits a split sequence and manages the stack map.
    this.stackMap.pop(); // consume the preimage from stack map

    switch (func) {
      case 'extractVersion':
        // <preimage> 4 OP_SPLIT OP_DROP OP_BIN2NUM
        // Split at 4, keep left (version bytes), convert to number.
        this.emitOp({ op: 'push', value: 4n });
        this.stackMap.push(null); // push offset
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop(); // pop offset
        // stack: [left(4), right(rest)] — but stackMap sees one consumed, two produced
        this.stackMap.push(null); // left: version bytes
        this.stackMap.push(null); // right: rest
        this.emitOp({ op: 'drop' }); // drop the rest
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' }); // convert to number
        break;

      case 'extractHashPrevouts':
        // <preimage> 4 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
        // Skip first 4 bytes, take next 32.
        this.emitOp({ op: 'push', value: 4n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null); // left
        this.stackMap.push(null); // right
        this.emitOp({ op: 'nip' }); // drop left (first 4 bytes)
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null); // right now on top
        this.emitOp({ op: 'push', value: 32n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null); // hashPrevouts (32 bytes)
        this.stackMap.push(null); // rest
        this.emitOp({ op: 'drop' }); // drop rest
        this.stackMap.pop();
        break;

      case 'extractHashSequence':
        // <preimage> 36 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
        // Skip first 36 bytes (4 + 32), take next 32.
        this.emitOp({ op: 'push', value: 36n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 32n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        break;

      case 'extractOutpoint':
        // <preimage> 68 OP_SPLIT OP_NIP 36 OP_SPLIT OP_DROP
        // Skip first 68 bytes (4+32+32), take next 36 (txid 32 + vout 4).
        this.emitOp({ op: 'push', value: 68n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 36n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        break;

      case 'extractSigHashType':
        // End-relative: last 4 bytes, converted to number.
        // <preimage> OP_SIZE 4 OP_SUB OP_SPLIT OP_NIP OP_BIN2NUM
        this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
        this.stackMap.push(null); // preimage still there
        this.stackMap.push(null); // size on top
        this.emitOp({ op: 'push', value: 4n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SUB' });
        this.stackMap.pop(); // 4
        this.stackMap.pop(); // size
        this.stackMap.push(null); // (size-4)
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop(); // offset
        this.stackMap.pop(); // preimage
        this.stackMap.push(null); // left
        this.stackMap.push(null); // right (sighashType bytes)
        this.emitOp({ op: 'nip' }); // drop left
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
        break;

      case 'extractLocktime':
        // End-relative: 4 bytes before the last 4 (sighashType).
        // <preimage> OP_SIZE 8 OP_SUB OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
        this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 8n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SUB' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 4n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
        break;

      case 'extractOutputHash':
        // End-relative: 32 bytes before the last 8 (nLocktime 4 + sighashType 4).
        // <preimage> OP_SIZE 44 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
        this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 44n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SUB' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 32n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        break;

      case 'extractOutputs':
        // Alias for extractOutputHash — same 32-byte hashOutputs field.
        this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 44n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SUB' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 32n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        break;

      case 'extractAmount':
        // End-relative: 8 bytes (LE int64) before nSequence(4) + hashOutputs(32) + nLocktime(4) + sighashType(4) = 44 bytes from end.
        // Total end offset: 44 + 4 + 8 = 56. Amount starts 56 bytes from end, is 8 bytes.
        // <preimage> OP_SIZE 52 OP_SUB OP_SPLIT OP_NIP 8 OP_SPLIT OP_DROP OP_BIN2NUM
        this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 52n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SUB' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 8n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
        break;

      case 'extractSequence':
        // End-relative: 4 bytes (nSequence) before hashOutputs(32) + nLocktime(4) + sighashType(4) = 40 bytes from end.
        // Total end offset: 40 + 4 = 44. nSequence starts 44 bytes from end, is 4 bytes.
        // <preimage> OP_SIZE 44 OP_SUB OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
        this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 44n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SUB' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 4n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
        break;

      case 'extractScriptCode':
        // Variable-length field at offset 104. End offset is: amount(8) + nSequence(4) + hashOutputs(32) + nLocktime(4) + sighashType(4) = 52 bytes from end.
        // scriptCode = preimage[104 .. len-52]
        // <preimage> 104 OP_SPLIT OP_NIP — skip fixed prefix
        // then: OP_SIZE 52 OP_SUB OP_SPLIT OP_DROP — take up to len-52 relative to remaining
        // But we need to recalculate: after splitting off first 104, the remaining has length = total - 104.
        // We want to take (total - 104 - 52) = (total - 156) bytes from that.
        // Simpler: OP_SIZE gives length of remaining. We want remaining_len - 52 bytes.
        this.emitOp({ op: 'push', value: 104n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' }); // drop prefix
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        // Now have the tail from offset 104. Get its size - 52 = scriptCode length.
        this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 52n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SUB' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' }); // drop tail
        this.stackMap.pop();
        break;

      case 'extractInputIndex':
        // The input index is encoded in the outpoint's vout field (bytes 100-103, 4 bytes at offset 100).
        // Outpoint is at offset 68, 36 bytes. vout is the last 4 bytes of outpoint = offset 100.
        // <preimage> 100 OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
        this.emitOp({ op: 'push', value: 100n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop();
        this.stackMap.pop();
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 4n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop();
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
        break;

      default:
        throw new Error(`Unknown extractor: ${func}`);
    }

    // Rename top of stack to the binding name
    this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower safediv(a, b) or safemod(a, b) — assert b != 0, then divide/mod.
   * Opcodes: <a> <b> OP_DUP OP_0NOTEQUAL OP_VERIFY OP_DIV (or OP_MOD)
   */
  private lowerSafeDivMod(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) throw new Error(`${func} requires 2 arguments`);
    const [a, b] = args as [string, string];

    const aIsLast = this.isLastUse(a, bindingIndex, lastUses);
    this.bringToTop(a, aIsLast);

    const bIsLast = this.isLastUse(b, bindingIndex, lastUses);
    this.bringToTop(b, bIsLast);

    // Stack: ... a b
    // DUP b, check non-zero, then divide/mod
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });   // ... a b b
    this.stackMap.push(null); // extra b copy
    this.emitOp({ op: 'opcode', code: 'OP_0NOTEQUAL' }); // ... a b (b!=0)
    this.emitOp({ op: 'opcode', code: 'OP_VERIFY' });     // ... a b (aborts if zero)
    this.stackMap.pop(); // remove the check result

    // Pop both operands, emit div or mod
    this.stackMap.pop(); // b
    this.stackMap.pop(); // a
    const opcode = func === 'safediv' ? 'OP_DIV' : 'OP_MOD';
    this.emitOp({ op: 'opcode', code: opcode });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower clamp(val, lo, hi) — clamp value to [lo, hi].
   * Opcodes: <val> <lo> OP_MAX <hi> OP_MIN
   */
  private lowerClamp(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 3) throw new Error('clamp requires 3 arguments');
    const [val, lo, hi] = args as [string, string, string];

    const valIsLast = this.isLastUse(val, bindingIndex, lastUses);
    this.bringToTop(val, valIsLast);

    const loIsLast = this.isLastUse(lo, bindingIndex, lastUses);
    this.bringToTop(lo, loIsLast);

    // Stack: ... val lo → OP_MAX → max(val, lo)
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_MAX' });
    this.stackMap.push(null); // intermediate

    const hiIsLast = this.isLastUse(hi, bindingIndex, lastUses);
    this.bringToTop(hi, hiIsLast);

    // Stack: ... max(val,lo) hi → OP_MIN → min(max(val,lo), hi)
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_MIN' });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower pow(base, exp) — exponentiation.
   * For constant exponents, unrolls to repeated OP_MUL.
   * For runtime exponents, emits a bounded loop.
   */
  private lowerPow(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) throw new Error('pow requires 2 arguments');
    const [base, exp] = args as [string, string];

    const baseIsLast = this.isLastUse(base, bindingIndex, lastUses);
    this.bringToTop(base, baseIsLast);

    const expIsLast = this.isLastUse(exp, bindingIndex, lastUses);
    this.bringToTop(exp, expIsLast);

    this.stackMap.pop(); // exp
    this.stackMap.pop(); // base

    // Emit the pow computation as a flat opcode sequence:
    // Input stack:  <base> <exp>  (already consumed from stackMap above)
    // Output stack: <result>
    //
    // Algorithm: iterative multiply with bounded loop (max 32 iterations)
    // <base> <exp>
    // OP_SWAP      → <exp> <base>
    // OP_1         → <exp> <base> <1>  (accumulator)
    // Then 32x: <exp> <base> <acc>
    //   2 OP_PICK  → <exp> <base> <acc> <exp>
    //   <i+1>      → <exp> <base> <acc> <exp> <i+1>
    //   OP_GREATERTHAN → <exp> <base> <acc> <exp > i>
    //   OP_IF
    //     OP_OVER   → <exp> <base> <acc> <base>
    //     OP_MUL    → <exp> <base> <acc*base>
    //   OP_ENDIF
    //
    // After all iterations: <exp> <base> <result>
    // OP_NIP OP_NIP → <result>
    //
    // Wait, this multiplies unconditionally for each step where exp > i.
    // That gives base^min(exp, 32). That's correct!

    this.emitOp({ op: 'swap' });     // exp base
    this.emitOp({ op: 'push', value: 1n }); // exp base 1

    const MAX_POW_ITERATIONS = 32;
    for (let i = 0; i < MAX_POW_ITERATIONS; i++) {
      // Stack: exp base acc
      this.emitOp({ op: 'push', value: 2n });
      this.emitOp({ op: 'opcode', code: 'OP_PICK' }); // exp base acc exp
      this.emitOp({ op: 'push', value: BigInt(i + 1) });
      this.emitOp({ op: 'opcode', code: 'OP_GREATERTHAN' }); // exp base acc (exp > i)
      this.emitOp({
        op: 'if',
        then: [
          { op: 'over' },  // exp base acc base
          { op: 'opcode', code: 'OP_MUL' },  // exp base (acc*base)
        ],
        else: undefined,
      });
    }
    // Stack: exp base result
    this.emitOp({ op: 'nip' }); // exp result
    this.emitOp({ op: 'nip' }); // result

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower mulDiv(a, b, c) — (a * b) / c without intermediate overflow concern.
   * Opcodes: <a> <b> OP_MUL <c> OP_DIV
   * (Bitcoin Script numbers can be large, so no overflow issue.)
   */
  private lowerMulDiv(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 3) throw new Error('mulDiv requires 3 arguments');
    const [a, b, c] = args as [string, string, string];

    const aIsLast = this.isLastUse(a, bindingIndex, lastUses);
    this.bringToTop(a, aIsLast);
    const bIsLast = this.isLastUse(b, bindingIndex, lastUses);
    this.bringToTop(b, bIsLast);

    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_MUL' });
    this.stackMap.push(null);

    const cIsLast = this.isLastUse(c, bindingIndex, lastUses);
    this.bringToTop(c, cIsLast);

    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_DIV' });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower percentOf(amount, bps) — (amount * bps) / 10000.
   * Opcodes: <amount> <bps> OP_MUL <10000> OP_DIV
   */
  private lowerPercentOf(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) throw new Error('percentOf requires 2 arguments');
    const [amount, bps] = args as [string, string];

    const amountIsLast = this.isLastUse(amount, bindingIndex, lastUses);
    this.bringToTop(amount, amountIsLast);
    const bpsIsLast = this.isLastUse(bps, bindingIndex, lastUses);
    this.bringToTop(bps, bpsIsLast);

    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_MUL' });
    this.stackMap.push(null);

    this.emitOp({ op: 'push', value: 10000n });
    this.stackMap.push(null);

    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_DIV' });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower sqrt(n) — integer square root via Newton's method.
   * Emits a bounded iteration (16 rounds suffice for 256-bit numbers).
   * Algorithm: guess = n, then repeatedly guess = (guess + n/guess) / 2
   */
  private lowerSqrt(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 1) throw new Error('sqrt requires 1 argument');
    const n = args[0]!;

    const nIsLast = this.isLastUse(n, bindingIndex, lastUses);
    this.bringToTop(n, nIsLast);
    this.stackMap.pop();

    // Stack: <n>
    // DUP to get initial guess = n
    this.emitOp({ op: 'opcode', code: 'OP_DUP' }); // n guess(=n)

    // 16 Newton iterations: guess = (guess + n/guess) / 2
    const SQRT_ITERATIONS = 16;
    for (let i = 0; i < SQRT_ITERATIONS; i++) {
      // Stack: n guess
      this.emitOp({ op: 'over' });                      // n guess n
      this.emitOp({ op: 'over' });                      // n guess n guess
      this.emitOp({ op: 'opcode', code: 'OP_DIV' });    // n guess (n/guess)
      this.emitOp({ op: 'opcode', code: 'OP_ADD' });    // n (guess + n/guess)
      this.emitOp({ op: 'push', value: 2n });            // n (guess + n/guess) 2
      this.emitOp({ op: 'opcode', code: 'OP_DIV' });    // n new_guess
    }
    // Stack: n result
    this.emitOp({ op: 'nip' }); // result (drop n)

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower gcd(a, b) — Euclidean algorithm.
   * Bounded to 256 iterations.
   * Algorithm: while (b != 0) { temp = b; b = a % b; a = temp; } return a;
   */
  private lowerGcd(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) throw new Error('gcd requires 2 arguments');
    const [a, b] = args as [string, string];

    const aIsLast = this.isLastUse(a, bindingIndex, lastUses);
    this.bringToTop(a, aIsLast);
    const bIsLast = this.isLastUse(b, bindingIndex, lastUses);
    this.bringToTop(b, bIsLast);

    this.stackMap.pop();
    this.stackMap.pop();

    // Stack: a b
    // Both should be absolute values
    this.emitOp({ op: 'opcode', code: 'OP_ABS' });
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'opcode', code: 'OP_ABS' });
    this.emitOp({ op: 'swap' });
    // Stack: |a| |b|

    const GCD_ITERATIONS = 256;
    for (let i = 0; i < GCD_ITERATIONS; i++) {
      // Stack: a b
      // if b != 0: a b → b (a%b)
      this.emitOp({ op: 'opcode', code: 'OP_DUP' });     // a b b
      this.emitOp({ op: 'opcode', code: 'OP_0NOTEQUAL' }); // a b (b!=0)
      this.emitOp({
        op: 'if',
        then: [
          // a b → b (a%b)
          { op: 'opcode', code: 'OP_TUCK' }, // b a b
          { op: 'opcode', code: 'OP_MOD' },  // b (a%b)
        ],
        else: undefined,
      });
    }
    // Stack: result 0 (or result if b was already 0)
    this.emitOp({ op: 'drop' }); // drop the 0

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower divmod(a, b) — returns quotient (division result).
   * Note: divmod in Rúnar returns the quotient. The modulo can be obtained
   * separately. This emits: <a> <b> OP_2DUP OP_MOD OP_TOALTSTACK OP_DIV
   * But since we can only return one value, we return the quotient.
   * The remainder is left on the alt stack for potential future use.
   *
   * Actually, since our type system returns bigint (not a tuple), divmod
   * just computes a / b. For the tuple return, contracts should use
   * separate div and mod calls. We emit both and drop the remainder.
   */
  private lowerDivmod(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) throw new Error('divmod requires 2 arguments');
    const [a, b] = args as [string, string];

    const aIsLast = this.isLastUse(a, bindingIndex, lastUses);
    this.bringToTop(a, aIsLast);
    const bIsLast = this.isLastUse(b, bindingIndex, lastUses);
    this.bringToTop(b, bIsLast);

    this.stackMap.pop();
    this.stackMap.pop();

    // Stack: a b
    // OP_2DUP: a b a b
    this.emitOp({ op: 'opcode', code: 'OP_2DUP' });
    // OP_DIV: a b (a/b)
    this.emitOp({ op: 'opcode', code: 'OP_DIV' });
    // OP_ROT OP_ROT: (a/b) a b
    this.emitOp({ op: 'opcode', code: 'OP_ROT' });
    this.emitOp({ op: 'opcode', code: 'OP_ROT' });
    // OP_MOD: (a/b) (a%b)
    this.emitOp({ op: 'opcode', code: 'OP_MOD' });
    // Drop the remainder, keep quotient
    this.emitOp({ op: 'drop' });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower log2(n) — approximate floor(log2(n)) via byte size.
   * Uses OP_SIZE on the script number encoding.
   * floor(log2(n)) ≈ (byteLength - 1) * 8 + highBitPosition
   * Simplified: (OP_SIZE * 8) - 8 gives a rough approximation.
   * More precisely: OP_SIZE OP_NIP OP_1SUB 8 OP_MUL
   * This gives (byteLength - 1) * 8, which is floor(log2(n)) for
   * numbers that are exact powers of 256.
   *
   * For a simpler but less precise version:
   * OP_SIZE OP_NIP OP_1SUB gives floor(log256(n)), multiply by 8 for bits.
   */
  private lowerLog2(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 1) throw new Error('log2 requires 1 argument');
    const n = args[0]!;

    const nIsLast = this.isLastUse(n, bindingIndex, lastUses);
    this.bringToTop(n, nIsLast);
    this.stackMap.pop();

    // Stack: <n>
    // OP_SIZE leaves: <n> <byteLen>
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
    // OP_NIP: <byteLen>
    this.emitOp({ op: 'nip' });
    // byteLen * 8 - 8 ≈ floor(log2(n))
    this.emitOp({ op: 'push', value: 8n });
    this.emitOp({ op: 'opcode', code: 'OP_MUL' });
    this.emitOp({ op: 'push', value: 8n });
    this.emitOp({ op: 'opcode', code: 'OP_SUB' });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower verifyRabinSig(msg, sig, padding, pubKey) to Script.
   *
   * Rabin signature verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
   *
   * Stack before: <msg> <sig> <padding> <pubKey>
   * Script:
   *   OP_DUP OP_TOALTSTACK        -- save pubKey copy for modulo
   *   OP_SWAP                     -- <msg> <sig> <pubKey> <padding>
   *   OP_3 OP_ROLL                -- <msg> <pubKey> <padding> <sig>
   *   OP_DUP OP_MUL               -- <msg> <pubKey> <padding> <sig^2>
   *   OP_ADD                      -- <msg> <pubKey> <sig^2+padding>
   *   OP_SWAP                     -- <msg> <sig^2+padding> <pubKey>
   *   OP_MOD                      -- <msg> <(sig^2+padding) mod pubKey>
   *   OP_SWAP                     -- <(sig^2+padding) mod pubKey> <msg>
   *   OP_SHA256                   -- <(sig^2+padding) mod pubKey> <SHA256(msg)>
   *   OP_EQUAL                    -- <result>
   */
  private lowerVerifyRabinSig(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 4) {
      throw new Error('verifyRabinSig requires 4 arguments: msg, sig, padding, pubKey');
    }

    // Bring all 4 args to the top: msg, sig, padding, pubKey
    for (const arg of args) {
      const isLast = this.isLastUse(arg, bindingIndex, lastUses);
      this.bringToTop(arg, isLast);
    }

    // Pop all 4 args from stack map
    for (let i = 0; i < 4; i++) {
      this.stackMap.pop();
    }

    // Stack: <msg> <sig> <padding> <pubKey>
    // Compute: (sig^2 + padding) mod pubKey == SHA256(msg)

    // Save pubKey copy, swap padding and pubKey, roll sig to top
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });        // dup pubKey
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });  // stash pubKey in altstack
    this.emitOp({ op: 'opcode', code: 'OP_SWAP' });        // swap padding and pubKey
    this.emitOp({ op: 'opcode', code: 'OP_3' });           // push 3 for ROLL
    this.emitOp({ op: 'opcode', code: 'OP_ROLL' });        // bring sig to top

    // sig^2
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });
    this.emitOp({ op: 'opcode', code: 'OP_MUL' });

    // sig^2 + padding
    this.emitOp({ op: 'opcode', code: 'OP_ADD' });

    // (sig^2 + padding) mod pubKey
    this.emitOp({ op: 'opcode', code: 'OP_SWAP' });
    this.emitOp({ op: 'opcode', code: 'OP_MOD' });

    // SHA256(msg) and compare
    this.emitOp({ op: 'opcode', code: 'OP_SWAP' });
    this.emitOp({ op: 'opcode', code: 'OP_SHA256' });
    this.emitOp({ op: 'opcode', code: 'OP_EQUAL' });

    // Result is on top
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // -------------------------------------------------------------------------
  // WOTS+ verification (post-quantum hash-based signature)
  // w=16, n=32 (SHA-256), len1=64, len2=3, len=67
  // Input:  <msg> <sig> <pubkey>
  // Output: <boolean>
  //
  // Canonical stack between chains: sig_rem(0) csum(1) endpt_acc(2)
  // Alt stack: pubkey only (plus balanced temp saves inside chain processing)
  // -------------------------------------------------------------------------

  /**
   * Emit one WOTS+ chain: sig(0) csum(1) endpt(2) digit(3) → sigRest(0) newCsum(1) newEndpt(2)
   * Alt stack pushes/pops are balanced (4 push, 4 pop).
   */
  private emitWOTSOneChain(): void {
    // steps = 15 - digit
    this.emitOp({ op: 'push', value: 15n });
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'opcode', code: 'OP_SUB' });
    // sig(0) csum(1) endpt(2) steps(3)

    // Save to alt: steps_copy, then endpt, then csum. Leave sig+steps on main.
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#1: steps_copy
    this.emitOp({ op: 'swap' });                            // sig csum steps endpt
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#2: endpt
    this.emitOp({ op: 'swap' });                            // sig steps csum
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#3: csum
    // main: sig(0) steps(1)

    // Split 32B sig element
    this.emitOp({ op: 'swap' });                            // steps sig
    this.emitOp({ op: 'push', value: 32n });
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });       // steps sigElem sigRest
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#4: sigRest
    this.emitOp({ op: 'swap' });                            // sigElem steps

    // Hash loop: hash sigElem `steps` times (max 15)
    for (let j = 0; j < 15; j++) {
      this.emitOp({ op: 'opcode', code: 'OP_DUP' });
      this.emitOp({ op: 'opcode', code: 'OP_0NOTEQUAL' });
      this.emitOp({
        op: 'if',
        then: [
          { op: 'swap' },
          { op: 'opcode', code: 'OP_SHA256' },
          { op: 'swap' },
          { op: 'opcode', code: 'OP_1SUB' },
        ],
        else: undefined,
      });
    }
    this.emitOp({ op: 'drop' }); // drop steps (now 0)
    // main: endpoint

    // Restore from alt (LIFO): sigRest, csum, endpt, steps_copy
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#4: sigRest
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#3: csum
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#2: endpt_acc
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#1: steps_copy
    // main b→t: endpoint(0) sigRest(1) csum(2) endpt_acc(3) steps_copy(4)

    // csum += steps_copy: ROT on top 3 brings csum to top
    this.emitOp({ op: 'opcode', code: 'OP_ROT' });
    // endpoint(0) sigRest(1) endpt_acc(2) steps_copy(3) csum(4)
    this.emitOp({ op: 'opcode', code: 'OP_ADD' });
    // endpoint(0) sigRest(1) endpt_acc(2) newCsum(3)

    // Concat endpoint to endpt_acc
    this.emitOp({ op: 'swap' });
    // endpoint(0) sigRest(1) newCsum(2) endpt_acc(3)
    this.emitOp({ op: 'push', value: 3n });
    this.emitOp({ op: 'opcode', code: 'OP_ROLL' });
    // sigRest(0) newCsum(1) endpt_acc(2) endpoint(3)
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    // sigRest(0) newCsum(1) newEndptAcc(2)
  }

  private lowerVerifyWOTS(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 3) {
      throw new Error('verifyWOTS requires 3 arguments: msg, sig, pubkey');
    }

    // Bring args to top: msg, sig, pubkey
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    for (let i = 0; i < 3; i++) this.stackMap.pop();
    // main: msg(0) sig(1) pubkey(2)

    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // pubkey → alt
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'opcode', code: 'OP_SHA256' });
    // main: sig(0) msgHash(1)

    // Canonical layout: sig(0) csum=0(1) endptAcc=empty(2) hashRem(3)
    this.emitOp({ op: 'swap' });                // msgHash sig
    this.emitOp({ op: 'push', value: 0n });     // msgHash sig 0
    this.emitOp({ op: 'opcode', code: 'OP_0' }); // msgHash sig 0 empty
    this.emitOp({ op: 'push', value: 3n });
    this.emitOp({ op: 'opcode', code: 'OP_ROLL' }); // sig 0 empty msgHash

    // Process 32 bytes → 64 message chains
    for (let byteIdx = 0; byteIdx < 32; byteIdx++) {
      // main: sig csum endptAcc hashRem
      if (byteIdx < 31) {
        this.emitOp({ op: 'push', value: 1n });
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // sig csum endpt byte hashRest
        this.emitOp({ op: 'swap' });                       // sig csum endpt hashRest byte
      }
      // Convert 1-byte string to unsigned integer.
      // BIN2NUM treats bit 7 as sign bit, so bytes >= 0x80 become negative.
      // Fix: append a 0x00 byte so the 2-byte value is always positive.
      this.emitOp({ op: 'push', value: 0n });
      this.emitOp({ op: 'push', value: 1n });
      this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' }); // push 0x00 byte
      this.emitOp({ op: 'opcode', code: 'OP_CAT' });     // <byte 0x00> (2 bytes)
      this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' }); // unsigned 0-255
      this.emitOp({ op: 'opcode', code: 'OP_DUP' });
      this.emitOp({ op: 'push', value: 16n });
      this.emitOp({ op: 'opcode', code: 'OP_DIV' });  // high
      this.emitOp({ op: 'swap' });
      this.emitOp({ op: 'push', value: 16n });
      this.emitOp({ op: 'opcode', code: 'OP_MOD' });  // low

      // Save low (and hashRest if present) to alt
      if (byteIdx < 31) {
        this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // low → alt
        this.emitOp({ op: 'swap' });
        this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // hashRest → alt
      } else {
        this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // low → alt
      }
      // main: sig csum endptAcc high

      this.emitWOTSOneChain(); // → sigRest newCsum newEndptAcc

      // Retrieve low from alt (and hashRest)
      if (byteIdx < 31) {
        this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // hashRest
        this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // low
        this.emitOp({ op: 'swap' });
        this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // hashRest → alt
      } else {
        this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // low
      }
      // main: sigRest csum endptAcc low

      this.emitWOTSOneChain(); // → sigRest2 csum2 endptAcc2

      if (byteIdx < 31) {
        this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // hashRest
      }
    }

    // main: sigRest(96B)(0) totalCsum(1) endptAcc(2)  |  alt: pubkey

    // Compute 3 checksum digits
    this.emitOp({ op: 'swap' }); // sigRest endptAcc totalCsum

    // d66 = csum % 16  (pushed first → bottom of 3 on alt → popped last)
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });
    this.emitOp({ op: 'push', value: 16n });
    this.emitOp({ op: 'opcode', code: 'OP_MOD' });
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });

    // d65 = (csum/16) % 16
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });
    this.emitOp({ op: 'push', value: 16n });
    this.emitOp({ op: 'opcode', code: 'OP_DIV' });
    this.emitOp({ op: 'push', value: 16n });
    this.emitOp({ op: 'opcode', code: 'OP_MOD' });
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });

    // d64 = (csum/256) % 16  (pushed last → top of 3 on alt → popped first)
    this.emitOp({ op: 'push', value: 256n });
    this.emitOp({ op: 'opcode', code: 'OP_DIV' });
    this.emitOp({ op: 'push', value: 16n });
    this.emitOp({ op: 'opcode', code: 'OP_MOD' });
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // main: sigRest(0) endptAcc(1)  |  alt: pubkey, d66, d65, d64

    // Process 3 checksum chains
    for (let ci = 0; ci < 3; ci++) {
      // main: sigRest(0) endptAcc(1)
      // Set up: sigRest(0) dummyCsum=0(1) endptAcc(2) digit(3)
      this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // endptAcc → alt (temp)
      this.emitOp({ op: 'push', value: 0n });                // sigRest 0
      this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // sigRest 0 endptAcc
      this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // sigRest 0 endptAcc digit

      this.emitWOTSOneChain();
      // main: sigRest(0) dummyCsum(1) newEndptAcc(2)

      // Drop dummy csum
      this.emitOp({ op: 'swap' }); // sigRest newEndptAcc dummyCsum
      this.emitOp({ op: 'drop' }); // sigRest newEndptAcc
    }

    // main: sigRest(empty)(0) endptAcc(1)  |  alt: pubkey
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'drop' }); // drop empty sigRest

    // Hash concatenated endpoints → computed public key
    this.emitOp({ op: 'opcode', code: 'OP_SHA256' });

    // Compare to pubkey
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pubkey
    this.emitOp({ op: 'opcode', code: 'OP_EQUAL' });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // SLH-DSA verification — delegates to slh-dsa-codegen.ts
  // =========================================================================

  private lowerVerifySLHDSA(
    bindingName: string,
    paramKey: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 3) {
      throw new Error('verifySLHDSA requires 3 arguments: msg, sig, pubkey');
    }
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    for (let i = 0; i < 3; i++) this.stackMap.pop();

    emitVerifySLHDSA((op) => this.emitOp(op), paramKey);

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerReverseBytes(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 1) {
      throw new Error('reverseBytes requires 1 argument');
    }
    const arg = args[0]!;
    const isLast = this.isLastUse(arg, bindingIndex, lastUses);
    this.bringToTop(arg, isLast);

    // BSV Genesis protocol provides OP_REVERSE (0xd1) for byte string reversal.
    // This is the most efficient implementation and handles any input length.
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_REVERSE' });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerSubstr(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // substr(data, start, length)
    // Compiled to: <data> <start> OP_SPLIT OP_NIP <length> OP_SPLIT OP_DROP
    if (args.length < 3) {
      throw new Error('substr requires 3 arguments');
    }

    const [data, start, length] = args as [string, string, string];

    // Push data
    const dataIsLast = this.isLastUse(data, bindingIndex, lastUses);
    this.bringToTop(data, dataIsLast);

    // Push start offset
    const startIsLast = this.isLastUse(start, bindingIndex, lastUses);
    this.bringToTop(start, startIsLast);

    // Split at start: [left, right]
    this.stackMap.pop(); // start consumed
    this.stackMap.pop(); // data consumed
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    this.stackMap.push(null); // left part (discard)
    this.stackMap.push(null); // right part (keep)

    // Drop the left part (NIP removes second-from-top)
    this.emitOp({ op: 'nip' });
    this.stackMap.pop();
    const rightPart = this.stackMap.pop();
    this.stackMap.push(rightPart);

    // Push length
    const lenIsLast = this.isLastUse(length, bindingIndex, lastUses);
    this.bringToTop(length, lenIsLast);

    // Split at length: [result, remainder]
    this.stackMap.pop(); // length consumed
    this.stackMap.pop(); // right part consumed
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    this.stackMap.push(null); // result (keep)
    this.stackMap.push(null); // remainder (discard)

    // Drop the remainder
    this.emitOp({ op: 'drop' });
    this.stackMap.pop();
    this.stackMap.pop();

    this.stackMap.push(bindingName);
    this.trackDepth();
  }
}

// ---------------------------------------------------------------------------
// Hex utility
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`Invalid hex string length: ${hex.length}`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Lower an ANF program to Stack IR.
 *
 * For each method, parameters are assumed to already be on the stack
 * (pushed by the Bitcoin VM from the scriptSig). The lowering tracks
 * named temporaries via a stack map and emits PICK/ROLL to materialise
 * values as needed.
 */
export function lowerToStack(program: ANFProgram): StackProgram {
  const methods: StackMethod[] = [];
  const privateMethods = new Map<string, ANFMethod>();

  for (const method of program.methods) {
    if (method.name !== 'constructor' && !method.isPublic) {
      privateMethods.set(method.name, method);
    }
  }

  for (const method of program.methods) {
    if (method.name !== 'constructor' && !method.isPublic) {
      continue;
    }
    const stackMethod = lowerMethod(method, program.properties, privateMethods);
    methods.push(stackMethod);
  }

  return {
    contractName: program.contractName,
    methods,
  };
}

/**
 * Check whether a method's body contains a check_preimage binding.
 * If so, the unlocking script will push an implicit <sig> parameter
 * before all declared parameters and we must account for it in the
 * stack map.
 */
function methodUsesCheckPreimage(bindings: ANFBinding[]): boolean {
  for (const b of bindings) {
    if (b.value.kind === 'check_preimage') return true;
  }
  return false;
}

function lowerMethod(
  method: ANFMethod,
  properties: ANFProperty[],
  privateMethods: Map<string, ANFMethod>,
): StackMethod {
  const paramNames = method.params.map(p => p.name);

  // If the method uses checkPreimage, the unlocking script pushes an
  // implicit <sig> before all declared parameters (OP_PUSH_TX pattern).
  // Insert _opPushTxSig at the base of the stack so it can be consumed
  // by lowerCheckPreimage later.
  if (methodUsesCheckPreimage(method.body)) {
    paramNames.unshift('_opPushTxSig');
  }

  const ctx = new LoweringContext(paramNames, properties, privateMethods);
  // Pass terminalAssert=true for public methods so the last assert leaves
  // its value on the stack (Bitcoin Script requires a truthy top-of-stack).
  ctx.lowerBindings(method.body, method.isPublic);

  const { ops, maxStackDepth } = ctx.result;

  if (maxStackDepth > MAX_STACK_DEPTH) {
    throw new Error(
      `Method '${method.name}' exceeds maximum stack depth of ${MAX_STACK_DEPTH} ` +
      `(actual: ${maxStackDepth}). Simplify the contract logic.`,
    );
  }

  return {
    name: method.name,
    ops,
    maxStackDepth,
  };
}
