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
    case 'load_prop':
    case 'load_const':
    case 'get_state_script':
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
   */
  lowerBindings(bindings: ANFBinding[]): void {
    const lastUses = computeLastUses(bindings);

    for (let i = 0; i < bindings.length; i++) {
      const binding = bindings[i]!;
      this.lowerBinding(binding, i, lastUses);
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

    if (func === 'reverseBytes') {
      this.lowerReverseBytes(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'substr') {
      this.lowerSubstr(bindingName, args, bindingIndex, lastUses);
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
    // Loops are unrolled at compile time. Repeat the body `count` times.
    for (let i = 0; i < count; i++) {
      // Push the iteration index as a constant (in case the loop body uses it)
      this.emitOp({ op: 'push', value: BigInt(i) });
      this.stackMap.push(_iterVar);
      this.lowerBindings(body);
    }
    // Loop produces a dummy value
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerAssert(
    value: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    const isLast = this.isLastUse(value, bindingIndex, lastUses);
    this.bringToTop(value, isLast);
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_VERIFY' });
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
  ctx.lowerBindings(method.body);

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
