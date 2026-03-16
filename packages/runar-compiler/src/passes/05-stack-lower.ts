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
import {
  emitEcAdd, emitEcMul, emitEcMulGen, emitEcNegate,
  emitEcOnCurve, emitEcModReduce, emitEcEncodeCompressed,
  emitEcMakePoint, emitEcPointX, emitEcPointY,
} from './ec-codegen.js';
import { emitSha256Compress, emitSha256Finalize } from './sha256-codegen.js';
import { emitBlake3Compress, emitBlake3Hash } from './blake3-codegen.js';

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
  // Note: `len` maps to OP_SIZE but has special stack handling below
  // because OP_SIZE leaves the original value on stack (stack: [original, size]).
  // The handler emits OP_NIP to remove the original, keeping only the size.
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
  int2str: ['OP_NUM2BIN'],
  bool: ['OP_0NOTEQUAL'],
  unpack: ['OP_BIN2NUM'],
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
    throw new Error(`Value '${name}' not found on stack (stack has ${this.slots.length} items: [${this.slots.join(', ')}])`);
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

  /** Get the set of all named (non-null) slot values. */
  namedSlots(): Set<string> {
    const names = new Set<string>();
    for (const s of this.slots) {
      if (s !== null) names.add(s);
    }
    return names;
  }

  /** Rename a slot at a given depth from top. */
  renameAtDepth(depthFromTop: number, newName: string | null): void {
    const index = this.slots.length - 1 - depthFromTop;
    if (index < 0 || index >= this.slots.length) {
      throw new Error(`Invalid stack depth for rename: ${depthFromTop}`);
    }
    this.slots[index] = newName;
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
    case 'get_state_script':
      break;
    case 'load_const':
      // load_const with @ref: values reference another binding
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
// Core lowering context
// ---------------------------------------------------------------------------

class LoweringContext {
  private stackMap: StackMap;
  private ops: StackOp[] = [];
  private maxDepth = 0;
  private _properties: ANFProperty[];
  private privateMethods: Map<string, ANFMethod>;
  /** Binding names defined in the current lowerBindings scope.
   *  Used by @ref: handler to decide whether to consume (local) or copy (outer-scope). */
  private localBindings: Set<string> = new Set();
  /** Parent-scope refs that must not be consumed (used after the current if-branch). */
  private outerProtectedRefs: Set<string> | null = null;
  /** True when executing inside an if-branch. update_prop skips old-value
   *  removal so that the same-property detection in lowerIf can handle it. */
  private _insideBranch = false;
  /** Debug: source location to attach to next emitted StackOps. */
  private currentSourceLoc: { file: string; line: number; column: number } | undefined;
  /** Tracks the number of elements in array literal bindings for checkMultiSig. */
  private arrayLengths: Map<string, number> = new Map();

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

  /**
   * Clean up excess stack items below the top-of-stack result.
   * Used after method body lowering to ensure a clean stack for Bitcoin Script.
   */
  cleanupExcessStack(): void {
    if (this.stackMap.depth > 1) {
      const excess = this.stackMap.depth - 1;
      for (let i = 0; i < excess; i++) {
        this.emitOp({ op: 'nip' });
        this.stackMap.removeAtDepth(1);
      }
    }
  }

  private trackDepth(): void {
    if (this.stackMap.depth > this.maxDepth) {
      this.maxDepth = this.stackMap.depth;
    }
  }

  private emitOp(stackOp: StackOp): void {
    if (this.currentSourceLoc && !stackOp.sourceLoc) {
      stackOp.sourceLoc = this.currentSourceLoc;
    }
    this.ops.push(stackOp);
    this.trackDepth();
  }

  /**
   * Emit a Bitcoin varint encoding of the length on top of the stack.
   *
   * Expects stack: [..., script, len]
   * Leaves stack:  [..., script, varint_bytes]
   *
   * Bitcoin varint format:
   *   - len < 253:    1 byte (unsigned)
   *   - len >= 253:   0xfd + 2 bytes unsigned LE
   *
   * OP_NUM2BIN uses sign-magnitude encoding, so values 128-255 need 2 bytes
   * to avoid the sign bit ambiguity. To produce a correct 1-byte unsigned
   * varint, we use OP_NUM2BIN 2 to get a 2-byte sign-magnitude result and
   * then SPLIT to extract only the low byte.
   *
   * Similarly, for 2-byte unsigned LE varints, values >= 32768 would need
   * 3 bytes in sign-magnitude. We use OP_NUM2BIN 4 and SPLIT to extract
   * the low 2 bytes.
   */
  private emitVarintEncoding(): void {
    // Stack: [..., script, len]
    this.emitOp({ op: 'dup' }); // [script, len, len]
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 253n }); // [script, len, len, 253]
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_LESSTHAN' }); // [script, len, isSmall]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);

    this.emitOp({ op: 'opcode', code: 'OP_IF' });
    this.stackMap.pop(); // pop condition

    // Then: 1-byte varint (len < 253)
    // Use NUM2BIN 2 to avoid sign-magnitude issue for values 128-252,
    // then take only the first (low) byte via SPLIT.
    this.emitOp({ op: 'push', value: 2n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' }); // [script, len_2bytes]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 1n }); // [script, len_2bytes, 1]
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [script, lowByte, highByte]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // lowByte
    this.stackMap.push(null); // highByte
    this.emitOp({ op: 'drop' }); // [script, lowByte]
    this.stackMap.pop();

    this.emitOp({ op: 'opcode', code: 'OP_ELSE' });

    // Else: 0xfd + 2-byte LE varint (len >= 253)
    // Use NUM2BIN 4 to avoid sign-magnitude issue for values >= 32768,
    // then take only the first 2 (low) bytes via SPLIT.
    this.emitOp({ op: 'push', value: 4n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' }); // [script, len_4bytes]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 2n }); // [script, len_4bytes, 2]
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [script, low2bytes, high2bytes]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // low2bytes
    this.stackMap.push(null); // high2bytes
    this.emitOp({ op: 'drop' }); // [script, low2bytes]
    this.stackMap.pop();
    this.emitOp({ op: 'push', value: new Uint8Array([0xfd]) });
    this.stackMap.push(null);
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.push(null);

    this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
    // --- Stack: [..., script, varint] ---
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
    this.localBindings = new Set(bindings.map(b => b.name));
    const lastUses = computeLastUses(bindings);

    // Protect parent-scope refs that are still needed after this scope
    // (e.g., txPreimage used both inside an if-branch and after the if).
    if (this.outerProtectedRefs) {
      for (const ref of this.outerProtectedRefs) {
        lastUses.set(ref, bindings.length);
      }
    }

    // Find the terminal binding index (if terminalAssert is set).
    // If the last binding is an 'if' whose branches end in asserts,
    // that 'if' is the terminal point (not an earlier standalone assert).
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
      // Propagate source location from ANF binding to StackOps
      this.currentSourceLoc = binding.sourceLoc;
      if (binding.value.kind === 'assert' && i === lastAssertIdx) {
        // Terminal assert: leave value on stack instead of OP_VERIFY
        this.lowerAssert(binding.value.value, i, lastUses, true);
      } else if (binding.value.kind === 'if' && i === terminalIfIdx) {
        // Terminal if: propagate terminalAssert into both branches
        this.lowerIf(binding.name, binding.value.cond, binding.value.then, binding.value.else, i, lastUses, true);
      } else {
        this.lowerBinding(binding, i, lastUses);
      }
      this.currentSourceLoc = undefined;
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
        this.lowerDeserializeState(value.preimage, bindingIndex, lastUses);
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
    if (this.stackMap.has(propName)) {
      // If the property has been updated (via update_prop), it lives on the stack.
      // Must check this BEFORE initialValue — after update_prop, we need the
      // updated value, not the original constant.
      this.bringToTop(propName, false);
      this.stackMap.pop();
    } else if (prop && prop.initialValue !== undefined) {
      this.pushValue(prop.initialValue);
    } else {
      // Property value will be provided at deployment time; emit a placeholder.
      // The emitter records byte offsets so the SDK can splice in real values.
      const paramIndex = this._properties.findIndex(p => p.name === propName);
      this.emitOp({
        op: 'placeholder',
        paramIndex: paramIndex >= 0 ? paramIndex : 0,
        paramName: propName,
      });
    }
    this.stackMap.push(bindingName);
  }

  private lowerLoadConst(
    bindingName: string,
    value: string | bigint | boolean,
    bindingIndex: number = 0,
    lastUses: Map<string, number> = new Map(),
  ): void {
    // Handle @ref: aliases (ANF variable aliasing)
    if (typeof value === 'string' && value.startsWith('@ref:')) {
      const refName = value.slice(5);
      if (this.stackMap.has(refName)) {
        // Only consume (ROLL) if the ref target is a local binding in the
        // current scope. Outer-scope refs must be copied (PICK) so that the
        // parent stackMap stays in sync (critical for IfElse branches and
        // BoundedLoop iterations).
        const consume = this.localBindings.has(refName)
          && this.isLastUse(refName, bindingIndex, lastUses);
        this.bringToTop(refName, consume);
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

    // For byte-typed operands, override certain operators.
    if (resultType === 'bytes' && (op === '===' || op === '!==')) {
      this.emitOp({ op: 'opcode', code: 'OP_EQUAL' });
      if (op === '!==') {
        this.emitOp({ op: 'opcode', code: 'OP_NOT' });
      }
    } else if (resultType === 'bytes' && op === '+') {
      // ByteString concatenation: + on byte types emits OP_CAT, not OP_ADD.
      this.emitOp({ op: 'opcode', code: 'OP_CAT' });
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

    if (func === 'exit') {
      // exit(condition) => condition OP_VERIFY — same as assert
      if (args.length >= 1) {
        const arg = args[0]!;
        const isLast = this.isLastUse(arg, bindingIndex, lastUses);
        this.bringToTop(arg, isLast);
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_VERIFY' });
        this.stackMap.push(bindingName);
      }
      return;
    }

    // pack() and toByteString() are type-level casts — no-ops at the script level
    if (func === 'pack' || func === 'toByteString') {
      if (args.length >= 1) {
        const arg = args[0]!;
        const isLast = this.isLastUse(arg, bindingIndex, lastUses);
        this.bringToTop(arg, isLast);
        // Replace the arg's stack entry with the binding name
        this.stackMap.pop();
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

    if (func === '__array_access') {
      this.lowerArrayAccess(bindingName, args, bindingIndex, lastUses);
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

    if (func === 'sha256Compress') {
      this.lowerSha256Compress(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'sha256Finalize') {
      this.lowerSha256Finalize(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'blake3Compress') {
      this.lowerBlake3Compress(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'blake3Hash') {
      this.lowerBlake3Hash(bindingName, args, bindingIndex, lastUses);
      return;
    }

    // EC builtins
    if (func === 'ecAdd' || func === 'ecMul' || func === 'ecMulGen' ||
        func === 'ecNegate' || func === 'ecOnCurve' || func === 'ecModReduce' ||
        func === 'ecEncodeCompressed' || func === 'ecMakePoint' ||
        func === 'ecPointX' || func === 'ecPointY') {
      this.lowerEcBuiltin(bindingName, func, args, bindingIndex, lastUses);
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

    if (func === 'sign') {
      this.lowerSign(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'right') {
      this.lowerRight(bindingName, args, bindingIndex, lastUses);
      return;
    }

    if (func === 'checkMultiSig') {
      this.lowerCheckMultiSig(bindingName, args, bindingIndex, lastUses);
      return;
    }

    // computeStateOutputHash(preimage, stateBytes) — builds the full BIP-143
    // output serialization for a single-output stateful continuation, then hashes it.
    // Extracts codePart and amount from the preimage's scriptCode field, builds:
    //   amount(8LE) + varint(scriptLen) + codePart + OP_RETURN + stateBytes
    // and returns hash256 of the result.
    if (func === 'computeStateOutputHash') {
      this.lowerComputeStateOutputHash(bindingName, args, bindingIndex, lastUses);
      return;
    }

    // computeStateOutput(preimage, stateBytes) — same as computeStateOutputHash
    // but returns raw output bytes WITHOUT hashing. Used when the output bytes
    // need to be concatenated with a change output before hashing.
    if (func === 'computeStateOutput') {
      this.lowerComputeStateOutput(bindingName, args, bindingIndex, lastUses);
      return;
    }

    // buildChangeOutput(pkh, amount) — builds a P2PKH output serialization:
    //   amount(8LE) + varint(25) + OP_DUP OP_HASH160 OP_PUSHBYTES_20 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    //   = amount(8LE) + 0x19 + 76a914 <pkh:20> 88ac
    if (func === 'buildChangeOutput') {
      this.lowerBuildChangeOutput(bindingName, args, bindingIndex, lastUses);
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
      // OP_SIZE leaves original on stack and pushes length on top.
      // Emit OP_NIP to remove the original value, keeping only the size.
      this.emitOp({ op: 'nip' });
      this.stackMap.push(bindingName);
    } else {
      this.stackMap.push(bindingName);
    }

    this.trackDepth();
  }

  /**
   * Lower an array literal to stack. Each element is brought to the top
   * in order. The binding name represents the array as a whole on the stack.
   * The element count is recorded in `arrayLengths` so that consumers
   * (like checkMultiSig) can emit the count push.
   */
  private lowerArrayLiteral(
    bindingName: string,
    elements: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Bring each element to the top in order
    for (const elem of elements) {
      const isLast = this.isLastUse(elem, bindingIndex, lastUses);
      this.bringToTop(elem, isLast);
    }

    // Pop all elements from the stack map (they're consumed into the array)
    for (let i = 0; i < elements.length; i++) {
      this.stackMap.pop();
    }

    // Push the array binding name — represents the N elements now on stack
    this.stackMap.push(bindingName);
    // Record the array length for checkMultiSig
    this.arrayLengths.set(bindingName, elements.length);
    this.trackDepth();
  }

  /**
   * Lower checkMultiSig([sig1, sig2, ...], [pk1, pk2, ...]) to Bitcoin Script.
   *
   * OP_CHECKMULTISIG expects the stack layout:
   *   OP_0 <sig1> <sig2> ... <nSigs> <pk1> <pk2> ... <nPKs> OP_CHECKMULTISIG
   *
   * The args[0] is the sigs array binding, args[1] is the pubkeys array binding.
   * Each was lowered as an array_literal, so the individual elements are already
   * on the stack. We need to insert the OP_0 dummy, counts, and the opcode.
   */
  private lowerCheckMultiSig(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length !== 2) {
      throw new Error(`checkMultiSig expects 2 arguments, got ${args.length}`);
    }

    const sigsRef = args[0]!;
    const pksRef = args[1]!;
    const nSigs = this.arrayLengths.get(sigsRef) ?? 1;
    const nPKs = this.arrayLengths.get(pksRef) ?? 1;

    // Push OP_0 dummy (required by Bitcoin's OP_CHECKMULTISIG bug)
    this.emitOp({ op: 'push', value: 0n });
    this.stackMap.push(null);

    // Bring sigs array to top (the individual elements are treated as one item)
    const sigsLast = this.isLastUse(sigsRef, bindingIndex, lastUses);
    this.bringToTop(sigsRef, sigsLast);

    // Push nSigs count
    this.emitOp({ op: 'push', value: BigInt(nSigs) });
    this.stackMap.push(null);

    // Bring pubkeys array to top
    const pksLast = this.isLastUse(pksRef, bindingIndex, lastUses);
    this.bringToTop(pksRef, pksLast);

    // Push nPKs count
    this.emitOp({ op: 'push', value: BigInt(nPKs) });
    this.stackMap.push(null);

    // Pop everything: OP_0 + sigs + nSigs + pks + nPKs = 2 + nSigs + nPKs + 2 items
    // But on our stack map they're: null(OP_0), sigsRef, null(nSigs), pksRef, null(nPKs)
    for (let i = 0; i < 5; i++) {
      this.stackMap.pop();
    }

    this.emitOp({ op: 'opcode', code: 'OP_CHECKMULTISIG' });
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerMethodCall(
    bindingName: string,
    object: string,
    method: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Method calls on `this` are treated as builtin calls
    // e.g. this.getStateScript(), this.buildP2PKH(addr)
    if (method === 'getStateScript') {
      // Consume the @this object before dispatching
      if (this.stackMap.has(object)) {
        this.bringToTop(object, true);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
      }
      this.lowerGetStateScript(bindingName);
      return;
    }

    const privateMethod = this.privateMethods.get(method);
    if (privateMethod) {
      // Consume the @this object reference — it's a compile-time concept,
      // not a runtime value. Without this, 0n stays on the stack.
      if (this.stackMap.has(object)) {
        this.bringToTop(object, true);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
      }
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
    // Track shadowed names so we can restore them after the body runs.
    // When a param name already exists on the stack, temporarily rename
    // the existing entry to avoid duplicate names which break Set-based
    // branch reconciliation in lowerIf.
    const shadowed: { paramName: string; shadowedName: string; depth: number }[] = [];

    // Bind call arguments to private method params.
    for (let i = 0; i < args.length; i++) {
      if (i < method.params.length) {
        const arg = args[i]!;
        const paramName = method.params[i]!.name;
        const isLast = this.isLastUse(arg, bindingIndex, lastUses);
        this.bringToTop(arg, isLast);
        this.stackMap.pop();

        // If paramName already exists on the stack, temporarily rename
        // the existing entry to prevent duplicate-name issues.
        if (this.stackMap.has(paramName)) {
          const existingDepth = this.stackMap.findDepth(paramName);
          const shadowedName = `__shadowed_${bindingIndex}_${paramName}`;
          this.stackMap.renameAtDepth(existingDepth, shadowedName);
          shadowed.push({ paramName, shadowedName, depth: existingDepth });
        }

        this.stackMap.push(paramName);
      }
    }

    this.lowerBindings(method.body);

    // Restore shadowed names so the caller's scope sees its original entries.
    for (const { paramName, shadowedName } of shadowed) {
      if (this.stackMap.has(shadowedName)) {
        const depth = this.stackMap.findDepth(shadowedName);
        this.stackMap.renameAtDepth(depth, paramName);
      }
    }

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
    terminalAssert = false,
  ): void {
    // Get condition to top of stack
    const isLast = this.isLastUse(cond, bindingIndex, lastUses);
    this.bringToTop(cond, isLast);
    this.stackMap.pop(); // OP_IF consumes the condition

    // Identify parent-scope items still needed after this if-expression.
    // These must NOT be consumed (ROLLed) inside the branches — only PICKed.
    const protectedRefs = new Set<string>();
    for (const [ref, lastIdx] of lastUses.entries()) {
      if (lastIdx > bindingIndex && this.stackMap.has(ref)) {
        protectedRefs.add(ref);
      }
    }

    // Snapshot parent stackMap names before branches run
    const preIfNames = this.stackMap.namedSlots();

    // Lower then-branch
    const thenCtx = new LoweringContext([], this._properties, this.privateMethods);
    thenCtx.stackMap = this.stackMap.clone();
    thenCtx.outerProtectedRefs = protectedRefs;
    thenCtx._insideBranch = true;
    thenCtx.lowerBindings(thenBindings, terminalAssert);

    if (terminalAssert && thenCtx.stackMap.depth > 1) {
      const excess = thenCtx.stackMap.depth - 1;
      for (let i = 0; i < excess; i++) {
        thenCtx.emitOp({ op: 'nip' });
        thenCtx.stackMap.removeAtDepth(1);
      }
    }

    // Lower else-branch
    const elseCtx = new LoweringContext([], this._properties, this.privateMethods);
    elseCtx.stackMap = this.stackMap.clone();
    elseCtx.outerProtectedRefs = protectedRefs;
    elseCtx._insideBranch = true;
    elseCtx.lowerBindings(elseBindings, terminalAssert);

    if (terminalAssert && elseCtx.stackMap.depth > 1) {
      const excess = elseCtx.stackMap.depth - 1;
      for (let i = 0; i < excess; i++) {
        elseCtx.emitOp({ op: 'nip' });
        elseCtx.stackMap.removeAtDepth(1);
      }
    }

    // Balance stack between branches so both end at the same depth.
    // When addOutput is inside an if-then with no else, the then-branch
    // consumes stack items and pushes a serialized output, while the
    // else-branch leaves the stack unchanged. Both must end at the same
    // depth for correct execution after OP_ENDIF.
    //
    // Fix: identify items consumed by the then-branch (present in parent
    // but gone after then). Emit targeted ROLL+DROP in the else-branch
    // to remove those same items, then push empty bytes as placeholder.
    // OP_CAT with empty bytes is identity (no-op for output hashing).
    // Identify items consumed asymmetrically between branches.
    // Phase 1: collect consumed names from both directions.
    const postThenNames = thenCtx.stackMap.namedSlots();
    const consumedNames: string[] = [];
    for (const name of preIfNames) {
      if (!postThenNames.has(name) && elseCtx.stackMap.has(name)) {
        consumedNames.push(name);
      }
    }
    const postElseNames = elseCtx.stackMap.namedSlots();
    const elseConsumedNames: string[] = [];
    for (const name of preIfNames) {
      if (!postElseNames.has(name) && thenCtx.stackMap.has(name)) {
        elseConsumedNames.push(name);
      }
    }

    // Phase 2: perform ALL drops before any placeholder pushes.
    // This prevents double-placeholder when bilateral drops balance each other.
    if (consumedNames.length > 0) {
      const depths = consumedNames.map(n => elseCtx.stackMap.findDepth(n)).sort((a, b) => b - a);
      for (const depth of depths) {
        if (depth === 0) {
          elseCtx.emitOp({ op: 'drop' });
          elseCtx.stackMap.pop();
        } else if (depth === 1) {
          elseCtx.emitOp({ op: 'nip' });
          elseCtx.stackMap.removeAtDepth(1);
        } else {
          elseCtx.emitOp({ op: 'push', value: BigInt(depth) });
          elseCtx.stackMap.push(null);
          elseCtx.emitOp({ op: 'roll', depth });
          elseCtx.stackMap.pop();
          const rolled = elseCtx.stackMap.removeAtDepth(depth);
          elseCtx.stackMap.push(rolled);
          elseCtx.emitOp({ op: 'drop' });
          elseCtx.stackMap.pop();
        }
      }
    }
    if (elseConsumedNames.length > 0) {
      const depths = elseConsumedNames.map(n => thenCtx.stackMap.findDepth(n)).sort((a, b) => b - a);
      for (const depth of depths) {
        if (depth === 0) {
          thenCtx.emitOp({ op: 'drop' });
          thenCtx.stackMap.pop();
        } else if (depth === 1) {
          thenCtx.emitOp({ op: 'nip' });
          thenCtx.stackMap.removeAtDepth(1);
        } else {
          thenCtx.emitOp({ op: 'push', value: BigInt(depth) });
          thenCtx.stackMap.push(null);
          thenCtx.emitOp({ op: 'roll', depth });
          thenCtx.stackMap.pop();
          const rolled = thenCtx.stackMap.removeAtDepth(depth);
          thenCtx.stackMap.push(rolled);
          thenCtx.emitOp({ op: 'drop' });
          thenCtx.stackMap.pop();
        }
      }
    }

    // Phase 3: single depth-balance check after ALL drops.
    // Push placeholder only if one branch is still deeper than the other.
    if (thenCtx.stackMap.depth > elseCtx.stackMap.depth) {
      // When the then-branch reassigned a local variable (if-without-else),
      // push a COPY of that variable in the else-branch instead of a generic
      // placeholder. This ensures the else-branch preserves the correct value
      // when post-ENDIF stale removal (NIP) removes the old entry.
      const thenTop = thenCtx.stackMap.peekAtDepth(0);
      if (elseBindings.length === 0 && thenTop && elseCtx.stackMap.has(thenTop)) {
        const varDepth = elseCtx.stackMap.findDepth(thenTop);
        if (varDepth === 0) {
          elseCtx.emitOp({ op: 'dup' });
        } else {
          elseCtx.emitOp({ op: 'push', value: BigInt(varDepth) });
          elseCtx.stackMap.push(null);
          elseCtx.emitOp({ op: 'pick', depth: varDepth });
          elseCtx.stackMap.pop();
        }
        elseCtx.stackMap.push(thenTop);
      } else {
        elseCtx.emitOp({ op: 'push', value: new Uint8Array(0) });
        elseCtx.stackMap.push(null);
      }
    } else if (elseCtx.stackMap.depth > thenCtx.stackMap.depth) {
      thenCtx.emitOp({ op: 'push', value: new Uint8Array(0) });
      thenCtx.stackMap.push(null);
    }

    const thenOps = thenCtx.result.ops;
    const elseOps = elseCtx.result.ops;

    this.emitOp({
      op: 'if',
      then: thenOps,
      else: elseOps.length > 0 ? elseOps : undefined,
    });

    // Reconcile parent stackMap: remove items consumed by the branches.
    // Use thenCtx as the reference (both branches must consume the same items).
    const postBranchNames = thenCtx.stackMap.namedSlots();
    for (const name of preIfNames) {
      if (!postBranchNames.has(name) && this.stackMap.has(name)) {
        const depth = this.stackMap.findDepth(name);
        this.stackMap.removeAtDepth(depth);
      }
    }

    // The if expression may produce a result value on top.
    if (thenCtx.stackMap.depth > this.stackMap.depth) {
      // Branches increased depth — check if both updated the same property.
      const thenTop = thenCtx.stackMap.peekAtDepth(0);
      const elseTop = elseCtx.stackMap.depth > 0 ? elseCtx.stackMap.peekAtDepth(0) : null;
      const isProperty = thenTop ? this._properties.some(p => p.name === thenTop) : false;
      if (isProperty && thenTop && thenTop === elseTop && thenTop !== bindingName && this.stackMap.has(thenTop)) {
        // Both branches did update_prop for the same property (e.g., turn flip).
        // The new value is on top of the actual stack. The old entry is stale.
        // Push the property name and physically remove the old entry.
        this.stackMap.push(thenTop);
        for (let d = 1; d < this.stackMap.depth; d++) {
          if (this.stackMap.peekAtDepth(d) === thenTop) {
            if (d === 1) {
              this.emitOp({ op: 'nip' });
              this.stackMap.removeAtDepth(1);
            } else {
              this.emitOp({ op: 'push', value: BigInt(d) });
              this.stackMap.push(null);
              this.emitOp({ op: 'roll', depth: d + 1 });
              this.stackMap.pop();
              const rolled = this.stackMap.removeAtDepth(d);
              this.stackMap.push(rolled);
              this.emitOp({ op: 'drop' });
              this.stackMap.pop();
            }
            break;
          }
        }
      } else if (thenTop && !isProperty && elseBindings.length === 0 &&
                 thenTop !== bindingName && this.stackMap.has(thenTop)) {
        // If-without-else: the then-branch reassigned a local variable that
        // was PICKed (outer-protected), leaving a stale copy on the stack.
        // The new value is at TOS; the old copy is deeper. Push the local
        // name and remove the stale entry so subsequent references find the
        // correct (new) value.
        this.stackMap.push(thenTop);
        for (let d = 1; d < this.stackMap.depth; d++) {
          if (this.stackMap.peekAtDepth(d) === thenTop) {
            if (d === 1) {
              this.emitOp({ op: 'nip' });
              this.stackMap.removeAtDepth(1);
            } else {
              this.emitOp({ op: 'push', value: BigInt(d) });
              this.stackMap.push(null);
              this.emitOp({ op: 'roll', depth: d + 1 });
              this.stackMap.pop();
              const rolled = this.stackMap.removeAtDepth(d);
              this.stackMap.push(rolled);
              this.emitOp({ op: 'drop' });
              this.stackMap.pop();
            }
            break;
          }
        }
      } else {
        this.stackMap.push(bindingName);
      }
    } else if (elseCtx.stackMap.depth > this.stackMap.depth) {
      // The else-branch produced a value even though the then-branch didn't.
      this.stackMap.push(bindingName);
    } else {
      // Neither branch increased depth beyond the (post-reconciliation) parent
      // depth. This is a void if (e.g., both branches end with assert or both
      // are empty). Don't push a phantom — there is no extra value on the
      // actual stack.
    }
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
    _bindingName: string,
    count: number,
    body: ANFBinding[],
    _iterVar: string,
  ): void {
    // Collect outer-scope names referenced in the loop body.
    // These must not be consumed in non-final iterations.
    const bodyBindingNames = new Set(body.map(b => b.name));
    const outerRefs = new Set<string>();
    for (const b of body) {
      if (b.value.kind === 'load_param' && b.value.name !== _iterVar) {
        outerRefs.add(b.value.name);
      }
      // Also protect @ref: targets from outer scope (not redefined in body)
      if (b.value.kind === 'load_const') {
        const v = b.value.value;
        if (typeof v === 'string' && v.startsWith('@ref:')) {
          const refName = v.slice(5);
          if (!bodyBindingNames.has(refName)) {
            outerRefs.add(refName);
          }
        }
      }
    }

    // Temporarily extend localBindings with body binding names so
    // @ref: to body-internal values can consume on last use.
    const prevLocalBindings = this.localBindings;
    this.localBindings = new Set([...this.localBindings, ...bodyBindingNames]);

    // Loops are unrolled at compile time. Repeat the body `count` times.
    for (let i = 0; i < count; i++) {
      // Push the iteration index as a constant (in case the loop body uses it)
      this.emitOp({ op: 'push', value: BigInt(i) });
      this.stackMap.push(_iterVar);

      const lastUses = computeLastUses(body);

      // In non-final iterations, prevent outer-scope refs from being
      // consumed by setting their last-use beyond any body binding index.
      if (i < count - 1) {
        for (const refName of outerRefs) {
          lastUses.set(refName, body.length);
        }
      }

      for (let j = 0; j < body.length; j++) {
        this.lowerBinding(body[j]!, j, lastUses);
      }

      // Clean up the iteration variable if it was not consumed by the body.
      // The body may not reference _iterVar at all, leaving it on the stack.
      if (this.stackMap.has(_iterVar)) {
        const depth = this.stackMap.findDepth(_iterVar);
        if (depth === 0) {
          this.emitOp({ op: 'drop' });
          this.stackMap.pop();
        }
      }
    }
    // Restore localBindings
    this.localBindings = prevLocalBindings;
    // Note: loops are statements, not expressions — they don't produce a
    // physical stack value. Do NOT push a dummy stackMap entry, as it would
    // desync the stackMap depth from the physical stack.
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

    // When NOT inside an if-branch, remove the old property entry from
    // the stack. After liftBranchUpdateProps transforms conditional
    // property updates into flat if-expressions + top-level update_prop,
    // the old value is dead and must be removed to keep stack depth correct.
    // Inside branches, the old value is kept for lowerIf's same-property
    // detection to handle correctly.
    if (!this._insideBranch) {
      for (let d = 1; d < this.stackMap.depth; d++) {
        if (this.stackMap.peekAtDepth(d) === propName) {
          if (d === 1) {
            this.emitOp({ op: 'nip' });
            this.stackMap.removeAtDepth(1);
          } else {
            this.emitOp({ op: 'push', value: BigInt(d) });
            this.stackMap.push(null);
            this.emitOp({ op: 'roll', depth: d + 1 });
            this.stackMap.pop();
            const rolled = this.stackMap.removeAtDepth(d);
            this.stackMap.push(rolled);
            this.emitOp({ op: 'drop' });
            this.stackMap.pop();
          }
          break;
        }
      }
    }

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

    // Bring each state property to the top and concatenate.
    // Use consume=true: the raw property value is dead after serialization
    // (only the serialized stateBytes are needed for state hash verification).
    let first = true;
    for (const prop of stateProps) {
      if (this.stackMap.has(prop.name)) {
        this.bringToTop(prop.name, true);
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

  /**
   * computeStateOutputHash(preimage, stateBytes) — builds the full BIP-143
   * output serialization for a single-output stateful continuation:
   *   amount(8LE) + varint(scriptLen) + codePart + OP_RETURN + stateBytes
   * then returns hash256 of the result.
   *
   * Uses _codePart implicit parameter for the code portion and extracts
   * the amount from the preimage's scriptCode field.
   */
  private lowerComputeStateOutputHash(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    const preimageRef = args[0]!;
    const stateBytesRef = args[1]!;

    // Bring stateBytes to stack first.
    const stateLast = this.isLastUse(stateBytesRef, bindingIndex, lastUses);
    this.bringToTop(stateBytesRef, stateLast);

    // Extract amount from preimage for the continuation output.
    // We still need the amount from the current UTXO. Extract from preimage:
    // BIP-143 preimage has amount at offset (104 + varint + scriptLen).
    // Since the varint+scriptCode length varies, use end-relative:
    // Last 44 bytes = nSeq(4) + hashOutputs(32) + nLocktime(4) + sighashType(4).
    // Amount(8) is right before that.
    const preLast = this.isLastUse(preimageRef, bindingIndex, lastUses);
    this.bringToTop(preimageRef, preLast);

    // Extract amount: last 52 bytes, take 8 bytes at offset 0.
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 52n }); // 8 (amount) + 44 (tail)
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SUB' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [prefix, amountAndTail]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // prefix
    this.stackMap.push(null); // amountAndTail
    this.emitOp({ op: 'nip' }); // drop prefix
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 8n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [amount(8), tail(44)]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // amount
    this.stackMap.push(null); // tail
    this.emitOp({ op: 'drop' }); // drop tail
    this.stackMap.pop();
    // --- Stack: [..., stateBytes, amount(8LE)] ---

    // Save amount to altstack
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });
    this.stackMap.pop();

    // Bring _codePart to top (PICK — never consume, reused across outputs)
    this.bringToTop('_codePart', false);
    // --- Stack: [..., stateBytes, codePart] ---

    // Append OP_RETURN + stateBytes
    this.emitOp({ op: 'push', value: new Uint8Array([0x6a]) });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., stateBytes, codePart+OP_RETURN] ---

    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

    // Compute varint prefix for script length
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
    this.stackMap.push(null);
    this.emitVarintEncoding();

    // Prepend varint to script
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.push(null);
    // --- Stack: [..., varint+script] ---

    // Prepend amount from altstack
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    this.stackMap.push(null);
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., amount+varint+script] ---

    // Hash with SHA256d
    this.emitOp({ op: 'opcode', code: 'OP_HASH256' });

    this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * computeStateOutput(preimage, stateBytes) — same as computeStateOutputHash
   * but returns raw output bytes WITHOUT the final hash. This allows the caller
   * to concatenate additional outputs (e.g., change output) before hashing.
   */
  private lowerComputeStateOutput(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // computeStateOutput(preimage, stateBytes, newAmount)
    // Builds the continuation output using _newAmount instead of sourceSatoshis.
    // Uses _codePart implicit parameter instead of extracting from preimage.

    const preimageRef = args[0]!;
    const stateBytesRef = args[1]!;
    const newAmountRef = args[2]!;

    // Consume preimage ref (no longer needed — we use _codePart and _newAmount).
    const preLast = this.isLastUse(preimageRef, bindingIndex, lastUses);
    this.bringToTop(preimageRef, preLast);
    this.emitOp({ op: 'drop' });
    this.stackMap.pop();

    // Step 1: Convert _newAmount to 8-byte LE and save to altstack.
    const amountLast = this.isLastUse(newAmountRef, bindingIndex, lastUses);
    this.bringToTop(newAmountRef, amountLast);
    this.emitOp({ op: 'push', value: 8n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });
    this.stackMap.pop();

    // Step 2: Bring stateBytes to stack.
    const stateLast = this.isLastUse(stateBytesRef, bindingIndex, lastUses);
    this.bringToTop(stateBytesRef, stateLast);

    // Step 3: Bring _codePart to top (PICK — never consume, reused across outputs)
    this.bringToTop('_codePart', false);
    // --- Stack: [..., stateBytes, codePart] ---

    // Step 4: Append OP_RETURN + stateBytes
    this.emitOp({ op: 'push', value: new Uint8Array([0x6a]) });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., stateBytes, codePart+OP_RETURN] ---

    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

    // Step 5: Compute varint prefix for script length
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
    this.stackMap.push(null);
    this.emitVarintEncoding();

    // Prepend varint to script
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.push(null);
    // --- Stack: [..., varint+script] ---

    // Step 6: Prepend _newAmount (8-byte LE) from altstack.
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    this.stackMap.push(null);
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., amount(8LE)+varint+script] --- (NO hash)

    this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * buildChangeOutput(pkh, amount) — builds a P2PKH output serialization:
   *   amount(8LE) + 0x19 + 76a914 <pkh:20bytes> 88ac
   * Total: 34 bytes (8 + 1 + 25).
   */
  private lowerBuildChangeOutput(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    const pkhRef = args[0]!;
    const amountRef = args[1]!;

    // Step 1: Build the P2PKH locking script with length prefix.
    // Push prefix: varint(25) + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 = 0x1976a914
    this.emitOp({ op: 'push', value: new Uint8Array([0x19, 0x76, 0xa9, 0x14]) });
    this.stackMap.push(null);

    // Push the 20-byte PKH
    const pkhLast = this.isLastUse(pkhRef, bindingIndex, lastUses);
    this.bringToTop(pkhRef, pkhLast);
    // CAT: prefix || pkh
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);

    // Push suffix: OP_EQUALVERIFY + OP_CHECKSIG = 0x88ac
    this.emitOp({ op: 'push', value: new Uint8Array([0x88, 0xac]) });
    this.stackMap.push(null);
    // CAT: (prefix || pkh) || suffix
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., 0x1976a914{pkh}88ac] ---

    // Step 2: Prepend amount as 8-byte LE.
    const amountLast = this.isLastUse(amountRef, bindingIndex, lastUses);
    this.bringToTop(amountRef, amountLast);
    this.emitOp({ op: 'push', value: 8n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
    this.stackMap.pop(); // pop width
    // Stack: [..., script, amount(8LE)]
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    // Stack: [..., amount(8LE), script]
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., amount(8LE)+0x1976a914{pkh}88ac] ---

    this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerAddOutput(
    bindingName: string,
    satoshis: string,
    stateValues: string[],
    _preimage: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Build a full BIP-143 output serialization:
    //   amount(8LE) + varint(scriptLen) + codePart + OP_RETURN + stateBytes
    // Uses _codePart implicit parameter (passed by SDK) instead of extracting
    // codePart from the preimage. This is simpler and works with OP_CODESEPARATOR.

    const stateProps = this._properties.filter(p => !p.readonly);

    // Step 1: Bring _codePart to top (PICK — never consume, reused across outputs)
    this.bringToTop('_codePart', false);
    // --- Stack: [..., codePart] ---

    // Step 2: Append OP_RETURN byte (0x6a).
    this.emitOp({ op: 'push', value: new Uint8Array([0x6a]) });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    // --- Stack: [..., codePart+OP_RETURN] ---

    // Step 3: Serialize each state value and concatenate.
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
    // --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

    // Step 4: Compute varint prefix for the full script length.
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' }); // [script, len]
    this.stackMap.push(null);
    this.emitVarintEncoding();
    // --- Stack: [..., script, varint] ---

    // Step 5: Prepend varint to script: SWAP CAT
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    this.stackMap.push(null);
    // --- Stack: [..., varint+script] ---

    // Step 6: Prepend satoshis as 8-byte LE.
    const isLastSatoshis = this.isLastUse(satoshis, bindingIndex, lastUses);
    this.bringToTop(satoshis, isLastSatoshis);
    this.emitOp({ op: 'push', value: 8n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
    this.stackMap.pop(); // pop the width
    // Stack: [..., varint+script, satoshis(8LE)]
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' }); // satoshis || varint+script
    this.stackMap.push(null);
    // --- Stack: [..., amount(8LE)+varint+scriptPubKey] ---

    // Rename top to binding name
    this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * add_raw_output(satoshis, scriptBytes) — builds a raw output serialization:
   *   amount(8LE) + varint(scriptLen) + scriptBytes
   * The scriptBytes are used as-is (no codePart/state insertion).
   */
  private lowerAddRawOutput(
    bindingName: string,
    satoshis: string,
    scriptBytes: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Step 1: Bring scriptBytes to top
    const scriptIsLast = this.isLastUse(scriptBytes, bindingIndex, lastUses);
    this.bringToTop(scriptBytes, scriptIsLast);

    // Step 2: Compute varint prefix for script length
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' }); // [script, len]
    this.stackMap.push(null);
    this.emitVarintEncoding();
    // --- Stack: [..., script, varint] ---

    // Step 3: Prepend varint to script: SWAP CAT
    this.emitOp({ op: 'swap' }); // [varint, script]
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' }); // [varint+script]
    this.stackMap.push(null);

    // Step 4: Prepend satoshis as 8-byte LE
    const satIsLast = this.isLastUse(satoshis, bindingIndex, lastUses);
    this.bringToTop(satoshis, satIsLast);
    this.emitOp({ op: 'push', value: 8n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
    this.stackMap.pop(); // pop width
    // Stack: [..., varint+script, satoshis(8LE)]
    this.emitOp({ op: 'swap' });
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' }); // satoshis || varint+script
    this.stackMap.push(null);

    // Rename top to binding name
    this.stackMap.pop();
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * deserialize_state(preimage) — extracts mutable property values from the
   * BIP-143 preimage's scriptCode field. The state is stored as the last
   * `stateLen` bytes of the scriptCode (after OP_RETURN).
   *
   * For each mutable property, the value is extracted, converted to the
   * correct type (BIN2NUM for bigint/boolean), and pushed onto the stack
   * with the property name in the stackMap. This allows `load_prop` to
   * find the deserialized values instead of using hardcoded initial values.
   */
  private lowerDeserializeState(
    preimageRef: string,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    const stateProps = this._properties.filter(p => !p.readonly);
    if (stateProps.length === 0) return;

    // Compute state layout
    const propSizes: number[] = [];
    for (const prop of stateProps) {
      switch (prop.type) {
        case 'bigint': propSizes.push(8); break;
        case 'boolean': propSizes.push(1); break;
        case 'PubKey': propSizes.push(33); break;
        case 'Addr': propSizes.push(20); break;
        case 'Sha256': propSizes.push(32); break;
        case 'Point': propSizes.push(64); break;
        default:
          throw new Error(`deserialize_state: unsupported type '${prop.type}' for '${prop.name}'`);
      }
    }
    const stateLen = propSizes.reduce((a, b) => a + b, 0);

    // Bring preimage to top (copy — don't consume, it's needed later)
    const isLast = this.isLastUse(preimageRef, bindingIndex, lastUses);
    this.bringToTop(preimageRef, isLast);

    // Extract state bytes from preimage's scriptCode:
    // 1. Skip first 104 bytes (header), drop prefix
    this.emitOp({ op: 'push', value: 104n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null); this.stackMap.push(null);
    this.emitOp({ op: 'nip' }); // drop header
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);

    // 2. Drop tail 44 bytes (nSequence + hashOutputs + nLocktime + sighashType)
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 44n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SUB' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null); this.stackMap.push(null);
    this.emitOp({ op: 'drop' }); // drop tail
    this.stackMap.pop();

    // 3. Drop amount (last 8 bytes)
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 8n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SUB' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null); this.stackMap.push(null);
    this.emitOp({ op: 'drop' }); // drop amount
    this.stackMap.pop();

    // Now we have varint + scriptCode on the stack.
    // 4. Extract last stateLen bytes (the state section, including OP_RETURN prefix byte)
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: BigInt(stateLen) });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SUB' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null); this.stackMap.push(null);
    this.emitOp({ op: 'nip' }); // drop codePart+varint+OP_RETURN, keep state
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null); // state bytes on top

    // 5. Split state bytes into individual property values
    if (stateProps.length === 1) {
      // Single property — the state bytes ARE the property value
      const prop = stateProps[0]!;
      if (prop.type === 'bigint' || prop.type === 'boolean') {
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
      }
      // Byte types need no conversion
      this.stackMap.pop();
      this.stackMap.push(prop.name);
    } else {
      // Multiple properties — split sequentially from left.
      // State layout: prop0_bytes || prop1_bytes || ... || propN_bytes
      // We split off each property from the left, convert it, and swap
      // so the remainder stays on top for the next split.
      for (let i = 0; i < stateProps.length; i++) {
        const prop = stateProps[i]!;
        const size = propSizes[i]!;

        if (i < stateProps.length - 1) {
          // Split at size to get this property's bytes on top-1, rest on top
          this.emitOp({ op: 'push', value: BigInt(size) });
          this.stackMap.push(null);
          this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
          this.stackMap.pop(); // pop size
          this.stackMap.pop(); // pop state
          this.stackMap.push(null); // left (this prop bytes)
          this.stackMap.push(null); // right (rest)

          // Convert property to correct type: swap to bring prop on top
          this.emitOp({ op: 'swap' });
          this.stackMap.swap();
          if (prop.type === 'bigint' || prop.type === 'boolean') {
            this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
          }
          // Now: [..., rest, propValue]
          // Swap back so rest is on top for next iteration
          this.emitOp({ op: 'swap' });
          this.stackMap.swap();
          // Name the property (it's at depth 1 now)
          this.stackMap.pop();  // pop rest
          this.stackMap.pop();  // pop unnamed prop
          this.stackMap.push(prop.name); // push named prop
          this.stackMap.push(null); // push rest back
        } else {
          // Last property — remaining bytes are this property
          if (prop.type === 'bigint' || prop.type === 'boolean') {
            this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
          }
          this.stackMap.pop();
          this.stackMap.push(prop.name);
        }
      }
    }

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
    // The unlocking script pushes <_opPushTxSig> <preimage>.
    // The SDK computes the BIP-143 sighash and signs with private key = 1
    // (public key = secp256k1 generator G, compressed).
    // The go-sdk's ECDSA library handles DER encoding, low-S normalization,
    // and all edge cases correctly.
    //
    // Locking script sequence:
    //   [bring preimage to top]     -- via PICK (non-consuming copy)
    //   [bring _opPushTxSig to top] -- via ROLL (consuming)
    //   <G>                         -- push compressed generator point
    //   OP_CHECKSIGVERIFY           -- verify sig and remove from stack
    //   -- preimage remains on stack for field extractors

    // Step 0: Emit OP_CODESEPARATOR so that the scriptCode in the BIP-143
    // preimage is only the code after this point. This reduces preimage size
    // for large scripts and is required for scripts > ~32KB.
    this.emitOp({ op: 'opcode', code: 'OP_CODESEPARATOR' });

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

    // Step 4: OP_CHECKSIGVERIFY — verify and remove sig + pubkey.
    this.emitOp({ op: 'opcode', code: 'OP_CHECKSIGVERIFY' });
    this.stackMap.pop(); // G consumed
    this.stackMap.pop(); // _opPushTxSig consumed

    // The preimage remains on top. Rename to binding name
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
        this.stackMap.pop(); // pop position (32)
        this.stackMap.pop(); // pop data being split
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
        this.stackMap.pop(); // pop position (32)
        this.stackMap.pop(); // pop data being split
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
        this.stackMap.pop(); // pop position (36)
        this.stackMap.pop(); // pop data being split
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
        this.stackMap.pop(); // pop position (4)
        this.stackMap.pop(); // pop value being split
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
        break;

      case 'extractOutputHash':
        // End-relative: 32 bytes before the last 8 (nLocktime 4 + sighashType 4).
        // <preimage> OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
        this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'push', value: 40n });
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
        this.stackMap.pop(); // pop position (32)
        this.stackMap.pop(); // pop value being split (last40)
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
        this.emitOp({ op: 'push', value: 40n });
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
        this.stackMap.pop(); // pop position (32)
        this.stackMap.pop(); // pop value being split (last40)
        this.stackMap.push(null);
        this.stackMap.push(null);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
        break;

      case 'extractAmount':
        // End-relative: 8 bytes (LE int64) before nSequence(4) + hashOutputs(32) + nLocktime(4) + sighashType(4) = 44 bytes from end.
        // Total end offset: 44 + 8 = 52. Amount starts 52 bytes from end, is 8 bytes.
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
        this.stackMap.pop(); // pop position (8)
        this.stackMap.pop(); // pop value being split
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
        this.stackMap.pop(); // pop position (4)
        this.stackMap.pop(); // pop value being split
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
        // NOTE: This extracts the prevout index (vout) from the outpoint field of the
        // BIP-143 sighash preimage. This is the output index in the *previous* transaction
        // that created the UTXO being spent -- NOT the spending input's position in the
        // current transaction's input list.
        // The outpoint's vout field is at bytes 100-103 (4 bytes at offset 100).
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
        this.stackMap.pop(); // pop position (4)
        this.stackMap.pop(); // pop value being split
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

    // NOTE: The stack map is intentionally abandoned during the pow computation.
    // The pow loop uses raw opcode-level stack manipulation (PICK, SWAP, OVER)
    // that bypasses the stack map tracking. This is safe because:
    //   1. Both operands have been popped from the stack map above.
    //   2. The entire pow sequence is self-contained -- it consumes exactly 2 values
    //      (base, exp) and produces exactly 1 value (result) on the real stack.
    //   3. No other named variables are accessed during the computation.
    //   4. After completion, the result is registered in the stack map as bindingName.
    // This pattern is also used by gcd, sqrt, and other bounded-iteration builtins.

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
    //   <i>        → <exp> <base> <acc> <exp> <i>
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
      this.emitOp({ op: 'push', value: BigInt(i) });
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
   *
   * Guards against division by zero when n=0 by wrapping the Newton
   * iteration in OP_DUP OP_IF ... OP_ENDIF. When n=0, the initial
   * guess is also 0, and we skip the iteration entirely — 0 remains
   * on the stack as the result.
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
    // Guard: if n == 0, skip Newton iteration (avoid div-by-zero)
    this.emitOp({ op: 'opcode', code: 'OP_DUP' }); // n n

    // Build the Newton iteration ops for the if-then branch
    const newtonOps: StackOp[] = [];
    // At entry of if-branch, OP_IF consumed the top copy, stack: <n>
    // DUP to get initial guess = n
    newtonOps.push({ op: 'opcode', code: 'OP_DUP' }); // n guess(=n)

    // 16 Newton iterations: guess = (guess + n/guess) / 2
    const SQRT_ITERATIONS = 16;
    for (let i = 0; i < SQRT_ITERATIONS; i++) {
      // Stack: n guess
      newtonOps.push({ op: 'over' });                      // n guess n
      newtonOps.push({ op: 'over' });                      // n guess n guess
      newtonOps.push({ op: 'opcode', code: 'OP_DIV' });    // n guess (n/guess)
      newtonOps.push({ op: 'opcode', code: 'OP_ADD' });    // n (guess + n/guess)
      newtonOps.push({ op: 'push', value: 2n });            // n (guess + n/guess) 2
      newtonOps.push({ op: 'opcode', code: 'OP_DIV' });    // n new_guess
    }
    // Stack: n result
    newtonOps.push({ op: 'nip' }); // result (drop n)

    this.emitOp({
      op: 'if',
      then: newtonOps,
      else: undefined,
    });
    // After OP_ENDIF: stack has the result (either 0 from skipped branch, or sqrt(n))

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
   * Lower log2(n) — exact floor(log2(n)) via bit-scanning.
   *
   * Uses a bounded unrolled loop (64 iterations for bigint range):
   *   counter = 0
   *   while input > 1: input >>= 1, counter++
   *   result = counter
   *
   * Stack layout during loop: <input> <counter>
   * Each iteration: OP_SWAP OP_DUP OP_1 OP_GREATERTHAN OP_IF OP_2 OP_DIV OP_SWAP OP_1ADD OP_SWAP OP_ENDIF
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
    // Push counter = 0
    this.emitOp({ op: 'push', value: 0n }); // n 0

    // 64 iterations (sufficient for Bitcoin Script bigint range)
    const LOG2_ITERATIONS = 64;
    for (let i = 0; i < LOG2_ITERATIONS; i++) {
      // Stack: input counter
      this.emitOp({ op: 'swap' });              // counter input
      this.emitOp({ op: 'opcode', code: 'OP_DUP' }); // counter input input
      this.emitOp({ op: 'push', value: 1n });    // counter input input 1
      this.emitOp({ op: 'opcode', code: 'OP_GREATERTHAN' }); // counter input (input>1)
      this.emitOp({
        op: 'if',
        then: [
          { op: 'push', value: 2n },              // counter input 2
          { op: 'opcode', code: 'OP_DIV' },       // counter (input/2)
          { op: 'swap' },                         // (input/2) counter
          { op: 'opcode', code: 'OP_1ADD' },      // (input/2) (counter+1)
          { op: 'swap' },                         // (counter+1) (input/2)
        ],
        else: undefined,
      });
      // Stack: counter input  (or input counter if swapped back)
      // After the if: stack is counter input (swap at start, then if-branch swaps back)
      this.emitOp({ op: 'swap' });              // input counter
    }
    // Stack: input counter
    // Drop input, keep counter
    this.emitOp({ op: 'nip' }); // counter

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower sign(x) — returns -1, 0, or 1.
   *
   * Guards against division by zero when x=0 by using an OP_IF:
   *   OP_DUP OP_IF OP_DUP OP_ABS OP_SWAP OP_DIV OP_ENDIF
   *
   * When x=0: OP_DUP pushes 0, OP_IF is false so we skip the division,
   * and the original 0 remains on the stack.
   * When x!=0: we compute x / abs(x) which gives -1 or 1.
   */
  private lowerSign(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 1) throw new Error('sign requires 1 argument');
    const x = args[0]!;

    const xIsLast = this.isLastUse(x, bindingIndex, lastUses);
    this.bringToTop(x, xIsLast);
    this.stackMap.pop();

    // Stack: <x>
    // OP_DUP: <x> <x>
    // OP_IF (x != 0):
    //   OP_DUP OP_ABS OP_SWAP OP_DIV => x / abs(x)
    // OP_ENDIF
    // If x == 0, the duplicated 0 is consumed by OP_IF (falsy) and original 0 stays.
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });
    this.emitOp({
      op: 'if',
      then: [
        { op: 'opcode', code: 'OP_DUP' },
        { op: 'opcode', code: 'OP_ABS' },
        { op: 'swap' },
        { op: 'opcode', code: 'OP_DIV' },
      ],
      else: undefined,
    });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower right(data, n) — returns the rightmost n bytes of data.
   *
   * Splits at (size - n) and keeps the right part:
   *   <data> <n> OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP
   *
   * Stack trace:
   *   <data> <n>
   *   OP_SWAP → <n> <data>
   *   OP_SIZE → <n> <data> <size>
   *   OP_ROT  → <data> <size> <n>
   *   OP_SUB  → <data> <size-n>
   *   OP_SPLIT → <left> <right>
   *   OP_NIP   → <right>  (rightmost n bytes)
   */
  private lowerRight(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) throw new Error('right requires 2 arguments');
    const [data, len] = args as [string, string];

    // Push data onto the stack
    const dataIsLast = this.isLastUse(data, bindingIndex, lastUses);
    this.bringToTop(data, dataIsLast);

    // Push len onto the stack
    const lenIsLast = this.isLastUse(len, bindingIndex, lastUses);
    this.bringToTop(len, lenIsLast);

    // Stack: <data> <len>
    this.stackMap.pop(); // len
    this.stackMap.pop(); // data

    // OP_SWAP → <len> <data>
    this.emitOp({ op: 'swap' });
    // OP_SIZE → <len> <data> <size>
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' });
    // OP_ROT → <data> <size> <len>
    this.emitOp({ op: 'rot' });
    // OP_SUB → <data> <size-len>
    this.emitOp({ op: 'opcode', code: 'OP_SUB' });
    // OP_SPLIT → <left> <right>
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    // OP_NIP → <right>
    this.emitOp({ op: 'nip' });

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  /**
   * Lower verifyRabinSig(msg, sig, padding, pubKey) to Script.
   *
   * Rabin signature verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
   *
   * Stack before: <msg(3)> <sig(2)> <padding(1)> <pubKey(0)>
   * Script:
   *   OP_SWAP                     -- msg sig pubKey padding
   *   OP_ROT                      -- msg pubKey padding sig  (sig on top for squaring)
   *   OP_DUP OP_MUL               -- msg pubKey padding sig^2
   *   OP_ADD                      -- msg pubKey (sig^2+padding)
   *   OP_SWAP                     -- msg (sig^2+padding) pubKey
   *   OP_MOD                      -- msg ((sig^2+padding) mod pubKey)
   *   OP_SWAP                     -- ((sig^2+padding) mod pubKey) msg
   *   OP_SHA256                   -- ((sig^2+padding) mod pubKey) SHA256(msg)
   *   OP_EQUAL                    -- result
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

    // Stack bottom->top: msg(3) sig(2) padding(1) pubKey(0)
    // Compute: (sig^2 + padding) mod pubKey == SHA256(msg)

    // Rearrange so sig is on top for squaring
    this.emitOp({ op: 'opcode', code: 'OP_SWAP' });  // msg sig pubKey padding
    this.emitOp({ op: 'opcode', code: 'OP_ROT' });   // msg pubKey padding sig

    // sig^2
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });
    this.emitOp({ op: 'opcode', code: 'OP_MUL' });   // msg pubKey padding sig^2

    // sig^2 + padding
    this.emitOp({ op: 'opcode', code: 'OP_ADD' });   // msg pubKey (sig^2+padding)

    // (sig^2 + padding) mod pubKey
    this.emitOp({ op: 'opcode', code: 'OP_SWAP' });  // msg (sig^2+padding) pubKey
    this.emitOp({ op: 'opcode', code: 'OP_MOD' });   // msg ((sig^2+padding) mod pubKey)

    // SHA256(msg) and compare
    this.emitOp({ op: 'opcode', code: 'OP_SWAP' });  // ((sig^2+padding) mod pubKey) msg
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
   * Emit one WOTS+ chain with RFC 8391 tweakable hashing.
   * Input:  pubSeed(bottom) sig(1) csum(2) endpt(3) digit(top)
   * Output: pubSeed(bottom) sigRest(1) newCsum(2) newEndpt(top)
   * Alt stack pushes/pops are balanced (4 push, 4 pop).
   *
   * F(pubSeed, chainIdx, stepIdx, X) = SHA-256(pubSeed || byte(chainIdx) || byte(stepIdx) || X)
   */
  private emitWOTSOneChain(chainIndex: number): void {
    // Entry stack: pubSeed(bottom) sig csum endpt digit(top)
    // Save steps_copy = 15 - digit to alt (for checksum accumulation later)
    this.emitOp({ op: 'opcode', code: 'OP_DUP' });
    this.emitOp({ op: 'push', value: 15n });
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'opcode', code: 'OP_SUB' });
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#1: steps_copy
    // main: pubSeed sig csum endpt digit

    // Save endpt, csum to alt. Leave pubSeed+sig+digit on main.
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#2: endpt
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#3: csum
    // main: pubSeed sig digit

    // Split 32B sig element
    this.emitOp({ op: 'swap' });                            // pubSeed digit sig
    this.emitOp({ op: 'push', value: 32n });
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });       // pubSeed digit sigElem sigRest
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // push#4: sigRest
    this.emitOp({ op: 'swap' });                            // pubSeed sigElem digit

    // Hash loop: skip first `digit` iterations, then apply F for the rest.
    // When digit > 0: decrement (skip). When digit == 0: hash at step j.
    // Stack at loop entry: pubSeed(depth2) sigElem(depth1) digit(depth0=top)
    for (let j = 0; j < 15; j++) {
      const adrsBytes = new Uint8Array([chainIndex, j]);
      this.emitOp({ op: 'opcode', code: 'OP_DUP' });
      this.emitOp({ op: 'opcode', code: 'OP_0NOTEQUAL' });
      this.emitOp({
        op: 'if',
        then: [
          { op: 'opcode', code: 'OP_1SUB' },                // skip: digit--
        ],
        else: [
          { op: 'swap' },                                    // pubSeed digit X
          { op: 'push', value: 2n },
          { op: 'opcode', code: 'OP_PICK' },                // copy pubSeed from depth 2
          { op: 'push', value: adrsBytes },                  // push ADRS [chainIndex, j]
          { op: 'opcode', code: 'OP_CAT' },                 // pubSeed || adrs
          { op: 'swap' },                                    // bring X to top
          { op: 'opcode', code: 'OP_CAT' },                 // pubSeed || adrs || X
          { op: 'opcode', code: 'OP_SHA256' },              // F result
          { op: 'swap' },                                    // pubSeed new_X digit(=0)
        ],
      });
    }
    this.emitOp({ op: 'drop' }); // drop digit (now 0)
    // main: pubSeed endpoint

    // Restore from alt (LIFO): sigRest, csum, endpt_acc, steps_copy
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#4: sigRest
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#3: csum
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#2: endpt_acc
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pop#1: steps_copy
    // main b→t: pubSeed endpoint sigRest csum endpt_acc steps_copy

    // csum += steps_copy
    this.emitOp({ op: 'opcode', code: 'OP_ROT' });
    this.emitOp({ op: 'opcode', code: 'OP_ADD' });

    // Concat endpoint to endpt_acc
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'push', value: 3n });
    this.emitOp({ op: 'opcode', code: 'OP_ROLL' });
    this.emitOp({ op: 'opcode', code: 'OP_CAT' });
    // pubSeed sigRest newCsum newEndptAcc
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
    // main: msg(0) sig(1) pubkey(2)  (pubkey is 64 bytes: pubSeed||pkRoot)

    // Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
    this.emitOp({ op: 'push', value: 32n });
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });         // msg sig pubSeed pkRoot
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });   // pkRoot → alt

    // Rearrange: put pubSeed at bottom, hash msg
    // main: msg sig pubSeed
    this.emitOp({ op: 'opcode', code: 'OP_ROT' });           // sig pubSeed msg
    this.emitOp({ op: 'opcode', code: 'OP_ROT' });           // pubSeed msg sig
    this.emitOp({ op: 'swap' });                               // pubSeed sig msg
    this.emitOp({ op: 'opcode', code: 'OP_SHA256' });        // pubSeed sig msgHash

    // Canonical layout: pubSeed(bottom) sig csum=0 endptAcc=empty hashRem(top)
    this.emitOp({ op: 'swap' });                // pubSeed msgHash sig
    this.emitOp({ op: 'push', value: 0n });     // pubSeed msgHash sig 0
    this.emitOp({ op: 'opcode', code: 'OP_0' }); // pubSeed msgHash sig 0 empty
    this.emitOp({ op: 'push', value: 3n });
    this.emitOp({ op: 'opcode', code: 'OP_ROLL' }); // pubSeed sig 0 empty msgHash

    // Process 32 bytes → 64 message chains
    // Chain indices: byteIdx*2 for high nibble, byteIdx*2+1 for low nibble
    for (let byteIdx = 0; byteIdx < 32; byteIdx++) {
      // main: pubSeed sig csum endptAcc hashRem
      if (byteIdx < 31) {
        this.emitOp({ op: 'push', value: 1n });
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.emitOp({ op: 'swap' });
      }
      // Convert 1-byte string to unsigned integer.
      this.emitOp({ op: 'push', value: 0n });
      this.emitOp({ op: 'push', value: 1n });
      this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
      this.emitOp({ op: 'opcode', code: 'OP_CAT' });
      this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
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
      // main: pubSeed sig csum endptAcc high

      this.emitWOTSOneChain(byteIdx * 2); // chain index for high nibble

      // Retrieve low from alt (and hashRest)
      if (byteIdx < 31) {
        this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // hashRest
        this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // low
        this.emitOp({ op: 'swap' });
        this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // hashRest → alt
      } else {
        this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // low
      }
      // main: pubSeed sigRest csum endptAcc low

      this.emitWOTSOneChain(byteIdx * 2 + 1); // chain index for low nibble

      if (byteIdx < 31) {
        this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // hashRest
      }
    }

    // main: pubSeed sigRest(96B) totalCsum endptAcc  |  alt: pkRoot

    // Compute 3 checksum digits
    this.emitOp({ op: 'swap' }); // pubSeed sigRest endptAcc totalCsum

    // d66 = csum % 16
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

    // d64 = (csum/256) % 16
    this.emitOp({ op: 'push', value: 256n });
    this.emitOp({ op: 'opcode', code: 'OP_DIV' });
    this.emitOp({ op: 'push', value: 16n });
    this.emitOp({ op: 'opcode', code: 'OP_MOD' });
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // main: pubSeed sigRest endptAcc  |  alt: pkRoot, d66, d65, d64

    // Process 3 checksum chains (indices 64, 65, 66)
    for (let ci = 0; ci < 3; ci++) {
      // main: pubSeed sigRest endptAcc
      // Set up: pubSeed sigRest dummyCsum=0 endptAcc digit
      this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' }); // endptAcc → alt (temp)
      this.emitOp({ op: 'push', value: 0n });                // pubSeed sigRest 0
      this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pubSeed sigRest 0 endptAcc
      this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pubSeed sigRest 0 endptAcc digit

      this.emitWOTSOneChain(64 + ci);
      // main: pubSeed sigRest dummyCsum newEndptAcc

      // Drop dummy csum
      this.emitOp({ op: 'swap' }); // pubSeed sigRest newEndptAcc dummyCsum
      this.emitOp({ op: 'drop' }); // pubSeed sigRest newEndptAcc
    }

    // main: pubSeed sigRest(empty) endptAcc  |  alt: pkRoot
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'drop' }); // drop empty sigRest
    // main: pubSeed endptAcc

    // Hash concatenated endpoints → computed pkRoot
    this.emitOp({ op: 'opcode', code: 'OP_SHA256' });
    // main: pubSeed computedPkRoot

    // Compare to pkRoot from alt
    this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // pkRoot
    this.emitOp({ op: 'opcode', code: 'OP_EQUAL' });
    // main: pubSeed bool

    // Clean up pubSeed
    this.emitOp({ op: 'swap' });
    this.emitOp({ op: 'drop' }); // drop pubSeed
    // main: bool

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // SHA-256 compression — delegates to sha256-codegen.ts
  // =========================================================================

  private lowerSha256Compress(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) {
      throw new Error('sha256Compress requires 2 arguments: state, block');
    }
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    for (let i = 0; i < 2; i++) this.stackMap.pop();

    emitSha256Compress((op) => this.emitOp(op));

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerSha256Finalize(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 3) {
      throw new Error('sha256Finalize requires 3 arguments: state, remaining, msgBitLen');
    }
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    for (let i = 0; i < 3; i++) this.stackMap.pop();

    emitSha256Finalize((op) => this.emitOp(op));

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // BLAKE3 compression — delegates to blake3-codegen.ts
  // =========================================================================

  private lowerBlake3Compress(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) {
      throw new Error('blake3Compress requires 2 arguments: chainingValue, block');
    }
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    for (let i = 0; i < 2; i++) this.stackMap.pop();

    emitBlake3Compress((op) => this.emitOp(op));

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerBlake3Hash(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 1) {
      throw new Error('blake3Hash requires 1 argument: message');
    }
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    this.stackMap.pop();

    emitBlake3Hash((op) => this.emitOp(op));

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

  // =========================================================================
  // EC builtins — delegates to ec-codegen.ts
  // =========================================================================

  private lowerEcBuiltin(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Bring all args to stack top
    for (const arg of args) {
      this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
    }
    for (let i = 0; i < args.length; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);

    switch (func) {
      case 'ecAdd':              emitEcAdd(emitFn); break;
      case 'ecMul':              emitEcMul(emitFn); break;
      case 'ecMulGen':           emitEcMulGen(emitFn); break;
      case 'ecNegate':           emitEcNegate(emitFn); break;
      case 'ecOnCurve':          emitEcOnCurve(emitFn); break;
      case 'ecModReduce':        emitEcModReduce(emitFn); break;
      case 'ecEncodeCompressed': emitEcEncodeCompressed(emitFn); break;
      case 'ecMakePoint':        emitEcMakePoint(emitFn); break;
      case 'ecPointX':           emitEcPointX(emitFn); break;
      case 'ecPointY':           emitEcPointY(emitFn); break;
      default: throw new Error(`Unknown EC builtin: ${func}`);
    }

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

    // Variable-length byte reversal using bounded unrolled loop.
    // Algorithm: split off first byte repeatedly, prepend each to accumulator.
    // Stack: [data]
    this.stackMap.pop();

    // Push empty result, swap so data is on top: ["", data]
    this.emitOp({ op: 'push', value: 0n });  // OP_0 pushes empty byte array
    this.emitOp({ op: 'swap' });

    // 520 iterations (max BSV element size)
    const REVERSE_MAX_BYTES = 520;
    for (let i = 0; i < REVERSE_MAX_BYTES; i++) {
      // Stack: [result, data]
      this.emitOp({ op: 'dup' });                              // result data data
      this.emitOp({ op: 'opcode', code: 'OP_SIZE' });          // result data data len
      this.emitOp({ op: 'nip' });                              // result data len
      this.emitOp({
        op: 'if',
        then: [
          { op: 'push', value: 1n },                           // result data 1
          { op: 'opcode', code: 'OP_SPLIT' },                  // result first remaining
          { op: 'swap' },                                      // result remaining first
          { op: 'rot' },                                       // remaining first result
          { op: 'opcode', code: 'OP_CAT' },                    // remaining (first||result)
          { op: 'swap' },                                      // (first||result) remaining
        ],
        else: undefined,
      });
    }

    // Stack: [reversed_result, empty_data]
    this.emitOp({ op: 'drop' }); // drop empty remainder

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

  /**
   * Lower `__array_access(data, index)` — ByteString byte-level indexing.
   *
   * Compiled to:
   *   <data> <index> OP_SPLIT OP_NIP 1 OP_SPLIT OP_DROP OP_BIN2NUM
   *
   * Stack trace:
   *   [..., data, index]
   *   OP_SPLIT  → [..., left, right]       (split at index)
   *   OP_NIP    → [..., right]             (discard left)
   *   push 1    → [..., right, 1]
   *   OP_SPLIT  → [..., firstByte, rest]   (split off first byte)
   *   OP_DROP   → [..., firstByte]         (discard rest)
   *   OP_BIN2NUM → [..., numericValue]     (convert byte to bigint)
   */
  private lowerArrayAccess(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 2) {
      throw new Error('__array_access requires 2 arguments (object, index)');
    }

    const [obj, index] = args as [string, string];

    // Push the data (ByteString) onto the stack
    const objIsLast = this.isLastUse(obj, bindingIndex, lastUses);
    this.bringToTop(obj, objIsLast);

    // Push the index onto the stack
    const indexIsLast = this.isLastUse(index, bindingIndex, lastUses);
    this.bringToTop(index, indexIsLast);

    // OP_SPLIT at index: stack = [..., left, right]
    this.stackMap.pop();  // index consumed
    this.stackMap.pop();  // data consumed
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    this.stackMap.push(null);  // left part (discard)
    this.stackMap.push(null);  // right part (keep)

    // OP_NIP: discard left, keep right: stack = [..., right]
    this.emitOp({ op: 'nip' });
    this.stackMap.pop();
    const rightPart = this.stackMap.pop();
    this.stackMap.push(rightPart);

    // Push 1 for the next split (extract 1 byte)
    this.emitOp({ op: 'push', value: 1n });
    this.stackMap.push(null);

    // OP_SPLIT: split off first byte: stack = [..., firstByte, rest]
    this.stackMap.pop();  // 1 consumed
    this.stackMap.pop();  // right consumed
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
    this.stackMap.push(null);  // first byte (keep)
    this.stackMap.push(null);  // rest (discard)

    // OP_DROP: discard rest: stack = [..., firstByte]
    this.emitOp({ op: 'drop' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);

    // OP_BIN2NUM: convert single byte to numeric value
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });

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

function methodUsesCodePart(bindings: ANFBinding[]): boolean {
  for (const b of bindings) {
    if (b.value.kind === 'add_output' || b.value.kind === 'add_raw_output') return true;
    // Single-output stateful continuation uses computeStateOutput/computeStateOutputHash
    if (b.value.kind === 'call' && (b.value.func === 'computeStateOutput' || b.value.func === 'computeStateOutputHash')) return true;
    // Recurse into if-else branches and loops
    if (b.value.kind === 'if') {
      if (methodUsesCodePart(b.value.then) || methodUsesCodePart(b.value.else)) return true;
    }
    if (b.value.kind === 'loop' && methodUsesCodePart(b.value.body)) return true;
  }
  return false;
}

function lowerMethod(
  method: ANFMethod,
  properties: ANFProperty[],
  privateMethods: Map<string, ANFMethod>,
): StackMethod {
  const paramNames = method.params.map(p => p.name);

  // If the method uses checkPreimage, the unlocking script pushes implicit
  // params before all declared parameters (OP_PUSH_TX pattern).
  // _codePart: full code script (locking script minus state) as ByteString
  // _opPushTxSig: ECDSA signature for OP_PUSH_TX verification
  // These are inserted at the base of the stack so they can be consumed later.
  if (methodUsesCheckPreimage(method.body)) {
    paramNames.unshift('_opPushTxSig');
    // _codePart is only needed when the method has add_output or add_raw_output
    // (it provides the code script for continuation output construction).
    // Stateless contracts and terminal methods don't use it.
    if (methodUsesCodePart(method.body)) {
      paramNames.unshift('_codePart');
    }
  }

  const ctx = new LoweringContext(paramNames, properties, privateMethods);
  // Pass terminalAssert=true for public methods so the last assert leaves
  // its value on the stack (Bitcoin Script requires a truthy top-of-stack).
  ctx.lowerBindings(method.body, method.isPublic);

  // Clean up excess stack items left by deserialize_state.
  // Only needed for stateful methods that deserialize state from the preimage.
  const hasDeserializeState = method.body.some(b => b.value.kind === 'deserialize_state');
  if (method.isPublic && hasDeserializeState) {
    ctx.cleanupExcessStack();
  }

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
