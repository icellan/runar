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
import { UnknownANFKindError, MERGED_LOCAL_TEMP_PREFIX } from 'runar-ir-schema';
import { emitVerifySLHDSA } from './slh-dsa-codegen.js';
import { emitVerifyWOTS } from './wots-codegen.js';
import { emitVerifyRabinSig } from './rabin-codegen.js';
import type { EcCodegenOptions } from './ec-codegen.js';
import { estimateScriptBytes } from '../metrics/cost-model.js';
import { optimizeStackIR } from '../optimizer/peephole.js';
import {
  emitEcAdd, emitEcMul, emitEcMulGen, emitEcNegate,
  emitEcOnCurve, emitEcModReduce, emitEcEncodeCompressed,
  emitEcMakePoint, emitEcPointX, emitEcPointY,
} from './ec-codegen.js';
import { emitCheckPreimageBindingRaw } from './oppushtx-codegen.js';
import {
  emitBn254FieldAdd, emitBn254FieldSub, emitBn254FieldMul,
  emitBn254FieldInv, emitBn254FieldNeg,
  emitBn254G1Add, emitBn254G1ScalarMul, emitBn254G1Negate, emitBn254G1OnCurve,
} from './bn254-codegen.js';
import { emitSha256Compress, emitSha256Finalize } from './sha256-codegen.js';
import { emitBlake3Compress, emitBlake3Hash } from './blake3-codegen.js';
import {
  emitBBFieldAdd, emitBBFieldSub, emitBBFieldMul, emitBBFieldInv,
  emitBBExt4Mul0, emitBBExt4Mul1, emitBBExt4Mul2, emitBBExt4Mul3,
  emitBBExt4Inv0, emitBBExt4Inv1, emitBBExt4Inv2, emitBBExt4Inv3,
} from './babybear-codegen.js';
import {
  emitKBFieldAdd, emitKBFieldSub, emitKBFieldMul, emitKBFieldInv,
  emitKBExt4Mul0, emitKBExt4Mul1, emitKBExt4Mul2, emitKBExt4Mul3,
  emitKBExt4Inv0, emitKBExt4Inv1, emitKBExt4Inv2, emitKBExt4Inv3,
} from './koalabear-codegen.js';
import { emitMerkleRootSha256, emitMerkleRootHash256 } from './merkle-codegen.js';
import { emitPoseidon2KBPermute, emitPoseidon2KBCompress } from './poseidon2-koalabear-codegen.js';
import { emitPoseidon2MerkleRoot } from './poseidon2-merkle-codegen.js';
import {
  emitP256Add, emitP256Mul, emitP256MulGen, emitP256Negate, emitP256OnCurve,
  emitP256EncodeCompressed, emitVerifyECDSA_P256,
  emitP384Add, emitP384Mul, emitP384MulGen, emitP384Negate, emitP384OnCurve,
  emitP384EncodeCompressed, emitVerifyECDSA_P384,
} from './p256-p384-codegen.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_STACK_DEPTH = 800;

/**
 * Experimental lowering options.
 *
 * Every field defaults to the shipping behaviour, so `lowerToStack(anf)` with
 * no options is byte-identical to what the seven tiers produce today. These
 * exist so a size experiment can be measured against the default without
 * moving a single golden. See `docs/experiments/`.
 */
export interface LoweringOptions {
  /**
   * Park each curve's field prime / group order in a stack slot inside the EC
   * codegen modules instead of re-pushing the 33- or 49-byte literal at every
   * modular reduction.
   */
  ecConstantPool?: boolean;

  /**
   * Drop the sign fix-up from EC modular reductions wherever a sign lattice
   * proves the dividend non-negative. Only pays alongside `ecConstantPool`;
   * the codegen compares emitted bytes before choosing the cheap subtraction.
   */
  ecReductionSinking?: boolean;

  /**
   * Use a fixed-base comb wherever the base point is a compile-time constant.
   * The window width is chosen by the byte-cost model, not fixed.
   */
  ecFixedBaseComb?: boolean;

  /**
   * Operand scheduling strategy.
   *
   * `'current'` (default) is the shipping behaviour: results are pushed on top
   * of the operands that produced them, so a chain that reads the same values
   * repeatedly pays a deeper `OP_PICK` each time.
   *
   * `'liveness'` parks a result on the alt stack when the next binding does
   * not consume it, keeping hot operands at depth 0/1, and restores the whole
   * spill group before the first binding that needs any of it.
   */
  schedulerMode?: 'current' | 'liveness';
}

/**
 * ANF value kinds the spill scheduler is allowed to reason about.
 *
 * Deliberately narrow: these compute a single value from operands already on
 * the stack and have no control flow, no side effects, and no bespoke stack
 * choreography. Everything else — `if`, `loop`, `assert`, state ops, calls,
 * `raw_script` — forces the alt stack to be drained first, so none of the
 * delicate branch/loop reconciliation in `lowerIf` / `lowerLoop` ever sees a
 * non-empty alt stack.
 */
const SPILLABLE_KINDS = new Set<ANFValue['kind']>([
  'bin_op', 'unary_op', 'load_const', 'load_param', 'load_prop',
]);

/** Bytes an OP_TOALTSTACK + OP_FROMALTSTACK round trip costs. */
const SPILL_ROUND_TRIP_BYTES = 2;

/**
 * Binary operators whose two operands may be materialized in either order.
 *
 * The operator itself is unchanged — only which operand is brought to the top
 * first. Excluded on purpose:
 *  - `+` is `OP_CAT` when `result_type` is `"bytes"`, and concatenation is not
 *    commutative, so the caller must check the result type too;
 *  - `&&` / `||` short-circuit on chain (they lower through a branch, not
 *    `OP_BOOLAND` / `OP_BOOLOR`), so their operands are not interchangeable
 *    at this level;
 *  - `-`, `/`, `%`, shifts and every ordered comparison are order-sensitive.
 *
 * `===` / `!==` are commutative under both `OP_NUMEQUAL` and `OP_EQUAL`.
 */
const COMMUTATIVE_BINOPS = new Set<string>(['+', '*', '===', '!==', '&', '|', '^']);

/**
 * The ops one `bringToTop` would emit, mirroring its cases exactly, applied to
 * a throwaway stack model.
 *
 * Returns null when the value is not resident, which makes the caller fall
 * back to source order rather than guess.
 *
 * Costing has to go through the real peephole rather than a byte formula,
 * because the cheapest-looking local choice is often the one the peephole
 * would have erased anyway: two consumed operands at depths 1 and 0 emit
 * `OP_SWAP OP_SWAP`, which `swap-swap` deletes outright — free — while
 * "cleverly" taking them in the other order emits one real `OP_SWAP` and
 * costs a byte.
 */
function materializationOps(model: StackMap, name: string, consume: boolean): StackOp[] | null {
  let depth: number;
  try {
    depth = model.findDepth(name);
  } catch {
    return null;
  }

  const ops: StackOp[] = [];
  if (depth === 0) {
    if (!consume) { ops.push({ op: 'dup' }); model.dup(); }
    return ops;
  }
  if (depth === 1) {
    if (consume) { ops.push({ op: 'swap' }); model.swap(); }
    else { ops.push({ op: 'over' }); model.push(model.peekAtDepth(1)); }
    return ops;
  }
  if (consume) {
    if (depth === 2) {
      ops.push({ op: 'rot' });
    } else {
      ops.push({ op: 'push', value: BigInt(depth) }, { op: 'roll', depth });
    }
    model.push(model.removeAtDepth(depth));
  } else {
    ops.push({ op: 'push', value: BigInt(depth) }, { op: 'pick', depth });
    model.push(model.peekAtDepth(depth));
  }
  return ops;
}


/**
 * Local hex-to-Uint8Array helper. Avoids a runar-testing dependency
 * (runar-testing depends on runar-compiler, so the reverse direction
 * would create a cycle).
 */
function decodeHexBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`raw_script bytes must have even hex length, got ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) {
      throw new Error(`raw_script bytes contain non-hex character near offset ${i * 2}`);
    }
    out[i] = b;
  }
  return out;
}

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

  /** Debug string of the slot names (bottom -> top) for error messages. */
  debugSlots(): string {
    return this.slots.join(', ');
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

  // Pre-scan: map each array_literal binding to its element refs. Used to
  // propagate last-use across the array indirection (the array binding is
  // pure metadata in the stack-lowerer — see lowerArrayLiteral — so its
  // elements must remain live until the array's consumer, not until the
  // array_literal binding itself).
  const arrayElems = new Map<string, string[]>();
  for (const b of bindings) {
    if (b.value.kind === 'array_literal') {
      arrayElems.set(b.name, [...b.value.elements]);
    }
  }

  for (let i = 0; i < bindings.length; i++) {
    const refs = collectRefs(bindings[i]!.value);
    // If this binding is itself an array_literal, do NOT advance its
    // elements' last-use to here — defer to the array's consumer.
    if (bindings[i]!.value.kind === 'array_literal') {
      continue;
    }
    for (const ref of refs) {
      lastUse.set(ref, i);
      const elems = arrayElems.get(ref);
      if (elems) {
        for (const e of elems) {
          lastUse.set(e, i);
        }
      }
    }
  }

  return lastUse;
}

/**
 * Collect every binding name defined anywhere in a binding sequence,
 * recursing into nested if-branches and loop bodies. Used by lowerLoop to
 * distinguish loop-internal (re)definitions from true outer-scope refs.
 */
function collectDeepBindingNames(bindings: ANFBinding[]): Set<string> {
  const names = new Set<string>();
  const walk = (bs: ANFBinding[]): void => {
    for (const b of bs) {
      names.add(b.name);
      if (b.value.kind === 'if') {
        walk(b.value.then);
        walk(b.value.else);
      } else if (b.value.kind === 'loop') {
        walk(b.value.body);
      }
    }
  };
  walk(bindings);
  return names;
}

/**
 * Locals a loop body REBINDS and then READS AGAIN in the same iteration.
 *
 * `computeLastUses` maps a name to the MAXIMUM index that references it, so
 * for a body like
 *
 *     t3   = acc + step     (index 1 — reads the value carried in)
 *     acc  = @ref:t3        (index 2 — rebinds: renames t3's slot to `acc`)
 *     t4   = wacc + acc     (index 3 — reads the value just rebound)
 *
 * `acc` gets last-use 3. Index 1 is therefore NOT a last use and copies
 * (PICK) instead of consuming, leaving the incoming slot on the stack under
 * the same name as the rebound one; index 3 then IS the last use, and
 * `StackMap.findDepth` resolves to the topmost match — so it consumes the
 * UPDATED value and leaves the dead incoming one. The next iteration reads
 * that dead slot, and every iteration recomputes from the pre-loop value:
 * `for (let i = 0n; i < N; i++) { acc = acc + step; wacc = wacc + acc; }`
 * produced `wacc = step*N` where the source says `step*N*(N+1)/2` — silently
 * in a stateless contract, and as a permanently unspendable UTXO in a
 * stateful one (the covenant commits to a continuation the SDK never builds).
 * `outerRefs` above does not cover it: `acc` is excluded there precisely
 * because the body binds it.
 *
 * The value these names hold at the end of an iteration is live at the start
 * of the next one, so `lowerLoop` protects them from consumption exactly like
 * an outer ref. The incoming slot each rebinding shadows is left behind and
 * drained with the rest of the frame at method exit — a name always resolves
 * to its newest slot, so the reads stay correct.
 *
 * Both halves of the predicate are load-bearing:
 *   - read BEFORE the first rebinding: the name is carried IN from the
 *     enclosing scope, rather than being a body-private temp that merely
 *     happens to be read after it is bound;
 *   - read AFTER the last rebinding: without it the rebound value is dead at
 *     the end of the iteration and consuming it is correct. This is what
 *     keeps every shipped accumulator (`sum = sum + i`, `off = off + len`)
 *     byte-for-byte unchanged.
 *
 * NESTED loops: the scan runs over `flattenNestedLoopBodies(body)`, not over
 * `body` itself. A name rebound only inside an INNER loop is bound at no
 * top-level index of the outer body, so the raw scan classified it as neither
 * an outer ref (`deepBodyBindingNames` excludes it — the body does bind it,
 * deeply) nor a carried rebind, and the outer loop never marked it live. The
 * inner loop's final iteration then consumed it, because `usedAfterLoop` asks
 * the enclosing scope and the enclosing scope had not been told either, so
 * every outer iteration restarted from the slot the previous one left behind:
 * `for (i<2) { for (j<2) { acc = acc + step; wacc = wacc + acc; } }` with
 * step = 3 produced `wacc = 24` where the source says 30. Splicing the inner
 * body in at the loop's position preserves the read/rebind/read ordering the
 * inner level already sees, so the outer level draws the same conclusion.
 */
function collectLoopCarriedRebinds(body: ANFBinding[]): Set<string> {
  const flat = flattenNestedLoopBodies(body);

  const firstBind = new Map<string, number>();
  const lastBind = new Map<string, number>();
  for (let i = 0; i < flat.length; i++) {
    const name = flat[i]!.name;
    if (!firstBind.has(name)) firstBind.set(name, i);
    lastBind.set(name, i);
  }

  const readBeforeBind = new Set<string>();
  const readAfterBind = new Set<string>();
  for (let i = 0; i < flat.length; i++) {
    for (const ref of collectRefs(flat[i]!.value)) {
      const first = firstBind.get(ref);
      if (first !== undefined && i < first) readBeforeBind.add(ref);
      const last = lastBind.get(ref);
      if (last !== undefined && i > last) readAfterBind.add(ref);
    }
  }

  const carried = new Set<string>();
  for (const name of readBeforeBind) {
    if (readAfterBind.has(name)) carried.add(name);
  }
  return carried;
}

/**
 * A binding sequence with every nested `loop` binding — and every `if`
 * binding — replaced, in place, by its own (recursively flattened) body.
 *
 * Only `collectLoopCarriedRebinds` uses this, and only to order reads against
 * rebindings. Neither replaced binding contributes a stack slot that predicate
 * reasons about, so dropping it loses nothing; splicing the sub-body in at its
 * position is what lets an enclosing loop see a rebinding one level down.
 *
 * `if` arms ARE spliced, in `then ++ else` order, even though they are
 * alternatives rather than a sequence. The predicate asks only "is this name
 * read, then rebound, then read again", and treating the arms as a sequence
 * can only ADD names to the carried set, never remove one — conservative in
 * the safe direction. Without it a local rebound ONLY inside an `if` arm was
 * bound at no index the predicate could see: neither an outer ref
 * (`deepBodyBindingNames` excludes it, since the body does bind it, deeply)
 * nor a carried rebind. The loop consumed it and the next iteration had
 * nothing to read, so `for (i<2) { if (i<5) { acc = acc + step; }
 * wacc = wacc + acc; }` was REJECTED outright with
 * `Value 'acc' not found on stack` — the loud face of the same gap the
 * merged-local protection in `lowerIf` fixes silently at K>=2.
 *
 * The `if` binding itself is NOT re-appended after its arms. Appending it
 * would count the arms' reads a second time at an index past every arm
 * rebinding, making a local that BOTH arms rebind look "read after its last
 * rebinding" — which protected a K=1 alias that must stay consumable and
 * broke `if (c) { acc = acc + s } else { acc = acc + 1n }` in a loop.
 *
 * A body with no nested loop and no `if` is returned entry-for-entry
 * unchanged, which is what makes this byte-neutral for every flat loop.
 */
function flattenNestedLoopBodies(body: ANFBinding[]): ANFBinding[] {
  if (!body.some(b => b.value.kind === 'loop' || b.value.kind === 'if')) return body;
  const flat: ANFBinding[] = [];
  for (const b of body) {
    if (b.value.kind === 'loop') {
      flat.push(...flattenNestedLoopBodies(b.value.body));
    } else if (b.value.kind === 'if') {
      flat.push(...flattenNestedLoopBodies(b.value.then));
      flat.push(...flattenNestedLoopBodies(b.value.else));
    } else {
      flat.push(b);
    }
  }
  return flat;
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
    case 'add_data_output':
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
    case 'raw_script':
      // No operand refs — the raw byte span has no SSA inputs visible to
      // the optimizer. Stack effect is declared via in_arity / out_arity.
      break;
    default: {
      const unknown = value as { kind: string };
      throw new UnknownANFKindError(unknown.kind, 'stack-lower.collectRefs');
    }
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
  /** Tracks the element refs of array literal bindings for checkMultiSig. */
  private arrayElements: Map<string, string[]> = new Map();
  /** Tracks constant values by binding name (for compile-time constant extraction). */
  private constValues: Map<string, bigint | string | boolean> = new Map();

  /**
   * Method params whose names collide with a mutable property. Maps the param
   * name to the reserved stack-slot name its witness value lives under, so
   * `lowerLoadParam` reads the param and not the same-named deserialized
   * property slot (issue #130). Empty for the common no-collision case.
   */
  private readonly renamedParams: Map<string, string> = new Map();

  /** Experimental lowering options; all default to shipping behaviour. */
  private readonly opts: LoweringOptions;

  /**
   * Values parked on the alt stack by the liveness scheduler, bottom -> top.
   *
   * Always empty in `'current'` mode, and always drained before any binding
   * the scheduler does not model (see SPILLABLE_KINDS) and at the end of
   * every `lowerBindings` scope.
   */
  private altSpills: string[] = [];

  constructor(
    params: string[],
    properties: ANFProperty[],
    privateMethods: Map<string, ANFMethod> = new Map(),
    opts: LoweringOptions = {},
  ) {
    this.opts = opts;
    // Parameters are pushed onto the stack by the Bitcoin VM in order.
    // The first parameter is at the bottom, last parameter at the top.
    this.stackMap = new StackMap(params);
    this._properties = properties;
    this.privateMethods = privateMethods;

    // Issue #130 (stack layer): a method param whose name collides with a
    // MUTABLE property gets a duplicate stackMap slot once `deserialize_state`
    // pushes that property under the same name. Name lookups resolve to the
    // shallowest match (the deserialized property), so `load_param` would read
    // the stale on-chain state instead of the witness value. Rename the
    // colliding param's slot to a reserved, collision-proof name up front and
    // remember the mapping so `lowerLoadParam` targets the real param slot.
    // Only mutable properties are deserialized onto the stack, so readonly
    // shadows (handled purely by ANF resolution) never enter this map, and
    // non-colliding contracts get an empty map — byte-identical output.
    const mutablePropNames = new Set(
      properties.filter(p => !p.readonly).map(p => p.name),
    );
    for (const name of params) {
      if (mutablePropNames.has(name)) {
        const renamed = `__param_${name}`;
        this.stackMap.renameAtDepth(this.stackMap.findDepth(name), renamed);
        this.renamedParams.set(name, renamed);
      }
    }

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
   *   - len < 0xfd:        1 byte (len itself)
   *   - len <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
   *   - len <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
   *   - otherwise:         0xff + 8 bytes LE                (9 bytes)
   *
   * We must support all four shapes; emitting a 3-byte varint for a script
   * whose length exceeds 0xffff produces a truncated value that no longer
   * matches what the BSV node uses for hashOutputs, breaking the
   * state-continuation hash equality assertion downstream.
   *
   * OP_NUM2BIN uses sign-magnitude encoding so the high-bit values need an
   * extra sign byte; we generate one extra byte and then SPLIT off the
   * unsigned low bytes.
   */
  private emitVarintEncoding(): void {
    // Stack: [..., script, len]

    // [..., len] -> [..., low_n_bytes]: NUM2BIN(n+1) then SPLIT(n) DROP.
    const emitNumToLowBytes = (nBytes: bigint): void => {
      this.emitOp({ op: 'push', value: nBytes + 1n });
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
      this.stackMap.pop();
      this.stackMap.pop();
      this.stackMap.push(null);
      this.emitOp({ op: 'push', value: nBytes });
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
      this.stackMap.pop();
      this.stackMap.pop();
      this.stackMap.push(null);
      this.stackMap.push(null);
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
    };

    // [..., script, low_bytes] -> [..., script, prefix||low_bytes].
    const emitPrefix = (prefixByte: number): void => {
      this.emitOp({ op: 'push', value: new Uint8Array([prefixByte]) });
      this.stackMap.push(null);
      this.emitOp({ op: 'swap' });
      this.stackMap.swap();
      this.stackMap.pop();
      this.stackMap.pop();
      this.emitOp({ op: 'opcode', code: 'OP_CAT' });
      this.stackMap.push(null);
    };

    // IF len < 253: 1-byte varint.
    this.emitOp({ op: 'dup' });
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 253n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_LESSTHAN' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_IF' });
    this.stackMap.pop();
    const smAt1Byte = this.stackMap.clone();
    emitNumToLowBytes(1n);
    this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
    this.stackMap = smAt1Byte.clone();

    // ELSE-IF len <= 0xffff: 0xfd + 2-byte LE.
    this.emitOp({ op: 'dup' });
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 0x10000n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_LESSTHAN' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_IF' });
    this.stackMap.pop();
    const smAt3Byte = this.stackMap.clone();
    emitNumToLowBytes(2n);
    emitPrefix(0xfd);
    this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
    this.stackMap = smAt3Byte.clone();

    // ELSE-IF len <= 0xffffffff: 0xfe + 4-byte LE.
    this.emitOp({ op: 'dup' });
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 0x100000000n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_LESSTHAN' });
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_IF' });
    this.stackMap.pop();
    const smAt5Byte = this.stackMap.clone();
    emitNumToLowBytes(4n);
    emitPrefix(0xfe);
    this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
    this.stackMap = smAt5Byte.clone();

    // ELSE: 0xff + 8-byte LE. (Practically unreachable on BSV but kept for
    // spec completeness so we never silently truncate.)
    emitNumToLowBytes(8n);
    emitPrefix(0xff);

    this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
    this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
    this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
    // --- Stack: [..., script, varint] ---
  }

  /**
   * Emit push-data encoding for a ByteString value on top of the stack.
   *
   * Expects stack: [..., bs_value]
   * Leaves stack:  [..., pushdata_encoded_value]
   *
   * Push-data format:
   *   - len <= 75:     1-byte length prefix
   *   - len 76-255:    0x4c + 1-byte length
   *   - len 256-65535: 0x4d + 2-byte LE length
   *
   * Uses save/restore of the stack map at each OP_ELSE to correctly
   * track all branches.
   */
  private emitPushDataEncode(): void {
    // Stack: [..., bs_value]
    this.emitOp({ op: 'opcode', code: 'OP_SIZE' }); // [..., bs_value, size]
    this.stackMap.push(null);
    this.emitOp({ op: 'dup' }); // [..., bs_value, size, size]
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 76n }); // [..., bs_value, size, size, 76]
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_LESSTHAN' }); // [..., bs_value, size, size<76]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);

    this.emitOp({ op: 'opcode', code: 'OP_IF' });
    this.stackMap.pop(); // pop condition
    // Save stack map state at branch point: [..., bs_value, size]
    const smAfterOuterIf = this.stackMap.clone();

    // --- THEN: len <= 75 → 1-byte length prefix ---
    // Stack: [..., bs_value, size]
    // Use NUM2BIN 2 + SPLIT to get a clean unsigned byte (handles 128+ correctly)
    this.emitOp({ op: 'push', value: 2n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' }); // [..., bs_value, size_2bytes]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 1n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., bs_value, lowByte, highByte]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // lowByte
    this.stackMap.push(null); // highByte
    this.emitOp({ op: 'drop' }); // [..., bs_value, lowByte]
    this.stackMap.pop();
    this.emitOp({ op: 'swap' }); // [..., lowByte, bs_value]
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' }); // [..., len_1byte || bs_value]
    this.stackMap.push(null);
    // Save THEN end state — this is the target depth all branches must reach
    const smEndTarget = this.stackMap.clone();

    this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
    // Restore stack map to branch point for ELSE
    this.stackMap = smAfterOuterIf.clone();
    // --- ELSE: len >= 76 ---
    // Stack: [..., bs_value, size]
    this.emitOp({ op: 'dup' }); // [..., bs_value, size, size]
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 256n }); // [..., bs_value, size, size, 256]
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_LESSTHAN' }); // [..., bs_value, size, size<256]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);

    this.emitOp({ op: 'opcode', code: 'OP_IF' });
    this.stackMap.pop(); // pop condition
    // Save stack map state at inner branch point: [..., bs_value, size]
    const smAfterInnerIf = this.stackMap.clone();

    // --- THEN: 76 <= len <= 255 → OP_PUSHDATA1: 0x4c + 1-byte length ---
    // Stack: [..., bs_value, size]
    this.emitOp({ op: 'push', value: 2n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' }); // [..., bs_value, size_2bytes]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 1n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., bs_value, lowByte, highByte]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.stackMap.push(null);
    this.emitOp({ op: 'drop' }); // [..., bs_value, lowByte]
    this.stackMap.pop();
    this.emitOp({ op: 'push', value: new Uint8Array([0x4c]) }); // [..., bs_value, lowByte, 0x4c]
    this.stackMap.push(null);
    this.emitOp({ op: 'swap' }); // [..., bs_value, 0x4c, lowByte]
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' }); // [..., bs_value, 0x4c || len_1byte]
    this.stackMap.push(null);
    this.emitOp({ op: 'swap' }); // [..., 0x4c || len_1byte, bs_value]
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' }); // [..., prefix || bs_value]
    this.stackMap.push(null);

    this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
    // Restore stack map to inner branch point for inner ELSE
    this.stackMap = smAfterInnerIf.clone();
    // --- ELSE: len >= 256 → OP_PUSHDATA2: 0x4d + 2-byte LE length ---
    // Stack: [..., bs_value, size]
    // Use NUM2BIN 4 + SPLIT to get unsigned 2-byte LE
    this.emitOp({ op: 'push', value: 4n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' }); // [..., bs_value, size_4bytes]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 2n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., bs_value, low2bytes, high2bytes]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);
    this.stackMap.push(null);
    this.emitOp({ op: 'drop' }); // [..., bs_value, low2bytes]
    this.stackMap.pop();
    this.emitOp({ op: 'push', value: new Uint8Array([0x4d]) }); // [..., bs_value, low2bytes, 0x4d]
    this.stackMap.push(null);
    this.emitOp({ op: 'swap' }); // [..., bs_value, 0x4d, low2bytes]
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' }); // [..., bs_value, 0x4d || len_2LE]
    this.stackMap.push(null);
    this.emitOp({ op: 'swap' }); // [..., 0x4d || len_2LE, bs_value]
    this.stackMap.swap();
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_CAT' }); // [..., prefix || bs_value]
    this.stackMap.push(null);

    this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
    this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
    // Restore to the target end state (same for all branches)
    this.stackMap = smEndTarget;
    // --- Stack: [..., pushdata_encoded_value] ---
  }

  /**
   * Emit push-data decoding for a ByteString state field.
   *
   * Expects stack: [..., state_bytes]
   * Leaves stack:  [..., data, remaining_state]
   *
   * Push-data format:
   *   - first byte < 76:  that IS the length → split at that length
   *   - first byte == 76 (0x4c): read 1 more byte as length
   *   - first byte == 77 (0x4d): read 2 more bytes as LE length
   *
   * Uses save/restore of the stack map at each OP_ELSE to correctly
   * track all branches.
   */
  private emitPushDataDecode(): void {
    // Stack: [..., state_bytes]
    this.emitOp({ op: 'push', value: 1n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., first_byte, rest]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // first_byte
    this.stackMap.push(null); // rest
    this.emitOp({ op: 'swap' }); // [..., rest, first_byte]
    this.stackMap.swap();
    this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' }); // [..., rest, fb_num]
    this.emitOp({ op: 'dup' }); // [..., rest, fb_num, fb_num]
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 76n }); // [..., rest, fb_num, fb_num, 76]
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_LESSTHAN' }); // [..., rest, fb_num, fb<76]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);

    this.emitOp({ op: 'opcode', code: 'OP_IF' });
    this.stackMap.pop(); // pop condition
    // Save stack map at branch point: [..., rest, fb_num]
    const smAfterOuterIf = this.stackMap.clone();

    // --- THEN: fb_num < 76 → fb_num IS the length ---
    // Stack: [..., rest, fb_num]
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., data, remaining]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // data
    this.stackMap.push(null); // remaining
    // Save THEN end state as target
    const smEndTarget = this.stackMap.clone();

    this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
    // Restore stack map to branch point
    this.stackMap = smAfterOuterIf.clone();
    // --- ELSE: fb_num >= 76 ---
    // Stack: [..., rest, fb_num]
    this.emitOp({ op: 'dup' }); // [..., rest, fb_num, fb_num]
    this.stackMap.push(null);
    this.emitOp({ op: 'push', value: 77n }); // [..., rest, fb_num, fb_num, 77]
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUMEQUAL' }); // [..., rest, fb_num, fb==77]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null);

    this.emitOp({ op: 'opcode', code: 'OP_IF' });
    this.stackMap.pop(); // pop condition
    // Save stack map at inner branch point: [..., rest, fb_num]
    const smAfterInnerIf = this.stackMap.clone();

    // --- THEN: fb_num == 77 (0x4d) → 2-byte LE length ---
    // Stack: [..., rest, fb_num]
    this.emitOp({ op: 'drop' }); // [..., rest]
    this.stackMap.pop();
    this.emitOp({ op: 'push', value: 2n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., len_2LE, rest2]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // len_2LE
    this.stackMap.push(null); // rest2
    this.emitOp({ op: 'swap' }); // [..., rest2, len_2LE]
    this.stackMap.swap();
    this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' }); // [..., rest2, len]
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., data, remaining]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // data
    this.stackMap.push(null); // remaining

    this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
    // Restore stack map to inner branch point
    this.stackMap = smAfterInnerIf.clone();
    // --- ELSE: fb_num == 76 (0x4c) → 1-byte length ---
    // Stack: [..., rest, fb_num]
    this.emitOp({ op: 'drop' }); // [..., rest]
    this.stackMap.pop();
    this.emitOp({ op: 'push', value: 1n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., len_1byte, rest2]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // len_1byte
    this.stackMap.push(null); // rest2
    this.emitOp({ op: 'swap' }); // [..., rest2, len_1byte]
    this.stackMap.swap();
    this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' }); // [..., rest2, len]
    this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [..., data, remaining]
    this.stackMap.pop();
    this.stackMap.pop();
    this.stackMap.push(null); // data
    this.stackMap.push(null); // remaining

    this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
    this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
    // Restore to the target end state (same for all branches)
    this.stackMap = smEndTarget;
    // --- Stack: [..., data, remaining] ---
  }

  /**
   * Bring a named value to the top of the stack.
   * If `consume` is true, use ROLL (removes from original position).
   * If `consume` is false, use PICK (copies, leaving original in place).
   */
  // -- liveness scheduler: alt-stack spilling --------------------------------
  //
  // ANF pushes every result on top of the operands that made it, so a chain
  // reading the same two values repeatedly buries them one slot deeper per
  // binding and pays a `push d; OP_PICK` pair instead of a 1-byte `OP_2DUP`.
  // Parking the result on the alt stack keeps the operands hot.
  //
  // Restores are done as a GROUP, not one at a time. Popping the whole alt
  // stack puts the values back on the main stack in production order (first
  // spilled ends up on top), which is the order an ANF accumulation chain
  // reads them in — so the group restore usually lands operands exactly where
  // the next bindings want them, and `bringToTop` fixes up any that differ.

  /** True when the liveness scheduler is active for this context. */
  private get schedulingByLiveness(): boolean {
    // Never inside a branch arm: `lowerIf` reconciles arms by MAIN-stack depth
    // alone (the Layer B/C invariants), so an arm must neither begin nor end
    // with a non-empty alt stack.
    return this.opts.schedulerMode === 'liveness' && !this._insideBranch;
  }

  /** Move the top-of-stack value to the alt stack. */
  private spillToAlt(name: string): void {
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });
    this.stackMap.pop();
    this.altSpills.push(name);
  }

  /** Pop every spilled value back. First-spilled ends up on top. */
  private restoreSpills(): void {
    while (this.altSpills.length > 0) {
      const name = this.altSpills.pop()!;
      this.emitOp({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      this.stackMap.push(name);
      this.trackDepth();
    }
  }

  /**
   * Decide whether the just-computed `name` (now on top) should be parked.
   *
   * Spilling pays only if the value would otherwise sit above operands that
   * get read before it is needed. The estimate counts those intervening reads:
   * each one would cross this slot, and crossing it costs at least a byte once
   * the access stops being a depth-0/1 `OP_DUP`/`OP_OVER`. Break-even is the
   * 2-byte round trip, so 2 intervening reads are required.
   */
  private maybeSpill(
    binding: ANFBinding,
    bindingIndex: number,
    bindings: ANFBinding[],
    lastUses: Map<string, number>,
  ): void {
    if (!this.schedulingByLiveness) return;
    if (!SPILLABLE_KINDS.has(binding.value.kind)) return;
    // Only a value we actually left on top, under its own name.
    if (this.stackMap.depth === 0) return;
    if (this.stackMap.peekAtDepth(0) !== binding.name) return;

    const nextUse = this.nextUseAfter(binding.name, bindingIndex, bindings);
    if (nextUse === null) return;            // dead or used past this scope
    if (nextUse === bindingIndex + 1) return; // consumed immediately: no burial
    if (lastUses.get(binding.name) !== undefined
      && lastUses.get(binding.name)! >= bindings.length) return; // pinned for an outer scope

    // No control flow may follow the spill anywhere in this scope.
    //
    // Restoring immediately before an `if` leaves the parent stack in a shape
    // `lowerIf` was not written for: its arm reconciliation, declared-result
    // trim and Layer B/C depth invariants all reason about a main stack the
    // scheduler has not been rearranging underneath them. That combination
    // MISCOMPILED `if-without-else-multi-temp` — the script kept running and
    // started ACCEPTING a witness the shipping compiler rejects, which the
    // conformance witness corpus caught (see
    // `packages/runar-testing/src/__tests__/liveness-scheduler-equivalence.test.ts`).
    // Rather than try to make the two agree, spilling stays out of any scope
    // that still has control flow ahead of it. `assert` is allowed: it consumes
    // a value and emits OP_VERIFY without reshaping anything.
    for (let j = bindingIndex + 1; j < bindings.length; j++) {
      const kind = bindings[j]!.value.kind;
      if (!SPILLABLE_KINDS.has(kind) && kind !== 'assert') return;
    }

    // Everything between here and the use must itself be schedulable, or the
    // restore would land in the middle of a construct we do not model.
    let interveningReads = 0;
    for (let j = bindingIndex + 1; j < nextUse; j++) {
      const v = bindings[j]!.value;
      if (!SPILLABLE_KINDS.has(v.kind)) return;
      interveningReads += collectRefs(v).filter(r => r !== binding.name).length;
    }
    if (interveningReads < SPILL_ROUND_TRIP_BYTES) return;

    // Do not spill a value the very next binding will restore anyway: the
    // round trip would be emitted and immediately undone. This is the
    // `OP_DIV OP_TOALTSTACK OP_FROMALTSTACK` shape — 2 bytes for nothing.
    const next = bindings[bindingIndex + 1];
    if (next !== undefined) {
      const nextRefs = collectRefs(next.value);
      if (!SPILLABLE_KINDS.has(next.value.kind)
        || nextRefs.some(r => this.altSpills.includes(r))) return;
    }

    this.spillToAlt(binding.name);
  }

  /** Index of the first binding at or after `from + 1` that references `name`. */
  private nextUseAfter(name: string, from: number, bindings: ANFBinding[]): number | null {
    for (let j = from + 1; j < bindings.length; j++) {
      if (collectRefs(bindings[j]!.value).includes(name)) return j;
    }
    return null;
  }

  /**
   * The options an `if`/`else` arm context inherits.
   *
   * The EC size flags have to cross into the arm: `if (usePQ) { ... } else {
   * verifyECDSA_P256(...) }` is the shape a contract that needs the bytes back
   * actually has, and dropping them here made the flags a no-op for it. Java
   * (`StackLower.java`) and Zig already copied them, so omitting them was also
   * a cross-tier divergence — the same source and flags produced locking
   * scripts tens of kilobytes apart, i.e. different funding addresses.
   *
   * `schedulerMode` is forced back to `'current'`. `lowerIf` reconciles the two
   * arms by MAIN-stack depth alone, so an arm must neither begin nor end with a
   * non-empty alt stack. `schedulingByLiveness` already refuses inside a branch
   * via `_insideBranch`, but `shouldSwapOperands` checks only the mode — so
   * inheriting it verbatim would newly reorder commutative operands inside arms.
   * Pin it here instead of relying on each call site to re-derive the rule.
   */
  private armOptions(): LoweringOptions {
    return { ...this.opts, schedulerMode: 'current' };
  }

  /**
   * Options handed to the EC / NIST codegen modules.
   *
   * Returns `undefined` — not `{}` — when nothing is enabled, so the emitters
   * take their untouched default path and the emitted bytes are provably
   * identical to the shipping ones.
   */
  private ecCodegenOptions(): EcCodegenOptions | undefined {
    if (!this.opts.ecConstantPool && !this.opts.ecReductionSinking
      && !this.opts.ecFixedBaseComb) return undefined;
    return {
      constantPool: this.opts.ecConstantPool === true,
      reductionSinking: this.opts.ecReductionSinking === true,
      fixedBaseComb: this.opts.ecFixedBaseComb === true,
    };
  }

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
   * Drain branch-private residue from below TOS at the end of a branch body,
   * so that both branches converge to a layout the parent stack model can
   * faithfully describe before OP_ENDIF (issue #36).
   *
   * A slot is residue when its name is NOT in `preIfNames` (the snapshot of
   * the parent's named slots taken before the branch ran). This catches both:
   *   1. Anonymous slots (`null`-named) — pushed by intrinsics like `substr`,
   *      which use OP_SPLIT and leave a residue half on the stack.
   *   2. Named branch-local slots — bindings introduced inside the branch
   *      that lingered past their last-use (e.g. dead-code load_const
   *      intermediates the constant-folder didn't eliminate).
   *
   * Slots whose name was already in `preIfNames` are kept — including
   * duplicates created by reassigning an outer-scope local from inside the
   * branch (those stale duplicates are cleaned up by the post-ENDIF logic in
   * `lowerIf`, not here). The TOS slot is also kept regardless: it's the
   * branch's result value or the latest reassignment.
   *
   * Process deepest-first so removing a deeper slot doesn't shift a shallower
   * slot's depth-from-top.
   */
  drainBranchPrivateResidue(preIfNames: Set<string>): void {
    const drainDepths: number[] = [];
    for (let d = 1; d < this.stackMap.depth; d++) {
      const name = this.stackMap.peekAtDepth(d);
      if (name === null) {
        drainDepths.push(d);
      } else if (!preIfNames.has(name)) {
        drainDepths.push(d);
      }
    }
    if (drainDepths.length === 0) return;
    drainDepths.sort((a, b) => b - a);
    for (const depth of drainDepths) {
      if (depth === 1) {
        this.emitOp({ op: 'nip' });
        this.stackMap.removeAtDepth(1);
      } else {
        this.emitOp({ op: 'push', value: BigInt(depth) });
        this.stackMap.push(null);
        this.emitOp({ op: 'roll', depth });
        this.stackMap.pop();
        const rolled = this.stackMap.removeAtDepth(depth);
        this.stackMap.push(rolled);
        this.emitOp({ op: 'drop' });
        this.stackMap.pop();
      }
    }
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
      // Drain the alt stack before anything the scheduler does not model, and
      // before the first binding that reads a parked value.
      if (this.altSpills.length > 0) {
        const refs = collectRefs(binding.value);
        if (!SPILLABLE_KINDS.has(binding.value.kind)
          || refs.some(r => this.altSpills.includes(r))
          || i === lastAssertIdx || i === terminalIfIdx) {
          this.restoreSpills();
        }
      }
      // Propagate source location from ANF binding to StackOps
      this.currentSourceLoc = binding.sourceLoc;
      if (binding.value.kind === 'assert' && i === lastAssertIdx) {
        // Terminal assert: leave value on stack instead of OP_VERIFY
        this.lowerAssert(binding.value.value, i, lastUses, true);
      } else if (binding.value.kind === 'if' && i === terminalIfIdx) {
        // Terminal if: propagate terminalAssert into both branches
        this.lowerIf(binding.name, binding.value.cond, binding.value.then, binding.value.else, binding.value.results ?? [], i, lastUses, true);
      } else {
        this.lowerBinding(binding, i, lastUses);
        this.maybeSpill(binding, i, bindings, lastUses);
      }
      this.currentSourceLoc = undefined;
    }

    // Nothing may outlive the scope on the alt stack.
    this.restoreSpills();
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
        this.lowerIf(name, value.cond, value.then, value.else, value.results ?? [], bindingIndex, lastUses);
        break;
      case 'loop':
        this.lowerLoop(name, value.count, value.body, value.iterVar, value.start, value.step, bindingIndex, lastUses);
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
        this.lowerCheckPreimage(name, value.preimage, value.sighashFlag, bindingIndex, lastUses);
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
      case 'add_data_output':
        // Wire shape matches add_raw_output: amount(8LE) + varint(scriptLen) + scriptBytes.
        // The distinction lives in the continuation-hash composition (ANF lowering).
        this.lowerAddRawOutput(name, value.satoshis, value.scriptBytes, bindingIndex, lastUses);
        break;
      case 'array_literal':
        this.lowerArrayLiteral(name, value.elements);
        break;
      case 'raw_script':
        this.lowerRawScript(name, value.bytes, value.in_arity, value.out_arity);
        break;
      default: {
        const unknown = value as { kind: string };
        throw new UnknownANFKindError(unknown.kind, 'stack-lower.lowerBinding');
      }
    }
  }

  /**
   * Lower a raw_script ANF node to a single opaque raw_bytes StackOp.
   *
   * The bytes pass through verbatim — the emit pass writes them as-is,
   * and the peephole optimizer must not bridge across them. Stack-tracker
   * bookkeeping consumes `in_arity` items and pushes `out_arity` items
   * named after the binding so downstream PICK/ROLL/DROP refer to the
   * correct logical slot.
   */
  private lowerRawScript(
    bindingName: string,
    bytesHex: string,
    inArity: number,
    outArity: number,
  ): void {
    if (this.stackMap.depth < inArity) {
      throw new Error(
        `raw_script binding '${bindingName}' requires ${inArity} stack items but only ${this.stackMap.depth} are present`,
      );
    }
    const bytes = decodeHexBytes(bytesHex);
    this.emitOp({ op: 'raw_bytes', bytes, in_arity: inArity, out_arity: outArity });
    for (let i = 0; i < inArity; i++) {
      this.stackMap.pop();
    }
    for (let i = 0; i < outArity; i++) {
      const slotName = outArity === 1 ? bindingName : `${bindingName}.${i}`;
      this.stackMap.push(slotName);
    }
    this.trackDepth();
  }

  /** Whether `ref` is used after `currentIndex`. */
  private isLastUse(ref: string, currentIndex: number, lastUses: Map<string, number>): boolean {
    const last = lastUses.get(ref);
    return last === undefined || last <= currentIndex;
  }

  /**
   * Consume-vs-copy decision for one operand of a multi-operand ANF value.
   *
   * `operands` is the FULL operand-ref list of the value (including `ref`
   * itself). The load may consume (ROLL / move) the ref only when this
   * binding is the ref's last use AND the ref occurs exactly once in the
   * operand list. A ref that is read at more than one operand position of
   * the same value must be copied (PICK / DUP) at EVERY position: each
   * operand position needs its own stack slot, and a consume-mode load of a
   * ref that is already on top of the stack is a no-op (see `bringToTop`),
   * so two consume-mode loads of the same ref would leave a single slot for
   * an opcode that pops one item per operand (e.g. `t := x + x` underflowing
   * OP_ADD), or — when the ref sits below other live slots — silently pair
   * the opcode with the wrong slot. The original value then simply stays on
   * the stack, exactly like any ref whose last use is a later binding.
   *
   * Unreachable from the frontend (pass 04 gives every operand a fresh
   * temp); reachable via `compileFromANF` / CLI `--ir` hand-written ANF.
   */
  private operandConsume(
    ref: string,
    operands: readonly string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): boolean {
    if (!this.isLastUse(ref, bindingIndex, lastUses)) return false;
    let occurrences = 0;
    for (const o of operands) {
      if (o === ref) occurrences++;
    }
    return occurrences <= 1;
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
    // The parameter is already on the stack under its original name — or, for
    // a param that shadows a mutable property, under a reserved renamed slot
    // (issue #130) so it is not confused with the deserialized property slot.
    const slotName = this.renamedParams.get(paramName) ?? paramName;
    if (this.stackMap.has(slotName)) {
      const isLast = this.isLastUse(paramName, bindingIndex, lastUses);
      this.bringToTop(slotName, isLast);
      // Rename the top-of-stack entry to the binding name
      this.stackMap.pop();
      this.stackMap.push(bindingName);
    } else {
      // Parameter no longer on the stack — a compiler invariant violation
      // (historically caused by unrolled loops consuming outer refs; see
      // lowerLoop). Silently emitting OP_0 here produced scripts that
      // compiled, passed the env-based interpreter, and then failed on
      // chain — fail loudly instead.
      throw new Error(
        `Stack lowering: method parameter '${paramName}' is not on the stack ` +
          `at a post-consumption reference (stack: [${this.stackMap.debugSlots()}]). ` +
          `Refusing to emit a silent OP_0 placeholder.`,
      );
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
      // Find the constructor param index: count only properties without initializers,
      // since initialized properties are excluded from the constructor.
      const ctorProps = this._properties.filter(p => p.initialValue === undefined);
      const paramIndex = ctorProps.findIndex(p => p.name === propName);
      // #119 tail (H1): a property that reaches the placeholder fallback with
      // no matching constructor slot (paramIndex === -1) has no deploy-time
      // bytes of its own. The previous behaviour coerced it onto slot 0,
      // silently splicing an UNRELATED constructor argument's placeholder into
      // the locking script — a silent-wrong-code path. Fail loudly instead.
      // (A real constructor-param property — readonly or a mutable state field
      // whose initial value is spliced at deploy — has paramIndex >= 0 and is
      // unaffected.)
      if (paramIndex < 0) {
        const loc = this.currentSourceLoc
          ? ` at ${this.currentSourceLoc.file}:${this.currentSourceLoc.line}:${this.currentSourceLoc.column}`
          : '';
        throw new Error(
          `Stack lowering: property '${propName}'${loc} is neither on the stack, ` +
            `initialized, nor a constructor parameter, so it has no deploy-time ` +
            `slot. Refusing to emit a placeholder for an unrelated constructor ` +
            `argument (slot 0). Known constructor-param properties: ` +
            `[${ctorProps.map(p => p.name).join(', ')}].`,
        );
      }
      this.emitOp({
        op: 'placeholder',
        paramIndex,
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
      // Special case: aliasing an array_literal (metadata-only binding,
      // not present in the stack-map). Copy the array metadata under the
      // new binding name and emit no stack moves.
      const refElems = this.arrayElements.get(refName);
      if (refElems !== undefined) {
        this.arrayElements.set(bindingName, [...refElems]);
        const refLen = this.arrayLengths.get(refName);
        if (refLen !== undefined) {
          this.arrayLengths.set(bindingName, refLen);
        }
        return;
      }
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
        // Referenced value no longer on the stack — a compiler invariant
        // violation (see lowerLoadParam for the loop-consumption history).
        // Fail loudly instead of silently emitting OP_0.
        throw new Error(
          `Stack lowering: value '${refName}' referenced by '${bindingName}' is not ` +
            `on the stack (stack: [${this.stackMap.debugSlots()}]). ` +
            `Refusing to emit a silent OP_0 placeholder.`,
        );
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
    // Track constant values for compile-time extraction (e.g., Merkle depth)
    this.constValues.set(bindingName, value);
  }

  /** Look up a compile-time constant value by binding name. Returns null if not a constant. */
  private getConstantValue(bindingName: string): bigint | string | boolean | null {
    return this.constValues.get(bindingName) ?? null;
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

  /**
   * Would materializing a commutative operator's operands right-then-left cost
   * fewer bytes than left-then-right?
   *
   * Scored with the exact emit-time cost of each `bringToTop`, on a throwaway
   * copy of the stack map so the real one is untouched. Ties keep source
   * order, which is what makes `'current'` and `'liveness'` identical wherever
   * this cannot help.
   */
  private shouldSwapOperands(
    op: string,
    left: string,
    right: string,
    leftConsume: boolean,
    rightConsume: boolean,
    resultType?: string,
  ): boolean {
    if (this.opts.schedulerMode !== 'liveness') return false;
    if (!COMMUTATIVE_BINOPS.has(op)) return false;
    // `+` on ByteString operands is OP_CAT, which is not commutative.
    if (resultType === 'bytes' && op === '+') return false;
    if (left === right) return false;

    const cost = (first: string, firstConsume: boolean, second: string, secondConsume: boolean): number => {
      const model = this.stackMap.clone();
      const ops: StackOp[] = [];
      for (const [name, consume] of [[first, firstConsume], [second, secondConsume]] as const) {
        const emitted = materializationOps(model, name, consume);
        if (emitted === null) return Number.POSITIVE_INFINITY; // not resident
        ops.push(...emitted);
      }
      // Score what the emitter would actually see, peephole included.
      return estimateScriptBytes(optimizeStackIR(ops));
    };

    return cost(right, rightConsume, left, leftConsume)
      < cost(left, leftConsume, right, rightConsume);
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
    const leftConsume = this.operandConsume(left, [left, right], bindingIndex, lastUses);
    const rightConsume = this.operandConsume(right, [left, right], bindingIndex, lastUses);

    // Commutative operators may take their operands in either order, so pick
    // the cheaper arrangement. The common win: the operand already on top is
    // materialized SECOND for free, instead of being buried by the other one
    // and then swapped back.
    if (this.shouldSwapOperands(op, left, right, leftConsume, rightConsume, resultType)) {
      this.bringToTop(right, rightConsume);
      this.bringToTop(left, leftConsume);
    } else {
      this.bringToTop(left, leftConsume);
      this.bringToTop(right, rightConsume);
    }

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

    // P-256 and P-384 EC builtins
    if (func === 'p256Add' || func === 'p256Mul' || func === 'p256MulGen' ||
        func === 'p256Negate' || func === 'p256OnCurve' || func === 'p256EncodeCompressed' ||
        func === 'p384Add' || func === 'p384Mul' || func === 'p384MulGen' ||
        func === 'p384Negate' || func === 'p384OnCurve' || func === 'p384EncodeCompressed') {
      this.lowerNistEcBuiltin(bindingName, func, args, bindingIndex, lastUses);
      return;
    }
    if (func === 'verifyECDSA_P256' || func === 'verifyECDSA_P384') {
      this.lowerVerifyECDSA(bindingName, func, args, bindingIndex, lastUses);
      return;
    }

    // BN254 builtins
    if (func === 'bn254FieldAdd' || func === 'bn254FieldSub' ||
        func === 'bn254FieldMul' || func === 'bn254FieldInv' ||
        func === 'bn254FieldNeg' || func === 'bn254G1Add' ||
        func === 'bn254G1ScalarMul' || func === 'bn254G1Negate' ||
        func === 'bn254G1OnCurve') {
      this.lowerBN254Builtin(bindingName, func, args, bindingIndex, lastUses);
      return;
    }

    // Baby Bear field arithmetic builtins
    if (func === 'bbFieldAdd' || func === 'bbFieldSub' ||
        func === 'bbFieldMul' || func === 'bbFieldInv' ||
        func === 'bbExt4Mul0' || func === 'bbExt4Mul1' ||
        func === 'bbExt4Mul2' || func === 'bbExt4Mul3' ||
        func === 'bbExt4Inv0' || func === 'bbExt4Inv1' ||
        func === 'bbExt4Inv2' || func === 'bbExt4Inv3') {
      this.lowerBBFieldBuiltin(bindingName, func, args, bindingIndex, lastUses);
      return;
    }

    // KoalaBear field arithmetic builtins
    if (func === 'kbFieldAdd' || func === 'kbFieldSub' ||
        func === 'kbFieldMul' || func === 'kbFieldInv' ||
        func === 'kbExt4Mul0' || func === 'kbExt4Mul1' ||
        func === 'kbExt4Mul2' || func === 'kbExt4Mul3' ||
        func === 'kbExt4Inv0' || func === 'kbExt4Inv1' ||
        func === 'kbExt4Inv2' || func === 'kbExt4Inv3') {
      this.lowerKBFieldBuiltin(bindingName, func, args, bindingIndex, lastUses);
      return;
    }

    // KoalaBear Poseidon2 builtins
    if (func === 'poseidon2KBPermute' || func === 'poseidon2KBCompress') {
      this.lowerKBPoseidon2Builtin(bindingName, func, args, bindingIndex, lastUses);
      return;
    }

    // KoalaBear Poseidon2 Merkle proof verification
    if (func === 'poseidon2MerkleRoot') {
      this.lowerPoseidon2MerkleRoot(bindingName, args, bindingIndex, lastUses);
      return;
    }

    // Merkle proof verification builtins
    if (func === 'merkleRootSha256' || func === 'merkleRootHash256') {
      this.lowerMerkleRoot(bindingName, func, args, bindingIndex, lastUses);
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
      const consume = this.operandConsume(arg, args, bindingIndex, lastUses);
      this.bringToTop(arg, consume);
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
   * Lower an array literal — a metadata-only operation.
   *
   * Array literals in Rúnar today only feed into `checkMultiSig`. Pre-laying
   * the elements onto the runtime stack here would desync the stack-map from
   * the runtime stack (the map can only model one slot per binding, but an
   * array binding spans N runtime slots). Instead we record the element refs
   * and the length and emit nothing — `lowerCheckMultiSig` will pull each
   * element to the top at the use site, producing a layout the stack-map can
   * faithfully describe.
   *
   * NOTE: this means `bindingName` never appears in the stack-map. Last-use
   * analysis for the array's element refs is patched in `computeLastUses` so
   * the elements stay live past this binding through to `checkMultiSig`.
   */
  private lowerArrayLiteral(
    bindingName: string,
    elements: string[],
  ): void {
    this.arrayLengths.set(bindingName, elements.length);
    this.arrayElements.set(bindingName, [...elements]);
  }

  /**
   * Lower checkMultiSig([sig1, ..., sigN], [pk1, ..., pkM]) to Bitcoin Script.
   *
   * OP_CHECKMULTISIG expects the stack (bottom -> top):
   *   <dummy=OP_0> <sig1> <sig2> ... <sigN> <N> <pk1> <pk2> ... <pkM> <M>
   *
   * OP_CHECKMULTISIG then pops M, then M pubkeys (top first => pkM..pk1),
   * then N, then N sigs (top first => sigN..sig1), then the dummy, then
   * pushes the result.
   *
   * `args[0]` and `args[1]` are bindings produced by `array_literal`. Those
   * bindings are NOT physical stack slots (see `lowerArrayLiteral`); their
   * element refs live on the stack-map as individual named bindings. We pull
   * each element to TOS via `bringToTop` in the order required by the layout
   * above. Last-use for each element is determined relative to THIS binding
   * (the checkMultiSig site) — `computeLastUses` patches lastUses for array
   * elements so they survive past their owning `array_literal` binding.
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
    const sigElems = this.arrayElements.get(sigsRef);
    const pkElems = this.arrayElements.get(pksRef);
    if (!sigElems || !pkElems) {
      throw new Error(
        `checkMultiSig: array_literal metadata missing (sigs='${sigsRef}', pks='${pksRef}')`,
      );
    }

    // Dummy OP_0 — required by the historical OP_CHECKMULTISIG off-by-one
    // (consumed from below the sigs).
    this.emitOp({ op: 'push', value: 0n });
    this.stackMap.push(null);

    // A ref repeated across the combined element list (e.g. the same pubkey
    // twice) must be copied at every position — see operandConsume.
    const msigOperands = [...sigElems, ...pkElems];

    // Bring each sig element to TOS in declaration order (sig1, sig2, ...).
    for (const sig of sigElems) {
      const consume = this.operandConsume(sig, msigOperands, bindingIndex, lastUses);
      this.bringToTop(sig, consume);
    }

    // Push nSigs.
    this.emitOp({ op: 'push', value: BigInt(sigElems.length) });
    this.stackMap.push(null);

    // Bring each pubkey element to TOS in declaration order (pk1, pk2, ...).
    for (const pk of pkElems) {
      const consume = this.operandConsume(pk, msigOperands, bindingIndex, lastUses);
      this.bringToTop(pk, consume);
    }

    // Push nPKs.
    this.emitOp({ op: 'push', value: BigInt(pkElems.length) });
    this.stackMap.push(null);

    // OP_CHECKMULTISIG consumes: dummy + N sigs + nSigs + M pks + nPKs.
    const consumed = 1 + sigElems.length + 1 + pkElems.length + 1;
    for (let i = 0; i < consumed; i++) {
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
        const consume = this.operandConsume(arg, args, bindingIndex, lastUses);
        this.bringToTop(arg, consume);
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

  /** Physically remove the stack slot `depth` places below the top. */
  private dropSlotAtDepth(depth: number): void {
    if (depth === 0) {
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
      return;
    }
    if (depth === 1) {
      this.emitOp({ op: 'nip' });
      this.stackMap.removeAtDepth(1);
      return;
    }
    this.emitOp({ op: 'push', value: BigInt(depth) });
    this.stackMap.push(null);
    this.emitOp({ op: 'roll', depth });
    this.stackMap.pop();
    const rolled = this.stackMap.removeAtDepth(depth);
    this.stackMap.push(rolled);
    this.emitOp({ op: 'drop' });
    this.stackMap.pop();
  }

  private lowerIf(
    bindingName: string,
    cond: string,
    thenBindings: ANFBinding[],
    elseBindings: ANFBinding[],
    /**
     * The `if` node's declared result slots, deepest first (see `If.results`
     * in ir/anf-ir.ts). Empty for an `if` that carries at most one result, and
     * then every path below behaves exactly as it did before the multi-result
     * contract existed.
     */
    results: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
    terminalAssert = false,
  ): void {
    // The ANF wire format has no version field, and `--ir` / `--ir-parity` are
    // documented surfaces that feed a checked-in ANF JSON straight into this
    // pass. An ANF produced BEFORE the multi-result node carries the trailing
    // `__merge$` block WITHOUT `results` — back then the block was a naming
    // CONVENTION this pass recognised, and no tier recognises it any more. It
    // deserialises cleanly, `nDeclared` is 0, and the result count falls back
    // to `thenDepth - parentDepth`, which counts the arm's untrimmed block
    // residue as results. Refuse it: the block can only be emitted by
    // `appendBranchResults`, which only runs for an `if` that declares
    // `results`, so block-without-results is by construction an ANF no current
    // compiler could have produced. Emits no opcodes.
    if (results.length === 0) {
      const stale = [...thenBindings, ...elseBindings]
        .find((b) => b.name.startsWith(MERGED_LOCAL_TEMP_PREFIX));
      if (stale) {
        throw new Error(
          `ANF produced by a pre-multi-result compiler: the conditional's arm ` +
          `carries a '${MERGED_LOCAL_TEMP_PREFIX}' block but the node declares ` +
          `no results (binding '${stale.name}'). That block used to be a naming ` +
          `convention this pass inferred results from; it is now a declared ` +
          `contract, and no tier reads the convention any more. Recompile the ` +
          `source with the current compiler instead of reusing the stored ANF. ` +
          `binding='${bindingName}'.`,
        );
      }
    }

    // Result slots are identified BY NAME — the layout assertion below compares
    // the arm's top-N slot names against this list, so two identically-named
    // results are indistinguishable and the assertion would be satisfied by
    // coincidence while one value silently replaced the other. 04-anf-lower
    // refuses the source shape that produces it (a local shadowing a written
    // property); this guards the `--ir` path, where the list arrives as data.
    if (results.length > 1 && new Set(results).size !== results.length) {
      throw new Error(
        `Internal codegen error: the conditional declares duplicate result ` +
        `names [${results.join(', ')}]. Result slots are matched by name, so ` +
        `duplicates cannot be told apart and one value would silently replace ` +
        `the other. binding='${bindingName}'.`,
      );
    }

    // NEW-015: does an ARM read the condition again?
    //
    // `lastUses` is keyed by the index of the ENCLOSING binding, and
    // `collectRefs` deliberately recurses into `then` / `else` so an arm-only
    // ref is not dropped early. Both facts together mean an arm's read of the
    // condition lands on THIS binding's index — indistinguishable from a ref
    // used only as the condition. `isLastUse` then said "yes, consume it",
    // `bringToTop` ROLLed the slot away, and the arm looked for a value that
    // was no longer there:
    //
    //     let f: boolean = c > 0n;
    //     assert(f ? c > 10n : !f);
    //     //  Value 'f' not found on stack (stack has 1 items: [c])
    //
    // Legal source, accepted by 02-validate and 03-typecheck, rejected here —
    // so there was no diagnostic a developer could act on. It only ever bit
    // when the condition local was DEAD after the `if`; one that stayed live
    // was already covered by the `lastIdx > bindingIndex` rule below, which is
    // why the shape looked like it worked. `&&` / `||` desugar to this node,
    // so `f || !f` routes through the same path.
    const condReadInArms =
      thenBindings.some(b => collectRefs(b.value).includes(cond)) ||
      elseBindings.some(b => collectRefs(b.value).includes(cond));

    // Get condition to top of stack
    const isLast = !condReadInArms && this.isLastUse(cond, bindingIndex, lastUses);
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

    // A condition the arms re-read was PICKed just above, so the slot survived
    // OP_IF. Protect it for the same reason the merged-local block below is
    // protected: only ONE arm may hold the read, so letting that arm consume
    // the slot would leave the two arms at different depths over a name the
    // parent still models.
    if (condReadInArms && this.stackMap.has(cond)) protectedRefs.add(cond);

    // The K>=2 merged-local block reads every merged local in BOTH arms, and
    // that read is RECONCILIATION, not a use: it is what makes each arm leave
    // exactly K equally-named result slots for the N>=2 reconcile below to
    // adopt. So the merged locals must be copied, never consumed — regardless
    // of whether the ENCLOSING scope reads them again.
    //
    // `appendMergedLocalResults` (04-anf-lower) states that as its premise:
    // "pass 1 always COPIES ... because a local live after the `if` is in
    // `outerProtectedRefs`". Enclosing-scope liveness is the wrong question,
    // and the premise silently failed for every merged local whose last
    // enclosing use IS this `if` — which is EVERY merged local of an `if` in a
    // loop body, since the body's last-use map ends at the `if` itself.
    //
    // What happened then: pass 1 ROLLED instead of picking, the arm's stack
    // effect stopped being +K, the arms ended at different depths, phase 3
    // padded the shortfall with EMPTY pushes, `elseMatchesThenNResultLayout`
    // saw `null` where it needed the merged name, and control fell through to
    // the single-slot fallback `this.stackMap.push(bindingName)` — ONE stackMap
    // name registered for K physical results, with `acc`/`wacc` still naming
    // the dead pre-`if` slots. `for (i<2) { if (i<5) { acc = acc + step;
    // wacc = wacc + acc; } }` with step = 3 produced wacc = 3 where the source
    // says 9: silently in a stateless contract, and as a permanently
    // unspendable UTXO in a stateful one. See
    // packages/runar-testing/src/__tests__/branch-merged-locals-dead-after-vm.test.ts.
    //
    // Byte-neutral for every program whose merged locals were already live
    // after the `if`: those names are already in `protectedRefs` above, which
    // is precisely why those programs compiled correctly.
    //
    // Now driven by the node's DECLARED results instead of by recognising a
    // trailing `__merge$` block, so an arm-written property is protected on the
    // same footing as a rebound local.
    for (const name of results) {
      if (this.stackMap.has(name)) protectedRefs.add(name);
    }

    // Snapshot parent stackMap names before branches run
    const preIfNames = this.stackMap.namedSlots();

    // Lower then-branch
    // `armOptions()`, not `this.opts`: the EC size flags MUST reach the arm
    // (an arm is where branch-guarded crypto lives), the liveness scheduler
    // must NOT — see the comment on `armOptions`.
    const thenCtx = new LoweringContext([], this._properties, this.privateMethods, this.armOptions());
    thenCtx.stackMap = this.stackMap.clone();
    thenCtx.outerProtectedRefs = protectedRefs;
    thenCtx._insideBranch = true;
    thenCtx.lowerBindings(thenBindings, terminalAssert);

    thenCtx.drainBranchPrivateResidue(preIfNames);

    // COVERAGE (measured 2026-08-17, v1 audit remediation — finding CC-016):
    // this guard did not fire ONCE across all 71 conformance fixtures, nine
    // hand-designed terminal-`if` shapes (stateless and stateful, multi-local
    // arms, property writes, multiple asserts per arm), 1200 `--tri-modal`
    // property runs, and 400 `--spend-oracle` cases. Instrumented with a
    // `console.error` in the body and counted; every count was 0.
    //
    // So a mechanical mutant here (`- 1` -> `+ 1`, which would emit two extra
    // OP_NIPs) survives the entire net — but as an EQUIVALENT mutant over dead
    // code, NOT as a coverage hole in a reachable path. Those are different
    // findings and the distinction matters for the mutation score.
    //
    // Deliberately NOT deleted. "I could not reach it" is not "it is provably
    // unreachable", and removing a defensive cleanup from `lowerIf` — the
    // function that carried issue #149 — on that evidence is not a trade worth
    // making before v1. If someone can show the arm can exit at depth > 1 under
    // a terminal assert, this needs a fixture; if it is provably unreachable,
    // it should go, and the mutation corpus should stop counting it.
    if (terminalAssert && thenCtx.stackMap.depth > 1) {
      const excess = thenCtx.stackMap.depth - 1;
      for (let i = 0; i < excess; i++) {
        thenCtx.emitOp({ op: 'nip' });
        thenCtx.stackMap.removeAtDepth(1);
      }
    }

    // Lower else-branch
    // `armOptions()`, not `this.opts`: the EC size flags MUST reach the arm
    // (an arm is where branch-guarded crypto lives), the liveness scheduler
    // must NOT — see the comment on `armOptions`.
    const elseCtx = new LoweringContext([], this._properties, this.privateMethods, this.armOptions());
    elseCtx.stackMap = this.stackMap.clone();
    elseCtx.outerProtectedRefs = protectedRefs;
    elseCtx._insideBranch = true;
    elseCtx.lowerBindings(elseBindings, terminalAssert);

    elseCtx.drainBranchPrivateResidue(preIfNames);

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
    //
    // NEW-018: counted by MULTIPLICITY, not by name-set membership.
    //
    // A parent stack legitimately holds the same name in more than one slot —
    // a loop rebinding a local leaves one slot per unrolled iteration, all
    // named `acc`, of which only the shallowest is ever read (the model
    // resolves a name to its shallowest slot). When an arm ROLLs that live
    // slot away, the name is STILL in the arm's name SET because the dead
    // residue slot beneath it carries the same name — so the set-difference
    // this phase used to compute saw nothing consumed, emitted no matching
    // drop in the sibling, and left the two arms one slot apart.
    //
    // Phase 3 then "fixed" the depth with an anonymous pad. A pad restores the
    // COUNT but not the POSITION: the arm that lost a slot from the middle of
    // the region gets a placeholder next to its result, while the sibling
    // still holds the real value in the original slot. The two arms leave
    // positionally different stacks, the parent adopts one of them, and every
    // slot the other arm holds below the result is off by one:
    //
    //     let acc = p; let wacc = 0n;
    //     for (…) for (…) { acc = acc + p; wacc = wacc + acc; }
    //     let br0 = 0n; const sib0 = p;
    //     if (p === 0n) { br0 = p; }
    //     assert((p >= 0n ? acc >= 0n : false) ? (br0 < sib0) : false);
    //
    // The inner conditional is the CONDITION of the outer one. Its then-arm
    // consumes the live `acc`; the parent holds `acc` twice, so phase 1 missed
    // it and the arms came back as `[t · br0 sib0 …]` against
    // `[t br0 sib0 acc …]`. With p = 1 the source ACCEPTS and `TestContract`
    // accepts; `ScriptVM` and `@bsv/sdk`'s `Spend` reject the spend with "The
    // top stack element must be truthy after script evaluation" — an ordinary
    // contract deployed to a permanently unspendable UTXO.
    //
    // Counting occurrences instead makes the sibling drop its matching slot,
    // both arms end at the same depth with the same layout, and no pad is
    // needed at all. Byte-neutral for every parent stack with no duplicated
    // name: for a name held once, "parent has 1, arm has 0" is exactly the
    // old `!postThenNames.has(name)`, and the drop depths are the same list.
    const countNames = (m: StackMap): Map<string, number> => {
      const counts = new Map<string, number>();
      for (let d = 0; d < m.depth; d++) {
        const n = m.peekAtDepth(d);
        if (n !== null) counts.set(n, (counts.get(n) ?? 0) + 1);
      }
      return counts;
    };
    const preIfCounts = countNames(this.stackMap);
    const thenCounts = countNames(thenCtx.stackMap);
    const elseCounts = countNames(elseCtx.stackMap);
    const consumedNames: string[] = [];
    const elseConsumedNames: string[] = [];
    for (const [name, held] of preIfCounts) {
      const thenLost = Math.max(0, held - (thenCounts.get(name) ?? 0));
      const elseLost = Math.max(0, held - (elseCounts.get(name) ?? 0));
      for (let i = 0; i < thenLost - elseLost; i++) consumedNames.push(name);
      for (let i = 0; i < elseLost - thenLost; i++) elseConsumedNames.push(name);
    }

    // The depths to drop, shallowest occurrences first for a name listed more
    // than once — the shallowest slot is the live one, and it is the one the
    // sibling arm consumed. Returned deepest-first so removing a deeper slot
    // does not shift a shallower one. For a name listed once this is exactly
    // `findDepth`, which also resolves to the shallowest slot.
    const dropDepthsFor = (m: StackMap, names: string[]): number[] => {
      const need = new Map<string, number>();
      for (const n of names) need.set(n, (need.get(n) ?? 0) + 1);
      const depths: number[] = [];
      for (let d = 0; d < m.depth; d++) {
        const n = m.peekAtDepth(d);
        if (n === null) continue;
        const want = need.get(n) ?? 0;
        if (want > 0) {
          depths.push(d);
          need.set(n, want - 1);
        }
      }
      return depths.sort((a, b) => b - a);
    };

    // Phase 2: perform ALL drops before any placeholder pushes.
    // This prevents double-placeholder when bilateral drops balance each other.
    if (consumedNames.length > 0) {
      const depths = dropDepthsFor(elseCtx.stackMap, consumedNames);
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
      const depths = dropDepthsFor(thenCtx.stackMap, elseConsumedNames);
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

    // Branch-merged locals: trim each arm down to exactly its K result slots.
    //
    // 04-anf-lower ends both arms with an identical K-binding block that
    // rebinds every merged local from a `__merge$<i>` temp (see
    // `appendMergedLocalResults`). That block leaves the K live values on top
    // in the same canonical order in both arms — but BENEATH them each arm
    // still holds whatever its own body produced, and those differ per arm
    // (the then-arm's rebind of `a`, the else-arm's rebind of `b`), which is
    // exactly what the N>=2 reconcile further down compares. Everything
    // beneath the K results is dead: the block copied each merged local before
    // rebinding it, and a branch-local binding is not visible after the `if`.
    //
    // Runs AFTER the phase-2 consumption drops, so both arms have given up the
    // same parent slots and share one base depth. Measuring the base from the
    // parent's raw depth instead would be wrong for any arm that consumed a
    // parent value (`na = bidAmount` rolls `bidAmount` away when the parent has
    // no later use for it), which is the shape the filed reproducer hits.
    const nDeclared = results.length;
    if (nDeclared >= 1) {
      // NEW-018: counted by MULTIPLICITY, for the same reason phase 1 is. Phase 1
      // now makes both arms give up the same slot of a name the parent holds
      // twice, so the base depth has to count that slot as given up too —
      // otherwise `targetDepth` is one too high, the trim below does nothing, and
      // the layout assertion fires on a program that is actually well-formed.
      // Byte-neutral for a name the parent holds once, where "held 1, arm holds
      // 0" is exactly the old `!stillHeld.has(name)`.
      const stillHeldCounts = countNames(thenCtx.stackMap);
      let consumedFromParent = 0;
      for (const [name, held] of preIfCounts) {
        consumedFromParent += Math.max(0, held - (stillHeldCounts.get(name) ?? 0));
      }
      const targetDepth = this.stackMap.depth - consumedFromParent + nDeclared;
      for (const ctx of [thenCtx, elseCtx]) {
        while (ctx.stackMap.depth > targetDepth) {
          ctx.dropSlotAtDepth(nDeclared);
        }
      }

      // The declared contract, checked rather than assumed: after the trim,
      // each arm's top N slots must BE the declared results, in the declared
      // order (`results[0]` deepest). `appendBranchResults` in 04-anf-lower is
      // what makes this true; if it ever stops being true the arms disagree on
      // layout, which is precisely the failure that produced the 2026-08
      // miscompile family. Emits no opcodes.
      for (const [label, ctx] of [['then', thenCtx], ['else', elseCtx]] as const) {
        if (ctx.stackMap.depth !== targetDepth) {
          throw new Error(
            `Internal codegen error: branch result layout mismatch — the ${label}-arm ` +
            `of the conditional ends at depth ${ctx.stackMap.depth}, but its ` +
            `${nDeclared} declared result(s) require depth ${targetDepth}. ` +
            `binding='${bindingName}'.`,
          );
        }
        for (let i = 0; i < nDeclared; i++) {
          const want = results[nDeclared - 1 - i]!;
          const got = ctx.stackMap.peekAtDepth(i);
          if (got !== want) {
            throw new Error(
              `Internal codegen error: branch result layout mismatch — the ${label}-arm ` +
              `of the conditional holds '${got}' where the node declares ` +
              `'${want}' (slot ${nDeclared - 1 - i} of [${results.join(', ')}]). ` +
              `Every later operand would resolve to the wrong slot. ` +
              `binding='${bindingName}'.`,
            );
          }
        }
      }
    }

    // Phase 3: depth-balance reconciliation after ALL drops.
    //
    // Compensate the FULL depth difference between the branches — NOT just a
    // single item. A conditional write of N state fields leaves N result
    // values on the then-branch, so the (empty) else-branch must preserve N
    // old values. Issue #99 Bug 1: the previous single-shot check only
    // balanced a 1-item difference, leaving N>=2 conditional writes
    // imbalanced by (N-1) and the update branch unspendable.
    //
    // For each missing slot, when the then-branch reassigned a variable
    // (if-without-else), push a COPY of that same-named (old) value in the
    // else-branch so the preserved value is correct; otherwise push a generic
    // placeholder. Process the then-branch's result slots from deepest to
    // top so the preserved copies land in the same order.
    while (thenCtx.stackMap.depth > elseCtx.stackMap.depth) {
      const resultDepth = thenCtx.stackMap.depth - elseCtx.stackMap.depth - 1;
      const thenName = thenCtx.stackMap.peekAtDepth(resultDepth);
      if (elseBindings.length === 0 && thenName && elseCtx.stackMap.has(thenName)) {
        const varDepth = elseCtx.stackMap.findDepth(thenName);
        if (varDepth === 0) {
          elseCtx.emitOp({ op: 'dup' });
        } else {
          elseCtx.emitOp({ op: 'push', value: BigInt(varDepth) });
          elseCtx.stackMap.push(null);
          elseCtx.emitOp({ op: 'pick', depth: varDepth });
          elseCtx.stackMap.pop();
        }
        elseCtx.stackMap.push(thenName);
      } else {
        elseCtx.emitOp({ op: 'push', value: new Uint8Array(0) });
        elseCtx.stackMap.push(null);
      }
    }
    while (elseCtx.stackMap.depth > thenCtx.stackMap.depth) {
      thenCtx.emitOp({ op: 'push', value: new Uint8Array(0) });
      thenCtx.stackMap.push(null);
    }

    // Layer B — branch-balance invariant (#99 Bug 1 guard).
    // After reconciliation the two arms of an OP_IF/OP_ELSE MUST leave the
    // stack at identical depth; otherwise the code after OP_ENDIF (which is
    // generated against a single assumed depth) is only correct for whichever
    // branch the spender does not take, producing a silently-unspendable
    // script. The Bitcoin Script VM does not enforce branch balance, so this
    // check is the compiler's responsibility. A failure here is a codegen bug,
    // never a user error — fail loudly at compile time instead of on-chain.
    if (thenCtx.stackMap.depth !== elseCtx.stackMap.depth) {
      throw new Error(
        `Internal codegen error: conditional in method emitted stack-imbalanced ` +
        `branches (then depth ${thenCtx.stackMap.depth} != else depth ${elseCtx.stackMap.depth}). ` +
        `This would produce an unspendable script (see GitHub issue #99). ` +
        `binding='${bindingName}'.`,
      );
    }

    const thenOps = thenCtx.result.ops;
    const elseOps = elseCtx.result.ops;

    this.emitOp({
      op: 'if',
      then: thenOps,
      else: elseOps.length > 0 ? elseOps : undefined,
    });

    // Physical slots this method drops AFTER OP_ENDIF, while reconciling the
    // parent stackMap against the arms' results. Counted because the invariant
    // at the end of `lowerIf` cannot compare the two depths directly: the
    // post-ENDIF reconcile legitimately ROLL/DROPs stale slots out from under
    // the results, so those drops have to be added back before comparing.
    let postEndifDrops = 0;

    // Reconcile parent stackMap: remove items consumed by the branches.
    // Use thenCtx as the reference (both branches must consume the same items).
    //
    // NEW-018: counted by MULTIPLICITY, for the same reason phase 1 is. When
    // the arms consume the live slot of a name the parent holds twice, the
    // parent must give up one slot too — the set test kept both, so the parent
    // modelled one more slot than the arms physically left and the adopt below
    // saw `armDepth === parentDepth` and pushed nothing at all. Byte-neutral
    // for a name the parent holds once: "held 1, arm holds 0" is exactly the
    // old `!postBranchNames.has(name)`, and it removes the same single slot.
    const postBranchCounts = countNames(thenCtx.stackMap);
    for (const [name, held] of preIfCounts) {
      let excess = held - (postBranchCounts.get(name) ?? 0);
      while (excess > 0 && this.stackMap.has(name)) {
        this.stackMap.removeAtDepth(this.stackMap.findDepth(name));
        excess--;
      }
    }

    // C27: the N>=2 result reconcile below also applies when the else-branch is
    // PRESENT and BOTH arms wrote the same N names (e.g. each branch runs
    // `this.a = ...; this.b = ...`, or each rebinds the same N locals). This is
    // the else-present twin of the empty-else fix (#99 Bug 1). Without it,
    // lowerIf falls through to `push(bindingName)` further down — registering
    // ONE stackMap name for N physical results — so the state serialization
    // emits against the wrong slot (OP_NUM2BIN on a byte string) and the
    // continuation is unspendable (a funds-safety bug). Only fire when both
    // arms leave the identical top-N names in the identical order, so a single
    // post-ENDIF reconcile is valid regardless of which branch the spender
    // takes. The single-field same-property case (N==1, "turn flip") is
    // unaffected — it still takes the dedicated path below.
    //
    // The names do NOT have to be contract properties. Branch-merged LOCALS
    // reach here in exactly the same shape: 04-anf-lower appends an explicit
    // rebind of every merged local to both arms precisely so that this
    // reconcile can adopt them by name. Requiring `_properties` membership was
    // what dropped merged locals into the broken single-slot fallback (see
    // packages/runar-testing/src/__tests__/branch-merged-locals-vm.test.ts).
    const nResults = thenCtx.stackMap.depth - this.stackMap.depth;
    const elseMatchesThenNResultLayout =
      elseBindings.length > 0 &&
      nResults >= 2 &&
      elseCtx.stackMap.depth - this.stackMap.depth === nResults &&
      Array.from({ length: nResults }).every((_unused, i) => {
        const tn = thenCtx.stackMap.peekAtDepth(i);
        return tn !== null && tn === elseCtx.stackMap.peekAtDepth(i);
      });

    // The if expression may produce a result value on top.
    if (nDeclared >= 1) {
      // DECLARED RESULTS. Both arms were normalised by `appendBranchResults`
      // and the layout check above proved they hold exactly `results`, so the
      // parent adopts them BY THE DECLARED ORDER — no counting of trailing
      // `__merge$` bindings, no comparison of arm depths, no inference of which
      // names are still live. `results[0]` is the deepest slot, matching the
      // order pass 2 of the normalisation rebound them in.
      //
      // Then each parent slot that the block shadows (the pre-`if` binding of a
      // merged local, the stale value of a written property) is physically
      // rolled out from under the results, exactly as the pre-existing N>=2
      // reconcile did — which is why the four `__merge$` goldens keep their
      // bytes.
      for (const name of results) {
        this.stackMap.push(name);
      }
      // How far below the result block the deepest stale slot sat. Adopting a
      // result puts it ON TOP, but its pre-`if` binding lived at depth `d`,
      // i.e. BENEATH the `d - nDeclared` slots in between. Removing the stale
      // copy does not reorder those in-between slots, so after the loop the
      // adopted result has crossed them: the layout is rotated even though the
      // NAME SET and the DEPTH are both unchanged. That is invisible to the
      // reconcile's name-set check and to Layer C's depth check, and it is the
      // whole of issue #149 — see `sinkBelow` below.
      let sinkBelow = 0;
      for (let i = nDeclared - 1; i >= 0; i--) {
        const name = results[i]!;
        for (let d = nDeclared; d < this.stackMap.depth; d++) {
          if (this.stackMap.peekAtDepth(d) === name) {
            this.emitOp({ op: 'push', value: BigInt(d) });
            this.stackMap.push(null);
            this.emitOp({ op: 'roll', depth: d + 1 });
            this.stackMap.pop();
            const rolled = this.stackMap.removeAtDepth(d);
            this.stackMap.push(rolled);
            this.emitOp({ op: 'drop' });
            this.stackMap.pop();
            postEndifDrops++;
            if (d - nDeclared > sinkBelow) sinkBelow = d - nDeclared;
            break;
          }
        }
      }

      // Restore the inherited layout: sink the whole result block back under
      // the `sinkBelow` slots it just crossed, so BOTH paths of the enclosing
      // `if` leave the same slot order and every post-OP_ENDIF read resolves
      // against the layout it was generated for. Rolling the deepest item of
      // the (nDeclared + sinkBelow) window to the top, `sinkBelow` times,
      // lifts those slots back above the results while preserving their own
      // relative order.
      // Applied unconditionally, NOT gated on this `if`'s own else. The
      // asymmetry that makes #149 unspendable belongs to the ENCLOSING `if`
      // (whose fall-through path keeps the pre-`if` layout), and `lowerIf` has
      // no view of its parent here. Gating on `elseBindings.length === 0` was
      // measured and is WRONG: the #149 inner `if` has a real else, so the gate
      // disables the repair exactly where it is needed. Restoring the pre-`if`
      // order unconditionally keeps the parent's own model — names at the
      // depths it recorded before the branch — true on every path.
      if (sinkBelow > 0) {
        const windowSize = nDeclared + sinkBelow;
        for (let j = 0; j < sinkBelow; j++) {
          this.emitOp({ op: 'push', value: BigInt(windowSize - 1) });
          this.stackMap.push(null);
          this.emitOp({ op: 'roll', depth: windowSize });
          this.stackMap.pop();
          const lifted = this.stackMap.removeAtDepth(windowSize - 1);
          this.stackMap.push(lifted);
        }
      }
    } else if (thenCtx.stackMap.depth > this.stackMap.depth &&
        nResults >= 2 &&
        (elseBindings.length === 0 || elseMatchesThenNResultLayout)) {
      // #99 Bug 1: a conditional write of N>=2 state fields leaves N result
      // values on top (new values if taken, preserved old values if skipped).
      // Record the N results in their on-stack order, then physically remove
      // the N stale old property values that now sit beneath the result block.
      const resultCount = thenCtx.stackMap.depth - this.stackMap.depth;
      for (let i = resultCount - 1; i >= 0; i--) {
        this.stackMap.push(thenCtx.stackMap.peekAtDepth(i) ?? bindingName);
      }
      const resultNames: (string | null)[] = [];
      for (let i = 0; i < resultCount; i++) {
        resultNames.push(this.stackMap.peekAtDepth(i));
      }
      for (const name of resultNames) {
        if (name === null) continue;
        for (let d = resultCount; d < this.stackMap.depth; d++) {
          if (this.stackMap.peekAtDepth(d) === name) {
            this.emitOp({ op: 'push', value: BigInt(d) });
            this.stackMap.push(null);
            this.emitOp({ op: 'roll', depth: d + 1 });
            this.stackMap.pop();
            const rolled = this.stackMap.removeAtDepth(d);
            this.stackMap.push(rolled);
            this.emitOp({ op: 'drop' });
            this.stackMap.pop();
            postEndifDrops++;
            break;
          }
        }
      }
    } else if (thenCtx.stackMap.depth > this.stackMap.depth) {
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
            postEndifDrops++;
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
            postEndifDrops++;
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

    // Layer C — branch result-depth invariant.
    //
    // The stackMap is the compiler's ONLY model of the stack, so a stackMap
    // that names FEWER slots than the arms physically left is not detectable
    // anywhere downstream: every later operand silently resolves N slots off.
    // That single failure mode produced the whole 2026-08 branch/loop
    // miscompile family — wrong-but-accepted state continuations at best, and
    // scripts `Spend` rejects outright (locked funds) at worst.
    //
    // What must hold when `lowerIf` returns: the parent stackMap describes
    // exactly the physical stack. Both arms ended at `armDepth` (Layer B above
    // proves they agree), OP_ENDIF changes nothing, and the only physical
    // effect after it is the `postEndifDrops` stale-slot drops the reconcile
    // emitted. So:
    //
    //     this.stackMap.depth + postEndifDrops === armDepth
    //
    // The naive `this.stackMap.depth === armDepth` is WRONG — the reconcile
    // legitimately ROLL/DROPs stale slots out from under the results, which is
    // exactly what `postEndifDrops` counts.
    //
    // A failure here is always a codegen bug, never a user error, and is
    // reported as such. Emits no opcodes: byte-neutral by construction. Same
    // genre as Layer B (#99), added for the same reason.
    const armDepth = thenCtx.stackMap.depth;
    if (this.stackMap.depth + postEndifDrops !== armDepth) {
      throw new Error(
        `Internal codegen error: branch result depth mismatch — the parent ` +
        `stack model does not describe the physical stack after OP_ENDIF ` +
        `(stackMap depth ${this.stackMap.depth} + ${postEndifDrops} post-ENDIF ` +
        `drop(s) != arm depth ${armDepth}). The arms leave ` +
        `${armDepth - this.stackMap.depth - postEndifDrops} more physical slot(s) ` +
        `than the compiler recorded, so every later operand would resolve to the ` +
        `wrong slot and the script would be wrong or unspendable. ` +
        `binding='${bindingName}'.`,
      );
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
    start: bigint,
    step: 1 | -1,
    loopBindingIndex?: number,
    enclosingLastUses?: Map<string, number>,
  ): void {
    // Names (re)defined anywhere inside the loop body, nested branches
    // included. A name the body itself binds is NOT an outer ref —
    // reassigned locals (e.g. `off = off + ...` inside an if) flow through
    // lowerIf's branch-reassignment reconciliation, not through protection
    // here.
    const deepBodyBindingNames = collectDeepBindingNames(body);
    const bodyBindingNames = new Set(body.map(b => b.name));

    // Collect ALL outer-scope refs used anywhere in the body — including
    // refs that only occur inside nested if-branches (collectRefs recurses).
    // The previous top-level-only scan missed nested references: a const
    // defined before the loop and referenced only inside an if-branch was
    // consumed by the first iteration, making iteration 2 fail with
    // "Value 'X' not found on stack".
    const outerRefs = new Set<string>();
    for (const b of body) {
      for (const ref of collectRefs(b.value)) {
        if (ref !== _iterVar && !deepBodyBindingNames.has(ref)) {
          outerRefs.add(ref);
        }
      }
    }

    // A local the body REBINDS and then READS again in the same iteration is
    // carried across iterations through the rebound slot, so it must survive
    // the body exactly like an outer ref. `deepBodyBindingNames` above
    // excludes it precisely because the body binds it — which is what made
    // the updated value consumable. See `collectLoopCarriedRebinds`.
    for (const name of collectLoopCarriedRebinds(body)) {
      if (name !== _iterVar) outerRefs.add(name);
    }

    // Temporarily extend localBindings with body binding names so
    // @ref: to body-internal values can consume on last use.
    const prevLocalBindings = this.localBindings;
    this.localBindings = new Set([...this.localBindings, ...bodyBindingNames]);

    // Loops are unrolled at compile time. Repeat the body `count` times.
    for (let i = 0; i < count; i++) {
      // Push the iteration variable value (in case the loop body uses it).
      // Iteration `i` binds `start + i*step` (issue #121); zero-start
      // counting-up loops (start=0, step=1) reduce to `BigInt(i)`, preserving
      // the historical byte-for-byte lowering.
      this.emitOp({ op: 'push', value: start + BigInt(i) * BigInt(step) });
      this.stackMap.push(_iterVar);

      const lastUses = computeLastUses(body);

      // Prevent outer-scope refs from being consumed by setting their
      // last-use beyond any body binding index:
      //  - in non-final iterations: always (the next iteration re-reads them);
      //  - in the FINAL iteration: when the enclosing scope still references
      //    them AFTER the loop. Previously the final iteration consumed
      //    every outer ref at its last body use, so a method param (or
      //    const) referenced after the loop was gone from the stack and was
      //    silently lowered to an OP_0/empty push — compilation succeeded,
      //    the env-based interpreter passed, but the emitted Script failed
      //    at runtime (silent interpreter <-> Script divergence).
      const isFinalIteration = i === count - 1;
      for (const refName of outerRefs) {
        const usedAfterLoop =
          enclosingLastUses !== undefined &&
          loopBindingIndex !== undefined &&
          (enclosingLastUses.get(refName) ?? -1) > loopBindingIndex;
        if (!isFinalIteration || usedAfterLoop) {
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

      // Convert numeric/boolean values to fixed-width bytes via OP_NUM2BIN.
      // RabinSig / RabinPubKey are bigint aliases and share the 8-byte layout.
      if (prop.type === 'bigint' || prop.type === 'RabinSig' || prop.type === 'RabinPubKey') {
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
      } else if (prop.type === 'ByteString') {
        // Prepend push-data length prefix (matching SDK format)
        this.emitPushDataEncode();
      }
      // For other byte types (PubKey, Sig, Sha256, Ripemd160, Addr, Point,
      // P256Point, P384Point, SigHashPreimage), no conversion needed — they
      // are already fixed-width byte strings.

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
    const stateConsume = this.operandConsume(
      stateBytesRef, [preimageRef, stateBytesRef], bindingIndex, lastUses);
    this.bringToTop(stateBytesRef, stateConsume);

    // Extract amount from preimage for the continuation output.
    // We still need the amount from the current UTXO. Extract from preimage:
    // BIP-143 preimage has amount at offset (104 + varint + scriptLen).
    // Since the varint+scriptCode length varies, use end-relative:
    // Last 44 bytes = nSeq(4) + hashOutputs(32) + nLocktime(4) + sighashType(4).
    // Amount(8) is right before that.
    const preConsume = this.operandConsume(
      preimageRef, [preimageRef, stateBytesRef], bindingIndex, lastUses);
    this.bringToTop(preimageRef, preConsume);

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

    const csoOperands = [preimageRef, stateBytesRef, newAmountRef];

    // Consume preimage ref (no longer needed — we use _codePart and _newAmount).
    const preConsume = this.operandConsume(preimageRef, csoOperands, bindingIndex, lastUses);
    this.bringToTop(preimageRef, preConsume);
    this.emitOp({ op: 'drop' });
    this.stackMap.pop();

    // Step 1: Convert _newAmount to 8-byte LE and save to altstack.
    const amountConsume = this.operandConsume(newAmountRef, csoOperands, bindingIndex, lastUses);
    this.bringToTop(newAmountRef, amountConsume);
    this.emitOp({ op: 'push', value: 8n });
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
    this.stackMap.pop(); this.stackMap.pop();
    this.stackMap.push(null);
    this.emitOp({ op: 'opcode', code: 'OP_TOALTSTACK' });
    this.stackMap.pop();

    // Step 2: Bring stateBytes to stack.
    const stateConsume = this.operandConsume(stateBytesRef, csoOperands, bindingIndex, lastUses);
    this.bringToTop(stateBytesRef, stateConsume);

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
    const pkhConsume = this.operandConsume(pkhRef, [pkhRef, amountRef], bindingIndex, lastUses);
    this.bringToTop(pkhRef, pkhConsume);
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
    const amountConsume = this.operandConsume(amountRef, [pkhRef, amountRef], bindingIndex, lastUses);
    this.bringToTop(amountRef, amountConsume);
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
    const outputOperands = [satoshis, ...stateValues];

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

      const consume = this.operandConsume(valueRef, outputOperands, bindingIndex, lastUses);
      this.bringToTop(valueRef, consume);

      // Convert numeric/boolean values to fixed-width bytes.
      // RabinSig / RabinPubKey are bigint aliases and share the 8-byte layout.
      if (prop.type === 'bigint' || prop.type === 'RabinSig' || prop.type === 'RabinPubKey') {
        this.emitOp({ op: 'push', value: 8n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
        this.stackMap.pop();
      } else if (prop.type === 'boolean') {
        this.emitOp({ op: 'push', value: 1n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_NUM2BIN' });
        this.stackMap.pop();
      } else if (prop.type === 'ByteString') {
        // Prepend push-data length prefix (matching SDK format)
        this.emitPushDataEncode();
      }
      // Other byte types (PubKey, Sig, Sha256, Ripemd160, Addr, Point,
      // P256Point, P384Point, SigHashPreimage) used as-is.

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
    const satoshisConsume = this.operandConsume(satoshis, outputOperands, bindingIndex, lastUses);
    this.bringToTop(satoshis, satoshisConsume);
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
    const scriptConsume = this.operandConsume(
      scriptBytes, [satoshis, scriptBytes], bindingIndex, lastUses);
    this.bringToTop(scriptBytes, scriptConsume);

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
    const satConsume = this.operandConsume(
      satoshis, [satoshis, scriptBytes], bindingIndex, lastUses);
    this.bringToTop(satoshis, satConsume);
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

    // Compute state layout — use -1 as sentinel for variable-length (ByteString)
    const propSizes: number[] = [];
    let hasVariableLength = false;
    for (const prop of stateProps) {
      switch (prop.type) {
        case 'bigint': propSizes.push(8); break;
        // RabinSig / RabinPubKey are bigint aliases — same 8-byte layout.
        case 'RabinSig':
        case 'RabinPubKey': propSizes.push(8); break;
        case 'boolean': propSizes.push(1); break;
        case 'PubKey': propSizes.push(33); break;
        case 'Addr': propSizes.push(20); break;
        // Ripemd160 is 20 bytes (same underlying shape as Addr).
        case 'Ripemd160': propSizes.push(20); break;
        case 'Sha256': propSizes.push(32); break;
        case 'Point': propSizes.push(64); break;
        // P-256 point: x[32] || y[32] = 64 bytes (same shape as Point).
        case 'P256Point': propSizes.push(64); break;
        // P-384 point: x[48] || y[48] = 96 bytes.
        case 'P384Point': propSizes.push(96); break;
        case 'ByteString': propSizes.push(-1); hasVariableLength = true; break;
        default:
          throw new Error(`deserialize_state: unsupported type '${prop.type}' for '${prop.name}'`);
      }
    }

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

    if (!hasVariableLength) {
      // All fields fixed-size — existing code path (backward compatible)
      const stateLen = propSizes.reduce((a, b) => a + b, 0);

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
      this.splitFixedStateFields(stateProps, propSizes);
    } else if (!this.stackMap.has('_codePart')) {
      // Variable-length state but _codePart is not available (terminal method).
      // Skip deserialization entirely — the method body doesn't use mutable state.
      // Drop the varint+scriptCode from the stack.
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
    } else {
      // Variable-length path: ByteString fields present. We need _codePart
      // to compute the state offset at runtime.
      //
      // After steps 1-3 we have [varint || scriptCode] on the stack and
      // need to strip the BIP-143 scriptCode varint prefix:
      //   length < 0xfd:        1 byte
      //   length <= 0xffff:     0xfd + 2 bytes LE  (3 bytes)
      //   length <= 0xffffffff: 0xfe + 4 bytes LE  (5 bytes)
      //   otherwise:            0xff + 8 bytes LE  (9 bytes)
      //
      // We must support all four shapes; stripping only 1- and 3-byte
      // varints corrupts state extraction for scripts whose scriptCode
      // exceeds 65,535 bytes (e.g. embedded BN254 verifiers) and
      // surfaces as `Invalid OP_SPLIT range` on regtest.
      this.emitOp({ op: 'push', value: 1n });
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null); // firstByte
      this.stackMap.push(null); // rest
      this.emitOp({ op: 'swap' }); // [rest, firstByte]
      this.stackMap.swap();
      // Zero-pad firstByte before BIN2NUM so 0xfd/0xfe/0xff aren't read
      // as negative script numbers.
      this.emitOp({ op: 'push', value: new Uint8Array([0]) });
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_CAT' });
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
      // Stack: [..., rest, fb_num]

      // emitDropMoreVarintBytes drops `n` more varint bytes from the top
      // of stack `rest`. [..., rest] -> [..., rest_minus_n].
      const emitDropMoreVarintBytes = (n: bigint): void => {
        this.emitOp({ op: 'push', value: n });
        this.stackMap.push(null);
        this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
        this.stackMap.pop(); this.stackMap.pop();
        this.stackMap.push(null); this.stackMap.push(null);
        this.emitOp({ op: 'nip' });
        this.stackMap.pop(); this.stackMap.pop();
        this.stackMap.push(null);
      };

      // IF fb_num < 253: 1-byte varint, drop fb_num.
      this.emitOp({ op: 'dup' });
      this.stackMap.dup();
      this.emitOp({ op: 'push', value: 253n });
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_LESSTHAN' });
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_IF' });
      this.stackMap.pop();
      const smAt1ByteIf = this.stackMap.clone();
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
      this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
      this.stackMap = smAt1ByteIf.clone();
      // ELSE: fb_num >= 253. Check 0xfe (5-byte varint) next.
      this.emitOp({ op: 'dup' });
      this.stackMap.dup();
      this.emitOp({ op: 'push', value: 254n });
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_NUMEQUAL' });
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_IF' });
      this.stackMap.pop();
      const smAtFEIf = this.stackMap.clone();
      // THEN: 5-byte varint (0xfe + 4 bytes LE).
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
      emitDropMoreVarintBytes(4n);
      this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
      this.stackMap = smAtFEIf.clone();
      // ELSE: fb_num != 254. Check 0xff (9-byte varint) next.
      this.emitOp({ op: 'dup' });
      this.stackMap.dup();
      this.emitOp({ op: 'push', value: 255n });
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_NUMEQUAL' });
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_IF' });
      this.stackMap.pop();
      const smAtFFIf = this.stackMap.clone();
      // THEN: 9-byte varint (0xff + 8 bytes LE).
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
      emitDropMoreVarintBytes(8n);
      this.emitOp({ op: 'opcode', code: 'OP_ELSE' });
      this.stackMap = smAtFFIf.clone();
      // ELSE: fb_num must be 253 (0xfd) — 3-byte varint.
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
      emitDropMoreVarintBytes(2n);
      this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
      this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
      this.emitOp({ op: 'opcode', code: 'OP_ENDIF' });
      // --- Stack: [..., scriptCode] ---

      // Compute skip to state in scriptCode.
      // scriptCode = postSepCode + 0x6a + state
      // skip = len(postSepCode) + 1 = SIZE(_codePart) - codeSepIdx
      // We use push_codesep_index (filled in by the emitter) to get codeSepIdx.

      // 4a. Compute skip = SIZE(_codePart) - codeSepIdx
      this.bringToTop('_codePart', false); // PICK _codePart
      this.emitOp({ op: 'opcode', code: 'OP_SIZE' }); // [scriptCode, _codePart, SIZE(_codePart)]
      this.stackMap.push(null);
      this.emitOp({ op: 'nip' }); // [scriptCode, SIZE(_codePart)]  — drop _codePart copy, keep size
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null);
      // Push codeSepIndex — the emitter fills in the actual value
      this.emitOp({ op: 'push_codesep_index' });
      this.stackMap.push(null);
      this.emitOp({ op: 'opcode', code: 'OP_SUB' }); // skip = SIZE(_codePart) - codeSepIdx
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null);
      // Stack: [..., scriptCode, skip]

      // 4b. Split scriptCode at skip to get state
      this.emitOp({ op: 'opcode', code: 'OP_SPLIT' }); // [prefix, state]
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null); // prefix (postSepCode + 0x6a)
      this.stackMap.push(null); // state
      this.emitOp({ op: 'nip' }); // drop prefix, keep state
      this.stackMap.pop(); this.stackMap.pop();
      this.stackMap.push(null); // state bytes on top

      // 5. Parse state fields left-to-right
      // Fixed-size: push(SIZE) OP_SPLIT OP_SWAP [OP_BIN2NUM] OP_SWAP
      // ByteString: push-data decode (variable-length prefix)
      if (stateProps.length === 1) {
        const prop = stateProps[0]!;
        if (prop.type === 'ByteString') {
          // Single ByteString field: decode push-data prefix, drop trailing empty
          this.emitPushDataDecode(); // [..., data, remaining]
          this.emitOp({ op: 'drop' }); // drop remaining (should be empty for single field)
          this.stackMap.pop();
        } else if (prop.type === 'bigint' || prop.type === 'boolean' || prop.type === 'RabinSig' || prop.type === 'RabinPubKey') {
          this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
        }
        // Other byte types need no conversion
        this.stackMap.pop();
        this.stackMap.push(prop.name);
      } else {
        // Multiple properties — parse left-to-right
        for (let i = 0; i < stateProps.length; i++) {
          const prop = stateProps[i]!;

          if (i < stateProps.length - 1) {
            if (prop.type === 'ByteString') {
              // ByteString: decode push-data prefix, extract data
              // Stack: [..., remaining_state]
              this.emitPushDataDecode(); // [..., data, rest]
              // data is the property value, rest continues
              // Name the property (at depth 1)
              this.stackMap.pop(); this.stackMap.pop();
              this.stackMap.push(prop.name);
              this.stackMap.push(null); // rest on top
            } else {
              // Fixed-size field: split at known size
              const size = propSizes[i]!;
              this.emitOp({ op: 'push', value: BigInt(size) });
              this.stackMap.push(null);
              this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
              this.stackMap.pop(); this.stackMap.pop();
              this.stackMap.push(null); this.stackMap.push(null);
              // Swap to bring property bytes on top
              this.emitOp({ op: 'swap' });
              this.stackMap.swap();
              if (prop.type === 'bigint' || prop.type === 'boolean' || prop.type === 'RabinSig' || prop.type === 'RabinPubKey') {
                this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
              }
              // Swap back so rest is on top for next iteration
              this.emitOp({ op: 'swap' });
              this.stackMap.swap();
              this.stackMap.pop(); this.stackMap.pop();
              this.stackMap.push(prop.name);
              this.stackMap.push(null);
            }
          } else {
            // Last property — remaining bytes are this property
            if (prop.type === 'ByteString') {
              // Last ByteString: decode push-data prefix, drop trailing empty
              this.emitPushDataDecode(); // [..., data, remaining]
              this.emitOp({ op: 'drop' }); // drop remaining (should be empty)
              this.stackMap.pop();
            } else if (prop.type === 'bigint' || prop.type === 'boolean' || prop.type === 'RabinSig' || prop.type === 'RabinPubKey') {
              this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
            }
            this.stackMap.pop();
            this.stackMap.push(prop.name);
          }
        }
      }
    }

    this.trackDepth();
  }

  /**
   * Split fixed-size state fields from the state bytes already on top of stack.
   * Used by lowerDeserializeState for the all-fixed-size case.
   */
  private splitFixedStateFields(stateProps: ANFProperty[], propSizes: number[]): void {
    if (stateProps.length === 1) {
      const prop = stateProps[0]!;
      if (prop.type === 'bigint' || prop.type === 'boolean' || prop.type === 'RabinSig' || prop.type === 'RabinPubKey') {
        this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
      }
      this.stackMap.pop();
      this.stackMap.push(prop.name);
    } else {
      for (let i = 0; i < stateProps.length; i++) {
        const prop = stateProps[i]!;
        const size = propSizes[i]!;

        if (i < stateProps.length - 1) {
          this.emitOp({ op: 'push', value: BigInt(size) });
          this.stackMap.push(null);
          this.emitOp({ op: 'opcode', code: 'OP_SPLIT' });
          this.stackMap.pop();
          this.stackMap.pop();
          this.stackMap.push(null);
          this.stackMap.push(null);
          this.emitOp({ op: 'swap' });
          this.stackMap.swap();
          if (prop.type === 'bigint' || prop.type === 'boolean' || prop.type === 'RabinSig' || prop.type === 'RabinPubKey') {
            this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
          }
          this.emitOp({ op: 'swap' });
          this.stackMap.swap();
          this.stackMap.pop();
          this.stackMap.pop();
          this.stackMap.push(prop.name);
          this.stackMap.push(null);
        } else {
          if (prop.type === 'bigint' || prop.type === 'boolean' || prop.type === 'RabinSig' || prop.type === 'RabinPubKey') {
            this.emitOp({ op: 'opcode', code: 'OP_BIN2NUM' });
          }
          this.stackMap.pop();
          this.stackMap.push(prop.name);
        }
      }
    }
  }

  private lowerCheckPreimage(
    bindingName: string,
    preimage: string,
    sighashFlag: number | undefined,
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // OP_PUSH_TX: verify the pushed BIP-143 sighash preimage is bound to the
    // current spending transaction. See https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX
    //
    // The signature is DERIVED FROM THE PREIMAGE ON CHAIN (Optimal OP_PUSH_TX):
    //   z    = hash256(preimage)
    //   s    = (z + r)·k⁻¹ mod n      (fixed nonce k, privkey d=1 ⇒ pubkey = G)
    // OP_CHECKSIG(sig, G) then passes iff hash256(preimage) equals the node's
    // real tx sighash — i.e. iff the pushed preimage IS the spending tx's
    // preimage. This closes BUG-100: a spender can no longer present a preimage
    // decoupled from the transaction they actually broadcast. The unlocking
    // script therefore pushes ONLY <preimage> (no witness signature).
    //
    // See emitCheckPreimageBinding (oppushtx-codegen.ts) for the construction,
    // validated end-to-end against the BSV Script interpreter.

    // Emit OP_CODESEPARATOR so the scriptCode in the BIP-143 preimage is only
    // the code after this point (smaller preimage; required for large scripts).
    this.emitOp({ op: 'opcode', code: 'OP_CODESEPARATOR' });

    // Bring the preimage to the top (kept for field extractors below).
    const isLast = this.isLastUse(preimage, bindingIndex, lastUses);
    this.bringToTop(preimage, isLast);

    // Derive + verify the signature on-chain (single opaque raw_bytes blob).
    // For the default ALL|FORKID (sighashFlag undefined) the blob is
    // byte-identical to the pinned cross-tier constant; issue #123 lets a
    // method declare a different mode, which only changes the appended sighash
    // flag byte (TS-reference tier only until the 6-tier port lands). Net stack
    // effect is zero: the preimage is consumed internally as a copy and left on
    // top; OP_CHECKSIGVERIFY aborts the script unless the binding holds.
    emitCheckPreimageBindingRaw((op) => this.emitOp(op), sighashFlag);

    // The preimage remains on top. Rename to the binding name so field
    // extractors can reference it.
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

    const aConsume = this.operandConsume(a, args, bindingIndex, lastUses);
    this.bringToTop(a, aConsume);

    const bConsume = this.operandConsume(b, args, bindingIndex, lastUses);
    this.bringToTop(b, bConsume);

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

    const valConsume = this.operandConsume(val, args, bindingIndex, lastUses);
    this.bringToTop(val, valConsume);

    const loConsume = this.operandConsume(lo, args, bindingIndex, lastUses);
    this.bringToTop(lo, loConsume);

    // Stack: ... val lo → OP_MAX → max(val, lo)
    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_MAX' });
    this.stackMap.push(null); // intermediate

    const hiConsume = this.operandConsume(hi, args, bindingIndex, lastUses);
    this.bringToTop(hi, hiConsume);

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

    const baseConsume = this.operandConsume(base, args, bindingIndex, lastUses);
    this.bringToTop(base, baseConsume);

    const expConsume = this.operandConsume(exp, args, bindingIndex, lastUses);
    this.bringToTop(exp, expConsume);

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

    const aConsume = this.operandConsume(a, args, bindingIndex, lastUses);
    this.bringToTop(a, aConsume);
    const bConsume = this.operandConsume(b, args, bindingIndex, lastUses);
    this.bringToTop(b, bConsume);

    this.stackMap.pop();
    this.stackMap.pop();
    this.emitOp({ op: 'opcode', code: 'OP_MUL' });
    this.stackMap.push(null);

    const cConsume = this.operandConsume(c, args, bindingIndex, lastUses);
    this.bringToTop(c, cConsume);

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

    const amountConsume = this.operandConsume(amount, args, bindingIndex, lastUses);
    this.bringToTop(amount, amountConsume);
    const bpsConsume = this.operandConsume(bps, args, bindingIndex, lastUses);
    this.bringToTop(bps, bpsConsume);

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

    const aConsume = this.operandConsume(a, args, bindingIndex, lastUses);
    this.bringToTop(a, aConsume);
    const bConsume = this.operandConsume(b, args, bindingIndex, lastUses);
    this.bringToTop(b, bConsume);

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

    const aConsume = this.operandConsume(a, args, bindingIndex, lastUses);
    this.bringToTop(a, aConsume);
    const bConsume = this.operandConsume(b, args, bindingIndex, lastUses);
    this.bringToTop(b, bConsume);

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
    const dataConsume = this.operandConsume(data, args, bindingIndex, lastUses);
    this.bringToTop(data, dataConsume);

    // Push len onto the stack
    const lenConsume = this.operandConsume(len, args, bindingIndex, lastUses);
    this.bringToTop(len, lenConsume);

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
   * The 10-opcode emission delegates to rabin-codegen.ts.
   *
   * Stack before (bottom→top): msg sig padding pubKey
   * Stack after: <boolean>
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
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }

    // Pop all 4 args from stack map
    for (let i = 0; i < 4; i++) this.stackMap.pop();

    emitVerifyRabinSig((op) => this.emitOp(op));

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // WOTS+ verification — delegates to wots-codegen.ts
  // =========================================================================

  private lowerVerifyWOTS(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 3) {
      throw new Error('verifyWOTS requires 3 arguments: msg, sig, pubkey');
    }
    for (const arg of args) {
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    for (let i = 0; i < 3; i++) this.stackMap.pop();

    emitVerifyWOTS((op) => this.emitOp(op));

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
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
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
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
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
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
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
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
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
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
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
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    for (let i = 0; i < args.length; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);
    const ecOpts = this.ecCodegenOptions();

    switch (func) {
      case 'ecAdd':              emitEcAdd(emitFn, ecOpts); break;
      case 'ecMul':              emitEcMul(emitFn, ecOpts); break;
      case 'ecMulGen':           emitEcMulGen(emitFn, ecOpts); break;
      case 'ecNegate':           emitEcNegate(emitFn, ecOpts); break;
      case 'ecOnCurve':          emitEcOnCurve(emitFn, ecOpts); break;
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

  // =========================================================================
  // P-256 and P-384 EC builtins — delegates to p256-p384-codegen.ts
  // =========================================================================

  private lowerNistEcBuiltin(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Bring all args to stack top
    for (const arg of args) {
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    for (let i = 0; i < args.length; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);
    const ecOpts = this.ecCodegenOptions();

    switch (func) {
      case 'p256Add':              emitP256Add(emitFn, ecOpts); break;
      case 'p256Mul':              emitP256Mul(emitFn, ecOpts); break;
      case 'p256MulGen':           emitP256MulGen(emitFn, ecOpts); break;
      case 'p256Negate':           emitP256Negate(emitFn, ecOpts); break;
      case 'p256OnCurve':          emitP256OnCurve(emitFn, ecOpts); break;
      case 'p256EncodeCompressed': emitP256EncodeCompressed(emitFn); break;
      case 'p384Add':              emitP384Add(emitFn, ecOpts); break;
      case 'p384Mul':              emitP384Mul(emitFn, ecOpts); break;
      case 'p384MulGen':           emitP384MulGen(emitFn, ecOpts); break;
      case 'p384Negate':           emitP384Negate(emitFn, ecOpts); break;
      case 'p384OnCurve':          emitP384OnCurve(emitFn, ecOpts); break;
      case 'p384EncodeCompressed': emitP384EncodeCompressed(emitFn); break;
      default: throw new Error(`Unknown NIST EC builtin: ${func}`);
    }

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  private lowerVerifyECDSA(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    if (args.length < 3) throw new Error(`${func} requires 3 arguments: msg, sig, pubkey`);
    const [msg, sig, pubkey] = args as [string, string, string];
    this.bringToTop(msg, this.operandConsume(msg, args, bindingIndex, lastUses));
    this.bringToTop(sig, this.operandConsume(sig, args, bindingIndex, lastUses));
    this.bringToTop(pubkey, this.operandConsume(pubkey, args, bindingIndex, lastUses));
    this.stackMap.pop(); // pubkey
    this.stackMap.pop(); // sig
    this.stackMap.pop(); // msg
    const emitFn = (op: StackOp) => this.emitOp(op);
    const ecOpts = this.ecCodegenOptions();
    if (func === 'verifyECDSA_P256') emitVerifyECDSA_P256(emitFn, ecOpts);
    else emitVerifyECDSA_P384(emitFn, ecOpts);
    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // BN254 field + G1 — delegates to bn254-codegen.ts
  // =========================================================================

  private lowerBN254Builtin(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Bring all args to stack top
    for (const arg of args) {
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    for (let i = 0; i < args.length; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);

    switch (func) {
      case 'bn254FieldAdd':    emitBn254FieldAdd(emitFn); break;
      case 'bn254FieldSub':    emitBn254FieldSub(emitFn); break;
      case 'bn254FieldMul':    emitBn254FieldMul(emitFn); break;
      case 'bn254FieldInv':    emitBn254FieldInv(emitFn); break;
      case 'bn254FieldNeg':    emitBn254FieldNeg(emitFn); break;
      case 'bn254G1Add':       emitBn254G1Add(emitFn); break;
      case 'bn254G1ScalarMul': emitBn254G1ScalarMul(emitFn); break;
      case 'bn254G1Negate':    emitBn254G1Negate(emitFn); break;
      case 'bn254G1OnCurve':   emitBn254G1OnCurve(emitFn); break;
      default: throw new Error(`Unknown BN254 builtin: ${func}`);
    }

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // Baby Bear field arithmetic — delegates to babybear-codegen.ts
  // =========================================================================

  private lowerBBFieldBuiltin(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Bring all args to stack top
    for (const arg of args) {
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    for (let i = 0; i < args.length; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);

    switch (func) {
      case 'bbFieldAdd': emitBBFieldAdd(emitFn); break;
      case 'bbFieldSub': emitBBFieldSub(emitFn); break;
      case 'bbFieldMul': emitBBFieldMul(emitFn); break;
      case 'bbFieldInv': emitBBFieldInv(emitFn); break;
      case 'bbExt4Mul0': emitBBExt4Mul0(emitFn); break;
      case 'bbExt4Mul1': emitBBExt4Mul1(emitFn); break;
      case 'bbExt4Mul2': emitBBExt4Mul2(emitFn); break;
      case 'bbExt4Mul3': emitBBExt4Mul3(emitFn); break;
      case 'bbExt4Inv0': emitBBExt4Inv0(emitFn); break;
      case 'bbExt4Inv1': emitBBExt4Inv1(emitFn); break;
      case 'bbExt4Inv2': emitBBExt4Inv2(emitFn); break;
      case 'bbExt4Inv3': emitBBExt4Inv3(emitFn); break;
      default: throw new Error(`Unknown Baby Bear builtin: ${func}`);
    }

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // KoalaBear field arithmetic — delegates to koalabear-codegen.ts
  // =========================================================================

  private lowerKBFieldBuiltin(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // Bring all args to stack top
    for (const arg of args) {
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    for (let i = 0; i < args.length; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);

    switch (func) {
      case 'kbFieldAdd': emitKBFieldAdd(emitFn); break;
      case 'kbFieldSub': emitKBFieldSub(emitFn); break;
      case 'kbFieldMul': emitKBFieldMul(emitFn); break;
      case 'kbFieldInv': emitKBFieldInv(emitFn); break;
      case 'kbExt4Mul0': emitKBExt4Mul0(emitFn); break;
      case 'kbExt4Mul1': emitKBExt4Mul1(emitFn); break;
      case 'kbExt4Mul2': emitKBExt4Mul2(emitFn); break;
      case 'kbExt4Mul3': emitKBExt4Mul3(emitFn); break;
      case 'kbExt4Inv0': emitKBExt4Inv0(emitFn); break;
      case 'kbExt4Inv1': emitKBExt4Inv1(emitFn); break;
      case 'kbExt4Inv2': emitKBExt4Inv2(emitFn); break;
      case 'kbExt4Inv3': emitKBExt4Inv3(emitFn); break;
      default: throw new Error(`Unknown KoalaBear builtin: ${func}`);
    }

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // KoalaBear Poseidon2 builtins — delegates to poseidon2-koalabear-codegen.ts
  // =========================================================================

  private lowerKBPoseidon2Builtin(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // poseidon2KBPermute(s0, s1, ..., s15): 16 args → 16-element result
    // poseidon2KBCompress(s0, s1, ..., s15): 16 args → 8-element result
    // For our stack lowering purposes the codegen functions handle the
    // internal stack manipulation; we just bring all args to top then call.
    const expectedArgs = 16;
    if (args.length !== expectedArgs) {
      throw new Error(`${func} requires exactly ${expectedArgs} arguments, got ${args.length}`);
    }

    for (const arg of args) {
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    for (let i = 0; i < args.length; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);

    switch (func) {
      case 'poseidon2KBPermute': emitPoseidon2KBPermute(emitFn); break;
      case 'poseidon2KBCompress': emitPoseidon2KBCompress(emitFn); break;
      default: throw new Error(`Unknown KoalaBear Poseidon2 builtin: ${func}`);
    }

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // Poseidon2 Merkle proof verification — delegates to poseidon2-merkle-codegen.ts
  // =========================================================================

  private lowerPoseidon2MerkleRoot(
    bindingName: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // poseidon2MerkleRoot(leaf0..7, proof, index, depth)
    // args: [leaf0..leaf7 (8 elems), proof (8*depth elems), index, depth]
    // For simplicity we model this as: args = [leaf, proof, index, depth]
    // where leaf is a conceptual name for all 8 leaf elements.
    // The actual calling convention expects exactly 4 args at the ANF level.
    if (args.length !== 4) {
      throw new Error(`poseidon2MerkleRoot requires exactly 4 arguments (leaf, proof, index, depth)`);
    }

    // Extract depth constant from ANF binding
    const depthArg = args[3]!;
    const depthValue = this.getConstantValue(depthArg);
    if (depthValue === null || typeof depthValue !== 'bigint') {
      throw new Error(
        `poseidon2MerkleRoot: depth (4th argument) must be a compile-time constant integer literal. ` +
        `Got a runtime value for '${depthArg}'.`,
      );
    }
    const depth = Number(depthValue);
    if (depth < 1 || depth > 32) {
      throw new Error(`poseidon2MerkleRoot: depth must be between 1 and 32, got ${depth}`);
    }

    // Remove depth value from the real stack FIRST (consumed at compile time).
    if (this.stackMap.has(depthArg)) {
      this.bringToTop(depthArg, true);
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
    }

    // Bring leaf, proof, index to stack top
    for (let i = 0; i < 3; i++) {
      const arg = args[i]!;
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    for (let i = 0; i < 3; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);
    emitPoseidon2MerkleRoot(emitFn, depth);

    this.stackMap.push(bindingName);
    this.trackDepth();
  }

  // =========================================================================
  // Merkle proof verification — delegates to merkle-codegen.ts
  // =========================================================================

  private lowerMerkleRoot(
    bindingName: string,
    func: string,
    args: string[],
    bindingIndex: number,
    lastUses: Map<string, number>,
  ): void {
    // args: [leaf, proof, index, depth]
    // depth must be a compile-time constant
    if (args.length !== 4) {
      throw new Error(`${func} requires exactly 4 arguments (leaf, proof, index, depth)`);
    }

    // Extract depth constant from ANF binding
    const depthArg = args[3]!;
    const depthValue = this.getConstantValue(depthArg);
    if (depthValue === null || typeof depthValue !== 'bigint') {
      throw new Error(
        `${func}: depth (4th argument) must be a compile-time constant integer literal. ` +
        `Got a runtime value for '${depthArg}'.`,
      );
    }
    const depth = Number(depthValue);
    if (depth < 1 || depth > 64) {
      throw new Error(`${func}: depth must be between 1 and 64, got ${depth}`);
    }

    // Remove depth value from the real stack FIRST (it's consumed at compile time).
    // Must happen before bringing the 3 runtime args to top, otherwise the stackMap
    // and real stack get out of sync.
    if (this.stackMap.has(depthArg)) {
      this.bringToTop(depthArg, true);
      this.emitOp({ op: 'drop' });
      this.stackMap.pop();
    }

    // Now bring leaf, proof, index to stack top for the codegen
    for (let i = 0; i < 3; i++) {
      const arg = args[i]!;
      this.bringToTop(arg, this.operandConsume(arg, args, bindingIndex, lastUses));
    }
    // Pop the 3 args — the codegen consumes them and produces 1 result
    for (let i = 0; i < 3; i++) this.stackMap.pop();

    const emitFn = (op: StackOp) => this.emitOp(op);

    if (func === 'merkleRootSha256') {
      emitMerkleRootSha256(emitFn, depth);
    } else {
      emitMerkleRootHash256(emitFn, depth);
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
    const dataConsume = this.operandConsume(data, args, bindingIndex, lastUses);
    this.bringToTop(data, dataConsume);

    // Push start offset
    const startConsume = this.operandConsume(start, args, bindingIndex, lastUses);
    this.bringToTop(start, startConsume);

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
    const lenConsume = this.operandConsume(length, args, bindingIndex, lastUses);
    this.bringToTop(length, lenConsume);

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
    const objConsume = this.operandConsume(obj, args, bindingIndex, lastUses);
    this.bringToTop(obj, objConsume);

    // Push the index onto the stack
    const indexConsume = this.operandConsume(index, args, bindingIndex, lastUses);
    this.bringToTop(index, indexConsume);

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
export function lowerToStack(program: ANFProgram, opts: LoweringOptions = {}): StackProgram {
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
    const stackMethod = lowerMethod(method, program.properties, privateMethods, opts);
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
function methodUsesCheckPreimage(
  bindings: ANFBinding[],
  privateMethods?: Map<string, ANFMethod>,
  seen: Set<string> = new Set(),
): boolean {
  for (const b of bindings) {
    if (b.value.kind === 'check_preimage') return true;
    if (b.value.kind === 'if') {
      if (methodUsesCheckPreimage(b.value.then, privateMethods, seen)) return true;
      if (methodUsesCheckPreimage(b.value.else, privateMethods, seen)) return true;
    }
    if (b.value.kind === 'loop') {
      if (methodUsesCheckPreimage(b.value.body, privateMethods, seen)) return true;
    }
    if (b.value.kind === 'method_call' && privateMethods) {
      const target = privateMethods.get(b.value.method);
      if (target && !seen.has(target.name)) {
        const nextSeen = new Set(seen);
        nextSeen.add(target.name);
        if (methodUsesCheckPreimage(target.body, privateMethods, nextSeen)) return true;
      }
    }
  }
  return false;
}

/**
 * Whether a method READS a mutable variable-length (ByteString) state field's
 * value (via load_prop). Issue #100: such a terminal method needs `_codePart`
 * for the preimage-relative state offset. Narrowed to the live var-length read
 * so methods that only read readonly fields (baked into the locking script) or
 * fixed-size fields keep their original terminal codegen.
 *
 * C18: the read may happen entirely inside a private helper reached via
 * `method_call` (private methods are inlined by `inlineMethodCall`, so the
 * load_prop executes in the caller's stack context at runtime). Recurse
 * through private method bodies exactly like `methodUsesCheckPreimage` does,
 * with the same cycle guard, or a public method whose only var-len state read
 * is behind a helper silently skips `_codePart` and falls back to the
 * deploy-time constant instead of the live on-chain state.
 */
function methodReadsVarLenState(
  bindings: ANFBinding[],
  varLenProps: Set<string>,
  privateMethods?: Map<string, ANFMethod>,
  seen: Set<string> = new Set(),
): boolean {
  for (const b of bindings) {
    if (b.value.kind === 'load_prop' && varLenProps.has(b.value.name)) return true;
    if (b.value.kind === 'if') {
      if (methodReadsVarLenState(b.value.then, varLenProps, privateMethods, seen) ||
          methodReadsVarLenState(b.value.else, varLenProps, privateMethods, seen)) return true;
    }
    if (b.value.kind === 'loop' && methodReadsVarLenState(b.value.body, varLenProps, privateMethods, seen)) return true;
    if (b.value.kind === 'method_call' && privateMethods) {
      const target = privateMethods.get(b.value.method);
      if (target && !seen.has(target.name)) {
        const nextSeen = new Set(seen);
        nextSeen.add(target.name);
        if (methodReadsVarLenState(target.body, varLenProps, privateMethods, nextSeen)) return true;
      }
    }
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

/**
 * Lower one method, and — under `schedulerMode: 'liveness'` — pick the
 * cheaper of the two schedules by emitted bytes.
 *
 * The per-site spill heuristic in `maybeSpill` is greedy and approximate: it
 * cannot know whether removing one slot actually moves an access across a
 * cost boundary, because `OP_DUP`/`OP_SWAP`/`OP_OVER`/`OP_ROT` all cost one
 * byte, so burying a value is free until the access reaches depth 3. Rather
 * than model the whole stack evolution ahead of time, lower both ways and let
 * the exact cost model decide. That makes "the scheduler never grows a method"
 * a structural property rather than a hope.
 *
 * Sizes are compared AFTER the peephole pass, since that is what the emitter
 * finally sees — spilling changes which peephole rules fire (an `OP_OVER
 * OP_OVER` that fused into `OP_2DUP` may become a plain `OP_DUP`).
 */
function lowerMethod(
  method: ANFMethod,
  properties: ANFProperty[],
  privateMethods: Map<string, ANFMethod>,
  opts: LoweringOptions = {},
): StackMethod {
  if (opts.schedulerMode === 'liveness') {
    const scheduled = lowerMethodOnce(method, properties, privateMethods, opts);
    const baseline = lowerMethodOnce(method, properties, privateMethods,
      { ...opts, schedulerMode: 'current' });
    const size = (m: StackMethod): number => estimateScriptBytes(optimizeStackIR(m.ops));
    return size(scheduled) < size(baseline) ? scheduled : baseline;
  }
  return lowerMethodOnce(method, properties, privateMethods, opts);
}

function lowerMethodOnce(
  method: ANFMethod,
  properties: ANFProperty[],
  privateMethods: Map<string, ANFMethod>,
  opts: LoweringOptions = {},
): StackMethod {
  const paramNames = method.params.map(p => p.name);

  // If the method uses checkPreimage, the unlocking script pushes implicit
  // params before all declared parameters (OP_PUSH_TX pattern).
  // _codePart: full code script (locking script minus state) as ByteString.
  // (BUG-100 fix: the OP_PUSH_TX signature is now derived on-chain from the
  // preimage — see lowerCheckPreimage — so NO _opPushTxSig witness item is
  // pushed. The unlocking script provides only the preimage.)
  // _codePart is needed for continuation builders (add_output/add_raw_output)
  // OR when the method reads variable-length (ByteString) mutable state — the
  // deserialization needs it for the preimage-relative offset (issue #100).
  const varLenProps = new Set(
    properties.filter(p => !p.readonly && p.type === 'ByteString').map(p => p.name),
  );
  const usesCodePart =
    methodUsesCheckPreimage(method.body, privateMethods) &&
    (methodUsesCodePart(method.body) || methodReadsVarLenState(method.body, varLenProps, privateMethods));
  if (methodUsesCheckPreimage(method.body, privateMethods) && usesCodePart) {
    paramNames.unshift('_codePart');
  }

  const ctx = new LoweringContext(paramNames, properties, privateMethods, opts);
  // Pass terminalAssert=true for public methods so the last assert leaves
  // its value on the stack (Bitcoin Script requires a truthy top-of-stack).
  ctx.lowerBindings(method.body, method.isPublic);

  // Clean up excess stack items below the top-of-stack boolean.
  //
  // Bitcoin Script's CLEANSTACK rule requires exactly one item on the stack
  // at end-of-script. Excess items can come from `deserialize_state` (stateful
  // methods reading mutable fields), from readonly-field-binding patterns in
  // the method body (force-embedding readonly fields by referencing them),
  // or from any other mid-method binding whose value isn't consumed by an
  // assert. The previous gate of `hasDeserializeState` missed the readonly-
  // only path, causing all-readonly terminal methods to emit a script that
  // failed CLEANSTACK on mainnet — "Script did not clean its stack".
  //
  // `cleanupExcessStack()` is idempotent (no-op when `stackMap.depth === 1`),
  // so running it unconditionally for public methods is safe — it adds
  // appropriate `OP_NIP` opcodes only when the stack genuinely needs cleanup.
  if (method.isPublic) {
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
    usesCodePart,
  };
}
