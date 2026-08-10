/**
 * Symbolic stack VM — analysis only (no codegen, no byte output).
 *
 * Walks an op slice maintaining a stack of provenance-tracked `SymValue`s, so a
 * recognizer can read *what* a region computes (varint decode, byte slicing,
 * amount comparison) without lifting it to executable Rúnar. Behavior-
 * preserving: the bytes stay as asm islands; the symbolic trace is the
 * recovered meaning.
 *
 * Control flow: balanced `IF/ELSE/ENDIF` is executed by symbolically running
 * both branches and merging differing stack slots into `select` (phi) values.
 * Unbalanced branches (then/else leave different depths) can't be merged
 * statically, so execution stops cleanly with `modeled: false`. Never throws.
 */

import { bytesToHex } from 'runar-testing';
import type { Op } from './types.js';

export type SymValue =
  | { t: 'input'; id: string }
  | { t: 'const'; hex: string }
  | { t: 'split'; side: 'lo' | 'hi'; src: SymValue; at: SymValue }
  | { t: 'cat'; a: SymValue; b: SymValue }
  | { t: 'bin2num'; v: SymValue }
  | { t: 'num2bin'; v: SymValue; size: SymValue }
  | { t: 'size'; v: SymValue }
  | { t: 'binop'; op: string; a: SymValue; b: SymValue }
  | { t: 'unop'; op: string; v: SymValue }
  | { t: 'select'; cond: SymValue; whenTrue: SymValue; whenFalse: SymValue }
  | { t: 'reverse'; v: SymValue; range?: [number, number] }
  | { t: 'unknown'; note: string };

export interface SymState {
  stack: SymValue[];
  /** True iff every opcode in the slice was modeled. */
  modeled: boolean;
  /** Number of opcodes consumed before stopping. */
  steps: number;
}

export interface SymExecOptions {
  /** Input ids placed on the stack bottom→top before execution. */
  initialStack?: string[];
  /**
   * When provided, records the value each `OP_IF`/`OP_NOTIF` tests, keyed by the
   * absolute op index of that IF. A single whole-program `symExec` thus yields
   * the threaded condition for every branch — nested ones traced through the
   * phi-merges back to the seeded inputs.
   */
  record?: Map<number, SymValue>;
  /**
   * When provided, records the value left on top of the stack after each op
   * (keyed by absolute op index), so a caller can read what each asm island
   * produces. Like `record`, populated by one whole-program pass.
   */
  recordTop?: Map<number, SymValue>;
  /** Cap on provenance-tree node count (collapse larger to `unknown`). Off by
   * default; the whole-program pass sets it low to stay bounded over loops. */
  maxNodes?: number;
}

const UNKNOWN = (note: string): SymValue => ({ t: 'unknown', note });

// A whole-program symbolic pass merges branches into `select` (phi) nodes and
// chains `cat`/`split`, which can grow provenance trees exponentially over loops.
// Cap the node count (memoized) and collapse anything larger to `unknown` so the
// pass stays bounded — an over-large condition reads as `?` rather than OOMing.
// The cap is per-call (`opts.maxNodes`): the whole-program pass sets it low;
// control-flow-free local runs leave it off (they can't explode).
let nodeCap = Infinity;
const sizeCache = new WeakMap<object, number>();

function sizeOf(v: SymValue): number {
  const cached = sizeCache.get(v);
  if (cached !== undefined) return cached;
  let n = 1;
  switch (v.t) {
    case 'split': n += sizeOf(v.src) + sizeOf(v.at); break;
    case 'cat': n += sizeOf(v.a) + sizeOf(v.b); break;
    case 'bin2num': case 'size': n += sizeOf(v.v); break;
    case 'num2bin': n += sizeOf(v.v) + sizeOf(v.size); break;
    case 'binop': n += sizeOf(v.a) + sizeOf(v.b); break;
    case 'unop': n += sizeOf(v.v); break;
    case 'select': n += sizeOf(v.cond) + sizeOf(v.whenTrue) + sizeOf(v.whenFalse); break;
    case 'reverse': n += sizeOf(v.v); break;
  }
  sizeCache.set(v, n);
  return n;
}

/** Known byte length of a value, or null if unknown. Hash outputs are fixed. */
function lenOf(v: SymValue): number | null {
  switch (v.t) {
    case 'const': return v.hex.length / 2;
    case 'unop':
      if (v.op === 'OP_HASH256' || v.op === 'OP_SHA256') return 32;
      if (v.op === 'OP_HASH160' || v.op === 'OP_RIPEMD160' || v.op === 'OP_SHA1') return 20;
      return null;
    case 'num2bin': return v.size.t === 'const' ? numFromConstHex(v.size.hex) : null;
    case 'reverse': return lenOf(v.v);
    case 'cat': {
      const a = lenOf(v.a), b = lenOf(v.b);
      return a === null || b === null ? null : a + b;
    }
    case 'split': {
      if (v.at.t !== 'const') return null;
      const at = numFromConstHex(v.at.hex);
      if (v.side === 'lo') return at;
      const s = lenOf(v.src);
      return s === null ? null : s - at;
    }
    default: return null;
  }
}

/** Interpret a (possibly nested) split as a byte sub-range of a base value. */
function sliceOf(v: SymValue): { base: SymValue; offset: number; len: number | null } {
  if (v.t === 'split' && v.at.t === 'const') {
    const at = numFromConstHex(v.at.hex);
    const inner = sliceOf(v.src);
    if (v.side === 'lo') return { base: inner.base, offset: inner.offset, len: at };
    return {
      base: inner.base,
      offset: inner.offset + at,
      len: inner.len === null ? null : inner.len - at,
    };
  }
  return { base: v, offset: 0, len: lenOf(v) };
}

function flattenCat(v: SymValue, out: SymValue[]): void {
  if (v.t === 'cat') {
    flattenCat(v.a, out);
    flattenCat(v.b, out);
  } else {
    out.push(v);
  }
}

/**
 * Recognize the sCrypt byte-reversal idiom: a `cat` chain whose leaves are the
 * single bytes of one base value at strictly descending consecutive offsets is
 * `reverse(base[lo:hi])` (used to read a big-endian hash as a little-endian
 * number). Returns the collapsed value, or null if the chain isn't a reversal.
 */
function tryReverse(leaves: SymValue[]): SymValue | null {
  if (leaves.length < 2) return null;
  const slices = leaves.map(sliceOf);
  const base = slices[0]!.base;
  const first = slices[0]!.offset;
  for (let i = 0; i < slices.length; i++) {
    const s = slices[i]!;
    if (s.len !== 1) return null;
    if (!structEq(s.base, base)) return null;
    if (s.offset !== first - i) return null; // descending, consecutive
  }
  const lo = first - (leaves.length - 1);
  const hi = first + 1;
  const whole = lenOf(base);
  const range: [number, number] | undefined = lo === 0 && whole === hi ? undefined : [lo, hi];
  return { t: 'reverse', v: base, range };
}

/** Collapse byte-reversal cat-chains to `reverse(...)`, recursing into children. */
export function simplify(v: SymValue): SymValue {
  switch (v.t) {
    case 'cat': {
      const leaves: SymValue[] = [];
      flattenCat(v, leaves);
      const rev = tryReverse(leaves);
      if (rev) return rev;
      return { t: 'cat', a: simplify(v.a), b: simplify(v.b) };
    }
    case 'split': return { t: 'split', side: v.side, src: simplify(v.src), at: v.at };
    case 'bin2num': return { t: 'bin2num', v: simplify(v.v) };
    case 'num2bin': return { t: 'num2bin', v: simplify(v.v), size: v.size };
    case 'size': return { t: 'size', v: simplify(v.v) };
    case 'unop': return { t: 'unop', op: v.op, v: simplify(v.v) };
    case 'binop': return { t: 'binop', op: v.op, a: simplify(v.a), b: simplify(v.b) };
    case 'select':
      return { t: 'select', cond: simplify(v.cond), whenTrue: simplify(v.whenTrue), whenFalse: simplify(v.whenFalse) };
    default: return v;
  }
}

/** Collapse an over-large provenance tree so the symbolic pass stays bounded. */
function cap(v: SymValue): SymValue {
  return nodeCap !== Infinity && sizeOf(v) > nodeCap ? { t: 'unknown', note: 'elided' } : v;
}

function toHexByte(n: number): string {
  return n.toString(16).padStart(2, '0');
}

/** Decode a minimal little-endian script number (small, non-negative indices). */
function numFromConstHex(hex: string): number {
  if (hex === '') return 0;
  const bytes = hex.match(/../g)!.map((h) => parseInt(h, 16));
  let n = 0;
  for (let i = 0; i < bytes.length; i++) {
    n += (bytes[i]! & (i === bytes.length - 1 ? 0x7f : 0xff)) * 256 ** i;
  }
  return n;
}

/** Encode a small non-negative number as a minimal little-endian script const. */
function numToConstHex(n: number): string {
  if (n <= 0) return '';
  const bytes: number[] = [];
  let x = n;
  while (x > 0) {
    bytes.push(x & 0xff);
    x = Math.floor(x / 256);
  }
  if (bytes[bytes.length - 1]! & 0x80) bytes.push(0x00); // keep positive sign
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}


function constOfOp(op: Op): SymValue | null {
  if (op.name === 'OP_0') return { t: 'const', hex: '' };
  if (op.byte >= 0x51 && op.byte <= 0x60) return { t: 'const', hex: toHexByte(op.byte - 0x50) };
  if (op.data) return { t: 'const', hex: bytesToHex(op.data) };
  return null;
}

function structEq(a: SymValue, b: SymValue): boolean {
  return describeSym(a) === describeSym(b);
}

/** Find the matching ELSE (if any) and ENDIF for the OP_IF/OP_NOTIF at `ifIdx`. */
function findBranch(
  ops: Op[],
  ifIdx: number,
  end: number,
): { elseIdx: number; endIdx: number } | null {
  let depth = 0;
  let elseIdx = -1;
  for (let j = ifIdx + 1; j < end; j++) {
    const n = ops[j]!.name;
    if (n === 'OP_IF' || n === 'OP_NOTIF') depth++;
    else if (n === 'OP_ENDIF') {
      if (depth === 0) return { elseIdx, endIdx: j };
      depth--;
    } else if (n === 'OP_ELSE' && depth === 0) {
      elseIdx = j;
    }
  }
  return null;
}

/** Merge two equal-length branch stacks: differing slots become `select`. */
function mergeStacks(cond: SymValue, whenTrue: SymValue[], whenFalse: SymValue[]): SymValue[] {
  const out: SymValue[] = [];
  for (let i = 0; i < whenTrue.length; i++) {
    const a = whenTrue[i]!;
    const b = whenFalse[i]!;
    out.push(structEq(a, b) ? a : cap({ t: 'select', cond, whenTrue: a, whenFalse: b }));
  }
  return out;
}

/** A concrete value only if it is small enough to fold safely in a JS number
 * (≤4 bytes) — enough for stack indices, but never large field constants like N. */
function smallConst(v: SymValue): number | null {
  if (v.t !== 'const' || v.hex.length > 8) return null;
  return numFromConstHex(v.hex);
}

/** Fold an arithmetic op when both operands are small concretes (so depth-relative
 * `OP_DEPTH OP_1SUB OP_ROLL` indices resolve); else build a symbolic binop. */
function arith(opName: string, a: SymValue, b: SymValue): SymValue {
  const x = smallConst(a);
  const y = smallConst(b);
  if (x !== null && y !== null) {
    let r: number | null = null;
    switch (opName) {
      case 'OP_ADD': r = x + y; break;
      case 'OP_SUB': r = x - y; break;
      case 'OP_MUL': r = x * y; break;
      case 'OP_DIV': r = y !== 0 ? Math.trunc(x / y) : null; break;
      case 'OP_MOD': r = y !== 0 ? x % y : null; break;
      case 'OP_MIN': r = Math.min(x, y); break;
      case 'OP_MAX': r = Math.max(x, y); break;
    }
    if (r !== null && r >= 0) return { t: 'const', hex: numToConstHex(r) };
  }
  return cap({ t: 'binop', op: opName, a, b });
}

/**
 * Apply one non-control-flow opcode, mutating `stack` (and `alt` for the alt
 * stack). Returns false if the op cannot be modeled. Hash / signature / verify
 * ops are modeled as opaque stack effects (not real crypto) so the simulator
 * can run end-to-end and trace the operands a later `OP_IF` tests.
 */
function stepOp(op: Op, stack: SymValue[], alt: SymValue[]): boolean {
  const c = constOfOp(op);
  if (c) {
    stack.push(c);
    return true;
  }
  const pop = (): SymValue => stack.pop() ?? UNKNOWN('underflow');
  switch (op.name) {
    case 'OP_DUP': { const a = pop(); stack.push(a, a); return true; }
    case 'OP_OVER': { stack.push(stack[stack.length - 2] ?? UNKNOWN('over-underflow')); return true; }
    case 'OP_2OVER': {
      const a = stack[stack.length - 4], b = stack[stack.length - 3];
      stack.push(a ?? UNKNOWN('2over'), b ?? UNKNOWN('2over')); return true;
    }
    case 'OP_SWAP': { const b = pop(), a = pop(); stack.push(b, a); return true; }
    case 'OP_2SWAP': {
      const d = pop(), c4 = pop(), b = pop(), a = pop(); stack.push(c4, d, a, b); return true;
    }
    case 'OP_DROP': { pop(); return true; }
    case 'OP_NIP': { const b = pop(); pop(); stack.push(b); return true; }
    case 'OP_TUCK': { const b = pop(), a = pop(); stack.push(b, a, b); return true; }
    case 'OP_ROT': { const c3 = pop(), b = pop(), a = pop(); stack.push(b, c3, a); return true; }
    case 'OP_2ROT': {
      const f = pop(), e = pop(), d = pop(), c4 = pop(), b = pop(), a = pop();
      stack.push(c4, d, e, f, a, b); return true;
    }
    case 'OP_2DUP': { const b = pop(), a = pop(); stack.push(a, b, a, b); return true; }
    case 'OP_3DUP': { const c3 = pop(), b = pop(), a = pop(); stack.push(a, b, c3, a, b, c3); return true; }
    case 'OP_2DROP': { pop(); pop(); return true; }
    case 'OP_DEPTH': { stack.push({ t: 'const', hex: numToConstHex(stack.length) }); return true; }
    case 'OP_TOALTSTACK': { alt.push(pop()); return true; }
    case 'OP_FROMALTSTACK': { stack.push(alt.pop() ?? UNKNOWN('alt-underflow')); return true; }
    case 'OP_SPLIT': {
      const at = pop(), src = pop();
      stack.push(cap({ t: 'split', side: 'lo', src, at }), cap({ t: 'split', side: 'hi', src, at }));
      return true;
    }
    case 'OP_CAT': { const b = pop(), a = pop(); stack.push(cap({ t: 'cat', a, b })); return true; }
    case 'OP_SIZE': { stack.push(cap({ t: 'size', v: stack[stack.length - 1] ?? UNKNOWN('size-underflow') })); return true; }
    case 'OP_BIN2NUM': { const v = pop(); stack.push(cap({ t: 'bin2num', v })); return true; }
    case 'OP_NUM2BIN': { const size = pop(), v = pop(); stack.push(cap({ t: 'num2bin', v, size })); return true; }
    case 'OP_1ADD': { const v = pop(); stack.push(arith('OP_ADD', v, { t: 'const', hex: '01' })); return true; }
    case 'OP_1SUB': { const v = pop(); stack.push(arith('OP_SUB', v, { t: 'const', hex: '01' })); return true; }
    case 'OP_NEGATE': { const v = pop(); stack.push(cap({ t: 'unop', op: 'OP_NEGATE', v })); return true; }
    case 'OP_ABS': { const v = pop(); stack.push(cap({ t: 'unop', op: 'OP_ABS', v })); return true; }
    case 'OP_NOT': { const v = pop(); stack.push(cap({ t: 'unop', op: 'OP_NOT', v })); return true; }
    case 'OP_0NOTEQUAL': { const v = pop(); stack.push(cap({ t: 'unop', op: 'OP_0NOTEQUAL', v })); return true; }
    case 'OP_INVERT': { const v = pop(); stack.push(cap({ t: 'unop', op: 'OP_INVERT', v })); return true; }
    // Hash ops — opaque unary (not real hashing; structure only).
    case 'OP_HASH160': case 'OP_HASH256': case 'OP_SHA256': case 'OP_SHA1': case 'OP_RIPEMD160': {
      const v = pop(); stack.push(cap({ t: 'unop', op: op.name, v })); return true;
    }
    case 'OP_ADD': case 'OP_SUB': case 'OP_MUL': case 'OP_DIV': case 'OP_MOD':
    case 'OP_MIN': case 'OP_MAX': {
      const b = pop(), a = pop(); stack.push(arith(op.name, a, b)); return true;
    }
    case 'OP_GREATERTHAN': case 'OP_LESSTHAN':
    case 'OP_GREATERTHANOREQUAL': case 'OP_LESSTHANOREQUAL':
    case 'OP_EQUAL': case 'OP_NUMEQUAL': case 'OP_NUMNOTEQUAL':
    case 'OP_BOOLAND': case 'OP_BOOLOR':
    case 'OP_AND': case 'OP_OR': case 'OP_XOR':
    case 'OP_LSHIFT': case 'OP_RSHIFT': {
      const b = pop(), a = pop();
      stack.push(cap({ t: 'binop', op: op.name, a, b }));
      return true;
    }
    case 'OP_WITHIN': {
      const max = pop(), min = pop(), x = pop();
      stack.push(cap({ t: 'binop', op: 'OP_WITHIN', a: x, b: cap({ t: 'binop', op: 'range', a: min, b: max }) }));
      return true;
    }
    // Signature / verify ops — opaque stack effects so execution continues.
    case 'OP_CHECKSIG': { const pk = pop(), sig = pop(); stack.push(cap({ t: 'binop', op: 'OP_CHECKSIG', a: sig, b: pk })); return true; }
    case 'OP_CHECKSIGVERIFY': { pop(); pop(); return true; }
    case 'OP_EQUALVERIFY': case 'OP_NUMEQUALVERIFY': { pop(); pop(); return true; }
    case 'OP_VERIFY': { pop(); return true; }
    case 'OP_NOP': return true;
    case 'OP_PICK': case 'OP_ROLL': {
      const n = pop();
      if (n.t !== 'const') return false;
      const idx = numFromConstHex(n.hex);
      const pos = stack.length - 1 - idx;
      if (idx < 0 || pos < 0) return false;
      const v = stack[pos]!;
      if (op.name === 'OP_PICK') stack.push(v);
      else { stack.splice(pos, 1); stack.push(v); }
      return true;
    }
    default:
      return false;
  }
}

interface RangeResult { stack: SymValue[]; modeled: boolean; steps: number }

function execRange(
  ops: Op[],
  start: number,
  end: number,
  stack: SymValue[],
  alt: SymValue[],
  record?: Map<number, SymValue>,
  recordTop?: Map<number, SymValue>,
): RangeResult {
  let steps = 0;
  let i = start;
  while (i < end) {
    const op = ops[i]!;
    if (op.name === 'OP_IF' || op.name === 'OP_NOTIF') {
      const br = findBranch(ops, i, end);
      if (!br) return { stack, modeled: false, steps };
      const cond = stack.pop() ?? UNKNOWN('underflow');
      record?.set(i, cond); // threaded condition for this IF (absolute op index)
      const thenEnd = br.elseIdx >= 0 ? br.elseIdx : br.endIdx;
      const thenAlt = alt.slice();
      const thenRes = execRange(ops, i + 1, thenEnd, stack.slice(), thenAlt, record, recordTop);
      const elseAlt = alt.slice();
      const elseRes =
        br.elseIdx >= 0
          ? execRange(ops, br.elseIdx + 1, br.endIdx, stack.slice(), elseAlt, record, recordTop)
          : { stack: stack.slice(), modeled: true, steps: 0 };
      if (!thenRes.modeled || !elseRes.modeled || thenRes.stack.length !== elseRes.stack.length) {
        return { stack, modeled: false, steps };
      }
      // OP_IF runs the THEN range when cond is true; OP_NOTIF runs it when false.
      const tRun = op.name === 'OP_IF' ? thenRes.stack : elseRes.stack;
      const fRun = op.name === 'OP_IF' ? elseRes.stack : thenRes.stack;
      const merged = mergeStacks(cond, tRun, fRun);
      stack.length = 0;
      stack.push(...merged);
      alt.length = 0;
      alt.push(...(op.name === 'OP_IF' ? thenAlt : elseAlt)); // approx: keep taken-branch alt
      if (recordTop && stack.length > 0) recordTop.set(br.endIdx, stack[stack.length - 1]!);
      steps += thenRes.steps + elseRes.steps + 1;
      i = br.endIdx + 1;
      continue;
    }
    if (op.name === 'OP_ELSE' || op.name === 'OP_ENDIF') {
      return { stack, modeled: false, steps };
    }
    if (!stepOp(op, stack, alt)) return { stack, modeled: false, steps };
    if (recordTop && stack.length > 0) recordTop.set(i, stack[stack.length - 1]!);
    steps++;
    i++;
  }
  return { stack, modeled: true, steps };
}

export function symExec(ops: Op[], opts: SymExecOptions = {}): SymState {
  nodeCap = opts.maxNodes ?? Infinity;
  try {
    const stack: SymValue[] = (opts.initialStack ?? []).map((id) => ({ t: 'input', id }) as SymValue);
    const res = execRange(ops, 0, ops.length, stack, [], opts.record, opts.recordTop);
    return { stack: res.stack, modeled: res.modeled, steps: res.steps };
  } finally {
    nodeCap = Infinity;
  }
}

export function describeSym(v: SymValue): string {
  switch (v.t) {
    case 'input': return v.id;
    case 'const': return '0x' + (v.hex || '00');
    case 'split': return `${describeSym(v.src)}[${v.side}@${describeSym(v.at)}]`;
    case 'cat': return `${describeSym(v.a)}||${describeSym(v.b)}`;
    case 'bin2num': return `num(${describeSym(v.v)})`;
    case 'num2bin': return `bin(${describeSym(v.v)}, ${describeSym(v.size)})`;
    case 'size': return `size(${describeSym(v.v)})`;
    case 'binop': return `(${describeSym(v.a)} ${v.op} ${describeSym(v.b)})`;
    case 'unop': return `${v.op}(${describeSym(v.v)})`;
    case 'select': return `(${describeSym(v.cond)} ? ${describeSym(v.whenTrue)} : ${describeSym(v.whenFalse)})`;
    case 'reverse': return v.range ? `reverse(${describeSym(v.v)}[${v.range[0]}..${v.range[1]}])` : `reverse(${describeSym(v.v)})`;
    case 'unknown': return v.note ? `?:${v.note}` : '?';
  }
}
