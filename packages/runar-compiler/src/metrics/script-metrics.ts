/**
 * Script-size instrumentation.
 *
 * Two views of the same question — "where did the bytes go?":
 *
 *  - `analyzeScriptHex` walks a SERIALIZED script and buckets every byte by
 *    what it is spent on. This is the view that matters for a size project,
 *    because opcode counts hide the thing that actually dominates: a 33-byte
 *    constant push and an `OP_DUP` are one opcode each and 34x apart in cost.
 *  - `stackOpMetrics` reports the same shape from Stack IR, before emission,
 *    so a pass can measure its own output without a round-trip through hex.
 *
 * The one classification rule worth stating out loud: a push immediately
 * consumed by `OP_PICK` / `OP_ROLL` is charged to `stack-shuffle`, not to
 * `const-push`. `bringToTop` emits `push(depth)` + `OP_PICK` as a pair (see
 * `05-stack-lower.ts`), and blaming those depth bytes on constants would
 * credit the wrong optimizer with fixing them.
 *
 * Nothing here changes compilation output; it only reads it.
 */

import type { StackOp } from '../ir/index.js';
import { OPCODES } from '../passes/06-emit.js';
import { estimateScriptBytes } from './cost-model.js';

// ---------------------------------------------------------------------------
// Byte categories
// ---------------------------------------------------------------------------

export type ByteCategory =
  | 'const-push'
  | 'small-int-push'
  | 'stack-shuffle'
  | 'arithmetic'
  | 'bytes'
  | 'crypto'
  | 'control'
  | 'other';

const CATEGORIES: ByteCategory[] = [
  'const-push', 'small-int-push', 'stack-shuffle',
  'arithmetic', 'bytes', 'crypto', 'control', 'other',
];

/** Reverse map byte -> preferred mnemonic, skipping the OP_FALSE/OP_TRUE aliases. */
const OPCODE_NAMES: Map<number, string> = new Map();
for (const [name, byte] of Object.entries(OPCODES)) {
  if (name === 'OP_FALSE' || name === 'OP_TRUE') continue;
  if (!OPCODE_NAMES.has(byte)) OPCODE_NAMES.set(byte, name);
}

const SHUFFLE_OPS = new Set<string>([
  'OP_DUP', 'OP_DROP', 'OP_NIP', 'OP_OVER', 'OP_PICK', 'OP_ROLL', 'OP_ROT',
  'OP_SWAP', 'OP_TUCK', 'OP_2DROP', 'OP_2DUP', 'OP_3DUP', 'OP_2OVER',
  'OP_2ROT', 'OP_2SWAP', 'OP_IFDUP', 'OP_DEPTH',
  'OP_TOALTSTACK', 'OP_FROMALTSTACK',
]);

const ARITHMETIC_OPS = new Set<string>([
  'OP_ADD', 'OP_SUB', 'OP_MUL', 'OP_DIV', 'OP_MOD', 'OP_1ADD', 'OP_1SUB',
  'OP_2MUL', 'OP_2DIV', 'OP_NEGATE', 'OP_ABS', 'OP_NOT', 'OP_0NOTEQUAL',
  'OP_BOOLAND', 'OP_BOOLOR', 'OP_NUMEQUAL', 'OP_NUMEQUALVERIFY',
  'OP_NUMNOTEQUAL', 'OP_LESSTHAN', 'OP_GREATERTHAN', 'OP_LESSTHANOREQUAL',
  'OP_GREATERTHANOREQUAL', 'OP_MIN', 'OP_MAX', 'OP_WITHIN',
  'OP_AND', 'OP_OR', 'OP_XOR', 'OP_INVERT', 'OP_LSHIFT', 'OP_RSHIFT',
  'OP_LSHIFTNUM', 'OP_RSHIFTNUM',
]);

const BYTES_OPS = new Set<string>([
  'OP_CAT', 'OP_SPLIT', 'OP_SIZE', 'OP_NUM2BIN', 'OP_BIN2NUM',
  'OP_SUBSTR', 'OP_LEFT', 'OP_RIGHT', 'OP_EQUAL', 'OP_EQUALVERIFY',
]);

const CRYPTO_OPS = new Set<string>([
  'OP_RIPEMD160', 'OP_SHA1', 'OP_SHA256', 'OP_HASH160', 'OP_HASH256',
  'OP_CHECKSIG', 'OP_CHECKSIGVERIFY', 'OP_CHECKMULTISIG',
  'OP_CHECKMULTISIGVERIFY', 'OP_CODESEPARATOR',
]);

const CONTROL_OPS = new Set<string>([
  'OP_IF', 'OP_NOTIF', 'OP_ELSE', 'OP_ENDIF', 'OP_VERIFY', 'OP_RETURN',
  'OP_NOP', 'OP_CHECKLOCKTIMEVERIFY', 'OP_CHECKSEQUENCEVERIFY',
]);

function categoryOfOpcode(name: string): ByteCategory {
  if (SHUFFLE_OPS.has(name)) return 'stack-shuffle';
  if (ARITHMETIC_OPS.has(name)) return 'arithmetic';
  if (BYTES_OPS.has(name)) return 'bytes';
  if (CRYPTO_OPS.has(name)) return 'crypto';
  if (CONTROL_OPS.has(name)) return 'control';
  return 'other';
}

// ---------------------------------------------------------------------------
// Serialized-script analysis
// ---------------------------------------------------------------------------

export interface ConstantUse {
  /** Hex of the pushed data (without the length prefix). */
  hex: string;
  /** How many times this exact payload is pushed. */
  count: number;
  /** Total serialized bytes spent pushing it (payload + prefix, times count). */
  bytes: number;
}

export interface ScriptMetrics {
  scriptBytes: number;
  /** Opcodes plus pushes, each counted once. */
  opcodeCount: number;
  pushCount: number;
  categories: Record<ByteCategory, number>;
  /** Mnemonic -> occurrence count. Data pushes are keyed as `PUSH`. */
  opcodes: Record<string, number>;
  /** Repeated data payloads, largest total byte cost first. */
  constants: ConstantUse[];
}

/**
 * Bucket every byte of a serialized script.
 *
 * Throws on a malformed / truncated push instead of silently dropping the
 * tail — a size report that quietly loses bytes is worse than no report.
 */
export function analyzeScriptHex(scriptHex: string): ScriptMetrics {
  const hex = scriptHex.trim();
  if (hex.length % 2 !== 0) {
    throw new Error(`analyzeScriptHex: odd-length hex (${hex.length} chars)`);
  }
  const bytes = Buffer.from(hex, 'hex');
  const n = bytes.length;

  const categories = Object.fromEntries(CATEGORIES.map(c => [c, 0])) as Record<ByteCategory, number>;
  const opcodes: Record<string, number> = {};
  const constants = new Map<string, { count: number; bytes: number }>();

  let opcodeCount = 0;
  let pushCount = 0;

  /** Bytes + category of the immediately preceding op, for the PICK/ROLL rule. */
  let prevPush: { size: number; category: ByteCategory; dataHex: string | null } | null = null;

  const bump = (name: string) => { opcodes[name] = (opcodes[name] ?? 0) + 1; };

  let i = 0;
  while (i < n) {
    const op = bytes[i]!;

    // --- direct pushes -----------------------------------------------------
    if (op >= 0x01 && op <= 0x4b) {
      const len = op;
      if (i + 1 + len > n) {
        throw new Error(`analyzeScriptHex: truncated push at offset ${i} (want ${len} bytes, ${n - i - 1} left)`);
      }
      const dataHex = bytes.subarray(i + 1, i + 1 + len).toString('hex');
      const size = 1 + len;
      categories['const-push'] += size;
      bump('PUSH');
      pushCount++; opcodeCount++;
      prevPush = { size, category: 'const-push', dataHex };
      i += size;
      continue;
    }

    if (op === 0x4c || op === 0x4d || op === 0x4e) {
      const hdr = op === 0x4c ? 2 : op === 0x4d ? 3 : 5;
      if (i + hdr > n) {
        throw new Error(`analyzeScriptHex: truncated PUSHDATA header at offset ${i}`);
      }
      const len = op === 0x4c
        ? bytes[i + 1]!
        : op === 0x4d
          ? bytes.readUInt16LE(i + 1)
          : bytes.readUInt32LE(i + 1);
      if (i + hdr + len > n) {
        throw new Error(`analyzeScriptHex: truncated PUSHDATA body at offset ${i} (want ${len} bytes)`);
      }
      const dataHex = bytes.subarray(i + hdr, i + hdr + len).toString('hex');
      const size = hdr + len;
      categories['const-push'] += size;
      bump('PUSH');
      pushCount++; opcodeCount++;
      prevPush = { size, category: 'const-push', dataHex };
      i += size;
      continue;
    }

    // --- single-byte constant pushes --------------------------------------
    if (op === 0x00 || op === 0x4f || (op >= 0x51 && op <= 0x60)) {
      categories['small-int-push'] += 1;
      bump(OPCODE_NAMES.get(op) ?? `OP_UNKNOWN_${op.toString(16)}`);
      pushCount++; opcodeCount++;
      prevPush = { size: 1, category: 'small-int-push', dataHex: null };
      i += 1;
      continue;
    }

    // --- opcodes -----------------------------------------------------------
    const name = OPCODE_NAMES.get(op) ?? `OP_UNKNOWN_${op.toString(16).padStart(2, '0')}`;
    const category = categoryOfOpcode(name);
    categories[category] += 1;
    bump(name);
    opcodeCount++;

    // A depth push consumed by PICK/ROLL is stack-access cost, not a constant.
    if ((name === 'OP_PICK' || name === 'OP_ROLL') && prevPush) {
      categories[prevPush.category] -= prevPush.size;
      categories['stack-shuffle'] += prevPush.size;
      if (prevPush.dataHex !== null) {
        // It was recorded as a data push; un-record it from the constants tally.
        const existing = constants.get(prevPush.dataHex);
        if (existing) {
          existing.count -= 1;
          existing.bytes -= prevPush.size;
          if (existing.count === 0) constants.delete(prevPush.dataHex);
        }
      }
    } else if (prevPush && prevPush.dataHex !== null) {
      // Only now is the previous data push confirmed to be a real constant.
      const entry = constants.get(prevPush.dataHex) ?? { count: 0, bytes: 0 };
      entry.count += 1;
      entry.bytes += prevPush.size;
      constants.set(prevPush.dataHex, entry);
    }

    prevPush = null;
    i += 1;
  }

  // A data push in final position was never confirmed by the loop above.
  if (prevPush && prevPush.dataHex !== null) {
    const entry = constants.get(prevPush.dataHex) ?? { count: 0, bytes: 0 };
    entry.count += 1;
    entry.bytes += prevPush.size;
    constants.set(prevPush.dataHex, entry);
  }

  const constantList: ConstantUse[] = [...constants.entries()]
    .map(([h, v]) => ({ hex: h, count: v.count, bytes: v.bytes }))
    .sort((a, b) => b.bytes - a.bytes);

  return {
    scriptBytes: n,
    opcodeCount,
    pushCount,
    categories,
    opcodes,
    constants: constantList,
  };
}

// ---------------------------------------------------------------------------
// Stack IR analysis
// ---------------------------------------------------------------------------

export interface StackOpMetrics {
  scriptBytes: number;
  /** Every op, recursing into `if` arms. An `if` counts as one plus its arms. */
  opCount: number;
  /** Ops that only move data around (dup/drop/pick/roll/swap/…). */
  shuffleOps: number;
  /** Mnemonic -> count. Structural ops are keyed by the opcode they emit. */
  opcodes: Record<string, number>;
  maxStackDepth?: number;
}

const STACK_OP_MNEMONIC: Partial<Record<StackOp['op'], string>> = {
  dup: 'OP_DUP', swap: 'OP_SWAP', roll: 'OP_ROLL', pick: 'OP_PICK',
  drop: 'OP_DROP', nip: 'OP_NIP', over: 'OP_OVER', rot: 'OP_ROT',
  tuck: 'OP_TUCK', if: 'OP_IF', push: 'PUSH',
  placeholder: 'PLACEHOLDER', push_codesep_index: 'CODESEP_INDEX',
  raw_bytes: 'RAW_BYTES',
};

/** Metrics for a Stack IR op sequence, before emission. */
export function stackOpMetrics(ops: StackOp[], maxStackDepth?: number): StackOpMetrics {
  const opcodes: Record<string, number> = {};
  let opCount = 0;
  let shuffleOps = 0;

  const walk = (list: StackOp[]): void => {
    for (const op of list) {
      opCount++;
      const name = op.op === 'opcode' ? op.code : STACK_OP_MNEMONIC[op.op]!;
      opcodes[name] = (opcodes[name] ?? 0) + 1;
      if (SHUFFLE_OPS.has(name)) shuffleOps++;
      if (op.op === 'if') {
        walk(op.then);
        if (op.else) walk(op.else);
      }
    }
  };
  walk(ops);

  return {
    scriptBytes: estimateScriptBytes(ops),
    opCount,
    shuffleOps,
    opcodes,
    maxStackDepth,
  };
}
