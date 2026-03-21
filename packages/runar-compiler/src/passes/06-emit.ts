/**
 * Pass 6: Emit — converts Stack IR to Bitcoin Script bytes (hex string).
 *
 * Walks the StackOp list and encodes each operation as one or more Bitcoin
 * Script opcodes, producing both a hex-encoded script and a human-readable
 * ASM representation.
 */

import type {
  StackProgram,
  StackMethod,
  StackOp,
} from '../ir/index.js';
import type { SourceMapping } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Opcode table
// ---------------------------------------------------------------------------

export const OPCODES: Record<string, number> = {
  'OP_0': 0x00,
  'OP_FALSE': 0x00,
  'OP_PUSHDATA1': 0x4c,
  'OP_PUSHDATA2': 0x4d,
  'OP_PUSHDATA4': 0x4e,
  'OP_1NEGATE': 0x4f,
  'OP_1': 0x51,
  'OP_TRUE': 0x51,
  'OP_2': 0x52,
  'OP_3': 0x53,
  'OP_4': 0x54,
  'OP_5': 0x55,
  'OP_6': 0x56,
  'OP_7': 0x57,
  'OP_8': 0x58,
  'OP_9': 0x59,
  'OP_10': 0x5a,
  'OP_11': 0x5b,
  'OP_12': 0x5c,
  'OP_13': 0x5d,
  'OP_14': 0x5e,
  'OP_15': 0x5f,
  'OP_16': 0x60,
  'OP_NOP': 0x61,
  'OP_IF': 0x63,
  'OP_NOTIF': 0x64,
  'OP_ELSE': 0x67,
  'OP_ENDIF': 0x68,
  'OP_VERIFY': 0x69,
  'OP_RETURN': 0x6a,
  'OP_TOALTSTACK': 0x6b,
  'OP_FROMALTSTACK': 0x6c,
  'OP_2DROP': 0x6d,
  'OP_2DUP': 0x6e,
  'OP_3DUP': 0x6f,
  'OP_2OVER': 0x70,
  'OP_2ROT': 0x71,
  'OP_2SWAP': 0x72,
  'OP_IFDUP': 0x73,
  'OP_DEPTH': 0x74,
  'OP_DROP': 0x75,
  'OP_DUP': 0x76,
  'OP_NIP': 0x77,
  'OP_OVER': 0x78,
  'OP_PICK': 0x79,
  'OP_ROLL': 0x7a,
  'OP_ROT': 0x7b,
  'OP_SWAP': 0x7c,
  'OP_TUCK': 0x7d,
  'OP_CAT': 0x7e,
  'OP_SPLIT': 0x7f,
  'OP_NUM2BIN': 0x80,
  'OP_BIN2NUM': 0x81,
  'OP_SIZE': 0x82,
  'OP_AND': 0x84,
  'OP_OR': 0x85,
  'OP_XOR': 0x86,
  'OP_EQUAL': 0x87,
  'OP_EQUALVERIFY': 0x88,
  'OP_1ADD': 0x8b,
  'OP_1SUB': 0x8c,
  'OP_NEGATE': 0x8f,
  'OP_ABS': 0x90,
  'OP_NOT': 0x91,
  'OP_0NOTEQUAL': 0x92,
  'OP_ADD': 0x93,
  'OP_SUB': 0x94,
  'OP_MUL': 0x95,
  'OP_DIV': 0x96,
  'OP_MOD': 0x97,
  'OP_LSHIFT': 0x98,
  'OP_RSHIFT': 0x99,
  'OP_BOOLAND': 0x9a,
  'OP_BOOLOR': 0x9b,
  'OP_NUMEQUAL': 0x9c,
  'OP_NUMEQUALVERIFY': 0x9d,
  'OP_NUMNOTEQUAL': 0x9e,
  'OP_LESSTHAN': 0x9f,
  'OP_GREATERTHAN': 0xa0,
  'OP_LESSTHANOREQUAL': 0xa1,
  'OP_GREATERTHANOREQUAL': 0xa2,
  'OP_MIN': 0xa3,
  'OP_MAX': 0xa4,
  'OP_WITHIN': 0xa5,
  'OP_RIPEMD160': 0xa6,
  'OP_SHA1': 0xa7,
  'OP_SHA256': 0xa8,
  'OP_HASH160': 0xa9,
  'OP_HASH256': 0xaa,
  'OP_CODESEPARATOR': 0xab,
  'OP_CHECKSIG': 0xac,
  'OP_CHECKSIGVERIFY': 0xad,
  'OP_CHECKMULTISIG': 0xae,
  'OP_CHECKMULTISIGVERIFY': 0xaf,
  'OP_INVERT': 0x83,
};

// ---------------------------------------------------------------------------
// Reverse lookup: opcode byte → name (for disassembly / ASM output)
// ---------------------------------------------------------------------------

const OPCODE_NAMES: Map<number, string> = new Map();
// Populate with preferred names (avoid aliases like OP_FALSE/OP_TRUE)
for (const [name, byte] of Object.entries(OPCODES)) {
  // Skip aliases — prefer the numeric name for OP_0/OP_1
  if (name === 'OP_FALSE' || name === 'OP_TRUE') continue;
  if (!OPCODE_NAMES.has(byte)) {
    OPCODE_NAMES.set(byte, name);
  }
}

// ---------------------------------------------------------------------------
// Emit result
// ---------------------------------------------------------------------------

export interface ConstructorSlot {
  paramIndex: number;
  byteOffset: number;
}

export interface EmitResult {
  /** Hex-encoded Bitcoin Script */
  scriptHex: string;
  /** Human-readable ASM representation */
  scriptAsm: string;
  /** Source mappings (opcode index → source location) */
  sourceMap: SourceMapping[];
  /** Byte offsets of constructor parameter placeholders */
  constructorSlots: ConstructorSlot[];
  /** Byte offset of OP_CODESEPARATOR in the script (undefined if not present).
   *  For multi-method contracts, this is the LAST separator's offset. */
  codeSeparatorIndex?: number;
  /** Per-method OP_CODESEPARATOR byte offsets, in method emission order.
   *  Index 0 = first public method, index 1 = second, etc. */
  codeSeparatorIndices?: number[];
}

// ---------------------------------------------------------------------------
// Script number encoding
// ---------------------------------------------------------------------------

/**
 * Encode a bigint as a Bitcoin Script number (little-endian, sign bit in MSB).
 *
 * Bitcoin Script numbers use a sign-magnitude representation:
 * - 0 is encoded as empty byte array
 * - Positive numbers: little-endian bytes, MSB's high bit clear
 * - Negative numbers: little-endian bytes, MSB's high bit set
 * - If the high bit of the most significant byte is already set,
 *   an extra 0x00 (positive) or 0x80 (negative) byte is appended.
 */
function encodeScriptNumber(n: bigint): Uint8Array {
  if (n === 0n) {
    return new Uint8Array(0);
  }

  const negative = n < 0n;
  let abs = negative ? -n : n;

  const bytes: number[] = [];
  while (abs > 0n) {
    bytes.push(Number(abs & 0xffn));
    abs >>= 8n;
  }

  // If the high bit of the last byte is set, we need an extra byte
  // for the sign bit.
  const lastByte = bytes[bytes.length - 1]!;
  if (lastByte & 0x80) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1] = lastByte | 0x80;
  }

  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// Push data encoding
// ---------------------------------------------------------------------------

/**
 * Encode a push-data operation as Bitcoin Script bytes.
 *
 * Rules:
 * - data.length 1-75: single byte length prefix + data
 * - data.length 76-255: OP_PUSHDATA1 (0x4c) + 1-byte length + data
 * - data.length 256-65535: OP_PUSHDATA2 (0x4d) + 2-byte LE length + data
 * - data.length > 65535: OP_PUSHDATA4 (0x4e) + 4-byte LE length + data
 */
function encodePushData(data: Uint8Array): Uint8Array {
  const len = data.length;

  if (len === 0) {
    // Push empty data = OP_0
    return new Uint8Array([0x00]);
  }

  if (len >= 1 && len <= 75) {
    const result = new Uint8Array(1 + len);
    result[0] = len;
    result.set(data, 1);
    return result;
  }

  if (len >= 76 && len <= 255) {
    const result = new Uint8Array(2 + len);
    result[0] = 0x4c; // OP_PUSHDATA1
    result[1] = len;
    result.set(data, 2);
    return result;
  }

  if (len >= 256 && len <= 65535) {
    const result = new Uint8Array(3 + len);
    result[0] = 0x4d; // OP_PUSHDATA2
    result[1] = len & 0xff;
    result[2] = (len >> 8) & 0xff;
    result.set(data, 3);
    return result;
  }

  // OP_PUSHDATA4
  const result = new Uint8Array(5 + len);
  result[0] = 0x4e;
  result[1] = len & 0xff;
  result[2] = (len >> 8) & 0xff;
  result[3] = (len >> 16) & 0xff;
  result[4] = (len >> 24) & 0xff;
  result.set(data, 5);
  return result;
}

/**
 * Encode a push value (bigint, boolean, or Uint8Array) as Bitcoin Script bytes.
 */
function encodePushValue(value: Uint8Array | bigint | boolean): { hex: string; asm: string } {
  if (typeof value === 'boolean') {
    if (value) {
      return { hex: '51', asm: 'OP_TRUE' };
    }
    return { hex: '00', asm: 'OP_FALSE' };
  }

  if (typeof value === 'bigint') {
    return encodePushBigInt(value);
  }

  // Uint8Array — raw data
  if (value.length === 0) {
    return { hex: '00', asm: 'OP_0' };
  }
  // MINIMALDATA: single-byte values 1-16 must use OP_1..OP_16, 0x81 must use OP_1NEGATE.
  // Note: 0x00 is NOT converted to OP_0 because OP_0 pushes empty [] not [0x00].
  if (value.length === 1) {
    const b = value[0]!;
    if (b >= 1 && b <= 16) return { hex: byteToHex(0x50 + b), asm: `OP_${b}` };
    if (b === 0x81) return { hex: '4f', asm: 'OP_1NEGATE' };
  }
  const encoded = encodePushData(value);
  const hex = bytesToHex(encoded);
  return { hex, asm: `<${bytesToHex(value)}>` };
}

/**
 * Encode a bigint push, using small integer opcodes where possible.
 */
function encodePushBigInt(n: bigint): { hex: string; asm: string } {
  // OP_0 for zero
  if (n === 0n) {
    return { hex: '00', asm: 'OP_0' };
  }

  // OP_1NEGATE for -1
  if (n === -1n) {
    return { hex: '4f', asm: 'OP_1NEGATE' };
  }

  // OP_1 through OP_16 for 1-16
  if (n >= 1n && n <= 16n) {
    const opcode = 0x50 + Number(n);
    return { hex: byteToHex(opcode), asm: `OP_${n}` };
  }

  // General case: encode as Script number
  const numBytes = encodeScriptNumber(n);
  const encoded = encodePushData(numBytes);
  return { hex: bytesToHex(encoded), asm: `<${bytesToHex(numBytes)}>` };
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

function byteToHex(b: number): string {
  return b.toString(16).padStart(2, '0');
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) {
    hex += byteToHex(b);
  }
  return hex;
}

// ---------------------------------------------------------------------------
// Emit context — accumulates hex and ASM output
// ---------------------------------------------------------------------------

class EmitContext {
  private hexParts: string[] = [];
  private asmParts: string[] = [];
  private opcodeIndex = 0;
  private byteLength = 0;
  readonly sourceMap: SourceMapping[] = [];
  readonly constructorSlots: ConstructorSlot[] = [];
  /** Byte offset of the last OP_CODESEPARATOR (undefined if none emitted) */
  codeSeparatorIndex?: number;
  /** Per-method OP_CODESEPARATOR byte offsets (in method emission order) */
  readonly codeSeparatorIndices: number[] = [];

  appendHex(hex: string): void {
    this.hexParts.push(hex);
    this.byteLength += hex.length / 2;
  }

  appendAsm(asm: string): void {
    this.asmParts.push(asm);
  }

  nextOpcodeIndex(): number {
    return this.opcodeIndex++;
  }

  private pendingSourceLoc: { file: string; line: number; column: number } | undefined;

  /** Set source location to attach to the next emitted opcode(s). */
  setSourceLoc(loc: { file: string; line: number; column: number } | undefined): void {
    this.pendingSourceLoc = loc;
  }

  private recordSourceMapping(): void {
    if (this.pendingSourceLoc) {
      this.sourceMap.push({
        opcodeIndex: this.opcodeIndex,
        sourceFile: this.pendingSourceLoc.file,
        line: this.pendingSourceLoc.line,
        column: this.pendingSourceLoc.column,
      });
    }
  }

  emitOpcode(name: string): void {
    const byte = OPCODES[name];
    if (byte === undefined) {
      throw new Error(`Unknown opcode: ${name}`);
    }
    if (name === 'OP_CODESEPARATOR') {
      this.codeSeparatorIndex = this.byteLength;
      this.codeSeparatorIndices.push(this.byteLength);
    }
    this.recordSourceMapping();
    this.appendHex(byteToHex(byte));
    this.appendAsm(name);
    this.nextOpcodeIndex();
  }

  emitPush(value: Uint8Array | bigint | boolean): void {
    const { hex, asm } = encodePushValue(value);
    this.recordSourceMapping();
    this.appendHex(hex);
    this.appendAsm(asm);
    this.nextOpcodeIndex();
  }

  emitPlaceholder(paramIndex: number, _paramName: string): void {
    const byteOffset = this.byteLength;
    this.recordSourceMapping();
    this.appendHex('00'); // OP_0 placeholder byte
    this.appendAsm('OP_0');
    this.nextOpcodeIndex();
    this.constructorSlots.push({ paramIndex, byteOffset });
  }

  getHex(): string {
    return this.hexParts.join('');
  }

  getAsm(): string {
    return this.asmParts.join(' ');
  }
}

// ---------------------------------------------------------------------------
// Emit a single StackOp
// ---------------------------------------------------------------------------

function emitStackOp(op: StackOp, ctx: EmitContext): void {
  // Propagate source location from StackOp to the emit context
  const loc = (op as { sourceLoc?: { file: string; line: number; column: number } }).sourceLoc;
  if (loc) {
    ctx.setSourceLoc(loc);
  }

  switch (op.op) {
    case 'push':
      ctx.emitPush(op.value);
      break;

    case 'dup':
      ctx.emitOpcode('OP_DUP');
      break;

    case 'swap':
      ctx.emitOpcode('OP_SWAP');
      break;

    case 'roll':
      ctx.emitOpcode('OP_ROLL');
      break;

    case 'pick':
      ctx.emitOpcode('OP_PICK');
      break;

    case 'drop':
      ctx.emitOpcode('OP_DROP');
      break;

    case 'nip':
      ctx.emitOpcode('OP_NIP');
      break;

    case 'over':
      ctx.emitOpcode('OP_OVER');
      break;

    case 'rot':
      ctx.emitOpcode('OP_ROT');
      break;

    case 'tuck':
      ctx.emitOpcode('OP_TUCK');
      break;

    case 'opcode':
      ctx.emitOpcode(op.code);
      break;

    case 'if':
      emitIf(op.then, op.else, ctx);
      break;

    case 'placeholder':
      ctx.emitPlaceholder(op.paramIndex, op.paramName);
      break;

    case 'push_codesep_index':
      // Push the codeSeparatorIndex as a numeric constant.
      // This value is known at emit time (set when OP_CODESEPARATOR was emitted).
      ctx.emitPush(BigInt(ctx.codeSeparatorIndex ?? 0));
      break;
  }

  // Clear after emitting so the location doesn't leak to the next op
  ctx.setSourceLoc(undefined);
}

/**
 * Emit an if/else/endif structure.
 */
function emitIf(
  thenOps: StackOp[],
  elseOps: StackOp[] | undefined,
  ctx: EmitContext,
): void {
  ctx.emitOpcode('OP_IF');

  for (const op of thenOps) {
    emitStackOp(op, ctx);
  }

  if (elseOps && elseOps.length > 0) {
    ctx.emitOpcode('OP_ELSE');
    for (const op of elseOps) {
      emitStackOp(op, ctx);
    }
  }

  ctx.emitOpcode('OP_ENDIF');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Emit a StackProgram as Bitcoin Script hex and ASM.
 *
 * For contracts with multiple public methods, the emitter generates a
 * method dispatch preamble that checks a function selector (the first
 * argument pushed by the spending transaction) and branches to the
 * corresponding method body.
 */
export function emit(program: StackProgram): EmitResult {
  const ctx = new EmitContext();

  const publicMethods = program.methods.filter(m => m.name !== 'constructor');

  if (publicMethods.length === 0) {
    // Only constructor — emit nothing (no spending paths)
    return {
      scriptHex: '',
      scriptAsm: '',
      sourceMap: [],
      constructorSlots: [],
    };
  }

  if (publicMethods.length === 1) {
    // Single public method — no dispatch needed, emit its ops directly.
    const method = publicMethods[0]!;
    for (const op of method.ops) {
      emitStackOp(op, ctx);
    }
  } else {
    // Multiple public methods — emit a dispatch table.
    // The last scriptSig argument is the method index (0, 1, 2...).
    // We use a chain of OP_IF / OP_ELSE to select the right method.
    emitMethodDispatch(publicMethods, ctx);
  }

  return {
    scriptHex: ctx.getHex(),
    scriptAsm: ctx.getAsm(),
    sourceMap: ctx.sourceMap,
    constructorSlots: ctx.constructorSlots,
    codeSeparatorIndex: ctx.codeSeparatorIndex,
    codeSeparatorIndices: ctx.codeSeparatorIndices.length > 0 ? ctx.codeSeparatorIndices : undefined,
  };
}

/**
 * Emit method dispatch for multiple public methods.
 *
 * The spending transaction pushes the method index as the topmost
 * scriptSig element. We compare against each index and branch.
 *
 * Pattern:
 *   <methodIdx> OP_0 OP_NUMEQUAL OP_IF <method0_ops> OP_ELSE
 *               OP_1 OP_NUMEQUAL OP_IF <method1_ops> OP_ELSE ...
 */
function emitMethodDispatch(methods: StackMethod[], ctx: EmitContext): void {
  for (let i = 0; i < methods.length; i++) {
    const method = methods[i]!;
    const isLast = i === methods.length - 1;

    if (!isLast) {
      // Duplicate the method index for comparison
      ctx.emitOpcode('OP_DUP');
      ctx.emitPush(BigInt(i));
      ctx.emitOpcode('OP_NUMEQUAL');
      ctx.emitOpcode('OP_IF');
      // Drop the method index since we matched
      ctx.emitOpcode('OP_DROP');
    } else {
      // Last method — verify the index matches (fail-closed for invalid selectors)
      ctx.emitPush(BigInt(i));
      ctx.emitOpcode('OP_NUMEQUALVERIFY');
    }

    for (const op of method.ops) {
      emitStackOp(op, ctx);
    }

    if (!isLast) {
      ctx.emitOpcode('OP_ELSE');
    }
  }

  // Close all the nested OP_IF/OP_ELSE blocks
  for (let i = 0; i < methods.length - 1; i++) {
    ctx.emitOpcode('OP_ENDIF');
  }
}

/**
 * Emit a single method's ops and return the result.
 * Useful for testing individual methods.
 */
export function emitMethod(method: StackMethod): EmitResult {
  const ctx = new EmitContext();
  for (const op of method.ops) {
    emitStackOp(op, ctx);
  }
  return {
    scriptHex: ctx.getHex(),
    scriptAsm: ctx.getAsm(),
    sourceMap: ctx.sourceMap,
    constructorSlots: ctx.constructorSlots,
  };
}
