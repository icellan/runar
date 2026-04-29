/**
 * Pass 7 helper: StackOp-to-SX bridge.
 *
 * Converts StackOp arrays (produced by specialized codegen modules like
 * ec-codegen, sha256-codegen, slh-dsa-codegen) into BitcoinSX text.
 * Used as a Phase 1 fallback for codegen that bypasses ANF.
 */

import type { StackOp } from '../ir/index.js';

// ---------------------------------------------------------------------------
// OP_ → SX camelCase name mapping
// ---------------------------------------------------------------------------

const OP_TO_SX: Record<string, string> = {
  // Stack
  'OP_DUP': 'dup',
  'OP_DROP': 'drop',
  'OP_SWAP': 'swap',
  'OP_PICK': 'pick',
  'OP_ROLL': 'roll',
  'OP_NIP': 'nip',
  'OP_OVER': 'over',
  'OP_ROT': 'rot',
  'OP_TUCK': 'tuck',
  'OP_2DROP': '2drop',
  'OP_2DUP': '2dup',
  'OP_3DUP': '3dup',
  'OP_2OVER': '2over',
  'OP_2ROT': '2rot',
  'OP_2SWAP': '2swap',
  'OP_IFDUP': 'ifDup',
  'OP_DEPTH': 'depth',
  'OP_TOALTSTACK': 'toAltStack',
  'OP_FROMALTSTACK': 'fromAltStack',

  // Arithmetic
  'OP_ADD': 'add',
  'OP_SUB': 'sub',
  'OP_MUL': 'mul',
  'OP_DIV': 'div',
  'OP_MOD': 'mod',
  'OP_NEGATE': 'negate',
  'OP_ABS': 'abs',
  'OP_NOT': 'not',
  'OP_0NOTEQUAL': '0notEqual',
  'OP_1ADD': '1add',
  'OP_1SUB': '1sub',
  'OP_NUMEQUAL': 'numEqual',
  'OP_NUMEQUALVERIFY': 'numEqualVerify',
  'OP_NUMNOTEQUAL': 'numNotEqual',
  'OP_LESSTHAN': 'lessThan',
  'OP_GREATERTHAN': 'greaterThan',
  'OP_LESSTHANOREQUAL': 'lessThanOrEqual',
  'OP_GREATERTHANOREQUAL': 'greaterThanOrEqual',
  'OP_MIN': 'min',
  'OP_MAX': 'max',
  'OP_WITHIN': 'within',
  'OP_BOOLAND': 'boolAnd',
  'OP_BOOLOR': 'boolOr',

  // Bitwise / String
  'OP_AND': 'and',
  'OP_OR': 'or',
  'OP_XOR': 'xor',
  'OP_INVERT': 'invert',
  'OP_LSHIFT': 'lshift',
  'OP_RSHIFT': 'rshift',
  'OP_EQUAL': 'equal',
  'OP_EQUALVERIFY': 'equalVerify',
  'OP_CAT': 'cat',
  'OP_SPLIT': 'split',
  'OP_NUM2BIN': 'num2bin',
  'OP_BIN2NUM': 'bin2num',
  'OP_SIZE': 'size',

  // Crypto
  'OP_SHA256': 'sha256',
  'OP_SHA1': 'sha1',
  'OP_RIPEMD160': 'ripemd160',
  'OP_HASH160': 'hash160',
  'OP_HASH256': 'hash256',
  'OP_CHECKSIG': 'checkSig',
  'OP_CHECKSIGVERIFY': 'checkSigVerify',
  'OP_CHECKMULTISIG': 'checkMultiSig',
  'OP_CHECKMULTISIGVERIFY': 'checkMultiSigVerify',
  'OP_CODESEPARATOR': 'codeSeparator',

  // Control
  'OP_IF': 'if',
  'OP_NOTIF': 'notIf',
  'OP_ELSE': 'else',
  'OP_ENDIF': 'endIf',
  'OP_VERIFY': 'verify',
  'OP_RETURN': 'return',
  'OP_NOP': 'nop',

  // Constants
  'OP_0': 'false',
  'OP_FALSE': 'false',
  'OP_1': 'true',
  'OP_TRUE': 'true',
  'OP_1NEGATE': '-1n',
};

/**
 * Convert an OP_X name to its SX camelCase equivalent.
 * Falls back to the raw name if unmapped (e.g., OP_2..OP_16 are handled separately).
 */
export function opcodeToSXName(opCode: string): string {
  const mapped = OP_TO_SX[opCode];
  if (mapped !== undefined) return mapped;

  // OP_2 through OP_16 → literal bigint
  const numMatch = opCode.match(/^OP_(\d+)$/);
  if (numMatch) {
    return `${numMatch[1]}n`;
  }

  // Unknown — emit as-is (shouldn't happen for valid scripts)
  return opCode;
}

// ---------------------------------------------------------------------------
// Push value formatting
// ---------------------------------------------------------------------------

function formatPushValue(value: Uint8Array | bigint | boolean): string {
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'bigint') {
    return `${value}n`;
  }

  // Uint8Array → hex literal
  if (value.length === 0) {
    return 'false'; // OP_0 = empty push
  }
  let hex = '';
  for (const b of value) {
    hex += b.toString(16).padStart(2, '0');
  }
  return `0x${hex}`;
}

// ---------------------------------------------------------------------------
// StackOp → SX text
// ---------------------------------------------------------------------------

/**
 * Convert a single StackOp to SX text token(s).
 */
export function stackOpToSX(op: StackOp, indent: string = ''): string {
  switch (op.op) {
    case 'push':
      return `${indent}${formatPushValue(op.value)}`;

    case 'dup':
      return `${indent}dup`;

    case 'swap':
      return `${indent}swap`;

    case 'roll':
      // ROLL needs depth on stack first: push depth, then roll
      return `${indent}${op.depth}n roll`;

    case 'pick':
      return `${indent}${op.depth}n pick`;

    case 'drop':
      return `${indent}drop`;

    case 'nip':
      return `${indent}nip`;

    case 'over':
      return `${indent}over`;

    case 'rot':
      return `${indent}rot`;

    case 'tuck':
      return `${indent}tuck`;

    case 'opcode':
      return `${indent}${opcodeToSXName(op.code)}`;

    case 'if': {
      const lines: string[] = [];
      lines.push(`${indent}if`);
      for (const thenOp of op.then) {
        lines.push(stackOpToSX(thenOp, indent + '  '));
      }
      if (op.else && op.else.length > 0) {
        lines.push(`${indent}else`);
        for (const elseOp of op.else) {
          lines.push(stackOpToSX(elseOp, indent + '  '));
        }
      }
      lines.push(`${indent}endIf`);
      return lines.join('\n');
    }

    case 'placeholder':
      return `${indent}.${op.paramName}`;

    case 'push_codesep_index':
      return `${indent}.codeSepIndex`;
  }
}

/**
 * Convert an array of StackOps to a multi-line SX text block.
 */
export function stackOpsToSX(ops: StackOp[], indent: string = ''): string {
  return ops.map(op => stackOpToSX(op, indent)).join('\n');
}
