/**
 * BSV (Bitcoin SV) opcode table.
 *
 * This covers the full set of opcodes supported in Bitcoin SV, including
 * opcodes that were disabled in BTC but re-enabled in BSV (OP_CAT, OP_SPLIT,
 * OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT, OP_AND, OP_OR, OP_XOR).
 */

export enum Opcode {
  // -------------------------------------------------------------------------
  // Push value
  // -------------------------------------------------------------------------
  OP_0 = 0x00,
  OP_FALSE = 0x00,
  OP_PUSHDATA1 = 0x4c,
  OP_PUSHDATA2 = 0x4d,
  OP_PUSHDATA4 = 0x4e,
  OP_1NEGATE = 0x4f,

  // OP_1 through OP_16
  OP_1 = 0x51,
  OP_TRUE = 0x51,
  OP_2 = 0x52,
  OP_3 = 0x53,
  OP_4 = 0x54,
  OP_5 = 0x55,
  OP_6 = 0x56,
  OP_7 = 0x57,
  OP_8 = 0x58,
  OP_9 = 0x59,
  OP_10 = 0x5a,
  OP_11 = 0x5b,
  OP_12 = 0x5c,
  OP_13 = 0x5d,
  OP_14 = 0x5e,
  OP_15 = 0x5f,
  OP_16 = 0x60,

  // -------------------------------------------------------------------------
  // Flow control
  // -------------------------------------------------------------------------
  OP_NOP = 0x61,
  OP_IF = 0x63,
  OP_NOTIF = 0x64,
  OP_ELSE = 0x67,
  OP_ENDIF = 0x68,
  OP_VERIFY = 0x69,
  OP_RETURN = 0x6a,

  // -------------------------------------------------------------------------
  // Stack
  // -------------------------------------------------------------------------
  OP_TOALTSTACK = 0x6b,
  OP_FROMALTSTACK = 0x6c,
  OP_2DROP = 0x6d,
  OP_2DUP = 0x6e,
  OP_3DUP = 0x6f,
  OP_2OVER = 0x70,
  OP_2ROT = 0x71,
  OP_2SWAP = 0x72,
  OP_IFDUP = 0x73,
  OP_DEPTH = 0x74,
  OP_DROP = 0x75,
  OP_DUP = 0x76,
  OP_NIP = 0x77,
  OP_OVER = 0x78,
  OP_PICK = 0x79,
  OP_ROLL = 0x7a,
  OP_ROT = 0x7b,
  OP_SWAP = 0x7c,
  OP_TUCK = 0x7d,

  // -------------------------------------------------------------------------
  // String / byte-string operations (BSV re-enabled)
  // -------------------------------------------------------------------------
  OP_CAT = 0x7e,
  OP_SPLIT = 0x7f,
  OP_NUM2BIN = 0x80,
  OP_BIN2NUM = 0x81,
  OP_SIZE = 0x82,

  // -------------------------------------------------------------------------
  // Bitwise logic
  // -------------------------------------------------------------------------
  OP_AND = 0x84,
  OP_OR = 0x85,
  OP_XOR = 0x86,
  OP_EQUAL = 0x87,
  OP_EQUALVERIFY = 0x88,

  // -------------------------------------------------------------------------
  // Arithmetic
  // -------------------------------------------------------------------------
  OP_1ADD = 0x8b,
  OP_1SUB = 0x8c,
  OP_NEGATE = 0x8f,
  OP_ABS = 0x90,
  OP_NOT = 0x91,
  OP_0NOTEQUAL = 0x92,
  OP_ADD = 0x93,
  OP_SUB = 0x94,
  OP_MUL = 0x95,
  OP_DIV = 0x96,
  OP_MOD = 0x97,
  OP_LSHIFT = 0x98,
  OP_RSHIFT = 0x99,
  OP_BOOLAND = 0x9a,
  OP_BOOLOR = 0x9b,
  OP_NUMEQUAL = 0x9c,
  OP_NUMEQUALVERIFY = 0x9d,
  OP_NUMNOTEQUAL = 0x9e,
  OP_LESSTHAN = 0x9f,
  OP_GREATERTHAN = 0xa0,
  OP_LESSTHANOREQUAL = 0xa1,
  OP_GREATERTHANOREQUAL = 0xa2,
  OP_MIN = 0xa3,
  OP_MAX = 0xa4,
  OP_WITHIN = 0xa5,

  // -------------------------------------------------------------------------
  // Crypto
  // -------------------------------------------------------------------------
  OP_RIPEMD160 = 0xa6,
  OP_SHA1 = 0xa7,
  OP_SHA256 = 0xa8,
  OP_HASH160 = 0xa9,
  OP_HASH256 = 0xaa,
  OP_CHECKSIG = 0xac,
  OP_CHECKSIGVERIFY = 0xad,
  OP_CHECKMULTISIG = 0xae,
  OP_CHECKMULTISIGVERIFY = 0xaf,
}

/**
 * Reverse lookup: opcode byte value -> opcode name.
 * Uses the enum's own reverse mapping for numeric enums.
 */
export function opcodeName(byte: number): string {
  // TypeScript numeric enums produce reverse mappings automatically.
  // However because of aliases (OP_0 === OP_FALSE, OP_1 === OP_TRUE)
  // we prefer the canonical name.
  const CANONICAL: Record<number, string> = {
    0x00: 'OP_0',
    0x51: 'OP_1',
  };
  if (byte in CANONICAL) {
    return CANONICAL[byte]!;
  }
  const name = Opcode[byte];
  return name ?? `OP_UNKNOWN(0x${byte.toString(16).padStart(2, '0')})`;
}
