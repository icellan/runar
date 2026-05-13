/**
 * Disassembler: bytes → typed Op[].
 *
 * Walks the Bitcoin Script byte stream and emits one Op per opcode (push
 * opcodes carry their payload in `data`). No interpretation, no fingerprint
 * matching — just a typed token stream.
 *
 * Reuses the BSV opcode table from runar-testing. Push encoding mirrors what
 * the compiler emits at 06-emit.ts:274-326.
 */

import { Opcode, opcodeName } from 'runar-testing';
import type { Op } from './types.js';

export function disassemble(script: Uint8Array): Op[] {
  const ops: Op[] = [];
  let i = 0;
  while (i < script.length) {
    const offset = i;
    const byte = script[i]!;
    i++;

    if (byte === 0x00) {
      ops.push({ name: 'OP_0', byte, offset, size: 1 });
      continue;
    }

    if (byte >= 0x01 && byte <= 0x4b) {
      const dataLen = byte;
      if (i + dataLen > script.length) {
        throw new DisasmError(`truncated direct push at offset ${offset}: need ${dataLen} bytes, have ${script.length - i}`);
      }
      const data = script.slice(i, i + dataLen);
      i += dataLen;
      ops.push({
        name: `OP_PUSHBYTES_${dataLen}`,
        byte,
        data,
        offset,
        size: 1 + dataLen,
      });
      continue;
    }

    if (byte === Opcode.OP_PUSHDATA1) {
      if (i + 1 > script.length) throw new DisasmError(`truncated OP_PUSHDATA1 length at ${offset}`);
      const dataLen = script[i]!;
      i += 1;
      if (i + dataLen > script.length) {
        throw new DisasmError(`truncated OP_PUSHDATA1 payload at ${offset}: need ${dataLen}, have ${script.length - i}`);
      }
      const data = script.slice(i, i + dataLen);
      i += dataLen;
      ops.push({ name: 'OP_PUSHDATA1', byte, data, offset, size: 1 + 1 + dataLen });
      continue;
    }

    if (byte === Opcode.OP_PUSHDATA2) {
      if (i + 2 > script.length) throw new DisasmError(`truncated OP_PUSHDATA2 length at ${offset}`);
      const dataLen = script[i]! | (script[i + 1]! << 8);
      i += 2;
      if (i + dataLen > script.length) {
        throw new DisasmError(`truncated OP_PUSHDATA2 payload at ${offset}: need ${dataLen}, have ${script.length - i}`);
      }
      const data = script.slice(i, i + dataLen);
      i += dataLen;
      ops.push({ name: 'OP_PUSHDATA2', byte, data, offset, size: 1 + 2 + dataLen });
      continue;
    }

    if (byte === Opcode.OP_PUSHDATA4) {
      if (i + 4 > script.length) throw new DisasmError(`truncated OP_PUSHDATA4 length at ${offset}`);
      const dataLen =
        script[i]! |
        (script[i + 1]! << 8) |
        (script[i + 2]! << 16) |
        (script[i + 3]! << 24);
      i += 4;
      if (i + dataLen > script.length) {
        throw new DisasmError(`truncated OP_PUSHDATA4 payload at ${offset}: need ${dataLen}, have ${script.length - i}`);
      }
      const data = script.slice(i, i + dataLen);
      i += dataLen;
      ops.push({ name: 'OP_PUSHDATA4', byte, data, offset, size: 1 + 4 + dataLen });
      continue;
    }

    // Non-push opcode — opcodeName falls back to OP_UNKNOWN(0xNN) for unmapped bytes.
    ops.push({ name: opcodeName(byte), byte, offset, size: 1 });
  }
  return ops;
}

export class DisasmError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DisasmError';
  }
}
