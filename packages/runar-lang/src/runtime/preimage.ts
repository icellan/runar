// ---------------------------------------------------------------------------
// runar-lang/runtime/preimage.ts — Mock preimage functions for off-chain sim
// ---------------------------------------------------------------------------
// Returns sensible defaults matching the runar-testing interpreter.
// ---------------------------------------------------------------------------

import type { ByteString, Sha256, SigHashPreimage } from '../types.js';

const ZERO_32 = '00'.repeat(32) as unknown as Sha256;
const ZERO_36 = '00'.repeat(36) as ByteString;

export function checkPreimage(_txPreimage: SigHashPreimage): boolean {
  return true;
}

export function extractVersion(_txPreimage: SigHashPreimage): bigint {
  return 1n;
}

export function extractHashPrevouts(_txPreimage: SigHashPreimage): Sha256 {
  return ZERO_32;
}

export function extractHashSequence(_txPreimage: SigHashPreimage): Sha256 {
  return ZERO_32;
}

export function extractOutpoint(_txPreimage: SigHashPreimage): ByteString {
  return ZERO_36;
}

export function extractInputIndex(_txPreimage: SigHashPreimage): bigint {
  return 0n;
}

export function extractScriptCode(_txPreimage: SigHashPreimage): ByteString {
  return '' as ByteString;
}

export function extractAmount(_txPreimage: SigHashPreimage): bigint {
  return 10000n;
}

export function extractSequence(_txPreimage: SigHashPreimage): bigint {
  return 0xfffffffen;
}

export function extractOutputHash(txPreimage: SigHashPreimage): Sha256 {
  // hashOutputs is the 32 bytes immediately before the trailing nLocktime(4)
  // + sighashType(4), i.e. end-relative: bytes[length-40 .. length-8). This
  // mirrors the compiled opcode sequence exactly (OP_SIZE 40 OP_SUB OP_SPLIT
  // OP_NIP 32 OP_SPLIT OP_DROP) and needs no knowledge of the variable-length
  // scriptCode field that precedes it. N-245: this used to echo the leading
  // 32 bytes (nVersion + most of hashPrevouts in a real preimage).
  const bytes = typeof txPreimage === 'string'
    ? Buffer.from(txPreimage as string, 'hex')
    : txPreimage as unknown as Buffer;
  if (bytes && bytes.length >= 40) {
    return bytes.slice(bytes.length - 40, bytes.length - 8).toString('hex') as unknown as Sha256;
  }
  return ZERO_32;
}

export function extractOutputs(txPreimage: SigHashPreimage): Sha256 {
  // Alias for extractOutputHash — the compiler lowers both to the same
  // 32-byte hashOutputs window (see 05-stack-lower.ts).
  return extractOutputHash(txPreimage);
}

export function extractLocktime(_txPreimage: SigHashPreimage): bigint {
  return 0n;
}

export function extractSigHashType(_txPreimage: SigHashPreimage): bigint {
  return 0x41n;
}
