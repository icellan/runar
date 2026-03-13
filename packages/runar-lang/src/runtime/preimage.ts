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
  // Returns the first 32 bytes of the preimage in test mode.
  // Tests set txPreimage = hash256(expectedOutputBytes) so the assertion
  // hash256(outputs) == extractOutputHash(txPreimage) passes.
  const bytes = typeof txPreimage === 'string'
    ? Buffer.from(txPreimage as string, 'hex')
    : txPreimage as unknown as Buffer;
  if (bytes && bytes.length >= 32) {
    return bytes.slice(0, 32).toString('hex') as unknown as Sha256;
  }
  return ZERO_32;
}

export function extractOutputs(_txPreimage: SigHashPreimage): Sha256 {
  return ZERO_32;
}

export function extractLocktime(_txPreimage: SigHashPreimage): bigint {
  return 0n;
}

export function extractSigHashType(_txPreimage: SigHashPreimage): bigint {
  return 0x41n;
}
