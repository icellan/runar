/**
 * BLAKE3 debug test — inspect what blake3Compress actually outputs.
 *
 * Uses the ScriptVM directly (not Spend.validate()) to get the final stack
 * state, so we can see the actual bytes produced by the codegen.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { ScriptVM, hexToBytes, bytesToHex } from '../vm/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode a hex ByteString as a push-data opcode sequence. */
function pushHex(hex: string): string {
  const bytes = hexToBytes(hex);
  if (bytes.length === 0) return '00'; // OP_0
  if (bytes.length <= 75) {
    return bytes.length.toString(16).padStart(2, '0') + hex;
  }
  if (bytes.length <= 255) {
    return '4c' + bytes.length.toString(16).padStart(2, '0') + hex;
  }
  const lo = (bytes.length & 0xff).toString(16).padStart(2, '0');
  const hi = ((bytes.length >> 8) & 0xff).toString(16).padStart(2, '0');
  return '4d' + lo + hi + hex;
}

// ---------------------------------------------------------------------------
// Reference BLAKE3 (copied from blake3.test.ts for independence)
// ---------------------------------------------------------------------------

const BLAKE3_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const CHUNK_START = 1;
const CHUNK_END = 2;
const ROOT = 8;

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function add32(a: number, b: number): number {
  return (a + b) >>> 0;
}

function g(state: number[], a: number, b: number, c: number, d: number, mx: number, my: number): void {
  state[a] = add32(add32(state[a]!, state[b]!), mx);
  state[d] = rotr32(state[d]! ^ state[a]!, 16);
  state[c] = add32(state[c]!, state[d]!);
  state[b] = rotr32(state[b]! ^ state[c]!, 12);
  state[a] = add32(add32(state[a]!, state[b]!), my);
  state[d] = rotr32(state[d]! ^ state[a]!, 8);
  state[c] = add32(state[c]!, state[d]!);
  state[b] = rotr32(state[b]! ^ state[c]!, 7);
}

function round(state: number[], m: number[]): void {
  g(state, 0, 4, 8, 12, m[0]!, m[1]!);
  g(state, 1, 5, 9, 13, m[2]!, m[3]!);
  g(state, 2, 6, 10, 14, m[4]!, m[5]!);
  g(state, 3, 7, 11, 15, m[6]!, m[7]!);
  g(state, 0, 5, 10, 15, m[8]!, m[9]!);
  g(state, 1, 6, 11, 12, m[10]!, m[11]!);
  g(state, 2, 7, 8, 13, m[12]!, m[13]!);
  g(state, 3, 4, 9, 14, m[14]!, m[15]!);
}

function permute(m: number[]): number[] {
  return MSG_PERM.map(i => m[i]!);
}

function referenceBlake3Compress(
  cvHex: string,
  blockHex: string,
  blockLen: number = 64,
  flags: number = CHUNK_START | CHUNK_END | ROOT,
): string {
  const cv: number[] = [];
  for (let i = 0; i < 8; i++) cv.push(parseInt(cvHex.substring(i * 8, i * 8 + 8), 16));

  const m: number[] = [];
  for (let i = 0; i < 16; i++) m.push(parseInt(blockHex.substring(i * 8, i * 8 + 8), 16));

  const state: number[] = [
    cv[0]!, cv[1]!, cv[2]!, cv[3]!,
    cv[4]!, cv[5]!, cv[6]!, cv[7]!,
    BLAKE3_IV[0]!, BLAKE3_IV[1]!, BLAKE3_IV[2]!, BLAKE3_IV[3]!,
    0, 0, blockLen, flags,
  ];

  let msg = [...m];
  for (let r = 0; r < 7; r++) {
    round(state, msg);
    if (r < 6) msg = permute(msg);
  }

  const output: number[] = [];
  for (let i = 0; i < 8; i++) {
    output.push((state[i]! ^ state[i + 8]!) >>> 0);
  }

  return output.map(w => w.toString(16).padStart(8, '0')).join('');
}

const BLAKE3_IV_HEX = BLAKE3_IV.map(w => w.toString(16).padStart(8, '0')).join('');

// ---------------------------------------------------------------------------
// Debug contract — leaves blake3Compress result on the stack, then pushes
// OP_TRUE so the script succeeds. We can inspect stack[0] for the result.
// ---------------------------------------------------------------------------

const DEBUG_COMPRESS_SOURCE = `
class Blake3DebugCompress extends SmartContract {
  readonly dummy: bigint;

  constructor(dummy: bigint) {
    super(dummy);
    this.dummy = dummy;
  }

  public inspect(chainingValue: ByteString, block: ByteString) {
    const result = blake3Compress(chainingValue, block);
    // Leave result on the stack, push true for script success
    assert(result !== "");
  }
}
`;

// ---------------------------------------------------------------------------
// A contract that asserts result == expected so we can test both pass/fail
// ---------------------------------------------------------------------------

const VERIFY_COMPRESS_SOURCE = `
class Blake3VerifyCompress extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(chainingValue: ByteString, block: ByteString) {
    const result = blake3Compress(chainingValue, block);
    assert(result === this.expected);
  }
}
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('blake3Compress — debug output inspection', () => {
  const block = '00'.repeat(64);
  const expectedRef = referenceBlake3Compress(BLAKE3_IV_HEX, block, 64, CHUNK_START | CHUNK_END | ROOT);

  it('reference implementation produces expected output', () => {
    console.log('BLAKE3 IV hex:', BLAKE3_IV_HEX);
    console.log('Block (all zeros):', block);
    console.log('Reference output (blockLen=64, flags=11):', expectedRef);
    console.log('Reference output length:', expectedRef.length / 2, 'bytes');
    expect(expectedRef.length).toBe(64); // 32 bytes = 64 hex chars
  });

  it('compile debug contract and inspect raw stack via ScriptVM', () => {
    // Compile the contract
    const result = compile(DEBUG_COMPRESS_SOURCE, {
      fileName: 'Blake3DebugCompress.runar.ts',
      constructorArgs: { dummy: 0n },
    });

    if (!result.success || !result.scriptHex) {
      console.log('Compilation failed:', result.diagnostics);
      expect(result.success).toBe(true);
      return;
    }

    console.log('Locking script length:', result.scriptHex.length / 2, 'bytes');

    // Build unlocking script: push chainingValue, then block
    const unlockingHex = pushHex(BLAKE3_IV_HEX) + pushHex(block);

    // Execute using ScriptVM to get the full stack
    const vm = new ScriptVM({ maxOps: 10_000_000 });
    const vmResult = vm.executeHex(unlockingHex + result.scriptHex);

    console.log('VM success:', vmResult.success);
    console.log('VM error:', vmResult.error ?? 'none');
    console.log('Ops executed:', vmResult.opsExecuted);
    console.log('Max stack depth:', vmResult.maxStackDepth);
    console.log('Final stack depth:', vmResult.stack.length);

    if (vmResult.stack.length > 0) {
      console.log('\n--- Final stack (TOS last) ---');
      for (let i = 0; i < vmResult.stack.length; i++) {
        const item = vmResult.stack[i]!;
        const hex = bytesToHex(item);
        console.log(`  stack[${i}]: (${item.length} bytes) ${hex}`);
      }
    }

    if (vmResult.altStack.length > 0) {
      console.log('\n--- Alt stack ---');
      for (let i = 0; i < vmResult.altStack.length; i++) {
        const item = vmResult.altStack[i]!;
        const hex = bytesToHex(item);
        console.log(`  alt[${i}]: (${item.length} bytes) ${hex}`);
      }
    }

    // The script should at least execute without error
    if (!vmResult.success) {
      console.log('\nScript FAILED — checking if it is a comparison mismatch...');
    }
  });

  it('compile verify contract with CORRECT expected and check via ScriptVM', () => {
    const result = compile(VERIFY_COMPRESS_SOURCE, {
      fileName: 'Blake3VerifyCompress.runar.ts',
      constructorArgs: { expected: expectedRef },
    });

    if (!result.success || !result.scriptHex) {
      console.log('Compilation failed:', result.diagnostics);
      expect(result.success).toBe(true);
      return;
    }

    const unlockingHex = pushHex(BLAKE3_IV_HEX) + pushHex(block);

    const vm = new ScriptVM({ maxOps: 10_000_000 });
    const vmResult = vm.executeHex(unlockingHex + result.scriptHex);

    console.log('Verify (correct expected) — success:', vmResult.success);
    console.log('Verify — error:', vmResult.error ?? 'none');
    console.log('Verify — ops executed:', vmResult.opsExecuted);
    console.log('Verify — stack depth:', vmResult.stack.length);

    if (vmResult.stack.length > 0) {
      for (let i = 0; i < vmResult.stack.length; i++) {
        const item = vmResult.stack[i]!;
        console.log(`  stack[${i}]: (${item.length} bytes) ${bytesToHex(item)}`);
      }
    }

    console.log('\nExpected reference output:', expectedRef);
  });

  it('compile verify contract with WRONG expected to confirm assertion fires', () => {
    const wrongExpected = 'ff'.repeat(32);

    const result = compile(VERIFY_COMPRESS_SOURCE, {
      fileName: 'Blake3VerifyCompress.runar.ts',
      constructorArgs: { expected: wrongExpected },
    });

    if (!result.success || !result.scriptHex) {
      console.log('Compilation failed:', result.diagnostics);
      expect(result.success).toBe(true);
      return;
    }

    const unlockingHex = pushHex(BLAKE3_IV_HEX) + pushHex(block);

    const vm = new ScriptVM({ maxOps: 10_000_000 });
    const vmResult = vm.executeHex(unlockingHex + result.scriptHex);

    console.log('Verify (wrong expected) — success:', vmResult.success);
    console.log('Verify (wrong expected) — error:', vmResult.error ?? 'none');

    // This SHOULD fail because the wrong hash is baked in
    expect(vmResult.success).toBe(false);
  });

  it('byte-level comparison of actual vs expected output', () => {
    // Use the debug contract to get actual output, then compare word by word
    const result = compile(DEBUG_COMPRESS_SOURCE, {
      fileName: 'Blake3DebugCompress.runar.ts',
      constructorArgs: { dummy: 0n },
    });

    if (!result.success || !result.scriptHex) {
      expect(result.success).toBe(true);
      return;
    }

    const unlockingHex = pushHex(BLAKE3_IV_HEX) + pushHex(block);
    const vm = new ScriptVM({ maxOps: 10_000_000 });
    const vmResult = vm.executeHex(unlockingHex + result.scriptHex);

    console.log('\n=== BYTE-LEVEL COMPARISON ===');
    console.log('Expected (reference):', expectedRef);

    // Look for a 32-byte item on the stack that might be the blake3 output
    let actualHex = '';
    for (let i = 0; i < vmResult.stack.length; i++) {
      const item = vmResult.stack[i]!;
      if (item.length === 32) {
        actualHex = bytesToHex(item);
        console.log(`Found 32-byte item at stack[${i}]:`, actualHex);
      }
    }

    if (!actualHex && vmResult.stack.length > 0) {
      // If no 32-byte item, dump everything
      console.log('No 32-byte item found. Full stack:');
      for (let i = 0; i < vmResult.stack.length; i++) {
        const item = vmResult.stack[i]!;
        console.log(`  [${i}] (${item.length}B): ${bytesToHex(item)}`);
      }
    }

    if (actualHex) {
      // Word-by-word comparison (8 x 4 bytes = 32 bytes)
      console.log('\nWord-by-word comparison (big-endian u32):');
      for (let w = 0; w < 8; w++) {
        const expWord = expectedRef.substring(w * 8, w * 8 + 8);
        const actWord = actualHex.substring(w * 8, w * 8 + 8);
        const match = expWord === actWord ? 'OK' : 'MISMATCH';
        console.log(`  word[${w}]: expected=${expWord}  actual=${actWord}  ${match}`);
      }

      // Check if it might be byte-reversed (LE vs BE issue)
      const reversed = actualHex.match(/.{2}/g)!.reverse().join('');
      if (reversed === expectedRef) {
        console.log('\n*** FULL BYTE REVERSAL detected — entire output is backwards ***');
      }

      // Check if it's word-level LE (each 4-byte word is reversed)
      const wordReversed = actualHex.match(/.{8}/g)!
        .map(w => w.match(/.{2}/g)!.reverse().join(''))
        .join('');
      if (wordReversed === expectedRef) {
        console.log('\n*** WORD-LEVEL BYTE SWAP detected — each u32 word is little-endian ***');
      }
    }
  });
});
