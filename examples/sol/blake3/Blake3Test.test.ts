import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScriptExecutionContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Blake3Test.runar.sol'), 'utf8');
const FILE_NAME = 'Blake3Test.runar.sol';

// BLAKE3 IV: the standard initialization vector (8 x 32-bit words, big-endian hex)
const BLAKE3_IV = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';

// BLAKE3 hash of an all-zero 64-byte block (compress with blockLen=64, flags=11)
const BLAKE3_HASH_OF_ZEROS = '7669004d96866a6330a609d9ad1a08a4f8507c4d04eefd1a50f00b02556aab86';

// All-zero 64-byte block
const ZERO_BLOCK = '00'.repeat(64);

describe('Blake3Test (Solidity)', () => {
  it('verifyCompress succeeds with correct chaining value and block', () => {
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: BLAKE3_HASH_OF_ZEROS,
    }, FILE_NAME);
    const result = contract.execute('verifyCompress', [BLAKE3_IV, ZERO_BLOCK]);
    expect(result.success).toBe(true);
  });

  it('verifyHash succeeds with correct message', () => {
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: BLAKE3_HASH_OF_ZEROS,
    }, FILE_NAME);
    const result = contract.execute('verifyHash', [ZERO_BLOCK]);
    expect(result.success).toBe(true);
  });

  it('verifyCompress fails with wrong expected hash', () => {
    const wrongHash = 'ff'.repeat(32);
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: wrongHash,
    }, FILE_NAME);
    const result = contract.execute('verifyCompress', [BLAKE3_IV, ZERO_BLOCK]);
    expect(result.success).toBe(false);
  });

  it('verifyHash fails with wrong expected hash', () => {
    const wrongHash = 'ff'.repeat(32);
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: wrongHash,
    }, FILE_NAME);
    const result = contract.execute('verifyHash', [ZERO_BLOCK]);
    expect(result.success).toBe(false);
  });
});
