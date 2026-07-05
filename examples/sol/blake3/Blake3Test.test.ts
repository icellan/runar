import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScriptExecutionContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Blake3Test.runar.sol'), 'utf8');
const FILE_NAME = 'Blake3Test.runar.sol';

// BLAKE3 IV as a chaining value: the standard IV encoded little-endian (a
// 4-byte Bitcoin Script byte-string is a little-endian 32-bit word).
const BLAKE3_IV = '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b';

// Standard BLAKE3 compress(IV, all-zero 64-byte block, blockLen=64, flags=11),
// which also equals blake3Hash of a 64-byte all-zero message.
const BLAKE3_HASH_OF_ZEROS = '4d006976636a8696d909a630a4081aad4d7c50f81afdee04020bf05086ab6a55';

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
