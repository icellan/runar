import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScriptExecutionContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Sha256FinalizeTest.runar.move'), 'utf8');
const FILE_NAME = 'Sha256FinalizeTest.runar.move';

const SHA256_INIT = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

describe('Sha256FinalizeTest (Move)', () => {
  it('sha256Finalize succeeds with correct state, remaining, and bitLen', () => {
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: SHA256_ABC,
    }, FILE_NAME);
    const result = contract.execute('verify', [SHA256_INIT, '616263', 24n]);
    expect(result.success).toBe(true);
  });

  it('rejects wrong expected hash', () => {
    const wrongHash = 'ff'.repeat(32);
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: wrongHash,
    }, FILE_NAME);
    const result = contract.execute('verify', [SHA256_INIT, '616263', 24n]);
    expect(result.success).toBe(false);
  });
});
