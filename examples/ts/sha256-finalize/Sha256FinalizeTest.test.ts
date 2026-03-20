import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScriptExecutionContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Sha256FinalizeTest.runar.ts'), 'utf8');
const FILE_NAME = 'Sha256FinalizeTest.runar.ts';

const SHA256_INIT = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

describe('Sha256FinalizeTest', () => {
  it('sha256Finalize(init, "abc", 24) matches known SHA-256("abc")', () => {
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: SHA256_ABC,
    }, FILE_NAME);
    const result = contract.execute('verify', [SHA256_INIT, '616263', 24n]);
    expect(result.success).toBe(true);
  });

  it('sha256Finalize(init, "", 0) matches known SHA-256("")', () => {
    const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const contract = ScriptExecutionContract.fromSource(source, {
      expected,
    }, FILE_NAME);
    const result = contract.execute('verify', [SHA256_INIT, '', 0n]);
    expect(result.success).toBe(true);
  });

  it('rejects wrong expected hash', () => {
    const wrongHash = '00'.repeat(32);
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: wrongHash,
    }, FILE_NAME);
    const result = contract.execute('verify', [SHA256_INIT, '616263', 24n]);
    expect(result.success).toBe(false);
  });
});
