import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScriptExecutionContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Sha256CompressTest.runar.ts'), 'utf8');
const FILE_NAME = 'Sha256CompressTest.runar.ts';

const SHA256_INIT = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const ABC_PADDED_BLOCK =
  '6162638000000000000000000000000000000000000000000000000000000000' +
  '0000000000000000000000000000000000000000000000000000000000000018';

describe('Sha256CompressTest', () => {
  it('sha256Compress(init, padded "abc") matches known hash', () => {
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: SHA256_ABC,
    }, FILE_NAME);
    const result = contract.execute('verify', [SHA256_INIT, ABC_PADDED_BLOCK]);
    expect(result.success).toBe(true);
  });

  it('rejects wrong expected hash', () => {
    const wrongHash = '00'.repeat(32);
    const contract = ScriptExecutionContract.fromSource(source, {
      expected: wrongHash,
    }, FILE_NAME);
    const result = contract.execute('verify', [SHA256_INIT, ABC_PADDED_BLOCK]);
    expect(result.success).toBe(false);
  });
});
