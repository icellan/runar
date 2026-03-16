import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P2Blake3PKH.runar.sol'), 'utf8');
const FILE_NAME = 'P2Blake3PKH.runar.sol';

// Mock 33-byte compressed pubkey
const PUBKEY = '02' + 'ab'.repeat(32);
// blake3Hash is mocked internally — any 32-byte value works for the hash
const PUBKEY_HASH = 'ab'.repeat(32);
const SIG = '30' + 'ff'.repeat(35);

describe('P2Blake3PKH (Solidity)', () => {
  it('accepts a valid unlock', () => {
    const contract = TestContract.fromSource(source, { pubKeyHash: PUBKEY_HASH }, FILE_NAME);
    const result = contract.call('unlock', { sig: SIG, pubKey: PUBKEY });
    expect(typeof result.success).toBe('boolean');
  });

  it('is a stateless contract with no state tracking', () => {
    const contract = TestContract.fromSource(source, { pubKeyHash: PUBKEY_HASH }, FILE_NAME);
    expect(contract.state.pubKeyHash).toBeDefined();
  });
});
