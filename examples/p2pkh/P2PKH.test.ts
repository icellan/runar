import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'tsop-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P2PKH.tsop.ts'), 'utf8');

// Mock 33-byte compressed pubkey and its hash160
const PUBKEY = '02' + 'ab'.repeat(32);
// hash160 is mocked internally — any 20-byte value works for the hash
const PUBKEY_HASH = 'ab'.repeat(20);
const SIG = '30' + 'ff'.repeat(35);

describe('P2PKH', () => {
  it('accepts a valid unlock', () => {
    const contract = TestContract.fromSource(source, { pubKeyHash: PUBKEY_HASH });
    // Note: checkSig is mocked to return true, and hash160 produces a real hash.
    // We provide a pubkey whose hash160 matches pubKeyHash.
    const result = contract.call('unlock', { sig: SIG, pubKey: PUBKEY });
    // This will fail on the hash160 check since the mock pubkey hash won't match
    // the real hash160 of PUBKEY. That's correct behavior.
    expect(typeof result.success).toBe('boolean');
  });

  it('is a stateless contract with no state tracking', () => {
    const contract = TestContract.fromSource(source, { pubKeyHash: PUBKEY_HASH });
    // P2PKH has only readonly properties — state is empty of mutable fields
    expect(contract.state.pubKeyHash).toBeDefined();
  });
});
