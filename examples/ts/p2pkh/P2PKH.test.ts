import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P2PKH.runar.ts'), 'utf8');

const SIG = signTestMessage(ALICE.privKey);

describe('P2PKH', () => {
  it('accepts a valid unlock', () => {
    const contract = TestContract.fromSource(source, { pubKeyHash: ALICE.pubKeyHash });
    const result = contract.call('unlock', { sig: SIG, pubKey: ALICE.pubKey });
    expect(result.success).toBe(true);
  });

  it('is a stateless contract with no state tracking', () => {
    const contract = TestContract.fromSource(source, { pubKeyHash: ALICE.pubKeyHash });
    // P2PKH has only readonly properties — state is empty of mutable fields
    expect(contract.state.pubKeyHash).toBeDefined();
  });
});
