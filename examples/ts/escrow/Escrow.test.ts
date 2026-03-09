import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Escrow.runar.ts'), 'utf8');

const BUYER_PK = '02' + 'aa'.repeat(32);
const SELLER_PK = '02' + 'bb'.repeat(32);
const ARBITER_PK = '02' + 'cc'.repeat(32);
const MOCK_SIG = '30' + 'ff'.repeat(35);

describe('Escrow', () => {
  function makeEscrow() {
    return TestContract.fromSource(source, {
      buyer: BUYER_PK,
      seller: SELLER_PK,
      arbiter: ARBITER_PK,
    });
  }

  it('allows release with seller + arbiter signatures', () => {
    const escrow = makeEscrow();
    const result = escrow.call('release', { sellerSig: MOCK_SIG, arbiterSig: MOCK_SIG });
    expect(result.success).toBe(true);
  });

  it('allows refund with buyer + arbiter signatures', () => {
    const escrow = makeEscrow();
    const result = escrow.call('refund', { buyerSig: MOCK_SIG, arbiterSig: MOCK_SIG });
    expect(result.success).toBe(true);
  });

  it('has two distinct spending paths', () => {
    const escrow = makeEscrow();
    const methods = [
      { name: 'release', args: { sellerSig: MOCK_SIG, arbiterSig: MOCK_SIG } },
      { name: 'refund', args: { buyerSig: MOCK_SIG, arbiterSig: MOCK_SIG } },
    ];
    for (const { name, args } of methods) {
      const result = escrow.call(name, args);
      expect(result.success).toBe(true);
    }
  });
});
