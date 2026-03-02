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

  it('allows release by seller', () => {
    const escrow = makeEscrow();
    const result = escrow.call('releaseBySeller', { sig: MOCK_SIG });
    expect(result.success).toBe(true);
  });

  it('allows release by arbiter', () => {
    const escrow = makeEscrow();
    const result = escrow.call('releaseByArbiter', { sig: MOCK_SIG });
    expect(result.success).toBe(true);
  });

  it('allows refund to buyer', () => {
    const escrow = makeEscrow();
    const result = escrow.call('refundToBuyer', { sig: MOCK_SIG });
    expect(result.success).toBe(true);
  });

  it('allows refund by arbiter', () => {
    const escrow = makeEscrow();
    const result = escrow.call('refundByArbiter', { sig: MOCK_SIG });
    expect(result.success).toBe(true);
  });

  it('has four distinct spending paths', () => {
    const escrow = makeEscrow();
    const methods = ['releaseBySeller', 'releaseByArbiter', 'refundToBuyer', 'refundByArbiter'];
    for (const method of methods) {
      const result = escrow.call(method, { sig: MOCK_SIG });
      expect(result.success).toBe(true);
    }
  });
});
