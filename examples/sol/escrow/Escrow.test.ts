import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, BOB, CHARLIE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Escrow.runar.sol'), 'utf8');
const FILE_NAME = 'Escrow.runar.sol';

const SELLER_PK = ALICE.pubKey;
const BUYER_PK = BOB.pubKey;
const ARBITER_PK = CHARLIE.pubKey;
const SELLER_SIG = signTestMessage(ALICE.privKey);
const BUYER_SIG = signTestMessage(BOB.privKey);
const ARBITER_SIG = signTestMessage(CHARLIE.privKey);

describe('Escrow (Solidity)', () => {
  function makeEscrow() {
    return TestContract.fromSource(source, {
      buyer: BUYER_PK,
      seller: SELLER_PK,
      arbiter: ARBITER_PK,
    }, FILE_NAME);
  }

  it('allows release with seller + arbiter signatures', () => {
    const escrow = makeEscrow();
    const result = escrow.call('release', { sellerSig: SELLER_SIG, arbiterSig: ARBITER_SIG });
    expect(result.success).toBe(true);
  });

  it('allows refund with buyer + arbiter signatures', () => {
    const escrow = makeEscrow();
    const result = escrow.call('refund', { buyerSig: BUYER_SIG, arbiterSig: ARBITER_SIG });
    expect(result.success).toBe(true);
  });

  it('has two distinct spending paths', () => {
    const escrow = makeEscrow();
    const methods = [
      { name: 'release', args: { sellerSig: SELLER_SIG, arbiterSig: ARBITER_SIG } },
      { name: 'refund', args: { buyerSig: BUYER_SIG, arbiterSig: ARBITER_SIG } },
    ];
    for (const { name, args } of methods) {
      const result = escrow.call(name, args);
      expect(result.success).toBe(true);
    }
  });
});
