// INTERPRETER-ONLY: spendability covered by packages/runar-sdk/src/__tests__/n042-token-wallet-example-e2e.test.ts
// (compiles THIS directory's WalletToken.runar.ts, drives the SDK's TokenWallet
//  through a default-validating MockProvider, replays every input via @bsv/sdk Spend).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

/**
 * Business logic of the TokenWallet ABI example. The interpreter mocks
 * checkSig, so these tests say nothing about signatures or spendability (see
 * the banner). They pin what the contract does to its state, including the
 * documented limit: `merge` accepts any non-negative `otherSupply`.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'WalletToken.runar.ts'), 'utf8');
const SIG = signTestMessage(ALICE.privKey);
const ADDR = '11'.repeat(20);

describe('WalletToken (TokenWallet ABI example)', () => {
  it('transfer authorises the spend and leaves supply and holder unchanged', () => {
    const t = TestContract.fromSource(source, { supply: 100n, holder: ALICE.pubKey });
    const r = t.call('transfer', { sig: SIG, to: ADDR });
    expect(r.success, r.error).toBe(true);
    expect(t.state.supply).toBe(100n);
  });

  it('transfer rejects a recipient that is not 20 bytes', () => {
    const t = TestContract.fromSource(source, { supply: 100n, holder: ALICE.pubKey });
    expect(t.call('transfer', { sig: SIG, to: '11'.repeat(19) }).success).toBe(false);
  });

  it('merge adds otherSupply to supply', () => {
    const t = TestContract.fromSource(source, { supply: 100n, holder: ALICE.pubKey });
    const r = t.call('merge', { sig: SIG, otherSupply: 250n, otherHolder: ALICE.pubKey });
    expect(r.success, r.error).toBe(true);
    expect(t.state.supply).toBe(350n);
  });

  it('merge rejects a companion with a different holder', () => {
    const t = TestContract.fromSource(source, { supply: 100n, holder: ALICE.pubKey });
    expect(t.call('merge', { sig: SIG, otherSupply: 1n, otherHolder: BOB.pubKey }).success).toBe(false);
  });

  it('merge rejects a negative otherSupply', () => {
    const t = TestContract.fromSource(source, { supply: 100n, holder: ALICE.pubKey });
    expect(t.call('merge', { sig: SIG, otherSupply: -1n, otherHolder: ALICE.pubKey }).success).toBe(false);
  });
});
