import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'MultiMethod.runar.ts'), 'utf8');

const ALICE_SIG = signTestMessage(ALICE.privKey);
const BOB_SIG = signTestMessage(BOB.privKey);

describe('MultiMethod', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { owner: ALICE.pubKey, backup: BOB.pubKey });
    expect(c.state.owner).toBe(ALICE.pubKey);
    expect(c.state.backup).toBe(BOB.pubKey);
  });

  it('spendWithOwner succeeds when threshold is met and owner signs', () => {
    const c = TestContract.fromSource(source, { owner: ALICE.pubKey, backup: BOB.pubKey });
    // amount * 2 + 1 must be > 10, so amount >= 5.
    const result = c.call('spendWithOwner', { sig: ALICE_SIG, amount: 6n });
    expect(result.success).toBe(true);
  });

  it('spendWithOwner rejects when the threshold is not met', () => {
    const c = TestContract.fromSource(source, { owner: ALICE.pubKey, backup: BOB.pubKey });
    const result = c.call('spendWithOwner', { sig: ALICE_SIG, amount: 1n });
    expect(result.success).toBe(false);
  });

  it('spendWithBackup succeeds with the backup signature', () => {
    const c = TestContract.fromSource(source, { owner: ALICE.pubKey, backup: BOB.pubKey });
    const result = c.call('spendWithBackup', { sig: BOB_SIG });
    expect(result.success).toBe(true);
  });
});
