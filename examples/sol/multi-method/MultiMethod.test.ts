import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'MultiMethod.runar.sol'), 'utf8');
const FILE_NAME = 'MultiMethod.runar.sol';

const ALICE_SIG = signTestMessage(ALICE.privKey);
const BOB_SIG = signTestMessage(BOB.privKey);

describe('MultiMethod (Solidity)', () => {
  it('compiles via TestContract.fromSource with sol parser', () => {
    const c = TestContract.fromSource(source, { owner: ALICE.pubKey, backup: BOB.pubKey }, FILE_NAME);
    expect(c.state.owner).toBe(ALICE.pubKey);
    expect(c.state.backup).toBe(BOB.pubKey);
  });

  it('spendWithOwner succeeds when threshold is met and owner signs', () => {
    const c = TestContract.fromSource(source, { owner: ALICE.pubKey, backup: BOB.pubKey }, FILE_NAME);
    expect(c.call('spendWithOwner', { sig: ALICE_SIG, amount: 6n }).success).toBe(true);
  });

  it('spendWithOwner rejects when the threshold is not met', () => {
    const c = TestContract.fromSource(source, { owner: ALICE.pubKey, backup: BOB.pubKey }, FILE_NAME);
    expect(c.call('spendWithOwner', { sig: ALICE_SIG, amount: 1n }).success).toBe(false);
  });

  it('spendWithBackup succeeds with the backup signature', () => {
    const c = TestContract.fromSource(source, { owner: ALICE.pubKey, backup: BOB.pubKey }, FILE_NAME);
    expect(c.call('spendWithBackup', { sig: BOB_SIG }).success).toBe(true);
  });
});
