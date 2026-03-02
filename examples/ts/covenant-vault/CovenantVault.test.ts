import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'CovenantVault.runar.ts'), 'utf8');

const OWNER_PK = '02' + 'aa'.repeat(32);
const RECIPIENT = 'bb'.repeat(20);  // 20-byte Addr
const MIN_AMOUNT = 5000n;
const MOCK_SIG = '30' + 'ff'.repeat(35);
const MOCK_PREIMAGE = '00'.repeat(181);  // SigHashPreimage

describe('CovenantVault', () => {
  function makeVault() {
    return TestContract.fromSource(source, {
      owner: OWNER_PK,
      recipient: RECIPIENT,
      minAmount: MIN_AMOUNT,
    });
  }

  it('allows spend above minimum amount', () => {
    const vault = makeVault();
    const result = vault.call('spend', {
      sig: MOCK_SIG,
      amount: 10000n,
      txPreimage: MOCK_PREIMAGE,
    });
    expect(result.success).toBe(true);
  });

  it('allows spend at exactly minimum amount', () => {
    const vault = makeVault();
    const result = vault.call('spend', {
      sig: MOCK_SIG,
      amount: MIN_AMOUNT,
      txPreimage: MOCK_PREIMAGE,
    });
    expect(result.success).toBe(true);
  });

  it('rejects spend below minimum amount', () => {
    const vault = makeVault();
    const result = vault.call('spend', {
      sig: MOCK_SIG,
      amount: 1000n,
      txPreimage: MOCK_PREIMAGE,
    });
    expect(result.success).toBe(false);
  });
});
