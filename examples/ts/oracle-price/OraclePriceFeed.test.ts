import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'OraclePriceFeed.runar.ts'), 'utf8');

const ORACLE_PK = 12345n;  // RabinPubKey is bigint
const RECEIVER_PK = '02' + 'aa'.repeat(32);
const MOCK_SIG = '30' + 'ff'.repeat(35);
const RABIN_SIG = 99999n;  // RabinSig is bigint
const PADDING = 'aabbccdd';

describe('OraclePriceFeed', () => {
  function makeOracle() {
    return TestContract.fromSource(source, {
      oraclePubKey: ORACLE_PK,
      receiver: RECEIVER_PK,
    });
  }

  it('settles when price exceeds threshold', () => {
    const oracle = makeOracle();
    const result = oracle.call('settle', {
      price: 60000n,
      rabinSig: RABIN_SIG,
      padding: PADDING,
      sig: MOCK_SIG,
    });
    // verifyRabinSig is mocked true, checkSig is mocked true, price > 50000
    expect(result.success).toBe(true);
  });

  it('rejects settlement when price is below threshold', () => {
    const oracle = makeOracle();
    const result = oracle.call('settle', {
      price: 30000n,
      rabinSig: RABIN_SIG,
      padding: PADDING,
      sig: MOCK_SIG,
    });
    expect(result.success).toBe(false);
  });

  it('rejects settlement at exactly the threshold', () => {
    const oracle = makeOracle();
    const result = oracle.call('settle', {
      price: 50000n,
      rabinSig: RABIN_SIG,
      padding: PADDING,
      sig: MOCK_SIG,
    });
    // price > 50000n is strict, so 50000n fails
    expect(result.success).toBe(false);
  });
});
