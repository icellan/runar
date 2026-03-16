import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, signTestMessage, rabinSign, RABIN_TEST_KEY } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'OraclePriceFeed.runar.ts'), 'utf8');

const ORACLE_PK = RABIN_TEST_KEY.n;
const RECEIVER_SIG = signTestMessage(ALICE.privKey);

/** Encode a positive price as 8-byte unsigned LE (matches num2bin(price, 8n)) */
function priceToMsg(price: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  let p = price;
  for (let i = 0; i < 8 && p > 0n; i++) {
    buf[i] = Number(p & 0xffn);
    p >>= 8n;
  }
  return buf;
}

/** Sign a price with the Rabin test key, returning sig (bigint) and padding (hex string) */
function signPrice(price: bigint): { rabinSig: bigint; padding: string } {
  const { sig, padding } = rabinSign(priceToMsg(price), RABIN_TEST_KEY);
  // Convert padding bigint to hex ByteString (unsigned LE)
  if (padding === 0n) return { rabinSig: sig, padding: '00' };
  const padBytes: number[] = [];
  let p = padding;
  while (p > 0n) { padBytes.push(Number(p & 0xffn)); p >>= 8n; }
  return { rabinSig: sig, padding: padBytes.map(b => b.toString(16).padStart(2, '0')).join('') };
}

describe('OraclePriceFeed', () => {
  function makeOracle() {
    return TestContract.fromSource(source, {
      oraclePubKey: ORACLE_PK,
      receiver: ALICE.pubKey,
    });
  }

  it('settles when price exceeds threshold', () => {
    const oracle = makeOracle();
    const { rabinSig, padding } = signPrice(60000n);
    const result = oracle.call('settle', {
      price: 60000n,
      rabinSig,
      padding,
      sig: RECEIVER_SIG,
    });
    expect(result.success).toBe(true);
  });

  it('rejects settlement when price is below threshold', () => {
    const oracle = makeOracle();
    const { rabinSig, padding } = signPrice(30000n);
    const result = oracle.call('settle', {
      price: 30000n,
      rabinSig,
      padding,
      sig: RECEIVER_SIG,
    });
    expect(result.success).toBe(false);
  });

  it('rejects settlement at exactly the threshold', () => {
    const oracle = makeOracle();
    const { rabinSig, padding } = signPrice(50000n);
    const result = oracle.call('settle', {
      price: 50000n,
      rabinSig,
      padding,
      sig: RECEIVER_SIG,
    });
    // price > 50000n is strict, so 50000n fails
    expect(result.success).toBe(false);
  });
});
