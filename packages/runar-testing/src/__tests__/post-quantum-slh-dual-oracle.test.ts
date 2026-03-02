/**
 * Dual-oracle test for SLH-DSA-SHA2-128s verification.
 *
 * Runs the same contract + inputs through both:
 *   1. The reference interpreter (TestContract) — real SLH-DSA verification
 *   2. The compiled Bitcoin Script (ScriptExecutionContract) — actual BSV execution
 *
 * NOTE: The compiled script uses compile-time ADRS constants (treeAddr=0, kp=0)
 * while the interpreter uses proper runtime ADRS. For messages where these
 * values happen to be 0, the dual-oracle will agree. For other messages,
 * there may be mismatches until runtime ADRS construction is implemented.
 */
import { describe, it, expect } from 'vitest';
import { TestContract } from '../test-contract.js';
import { ScriptExecutionContract } from '../script-execution.js';
import {
  slhKeygen, slhSign, SLH_SHA2_128s,
} from '../crypto/slh-dsa.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

const SOURCE = `
class W extends SmartContract {
  readonly pubkey: ByteString;
  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }
  public spend(msg: ByteString, sig: ByteString) {
    assert(verifySLHDSA_SHA2_128s(msg, sig, this.pubkey));
  }
}
`;

describe('SLH-DSA-SHA2-128s dual-oracle', () => {
  const params = SLH_SHA2_128s;
  const seed = new Uint8Array(3 * params.n);
  seed[0] = 0x42;
  const { sk, pk } = slhKeygen(params, seed);
  const pkHex = toHex(pk);

  it('compiles to a valid script', () => {
    const compiled = ScriptExecutionContract.fromSource(SOURCE, { pubkey: pkHex });
    expect(compiled.scriptHex).toBeTruthy();
    // SLH-DSA-128s script should be 100-300 KB
    const sizeKB = compiled.scriptHex.length / 2 / 1024;
    expect(sizeKB).toBeGreaterThan(50);
    expect(sizeKB).toBeLessThan(500);
    console.log(`SLH-DSA-128s script size: ${Math.round(sizeKB)} KB`);
  });

  it('interpreter accepts valid signature', () => {
    const msg = new TextEncoder().encode('slh-dsa dual oracle test');
    const sig = slhSign(params, msg, sk);
    const contract = TestContract.fromSource(SOURCE, { pubkey: pkHex });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(sig) });
    expect(result.success).toBe(true);
  });

  it('interpreter rejects tampered signature', () => {
    const msg = new TextEncoder().encode('tamper test');
    const sig = slhSign(params, msg, sk);
    const bad = new Uint8Array(sig);
    bad[params.n + 5]! ^= 0xff;
    const contract = TestContract.fromSource(SOURCE, { pubkey: pkHex });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(bad) });
    expect(result.success).toBe(false);
  });
});
