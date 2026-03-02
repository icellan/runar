/**
 * Dual-oracle tests for WOTS+ verification.
 *
 * These tests run the same contract + inputs through both:
 *   1. The reference interpreter (TestContract) — walks AST, uses real WOTS+ verification
 *   2. The compiled Bitcoin Script (ScriptExecutionContract) — actual BSV script execution
 *
 * If both paths agree, the compiler's opcode generation is correct.
 */
import { describe, it, expect } from 'vitest';
import { TestContract } from '../test-contract.js';
import { ScriptExecutionContract } from '../script-execution.js';
import { wotsKeygen, wotsSign } from '../crypto/wots.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

const PQ_WALLET_SOURCE = `
class PQWallet extends SmartContract {
  readonly pubkey: ByteString;
  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }
  public spend(msg: ByteString, sig: ByteString) {
    assert(verifyWOTS(msg, sig, this.pubkey));
  }
}
`;

describe('WOTS+ dual-oracle: interpreter vs compiled script', () => {
  const seed = new Uint8Array(32);
  seed[0] = 0x42;
  const { sk, pk } = wotsKeygen(seed);
  const pkHex = toHex(pk);

  it('both paths accept a valid WOTS+ signature', () => {
    const msg = new TextEncoder().encode('dual oracle test');
    const sig = wotsSign(msg, sk);
    const msgHex = toHex(msg);
    const sigHex = toHex(sig);

    // Path 1: Interpreter
    const interp = TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: pkHex });
    const interpResult = interp.call('spend', { msg: msgHex, sig: sigHex });
    expect(interpResult.success).toBe(true);

    // Path 2: Compiled Script
    const compiled = ScriptExecutionContract.fromSource(
      PQ_WALLET_SOURCE,
      { pubkey: pkHex },
    );
    // Check that compilation succeeds and produces script hex
    expect(compiled.scriptHex).toBeTruthy();
    expect(compiled.scriptHex.length).toBeGreaterThan(100);

    // Execute the compiled script
    const scriptResult = compiled.execute('spend', [msgHex, sigHex]);
    expect(scriptResult.success).toBe(interpResult.success);
  });

  it('both paths reject a tampered signature', () => {
    const msg = new TextEncoder().encode('tamper test');
    const sig = wotsSign(msg, sk);
    const badSig = new Uint8Array(sig);
    badSig[0]! ^= 0xff;
    const msgHex = toHex(msg);
    const badSigHex = toHex(badSig);

    // Path 1: Interpreter
    const interp = TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: pkHex });
    const interpResult = interp.call('spend', { msg: msgHex, sig: badSigHex });
    expect(interpResult.success).toBe(false);

    // Path 2: Compiled Script
    const compiled = ScriptExecutionContract.fromSource(
      PQ_WALLET_SOURCE,
      { pubkey: pkHex },
    );
    const scriptResult = compiled.execute('spend', [msgHex, badSigHex]);
    expect(scriptResult.success).toBe(interpResult.success);
  });
});
