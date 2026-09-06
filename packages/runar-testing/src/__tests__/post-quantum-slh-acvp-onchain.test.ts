/**
 * NIST ACVP conformance test for the ON-CHAIN SLH-DSA-SHA2-128s verifier.
 *
 * Issue #137. The SLH-DSA implementation used to be self-consistent but NOT
 * FIPS-205 conformant: it round-tripped its own signatures while rejecting the
 * authoritative NIST vector. Every SLH-DSA test in the repo generated its own
 * signature with the same buggy signer, so the whole family was self-graded and
 * the deviation was invisible.
 *
 * This test closes that hole for the compiled script: it replays the vendored
 * NIST ACVP vector (SLH-DSA-SHA2-128s, internal interface, tgId 31 / tcId 422,
 * testPassed=true) through BOTH oracles — the reference interpreter and the
 * emitted Bitcoin Script — using a signature this repo did not produce.
 *
 * The two FIPS-205 deviations this pins down (see #137):
 *   1. §11.2.1 — H_msg's MGF1 seed must be
 *      R || PK.seed || SHA-256(R || PK.seed || PK.root || M).
 *   2. Alg. 8 lines 8-11 — wots_pkFromSig must restore the key pair address
 *      after setTypeAndClear(WOTS_PK) zeroes ADRS bytes 20-31.
 * Neither deviation alone is sufficient to reject the vector; both had to be
 * fixed, in the native impl AND in the on-chain codegen, for this to pass.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { TestContract } from '../test-contract.js';
import { ScriptExecutionContract } from '../script-execution.js';
import { runSlowTests } from '../test-env.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const KAT_PATH = join(
  __dirname, '..', '..', '..', '..',
  'conformance', 'runtime-vectors', 'slh-dsa-acvp-kat.json',
);

interface AcvpVector {
  name: string;
  param_set: string;
  pk: string;
  message: string;
  signature: string;
  expected_valid: boolean;
}

const kat = JSON.parse(readFileSync(KAT_PATH, 'utf8')) as {
  slh_dsa_acvp: AcvpVector[];
};

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

/** Flip the low bit of the final byte — must invalidate the signature. */
function tamper(sigHex: string): string {
  const last = parseInt(sigHex.slice(-2), 16) ^ 0x01;
  return sigHex.slice(0, -2) + last.toString(16).padStart(2, '0');
}

describe('SLH-DSA-SHA2-128s NIST ACVP vector (on-chain)', () => {
  const vectors = kat.slh_dsa_acvp.filter(v => v.param_set === 'SLH-DSA-SHA2-128s');

  it('vendored KAT carries at least one SLH-DSA-SHA2-128s vector', () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  for (const v of vectors) {
    // The vector is authoritative: NIST published it with testPassed=true.
    expect(v.expected_valid).toBe(true);

    it(`interpreter accepts the NIST signature (${v.name})`, () => {
      const contract = TestContract.fromSource(SOURCE, { pubkey: v.pk });
      const result = contract.call('spend', { msg: v.message, sig: v.signature });
      expect(result.success).toBe(true);
    });

    it(`interpreter rejects a 1-bit-tampered NIST signature (${v.name})`, () => {
      const contract = TestContract.fromSource(SOURCE, { pubkey: v.pk });
      const result = contract.call('spend', { msg: v.message, sig: tamper(v.signature) });
      expect(result.success).toBe(false);
    });

    it.skipIf(!runSlowTests)(
      `compiled script accepts the NIST signature (${v.name})`,
      () => {
        const contract = ScriptExecutionContract.fromSource(SOURCE, { pubkey: v.pk });
        const result = contract.execute('spend', [v.message, v.signature]);
        if (!result.success) {
          console.log('Script execution failed:', result.error);
        }
        expect(result.success).toBe(true);
      },
      120000,
    );

    it.skipIf(!runSlowTests)(
      `compiled script rejects a 1-bit-tampered NIST signature (${v.name})`,
      () => {
        const contract = ScriptExecutionContract.fromSource(SOURCE, { pubkey: v.pk });
        const result = contract.execute('spend', [v.message, tamper(v.signature)]);
        expect(result.success).toBe(false);
      },
      120000,
    );
  }
});
