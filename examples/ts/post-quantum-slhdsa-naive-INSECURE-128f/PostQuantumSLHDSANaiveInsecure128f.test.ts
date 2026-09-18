import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, slhKeygen, slhSign, SLH_SHA2_128f, runSlowTests } from 'runar-testing';
import { compile } from 'runar-compiler';

/**
 * R-193 / R-106 — the 128f SLH-DSA parameter set had no example-layer test.
 *
 * `conformance/` carries golden-hex coverage for all six parameter sets, so
 * this is defence in depth rather than a total absence: what was missing is the
 * SOURCE-semantics side, where a signature is actually made and actually
 * verified rather than a byte string being compared to a stored one.
 *
 * PEDAGOGY, inherited from the 128s sibling: this contract is deliberately
 * INSECURE. `verifySLHDSA_SHA2_128f(msg, sig, pubkey)` proves only that `sig`
 * signs `msg` under `pubkey`; `msg` is a free unlocking-script argument with no
 * link to the spending transaction, so anyone holding ANY valid (msg, sig) pair
 * under that key can spend. The "FLAW" case below asserts that, on purpose — if
 * it ever starts failing, the contract stopped being the teaching example it
 * claims to be.
 *
 * The signing cases are gated behind `runSlowTests` (SLH-DSA keygen and signing
 * are expensive). The compile-shape cases are NOT gated, so this file still
 * asserts something on an ordinary run instead of skipping to a green nothing.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'PostQuantumSLHDSANaiveInsecure128f.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('PostQuantumSLHDSANaiveInsecure128f (always-on shape checks)', () => {
  it('compiles', () => {
    const r = compile(source, { fileName: FILE });
    expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
  });

  it('calls the 128f verifier and not another parameter set', () => {
    expect(
      source.includes('verifySLHDSA_SHA2_128f('),
      'the directory name promises 128f; a contract calling a different ' +
        'parameter set here would leave 128f untested while looking covered',
    ).toBe(true);
    const others = ['128s', '128f', '192s', '192f', '256s', '256f'].filter((p) => p !== '128f');
    for (const p of others) {
      expect(source.includes(`verifySLHDSA_SHA2_${p}(`), `also calls ${p}`).toBe(false);
    }
  });
});

describe.skipIf(!runSlowTests)('PostQuantumSLHDSANaiveInsecure128f (real signatures)', () => {
  const params = SLH_SHA2_128f;
  const seed = new Uint8Array(3 * params.n);
  seed[0] = 0x42;
  const { sk, pk } = slhKeygen(params, seed);
  const pubkeyHex = toHex(pk);

  it('accepts a real signature under the deployed key', () => {
    const msg = new Uint8Array(32);
    msg[0] = 0xab;
    const sig = slhSign(params, msg, sk);
    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE);
    const r = c.call('spend', { msg: toHex(msg), sig: toHex(sig) });
    expect(r.success, r.error).toBe(true);
  });

  it('rejects a signature under a DIFFERENT key', () => {
    const otherSeed = new Uint8Array(3 * params.n);
    otherSeed[0] = 0x43;
    const other = slhKeygen(params, otherSeed);
    const msg = new Uint8Array(32);
    msg[0] = 0xab;
    const sig = slhSign(params, msg, other.sk);
    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE);
    expect(c.call('spend', { msg: toHex(msg), sig: toHex(sig) }).success).toBe(false);
  });

  it('FLAW (deliberate): any msg the holder can sign is accepted', () => {
    const arbitrary = new Uint8Array(32);
    arbitrary[0] = 0xcd;
    const sig = slhSign(params, arbitrary, sk);
    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE);
    expect(
      c.call('spend', { msg: toHex(arbitrary), sig: toHex(sig) }).success,
      'the message is not bound to the spending transaction — that is the ' +
        'lesson this example exists to teach',
    ).toBe(true);
  });
});
