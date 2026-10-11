/**
 * F-286 — a spender-chosen Rabin modulus is a universal forgery; the compiler
 * now refuses to build one.
 *
 * Before the fix, `public check(msg, sig, padding, pk: RabinPubKey)` compiled,
 * and on @bsv/sdk's real `Spend` the spender could pass `pk = 1, sig = 0,
 * padding = ''` for ANY message: `(0² + 0) mod 1 == SHA256(msg) mod 1`. No
 * factoring, no key, no signature (the attempt-1 repro saved in the
 * remediation log shows `n=1 {"reached":true,"vm":true}` at HEAD).
 *
 * After the fix the frontend refuses that contract (F-286 rule, user decision
 * R78), so the forgery is not expressible. The control is the shape authors
 * are meant to write — the modulus as a contract property baked at deploy —
 * where an honest signature passes real `Spend` and the same `sig = 0, empty
 * padding` witness is refused, because the spender no longer chooses `n`.
 *
 * Oracle: @bsv/sdk `Spend` via `runStatelessSigned` (consensus flags). The ANF
 * interpreter is a second opinion only.
 *
 * What this proves: the TS-tier compiler refuses the spender-supplied-modulus
 * contract that real `Spend` would have accepted a forged witness for, and the
 * property-modulus contract still verifies an honest signature and refuses the
 * forgery shape on real `Spend`.
 * What it does NOT prove: the six peer tiers (conformance/negatives N220–N228
 * and each tier's own test), or a hostile `--ir` JSON that names a parameter as
 * the modulus (`--ir` input skips the frontend). It also says nothing about a
 * WEAK key the deployer chose themselves (F-047 covers small moduli).
 */
import { describe, it, expect } from 'vitest';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';
import { rabinSign, rabinVerify, RABIN_TEST_KEY } from '../crypto/rabin.js';

const PARAM_SOURCE = `
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';
class RabinOperands extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public check(msg: ByteString, sig: RabinSig, padding: ByteString, pk: RabinPubKey) {
    assert(verifyRabinSig(msg, sig, padding, pk));
  }
}`;

const PROPERTY_SOURCE = `
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';
class RabinOperands extends SmartContract {
  readonly pk: RabinPubKey;
  constructor(pk: RabinPubKey) { super(pk); this.pk = pk; }
  public check(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.pk));
  }
}`;

const MSG = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);

/** Non-negative value as a minimal Script number. */
function scriptNum(v: bigint): Uint8Array {
  const out: number[] = [];
  let x = v;
  while (x > 0n) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  if (out.length > 0 && out[out.length - 1]! & 0x80) out.push(0);
  return new Uint8Array(out);
}

describe('F-286: verifyRabinSig with a spender-chosen modulus', () => {
  it('the attempt-1 forgery contract (pk is a public-method parameter) no longer compiles', () => {
    expect(() =>
      runStatelessSigned({
        source: PARAM_SOURCE,
        fileName: 'RabinOperands.runar.ts',
        method: 'check',
        // pk = 1, sig = 0, padding = '': the forged witness from the repro.
        args: [MSG, new Uint8Array([]), new Uint8Array([]), new Uint8Array([0x01])],
        constructorArgs: { tag: 1n },
        checkInterpreter: false,
      }),
    ).toThrow(/verifyRabinSig public key \(4th argument\) must be a contract property or a literal/);
  });

  describe('control: the modulus is a contract property', () => {
    const { sig, padding } = rabinSign(MSG, RABIN_TEST_KEY);
    const run = (sigBytes: Uint8Array, paddingBytes: Uint8Array) =>
      runStatelessSigned({
        source: PROPERTY_SOURCE,
        fileName: 'RabinOperands.runar.ts',
        method: 'check',
        args: [MSG, sigBytes, paddingBytes],
        constructorArgs: { pk: RABIN_TEST_KEY.n },
      });

    it('an honest signature passes real Spend', () => {
      expect(rabinVerify(MSG, sig, scriptNum(padding), RABIN_TEST_KEY.n)).toBe(true);
      const r = run(scriptNum(sig), scriptNum(padding));
      expect(r.reachedEngine).toBe(true);
      expect(r.vmAccepted, `Spend refused an honest signature: ${r.vmError}`).toBe(true);
      expect(r.interpreterAccepted).toBe(true);
    });

    it('the forgery witness (sig = 0, empty padding) is refused: the spender cannot pick n', () => {
      const r = run(new Uint8Array([]), new Uint8Array([]));
      expect(r.reachedEngine).toBe(true);
      expect(r.vmAccepted).toBe(false);
      expect(r.interpreterAccepted).toBe(false);
    });
  });
});
