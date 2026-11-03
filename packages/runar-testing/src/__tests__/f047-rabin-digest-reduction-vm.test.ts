/**
 * F-047 — the on-chain Rabin verifier reduces the SHA-256 digest mod n.
 *
 * Every off-chain verifier (`rabinVerify` here, `runar-lang` builtins,
 * `runar-go/rabin.go`, …) checks
 *
 *     (sig² + padding) mod n == SHA256(msg) mod n
 *
 * Before F-047 the emitted script reduced only the left side and compared it
 * against the UNREDUCED 256-bit digest. Whenever n <= SHA256(msg) the two
 * definitions disagree: a signature the off-chain verifier accepts is refused
 * on-chain (funds stuck behind an honest attestation), and the TestContract
 * interpreter green-lights a spend the network rejects.
 *
 * Forced near-miss: n = 251 (so every digest is far above n), sig = 0,
 * padding = SHA256(msg) mod 251. Off-chain accepts by construction. The same
 * shape with padding + 1 must be refused by both.
 *
 * Oracle: @bsv/sdk's production `Spend` (via `runStatelessSigned`, consensus
 * flags), never the ANF interpreter. The interpreter verdict is compared only
 * as a second opinion.
 *
 * What this proves: the compiled TS-tier script now agrees with the off-chain
 * Rabin definition for a modulus below the digest, in both directions (honest
 * accept, wrong padding reject), and still accepts an honest signature under
 * the >2^256 test key.
 * What it does NOT prove: anything about the six peer tiers (pinned by the
 * oracle-price conformance golden + its real-crypto witness), nor anything
 * about negative or zero moduli / negative operands (F-144's scope). A
 * 251-modulus key is trivially forgeable; accepting it is the DEFINED
 * semantics, not a security property.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';
import { rabinSign, rabinVerify, RABIN_TEST_KEY } from '../crypto/rabin.js';

const SOURCE = `
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class RabinCheck extends SmartContract {
  readonly pk: RabinPubKey;

  constructor(pk: RabinPubKey) {
    super(pk);
    this.pk = pk;
  }

  public check(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(verifyRabinSig(msg, sig, padding, this.pk));
  }
}
`;

const MSG = new TextEncoder().encode('F-047 small-modulus near-miss');

function digestLE(msg: Uint8Array): bigint {
  const h = createHash('sha256').update(msg).digest();
  let v = 0n;
  for (let i = h.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(h[i]!);
  return v;
}

/** Non-negative value as a minimal Script number (unsigned-LE + sign byte if needed). */
function scriptNum(v: bigint): Uint8Array {
  if (v === 0n) return new Uint8Array([]);
  const out: number[] = [];
  let x = v;
  while (x > 0n) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  if (out[out.length - 1]! & 0x80) out.push(0);
  return new Uint8Array(out);
}

function run(n: bigint, sig: bigint, padding: bigint) {
  return runStatelessSigned({
    source: SOURCE,
    fileName: 'RabinCheck.runar.ts',
    method: 'check',
    args: [MSG, scriptNum(sig), scriptNum(padding)],
    constructorArgs: { pk: n },
  });
}

describe('F-047: on-chain Rabin verify reduces SHA256(msg) mod n', () => {
  const n = 251n;
  const h = digestLE(MSG);
  const padding = h % n;

  it('precondition: the digest exceeds n and the padding is a non-zero residue', () => {
    expect(h > n).toBe(true);
    expect(padding > 0n).toBe(true);
  });

  it('n=251, sig=0, padding=SHA256(msg) mod n: off-chain accepts AND real Spend accepts', () => {
    expect(rabinVerify(MSG, 0n, scriptNum(padding), n)).toBe(true);
    const r = run(n, 0n, padding);
    expect(r.reachedEngine).toBe(true);
    expect(r.vmAccepted, `Spend refused a signature the off-chain verifier accepts: ${r.vmError}`).toBe(true);
    expect(r.interpreterAccepted).toBe(true);
  });

  it('n=251, wrong padding (residue + 1): off-chain rejects AND real Spend rejects', () => {
    const bad = (padding + 1n) % n;
    expect(rabinVerify(MSG, 0n, scriptNum(bad), n)).toBe(false);
    const r = run(n, 0n, bad);
    expect(r.reachedEngine).toBe(true);
    expect(r.vmAccepted).toBe(false);
    expect(r.interpreterAccepted).toBe(false);
  });

  it('honest signature under the >2^256 test key is still accepted on-chain', () => {
    const { sig, padding: p } = rabinSign(MSG, RABIN_TEST_KEY);
    expect(rabinVerify(MSG, sig, scriptNum(p), RABIN_TEST_KEY.n)).toBe(true);
    const r = run(RABIN_TEST_KEY.n, sig, p);
    expect(r.vmAccepted, `vmErr=${r.vmError}`).toBe(true);
  });
});
