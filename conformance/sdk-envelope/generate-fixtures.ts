#!/usr/bin/env npx tsx
/**
 * Generate cross-tier interop fixtures for the signed-envelope wire protocol.
 *
 * Produces `conformance/sdk-envelope/fixtures.json` with:
 *  - canonical_json_vectors: input value → expected canonical JSON bytes.
 *    Every tier's `canonical_json` MUST produce the documented bytes for
 *    the documented input.
 *  - valid_envelope: a TS-signed envelope using Alice's well-known privkey
 *    (0x...01). Every tier's `verify_envelope` MUST return ok=true when
 *    given this fixture and the documented `now_ms` (nonce + 500ms).
 *  - rejection_vectors: one tampered envelope per `VerifyEnvelopeReason`.
 *    Every tier MUST return the listed reason.
 *
 * Re-run from repo root: `npx tsx conformance/sdk-envelope/generate-fixtures.ts`.
 */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BigNumber, PrivateKey, Utils } from '@bsv/sdk';
import { sign as ecdsaSignRaw } from '@bsv/sdk/primitives/ECDSA';
import { canonicalJson, signEnvelope, type EnvelopeSigner } from '../../packages/runar-sdk/src/envelope.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const ALICE = new PrivateKey(1n);
const ALICE_PUB_HEX = ALICE.toPublicKey().toDER('hex') as string;

class TestSigner implements EnvelopeSigner {
  constructor(private readonly priv: PrivateKey) {}
  async signHash(digest: number[]): Promise<string> {
    const msgBN = new BigNumber(digest);
    const sig = ecdsaSignRaw(msgBN, this.priv as unknown as BigNumber, true);
    return Utils.toHex(sig.toDER() as number[]);
  }
  async getPublicKey(): Promise<string> {
    return ALICE_PUB_HEX;
  }
}

const NONCE = 1_700_000_000_000;        // arbitrary fixed timestamp
const TTL = 30_000;
const EXPIRES_AT = NONCE + TTL;

const canonicalVectors = [
  { input: { a: 1, b: 2 },                           expected: '{"a":1,"b":2}' },
  { input: { b: 2, a: 1 },                           expected: '{"a":1,"b":2}' },
  { input: [1, 2, 3],                                expected: '[1,2,3]' },
  { input: null,                                     expected: 'null' },
  { input: true,                                     expected: 'true' },
  { input: false,                                    expected: 'false' },
  { input: 42,                                       expected: '42' },
  { input: 0,                                        expected: '0' },
  { input: -7,                                       expected: '-7' },
  { input: 'hi',                                     expected: '"hi"' },
  { input: '',                                       expected: '""' },
  { input: { kind: 'hello', n: 7 },                  expected: '{"kind":"hello","n":7}' },
  {
    input: {
      outer: { z: 1, a: [3, 2, 1] },
      list: [{ y: 1, x: 2 }],
      n: null,
      b: true,
      s: 'hi',
    },
    expected: '{"b":true,"list":[{"x":2,"y":1}],"n":null,"outer":{"a":[3,2,1],"z":1},"s":"hi"}',
  },
  // String escaping coverage.
  { input: { t: 'a\tb' },                            expected: '{"t":"a\\tb"}' },
  { input: { q: 'say "hi"' },                        expected: '{"q":"say \\"hi\\""}' },
  { input: { b: '\\' },                              expected: '{"b":"\\\\"}' },
];

async function main() {
  // Generate canonical vectors actively (verifies our impl against the
  // hand-written expected strings before they get committed).
  for (const v of canonicalVectors) {
    const got = canonicalJson(v.input);
    if (got !== v.expected) {
      throw new Error(`canonicalJson mismatch:\n  input: ${JSON.stringify(v.input)}\n  expected: ${v.expected}\n       got: ${got}`);
    }
  }

  const signer = new TestSigner(ALICE);
  const validEnvelope = await signEnvelope({
    data: { kind: 'hello', n: 7 },
    signer,
    ttlMs: TTL,
  });
  // Override the synthesized nonce/expiresAt with our fixed values for
  // determinism. We re-sign with the same canonical payload.
  const fixedPayload = canonicalJson({ kind: 'hello', n: 7, nonce: NONCE, expiresAt: EXPIRES_AT });
  const fixedDigest = await import('node:crypto').then((c) =>
    Array.from(c.createHash('sha256').update(fixedPayload, 'utf-8').digest())
  );
  const fixedSig = await signer.signHash(fixedDigest);

  const fixture = {
    fixture_version: 1,
    notes:
      'Cross-tier interop fixture for the signed-envelope wire protocol. ' +
      'Every Runar SDK (TS/Go/Rust/Python/Zig/Ruby/Java) must consume this ' +
      'and produce byte-identical canonical_json output + verify the valid ' +
      'envelope + reject each tampered envelope with the listed reason.',
    alice_priv_hex: '0000000000000000000000000000000000000000000000000000000000000001',
    alice_pub_hex: ALICE_PUB_HEX,
    nonce: NONCE,
    expires_at: EXPIRES_AT,
    verify_now_ms: NONCE + 500,
    canonical_json_vectors: canonicalVectors,
    valid_envelope: {
      payload: fixedPayload,
      sig: fixedSig,
      pubkey: ALICE_PUB_HEX,
      nonce: NONCE,
      expiresAt: EXPIRES_AT,
    },
    rejection_vectors: [
      {
        reason: 'missing-fields',
        envelope: { payload: fixedPayload, sig: '', pubkey: ALICE_PUB_HEX, nonce: NONCE, expiresAt: EXPIRES_AT },
      },
      {
        reason: 'expired',
        envelope: {
          payload: canonicalJson({ ok: 1, nonce: 1_000_000_000_000, expiresAt: 1_000_000_000_001 }),
          sig: fixedSig,
          pubkey: ALICE_PUB_HEX,
          nonce: 1_000_000_000_000,
          expiresAt: 1_000_000_000_001,
        },
      },
      {
        reason: 'bad-json',
        envelope: { payload: 'not json{', sig: fixedSig, pubkey: ALICE_PUB_HEX, nonce: NONCE, expiresAt: EXPIRES_AT },
      },
      {
        reason: 'envelope-mismatch',
        envelope: { payload: fixedPayload, sig: fixedSig, pubkey: ALICE_PUB_HEX, nonce: NONCE + 1, expiresAt: EXPIRES_AT },
      },
      {
        reason: 'bad-sig',
        // Flip a middle hex char.
        envelope: {
          payload: fixedPayload,
          sig: fixedSig.slice(0, fixedSig.length / 2) + (fixedSig[fixedSig.length / 2] === '1' ? '2' : '1') + fixedSig.slice(fixedSig.length / 2 + 1),
          pubkey: ALICE_PUB_HEX,
          nonce: NONCE,
          expiresAt: EXPIRES_AT,
        },
      },
    ],
    note_on_pubkey_not_allowed:
      'pubkey-not-allowed cannot be expressed in a tier-agnostic fixture: it ' +
      'depends on caller-supplied expected_keys. Each tier verifies this ' +
      'reason in its own unit tests by passing a non-matching allowlist; the ' +
      'wire bytes are independent.',
  };

  const outPath = join(__dirname, 'fixtures.json');
  writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n');
  console.log(`Wrote ${outPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
