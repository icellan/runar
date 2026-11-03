import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { TEST_MESSAGE_DIGEST, verifyTestMessageSigHex } from '../crypto/ecdsa.js';

// ---------------------------------------------------------------------------
// F-242 (CL-BUG-160): the interpreter's checkSig (`verifyTestMessageSig`,
// REAL ECDSA over the fixed TEST_MESSAGE) must apply strict DER, as a node
// does. It parsed through @bsv/sdk `Signature.fromDER`, which accepts an
// INTEGER whose top bit is set without the 0x00 sign pad.
//
// Uses the conformance/sdk-der vectors signed over SHA256(TEST_MESSAGE) —
// the only digest this verifier checks against. Proves it reaches the fixture
// verdict on each of them (controls accepted, re-encodings refused). Does not
// prove anything about the vectors over other digests; der-strict.test.ts in
// runar-sdk covers those, and the fixture's own integrity.
// ---------------------------------------------------------------------------

const fixture = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-der/vectors.json'),
    'utf8',
  ),
) as { pubkey: string; vectors: Array<{ id: string; digest: string; sig: string; ok: boolean }> };

const vectors = fixture.vectors.filter((v) => v.digest === TEST_MESSAGE_DIGEST);

describe('verifyTestMessageSig strict DER (F-242)', () => {
  it('has vectors over the test-message digest, both controls and refusals', () => {
    expect(vectors.some((v) => v.ok)).toBe(true);
    expect(vectors.some((v) => !v.ok)).toBe(true);
  });

  for (const v of vectors) {
    it(`${v.ok ? 'accepts' : 'refuses'} ${v.id}`, () => {
      expect(verifyTestMessageSigHex(v.sig, fixture.pubkey)).toBe(v.ok);
    });
  }
});
