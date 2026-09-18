#!/usr/bin/env npx tsx
/**
 * Validate the cross-tier signed-envelope fixture against the TypeScript
 * reference implementation.
 *
 * `conformance/sdk-envelope/fixtures.json` is the frozen, hand-curated wire
 * fixture that all six non-TS SDKs validate against (canonicalJson +
 * signEnvelope/verifyEnvelope). This script is the TS tier's drift guard: it
 * LOADS the committed fixture — it never rewrites it, so the curated vectors
 * and their `_vector_id` / `_audit_ref` / `_notes` annotations are preserved —
 * and asserts that every TS-derived byte still matches:
 *   - canonicalJson(input) === expected   for every canonical_json_vector
 *     (including the RFC 8785 parity gates v18/v18b/v19/v20/v21).
 *   - canonicalJson is idempotent on valid_envelope.payload.
 *   - the valid_envelope signature verifies for its payload under the
 *     documented signer pubkey (canonicalJson + sha256 + ECDSA).
 *
 * If TS's canonicalJson or signing path drifts from the committed bytes, this
 * fails — which is what stops the six consumers from silently validating
 * against a stale fixture. The lone-surrogate rejection vectors and the
 * verifyEnvelope rejection vectors are intentionally NOT checked here: they
 * depend on per-tier rejection semantics / an injectable clock and are owned
 * by each tier's interop test.
 *
 * Run from repo root: `cd conformance && npx tsx sdk-envelope/validate-fixtures.ts`.
 * Exits non-zero on the first mismatch.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BigNumber, Hash, PrivateKey, PublicKey, Signature, Utils } from '@bsv/sdk';
import { verify as ecdsaVerifyRaw, sign as ecdsaSign } from '@bsv/sdk/primitives/ECDSA';
// The SDK's wire `canonicalJson` (runar-sdk/src/envelope.ts) is a literal
// re-export of this `canonicalJsonStringify`, so importing the source here
// tests the identical function while avoiding a build of runar-ir-schema's
// dist — this guard stays install-only in CI.
import { canonicalJsonStringify as canonicalJson } from '../../packages/runar-ir-schema/src/canonical-json.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ALICE_PUB_HEX = new PrivateKey(1).toPublicKey().toDER('hex') as string;

function fail(msg: string): never {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

function main(): void {
  const fixturePath = join(__dirname, 'fixtures.json');
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

  // 1. Every canonical_json_vector must round-trip through the TS canonicalJson.
  const vectors = fixture.canonical_json_vectors as Array<{ input: unknown; expected: string; _vector_id?: string }>;
  if (!Array.isArray(vectors) || vectors.length === 0) fail('canonical_json_vectors missing or empty');
  for (const [i, v] of vectors.entries()) {
    const got = canonicalJson(v.input);
    if (got !== v.expected) {
      const id = v._vector_id ? ` (${v._vector_id})` : '';
      fail(`canonical_json_vectors[${i}]${id}: expected ${JSON.stringify(v.expected)}, got ${JSON.stringify(got)}`);
    }
  }

  // 2. The valid_envelope must verify against the TS reference.
  const env = fixture.valid_envelope as { payload: string; sig: string; pubkey: string };
  if (!env || typeof env.payload !== 'string' || typeof env.sig !== 'string' || typeof env.pubkey !== 'string') {
    fail('valid_envelope missing payload/sig/pubkey');
  }
  if (env.pubkey !== ALICE_PUB_HEX) {
    fail(`valid_envelope.pubkey ${env.pubkey} != documented signer ${ALICE_PUB_HEX}`);
  }
  // canonicalJson must be idempotent on the committed payload (drift guard).
  const reCanon = canonicalJson(JSON.parse(env.payload));
  if (reCanon !== env.payload) {
    fail(`canonicalJson not idempotent on valid_envelope.payload:\n  committed:  ${env.payload}\n  recomputed: ${reCanon}`);
  }
  // The committed signature must verify for sha256(payload) under the pubkey.
  const digest = Hash.sha256(Utils.toArray(env.payload, 'utf8'));
  let sigOk = false;
  try {
    sigOk = ecdsaVerifyRaw(
      new BigNumber(digest),
      Signature.fromDER(Utils.toArray(env.sig, 'hex')),
      PublicKey.fromDER(Utils.toArray(env.pubkey, 'hex')),
    );
  } catch (e) {
    fail(`valid_envelope signature failed to parse/verify: ${(e as Error).message}`);
  }
  if (!sigOk) {
    fail('valid_envelope.sig does not verify for its payload under the TS reference (canonicalJson/sha256/ECDSA drift)');
  }

  // 3. GAP-064 signing vectors: re-derive payload + deterministic low-S DER
  //    signature from the TS reference and assert byte-identity. This is the
  //    drift guard for the cross-tier signing-reproduction matrix — if TS's
  //    canonicalJson or its RFC 6979 (plain-SHA-256-nonce) ECDSA path drifts
  //    from the committed bytes, this fails before any non-TS tier replays
  //    against a stale expected_sig.
  const alicePriv = new PrivateKey(1);
  const signingVectors = fixture.signing_vectors as Array<{
    _vector_id?: string;
    data: Record<string, unknown>;
    nonce: number;
    expiresAt: number;
    expected_payload: string;
    expected_sig: string;
  }>;
  if (!Array.isArray(signingVectors) || signingVectors.length === 0) {
    fail('signing_vectors missing or empty');
  }
  for (const [i, v] of signingVectors.entries()) {
    const id = v._vector_id ? ` (${v._vector_id})` : '';
    const payload = canonicalJson({ ...v.data, nonce: v.nonce, expiresAt: v.expiresAt });
    if (payload !== v.expected_payload) {
      fail(`signing_vectors[${i}]${id}: expected_payload ${JSON.stringify(v.expected_payload)}, got ${JSON.stringify(payload)}`);
    }
    const d = Hash.sha256(Utils.toArray(payload, 'utf8'));
    // forceLowS=true ⇒ canonical low-S form; the digest IS the message
    // representative (sign the prehash directly, never re-hash).
    const sig = ecdsaSign(new BigNumber(d), alicePriv, true);
    const der = Utils.toHex(sig.toDER() as number[]);
    if (der !== v.expected_sig) {
      fail(`signing_vectors[${i}]${id}: expected_sig\n  committed:  ${v.expected_sig}\n  recomputed: ${der}`);
    }
  }

  // 4. R-260 depth vectors. Each one must (a) actually have the nesting depth
  //    it claims, measured the same way every tier's guard measures it — the
  //    maximum number of simultaneously-open {/[ containers outside strings —
  //    and (b) carry a signature that genuinely verifies. (b) is what gives the
  //    over-limit vector its teeth: a tier that fails to enforce the bound
  //    returns ok:true rather than falling through to some other rejection, so
  //    the interop assertion cannot pass by accident.
  const depthLimit = fixture.payload_depth_limit as number;
  if (typeof depthLimit !== 'number') fail('payload_depth_limit missing');
  const depthVectors = fixture.depth_vectors as Array<{
    _vector_id?: string;
    max_depth: number;
    expect_ok: boolean;
    reason?: string;
    envelope: { payload: string; sig: string; pubkey: string };
  }>;
  if (!Array.isArray(depthVectors) || depthVectors.length === 0) fail('depth_vectors missing or empty');

  const measureDepth = (payload: string): number => {
    let depth = 0;
    let max = 0;
    let inString = false;
    let escaped = false;
    for (const c of payload) {
      if (inString) {
        if (escaped) escaped = false;
        else if (c === '\\') escaped = true;
        else if (c === '"') inString = false;
        continue;
      }
      if (c === '"') inString = true;
      else if (c === '{' || c === '[') {
        depth++;
        if (depth > max) max = depth;
      } else if ((c === '}' || c === ']') && depth > 0) depth--;
    }
    return max;
  };

  let sawAtLimit = false;
  let sawOverLimit = false;
  for (const [i, v] of depthVectors.entries()) {
    const id = v._vector_id ? ` (${v._vector_id})` : '';
    const measured = measureDepth(v.envelope.payload);
    if (measured !== v.max_depth) {
      fail(`depth_vectors[${i}]${id}: declares max_depth ${v.max_depth}, payload measures ${measured}`);
    }
    if (v.envelope.pubkey !== ALICE_PUB_HEX) {
      fail(`depth_vectors[${i}]${id}: pubkey ${v.envelope.pubkey} != documented signer ${ALICE_PUB_HEX}`);
    }
    const d = Hash.sha256(Utils.toArray(v.envelope.payload, 'utf8'));
    let ok = false;
    try {
      ok = ecdsaVerifyRaw(
        new BigNumber(d),
        Signature.fromDER(Utils.toArray(v.envelope.sig, 'hex')),
        PublicKey.fromDER(Utils.toArray(v.envelope.pubkey, 'hex')),
      );
    } catch (e) {
      fail(`depth_vectors[${i}]${id}: signature failed to parse/verify: ${(e as Error).message}`);
    }
    if (!ok) {
      fail(`depth_vectors[${i}]${id}: signature does not verify — the vector would reject as bad-sig and prove nothing about the depth bound`);
    }
    if (v.max_depth === depthLimit && v.expect_ok) sawAtLimit = true;
    if (v.max_depth === depthLimit + 1 && !v.expect_ok && v.reason === 'bad-json') sawOverLimit = true;
  }
  if (!sawAtLimit) fail(`depth_vectors must carry an accepted vector at exactly max_depth ${depthLimit}`);
  if (!sawOverLimit) {
    fail(`depth_vectors must carry a bad-json vector at exactly max_depth ${depthLimit + 1}`);
  }

  console.log(`OK: ${vectors.length} canonical-JSON vectors + valid envelope signature + ${signingVectors.length} signing vectors + ${depthVectors.length} depth vectors validate against the TS reference.`);
}

main();
