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

  // 5. F-138 malleability vectors. Each must (a) really carry a high-S
  //    signature (s > N/2) — otherwise it pins nothing — and (b) verify under
  //    the TS reference's raw ECDSA, so a tier that rejects it can only be
  //    doing so on the low-S rule, not on a broken signature.
  const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
  const malleabilityVectors = fixture.malleability_vectors as Array<{
    _vector_id?: string;
    expect_ok: boolean;
    envelope: { payload: string; sig: string; pubkey: string };
  }>;
  if (!Array.isArray(malleabilityVectors) || malleabilityVectors.length === 0) {
    fail('malleability_vectors missing or empty');
  }
  for (const [i, v] of malleabilityVectors.entries()) {
    const id = v._vector_id ? ` (${v._vector_id})` : '';
    const sig = Signature.fromDER(Utils.toArray(v.envelope.sig, 'hex'));
    if (BigInt('0x' + sig.s.toHex()) <= N / 2n) {
      fail(`malleability_vectors[${i}]${id}: s is low — the vector does not exercise the high-S case`);
    }
    const d = Hash.sha256(Utils.toArray(v.envelope.payload, 'utf8'));
    const ok = ecdsaVerifyRaw(new BigNumber(d), sig, PublicKey.fromDER(Utils.toArray(v.envelope.pubkey, 'hex')));
    if (ok !== v.expect_ok) {
      fail(`malleability_vectors[${i}]${id}: TS raw ECDSA verify returned ${ok}, fixture expects ok=${v.expect_ok}`);
    }
  }

  // 6. F-242 strict-DER rejection vectors. Each `der-*` vector must re-encode
  //    a signature (`_canonical_sig`) that really verifies for its payload, so
  //    the encoding is the only thing a tier can reject it for.
  const derVectors = (fixture.rejection_vectors as Array<{
    _vector_id?: string;
    _canonical_sig?: string;
    reason: string;
    envelope: { payload: string; sig: string; pubkey: string };
  }>).filter((v) => v._vector_id?.startsWith('der-'));
  if (derVectors.length === 0) fail('rejection_vectors carries no der-* (F-242) vectors');
  for (const v of derVectors) {
    if (v.reason !== 'bad-sig') fail(`${v._vector_id}: reason must be bad-sig`);
    if (!v._canonical_sig || v._canonical_sig === v.envelope.sig) {
      fail(`${v._vector_id}: _canonical_sig missing or identical to the re-encoded sig`);
    }
    const d = Hash.sha256(Utils.toArray(v.envelope.payload, 'utf8'));
    const ok = ecdsaVerifyRaw(
      new BigNumber(d),
      Signature.fromDER(Utils.toArray(v._canonical_sig, 'hex')),
      PublicKey.fromDER(Utils.toArray(v.envelope.pubkey, 'hex')),
    );
    if (!ok) fail(`${v._vector_id}: _canonical_sig does not verify for the payload`);
  }

  // 7. GK-BUG-009 integer-token vectors (it*). Each must carry a signature
  //    that verifies for its EXACT payload text (not a canonicalized copy,
  //    which would normalise the token away), so a tier that accepts the
  //    non-integer token returns ok:true instead of falling through to
  //    bad-sig — the assertion cannot pass by accident.
  const intTokenVectors = (fixture.rejection_vectors as Array<{
    _vector_id?: string;
    reason: string;
    envelope: { payload: string; sig: string; pubkey: string };
  }>).filter((v) => /^(it|nt)\d/.test(v._vector_id ?? ''));
  if (!intTokenVectors.some((v) => /^it\d/.test(v._vector_id ?? ''))) fail('rejection_vectors carries no it* (GK-BUG-009) vectors');
  if (!intTokenVectors.some((v) => /^nt\d/.test(v._vector_id ?? ''))) fail('rejection_vectors carries no nt* (GK-BUG-009 number grammar) vectors');
  for (const v of intTokenVectors) {
    // it*: a valid JSON number that is not an integer token -> envelope-mismatch.
    // nt*: not a JSON number token at all (01, 1.) -> bad-json at parse time.
    const want = v._vector_id!.startsWith('nt') ? 'bad-json' : 'envelope-mismatch';
    if (v.reason !== want) fail(`${v._vector_id}: reason must be ${want}`);
    const d = Hash.sha256(Utils.toArray(v.envelope.payload, 'utf8'));
    const ok = ecdsaVerifyRaw(
      new BigNumber(d),
      Signature.fromDER(Utils.toArray(v.envelope.sig, 'hex')),
      PublicKey.fromDER(Utils.toArray(v.envelope.pubkey, 'hex')),
    );
    if (!ok) fail(`${v._vector_id}: signature does not verify for its payload text`);
  }

  // 8. GK-BUG-008 allowlist vectors. Must carry the row Go failed (an EMPTY
  //    list -> pubkey-not-allowed) and the null control (no allowlist -> ok).
  const allowlistVectors = fixture.allowlist_vectors as Array<{
    _vector_id?: string;
    expected_keys: string[] | null;
    expect_ok: boolean;
    reason?: string;
  }>;
  if (!Array.isArray(allowlistVectors) || allowlistVectors.length === 0) fail('allowlist_vectors missing or empty');
  if (!allowlistVectors.some((v) => Array.isArray(v.expected_keys) && v.expected_keys.length === 0 && !v.expect_ok && v.reason === 'pubkey-not-allowed')) {
    fail('allowlist_vectors must carry an empty-list vector rejected as pubkey-not-allowed');
  }
  if (!allowlistVectors.some((v) => v.expected_keys === null && v.expect_ok)) {
    fail('allowlist_vectors must carry a null (not supplied) control that is accepted');
  }

  // 9. R2-DUPKEY duplicate-key vectors. Each payload must be well-formed JSON
  //    (JSON.parse accepts it) within the depth bound, so a duplicate key is
  //    the ONLY thing wrong with it; a duplicate must really be present in
  //    every rejected vector and absent from every dkc* control; and every
  //    signature must verify for the exact payload text, except the
  //    *-precedes-bad-sig vector that pins bad-json ahead of bad-sig (its
  //    signature must NOT verify).
  const verifiesFor = (e: { payload: string; sig: string; pubkey: string }): boolean => {
    try {
      return ecdsaVerifyRaw(
        new BigNumber(Hash.sha256(Utils.toArray(e.payload, 'utf8'))),
        Signature.fromDER(Utils.toArray(e.sig, 'hex')),
        PublicKey.fromDER(Utils.toArray(e.pubkey, 'hex')),
      );
    } catch {
      return false;
    }
  };
  // Independent duplicate-key oracle: a small recursive-descent reader over
  // text JSON.parse has already accepted (so no error paths), keys decoded
  // with JSON.parse, one key set per object.
  const hasDuplicateKey = (text: string): boolean => {
    let i = 0;
    let dup = false;
    const ws = (): void => {
      while (' \t\n\r'.includes(text[i] ?? 'x')) i++;
    };
    const str = (): string => {
      const start = i++;
      while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      i++;
      return JSON.parse(text.slice(start, i)) as string;
    };
    const value = (): void => {
      ws();
      const c = text[i];
      if (c === '{') {
        i++;
        const keys = new Set<string>();
        ws();
        if (text[i] === '}') {
          i++;
          return;
        }
        for (;;) {
          ws();
          const k = str();
          if (keys.has(k)) dup = true;
          keys.add(k);
          ws();
          i++; // ':'
          value();
          ws();
          if (text[i++] === '}') return;
        }
      } else if (c === '[') {
        i++;
        ws();
        if (text[i] === ']') {
          i++;
          return;
        }
        for (;;) {
          value();
          ws();
          if (text[i++] === ']') return;
        }
      } else if (c === '"') {
        str();
      } else {
        while (i < text.length && !',]} \t\n\r'.includes(text[i]!)) i++;
      }
    };
    value();
    return dup;
  };
  const dupVectors = fixture.duplicate_key_vectors as Array<{
    _vector_id: string;
    expect_ok: boolean;
    reason?: string;
    envelope: { payload: string; sig: string; pubkey: string; nonce: number; expiresAt: number };
  }>;
  if (!Array.isArray(dupVectors) || dupVectors.length === 0) fail('duplicate_key_vectors missing or empty');
  const verifyNowMs = fixture.verify_now_ms as number;
  let sawDupControl = false;
  let sawDupBeforeBadSig = false;
  let sawExpiryBeforeDup = false;
  for (const v of dupVectors) {
    const id = v._vector_id;
    try {
      JSON.parse(v.envelope.payload);
    } catch {
      fail(`${id}: payload is not well-formed JSON, so it would be bad-json for a reason other than the duplicate`);
    }
    if (measureDepth(v.envelope.payload) > depthLimit) fail(`${id}: payload deeper than payload_depth_limit`);
    if (hasDuplicateKey(v.envelope.payload) !== !v.expect_ok) {
      fail(`${id}: expect_ok=${v.expect_ok} but the payload ${v.expect_ok ? 'HAS' : 'has NO'} duplicate key`);
    }
    if (v.envelope.pubkey !== ALICE_PUB_HEX) fail(`${id}: pubkey is not the documented signer`);
    const sigOk = verifiesFor(v.envelope);
    const expired = v.envelope.expiresAt < verifyNowMs - 5_000;
    if (v.expect_ok) {
      if (!sigOk) fail(`${id}: control signature does not verify`);
      sawDupControl = true;
    } else if (expired) {
      if (v.reason !== 'expired') fail(`${id}: expired envelope must carry reason expired`);
      sawExpiryBeforeDup = true;
    } else if (id.includes('precedes-bad-sig')) {
      if (sigOk) fail(`${id}: the bad-json-before-bad-sig vector must carry a signature that does NOT verify`);
      if (v.reason !== 'bad-json') fail(`${id}: unverifiable duplicate must still be bad-json (precedes bad-sig)`);
      sawDupBeforeBadSig = true;
    } else if (!sigOk) {
      fail(`${id}: signature does not verify for its exact payload text`);
    } else if (v.reason !== 'bad-json') {
      fail(`${id}: reason must be bad-json`);
    }
  }
  if (!sawDupControl) fail('duplicate_key_vectors carries no accepted (dkc*) control');
  if (!sawDupBeforeBadSig) fail('duplicate_key_vectors carries no bad-json-before-bad-sig precedence vector');
  if (!sawExpiryBeforeDup) fail('duplicate_key_vectors carries no expired-before-bad-json precedence vector');

  // 10. R2-JAVA-JSON string-grammar vectors (jj*), NaN / Infinity literal
  //     vectors (pj*), trailing-data vectors (tj*) and comment vectors (cj*).
  //     Each payload must be rejected by JSON.parse (raw control character,
  //     malformed \u escape, non-JSON constant, text after the value, comment) and carry a signature that verifies for its exact text, so a
  //     tier that accepts the string returns ok:true rather than bad-sig.
  const jjVectors = (fixture.rejection_vectors as Array<{
    _vector_id?: string;
    reason: string;
    envelope: { payload: string; sig: string; pubkey: string };
  }>).filter((v) => /^(jj|pj|tj|cj)\d/.test(v._vector_id ?? ''));
  if (!jjVectors.some((v) => /^jj\d/.test(v._vector_id ?? ''))) fail('rejection_vectors carries no jj* (R2-JAVA-JSON) vectors');
  if (!jjVectors.some((v) => /^pj\d/.test(v._vector_id ?? ''))) fail('rejection_vectors carries no pj* (NaN / Infinity) vectors');
  if (!jjVectors.some((v) => /^tj\d/.test(v._vector_id ?? ''))) fail('rejection_vectors carries no tj* (trailing data) vectors');
  if (!jjVectors.some((v) => /^cj\d/.test(v._vector_id ?? ''))) fail('rejection_vectors carries no cj* (comment) vectors');
  for (const v of jjVectors) {
    if (v.reason !== 'bad-json') fail(`${v._vector_id}: reason must be bad-json`);
    let parsedOk = true;
    try {
      JSON.parse(v.envelope.payload);
    } catch {
      parsedOk = false;
    }
    if (parsedOk) fail(`${v._vector_id}: JSON.parse ACCEPTS the payload, so it pins nothing`);
    if (!verifiesFor(v.envelope)) fail(`${v._vector_id}: signature does not verify for its payload text`);
  }

  console.log(`OK: ${vectors.length} canonical-JSON vectors + valid envelope signature + ${signingVectors.length} signing vectors + ${depthVectors.length} depth vectors + ${malleabilityVectors.length} malleability vectors + ${derVectors.length} strict-DER controls + ${intTokenVectors.length} integer-token vectors + ${allowlistVectors.length} allowlist vectors + ${dupVectors.length} duplicate-key vectors + ${jjVectors.length} JSON-grammar vectors validate against the TS reference.`);
}

main();
