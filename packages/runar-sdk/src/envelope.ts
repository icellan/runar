// ---------------------------------------------------------------------------
// runar-sdk/envelope.ts — Signed-broadcast wire protocol for overlay apps.
// ---------------------------------------------------------------------------

import { Hash, Utils, PublicKey, Signature, BigNumber } from '@bsv/sdk';
import { hasLoneSurrogate } from './lone-surrogate.js';
import { verify as ecdsaVerifyRaw } from '@bsv/sdk/primitives/ECDSA';
import { canonicalJsonStringify, InputLimits } from 'runar-ir-schema';

/**
 * Deterministic JSON stringification (RFC 8785 / JCS). Sorted object keys,
 * recursive over arrays/objects. Used to canonicalize payloads before
 * hashing so different key-insertion orders produce identical signatures.
 */
export const canonicalJson = canonicalJsonStringify;

/**
 * Wire format for a signed broadcast payload. `payload` is the canonical
 * JSON of the inner `data` object merged with `nonce` and `expiresAt`, so
 * the signature commits to all the data + lifetime fields together.
 */
export interface SignedEnvelope {
  /** canonicalJson({ ...data, nonce, expiresAt }) */
  payload: string;
  /** DER hex of ECDSA over sha256(payload). */
  sig: string;
  /** 66-char hex of the signer's compressed secp256k1 pubkey. */
  pubkey: string;
  /** `Date.now()` at signing. */
  nonce: number;
  /** `nonce + ttlMs` — envelope is considered expired past this. */
  expiresAt: number;
}

/**
 * Minimal signer surface needed by {@link signEnvelope}. Structurally a
 * subset of {@link WalletSigner} — existing `WalletSigner` instances
 * satisfy this without an adapter. Apps that don't use a wallet can pass
 * a stub.
 */
export interface EnvelopeSigner {
  /** Sign a precomputed 32-byte digest directly; return DER hex. */
  signHash(digest: number[]): Promise<string>;
  /** Return the signer's pubkey as 66-char compressed hex. */
  getPublicKey(): Promise<string>;
}

export interface SignEnvelopeOpts {
  data: Record<string, unknown>;
  signer: EnvelopeSigner;
  /** TTL in milliseconds. Default 30_000. */
  ttlMs?: number;
}

/**
 * Sign an envelope around `data`. The envelope binds `data + nonce +
 * expiresAt` together via canonical JSON and an ECDSA signature over
 * sha256 of that canonical form.
 */
export async function signEnvelope(opts: SignEnvelopeOpts): Promise<SignedEnvelope> {
  const ttlMs = opts.ttlMs ?? 30_000;
  const nonce = Date.now();
  const expiresAt = nonce + ttlMs;
  const payload = canonicalJson({ ...opts.data, nonce, expiresAt });
  const digest = Hash.sha256(Utils.toArray(payload, 'utf8'));
  const sig = await opts.signer.signHash(digest);
  const pubkey = await opts.signer.getPublicKey();
  return { payload, sig, pubkey, nonce, expiresAt };
}

/**
 * Maximum payload nesting {@link verifyEnvelope} will parse: the number of containers
 * enclosing a value, 1-based, outermost = 1. 100 is accepted, 101 is rejected.
 * R-260.
 *
 * Without an explicit bound the limit was whatever each tier's stock JSON library
 * imposed, and those differ. Measured on ONE envelope, payload
 * {"deep":<N-deep array>,...}: ruby flipped to bad-json at total depth 101
 * (JSON.parse default max_nesting: 100) and rust at 128 (serde_json
 * RECURSION_LIMIT); ts, go, python and zig accepted every depth probed (zig's
 * iterative scanner took 100001 without complaint); and java threw
 * StackOverflowError straight OUT of verify -- its hand-written parser is
 * recursive with no cap and verify catches Exception, not Error -- at ~5000 deep
 * on a default JVM stack and ~1000 deep under -Xss512k, i.e. a contract escape on
 * unauthenticated input whose threshold was a JVM launch flag rather than a
 * protocol property.
 *
 * 100 is Ruby's native JSON.parse default EXACTLY and sits 27 below rust's 127,
 * so no tier has to hand-roll or reconfigure its parser to stay inside it. It is
 * also far above what the wire needs: the deepest of the 157 checked-in
 * conformance artifacts is depth 15 and conformance/sdk-envelope/fixtures.json
 * tops out at 6. The number is deliberately the SAME as canonicalJson's emit-side
 * bound: if parse were the smaller of the two, a tier could emit a legal,
 * correctly-signed envelope that another tier is physically unable to parse.
 *
 * The guard runs on the payload TEXT, immediately before the stock parser, and is
 * a flat non-recursive bracket scan so the guard itself cannot overflow.
 */
export const MAX_ENVELOPE_PAYLOAD_DEPTH = 100;

/**
 * Does the payload text nest deeper than MAX_ENVELOPE_PAYLOAD_DEPTH?
 *
 * Counts the maximum number of simultaneously-open {/[ containers, skipping
 * anything inside a JSON string (so a value of "[[[[..." is not nesting). The
 * scan is FLAT -- no recursion -- which is the point: a guard that recursed
 * would overflow on exactly the input it exists to reject. It bails out the
 * instant the bound is passed, so a 200 KB bracket bomb costs a few hundred
 * bytes of scanning.
 *
 * This does not validate JSON; malformed input still falls through to the real
 * parser and its own bad-json rejection.
 */
function payloadExceedsMaxDepth(payload: string): boolean {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < payload.length; i++) {
    const c = payload[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === '{' || c === '[') {
      depth++;
      if (depth > MAX_ENVELOPE_PAYLOAD_DEPTH) return true;
    } else if ((c === '}' || c === ']') && depth > 0) depth--;
  }
  return false;
}

export type VerifyEnvelopeReason =
  | 'missing-fields'
  | 'expired'
  | 'bad-json'
  | 'envelope-mismatch'
  | 'bad-sig'
  | 'pubkey-not-allowed'
  | 'too-large';

export interface VerifyEnvelopeOpts {
  envelope: SignedEnvelope;
  /** Optional pubkey allowlist (66-char hex strings). */
  expectedKeys?: string[];
  /** Allowed wall-clock skew in ms when checking `expiresAt`. Default 5_000. */
  clockSkewMs?: number;
}

export interface VerifyEnvelopeResult {
  ok: boolean;
  reason?: VerifyEnvelopeReason;
  /** Parsed payload when JSON parsing succeeded — populated even on
   *  later-stage rejections so callers can apply app-specific checks. */
  data?: Record<string, unknown>;
}

/**
 * Verify a signed envelope. See {@link VerifyEnvelopeReason} for the
 * ordered list of rejection causes. On `ok: true`, `data` contains the
 * parsed payload (including the merged `nonce`/`expiresAt`).
 */
export function verifyEnvelope(opts: VerifyEnvelopeOpts): VerifyEnvelopeResult {
  const env = opts.envelope;
  const clockSkewMs = opts.clockSkewMs ?? 5_000;

  // 0. DoS-bound size guard. Reject envelopes whose string fields exceed
  //    `InputLimits` BEFORE running JSON.parse, hashing, or ECDSA verify
  //    — those operations are linear in input size and a pathological
  //    100 MB payload would otherwise pin the event loop. Only string-
  //    typed fields are checked; missing/non-string fields fall through
  //    to the field-presence check below.
  if (env && typeof env === 'object') {
    if (typeof env.payload === 'string') {
      const payloadBytes = Buffer.byteLength(env.payload, 'utf8');
      if (payloadBytes > InputLimits.MAX_IR_BYTES) {
        return { ok: false, reason: 'too-large' };
      }
    }
    if (typeof env.sig === 'string' && env.sig.length > InputLimits.MAX_STRING_BYTES) {
      return { ok: false, reason: 'too-large' };
    }
    if (typeof env.pubkey === 'string' && env.pubkey.length > InputLimits.MAX_STRING_BYTES) {
      return { ok: false, reason: 'too-large' };
    }
  }

  // 1. Field presence and types. An EMPTY string field and a ZERO
  //    nonce/expiresAt count as absent, not present-but-odd — the other six
  //    SDK tiers all reject them here as `missing-fields` (Go
  //    sdk_envelope.go:550, Rust envelope.rs:336, Python envelope.py:310, Zig
  //    sdk_envelope.zig:483, Ruby envelope.rb:260, Java Envelope.java:368),
  //    and `verifyEnvelope` must return the SAME VerifyEnvelopeReason on every
  //    tier for the same rejection case. Without the emptiness checks TS was
  //    the outlier: `sig: ''` fell through to `expired`/`bad-sig` and a zero
  //    nonce was ACCEPTED outright.
  if (
    !env ||
    typeof env !== 'object' ||
    typeof env.payload !== 'string' ||
    env.payload === '' ||
    typeof env.sig !== 'string' ||
    env.sig === '' ||
    typeof env.pubkey !== 'string' ||
    env.pubkey === '' ||
    typeof env.nonce !== 'number' ||
    !Number.isFinite(env.nonce) ||
    env.nonce === 0 ||
    typeof env.expiresAt !== 'number' ||
    !Number.isFinite(env.expiresAt) ||
    env.expiresAt === 0
  ) {
    return { ok: false, reason: 'missing-fields' };
  }

  // 2. Expiry.
  if (env.expiresAt < Date.now() - clockSkewMs) {
    return { ok: false, reason: 'expired' };
  }

  // 3. Parse payload.
  //
  // R-115: an unpaired surrogate makes the payload ill-formed Unicode, and the
  // seven tiers' JSON parsers disagree about it (ts/go/python/java accepted it,
  // rust/ruby/zig refused). Decide it here, on the text, so every tier returns
  // the same reason — and so Go can see the `\uD800` escape before its parser
  // rewrites it to U+FFFD.
  if (hasLoneSurrogate(env.payload)) {
    return { ok: false, reason: 'bad-json' };
  }
  // R-260: bound nesting on the TEXT, before the stock parser, so the answer
  // does not depend on JSON.parse's (undocumented, engine-specific) recursion
  // behaviour. Same bound and same reason in all seven tiers.
  if (payloadExceedsMaxDepth(env.payload)) {
    return { ok: false, reason: 'bad-json' };
  }
  let parsed: Record<string, unknown>;
  try {
    const raw = JSON.parse(env.payload);
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      return { ok: false, reason: 'bad-json' };
    }
    parsed = raw as Record<string, unknown>;
  } catch {
    return { ok: false, reason: 'bad-json' };
  }

  // 4. Payload's own nonce/expiresAt must match the envelope's outer
  //    fields, so a forwarder can't strip the lifetime guarantee by
  //    rewriting outer fields while keeping the inner sig.
  if (parsed.nonce !== env.nonce || parsed.expiresAt !== env.expiresAt) {
    return { ok: false, reason: 'envelope-mismatch', data: parsed };
  }

  // 5. ECDSA verify sig over sha256(payload).
  let sigValid = false;
  try {
    const digest = Hash.sha256(Utils.toArray(env.payload, 'utf8'));
    const sigBytes = Utils.toArray(env.sig, 'hex');
    const pkBytes = Utils.toArray(env.pubkey, 'hex');
    const sig = Signature.fromDER(sigBytes);
    const pubKey = PublicKey.fromDER(pkBytes);
    sigValid = ecdsaVerifyRaw(new BigNumber(digest), sig, pubKey);
  } catch {
    sigValid = false;
  }
  if (!sigValid) {
    return { ok: false, reason: 'bad-sig', data: parsed };
  }

  // 6. Allowlist (last, so a verified-but-not-allowed signer is
  //    distinguishable from a forged one).
  if (opts.expectedKeys && !opts.expectedKeys.includes(env.pubkey)) {
    return { ok: false, reason: 'pubkey-not-allowed', data: parsed };
  }

  return { ok: true, data: parsed };
}
