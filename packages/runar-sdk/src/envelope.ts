// ---------------------------------------------------------------------------
// runar-sdk/envelope.ts — Signed-broadcast wire protocol for overlay apps.
// ---------------------------------------------------------------------------

import { Hash, Utils, PublicKey, Signature, BigNumber } from '@bsv/sdk';
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

  // 1. Field presence and types.
  if (
    !env ||
    typeof env !== 'object' ||
    typeof env.payload !== 'string' ||
    typeof env.sig !== 'string' ||
    typeof env.pubkey !== 'string' ||
    typeof env.nonce !== 'number' ||
    !Number.isFinite(env.nonce) ||
    typeof env.expiresAt !== 'number' ||
    !Number.isFinite(env.expiresAt)
  ) {
    return { ok: false, reason: 'missing-fields' };
  }

  // 2. Expiry.
  if (env.expiresAt < Date.now() - clockSkewMs) {
    return { ok: false, reason: 'expired' };
  }

  // 3. Parse payload.
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
