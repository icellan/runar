"""GK-BUG-009: inner nonce/expiresAt must be a JSON integer token in i64 range.

The cross-tier vectors (it1..it8) live in conformance/sdk-envelope/fixtures.json
and are replayed by test_envelope_interop.py. This file pins the i64 boundary,
which only Python and Ruby (unbounded ints) need to check explicitly: an outer
nonce of 2**63 equals an inner token of 2**63 by value, so only the range check
rejects it. Every envelope is validly signed for its exact payload text, so a
wrong accept shows as ok, not bad-sig.
"""

import hashlib

from runar.ecdsa import ecdsa_sign, pub_key_from_priv_key
from runar.sdk.envelope import SignedEnvelope, VerifyEnvelopeReason, verify_envelope

EXP = 1700000030000
NOW = 1700000000500
PUB = pub_key_from_priv_key("00" * 31 + "01").hex()


def _signed(payload: str, nonce: int, expires_at: int) -> SignedEnvelope:
    sig = ecdsa_sign(1, hashlib.sha256(payload.encode("utf-8")).digest()).hex()
    return SignedEnvelope(payload=payload, sig=sig, pubkey=PUB, nonce=nonce, expiresAt=expires_at)


def test_i64_max_integer_token_accepted() -> None:
    n = 2**63 - 1
    r = verify_envelope(_signed('{"expiresAt":%d,"nonce":%d}' % (EXP, n), n, EXP), now_ms=NOW)
    assert r.ok, r.reason


def test_integer_token_past_i64_max_rejected() -> None:
    n = 2**63
    r = verify_envelope(_signed('{"expiresAt":%d,"nonce":%d}' % (EXP, n), n, EXP), now_ms=NOW)
    assert not r.ok
    assert r.reason == VerifyEnvelopeReason.ENVELOPE_MISMATCH


def test_integer_token_below_i64_min_rejected() -> None:
    n = -(2**63) - 1
    r = verify_envelope(_signed('{"expiresAt":%d,"nonce":%d}' % (EXP, n), n, EXP), now_ms=NOW)
    assert not r.ok
    assert r.reason == VerifyEnvelopeReason.ENVELOPE_MISMATCH


def test_boolean_true_is_not_one_for_expires_at() -> None:
    # Outer 1 / inner true is fixture it6; this pins the expiresAt half.
    r = verify_envelope(_signed('{"expiresAt":true,"nonce":7}', 7, 1), now_ms=0)
    assert not r.ok
    assert r.reason == VerifyEnvelopeReason.ENVELOPE_MISMATCH
