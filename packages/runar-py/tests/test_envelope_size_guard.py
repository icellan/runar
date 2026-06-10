"""DoS-bound size guard tests for verify_envelope.

Mirrors the TS `'too-large'` rejection at
`packages/runar-sdk/src/envelope.ts:104`. The guard fires BEFORE any
JSON parse / ECDSA verify work so a pathological 100 MB payload cannot
pin the worker.
"""

from runar.sdk.envelope import (
    MAX_ENVELOPE_FIELD_BYTES,
    MAX_ENVELOPE_PAYLOAD_BYTES,
    SignedEnvelope,
    VerifyEnvelopeReason,
    verify_envelope,
)


def test_verify_envelope_rejects_oversized_payload() -> None:
    env = SignedEnvelope(
        payload="x" * (MAX_ENVELOPE_PAYLOAD_BYTES + 1),
        sig="00",
        pubkey="00",
        nonce=1,
        expiresAt=9_999_999_999_999,
    )
    result = verify_envelope(env, now_ms=1)
    assert not result.ok
    assert result.reason == VerifyEnvelopeReason.TOO_LARGE


def test_verify_envelope_rejects_oversized_sig() -> None:
    env = SignedEnvelope(
        payload='{"nonce":1,"expiresAt":9999999999999}',
        sig="a" * (MAX_ENVELOPE_FIELD_BYTES + 1),
        pubkey="00",
        nonce=1,
        expiresAt=9_999_999_999_999,
    )
    result = verify_envelope(env, now_ms=1)
    assert not result.ok
    assert result.reason == VerifyEnvelopeReason.TOO_LARGE


def test_verify_envelope_normal_sized_envelope_does_not_trip_size_guard() -> None:
    # A modest envelope must NOT trip the size guard. Downstream we
    # expect a different rejection reason (bad-sig / envelope-mismatch
    # / etc.); the only assertion here is that we do NOT get too-large.
    env = SignedEnvelope(
        payload='{"nonce":1,"expiresAt":9999999999999}',
        sig="deadbeef",
        pubkey="deadbeef",
        nonce=1,
        expiresAt=9_999_999_999_999,
    )
    result = verify_envelope(env, now_ms=1)
    assert result.reason != VerifyEnvelopeReason.TOO_LARGE
