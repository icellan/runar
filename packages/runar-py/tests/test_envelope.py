"""Tests for runar.sdk.envelope — wire-protocol parity with TS reference."""

import hashlib

import pytest

from runar.ecdsa import ecdsa_sign, pub_key_from_priv_key
from runar.sdk.envelope import (
    canonical_json,
    sign_envelope,
    verify_envelope,
    SignedEnvelope,
    VerifyEnvelopeReason,
)


# ---------------------------------------------------------------------------
# Test signer — wraps a fixed test priv key + raw ECDSA sign
# ---------------------------------------------------------------------------


ALICE_PRIV_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
BOB_PRIV_HEX = "0000000000000000000000000000000000000000000000000000000000000002"


def alice_signer(digest: bytes) -> bytes:
    return ecdsa_sign(int(ALICE_PRIV_HEX, 16), digest)


def bob_signer(digest: bytes) -> bytes:
    return ecdsa_sign(int(BOB_PRIV_HEX, 16), digest)


def alice_pubkey() -> str:
    return pub_key_from_priv_key(ALICE_PRIV_HEX).hex()


def bob_pubkey() -> str:
    return pub_key_from_priv_key(BOB_PRIV_HEX).hex()


# ---------------------------------------------------------------------------
# canonical_json
# ---------------------------------------------------------------------------


class TestCanonicalJson:
    def test_order_independent(self):
        a = canonical_json({"a": 1, "b": 2})
        b = canonical_json({"b": 2, "a": 1})
        assert a == b
        assert a == '{"a":1,"b":2}'

    def test_nested(self):
        got = canonical_json({
            "outer": {"z": 1, "a": [3, 2, 1]},
            "list": [{"y": 1, "x": 2}],
            "n": None,
            "b": True,
            "s": "hi",
        })
        assert got == '{"b":true,"list":[{"x":2,"y":1}],"n":null,"outer":{"a":[3,2,1],"z":1},"s":"hi"}'

    def test_primitives(self):
        assert canonical_json(None) == "null"
        assert canonical_json(True) == "true"
        assert canonical_json(False) == "false"
        assert canonical_json(42) == "42"
        assert canonical_json("hi") == '"hi"'


# ---------------------------------------------------------------------------
# Round-trip + rejection ladder
# ---------------------------------------------------------------------------


class TestSignVerify:
    def test_round_trip(self):
        env = sign_envelope(
            {"kind": "hello", "n": 7},
            alice_signer,
            alice_pubkey(),
            now_ms=1_000_000_000_000,
        )
        r = verify_envelope(env, now_ms=1_000_000_000_500)
        assert r.ok, f"reason={r.reason}"
        assert r.data["kind"] == "hello"

    def test_missing_fields(self):
        env = sign_envelope({"ok": 1}, alice_signer, alice_pubkey(), now_ms=1_000_000_000_000)
        env.sig = ""
        r = verify_envelope(env, now_ms=1_000_000_000_500)
        assert not r.ok
        assert r.reason == VerifyEnvelopeReason.MISSING_FIELDS

    def test_expired(self):
        env = sign_envelope({"ok": 1}, alice_signer, alice_pubkey(), now_ms=1_000_000_000_000)
        r = verify_envelope(env, now_ms=1_000_000_000_000 + 1_000_000)
        assert not r.ok
        assert r.reason == VerifyEnvelopeReason.EXPIRED

    def test_bad_json(self):
        env = sign_envelope({"ok": 1}, alice_signer, alice_pubkey(), now_ms=1_000_000_000_000)
        env.payload = "not json{"
        r = verify_envelope(env, now_ms=1_000_000_000_500)
        assert not r.ok
        assert r.reason == VerifyEnvelopeReason.BAD_JSON

    def test_envelope_mismatch(self):
        env = sign_envelope({"ok": 1}, alice_signer, alice_pubkey(), now_ms=1_000_000_000_000)
        env.nonce += 1
        r = verify_envelope(env, now_ms=1_000_000_000_500)
        assert not r.ok
        assert r.reason == VerifyEnvelopeReason.ENVELOPE_MISMATCH
        assert r.data is not None

    def test_bad_sig(self):
        env = sign_envelope({"ok": 1}, alice_signer, alice_pubkey(), now_ms=1_000_000_000_000)
        mid = len(env.sig) // 2
        flip = "1" if env.sig[mid] != "1" else "2"
        env.sig = env.sig[:mid] + flip + env.sig[mid + 1:]
        r = verify_envelope(env, now_ms=1_000_000_000_500)
        assert not r.ok
        assert r.reason == VerifyEnvelopeReason.BAD_SIG

    def test_pubkey_not_allowed(self):
        env = sign_envelope({"ok": 1}, alice_signer, alice_pubkey(), now_ms=1_000_000_000_000)
        r = verify_envelope(env, expected_keys=[bob_pubkey()], now_ms=1_000_000_000_500)
        assert not r.ok
        assert r.reason == VerifyEnvelopeReason.PUBKEY_NOT_ALLOWED

    def test_pubkey_allowed(self):
        env = sign_envelope({"ok": 1}, alice_signer, alice_pubkey(), now_ms=1_000_000_000_000)
        r = verify_envelope(env, expected_keys=[env.pubkey], now_ms=1_000_000_000_500)
        assert r.ok

    def test_digest_matches_payload(self):
        env = sign_envelope({"k": 1}, alice_signer, alice_pubkey(), now_ms=1_000_000_000_000)
        from runar.ecdsa import ecdsa_verify
        digest = hashlib.sha256(env.payload.encode("utf-8")).digest()
        sig_bytes = bytes.fromhex(env.sig)
        pk_bytes = bytes.fromhex(env.pubkey)
        assert ecdsa_verify(sig_bytes, pk_bytes, digest)
