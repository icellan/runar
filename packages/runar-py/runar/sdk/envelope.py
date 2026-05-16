"""Signed-broadcast wire protocol for overlay apps.

Byte-compatible with the TypeScript reference implementation in
``packages/runar-sdk/src/envelope.ts``. The three primitives are:

- :func:`canonical_json` — RFC 8785 / JCS serializer (sorted object keys
  by UTF-16 code-unit order, no whitespace, ES Number.prototype.toString-
  compatible number formatting). Byte-identical across every Runar SDK
  tier for the same input.
- :func:`sign_envelope` — bind data + nonce + expiresAt into a canonical-
  JSON payload, sha256 it, sign the digest via a caller-supplied callback.
- :func:`verify_envelope` — six-reason rejection ladder mirroring every
  other SDK tier.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, List, Optional

# ---------------------------------------------------------------------------
# canonical_json
# ---------------------------------------------------------------------------


def canonical_json(value: Any) -> str:
    """Serialize ``value`` to RFC 8785 / JCS canonical JSON."""
    parts: List[str] = []
    _canonical_append(parts, value)
    return "".join(parts)


def _canonical_append(out: List[str], value: Any) -> None:
    if value is None:
        out.append("null")
        return
    if isinstance(value, bool):  # bool is a subclass of int — check first
        out.append("true" if value else "false")
        return
    if isinstance(value, int):
        out.append(str(value))
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("canonical JSON: non-finite number")
        if value == 0:
            out.append("0")
            return
        if value.is_integer() and -9_007_199_254_740_992 <= value <= 9_007_199_254_740_992:
            out.append(str(int(value)))
            return
        # Python's repr matches ES Number.prototype.toString for most cases
        # via shortest-roundtrip. Use repr() for floats.
        out.append(repr(value))
        return
    if isinstance(value, str):
        _append_json_string(out, value)
        return
    if isinstance(value, list):
        out.append("[")
        for i, e in enumerate(value):
            if i > 0:
                out.append(",")
            _canonical_append(out, e)
        out.append("]")
        return
    if isinstance(value, dict):
        # Sort keys by UTF-16 code-unit order to match JS default sort().
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        out.append("{")
        first = True
        for k in keys:
            v = value[k]
            if not first:
                out.append(",")
            first = False
            _append_json_string(out, k)
            out.append(":")
            _canonical_append(out, v)
        out.append("}")
        return
    raise TypeError(f"canonical JSON: unsupported type {type(value).__name__}")


def _append_json_string(out: List[str], s: str) -> None:
    out.append('"')
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')


# ---------------------------------------------------------------------------
# Envelope types
# ---------------------------------------------------------------------------


@dataclass
class SignedEnvelope:
    """Wire format for a signed broadcast payload."""

    payload: str
    sig: str
    pubkey: str
    nonce: int
    expiresAt: int

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "sig": self.sig,
            "pubkey": self.pubkey,
            "nonce": self.nonce,
            "expiresAt": self.expiresAt,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SignedEnvelope":
        return cls(
            payload=d["payload"],
            sig=d["sig"],
            pubkey=d["pubkey"],
            nonce=int(d["nonce"]),
            expiresAt=int(d["expiresAt"]),
        )


# A signer is any callable that takes a 32-byte digest and returns DER bytes.
SignFn = Callable[[bytes], bytes]


def sign_envelope(
    data: dict,
    signer: SignFn,
    pubkey: str,
    ttl_ms: int = 30_000,
    now_ms: Optional[int] = None,
) -> SignedEnvelope:
    """Produce a signed envelope around ``data``.

    ``signer`` receives a 32-byte sha256 digest and must return DER-encoded
    ECDSA signature bytes (no sighash byte). ``pubkey`` is the 66-char
    compressed-hex pubkey of the signing key.
    """
    nonce = int(now_ms if now_ms is not None else time.time() * 1000)
    expires_at = nonce + ttl_ms
    merged = {**data, "nonce": nonce, "expiresAt": expires_at}
    payload = canonical_json(merged)
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    sig_bytes = signer(digest)
    return SignedEnvelope(
        payload=payload,
        sig=sig_bytes.hex(),
        pubkey=pubkey,
        nonce=nonce,
        expiresAt=expires_at,
    )


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


class VerifyEnvelopeReason(str, Enum):
    MISSING_FIELDS = "missing-fields"
    EXPIRED = "expired"
    BAD_JSON = "bad-json"
    ENVELOPE_MISMATCH = "envelope-mismatch"
    BAD_SIG = "bad-sig"
    PUBKEY_NOT_ALLOWED = "pubkey-not-allowed"


@dataclass
class VerifyEnvelopeResult:
    ok: bool
    reason: Optional[VerifyEnvelopeReason] = None
    data: Optional[dict] = None


def verify_envelope(
    envelope: SignedEnvelope,
    expected_keys: Optional[List[str]] = None,
    clock_skew_ms: int = 5_000,
    now_ms: Optional[int] = None,
) -> VerifyEnvelopeResult:
    """Verify a signed envelope against the same six rejection reasons every
    other SDK tier uses."""
    # 1. Field presence + types.
    if (
        not isinstance(envelope, SignedEnvelope)
        or not envelope.payload
        or not envelope.sig
        or not envelope.pubkey
        or not envelope.nonce
        or not envelope.expiresAt
    ):
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.MISSING_FIELDS, None)

    now = int(now_ms if now_ms is not None else time.time() * 1000)

    # 2. Expiry.
    if envelope.expiresAt < now - clock_skew_ms:
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.EXPIRED, None)

    # 3. Parse payload.
    try:
        parsed = json.loads(envelope.payload)
    except json.JSONDecodeError:
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.BAD_JSON, None)
    if not isinstance(parsed, dict):
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.BAD_JSON, None)

    # 4. Inner nonce / expiresAt must match outer fields.
    if (
        parsed.get("nonce") != envelope.nonce
        or parsed.get("expiresAt") != envelope.expiresAt
    ):
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.ENVELOPE_MISMATCH, parsed)

    # 5. ECDSA verify (raw, no re-hashing).
    from runar.ecdsa import ecdsa_verify

    try:
        sig_bytes = bytes.fromhex(envelope.sig)
        pk_bytes = bytes.fromhex(envelope.pubkey)
    except ValueError:
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.BAD_SIG, parsed)
    digest = hashlib.sha256(envelope.payload.encode("utf-8")).digest()
    if not ecdsa_verify(sig_bytes, pk_bytes, digest):
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.BAD_SIG, parsed)

    # 6. Allowlist.
    if expected_keys is not None and envelope.pubkey not in expected_keys:
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.PUBKEY_NOT_ALLOWED, parsed)

    return VerifyEnvelopeResult(True, None, parsed)
