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


#: Bounds the nesting ``canonical_json`` will EMIT: the number of containers
#: enclosing a value, 1-based, outermost = 1. 100 is accepted, 101 rejected.
#:
#: Deliberately the same number ``verify_envelope`` enforces on the parse side
#: (``MAX_ENVELOPE_PAYLOAD_DEPTH``) -- if emit allowed more than parse, this
#: tier could produce a legal, correctly-signed envelope another tier is
#: physically unable to read. It is NOT the compiler's IR nesting bound (512):
#: that serves the ``--ir`` loader, which reads a trusted local file rather
#: than unauthenticated wire input. R-260.
#:
#: 100 also sits far inside CPython's default recursion limit of 1000, so the
#: guard raises a typed ValueError rather than letting the interpreter die of
#: native stack exhaustion (measured at depth 1024). Do NOT raise
#: sys.setrecursionlimit to accommodate a deeper bound -- that trades the
#: typed rejection for a hard crash.
MAX_WIRE_NESTING = 100


def canonical_json(value: Any) -> str:
    """Serialize ``value`` to RFC 8785 / JCS canonical JSON.

    :raises ValueError: if nesting exceeds :data:`MAX_WIRE_NESTING`, a single
        string exceeds ``MAX_ENVELOPE_FIELD_BYTES``, or the finished document
        exceeds ``MAX_ENVELOPE_PAYLOAD_BYTES``.
    """
    parts: List[str] = []
    _canonical_append(parts, value, 1)
    out = "".join(parts)
    # G3: total output guard, on the finished document's UTF-8 byte length.
    n = len(out.encode("utf-8"))
    if n > MAX_ENVELOPE_PAYLOAD_BYTES:
        raise ValueError(
            f"canonical JSON: output exceeds {MAX_ENVELOPE_PAYLOAD_BYTES} bytes (actual {n})"
        )
    return out


def _canonical_append(out: List[str], value: Any, depth: int) -> None:
    """``depth`` is the 1-based nesting level of the container being written
    (outermost = 1); scalars ignore it."""
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
        # ECMA-262 §6.1.6.1.13 Number::toString. Python's repr() is shortest
        # round-trip (same digit string as JS) but its surface form diverges
        # from ES: repr zero-pads exponents (1e-07), switches to scientific
        # form earlier than ES (1e-06 vs ES 0.000001), and never expands large
        # integers (1e+20 vs ES 100000000000000000000). Re-emit per the ES
        # rules so the bytes are byte-identical to the TS / Go / Rust tiers.
        out.append(_format_ecma262_double(value))
        return
    if isinstance(value, str):
        _append_json_string(out, value)
        return
    if isinstance(value, list):
        # G1: depth guard on entry to the container, before children.
        if depth > MAX_WIRE_NESTING:
            raise ValueError(f"canonical JSON: nesting exceeds {MAX_WIRE_NESTING}")
        out.append("[")
        for i, e in enumerate(value):
            if i > 0:
                out.append(",")
            _canonical_append(out, e, depth + 1)
        out.append("]")
        return
    if isinstance(value, dict):
        # G1: depth guard on entry to the container, before children.
        if depth > MAX_WIRE_NESTING:
            raise ValueError(f"canonical JSON: nesting exceeds {MAX_WIRE_NESTING}")
        # Sort keys by UTF-16 code-unit order to match JS default sort().
        # `.encode('utf-16-be')` raises UnicodeEncodeError on lone surrogates;
        # surface that as the typed canonical-JSON ValueError so callers can
        # catch a single error class (RFC 8785 §3.2.2.2 / audit D6).
        def _utf16be(k: str) -> bytes:
            try:
                return k.encode("utf-16-be")
            except UnicodeEncodeError as e:
                raise ValueError(
                    f"canonical JSON: lone surrogate in object key ({e})"
                ) from e

        keys = sorted(value.keys(), key=_utf16be)
        out.append("{")
        first = True
        for k in keys:
            v = value[k]
            if not first:
                out.append(",")
            first = False
            _append_json_string(out, k)
            out.append(":")
            _canonical_append(out, v, depth + 1)
        out.append("}")
        return
    raise TypeError(f"canonical JSON: unsupported type {type(value).__name__}")


def _format_ecma262_double(x: float) -> str:
    """Format a finite, non-zero double per ECMA-262 §6.1.6.1.13
    Number::toString. Output is byte-identical to JS ``JSON.stringify(x)`` /
    ``String(x)`` for any finite ``x``. Ported from the Rust reference
    ``format_ecma262_double`` (packages/runar-rs/src/sdk/envelope.rs) so the
    bytes match across tiers (caller filters 0 / NaN / Infinity).
    """
    if x < 0:
        return "-" + _format_ecma262_double(-x)

    # repr() gives the shortest round-trip decimal string (same digits JS
    # picks). Decompose it into a normalized digit string + decimal exponent
    # k, then re-emit per the ES rules — independent of repr's surface form.
    s = repr(x)
    if "e" in s or "E" in s:
        mantissa, _, exp_str = s.replace("E", "e").partition("e")
        exp_part = int(exp_str)
    else:
        mantissa, exp_part = s, 0

    if "." in mantissa:
        int_part, frac_part = mantissa.split(".", 1)
    else:
        int_part, frac_part = mantissa, ""

    raw_digits = int_part + frac_part
    leading_zeros = len(raw_digits) - len(raw_digits.lstrip("0"))
    digits = raw_digits[leading_zeros:].rstrip("0")
    if not digits:
        return "0"

    # k: position of the decimal point relative to the significant digits.
    k = len(int_part) - leading_zeros + exp_part
    s_len = len(digits)

    if k >= s_len and k <= 21:
        return digits + "0" * (k - s_len)
    if 0 < k <= 21:
        return digits[:k] + "." + digits[k:]
    if -6 < k <= 0:
        return "0." + "0" * (-k) + digits
    # Scientific notation.
    exp = k - 1
    exp_sign = "+" if exp >= 0 else "-"
    exp_abs = abs(exp)
    if s_len == 1:
        return f"{digits}e{exp_sign}{exp_abs}"
    return f"{digits[0]}.{digits[1:]}e{exp_sign}{exp_abs}"


def _append_json_string(out: List[str], s: str) -> None:
    # G2: string-byte guard on the RAW input, before escaping, so the bound is
    # about the caller's data rather than about how much the escaper inflated
    # it. Object KEYS route through here too, so an oversized key is rejected
    # the same way an oversized value is.
    n = len(s.encode("utf-8", "surrogatepass"))
    if n > MAX_ENVELOPE_FIELD_BYTES:
        raise ValueError(
            f"canonical JSON: string exceeds {MAX_ENVELOPE_FIELD_BYTES} bytes (actual {n})"
        )
    out.append('"')
    for ch in s:
        cp = ord(ch)
        # RFC 8785 §3.2.2.2: lone surrogates (U+D800..U+DFFF) are not valid
        # scalar values and MUST be rejected. Python's `str` happily holds
        # them (unlike Rust's safe String) so we explicitly walk codepoints
        # and raise — audit D6.
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError(
                f"canonical JSON: lone surrogate U+{cp:04X} in string"
            )
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
    # TOO_LARGE mirrors the TS 'too-large' reason. Returned BEFORE any
    # JSON parse / ECDSA verify work when an envelope string field
    # exceeds its InputLimits cap (DoS-bound).
    TOO_LARGE = "too-large"


# Envelope DoS-bound caps. Mirror InputLimits.{MAX_IR_BYTES, MAX_STRING_BYTES}
# from the TS schema package.
MAX_ENVELOPE_PAYLOAD_BYTES = 16 * 1024 * 1024  # 16 MiB — matches MAX_IR_BYTES
MAX_ENVELOPE_FIELD_BYTES = 4 * 1024 * 1024     # 4 MiB — matches MAX_STRING_BYTES

#: Maximum payload nesting ``verify_envelope`` will parse: the number of containers
#: enclosing a value, 1-based, outermost = 1. 100 is accepted, 101 is rejected.
#: R-260.
#:
#: Without an explicit bound the limit was whatever each tier's stock JSON library
#: imposed, and those differ. Measured on ONE envelope, payload
#: {"deep":<N-deep array>,...}: ruby flipped to bad-json at total depth 101
#: (JSON.parse default max_nesting: 100) and rust at 128 (serde_json
#: RECURSION_LIMIT); ts, go, python and zig accepted every depth probed (zig's
#: iterative scanner took 100001 without complaint); and java threw
#: StackOverflowError straight OUT of verify -- its hand-written parser is
#: recursive with no cap and verify catches Exception, not Error -- at ~5000 deep
#: on a default JVM stack and ~1000 deep under -Xss512k, i.e. a contract escape on
#: unauthenticated input whose threshold was a JVM launch flag rather than a
#: protocol property.
#:
#: 100 is Ruby's native JSON.parse default EXACTLY and sits 27 below rust's 127,
#: so no tier has to hand-roll or reconfigure its parser to stay inside it. It is
#: also far above what the wire needs: the deepest of the 165 checked-in
#: conformance artifacts is depth 15 and conformance/sdk-envelope/fixtures.json
#: tops out at 6. The number is deliberately the SAME as canonicalJson's emit-side
#: bound: if parse were the smaller of the two, a tier could emit a legal,
#: correctly-signed envelope that another tier is physically unable to parse.
#:
#: The guard runs on the payload TEXT, immediately before the stock parser, and is
#: a flat non-recursive bracket scan so the guard itself cannot overflow.
MAX_ENVELOPE_PAYLOAD_DEPTH = 100


def _payload_exceeds_max_depth(payload: str) -> bool:
    """Does the payload text nest deeper than MAX_ENVELOPE_PAYLOAD_DEPTH?

Counts the maximum number of simultaneously-open {/[ containers, skipping
anything inside a JSON string (so a value of "[[[[..." is not nesting). The
scan is FLAT -- no recursion -- which is the point: a guard that recursed
would overflow on exactly the input it exists to reject. It bails out the
instant the bound is passed, so a 200 KB bracket bomb costs a few hundred
bytes of scanning.

This does not validate JSON; malformed input still falls through to the real
parser and its own bad-json rejection.
    """
    depth = 0
    in_string = False
    escaped = False
    for c in payload:
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c in "{[":
            depth += 1
            if depth > MAX_ENVELOPE_PAYLOAD_DEPTH:
                return True
        elif c in "}]" and depth > 0:
            depth -= 1
    return False



@dataclass
class VerifyEnvelopeResult:
    ok: bool
    reason: Optional[VerifyEnvelopeReason] = None
    data: Optional[dict] = None


def _payload_has_lone_surrogate(text: str) -> bool:
    """Unpaired-surrogate detection on an envelope payload (R-115 / CL-BUG-066).

    ``verify_envelope`` hashes the payload string RAW -- it never routes it
    through ``canonical_json`` -- so canonical_json's lone-surrogate rejection
    (audit D6, fixture vector v22) never sees the envelope path. What each tier
    did instead was whatever its JSON parser happened to do, and the parsers
    disagree. Measured on one envelope whose payload holds ``"x\\ud800y"``:

        ts / go / python / java   accepted it, fell through to bad-sig
        rust / ruby / zig         rejected it at the parse step, bad-json

    The check runs on the payload TEXT rather than the parsed value, because
    that is the only form every tier still has -- Go's ``encoding/json``
    rewrites ``\\ud800`` to U+FFFD while parsing.
    """
    # Raw code points first (a Python str can hold a lone surrogate).
    for ch in text:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            return True

    i = 0
    n = len(text)
    while i < n:
        if text[i] != "\\":
            i += 1
            continue
        run = 0
        while i + run < n and text[i + run] == "\\":
            run += 1
        esc = i + run - 1
        i = esc + 1
        if run % 2 == 0:
            continue
        if esc + 5 >= n or text[esc + 1] != "u":
            continue
        hex_digits = text[esc + 2 : esc + 6]
        try:
            code = int(hex_digits, 16)
        except ValueError:
            continue
        if 0xD800 <= code <= 0xDBFF:
            if esc + 11 >= n or text[esc + 6] != "\\" or text[esc + 7] != "u":
                return True
            try:
                low = int(text[esc + 8 : esc + 12], 16)
            except ValueError:
                return True
            if not (0xDC00 <= low <= 0xDFFF):
                return True
            i = esc + 12
        elif 0xDC00 <= code <= 0xDFFF:
            return True
        else:
            i = esc + 6
    return False


def verify_envelope(
    envelope: SignedEnvelope,
    expected_keys: Optional[List[str]] = None,
    clock_skew_ms: int = 5_000,
    now_ms: Optional[int] = None,
) -> VerifyEnvelopeResult:
    """Verify a signed envelope against the same six rejection reasons every
    other SDK tier uses."""
    # 0. DoS-bound size guard. Reject envelopes whose string fields exceed
    #    their InputLimits cap BEFORE running JSON parse, hashing, or
    #    ECDSA verify -- those operations are linear in input size and a
    #    pathological 100 MB payload would otherwise pin the worker.
    #    Mirrors the TS 'too-large' rejection at sdk/envelope.ts:104.
    if isinstance(envelope, SignedEnvelope):
        if (
            isinstance(envelope.payload, str)
            and len(envelope.payload.encode("utf-8")) > MAX_ENVELOPE_PAYLOAD_BYTES
        ):
            return VerifyEnvelopeResult(False, VerifyEnvelopeReason.TOO_LARGE, None)
        if isinstance(envelope.sig, str) and len(envelope.sig) > MAX_ENVELOPE_FIELD_BYTES:
            return VerifyEnvelopeResult(False, VerifyEnvelopeReason.TOO_LARGE, None)
        if isinstance(envelope.pubkey, str) and len(envelope.pubkey) > MAX_ENVELOPE_FIELD_BYTES:
            return VerifyEnvelopeResult(False, VerifyEnvelopeReason.TOO_LARGE, None)

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
    #
    # R-115: an unpaired surrogate makes the payload ill-formed Unicode, and
    # the seven tiers' JSON parsers disagree about it. Decide it here, on the
    # text, so every tier returns the same reason.
    if _payload_has_lone_surrogate(envelope.payload):
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.BAD_JSON, None)
    # R-260: bound nesting on the TEXT, before json.loads, so the answer does
    # not depend on the C scanner's recursion behaviour. Same bound and same
    # reason in all seven tiers.
    if _payload_exceeds_max_depth(envelope.payload):
        return VerifyEnvelopeResult(False, VerifyEnvelopeReason.BAD_JSON, None)
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
