"""F-242 (CL-BUG-160): strict DER (BIP66) for ECDSA signature verification.

``_parse_der_signature`` used to accept bytes left over inside the SEQUENCE,
an INTEGER whose top bit is set without the 0x00 sign pad, and superfluous
leading 0x00 bytes, so several byte strings verified as one signature.
``conformance/sdk-der/vectors.json`` holds the cross-tier vectors: every
ok=False entry re-encodes a valid signature's (r, s), so only the encoding can
make it fail.

Proves: ``_parse_der_signature`` returns None for every malformed encoding and
the canonical (r, s) for every control, and ``ecdsa_verify`` (the path behind
``check_sig``, the ANF interpreter's real-crypto verify and ``verify_envelope``)
reaches the fixture verdict. Does not prove anything about the curve arithmetic
or about low-S (this tier's ``ecdsa_verify`` has no low-S rule).
"""

import json
import pathlib

import pytest

from runar.ecdsa import _parse_der_signature, ecdsa_verify

VECTORS_PATH = pathlib.Path(__file__).resolve().parents[3] / "conformance" / "sdk-der" / "vectors.json"
FIXTURE = json.loads(VECTORS_PATH.read_text())


def test_fixture_has_controls_and_refusals() -> None:
    oks = {v["ok"] for v in FIXTURE["vectors"]}
    assert oks == {True, False}


@pytest.mark.parametrize("v", FIXTURE["vectors"], ids=lambda v: v["id"])
def test_strict_der_vector(v: dict) -> None:
    sig = bytes.fromhex(v["sig"])
    parsed = _parse_der_signature(sig)
    if v["ok"]:
        assert parsed is not None
        assert parsed == _parse_der_signature(bytes.fromhex(v["canonical_sig"]))
    else:
        assert parsed is None, f"{v['id']}: parsed to {parsed}"
    got = ecdsa_verify(sig, bytes.fromhex(FIXTURE["pubkey"]), bytes.fromhex(v["digest"]))
    assert got is v["ok"]
