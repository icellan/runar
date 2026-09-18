"""Cross-tier BIP-143 sighash interop test (GAP-003).

Loads `conformance/sdk-bip143/fixtures.json` (TS reference, generated via
@bsv/sdk TransactionSignature.format) and asserts, for every scenario, that
this tier's hand-written BIP-143 implementation:

  1. recomputes the full preimage byte-identically from (unsignedTxHex,
     inputIndex, prevScriptHex, prevValueSats) — the core node-free cross-tier
     correctness check;
  2. produces sha256d(preimage) == the fixture digestHex; and
  3. verifies the TS-produced sigHex against pubkeyHex over that digest.

Any failure here is a cross-tier BIP-143 protocol divergence (a real consensus
bug). See CLAUDE.md §"Seven SDKs Must Stay in Sync".
"""

import hashlib
import json
import pathlib

import pytest

from runar.ecdsa import ecdsa_verify
from runar.sdk.oppushtx import compute_op_push_tx

FIXTURE_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "conformance"
    / "sdk-bip143"
    / "fixtures.json"
)


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


def test_bip143_preimage_and_signature(fixture: dict) -> None:
    scenarios = fixture["scenarios"]
    assert scenarios, "fixture has no scenarios"

    for s in scenarios:
        name = s["scenario"]
        # 1. Independently recompute the BIP-143 preimage (hand-written impl)
        #    under the scenario's OWN sighash flags.
        #
        #    R-206: this used to reject anything but 0x41, and every scenario in
        #    the fixture was ALL|FORKID — so the per-mode zeroing rules
        #    (hashPrevouts under ANYONECANPAY, hashSequence unless pure ALL,
        #    hashOutputs under NONE and the single-output rule under SINGLE)
        #    were implemented seven times and compared zero times.
        _sig_hex, got_preimage = compute_op_push_tx(
            s["unsignedTxHex"],
            s["inputIndex"],
            s["prevScriptHex"],
            s["prevValueSats"],
            -1,
            s["sighashFlags"],
        )
        assert got_preimage == s["preimageHex"], (
            f"{name}: BIP-143 PREIMAGE DIVERGENCE from TS reference\n"
            f"  want {s['preimageHex']}\n  got  {got_preimage}"
        )

        # 2. sha256d(preimage) must equal the published digest.
        preimage_bytes = bytes.fromhex(got_preimage)
        got_digest = _sha256d(preimage_bytes).hex()
        assert got_digest == s["digestHex"], f"{name}: sighash digest divergence"

        # 3. The TS-produced signature must verify over this tier's digest.
        sig_bytes = bytes.fromhex(s["sigHex"])  # ecdsa_verify strips sighash byte
        pk_bytes = bytes.fromhex(s["pubkeyHex"])
        assert ecdsa_verify(sig_bytes, pk_bytes, _sha256d(preimage_bytes)), (
            f"{name}: TS reference signature does not verify under this tier's digest"
        )
