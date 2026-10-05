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


# F-137: the signer paths. LocalSigner's pure-Python backend and WalletSigner
# each carried a private BIP-143 builder that never got the issue-#123 fix:
# both digested every prevout / sequence / output whatever the sighash flags
# said. The test above only checks the compute_op_push_tx builder, so the
# divergence was invisible.
#
# Proves: for every fixture scenario, including all six FORKID modes
# (0x41/42/43/c1/c2/c3) on the shared 2-in/2-out tx signing input 1, each
# signer's full signature (RFC-6979, priv=1, so deterministic) is
# byte-identical to the TS (@bsv/sdk) reference sigHex.
# Does not prove: anything about LocalSigner's bsv-sdk backend, or that a node
# accepts the signature (the fixture is TS + Go go-sdk cross-checked, not
# broadcast).


def test_local_signer_fallback_matches_ts_reference(fixture: dict, monkeypatch) -> None:
    import runar.sdk.local_signer as ls_module

    monkeypatch.setattr(ls_module, "_BSV_SDK_AVAILABLE", False)
    signer = ls_module.LocalSigner(fixture["signer_priv_hex"])
    assert signer._backend == "fallback"
    assert signer.get_public_key() == fixture["signer_pub_hex"]

    for s in fixture["scenarios"]:
        sig = signer.sign(
            s["unsignedTxHex"], s["inputIndex"], s["prevScriptHex"],
            s["prevValueSats"], s["sighashFlags"],
        )
        assert sig == s["sigHex"], f"{s['scenario']}: LocalSigner diverges from TS reference"


def test_wallet_signer_matches_ts_reference(fixture: dict) -> None:
    from runar.ecdsa import ecdsa_sign
    from runar.sdk.wallet import WalletClient, WalletSigner

    priv_int = int(fixture["signer_priv_hex"], 16)

    class _KeyOneWallet(WalletClient):
        def get_public_key(self, protocol_id, key_id):
            return fixture["signer_pub_hex"]

        def create_signature(self, hash_to_sign, protocol_id, key_id):
            return ecdsa_sign(priv_int, hash_to_sign)

        def create_action(self, description, outputs):
            raise NotImplementedError

        def list_outputs(self, basket, tags, limit=100):
            raise NotImplementedError

    signer = WalletSigner(_KeyOneWallet(), (2, "runar"), "1")
    for s in fixture["scenarios"]:
        sig = signer.sign(
            s["unsignedTxHex"], s["inputIndex"], s["prevScriptHex"],
            s["prevValueSats"], s["sighashFlags"],
        )
        assert sig == s["sigHex"], f"{s['scenario']}: WalletSigner diverges from TS reference"
