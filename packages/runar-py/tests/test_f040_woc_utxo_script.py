"""F-040: WhatsOnChainProvider.get_utxos returned script '' for every UTXO.

WoC's GET /address/{a}/unspent listing carries no locking script, and the
empty string became the BIP-143 scriptCode in LocalSigner.sign, so every
funding signature was computed over a zero-length scriptCode that no real
P2PKH OP_CHECKSIG accepts.

Proves: with the shared recorded responses (conformance/sdk-woc/vectors.json)
get_utxos fetches GET /tx/{txid}/hex per UTXO and returns the real locking
script; it fails loudly on a body for another txid, a missing output, a value
that disagrees with the tx, an unavailable tx and an empty output script; and
LocalSigner / WalletSigner refuse an empty subscript.
Does NOT prove: that the live WoC API still serves these shapes (vectors
recorded 2026-09-29), or anything about get_contract_utxo. The Spend.validate
harm demo lives in packages/runar-sdk/src/__tests__/f040-woc-utxo-script.test.ts.
"""

from __future__ import annotations

import io
import json
import pathlib
import re
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from runar.sdk.local_signer import LocalSigner
from runar.sdk.wallet import WalletSigner
from runar.sdk.woc_provider import WhatsOnChainProvider

from test_wallet import MockWalletClient

VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parents[3] / "conformance" / "sdk-woc" / "vectors.json").read_text()
)
BASE = "https://api.whatsonchain.com/v1/bsv/main"
_TX_HEX = re.compile(r"/tx/([0-9a-f]{64})/hex$")


def _serve(address: str, unspent_body: str, raw_tx_hex: dict[str, str]):
    """urlopen stand-in: the listing, each raw tx at /tx/{txid}/hex, 404 otherwise."""

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        if url == f"{BASE}/address/{address}/unspent":
            body = unspent_body.encode()
        else:
            m = _TX_HEX.search(url)
            if not (m and m.group(1) in raw_tx_hex):
                raise HTTPError(url, 404, "Not Found", {}, io.BytesIO(b"Not Found"))
            body = raw_tx_hex[m.group(1)].encode()
        resp = MagicMock()
        resp.read.return_value = body
        return resp

    return patch("runar.sdk.woc_provider.urlopen", side_effect=fake_urlopen)


def test_get_utxos_returns_recorded_locking_scripts():
    with _serve(VECTORS["address"], VECTORS["unspentBody"], VECTORS["rawTxHex"]):
        utxos = WhatsOnChainProvider("mainnet").get_utxos(VECTORS["address"])
    got = [
        {"txid": u.txid, "outputIndex": u.output_index, "satoshis": u.satoshis, "script": u.script}
        for u in utxos
    ]
    assert got == VECTORS["expected"]


@pytest.mark.parametrize("rv", VECTORS["rejection_vectors"], ids=lambda rv: rv["name"])
def test_get_utxos_rejection_vectors(rv):
    with _serve(VECTORS["address"], rv["unspentBody"], rv["rawTxHex"]):
        with pytest.raises(RuntimeError, match=re.escape(rv["error"])):
            WhatsOnChainProvider("mainnet").get_utxos(VECTORS["address"])


# 1-in/1-out tx spending 11..11:0.
SPEND_TX_HEX = (
    "01000000" "01" + "11" * 32 + "00000000" "00" "ffffffff" "01" "8403000000000000" "01" "51" "00000000"
)


def test_local_signer_refuses_empty_subscript():
    signer = LocalSigner("01" * 32)
    with pytest.raises(ValueError, match="empty subscript"):
        signer.sign(SPEND_TX_HEX, 0, "", 1000)


def test_wallet_signer_refuses_empty_subscript():
    wallet = MockWalletClient()
    signer = WalletSigner(wallet, protocol_id=(2, "test"), key_id="1")
    with pytest.raises(ValueError, match="empty subscript"):
        signer.sign(SPEND_TX_HEX, 0, "", 1000)
    assert wallet.create_signature_calls == []
