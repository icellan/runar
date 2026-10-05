"""N-041: WhatsOnChainProvider.get_contract_utxo returned script '' and
get_transaction had an empty raw with float-derived satoshis.

WoC's GET /script/{h}/unspent listing carries no locking script, and
GET /tx/hash/{txid} has no ``hex`` field and reports float BTC values.
ExternalSigner passed an empty subscript straight to its callback.

Proves, with conformance/sdk-woc/contract-utxo-tx-vectors.json and a stubbed
urlopen: get_contract_utxo returns the real locking script for both the legacy
array and the {script,result} object listing, None for an empty listing or a
404, and fails loudly on a txid mismatch, a missing output, a value mismatch, a
script hashing to another scripthash, an empty script and an unavailable tx;
get_transaction returns the hash-verified served hex as raw with
inputs/outputs parsed from it and exact 21e14-scale satoshis, and refuses a
body for another txid; ExternalSigner refuses an empty subscript without
calling its callback.
Does NOT prove: that the live WoC API keeps these shapes (recorded
2026-09-29), nor which of several listed UTXOs is the right contract UTXO
(the first entry is used, as before).
"""

from __future__ import annotations

import io
import json
import pathlib
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from runar.sdk.signer import ExternalSigner
from runar.sdk.woc_provider import WhatsOnChainProvider

VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parents[3] / "conformance" / "sdk-woc"
     / "contract-utxo-tx-vectors.json").read_text()
)
BASE = "https://api.whatsonchain.com/v1/bsv/main"


def _serve(routes: dict[str, str]):
    """urlopen stand-in serving exact paths from ``routes``; 404 otherwise."""

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        path = url[len(BASE):] if url.startswith(BASE) else None
        if path not in routes:
            raise HTTPError(url, 404, "Not Found", {}, io.BytesIO(b"Not Found"))
        resp = MagicMock()
        resp.read.return_value = routes[path].encode()
        return resp

    return patch("runar.sdk.woc_provider.urlopen", side_effect=fake_urlopen)


def _routes(listing_path: str, listing: str | None, raw_tx_hex: dict[str, str]) -> dict[str, str]:
    routes = {f"/tx/{txid}/hex": h for txid, h in raw_tx_hex.items()}
    if listing is not None:
        routes[listing_path] = listing
    return routes


def _utxo_dict(u) -> dict:
    return {"txid": u.txid, "outputIndex": u.output_index, "satoshis": u.satoshis, "script": u.script}


CU = VECTORS["contractUtxo"]
LISTING = f"/script/{CU['scriptHash']}/unspent"


@pytest.mark.parametrize("body_key,expected_key", [
    ("legacyBody", "expectedLegacy"),
    ("objectBody", "expectedObject"),
])
def test_get_contract_utxo_returns_real_locking_script(body_key, expected_key):
    with _serve(_routes(LISTING, CU[body_key], CU["rawTxHex"])):
        utxo = WhatsOnChainProvider("mainnet").get_contract_utxo(CU["scriptHash"])
    assert utxo is not None
    assert _utxo_dict(utxo) == CU[expected_key]


@pytest.mark.parametrize("nv", CU["null_vectors"], ids=lambda nv: nv["name"])
def test_get_contract_utxo_returns_none(nv):
    with _serve(_routes(LISTING, nv["body"], {})):
        assert WhatsOnChainProvider("mainnet").get_contract_utxo(CU["scriptHash"]) is None


@pytest.mark.parametrize("rv", CU["rejection_vectors"], ids=lambda rv: rv["name"])
def test_get_contract_utxo_rejections(rv):
    path = f"/script/{rv['scriptHash']}/unspent"
    with _serve(_routes(path, rv["body"], rv["rawTxHex"])):
        with pytest.raises(RuntimeError, match=rv["error"]):
            WhatsOnChainProvider("mainnet").get_contract_utxo(rv["scriptHash"])


@pytest.mark.parametrize("case", VECTORS["getTransaction"]["cases"], ids=lambda c: c["name"])
def test_get_transaction_parses_verified_raw_tx(case):
    routes = {f"/tx/{case['txid']}/hex": case["rawTxHex"], f"/tx/hash/{case['txid']}": case["hashBody"]}
    with _serve(routes):
        tx = WhatsOnChainProvider("mainnet").get_transaction(case["txid"])
    exp = case["expected"]
    assert tx.txid == exp["txid"]
    assert tx.version == exp["version"]
    assert tx.locktime == exp["locktime"]
    assert tx.raw == exp["raw"]
    assert [
        {"txid": i.txid, "outputIndex": i.output_index, "script": i.script, "sequence": i.sequence}
        for i in tx.inputs
    ] == exp["inputs"]
    assert [{"satoshis": o.satoshis, "script": o.script} for o in tx.outputs] == exp["outputs"]
    assert all(isinstance(o.satoshis, int) for o in tx.outputs)


@pytest.mark.parametrize(
    "rv", VECTORS["getTransaction"]["rejection_vectors"], ids=lambda rv: rv["name"])
def test_get_transaction_rejections(rv):
    routes = {}
    if rv["rawTxHex"] is not None:
        routes[f"/tx/{rv['txid']}/hex"] = rv["rawTxHex"]
    if rv["hashBody"] is not None:
        routes[f"/tx/hash/{rv['txid']}"] = rv["hashBody"]
    with _serve(routes):
        with pytest.raises(RuntimeError, match=rv["error"]):
            WhatsOnChainProvider("mainnet").get_transaction(rv["txid"])


def test_external_signer_refuses_empty_subscript():
    calls = []
    signer = ExternalSigner("02" * 33, "addr", lambda *a: calls.append(a) or "deadbeef")
    with pytest.raises(ValueError, match="empty subscript"):
        signer.sign("00", 0, "", 1000)
    assert calls == []
    assert signer.sign("00", 0, "51", 1000) == "deadbeef"
    assert len(calls) == 1


# 1-in/1-out tx spending 11..11:0.
_SPEND_TX_HEX = (
    "01000000" "01" + "11" * 32 + "00000000" "00" "ffffffff"
    "01" "8403000000000000" "01" "51" "00000000"
)


def test_compute_op_push_tx_refuses_empty_subscript():
    """An empty subscript can never match the script the node executes, so it
    is refused. Does not cover a non-empty subscript whose separator is its
    last byte (still accepted)."""
    from runar.sdk.oppushtx import compute_op_push_tx

    with pytest.raises(ValueError, match="empty subscript"):
        compute_op_push_tx(_SPEND_TX_HEX, 0, "", 1000)
    _sig, preimage = compute_op_push_tx(_SPEND_TX_HEX, 0, "51ab51", 1000, 1)
    assert preimage
