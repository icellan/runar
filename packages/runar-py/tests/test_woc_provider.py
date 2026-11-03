"""HTTP-mocked tests for ``runar.sdk.woc_provider.WhatsOnChainProvider``.

These tests verify the URL shape and response parsing of every public method
on the provider. The HTTP layer is fully mocked via ``unittest.mock.patch``
on ``urllib.request.urlopen`` so no network access is performed.

Audit context (GAP-041): the Python SDK shipped a WoC provider but lacked a
direct unit test asserting URL shape + response parsing. This file closes
that gap by:

  1. Pinning the exact URL (path + base) for each endpoint.
  2. Asserting get_transaction parses the hash-verified raw tx (N-041: it
     no longer reads /tx/hash/{txid}'s float BSV values).
  3. Asserting the broadcast endpoint sends a JSON ``{"txhex": ...}`` body
     and parses the JSON-encoded txid response.
  4. Asserting the mainnet vs testnet base URL switch works.
"""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch

import pytest

from runar.sdk.woc_provider import WhatsOnChainProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(body: bytes):
    """Return a MagicMock that mimics urlopen's response object."""
    resp = MagicMock()
    resp.read.return_value = body
    return resp


# ---------------------------------------------------------------------------
# Constructor / network selection
# ---------------------------------------------------------------------------

class TestWoCInit:
    def test_default_is_mainnet(self):
        p = WhatsOnChainProvider()
        assert p.network == "mainnet"
        assert p.base_url == "https://api.whatsonchain.com/v1/bsv/main"

    def test_explicit_mainnet(self):
        p = WhatsOnChainProvider(network="mainnet")
        assert p.base_url == "https://api.whatsonchain.com/v1/bsv/main"

    def test_testnet_base_url(self):
        p = WhatsOnChainProvider(network="testnet")
        assert p.network == "testnet"
        assert p.base_url == "https://api.whatsonchain.com/v1/bsv/test"

    def test_get_network_returns_configured_network(self):
        p = WhatsOnChainProvider(network="testnet")
        assert p.get_network() == "testnet"

    def test_fee_rate_is_100_sat_per_kb(self):
        """BSV standard relay fee: 100 sat/KB."""
        assert WhatsOnChainProvider().get_fee_rate() == 100


# ---------------------------------------------------------------------------
# get_transaction
# ---------------------------------------------------------------------------

class TestGetTransaction:
    # N-041: get_transaction read GET /tx/hash/{txid}, whose JSON has no
    # ``hex`` field (raw was always '') and float BSV values. These tests
    # served synthetic /tx/hash bodies with an invented ``hex`` field; they
    # now serve the raw tx at /tx/{txid}/hex from
    # conformance/sdk-woc/contract-utxo-tx-vectors.json and check the same
    # fields (plus raw).

    def test_url_shape_uses_tx_hex_path(self):
        from test_n041_woc_contract_utxo_tx import VECTORS as N041

        case = N041["getTransaction"]["cases"][0]
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(case["rawTxHex"].encode())
            provider.get_transaction(case["txid"])

        # Inspect the Request object passed to urlopen
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            f"https://api.whatsonchain.com/v1/bsv/main/tx/{case['txid']}/hex"
        )
        assert req.get_method() == "GET"

    def test_parses_inputs_outputs_and_exact_satoshis(self):
        """Inputs/outputs come from the raw tx; satoshis are the exact 8-byte
        integer values, not a float BSV conversion.
        """
        from test_n041_woc_contract_utxo_tx import VECTORS as N041

        case = N041["getTransaction"]["cases"][0]
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(case["rawTxHex"].encode())
            tx = provider.get_transaction(case["txid"])

        exp = case["expected"]
        assert tx.txid == case["txid"]
        assert tx.version == 1
        assert tx.locktime == 0
        assert tx.raw == case["rawTxHex"]

        assert len(tx.inputs) == 2
        assert tx.inputs[0].txid == exp["inputs"][0]["txid"]
        assert tx.inputs[0].output_index == 0
        assert tx.inputs[0].script == exp["inputs"][0]["script"]
        assert tx.inputs[0].sequence == 0xFFFFFFFF

        assert len(tx.outputs) == 2
        assert tx.outputs[0].satoshis == 1
        assert tx.outputs[0].script == exp["outputs"][0]["script"]
        assert tx.outputs[1].satoshis == 99_575
        assert tx.outputs[1].script == exp["outputs"][1]["script"]

    def test_handles_empty_scriptsig(self):
        """An input with an empty scriptSig parses to script '' with its sequence."""
        from test_n041_woc_contract_utxo_tx import VECTORS as N041

        case = N041["getTransaction"]["cases"][1]
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(case["rawTxHex"].encode())
            tx = provider.get_transaction(case["txid"])

        assert tx.inputs[0].script == ""
        assert tx.inputs[0].sequence == 0xFFFFFFFF


# ---------------------------------------------------------------------------
# broadcast
# ---------------------------------------------------------------------------

class TestBroadcast:
    def test_posts_json_body_to_tx_raw(self):
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps("ff" * 32).encode())
            provider.broadcast("01000000abcd")

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://api.whatsonchain.com/v1/bsv/main/tx/raw"
        assert req.get_method() == "POST"
        # Content-Type header must be JSON.
        # (urllib lowercases header keys via Request.get_header.)
        assert req.headers.get("Content-type") == "application/json"
        # Body must encode the txhex field.
        body_obj = json.loads(req.data.decode())
        assert body_obj == {"txhex": "01000000abcd"}

    def test_returns_decoded_txid_string(self):
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps("aa" * 32).encode())
            txid = provider.broadcast("deadbeef")
        assert txid == "aa" * 32

    def test_accepts_hex_method_object(self):
        """Tx objects with a .hex() method must be unwrapped before broadcast."""
        provider = WhatsOnChainProvider("mainnet")
        tx_obj = MagicMock()
        tx_obj.hex.return_value = "01abcd"
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps("bb" * 32).encode())
            provider.broadcast(tx_obj)

        body_obj = json.loads(mock_urlopen.call_args[0][0].data.decode())
        assert body_obj == {"txhex": "01abcd"}


# ---------------------------------------------------------------------------
# get_utxos
# ---------------------------------------------------------------------------

class TestGetUtxos:
    def test_url_shape_uses_address_unspent_path(self):
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"[]")
            provider.get_utxos("1SomeAddress")

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            "https://api.whatsonchain.com/v1/bsv/main/address/1SomeAddress/unspent"
        )

    def test_parses_utxo_list(self):
        # F-040: this test used to assert ``script == ""`` as "correct". That
        # empty script became the BIP-143 scriptCode of every funding
        # signature. get_utxos now also fetches /tx/{txid}/hex per UTXO, so the
        # test replays the recorded listing + raw txs (conformance/sdk-woc).
        from test_f040_woc_utxo_script import VECTORS, _serve

        provider = WhatsOnChainProvider("mainnet")
        with _serve(VECTORS["address"], VECTORS["unspentBody"], VECTORS["rawTxHex"]):
            utxos = provider.get_utxos(VECTORS["address"])

        assert len(utxos) == 2
        assert utxos[0].txid == VECTORS["expected"][0]["txid"]
        assert utxos[0].output_index == 1
        assert utxos[0].satoshis == 29884
        assert utxos[0].script == VECTORS["expected"][0]["script"]
        assert utxos[1].output_index == 1
        assert utxos[1].satoshis == 70997


# ---------------------------------------------------------------------------
# get_contract_utxo
# ---------------------------------------------------------------------------

class TestGetContractUtxo:
    def test_url_shape_uses_script_unspent(self):
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"[]")
            provider.get_contract_utxo("00112233")

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            "https://api.whatsonchain.com/v1/bsv/main/script/00112233/unspent"
        )

    def test_returns_first_utxo_when_multiple_present(self):
        # N-041: the listing has no locking script, so get_contract_utxo also
        # fetches /tx/{txid}/hex. This test used synthetic txids with no raw tx
        # behind them; it now replays the recorded two-entry listing.
        from test_n041_woc_contract_utxo_tx import VECTORS as N041, _routes, _serve

        cu = N041["contractUtxo"]
        provider = WhatsOnChainProvider("mainnet")
        listing = f"/script/{cu['scriptHash']}/unspent"
        assert len(json.loads(cu["legacyBody"])) == 2
        with _serve(_routes(listing, cu["legacyBody"], cu["rawTxHex"])):
            utxo = provider.get_contract_utxo(cu["scriptHash"])

        assert utxo is not None
        assert utxo.txid == cu["expectedLegacy"]["txid"]
        assert utxo.output_index == 0
        assert utxo.satoshis == 1
        assert utxo.script == cu["expectedLegacy"]["script"]

    def test_returns_none_for_empty_response(self):
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"[]")
            assert provider.get_contract_utxo("scripthash") is None


# ---------------------------------------------------------------------------
# get_raw_transaction
# ---------------------------------------------------------------------------

class TestGetRawTransaction:
    def test_url_shape_uses_tx_hex(self):
        provider = WhatsOnChainProvider("mainnet")
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"abcdef\n")
            raw = provider.get_raw_transaction("aa" * 32)

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            f"https://api.whatsonchain.com/v1/bsv/main/tx/{'aa' * 32}/hex"
        )
        assert raw == "abcdef"  # trailing whitespace stripped


# ---------------------------------------------------------------------------
# Network switching
# ---------------------------------------------------------------------------

def test_testnet_uses_test_path_for_get_transaction():
    from test_n041_woc_contract_utxo_tx import VECTORS as N041

    case = N041["getTransaction"]["cases"][0]
    provider = WhatsOnChainProvider("testnet")
    with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _make_response(case["rawTxHex"].encode())
        provider.get_transaction(case["txid"])

    req = mock_urlopen.call_args[0][0]
    assert "/v1/bsv/test/" in req.full_url
    assert "/v1/bsv/main/" not in req.full_url
