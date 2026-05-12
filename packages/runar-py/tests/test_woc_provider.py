"""HTTP-mocked tests for ``runar.sdk.woc_provider.WhatsOnChainProvider``.

These tests verify the URL shape and response parsing of every public method
on the provider. The HTTP layer is fully mocked via ``unittest.mock.patch``
on ``urllib.request.urlopen`` so no network access is performed.

Audit context (GAP-041): the Python SDK shipped a WoC provider but lacked a
direct unit test asserting URL shape + response parsing. This file closes
that gap by:

  1. Pinning the exact URL (path + base) for each endpoint.
  2. Asserting the parser correctly converts WoC's BSV-denominated values to
     satoshis (round() of value*1e8, matching the implementation).
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
    def test_url_shape_uses_tx_hash_path(self):
        provider = WhatsOnChainProvider("mainnet")
        body = json.dumps({
            "txid": "aa" * 32,
            "version": 1,
            "vin": [],
            "vout": [],
            "locktime": 0,
            "hex": "deadbeef",
        }).encode()

        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            provider.get_transaction("aa" * 32)

        # Inspect the Request object passed to urlopen
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            f"https://api.whatsonchain.com/v1/bsv/main/tx/hash/{'aa' * 32}"
        )
        assert req.get_method() == "GET"

    def test_parses_inputs_outputs_and_satoshi_conversion(self):
        """WoC returns BSV-denominated values; the parser must convert via
        ``round(value * 1e8)`` to satoshis.
        """
        provider = WhatsOnChainProvider("mainnet")
        body = json.dumps({
            "txid": "bb" * 32,
            "version": 2,
            "vin": [
                {
                    "txid": "cc" * 32,
                    "vout": 0,
                    "scriptSig": {"hex": "47304402..."},
                    "sequence": 0xFFFFFFFE,
                }
            ],
            "vout": [
                {"value": 0.0001, "scriptPubKey": {"hex": "76a914...88ac"}},
                {"value": 1.5,    "scriptPubKey": {"hex": "6a..."}},
            ],
            "locktime": 12345,
            "hex": "01000000...",
        }).encode()

        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            tx = provider.get_transaction("bb" * 32)

        assert tx.txid == "bb" * 32
        assert tx.version == 2
        assert tx.locktime == 12345
        assert tx.raw == "01000000..."

        assert len(tx.inputs) == 1
        assert tx.inputs[0].txid == "cc" * 32
        assert tx.inputs[0].output_index == 0
        assert tx.inputs[0].script == "47304402..."
        assert tx.inputs[0].sequence == 0xFFFFFFFE

        assert len(tx.outputs) == 2
        # 0.0001 BSV = 10_000 sats (round of 10000.000000000002 etc).
        assert tx.outputs[0].satoshis == 10_000
        assert tx.outputs[0].script == "76a914...88ac"
        # 1.5 BSV = 150_000_000 sats.
        assert tx.outputs[1].satoshis == 150_000_000
        assert tx.outputs[1].script == "6a..."

    def test_handles_missing_optional_fields(self):
        """vin entries missing scriptSig / sequence must default cleanly."""
        provider = WhatsOnChainProvider("mainnet")
        body = json.dumps({
            "txid": "dd" * 32,
            "vin": [{"txid": "ee" * 32, "vout": 1}],
            "vout": [{"value": 0.0, "scriptPubKey": {"hex": ""}}],
        }).encode()

        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            tx = provider.get_transaction("dd" * 32)

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
        provider = WhatsOnChainProvider("mainnet")
        body = json.dumps([
            {"tx_hash": "aa" * 32, "tx_pos": 0, "value": 12345},
            {"tx_hash": "bb" * 32, "tx_pos": 7, "value": 67890},
        ]).encode()

        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            utxos = provider.get_utxos("1Addr")

        assert len(utxos) == 2
        assert utxos[0].txid == "aa" * 32
        assert utxos[0].output_index == 0
        assert utxos[0].satoshis == 12345
        # WoC unspent endpoint omits the locking script -- empty string is correct.
        assert utxos[0].script == ""
        assert utxos[1].output_index == 7
        assert utxos[1].satoshis == 67890


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
        provider = WhatsOnChainProvider("mainnet")
        body = json.dumps([
            {"tx_hash": "11" * 32, "tx_pos": 2, "value": 1000},
            {"tx_hash": "22" * 32, "tx_pos": 3, "value": 2000},
        ]).encode()
        with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            utxo = provider.get_contract_utxo("scripthash")

        assert utxo is not None
        assert utxo.txid == "11" * 32
        assert utxo.output_index == 2
        assert utxo.satoshis == 1000

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
    provider = WhatsOnChainProvider("testnet")
    body = json.dumps({"txid": "00" * 32, "vin": [], "vout": []}).encode()
    with patch("runar.sdk.woc_provider.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _make_response(body)
        provider.get_transaction("00" * 32)

    req = mock_urlopen.call_args[0][0]
    assert "/v1/bsv/test/" in req.full_url
    assert "/v1/bsv/main/" not in req.full_url
