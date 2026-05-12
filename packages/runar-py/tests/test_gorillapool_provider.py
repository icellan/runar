"""HTTP-mocked tests for ``runar.sdk.gorillapool.GorillaPoolProvider``.

Verifies URL shape and response parsing for every public method, including
the ordinal-specific BSV-20 / BSV-21 endpoints. The HTTP layer is fully
mocked via ``unittest.mock.patch`` on ``urllib.request.urlopen`` so no
network access is performed.

Audit context (GAP-043): the Python SDK shipped a GorillaPool provider but
lacked a direct unit test asserting URL shape + response parsing. This file
closes that gap by:

  1. Pinning the exact URL (path + base) for each endpoint, including the
     ordinal-specific BSV-20 / BSV-21 routes.
  2. Asserting the broadcast endpoint sends a JSON ``{"rawTx": ...}`` body.
  3. Asserting the ordinal-balance / utxo lookups handle URL-encoded ticks.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from runar.sdk.gorillapool import GorillaPoolProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(body: bytes):
    resp = MagicMock()
    resp.read.return_value = body
    return resp


def _make_404():
    """Return an HTTPError raising '404' (used by the provider's fallback paths)."""
    return HTTPError(
        url="x", code=404, msg="Not Found", hdrs={}, fp=MagicMock(read=lambda: b""),
    )


# ---------------------------------------------------------------------------
# Constructor / network selection
# ---------------------------------------------------------------------------

class TestGorillaPoolInit:
    def test_default_is_mainnet(self):
        p = GorillaPoolProvider()
        assert p.network == "mainnet"
        assert p.base_url == "https://ordinals.gorillapool.io/api"

    def test_testnet_base_url(self):
        p = GorillaPoolProvider(network="testnet")
        assert p.network == "testnet"
        assert p.base_url == "https://testnet.ordinals.gorillapool.io/api"

    def test_get_network_returns_configured_value(self):
        assert GorillaPoolProvider("testnet").get_network() == "testnet"

    def test_fee_rate_is_100_sat_per_kb(self):
        assert GorillaPoolProvider().get_fee_rate() == 100


# ---------------------------------------------------------------------------
# get_transaction
# ---------------------------------------------------------------------------

class TestGetTransaction:
    def test_url_shape(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps({"txid": "aa" * 32, "vin": [], "vout": []}).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            provider.get_transaction("aa" * 32)
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == f"https://ordinals.gorillapool.io/api/tx/{'aa' * 32}"

    def test_parses_outputs_with_btc_denominated_value(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps({
            "txid": "bb" * 32,
            "version": 1,
            "vin": [],
            # value < 1000 -> treated as BTC, multiplied by 1e8.
            "vout": [{"value": 0.0001, "scriptPubKey": {"hex": "76a914...88ac"}}],
            "locktime": 0,
            "hex": "01abcd",
        }).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            tx = provider.get_transaction("bb" * 32)
        assert tx.outputs[0].satoshis == 10_000

    def test_parses_outputs_with_satoshi_denominated_value(self):
        """Values >=1000 are treated as already-in-satoshis (GorillaPool returns
        either denomination depending on the endpoint)."""
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps({
            "txid": "cc" * 32,
            "vin": [],
            "vout": [{"value": 50000, "scriptPubKey": {"hex": "abc"}}],
        }).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            tx = provider.get_transaction("cc" * 32)
        # 50000 >= 1000 so the value is already satoshis -> no *1e8.
        assert tx.outputs[0].satoshis == 50000


# ---------------------------------------------------------------------------
# broadcast
# ---------------------------------------------------------------------------

class TestBroadcast:
    def test_posts_json_body_with_rawtx_key(self):
        """GorillaPool's broadcast body uses ``rawTx`` (not ``txhex`` like WoC)."""
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps("aa" * 32).encode())
            provider.broadcast("01abcd")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://ordinals.gorillapool.io/api/tx"
        assert req.get_method() == "POST"
        body_obj = json.loads(req.data.decode())
        assert body_obj == {"rawTx": "01abcd"}

    def test_returns_string_txid_directly(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps("aa" * 32).encode())
            txid = provider.broadcast("01abcd")
        assert txid == "aa" * 32

    def test_returns_txid_from_object_response(self):
        """Some endpoints return ``{"txid": "..."}`` instead of a bare string."""
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(
                json.dumps({"txid": "bb" * 32}).encode()
            )
            txid = provider.broadcast("01abcd")
        assert txid == "bb" * 32

    def test_unwraps_hex_method_object(self):
        provider = GorillaPoolProvider("mainnet")
        tx_obj = MagicMock()
        tx_obj.hex.return_value = "01dead"
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps("aa" * 32).encode())
            provider.broadcast(tx_obj)
        body_obj = json.loads(mock_urlopen.call_args[0][0].data.decode())
        assert body_obj == {"rawTx": "01dead"}


# ---------------------------------------------------------------------------
# get_utxos / get_contract_utxo
# ---------------------------------------------------------------------------

class TestGetUtxos:
    def test_url_shape_uses_address_utxos_path(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"[]")
            provider.get_utxos("1Addr")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://ordinals.gorillapool.io/api/address/1Addr/utxos"

    def test_parses_utxo_list(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps([
            {"txid": "aa" * 32, "vout": 0, "satoshis": 100, "script": "76a9"},
            {"txid": "bb" * 32, "vout": 1, "satoshis": 200, "script": "ac"},
        ]).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            utxos = provider.get_utxos("1Addr")
        assert len(utxos) == 2
        assert utxos[0].satoshis == 100
        assert utxos[0].script == "76a9"
        assert utxos[1].output_index == 1

    def test_returns_empty_list_on_404(self):
        """404 means no UTXOs -- the provider must convert it to []."""
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = _make_404()
            utxos = provider.get_utxos("1Addr")
        assert utxos == []


class TestGetContractUtxo:
    def test_url_shape_uses_script_utxos(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"[]")
            provider.get_contract_utxo("00112233")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            "https://ordinals.gorillapool.io/api/script/00112233/utxos"
        )

    def test_returns_first_utxo(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps([
            {"txid": "11" * 32, "vout": 5, "satoshis": 999, "script": "ac"},
        ]).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            utxo = provider.get_contract_utxo("scripthash")
        assert utxo is not None
        assert utxo.output_index == 5
        assert utxo.satoshis == 999

    def test_returns_none_on_404(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = _make_404()
            assert provider.get_contract_utxo("scripthash") is None


# ---------------------------------------------------------------------------
# get_raw_transaction
# ---------------------------------------------------------------------------

class TestGetRawTransaction:
    def test_url_shape_uses_tx_hex(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"01abcd\n")
            raw = provider.get_raw_transaction("aa" * 32)
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == f"https://ordinals.gorillapool.io/api/tx/{'aa' * 32}/hex"
        assert raw == "01abcd"  # whitespace stripped


# ---------------------------------------------------------------------------
# Ordinal-specific endpoints
# ---------------------------------------------------------------------------

class TestInscriptions:
    def test_get_inscriptions_by_address_url_shape(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"[]")
            inscriptions = provider.get_inscriptions_by_address("1Addr")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            "https://ordinals.gorillapool.io/api/inscriptions/address/1Addr"
        )
        assert inscriptions == []

    def test_get_inscriptions_by_address_returns_empty_on_404(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = _make_404()
            assert provider.get_inscriptions_by_address("1Addr") == []

    def test_get_inscription_url_shape(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps({"txid": "aa" * 32, "vout": 0}).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            data = provider.get_inscription("aa" * 32 + "_0")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            f"https://ordinals.gorillapool.io/api/inscriptions/{'aa' * 32}_0"
        )
        assert data["txid"] == "aa" * 32


class TestBsv20:
    def test_get_bsv20_balance_url_shape_url_encodes_tick(self):
        """Tick names with special characters (e.g. '#' or spaces) must be
        URL-encoded so the API receives the literal value.
        """
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps("100").encode())
            bal = provider.get_bsv20_balance("1Addr", "TICK#1")
        req = mock_urlopen.call_args[0][0]
        # '#' must be URL-encoded to %23.
        assert req.full_url == (
            "https://ordinals.gorillapool.io/api/bsv20/balance/1Addr/TICK%231"
        )
        assert bal == "100"

    def test_get_bsv20_balance_zero_on_404(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = _make_404()
            assert provider.get_bsv20_balance("1Addr", "PEPE") == "0"

    def test_get_bsv20_utxos_url_shape(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps([
            {"txid": "aa" * 32, "vout": 0, "satoshis": 1, "script": "76"},
        ]).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            utxos = provider.get_bsv20_utxos("1Addr", "PEPE")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            "https://ordinals.gorillapool.io/api/bsv20/utxos/1Addr/PEPE"
        )
        assert len(utxos) == 1
        assert utxos[0].satoshis == 1


class TestBsv21:
    def test_get_bsv21_balance_url_shape(self):
        """BSV-21 reuses the bsv20 endpoint with a token_id (txid_vout)."""
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps({"balance": "999"}).encode())
            bal = provider.get_bsv21_balance("1Addr", "aa" * 32 + "_0")
        req = mock_urlopen.call_args[0][0]
        # '_' is not encoded (it's a valid URL char).
        assert req.full_url == (
            f"https://ordinals.gorillapool.io/api/bsv20/balance/1Addr/{'aa' * 32}_0"
        )
        assert bal == "999"

    def test_get_bsv21_utxos_url_shape(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps([
            {"txid": "bb" * 32, "vout": 1, "satoshis": 1, "script": "ac"},
        ]).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            utxos = provider.get_bsv21_utxos("1Addr", "bb" * 32 + "_1")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            f"https://ordinals.gorillapool.io/api/bsv20/utxos/1Addr/{'bb' * 32}_1"
        )
        assert len(utxos) == 1


# ---------------------------------------------------------------------------
# Network switching
# ---------------------------------------------------------------------------

def test_testnet_uses_testnet_base():
    provider = GorillaPoolProvider("testnet")
    body = json.dumps({"txid": "00" * 32, "vin": [], "vout": []}).encode()
    with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _make_response(body)
        provider.get_transaction("00" * 32)
    req = mock_urlopen.call_args[0][0]
    assert req.full_url.startswith("https://testnet.ordinals.gorillapool.io/api/")
