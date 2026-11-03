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
  2. Asserting the broadcast endpoint sends a JSON ``{"rawtx": ...}`` body
     (N-025: the documented key is lowercase ``rawtx``).
  3. Asserting the ordinal-balance / utxo lookups handle URL-encoded ticks.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
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

# F-027: GorillaPool's GET /tx/{txid} returns a BINARY body, not the JSON
# ``vout[].value`` the old decoder expected (with a ``value < 1000 -> BTC``
# guess that turned a 1-sat ordinal into 100,000,000 sat). get_transaction now
# fetches GET /tx/{txid}/raw and reads each output's 8-byte LE satoshis.
# These tests replay the shared recorded vectors in conformance/sdk-gorillapool.
# Proves: exact decoding of a real 1-sat output, 999/1000/1e12/2.1e15, the
# input/output shape, and rejection of a body hashing to another txid.
# Does NOT prove the live API still serves /tx/{txid}/raw (recorded 2026-09-27).

_VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parents[3] / "conformance" / "sdk-gorillapool" / "vectors.json").read_text()
)


def _sha256_hex_of_hex(h: str) -> str:
    return hashlib.sha256(bytes.fromhex(h)).hexdigest()


class TestGetTransaction:
    def test_url_shape(self):
        # F-027: the endpoint moved from /tx/{txid} (binary, prefixed) to /tx/{txid}/raw.
        v = _VECTORS["vectors"][0]
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(bytes.fromhex(v["responseHex"]))
            provider.get_transaction(v["txid"])
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == f"https://ordinals.gorillapool.io/api/tx/{v['txid']}/raw"

    # F-027: replaces test_parses_outputs_with_btc_denominated_value and
    # test_parses_outputs_with_satoshi_denominated_value, which pinned the
    # ``< 1000 -> BTC`` heuristic on a JSON field GorillaPool never returns.
    @pytest.mark.parametrize("v", _VECTORS["vectors"], ids=lambda v: v["name"])
    def test_decodes_recorded_raw_tx(self, v):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(bytes.fromhex(v["responseHex"]))
            tx = provider.get_transaction(v["txid"])
        exp = v["expected"]
        assert tx.txid == v["txid"]
        assert tx.version == exp["version"]
        assert tx.locktime == exp["locktime"]
        assert tx.raw == v["responseHex"]
        assert len(tx.inputs) == exp["inputCount"]
        fi, in0 = exp["firstInput"], tx.inputs[0]
        assert in0.txid == fi["txid"]
        assert in0.output_index == fi["outputIndex"]
        assert in0.sequence == fi["sequence"]
        assert len(in0.script) == 2 * fi["scriptLen"]
        assert _sha256_hex_of_hex(in0.script) == fi["scriptSha256"]
        assert [o.satoshis for o in tx.outputs] == [o["satoshis"] for o in exp["outputs"]]
        for got, want in zip(tx.outputs, exp["outputs"]):
            assert isinstance(got.satoshis, int)
            assert len(got.script) == 2 * want["scriptLen"]
            assert _sha256_hex_of_hex(got.script) == want["scriptSha256"]

    @pytest.mark.parametrize("rv", _VECTORS["rejection_vectors"], ids=lambda rv: rv["name"])
    def test_rejects_body_for_another_txid(self, rv):
        src = next(v for v in _VECTORS["vectors"] if v["name"] == rv["responseOf"])
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(bytes.fromhex(src["responseHex"]))
            with pytest.raises(RuntimeError, match="txid mismatch"):
                provider.get_transaction(rv["requestedTxid"])


# ---------------------------------------------------------------------------
# broadcast
# ---------------------------------------------------------------------------

class TestBroadcast:
    # N-025: the documented Broadcast body is {"rawtx": string} (lowercase);
    # these tests previously pinned the undocumented ``rawTx`` key.
    def test_posts_json_body_with_rawtx_key(self):
        """GorillaPool's broadcast body uses ``rawtx`` (not ``txhex`` like WoC)."""
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(json.dumps("aa" * 32).encode())
            provider.broadcast("01abcd")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://ordinals.gorillapool.io/api/tx"
        assert req.get_method() == "POST"
        body_obj = json.loads(req.data.decode())
        assert body_obj == {"rawtx": "01abcd"}

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
        assert body_obj == {"rawtx": "01dead"}


# ---------------------------------------------------------------------------
# get_utxos / get_contract_utxo
# ---------------------------------------------------------------------------

# N-025: /address/{a}/utxos and /script/{h}/utxos do not exist (live 404), and
# the provider mapped that 404 to [] / None. get_utxos now lists
# /txos/address/{a}/unspent and takes each script + value from the verified raw
# tx (/tx/{txid}/raw); a 404 raises. get_contract_utxo refuses (no documented
# route by script hash). The full recorded replay is test_n025_gorillapool_endpoints.py.

class TestGetUtxos:
    def test_url_shape_uses_txos_unspent_path(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"[]")
            assert provider.get_utxos("1Addr") == []
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://ordinals.gorillapool.io/api/txos/address/1Addr/unspent"

    def test_parses_utxo_list_from_verified_raw_tx(self):
        v = _VECTORS["vectors"][0]
        exp_out = v["expected"]["outputs"][0]
        listing = json.dumps([
            {"txid": v["txid"], "vout": 0, "satoshis": exp_out["satoshis"]},
        ]).encode()
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = [
                _make_response(listing),
                _make_response(bytes.fromhex(v["responseHex"])),
            ]
            utxos = provider.get_utxos("1Addr")
        urls = [c[0][0].full_url for c in mock_urlopen.call_args_list]
        assert urls == [
            "https://ordinals.gorillapool.io/api/txos/address/1Addr/unspent",
            f"https://ordinals.gorillapool.io/api/tx/{v['txid']}/raw",
        ]
        assert len(utxos) == 1
        assert utxos[0].txid == v["txid"]
        assert utxos[0].output_index == 0
        assert utxos[0].satoshis == exp_out["satoshis"]
        assert len(utxos[0].script) == 2 * exp_out["scriptLen"]
        assert _sha256_hex_of_hex(utxos[0].script) == exp_out["scriptSha256"]

    def test_raises_on_404(self):
        """N-025: a 404 is an error, never "no UTXOs" (was: returned [])."""
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = _make_404()
            with pytest.raises(RuntimeError, match="404"):
                provider.get_utxos("1Addr")


class TestGetContractUtxo:
    # N-025: replaces test_url_shape_uses_script_utxos / test_returns_first_utxo
    # / test_returns_none_on_404, which pinned a route the API does not serve.
    def test_refuses_without_a_request(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            with pytest.raises(RuntimeError, match="not supported"):
                provider.get_contract_utxo("00112233")
        assert mock_urlopen.call_count == 0


# ---------------------------------------------------------------------------
# get_raw_transaction
# ---------------------------------------------------------------------------

class TestGetRawTransaction:
    # N-025: /tx/{txid}/hex does not exist; the documented route is
    # /tx/{txid}/raw (binary), hash-verified and returned as hex.
    def test_url_shape_uses_tx_raw(self):
        v = _VECTORS["vectors"][0]
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(bytes.fromhex(v["responseHex"]))
            raw = provider.get_raw_transaction(v["txid"])
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == f"https://ordinals.gorillapool.io/api/tx/{v['txid']}/raw"
        assert raw == v["responseHex"]

    def test_rejects_body_for_another_txid(self):
        v = _VECTORS["vectors"][0]
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(bytes.fromhex(v["responseHex"]))
            with pytest.raises(RuntimeError, match="txid mismatch"):
                provider.get_raw_transaction("00" * 32)


# ---------------------------------------------------------------------------
# Ordinal-specific endpoints
# ---------------------------------------------------------------------------

class TestInscriptions:
    # N-025: /inscriptions/address/{a} does not exist; inscriptions held by an
    # address are the unspent Txos with an origin. /inscriptions/{outpoint}
    # returns a Txo; content comes from /content/{outpoint}.
    def test_get_inscriptions_by_address_url_shape(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(b"[]")
            inscriptions = provider.get_inscriptions_by_address("1Addr")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            "https://ordinals.gorillapool.io/api/txos/address/1Addr/unspent"
        )
        assert inscriptions == []

    def test_get_inscriptions_by_address_raises_on_404(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = _make_404()
            with pytest.raises(RuntimeError, match="404"):
                provider.get_inscriptions_by_address("1Addr")

    def test_get_inscription_url_shape(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps({"txid": "aa" * 32, "vout": 0, "origin": None}).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            with pytest.raises(RuntimeError, match="not an inscription"):
                provider.get_inscription("aa" * 32 + "_0")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            f"https://ordinals.gorillapool.io/api/inscriptions/{'aa' * 32}_0"
        )


class TestBsv20:
    # N-025: /bsv20/balance/{a}/{x} and /bsv20/utxos/{a}/{x} do not exist. The
    # documented routes are /bsv20/{a}/balance (TokenBalanceResponse[]) and
    # /bsv20/{a}/tick/{tick} (BSV20Txo[], base64 script).
    def test_get_bsv20_balance_url_shape_and_tick_match(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps([
            {"all": {"confirmed": "100", "pending": "0"}, "listed": {"confirmed": "0", "pending": "0"}, "tick": "TICK#1"},
        ]).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            bal = provider.get_bsv20_balance("1Addr", "TICK#1")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://ordinals.gorillapool.io/api/bsv20/1Addr/balance"
        assert bal == "100"

    def test_get_bsv20_balance_raises_on_404(self):
        provider = GorillaPoolProvider("mainnet")
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = _make_404()
            with pytest.raises(RuntimeError, match="404"):
                provider.get_bsv20_balance("1Addr", "PEPE")

    def test_get_bsv20_utxos_url_shape_url_encodes_tick(self):
        """Tick names with special characters (e.g. '#') must be URL-encoded."""
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps([
            {"txid": "aa" * 32, "vout": 0, "satoshis": 1, "script": "dqw="},
        ]).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            utxos = provider.get_bsv20_utxos("1Addr", "TICK#1")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == (
            "https://ordinals.gorillapool.io/api/bsv20/1Addr/tick/TICK%231"
        )
        assert len(utxos) == 1
        assert utxos[0].satoshis == 1
        assert utxos[0].script == "76ac"


class TestBsv21:
    def test_get_bsv21_balance_url_shape(self):
        """N-025: BSV-21 balance is the /bsv20/{a}/balance entry with this id."""
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps([
            {"all": {"confirmed": "999", "pending": "0"}, "listed": {"confirmed": "0", "pending": "0"}, "id": "aa" * 32 + "_0"},
        ]).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            bal = provider.get_bsv21_balance("1Addr", "aa" * 32 + "_0")
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://ordinals.gorillapool.io/api/bsv20/1Addr/balance"
        assert bal == "999"

    def test_get_bsv21_utxos_url_shape(self):
        provider = GorillaPoolProvider("mainnet")
        body = json.dumps([
            {"txid": "bb" * 32, "vout": 1, "satoshis": 1, "script": "rA=="},
        ]).encode()
        with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _make_response(body)
            utxos = provider.get_bsv21_utxos("1Addr", "bb" * 32 + "_1")
        req = mock_urlopen.call_args[0][0]
        # '_' is not encoded (it's a valid URL char).
        assert req.full_url == (
            f"https://ordinals.gorillapool.io/api/bsv20/1Addr/id/{'bb' * 32}_1"
        )
        assert len(utxos) == 1
        assert utxos[0].script == "ac"


# ---------------------------------------------------------------------------
# Network switching
# ---------------------------------------------------------------------------

def test_testnet_uses_testnet_base():
    provider = GorillaPoolProvider("testnet")
    # F-027: get_transaction now needs a real raw tx body that hashes to the txid.
    v = _VECTORS["vectors"][0]
    with patch("runar.sdk.gorillapool.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _make_response(bytes.fromhex(v["responseHex"]))
        provider.get_transaction(v["txid"])
    req = mock_urlopen.call_args[0][0]
    assert req.full_url.startswith("https://testnet.ordinals.gorillapool.io/api/")
