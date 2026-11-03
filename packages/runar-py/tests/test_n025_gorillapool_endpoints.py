"""N-025: GorillaPoolProvider must call the routes the GorillaPool API actually
serves, decode their documented shapes, and surface a 404 as an error.

The old routes (/tx/{txid}/hex, /address/{a}/utxos, /script/{h}/utxos,
/inscriptions/address/{a}, /bsv20/balance/..., /bsv20/utxos/...) do not exist,
and the provider mapped their 404 to [] / None / '0'.

Proves: replaying the shared recorded responses
(conformance/sdk-gorillapool/endpoint-vectors.json, recorded 2026-10-05) at the
real HTTP boundary (``urlopen``; non-2xx raised as ``HTTPError`` exactly as
urllib does), every call decodes to the independently derived expectation,
every unrouted (404) request raises, tampered bodies (txid mismatch, listing
value != raw tx value, inscription content not matching its hash) are refused,
get_contract_utxo refuses (no documented route), and broadcast posts
{"rawtx": hex}.

N-159: the synthetic listing for 1SyntheticOrdinalAndPlain... holds a 1-sat
BSV-20 inscription output (origin set) before a plain P2PKH output, both in
the recorded tx 8c28...; getUtxos must return only the plain one, so an
inscription the indexer reports is never offered as a funding input. Does
NOT prove: that the live listing populates `origin` for every inscription
or token output, nor anything about outputs that carry `data` but no origin.
Does NOT prove: that the live API still serves these shapes; that POST /api/tx
accepts {"rawtx"} (schema-documented, never sent live); pagination beyond the
API's default page (100).
"""

from __future__ import annotations

import io
import json
import pathlib
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from runar.sdk.gorillapool import GorillaPoolProvider

_VF = json.loads(
    (pathlib.Path(__file__).resolve().parents[3]
     / 'conformance' / 'sdk-gorillapool' / 'endpoint-vectors.json').read_text()
)
_HOST = 'https://ordinals.gorillapool.io'


def _serve(posted: list):
    def fake_urlopen(req, timeout=None):
        method = req.get_method()
        if method == 'POST' and req.data is not None:
            posted.append(req.data.decode('utf-8'))
        route = next(
            (r for r in _VF['routes'] if r['method'] == method and _HOST + r['path'] == req.full_url),
            _VF['notFound'],
        )
        body = bytes.fromhex(route['bodyHex'])
        if not 200 <= route['status'] < 300:
            raise HTTPError(req.full_url, route['status'], 'err', {}, io.BytesIO(body))
        resp = MagicMock()
        resp.read.return_value = body
        resp.status = route['status']
        return resp
    return fake_urlopen


def _utxo_dict(u):
    return {'txid': u.txid, 'outputIndex': u.output_index, 'satoshis': u.satoshis, 'script': u.script}


def _invoke(p: GorillaPoolProvider, c: dict):
    a = c['args']
    name = c['call']
    if name == 'getRawTransaction':
        return p.get_raw_transaction(a[0])
    if name == 'getUtxos':
        return [_utxo_dict(u) for u in p.get_utxos(a[0])]
    if name == 'getContractUtxo':
        u = p.get_contract_utxo(a[0])
        return None if u is None else _utxo_dict(u)
    if name == 'getInscriptionsByAddress':
        return p.get_inscriptions_by_address(a[0])
    if name == 'getInscription':
        return p.get_inscription(a[0])
    if name == 'getBSV20Balance':
        return p.get_bsv20_balance(a[0], a[1])
    if name == 'getBSV21Balance':
        return p.get_bsv21_balance(a[0], a[1])
    if name == 'getBSV20Utxos':
        return [_utxo_dict(u) for u in p.get_bsv20_utxos(a[0], a[1])]
    if name == 'getBSV21Utxos':
        return [_utxo_dict(u) for u in p.get_bsv21_utxos(a[0], a[1])]
    if name == 'broadcast':
        return p.broadcast(a[0])
    raise AssertionError(f'unknown call {name}')


def test_loads_shared_vectors():
    assert len(_VF['calls']) >= 27


@pytest.mark.parametrize(
    'c', _VF['calls'],
    ids=[f"{i}-{c['call']}-{'err' if 'expectError' in c else 'ok'}" for i, c in enumerate(_VF['calls'])],
)
def test_n025_replays_recorded_endpoints(c):
    posted: list = []
    p = GorillaPoolProvider('mainnet')
    with patch('runar.sdk.gorillapool.urlopen', side_effect=_serve(posted)):
        if 'expectError' in c:
            with pytest.raises(Exception) as excinfo:
                _invoke(p, c)
            assert c['expectError'] in str(excinfo.value)
        else:
            assert _invoke(p, c) == c['expect']
    if 'expectRequestJson' in c:
        assert len(posted) == 1
        assert json.loads(posted[0]) == c['expectRequestJson']
