"""Live BRC-100 WalletClient integration test.

Mirrors integration/ruby/spec/wallet_client_spec.rb. Environment-gated:
runs only when RUNAR_WALLET_ENDPOINT is set to the base URL of a BRC-100
JSON-over-HTTP wallet endpoint. When unset, the test is skipped cleanly so
local + CI runs stay green without any wallet setup.

Optional env:
  RUNAR_WALLET_ENDPOINT — base URL, required
  RUNAR_WALLET_AUTH     — bearer token, optional
  RUNAR_WALLET_BASKET   — basket name, default 'runar-integration-test'

Asserts:
  * get_public_key returns a 33-byte compressed pubkey (66 hex chars,
    prefix 02/03).
  * list_outputs returns a list; each entry (if any) exposes at least
    one of outpoint / satoshis / locking_script / lockingScript.
"""

from __future__ import annotations

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest


ENDPOINT = os.environ.get('RUNAR_WALLET_ENDPOINT', '')
AUTH_TOKEN = os.environ.get('RUNAR_WALLET_AUTH')
BASKET = os.environ.get('RUNAR_WALLET_BASKET', 'runar-integration-test')

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')


def _post(endpoint: str, method: str, body: dict) -> dict:
    url = endpoint.rstrip('/') + '/' + method
    req = Request(
        url,
        data=json.dumps(body).encode('utf-8'),
        method='POST',
        headers={'Content-Type': 'application/json'},
    )
    if AUTH_TOKEN:
        req.add_header('Authorization', f'Bearer {AUTH_TOKEN}')
    try:
        with urlopen(req, timeout=30) as resp:
            data = resp.read()
    except (HTTPError, URLError) as e:
        raise AssertionError(f'wallet {method} request failed: {e}') from e
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise AssertionError(
            f'wallet {method} response not JSON: {data!r}'
        ) from e


@pytest.mark.skipif(
    not ENDPOINT,
    reason=(
        'RUNAR_WALLET_ENDPOINT not set — skipping live BRC-100 wallet round-trip. '
        'Set RUNAR_WALLET_ENDPOINT to a BRC-100 wallet URL to enable.'
    ),
)
def test_wallet_client_live_round_trip() -> None:
    # 1. get_public_key: must return a 33-byte compressed secp256k1 key.
    resp = _post(
        ENDPOINT,
        'getPublicKey',
        {'protocolID': [2, 'runar integration'], 'keyID': '1'},
    )
    pub_key = resp.get('publicKey') or resp.get('publicKeyHex')
    assert pub_key, f'getPublicKey: missing publicKey in response: {resp!r}'
    assert isinstance(pub_key, str), f'getPublicKey: not str: {pub_key!r}'
    assert len(pub_key) == 66, (
        f'getPublicKey: expected 66 hex chars, got {len(pub_key)} ({pub_key!r})'
    )
    assert pub_key[:2] in ('02', '03'), (
        f'getPublicKey: expected compressed prefix 02/03, got {pub_key[:2]!r}'
    )
    assert HEX_RE.match(pub_key), f'getPublicKey: not hex: {pub_key!r}'

    # 2. list_outputs: must return an array (possibly empty).
    resp = _post(
        ENDPOINT,
        'listOutputs',
        {'basket': BASKET, 'tags': [], 'limit': 10},
    )
    outputs = resp.get('outputs') or []
    assert isinstance(outputs, list), f'listOutputs: outputs not a list: {outputs!r}'
    canonical_keys = {'outpoint', 'satoshis', 'lockingScript', 'locking_script'}
    for i, out in enumerate(outputs):
        assert isinstance(out, dict), f'listOutputs[{i}]: not a dict: {out!r}'
        assert canonical_keys.intersection(out.keys()), (
            f'listOutputs[{i}]: missing canonical outpoint/satoshis/lockingScript: {out!r}'
        )
