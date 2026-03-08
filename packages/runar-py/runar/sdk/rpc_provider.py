"""RPCProvider — JSON-RPC provider for Bitcoin nodes.

Uses only stdlib (urllib.request) for HTTP — no external dependencies required.
"""

from __future__ import annotations

import json
import math
from base64 import b64encode
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from runar.sdk.provider import Provider
from runar.sdk.types import Transaction, TxOutput, Utxo


class RPCProvider(Provider):
    """Implements Provider by making JSON-RPC calls to a Bitcoin node."""

    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        *,
        auto_mine: bool = False,
        network: str = 'testnet',
    ):
        self._url = url
        self._auth = b64encode(f'{user}:{password}'.encode()).decode()
        self._auto_mine = auto_mine
        self._network = network

    @classmethod
    def regtest(cls, url: str, user: str, password: str) -> RPCProvider:
        """Create an RPCProvider configured for regtest (auto-mines after broadcast)."""
        return cls(url, user, password, auto_mine=True, network='regtest')

    def _rpc_call(self, method: str, *params: object) -> object:
        body = json.dumps({
            'jsonrpc': '1.0',
            'id': 'runar',
            'method': method,
            'params': list(params),
        }).encode()

        req = Request(
            self._url,
            data=body,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Basic {self._auth}',
            },
        )

        try:
            resp = urlopen(req, timeout=600)
        except HTTPError as e:
            # Bitcoin RPC returns HTTP 500 for rejected transactions
            # but the response body contains the JSON-RPC error details
            body = e.read()
            try:
                data = json.loads(body)
                if data.get('error'):
                    msg = data['error'].get('message', str(data['error']))
                    raise RuntimeError(f'RPC error {data["error"].get("code", "")}: {msg}')
            except (json.JSONDecodeError, KeyError):
                pass
            raise RuntimeError(f'RPC {method}: HTTP {e.code} {e.reason}') from e

        data = json.loads(resp.read())

        if data.get('error'):
            msg = data['error'].get('message', str(data['error']))
            raise RuntimeError(f'RPC {method}: {msg}')

        return data['result']

    def _mine(self, blocks: int) -> None:
        self._rpc_call('generate', blocks)

    def get_transaction(self, txid: str) -> Transaction:
        raw = self._rpc_call('getrawtransaction', txid, True)
        assert isinstance(raw, dict)
        raw_hex = raw.get('hex', '')

        outputs: list[TxOutput] = []
        for o in raw.get('vout', []):
            val_btc = o.get('value', 0.0)
            sats = round(val_btc * 1e8)
            sp = o.get('scriptPubKey', {})
            script_hex = sp.get('hex', '')
            outputs.append(TxOutput(satoshis=sats, script=script_hex))

        return Transaction(
            txid=txid,
            version=1,
            outputs=outputs,
            raw=raw_hex,
        )

    def broadcast(self, raw_tx: str) -> str:
        txid = self._rpc_call('sendrawtransaction', raw_tx)
        assert isinstance(txid, str)
        if self._auto_mine:
            self._mine(1)
        return txid

    def get_utxos(self, address: str) -> list[Utxo]:
        result = self._rpc_call('listunspent', 0, 9999999, [address])
        assert isinstance(result, list)
        utxos: list[Utxo] = []
        for u in result:
            utxos.append(Utxo(
                txid=u['txid'],
                output_index=int(u['vout']),
                satoshis=round(u['amount'] * 1e8),
                script=u.get('scriptPubKey', ''),
            ))
        return utxos

    def get_contract_utxo(self, script_hash: str) -> Utxo | None:
        return None

    def get_network(self) -> str:
        return self._network

    def get_fee_rate(self) -> int:
        return 1
