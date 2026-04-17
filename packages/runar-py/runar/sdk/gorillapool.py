"""GorillaPoolProvider -- HTTP-based 1sat Ordinals API provider.

Uses only stdlib (urllib.request) for HTTP -- no external dependencies required.

Endpoints:
  Mainnet: https://ordinals.gorillapool.io/api/
  Testnet: https://testnet.ordinals.gorillapool.io/api/
"""

from __future__ import annotations

import json
import math
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from runar.sdk.provider import Provider
from runar.sdk.types import TransactionData, TxInput, TxOutput, Utxo


class GorillaPoolProvider(Provider):
    """Implements Provider using the GorillaPool 1sat Ordinals REST API."""

    def __init__(self, network: str = 'mainnet'):
        self.network = network
        if network == 'mainnet':
            self.base_url = 'https://ordinals.gorillapool.io/api'
        else:
            self.base_url = 'https://testnet.ordinals.gorillapool.io/api'

    def _get(self, path: str) -> bytes:
        """Perform a GET request and return the response body bytes."""
        url = f'{self.base_url}{path}'
        req = Request(url, method='GET')
        try:
            resp = urlopen(req, timeout=30)
            return resp.read()
        except HTTPError as e:
            body = e.read()
            raise RuntimeError(
                f'GorillaPool GET {path} failed ({e.code}): {body.decode("utf-8", errors="replace")}'
            ) from e

    def _post_json(self, path: str, data: dict) -> bytes:
        """Perform a POST request with JSON body and return the response body bytes."""
        url = f'{self.base_url}{path}'
        body = json.dumps(data).encode('utf-8')
        req = Request(
            url,
            data=body,
            method='POST',
            headers={'Content-Type': 'application/json'},
        )
        try:
            resp = urlopen(req, timeout=30)
            return resp.read()
        except HTTPError as e:
            err_body = e.read()
            raise RuntimeError(
                f'GorillaPool POST {path} failed ({e.code}): {err_body.decode("utf-8", errors="replace")}'
            ) from e

    # -- Standard Provider methods --

    def get_transaction(self, txid: str) -> TransactionData:
        raw = self._get(f'/tx/{txid}')
        data = json.loads(raw)

        inputs: list[TxInput] = []
        for vin in data.get('vin', []):
            inputs.append(TxInput(
                txid=vin['txid'],
                output_index=vin['vout'],
                script=vin.get('scriptSig', {}).get('hex', ''),
                sequence=vin.get('sequence', 0xFFFFFFFF),
            ))

        outputs: list[TxOutput] = []
        for vout in data.get('vout', []):
            value = vout['value']
            # Handle both satoshi-denominated and BTC-denominated responses
            if isinstance(value, (int, float)) and value < 1000:
                satoshis = round(value * 1e8)
            else:
                satoshis = value
            script_hex = vout.get('scriptPubKey', {}).get('hex', '')
            outputs.append(TxOutput(satoshis=satoshis, script=script_hex))

        return TransactionData(
            txid=data['txid'],
            version=data.get('version', 1),
            inputs=inputs,
            outputs=outputs,
            locktime=data.get('locktime', 0),
            raw=data.get('hex', ''),
        )

    def broadcast(self, tx) -> str:
        if isinstance(tx, str):
            raw_tx = tx
        else:
            raw_tx = tx.hex()

        resp_body = self._post_json('/tx', {'rawTx': raw_tx})
        result = json.loads(resp_body)
        if isinstance(result, str):
            return result
        return str(result.get('txid', ''))

    def get_utxos(self, address: str) -> list[Utxo]:
        try:
            raw = self._get(f'/address/{address}/utxos')
        except RuntimeError as e:
            if '404' in str(e):
                return []
            raise

        entries = json.loads(raw)

        utxos: list[Utxo] = []
        for e in entries:
            utxos.append(Utxo(
                txid=e['txid'],
                output_index=e['vout'],
                satoshis=e['satoshis'],
                script=e.get('script', ''),
            ))
        return utxos

    def get_contract_utxo(self, script_hash: str) -> Utxo | None:
        try:
            raw = self._get(f'/script/{script_hash}/utxos')
        except RuntimeError as e:
            if '404' in str(e):
                return None
            raise

        entries = json.loads(raw)
        if not entries:
            return None

        first = entries[0]
        return Utxo(
            txid=first['txid'],
            output_index=first['vout'],
            satoshis=first['satoshis'],
            script=first.get('script', ''),
        )

    def get_network(self) -> str:
        return self.network

    def get_raw_transaction(self, txid: str) -> str:
        raw = self._get(f'/tx/{txid}/hex')
        return raw.decode('utf-8').strip()

    def get_fee_rate(self) -> int:
        # BSV standard relay fee: 0.1 sat/byte (100 sat/KB)
        return 100

    # -- Ordinal-specific methods --

    def get_inscriptions_by_address(self, address: str) -> list[dict]:
        """Get all inscriptions associated with an address.

        Returns a list of inscription info dicts with keys:
        txid, vout, origin, contentType, contentLength, height.
        """
        try:
            raw = self._get(f'/inscriptions/address/{address}')
        except RuntimeError as e:
            if '404' in str(e):
                return []
            raise
        return json.loads(raw)

    def get_inscription(self, inscription_id: str) -> dict:
        """Get inscription details (including content) by inscription ID.

        Args:
            inscription_id: Format ``<txid>_<vout>``

        Returns a dict with keys:
        txid, vout, origin, contentType, contentLength, height, data.
        """
        raw = self._get(f'/inscriptions/{inscription_id}')
        return json.loads(raw)

    def get_bsv20_balance(self, address: str, tick: str) -> str:
        """Get BSV-20 (v1, tick-based) token balance for an address."""
        from urllib.parse import quote
        try:
            raw = self._get(f'/bsv20/balance/{address}/{quote(tick)}')
        except RuntimeError as e:
            if '404' in str(e):
                return '0'
            raise
        result = json.loads(raw)
        if isinstance(result, str):
            return result
        return str(result.get('balance', '0'))

    def get_bsv20_utxos(self, address: str, tick: str) -> list[Utxo]:
        """Get BSV-20 token UTXOs for an address and ticker."""
        from urllib.parse import quote
        try:
            raw = self._get(f'/bsv20/utxos/{address}/{quote(tick)}')
        except RuntimeError as e:
            if '404' in str(e):
                return []
            raise
        entries = json.loads(raw)
        return [
            Utxo(
                txid=e['txid'],
                output_index=e['vout'],
                satoshis=e['satoshis'],
                script=e.get('script', ''),
            )
            for e in entries
        ]

    def get_bsv21_balance(self, address: str, token_id: str) -> str:
        """Get BSV-21 (v2, ID-based) token balance for an address.

        Args:
            token_id: Token ID in format ``<txid>_<vout>``
        """
        from urllib.parse import quote
        try:
            raw = self._get(f'/bsv20/balance/{address}/{quote(token_id)}')
        except RuntimeError as e:
            if '404' in str(e):
                return '0'
            raise
        result = json.loads(raw)
        if isinstance(result, str):
            return result
        return str(result.get('balance', '0'))

    def get_bsv21_utxos(self, address: str, token_id: str) -> list[Utxo]:
        """Get BSV-21 token UTXOs for an address and token ID.

        Args:
            token_id: Token ID in format ``<txid>_<vout>``
        """
        from urllib.parse import quote
        try:
            raw = self._get(f'/bsv20/utxos/{address}/{quote(token_id)}')
        except RuntimeError as e:
            if '404' in str(e):
                return []
            raise
        entries = json.loads(raw)
        return [
            Utxo(
                txid=e['txid'],
                output_index=e['vout'],
                satoshis=e['satoshis'],
                script=e.get('script', ''),
            )
            for e in entries
        ]
