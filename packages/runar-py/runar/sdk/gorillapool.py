"""GorillaPoolProvider -- HTTP-based 1sat Ordinals API provider.

Uses only stdlib (urllib.request) for HTTP -- no external dependencies required.

Endpoints:
  Mainnet: https://ordinals.gorillapool.io/api/
  Testnet: https://testnet.ordinals.gorillapool.io/api/
"""

from __future__ import annotations

import hashlib
import json
import struct
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from runar.sdk.provider import Provider
from runar.sdk.types import TransactionData, TxInput, TxOutput, Utxo
from runar.sdk.errors import assert_script_hex_under_limit
from runar.sdk.input_limits import MAX_SCRIPT_BYTES


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
        """Fetch a transaction via GET /tx/{txid}/raw (the bare serialized tx).

        Each output's satoshis is read from its 8-byte little-endian field, so
        values are exact (F-027: the former JSON ``vout[].value`` decode with
        its ``< 1000 -> BTC`` guess targeted a field GorillaPool never
        returns). The body must hash to the requested txid.
        """
        raw = self._get(f'/tx/{txid}/raw')
        body_txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
        if body_txid != txid.lower():
            raise RuntimeError(
                f'GorillaPool getTransaction: txid mismatch: response body hashes to '
                f'{body_txid}, requested {txid}'
            )
        return _decode_raw_tx(body_txid, raw)

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
        # DoS-bound: reject pathological scripts at the provider boundary.
        for u in utxos:
            if not u.script:
                continue
            assert_script_hex_under_limit(
                u.script, MAX_SCRIPT_BYTES,
                f"GorillaPoolProvider.get_utxos({address})",
            )
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
        utxo = Utxo(
            txid=first['txid'],
            output_index=first['vout'],
            satoshis=first['satoshis'],
            script=first.get('script', ''),
        )
        if utxo.script:
            assert_script_hex_under_limit(
                utxo.script, MAX_SCRIPT_BYTES,
                f"GorillaPoolProvider.get_contract_utxo({script_hash})",
            )
        return utxo

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


def _decode_raw_tx(txid: str, raw: bytes) -> TransactionData:
    """Decode a serialized transaction into TransactionData, keeping scriptSigs.

    The SDK's other raw-tx parsers (wallet/oppushtx/local_signer) discard the
    input scripts and do not bounds-check, so this one is local.
    """
    offset = 0

    def read(n: int) -> bytes:
        nonlocal offset
        if offset + n > len(raw):
            raise RuntimeError('GorillaPool getTransaction: truncated transaction')
        chunk = raw[offset:offset + n]
        offset += n
        return chunk

    def read_varint() -> int:
        first = read(1)[0]
        if first < 0xfd:
            return first
        if first == 0xfd:
            return struct.unpack('<H', read(2))[0]
        if first == 0xfe:
            return struct.unpack('<I', read(4))[0]
        return struct.unpack('<Q', read(8))[0]

    version = struct.unpack('<I', read(4))[0]
    inputs: list[TxInput] = []
    for _ in range(read_varint()):
        prev_txid = read(32)[::-1].hex()
        prev_index = struct.unpack('<I', read(4))[0]
        script = read(read_varint()).hex()
        sequence = struct.unpack('<I', read(4))[0]
        inputs.append(TxInput(txid=prev_txid, output_index=prev_index, script=script, sequence=sequence))
    outputs: list[TxOutput] = []
    for _ in range(read_varint()):
        satoshis = struct.unpack('<Q', read(8))[0]
        outputs.append(TxOutput(satoshis=satoshis, script=read(read_varint()).hex()))
    locktime = struct.unpack('<I', read(4))[0]
    if offset != len(raw):
        raise RuntimeError('GorillaPool getTransaction: trailing bytes after transaction')
    return TransactionData(
        txid=txid,
        version=version,
        inputs=inputs,
        outputs=outputs,
        locktime=locktime,
        raw=raw.hex(),
    )
