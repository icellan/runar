"""GorillaPoolProvider -- HTTP-based 1sat Ordinals API provider.

Uses only stdlib (urllib.request) for HTTP -- no external dependencies required.

Endpoints:
  Mainnet: https://ordinals.gorillapool.io/api/
  Testnet: https://testnet.ordinals.gorillapool.io/api/
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from urllib.parse import quote
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
        # Inscription content is served at the host root: /content/{outpoint}.
        self.content_base_url = self.base_url[:-len('/api')]

    def _get(self, path: str, base_url: str | None = None) -> bytes:
        """Perform a GET request and return the response body bytes.

        Any non-2xx (a 404 included) raises RuntimeError (N-025).
        """
        url = f'{base_url or self.base_url}{path}'
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
        raw = self._fetch_verified_raw(txid, 'getTransaction')
        return _decode_raw_tx(txid.lower(), raw)

    def broadcast(self, tx) -> str:
        if isinstance(tx, str):
            raw_tx = tx
        else:
            raw_tx = tx.hex()

        # N-025: the documented Broadcast body is {"rawtx": string} (lowercase).
        resp_body = self._post_json('/tx', {'rawtx': raw_tx})
        result = json.loads(resp_body)
        if isinstance(result, str):
            return result
        return str(result.get('txid', ''))

    def get_utxos(self, address: str) -> list[Utxo]:
        """N-025: GET /txos/address/{address}/unspent (Txo[]).

        The listing carries no locking script, so each entry's tx is fetched via
        /tx/{txid}/raw (hash-verified); the output must exist, its value must
        equal the listing's, and its script is returned. Any non-2xx (404
        included) raises. N-159: entries whose ``origin`` is set (1-sat ordinal
        inscriptions, BSV-20 / BSV-21 token outputs) are dropped before any
        fetch -- spending one as a fee input destroys the inscription or token.
        They remain available via get_inscriptions_by_address /
        get_bsv20_utxos / get_bsv21_utxos.
        """
        entries = json.loads(self._get(f'/txos/address/{address}/unspent'))
        txs: dict[str, TransactionData] = {}
        utxos: list[Utxo] = []
        for e in entries:
            if e.get('origin') is not None:
                continue
            txid, vout, sats = e['txid'], e['vout'], e['satoshis']
            tx = txs.get(txid)
            if tx is None:
                tx = _decode_raw_tx(txid, self._fetch_verified_raw(txid, 'getUtxos'))
                txs[txid] = tx
            if not isinstance(vout, int) or vout < 0 or vout >= len(tx.outputs):
                raise RuntimeError(
                    f'GorillaPool getUtxos: no output {vout} in tx {txid} ({len(tx.outputs)} outputs)'
                )
            out = tx.outputs[vout]
            if out.satoshis != sats:
                raise RuntimeError(
                    f'GorillaPool getUtxos: value mismatch for {txid}_{vout}: '
                    f'listing says {sats}, tx says {out.satoshis}'
                )
            if not out.script:
                raise RuntimeError(f'GorillaPool getUtxos: empty locking script for {txid}_{vout}')
            assert_script_hex_under_limit(
                out.script, MAX_SCRIPT_BYTES,
                f"GorillaPoolProvider.get_utxos({address})",
            )
            utxos.append(Utxo(txid=txid, output_index=vout, satoshis=sats, script=out.script))
        return utxos

    def get_contract_utxo(self, script_hash: str) -> Utxo | None:
        """N-025: GorillaPool has no documented route that looks UTXOs up by
        script hash (the former /script/{hash}/utxos is a 404), so this refuses
        rather than reporting "no UTXO".
        """
        raise RuntimeError(
            f'GorillaPool getContractUtxo({script_hash}): lookup by script hash is '
            f'not supported by the GorillaPool API'
        )

    def get_network(self) -> str:
        return self.network

    def get_raw_transaction(self, txid: str) -> str:
        """N-025: GET /tx/{txid}/raw (binary), hash-verified, returned as hex."""
        return self._fetch_verified_raw(txid, 'getRawTransaction').hex()

    def get_fee_rate(self) -> int:
        # BSV standard relay fee: 0.1 sat/byte (100 sat/KB)
        return 100

    # -- Ordinal-specific methods --

    def get_inscriptions_by_address(self, address: str) -> list[dict]:
        """N-025: inscriptions currently held by an address -- the unspent Txos
        from GET /txos/address/{address}/unspent whose ``origin`` is set.

        Returns a list of inscription info dicts with keys:
        txid, vout, origin, contentType, contentLength, height.
        """
        entries = json.loads(self._get(f'/txos/address/{address}/unspent'))
        return [_inscription_info(t) for t in entries if t.get('origin') is not None]

    def get_inscription(self, inscription_id: str) -> dict:
        """N-025: GET /inscriptions/{outpoint} returns a Txo (not a content
        record). The content is GET /content/{outpoint} (host root), and its
        base64 sha256 must equal origin.data.insc.file.hash.

        Args:
            inscription_id: Format ``<txid>_<vout>``

        Returns a dict with keys:
        txid, vout, origin, contentType, contentLength, height, data.
        """
        t = json.loads(self._get(f'/inscriptions/{inscription_id}'))
        if not isinstance(t, dict) or t.get('origin') is None:
            raise RuntimeError(
                f'GorillaPool getInscription: {inscription_id} is not an inscription (no origin)'
            )
        info = _inscription_info(t)
        content = self._get(f'/content/{inscription_id}', base_url=self.content_base_url)
        want = (((t['origin'].get('data') or {}).get('insc') or {}).get('file') or {}).get('hash')
        got = base64.b64encode(hashlib.sha256(content).digest()).decode('ascii')
        if want is None or got != want:
            raise RuntimeError(
                f'GorillaPool getInscription: content hash mismatch for {inscription_id}: '
                f'sha256 {got}, inscription says {want if want is not None else "(none)"}'
            )
        info['data'] = content.hex()
        return info

    def get_bsv20_balance(self, address: str, tick: str) -> str:
        """N-025: BSV-20 (v1, tick-based) confirmed balance, from
        GET /bsv20/{address}/balance. No entry for the tick means "0".
        """
        rows = json.loads(self._get(f'/bsv20/{address}/balance'))
        for r in rows:
            if r.get('tick') == tick:
                return str(r['all']['confirmed'])
        return '0'

    def get_bsv20_utxos(self, address: str, tick: str) -> list[Utxo]:
        """N-025: BSV-20 token UTXOs, from GET /bsv20/{address}/tick/{tick}."""
        rows = json.loads(self._get(f'/bsv20/{address}/tick/{quote(tick, safe="")}'))
        return [_bsv20_utxo(r, 'getBSV20Utxos') for r in rows]

    def get_bsv21_balance(self, address: str, token_id: str) -> str:
        """N-025: BSV-21 (v2, ID-based) confirmed balance, from
        GET /bsv20/{address}/balance. No entry for the id means "0".

        Args:
            token_id: Token ID in format ``<txid>_<vout>``
        """
        rows = json.loads(self._get(f'/bsv20/{address}/balance'))
        for r in rows:
            if r.get('id') == token_id:
                return str(r['all']['confirmed'])
        return '0'

    def get_bsv21_utxos(self, address: str, token_id: str) -> list[Utxo]:
        """N-025: BSV-21 token UTXOs, from GET /bsv20/{address}/id/{id}.

        Args:
            token_id: Token ID in format ``<txid>_<vout>``
        """
        rows = json.loads(self._get(f'/bsv20/{address}/id/{quote(token_id, safe="")}'))
        return [_bsv20_utxo(r, 'getBSV21Utxos') for r in rows]

    # -- Helpers --

    def _fetch_verified_raw(self, txid: str, method: str) -> bytes:
        """GET /tx/{txid}/raw; the body must hash (sha256d, reversed) to txid."""
        raw = self._get(f'/tx/{txid}/raw')
        body_txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
        if body_txid != txid.lower():
            raise RuntimeError(
                f'GorillaPool {method}: txid mismatch: response body hashes to '
                f'{body_txid}, requested {txid}'
            )
        return raw


def _inscription_info(t: dict) -> dict:
    origin = t['origin']
    f = (((origin.get('data') or {}).get('insc') or {}).get('file') or {})
    return {
        'txid': t['txid'],
        'vout': t['vout'],
        'origin': origin['outpoint'],
        'contentType': f.get('type', ''),
        'contentLength': f.get('size', 0),
        'height': t.get('height') or 0,
    }


def _bsv20_utxo(r: dict, method: str) -> Utxo:
    script = base64.b64decode(r['script'], validate=True).hex() if r.get('script') else ''
    if not script:
        raise RuntimeError(f'GorillaPool {method}: no locking script for {r["txid"]}_{r["vout"]}')
    assert_script_hex_under_limit(script, MAX_SCRIPT_BYTES, f'GorillaPoolProvider.{method}')
    return Utxo(txid=r['txid'], output_index=r['vout'], satoshis=r['satoshis'], script=script)


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
