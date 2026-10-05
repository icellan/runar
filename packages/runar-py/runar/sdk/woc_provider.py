"""WhatsOnChainProvider — HTTP-based BSV API provider.

Uses only stdlib (urllib.request) for HTTP — no external dependencies required.
"""

from __future__ import annotations

import hashlib
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from runar.sdk.provider import Provider
from runar.sdk.types import TransactionData, TxInput, TxOutput, Utxo
from runar.sdk.errors import assert_script_hex_under_limit
from runar.sdk.input_limits import MAX_SCRIPT_BYTES
# The GorillaPool provider's bounds-checked raw-tx decoder (F-027).
from runar.sdk.gorillapool import _decode_raw_tx


class WhatsOnChainProvider(Provider):
    """Implements Provider using the WhatsOnChain REST API."""

    def __init__(self, network: str = 'mainnet'):
        self.network = network
        if network == 'mainnet':
            self.base_url = 'https://api.whatsonchain.com/v1/bsv/main'
        else:
            self.base_url = 'https://api.whatsonchain.com/v1/bsv/test'

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
                f'WoC GET {path} failed ({e.code}): {body.decode("utf-8", errors="replace")}'
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
                f'WoC POST {path} failed ({e.code}): {err_body.decode("utf-8", errors="replace")}'
            ) from e

    def get_transaction(self, txid: str) -> TransactionData:
        """Fetch a transaction, parsed from its hash-verified raw bytes.

        N-041: GET /tx/hash/{txid} has no ``hex`` field and reports values as
        float BTC, so ``raw`` was always empty. The serialized tx is fetched
        via GET /tx/{txid}/hex instead, its double-SHA256 must equal the txid,
        and inputs/outputs (with integer satoshis) are parsed from those bytes.
        """
        return self._fetch_verified_tx(txid, 'getTransaction')

    def _fetch_verified_tx(self, txid: str, context: str) -> TransactionData:
        """GET /tx/{txid}/hex; require double-SHA256 (reversed) == txid; parse."""
        raw_hex = self.get_raw_transaction(txid)
        try:
            body = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise RuntimeError(f'WoC {context}: /tx/{txid}/hex body is not hex: {exc}') from exc
        body_txid = hashlib.sha256(hashlib.sha256(body).digest()).digest()[::-1].hex()
        if body_txid != txid.lower():
            raise RuntimeError(
                f'WoC {context}: txid mismatch: /tx/{txid}/hex body hashes to {body_txid}'
            )
        try:
            return _decode_raw_tx(body_txid, body)
        except RuntimeError as exc:
            raise RuntimeError(f'WoC {context}: parsing tx {txid}: {exc}') from exc

    def broadcast(self, tx) -> str:
        # Accept either a raw hex string or an object with .hex() method
        if isinstance(tx, str):
            raw_tx = tx
        else:
            raw_tx = tx.hex()

        resp_body = self._post_json('/tx/raw', {'txhex': raw_tx})
        # WoC returns the txid as a JSON-encoded string
        txid = json.loads(resp_body)
        if isinstance(txid, str):
            return txid
        return str(txid)

    def get_utxos(self, address: str) -> list[Utxo]:
        """Return the address's UTXOs, each with its real locking script.

        WoC's GET /address/{address}/unspent listing carries outpoints and
        values but no locking script. The script is the BIP-143 scriptCode a
        signer commits to, so an empty one yields signatures no OP_CHECKSIG
        accepts (F-040). Each distinct txid is therefore fetched via
        GET /tx/{txid}/hex, its double-SHA256 must equal the txid, and tx_pos
        must be an output whose value equals the listed value. Any failure
        raises; no UTXO is returned with an empty script.

        Note: WoC caps this legacy listing at about 1000 entries, so an
        address holding more UTXOs is returned truncated.
        """
        raw = self._get(f'/address/{address}/unspent')
        entries = json.loads(raw)

        txs: dict[str, TransactionData] = {}
        utxos: list[Utxo] = []
        for e in entries:
            txid = e['tx_hash']
            tx_pos = e['tx_pos']
            value = e['value']
            tx = txs.get(txid)
            if tx is None:
                tx = self._fetch_verified_tx(txid, 'getUtxos')
                txs[txid] = tx
            if not isinstance(tx_pos, int) or tx_pos < 0 or tx_pos >= len(tx.outputs):
                raise RuntimeError(
                    f'WoC getUtxos: no output {tx_pos} in tx {txid} ({len(tx.outputs)} outputs)'
                )
            out = tx.outputs[tx_pos]
            if out.satoshis != value:
                raise RuntimeError(
                    f'WoC getUtxos: value mismatch for {txid}:{tx_pos}: '
                    f'listing says {value}, tx says {out.satoshis}'
                )
            if not out.script:
                raise RuntimeError(f'WoC getUtxos: empty locking script for {txid}:{tx_pos}')
            assert_script_hex_under_limit(
                out.script, MAX_SCRIPT_BYTES,
                f"WhatsOnChainProvider.get_utxos({address})",
            )
            utxos.append(Utxo(txid=txid, output_index=tx_pos, satoshis=value, script=out.script))
        return utxos

    def get_contract_utxo(self, script_hash: str) -> Utxo | None:
        """Return the first UTXO locked by ``script_hash``, with its real script.

        N-041: WoC's GET /script/{scriptHash}/unspent listing (a legacy array,
        or a ``{script, result}`` object on the /unspent/all family) carries
        outpoints and values but no locking script. The first entry's tx is
        fetched via GET /tx/{txid}/hex and hash-verified; tx_pos must be an
        output whose value equals the listed value, whose script is non-empty
        and hashes (sha256, reversed: WoC's scripthash) to ``script_hash``.
        Any failure raises.
        """
        try:
            raw = self._get(f'/script/{script_hash}/unspent')
        except RuntimeError as e:
            # 404 means no UTXO found
            if '404' in str(e):
                return None
            raise

        listing = json.loads(raw)
        if isinstance(listing, dict) and isinstance(listing.get('result'), list):
            entries = listing['result']
        elif isinstance(listing, list):
            entries = listing
        else:
            raise RuntimeError(f'WoC getContractUtxo: unexpected listing shape for {script_hash}')
        if not entries:
            return None

        first = entries[0]
        txid = first['tx_hash']
        tx_pos = first['tx_pos']
        value = first['value']
        tx = self._fetch_verified_tx(txid, 'getContractUtxo')
        if not isinstance(tx_pos, int) or tx_pos < 0 or tx_pos >= len(tx.outputs):
            raise RuntimeError(
                f'WoC getContractUtxo: no output {tx_pos} in tx {txid} ({len(tx.outputs)} outputs)'
            )
        out = tx.outputs[tx_pos]
        if out.satoshis != value:
            raise RuntimeError(
                f'WoC getContractUtxo: value mismatch for {txid}:{tx_pos}: '
                f'listing says {value}, tx says {out.satoshis}'
            )
        if not out.script:
            raise RuntimeError(f'WoC getContractUtxo: empty locking script for {txid}:{tx_pos}')
        got = hashlib.sha256(bytes.fromhex(out.script)).digest()[::-1].hex()
        if got != script_hash.lower():
            raise RuntimeError(
                f'WoC getContractUtxo: script hash mismatch for {txid}:{tx_pos}: '
                f'output script hashes to {got}, requested {script_hash}'
            )
        assert_script_hex_under_limit(
            out.script, MAX_SCRIPT_BYTES,
            f"WhatsOnChainProvider.get_contract_utxo({script_hash})",
        )
        return Utxo(txid=txid, output_index=tx_pos, satoshis=value, script=out.script)

    def get_network(self) -> str:
        return self.network

    def get_raw_transaction(self, txid: str) -> str:
        raw = self._get(f'/tx/{txid}/hex')
        return raw.decode('utf-8').strip()

    def get_fee_rate(self) -> int:
        # BSV standard relay fee is 0.1 sat/byte (100 sat/KB).
        return 100
