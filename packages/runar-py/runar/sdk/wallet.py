"""BRC-100 wallet integration — WalletClient ABC, WalletProvider, and WalletSigner.

Provides a Provider and Signer backed by a BRC-100 compatible wallet.
WalletClient is an abstract base class that applications must implement to
bridge their specific wallet (browser extension, native app, etc.).

Uses only stdlib (urllib.request, hashlib, struct, json) -- no external deps.
"""

from __future__ import annotations

import hashlib
import json
import struct
from abc import ABC, abstractmethod
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from runar.sdk.provider import Provider
from runar.sdk.signer import Signer
from runar.sdk.types import TransactionData, TxInput, TxOutput, Utxo
from runar.sdk.deployment import build_p2pkh_script


# ---------------------------------------------------------------------------
# WalletClient ABC
# ---------------------------------------------------------------------------

class WalletClient(ABC):
    """Abstract base class for BRC-100 compatible wallet clients.

    Applications must subclass this and implement all four methods to bridge
    their specific wallet implementation.
    """

    @abstractmethod
    def get_public_key(self, protocol_id: tuple, key_id: str) -> str:
        """Derive a public key for the given protocol and key ID.

        Args:
            protocol_id: A (security_level, protocol_name) tuple, e.g. (2, 'my app').
            key_id: Key derivation identifier, e.g. '1'.

        Returns:
            Hex-encoded compressed public key (66 hex chars).
        """
        ...

    @abstractmethod
    def create_signature(self, hash_to_sign: bytes, protocol_id: tuple, key_id: str) -> bytes:
        """Sign a pre-computed hash digest.

        The wallet signs the hash directly (no additional hashing).

        Args:
            hash_to_sign: 32-byte hash digest to sign.
            protocol_id: A (security_level, protocol_name) tuple.
            key_id: Key derivation identifier.

        Returns:
            DER-encoded ECDSA signature bytes (without sighash flag).
        """
        ...

    @abstractmethod
    def create_action(self, description: str, outputs: list[dict]) -> dict:
        """Create a wallet action (transaction) with the specified outputs.

        Args:
            description: Human-readable description of the action.
            outputs: List of output dicts, each with keys:
                - 'locking_script': hex-encoded locking script
                - 'satoshis': output value
                - 'description': output description (optional)
                - 'basket': basket name (optional)
                - 'tags': list of tag strings (optional)

        Returns:
            Dict with at least 'txid' (str) and optionally 'raw_tx' (hex str).
        """
        ...

    @abstractmethod
    def list_outputs(self, basket: str, tags: list[str], limit: int = 100) -> list[dict]:
        """List outputs (UTXOs) from a wallet basket.

        Args:
            basket: Basket name to query.
            tags: Tags to filter outputs by.
            limit: Maximum number of outputs to return.

        Returns:
            List of output dicts, each with keys:
                - 'outpoint': str in 'txid.vout' format
                - 'satoshis': int
                - 'locking_script': hex-encoded locking script (optional)
                - 'spendable': bool
        """
        ...


# ---------------------------------------------------------------------------
# WalletProvider
# ---------------------------------------------------------------------------

MAINNET_ARC_URL = 'https://arc.gorillapool.io'
"""The default ARC broadcaster. A MAINNET endpoint — see R-179."""


class WalletProvider(Provider):
    """Provider implementation backed by a BRC-100 wallet.

    Uses the wallet for UTXO management, GorillaPool ARC for broadcast,
    and an optional overlay service for transaction lookups.
    """

    def __init__(
        self,
        wallet: WalletClient,
        signer: Signer,
        basket: str,
        funding_tag: str = 'funding',
        arc_url: str | None = None,
        overlay_url: str | None = None,
        network: str = 'mainnet',
        fee_rate: int = 100,
    ):
        self.wallet = wallet
        self.signer = signer
        self.basket = basket
        self.funding_tag = funding_tag
        # R-179: arc_url and network used to be defaulted independently, so a
        # provider configured for testnet reported get_network() == 'testnet'
        # and broadcast every transaction to the MAINNET ARC. There is no
        # canonical testnet ARC endpoint to default to, so a non-mainnet
        # provider has to name its own instead of inheriting one that points at
        # real money.
        if arc_url is not None:
            self.arc_url = arc_url
        elif network == 'mainnet':
            self.arc_url = MAINNET_ARC_URL
        else:
            raise ValueError(
                f"WalletProvider: no default ARC endpoint for network {network!r} — "
                f"{MAINNET_ARC_URL} is a MAINNET broadcaster. Pass arc_url explicitly."
            )
        self.overlay_url = overlay_url
        self._network = network
        self._fee_rate = fee_rate
        self._tx_cache: dict[str, str] = {}

    # -- Cache helpers -------------------------------------------------------

    def cache_tx(self, txid: str, raw_hex: str) -> None:
        """Cache a raw transaction hex for future lookups."""
        self._tx_cache[txid] = raw_hex

    def _fetch_raw_tx(self, txid: str) -> str:
        """Fetch raw tx hex: cache first, then overlay, then raise."""
        cached = self._tx_cache.get(txid)
        if cached:
            return cached

        if self.overlay_url:
            try:
                url = f'{self.overlay_url}/api/tx/{txid}/hex'
                req = Request(url, method='GET')
                resp = urlopen(req, timeout=30)
                raw_hex = resp.read().decode('utf-8').strip()
                self._tx_cache[txid] = raw_hex
                return raw_hex
            except (HTTPError, OSError):
                pass

        raise RuntimeError(
            f'WalletProvider: could not fetch tx {txid} '
            f'(not in cache{", overlay returned error" if self.overlay_url else ""})'
        )

    # -- Provider interface --------------------------------------------------

    def get_utxos(self, address: str) -> list[Utxo]:
        """Get UTXOs from the wallet basket, filtered to spendable P2PKH."""
        outputs = self.wallet.list_outputs(
            basket=self.basket,
            tags=[self.funding_tag],
            limit=100,
        )

        derived_pub_key = self.signer.get_public_key()
        expected_script = build_p2pkh_script(derived_pub_key)

        utxos: list[Utxo] = []
        for out in outputs:
            if not out.get('spendable', False):
                continue
            locking_script = out.get('locking_script', '')
            if locking_script and locking_script != expected_script:
                continue

            outpoint = out.get('outpoint', '')
            if '.' not in outpoint:
                continue
            txid, vout_str = outpoint.split('.', 1)
            utxos.append(Utxo(
                txid=txid,
                output_index=int(vout_str),
                satoshis=out.get('satoshis', 0),
                script=locking_script or expected_script,
            ))

        return utxos

    def get_transaction(self, txid: str) -> TransactionData:
        """Fetch transaction data from cache or overlay."""
        cached = self._tx_cache.get(txid)
        if cached:
            try:
                return _parse_raw_tx_to_data(txid, cached)
            except Exception:
                pass

        if self.overlay_url:
            try:
                raw_hex = self._fetch_raw_tx(txid)
                return _parse_raw_tx_to_data(txid, raw_hex)
            except Exception:
                pass

        # Minimal fallback
        return TransactionData(txid=txid, version=1)

    def broadcast(self, tx) -> str:
        """Broadcast a transaction via ARC.

        Accepts either a raw hex string or an object with a .hex() method.
        """
        if isinstance(tx, str):
            raw_hex = tx
        else:
            raw_hex = tx.hex()

        raw_bytes = bytes.fromhex(raw_hex)
        url = f'{self.arc_url}/v1/tx'
        req = Request(
            url,
            data=raw_bytes,
            method='POST',
            headers={'Content-Type': 'application/octet-stream'},
        )
        try:
            resp = urlopen(req, timeout=30)
            result = json.loads(resp.read())
            txid = result.get('txid', '')
            if txid:
                self._tx_cache[txid] = raw_hex
            return txid
        except HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            raise RuntimeError(
                f'WalletProvider: ARC broadcast failed ({e.code}): {body}'
            ) from e

    def get_contract_utxo(self, script_hash: str) -> Utxo | None:
        """Contract UTXOs are typically managed by overlay services, not the wallet."""
        return None

    def get_network(self) -> str:
        return self._network

    def get_fee_rate(self) -> int:
        return self._fee_rate

    def get_raw_transaction(self, txid: str) -> str:
        return self._fetch_raw_tx(txid)

    # -- Funding -------------------------------------------------------------

    def ensure_funding(self, min_satoshis: int) -> None:
        """Ensure there are enough P2PKH funding UTXOs in the wallet basket.

        Creates a new funding UTXO via wallet.create_action() if the balance
        is insufficient.

        Args:
            min_satoshis: Minimum total satoshis required.
        """
        address = self.signer.get_address()
        utxos = self.get_utxos(address)

        total_available = sum(u.satoshis for u in utxos)
        if total_available >= min_satoshis:
            return

        derived_pub_key = self.signer.get_public_key()
        locking_script = build_p2pkh_script(derived_pub_key)
        fund_amount = min_satoshis - total_available

        result = self.wallet.create_action(
            description='Runar contract funding',
            outputs=[{
                'locking_script': locking_script,
                'satoshis': fund_amount,
                'description': 'Funding UTXO',
                'basket': self.basket,
                'tags': [self.funding_tag],
            }],
        )

        # Cache the funding tx
        txid = result.get('txid', '')
        raw_tx = result.get('raw_tx', '')
        if txid and raw_tx:
            self._tx_cache[txid] = raw_tx


# ---------------------------------------------------------------------------
# WalletSigner
# ---------------------------------------------------------------------------

class WalletSigner(Signer):
    """Signer that delegates to a BRC-100 wallet client.

    Computes BIP-143 sighash locally, then sends the pre-hashed digest to
    the wallet for ECDSA signing.
    """

    SIGHASH_ALL_FORKID = 0x41

    def __init__(
        self,
        wallet: WalletClient,
        protocol_id: tuple,
        key_id: str,
    ):
        self._wallet = wallet
        self._protocol_id = protocol_id
        self._key_id = key_id
        self._cached_pub_key: str | None = None

    def get_public_key(self) -> str:
        if self._cached_pub_key is not None:
            return self._cached_pub_key
        pub_key = self._wallet.get_public_key(self._protocol_id, self._key_id)
        self._cached_pub_key = pub_key
        return pub_key

    def get_address(self) -> str:
        """Return the hash160 of the public key as 40-char hex."""
        pub_key_hex = self.get_public_key()
        pub_key_bytes = bytes.fromhex(pub_key_hex)
        sha256_hash = hashlib.sha256(pub_key_bytes).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        return ripemd160_hash.hex()

    def sign(
        self,
        tx_hex: str,
        input_index: int,
        subscript: str,
        satoshis: int,
        sighash_type: int | None = None,
    ) -> str:
        """Sign a transaction input using BIP-143 sighash.

        Computes the BIP-143 preimage and sighash locally, then delegates
        the actual ECDSA signing to the wallet.

        Returns the DER-encoded signature with sighash byte appended, hex-encoded.
        """
        flag = sighash_type if sighash_type is not None else self.SIGHASH_ALL_FORKID

        # 1. Compute BIP-143 preimage
        tx_bytes = bytes.fromhex(tx_hex)
        tx = _parse_raw_tx(tx_bytes)
        subscript_bytes = bytes.fromhex(subscript)
        preimage = _bip143_preimage(tx, input_index, subscript_bytes, satoshis, flag)

        # 2. Double SHA256 = BIP-143 sighash
        sighash = _sha256d(preimage)

        # 3. Send to wallet for signing
        der_sig = self._wallet.create_signature(
            sighash, self._protocol_id, self._key_id,
        )

        # 4. Append sighash flag byte
        return der_sig.hex() + format(flag, '02x')

    def sign_hash(self, sighash_hex: str) -> str:
        """Sign a pre-computed sighash directly.

        Useful for multi-signer flows where the sighash has already been
        computed by prepare_call().

        Args:
            sighash_hex: Pre-computed sighash as hex string.

        Returns:
            DER-encoded signature hex (without sighash flag byte).
        """
        hash_bytes = bytes.fromhex(sighash_hex)
        der_sig = self._wallet.create_signature(
            hash_bytes, self._protocol_id, self._key_id,
        )
        return der_sig.hex()


# ---------------------------------------------------------------------------
# BIP-143 helpers (reused from oppushtx.py patterns, local copy to avoid
# circular imports and keep wallet module self-contained)
# ---------------------------------------------------------------------------

def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _bip143_preimage(
    tx: dict,
    input_index: int,
    subscript: bytes,
    satoshis: int,
    sighash_type: int = 0x41,
) -> bytes:
    # hashPrevouts
    prevouts = b''
    for inp in tx['inputs']:
        prevouts += inp['prev_txid_bytes'] + struct.pack('<I', inp['prev_output_index'])
    hash_prevouts = _sha256d(prevouts)

    # hashSequence
    sequences = b''
    for inp in tx['inputs']:
        sequences += struct.pack('<I', inp['sequence'])
    hash_sequence = _sha256d(sequences)

    # hashOutputs
    outputs_data = b''
    for out in tx['outputs']:
        outputs_data += struct.pack('<Q', out['satoshis'])
        outputs_data += _encode_varint_bytes(len(out['script']))
        outputs_data += out['script']
    hash_outputs = _sha256d(outputs_data)

    # Build preimage
    inp = tx['inputs'][input_index]
    preimage = b''
    preimage += struct.pack('<I', tx['version'])
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += inp['prev_txid_bytes']
    preimage += struct.pack('<I', inp['prev_output_index'])
    preimage += _encode_varint_bytes(len(subscript))
    preimage += subscript
    preimage += struct.pack('<Q', satoshis)
    preimage += struct.pack('<I', inp['sequence'])
    preimage += hash_outputs
    preimage += struct.pack('<I', tx['locktime'])
    preimage += struct.pack('<I', sighash_type)

    return preimage


def _parse_raw_tx(data: bytes) -> dict:
    """Minimal raw transaction parser."""
    offset = 0

    def read(n: int) -> bytes:
        nonlocal offset
        result = data[offset:offset + n]
        offset += n
        return result

    def read_u32() -> int:
        return struct.unpack('<I', read(4))[0]

    def read_u64() -> int:
        return struct.unpack('<Q', read(8))[0]

    def read_varint() -> int:
        first = read(1)[0]
        if first < 0xfd:
            return first
        elif first == 0xfd:
            return struct.unpack('<H', read(2))[0]
        elif first == 0xfe:
            return struct.unpack('<I', read(4))[0]
        else:
            return struct.unpack('<Q', read(8))[0]

    version = read_u32()

    input_count = read_varint()
    inputs = []
    for _ in range(input_count):
        prev_txid = read(32)
        prev_out_idx = read_u32()
        script_len = read_varint()
        _ = read(script_len)
        sequence = read_u32()
        inputs.append({
            'prev_txid_bytes': prev_txid,
            'prev_output_index': prev_out_idx,
            'sequence': sequence,
        })

    output_count = read_varint()
    outputs = []
    for _ in range(output_count):
        sats = read_u64()
        script_len = read_varint()
        script = read(script_len)
        outputs.append({'satoshis': sats, 'script': script})

    locktime = read_u32()

    return {
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime,
    }


def _encode_varint_bytes(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def _parse_raw_tx_to_data(txid: str, raw_hex: str) -> TransactionData:
    """Parse a raw transaction hex into a TransactionData object."""
    data = bytes.fromhex(raw_hex)
    tx = _parse_raw_tx(data)

    inputs: list[TxInput] = []
    for inp in tx['inputs']:
        inputs.append(TxInput(
            txid=inp['prev_txid_bytes'].hex(),
            output_index=inp['prev_output_index'],
            script='',
            sequence=inp['sequence'],
        ))

    outputs: list[TxOutput] = []
    for out in tx['outputs']:
        outputs.append(TxOutput(
            satoshis=out['satoshis'],
            script=out['script'].hex(),
        ))

    return TransactionData(
        txid=txid,
        version=tx['version'],
        inputs=inputs,
        outputs=outputs,
        locktime=tx['locktime'],
        raw=raw_hex,
    )
