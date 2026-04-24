"""LocalSigner — private key in memory.

Priority:
  1. If ``bsv-sdk`` is installed, use it (C extensions, fastest).
  2. Otherwise, fall back to the bundled pure-Python ECDSA implementation
     (``runar.ecdsa`` + ``runar.ec``) which provides BIP-143 sighash
     computation and low-S deterministic signing.
  3. Only raise :class:`RuntimeError` if neither path is usable.

The public constructor/API does not change: ``LocalSigner(key_hex)`` with
``get_public_key()``, ``get_address()``, and
``sign(tx_hex, input_index, subscript, satoshis, sighash_type=None)``.
"""

from __future__ import annotations

import hashlib

from runar.sdk.signer import Signer

try:
    from bsv import PrivateKey, PublicKey, Transaction as BsvTransaction  # type: ignore
    from bsv import P2PKH, Script, TransactionInput, TransactionOutput  # type: ignore
    from bsv.constants import SIGHASH  # type: ignore
    _BSV_SDK_AVAILABLE = True
except ImportError:
    _BSV_SDK_AVAILABLE = False


# ---------------------------------------------------------------------------
# Fallback: pure-Python ECDSA via runar.ecdsa + manual BIP-143 sighash
# ---------------------------------------------------------------------------

_FALLBACK_AVAILABLE = False
_FALLBACK_IMPORT_ERROR: Exception | None = None

try:
    from runar.ec import EC_G_X, EC_G_Y, _point_mul  # type: ignore
    from runar.ecdsa import ecdsa_sign  # type: ignore
    _FALLBACK_AVAILABLE = True
except Exception as _e:  # pragma: no cover — only hit if runar.ec itself is broken
    _FALLBACK_IMPORT_ERROR = _e


# Bitcoin / BSV default sighash: SIGHASH_ALL | SIGHASH_FORKID
_SIGHASH_ALL_FORKID = 0x41

# Base58 alphabet (Bitcoin)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class LocalSigner(Signer):
    """Holds a private key in memory for signing transactions.

    Suitable for CLI tooling and testing. For production wallets, use
    ExternalSigner with hardware wallet callbacks instead.

    Prefers the ``bsv-sdk`` package when available; otherwise falls back
    to the bundled pure-Python ECDSA implementation in :mod:`runar.ecdsa`.
    """

    def __init__(self, key_hex: str):
        """Create a LocalSigner from a 64-char hex private key."""
        if _BSV_SDK_AVAILABLE:
            self._backend = 'bsv'
            self._priv_key = PrivateKey(bytes.fromhex(key_hex))
            self._pub_key = self._priv_key.public_key()
            return

        if _FALLBACK_AVAILABLE:
            self._backend = 'fallback'
            # Validate hex + range
            if len(key_hex) != 64:
                raise ValueError(
                    f'LocalSigner: expected 64-char hex private key, got {len(key_hex)} chars'
                )
            priv_int = int(key_hex, 16)
            self._priv_int = priv_int
            # Derive compressed public key: pub = priv * G
            x, y = _point_mul(EC_G_X, EC_G_Y, priv_int)
            prefix = 0x02 if y % 2 == 0 else 0x03
            self._pub_key_bytes = bytes([prefix]) + x.to_bytes(32, 'big')
            self._pub_key_hex = self._pub_key_bytes.hex()
            # Mainnet P2PKH address: Base58Check(0x00 || HASH160(pubkey))
            pkh = hashlib.new(
                'ripemd160', hashlib.sha256(self._pub_key_bytes).digest()
            ).digest()
            self._address = _base58check_encode(b'\x00' + pkh)
            return

        raise RuntimeError(
            'LocalSigner requires either the bsv-sdk package '
            '(install with: pip install bsv-sdk) or the runar.ecdsa fallback '
            f'(which failed to import: {_FALLBACK_IMPORT_ERROR})'
        )

    def get_public_key(self) -> str:
        if self._backend == 'bsv':
            return self._pub_key.hex()
        return self._pub_key_hex

    def get_address(self) -> str:
        if self._backend == 'bsv':
            return self._pub_key.address()
        return self._address

    def sign(
        self,
        tx_hex: str,
        input_index: int,
        subscript: str,
        satoshis: int,
        sighash_type: int | None = None,
    ) -> str:
        """Sign a transaction input using BIP-143 sighash and ECDSA.

        Returns the DER-encoded signature with sighash byte, hex-encoded.
        """
        flag = sighash_type if sighash_type is not None else _SIGHASH_ALL_FORKID

        if self._backend == 'bsv':
            return self._sign_with_bsv(tx_hex, input_index, subscript, satoshis, flag)
        return self._sign_with_fallback(tx_hex, input_index, subscript, satoshis, flag)

    # -- bsv-sdk backed signing (original code) ------------------------------

    def _sign_with_bsv(
        self,
        tx_hex: str,
        input_index: int,
        subscript: str,
        satoshis: int,
        flag: int,
    ) -> str:
        tx = BsvTransaction.from_hex(tx_hex)

        # Set the source output info needed for BIP-143 sighash computation.
        # Create a dummy source transaction with the right output at the right index.
        source_output_index = tx.inputs[input_index].source_output_index
        source_tx = BsvTransaction()
        # Pad with empty outputs up to the source index
        for _ in range(source_output_index):
            source_tx.add_output(TransactionOutput(locking_script=Script(), satoshis=0))
        locking_script = Script(bytes.fromhex(subscript))
        source_tx.add_output(TransactionOutput(
            locking_script=locking_script,
            satoshis=satoshis,
        ))
        tx.inputs[input_index].source_transaction = source_tx

        # Set the unlocking script template so sign() knows how to sign this input
        tx.inputs[input_index].unlocking_script_template = P2PKH().unlock(self._priv_key)

        # Set locking script and satoshis for BIP-143 sighash preimage computation
        tx.inputs[input_index].locking_script = locking_script
        tx.inputs[input_index].satoshis = satoshis

        # Clear existing unlocking script so sign() processes this input
        tx.inputs[input_index].unlocking_script = None

        # Sign the full transaction — this fills in unlocking scripts
        tx.sign()

        # Extract the signature from the signed unlocking script.
        # P2PKH unlocking script: <sig> <pubkey>
        # The signature is the first push data element.
        unlocking_hex = tx.inputs[input_index].unlocking_script.hex()
        sig_hex = _extract_first_push(unlocking_hex)
        return sig_hex

    # -- pure-Python fallback signing ----------------------------------------

    def _sign_with_fallback(
        self,
        tx_hex: str,
        input_index: int,
        subscript: str,
        satoshis: int,
        flag: int,
    ) -> str:
        tx_bytes = bytes.fromhex(tx_hex)
        parsed = _parse_raw_tx(tx_bytes)

        if input_index >= len(parsed['inputs']):
            raise ValueError(
                f'LocalSigner: input index {input_index} out of range '
                f"(tx has {len(parsed['inputs'])} inputs)"
            )

        subscript_bytes = bytes.fromhex(subscript)
        sighash = _bip143_sighash(
            parsed, input_index, subscript_bytes, int(satoshis), flag
        )

        der = ecdsa_sign(self._priv_int, sighash)
        return der.hex() + f'{flag & 0xff:02x}'


# ---------------------------------------------------------------------------
# Helpers shared by both backends
# ---------------------------------------------------------------------------


def _extract_first_push(script_hex: str) -> str:
    """Extract the first push data element from a script hex string."""
    data = bytes.fromhex(script_hex)
    if not data:
        raise ValueError("empty script")
    opcode = data[0]
    if 1 <= opcode <= 75:
        # Direct push: opcode is the length
        return data[1:1 + opcode].hex()
    elif opcode == 0x4c:  # OP_PUSHDATA1
        length = data[1]
        return data[2:2 + length].hex()
    elif opcode == 0x4d:  # OP_PUSHDATA2
        length = int.from_bytes(data[1:3], 'little')
        return data[3:3 + length].hex()
    else:
        raise ValueError(f"unexpected opcode 0x{opcode:02x} at start of script")


# ---------------------------------------------------------------------------
# Fallback: raw transaction parser + BIP-143 sighash
# ---------------------------------------------------------------------------


def _parse_raw_tx(data: bytes) -> dict:
    """Parse a raw Bitcoin transaction into its component parts.

    Returns a dict with keys: version, inputs, outputs, locktime.
    Each input is a dict with prev_txid (32 bytes), prev_output_index (int),
    sequence (int). Each output has satoshis (int) and script (bytes).
    """
    pos = 0

    def _read(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise ValueError('LocalSigner: transaction hex too short')
        chunk = data[pos:pos + n]
        pos += n
        return chunk

    def _read_u32_le() -> int:
        return int.from_bytes(_read(4), 'little')

    def _read_u64_le() -> int:
        return int.from_bytes(_read(8), 'little')

    def _read_var_int() -> int:
        first = _read(1)[0]
        if first < 0xfd:
            return first
        if first == 0xfd:
            return int.from_bytes(_read(2), 'little')
        if first == 0xfe:
            return int.from_bytes(_read(4), 'little')
        return int.from_bytes(_read(8), 'little')

    version = _read_u32_le()

    inputs = []
    in_count = _read_var_int()
    for _ in range(in_count):
        prev_txid = _read(32)
        prev_idx = _read_u32_le()
        script_len = _read_var_int()
        _read(script_len)  # skip scriptSig
        sequence = _read_u32_le()
        inputs.append({
            'prev_txid': prev_txid,
            'prev_output_index': prev_idx,
            'sequence': sequence,
        })

    outputs = []
    out_count = _read_var_int()
    for _ in range(out_count):
        sats = _read_u64_le()
        script_len = _read_var_int()
        script = _read(script_len)
        outputs.append({'satoshis': sats, 'script': bytes(script)})

    locktime = _read_u32_le()

    return {
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime,
    }


def _write_var_int(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return bytes([0xfd]) + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return bytes([0xfe]) + n.to_bytes(4, 'little')
    return bytes([0xff]) + n.to_bytes(8, 'little')


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _bip143_sighash(
    tx: dict,
    input_index: int,
    subscript: bytes,
    satoshis: int,
    sighash_type: int,
) -> bytes:
    """Compute BIP-143 sighash preimage digest."""
    # hashPrevouts = SHA256d(all outpoints)
    prevouts = b''.join(
        inp['prev_txid'] + inp['prev_output_index'].to_bytes(4, 'little')
        for inp in tx['inputs']
    )
    hash_prevouts = _sha256d(prevouts)

    # hashSequence = SHA256d(all sequences)
    seqs = b''.join(inp['sequence'].to_bytes(4, 'little') for inp in tx['inputs'])
    hash_sequence = _sha256d(seqs)

    # hashOutputs = SHA256d(all outputs)
    outs = b''
    for out in tx['outputs']:
        outs += out['satoshis'].to_bytes(8, 'little')
        outs += _write_var_int(len(out['script']))
        outs += out['script']
    hash_outputs = _sha256d(outs)

    inp = tx['inputs'][input_index]
    preimage = (
        tx['version'].to_bytes(4, 'little')
        + hash_prevouts
        + hash_sequence
        + inp['prev_txid']
        + inp['prev_output_index'].to_bytes(4, 'little')
        + _write_var_int(len(subscript))
        + subscript
        + satoshis.to_bytes(8, 'little', signed=False)
        + inp['sequence'].to_bytes(4, 'little')
        + hash_outputs
        + tx['locktime'].to_bytes(4, 'little')
        + (sighash_type & 0xffffffff).to_bytes(4, 'little')
    )

    return _sha256d(preimage)


# ---------------------------------------------------------------------------
# Base58Check encoding (fallback path only)
# ---------------------------------------------------------------------------


def _base58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    full = payload + checksum
    num = int.from_bytes(full, 'big') if full else 0
    encoded = ''
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = _BASE58_ALPHABET[rem] + encoded
    # Leading 0x00 bytes → '1' characters
    for b in full:
        if b == 0:
            encoded = '1' + encoded
        else:
            break
    return encoded
