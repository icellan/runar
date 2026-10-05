"""Transaction construction for contract deployment."""

from __future__ import annotations
from runar._ripemd160 import ripemd160_digest
from runar.sdk.types import Utxo

# P2PKH sizes for fee estimation
_P2PKH_INPUT_SIZE = 148   # prevTxid(32) + index(4) + scriptSig(~107) + sequence(4) + varint(1)
_P2PKH_OUTPUT_SIZE = 34   # satoshis(8) + varint(1) + P2PKH script(25)
_TX_OVERHEAD = 10          # version(4) + input varint(1) + output varint(1) + locktime(4)


def build_deploy_transaction(
    locking_script: str,
    utxos: list[Utxo],
    satoshis: int,
    change_address: str,
    change_script: str = '',
    fee_rate: int = 100,
) -> tuple[str, int]:
    """Build an unsigned deployment transaction.

    Returns (tx_hex, input_count).
    """
    if not utxos:
        raise ValueError("build_deploy_transaction: no UTXOs provided")

    total_input = sum(u.satoshis for u in utxos)
    fee = estimate_deploy_fee(len(utxos), len(locking_script) // 2, fee_rate)
    change = total_input - satoshis - fee

    if change < 0:
        raise ValueError(
            f"build_deploy_transaction: insufficient funds. "
            f"Need {satoshis + fee} sats, have {total_input}"
        )

    tx = ''
    # Version (4 bytes LE)
    tx += _to_le32(1)
    # Input count
    tx += _encode_varint(len(utxos))

    # Inputs (unsigned)
    for utxo in utxos:
        tx += _reverse_hex(utxo.txid)
        tx += _to_le32(utxo.output_index)
        tx += '00'  # empty scriptSig
        tx += 'ffffffff'

    # Outputs
    has_change = change > 0
    output_count = 2 if has_change else 1
    tx += _encode_varint(output_count)

    # Output 0: contract locking script
    tx += _to_le64(satoshis)
    tx += _encode_varint(len(locking_script) // 2)
    tx += locking_script

    # Output 1: change
    if has_change:
        actual_change_script = change_script or build_p2pkh_script(change_address)
        tx += _to_le64(change)
        tx += _encode_varint(len(actual_change_script) // 2)
        tx += actual_change_script

    # Locktime
    tx += _to_le32(0)

    return tx, len(utxos)


def select_utxos(
    utxos: list[Utxo],
    target_satoshis: int,
    locking_script_byte_len: int,
    fee_rate: int = 100,
    extra_input_bytes: int = 0,
    extra_output_bytes: int = 0,
) -> list[Utxo]:
    """Select the minimum set of UTXOs using largest-first strategy.

    ``extra_input_bytes`` carries the serialized size of any non-P2PKH inputs
    the same tx spends (the contract/covenant input, finding C2); and
    ``extra_output_bytes`` carries the framing of any outputs beyond the single
    continuation (multi-output / raw / data outputs, finding C15). Both keep the
    fee — and therefore how much funding is selected — from being
    under-provisioned. Deploy callers pass nothing (defaults 0), unchanged.
    """
    sorted_utxos = sorted(utxos, key=lambda u: u.satoshis, reverse=True)
    selected: list[Utxo] = []
    total = 0

    for utxo in sorted_utxos:
        selected.append(utxo)
        total += utxo.satoshis
        fee = estimate_deploy_fee(
            len(selected), locking_script_byte_len, fee_rate,
            extra_input_bytes, extra_output_bytes,
        )
        if total >= target_satoshis + fee:
            return selected

    return selected


def estimate_deploy_fee(
    num_inputs: int,
    locking_script_byte_len: int,
    fee_rate: int = 100,
    extra_input_bytes: int = 0,
    extra_output_bytes: int = 0,
) -> int:
    """Estimate the fee for a deploy transaction. Fee rate is in sat/KB.

    ``extra_input_bytes`` (finding C2) is the serialized byte size of any
    NON-P2PKH inputs this fee must also cover (a contract/covenant input being
    spent in the same tx — tens of KB for a MERGE that embeds both parent txs).
    ``extra_output_bytes`` (finding C15) is the serialized framing (8 + varint +
    scriptLen) of every output BEYOND the single ``locking_script_byte_len`` one
    counted here — additional multi-outputs, raw outputs (finding G1), and data
    outputs. Both default to 0, so pure-deploy and funding-only selection are
    byte-for-byte unaffected.
    """
    rate = max(1, fee_rate)
    inputs_size = num_inputs * _P2PKH_INPUT_SIZE + extra_input_bytes
    contract_output_size = 8 + _varint_byte_size(locking_script_byte_len) + locking_script_byte_len
    change_output_size = _P2PKH_OUTPUT_SIZE
    tx_size = _TX_OVERHEAD + inputs_size + contract_output_size + extra_output_bytes + change_output_size
    return (tx_size * rate + 999) // 1000


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode(encoded: str) -> bytes:
    """Decode a Base58-encoded string to bytes."""
    num = 0
    for char in encoded:
        digit = _BASE58_ALPHABET.find(char)
        if digit < 0:
            raise ValueError(f"invalid Base58 character {char!r} in {encoded!r}")
        num = num * 58 + digit
    # Convert to bytes
    result = []
    while num > 0:
        num, rem = divmod(num, 256)
        result.append(rem)
    result.reverse()
    # Leading '1' chars map to zero bytes
    pad = 0
    for char in encoded:
        if char == '1':
            pad += 1
        else:
            break
    return bytes(pad) + bytes(result)


def _address_to_pubkey_hash(address: str) -> str:
    """Extract the 20-byte pubkey hash from a Base58Check P2PKH address.

    Verifies the SHA256d checksum and the version byte (0x00 mainnet,
    0x6f testnet/regtest).
    """
    import hashlib
    decoded = _base58_decode(address)
    # Format: version_byte(1) + pubkey_hash(20) + checksum(4)
    if len(decoded) != 25:
        raise ValueError(f"invalid address length: {len(decoded)}")
    payload = decoded[:21]
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != decoded[21:]:
        raise ValueError(f"invalid address checksum: {address!r}")
    if payload[0] not in (0x00, 0x6F):
        raise ValueError(
            f"unsupported address version byte 0x{payload[0]:02x} "
            f"(expected 0x00 or 0x6f P2PKH): {address}"
        )
    return payload[1:].hex()


def build_p2pkh_script(address_or_pub_key: str) -> str:
    """Build a standard P2PKH locking script.

    Accepted input formats:
    - 40-char hex: treated as raw 20-byte pubkey hash (hash160)
    - 66-char hex: compressed public key (auto-hashed via hash160)
    - 130-char hex: uncompressed public key (auto-hashed via hash160)
    - Other: decoded as Base58Check BSV address
    """
    if len(address_or_pub_key) == 40 and _is_hex(address_or_pub_key):
        pub_key_hash = address_or_pub_key
    elif (
        (len(address_or_pub_key) == 66 or len(address_or_pub_key) == 130)
        and _is_hex(address_or_pub_key)
    ):
        # Compressed (33 bytes) or uncompressed (65 bytes) public key -- hash it
        import hashlib
        pub_key_bytes = bytes.fromhex(address_or_pub_key)
        sha256_hash = hashlib.sha256(pub_key_bytes).digest()
        ripemd160_hash = ripemd160_digest(sha256_hash)
        pub_key_hash = ripemd160_hash.hex()
    else:
        pub_key_hash = _address_to_pubkey_hash(address_or_pub_key)
    return '76a914' + pub_key_hash + '88ac'


# ---------------------------------------------------------------------------
# Wire format helpers
# ---------------------------------------------------------------------------

def _to_le32(n: int) -> str:
    b = n.to_bytes(4, 'little', signed=False)
    return b.hex()


def _to_le64(n: int) -> str:
    b = n.to_bytes(8, 'little', signed=False)
    return b.hex()


def _encode_varint(n: int) -> str:
    if n < 0xFD:
        return f'{n:02x}'
    elif n <= 0xFFFF:
        return 'fd' + n.to_bytes(2, 'little').hex()
    elif n <= 0xFFFFFFFF:
        return 'fe' + n.to_bytes(4, 'little').hex()
    else:
        return 'ff' + n.to_bytes(8, 'little').hex()


def _reverse_hex(hex_str: str) -> str:
    return bytes.fromhex(hex_str)[::-1].hex()


def _varint_byte_size(n: int) -> int:
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False
