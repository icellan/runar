"""OP_PUSH_TX helper for checkPreimage contracts.

Computes the BIP-143 sighash preimage and OP_PUSH_TX signature for contracts
that use checkPreimage() (both stateful and stateless).

The OP_PUSH_TX technique uses private key k=1 (public key = generator point G).
The on-chain script derives the signature from the preimage, so both must be
provided in the unlocking script.

Zero external dependencies — uses only hashlib and pure-Python ECDSA with k=1.
"""

from __future__ import annotations

import hashlib
import struct

# secp256k1 curve parameters
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

SIGHASH_ALL_FORKID = 0x41


def compute_op_push_tx(
    tx_hex: str,
    input_index: int,
    subscript: str,
    satoshis: int,
    code_separator_index: int = -1,
) -> tuple[str, str]:
    """Compute the OP_PUSH_TX DER signature and BIP-143 preimage.

    Returns (sig_hex, preimage_hex) where sig_hex includes the sighash byte.
    """
    # If OP_CODESEPARATOR is present, use only the script after it as scriptCode.
    effective_subscript = subscript
    if code_separator_index >= 0:
        trim_pos = (code_separator_index + 1) * 2
        if trim_pos <= len(subscript):
            effective_subscript = subscript[trim_pos:]
    tx_bytes = bytes.fromhex(tx_hex)
    tx = _parse_raw_tx(tx_bytes)
    subscript_bytes = bytes.fromhex(effective_subscript)

    preimage = _bip143_preimage(tx, input_index, subscript_bytes, satoshis)
    sighash = _sha256d(preimage)

    # Sign with k=1 private key
    sig_r, sig_s = _ecdsa_sign_k1(sighash)

    # Enforce low-S
    half_n = _N >> 1
    if sig_s > half_n:
        sig_s = _N - sig_s

    # DER encode
    der = _der_encode(sig_r, sig_s)
    sig_hex = der.hex() + format(SIGHASH_ALL_FORKID, '02x')
    preimage_hex = preimage.hex()

    return sig_hex, preimage_hex


# ---------------------------------------------------------------------------
# ECDSA with k=1 (OP_PUSH_TX)
# ---------------------------------------------------------------------------

def _modinv(a: int, m: int) -> int:
    """Modular inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError('no modular inverse')
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _ec_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1) * _modinv(2 * y1, _P) % _P
    elif x1 == x2:
        return None
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _ec_mul(k: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _ecdsa_sign_k1(msg_hash: bytes) -> tuple[int, int]:
    """Sign a message hash with private key = 1 and nonce k = 1.

    For OP_PUSH_TX, we use private key d=1 (pubkey = G).
    We use deterministic k=1 for the nonce (since the on-chain
    script derives the signature algebraically, the exact k doesn't matter
    as long as it's consistent).
    """
    z = int.from_bytes(msg_hash, 'big')
    # k = 1, R = k*G = G
    r = _Gx % _N
    # s = k^{-1} * (z + r*d) mod N, where d=1, k=1
    s = _modinv(1, _N) * (z + r * 1) % _N  # k_inv = 1
    return r, s


def _der_encode(r: int, s: int) -> bytes:
    """DER-encode an ECDSA signature (r, s)."""
    r_bytes = _int_to_signed_bytes(r)
    s_bytes = _int_to_signed_bytes(s)
    payload = b'\x02' + bytes([len(r_bytes)]) + r_bytes + b'\x02' + bytes([len(s_bytes)]) + s_bytes
    return b'\x30' + bytes([len(payload)]) + payload


def _int_to_signed_bytes(n: int) -> bytes:
    """Convert a positive integer to DER integer bytes (minimal, signed)."""
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return b


# ---------------------------------------------------------------------------
# BIP-143 preimage computation
# ---------------------------------------------------------------------------

def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _bip143_preimage(
    tx: dict,
    input_index: int,
    subscript: bytes,
    satoshis: int,
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
        outputs_data += _encode_varint(len(out['script']))
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
    preimage += _encode_varint(len(subscript))
    preimage += subscript
    preimage += struct.pack('<Q', satoshis)
    preimage += struct.pack('<I', inp['sequence'])
    preimage += hash_outputs
    preimage += struct.pack('<I', tx['locktime'])
    preimage += struct.pack('<I', SIGHASH_ALL_FORKID)

    return preimage


# ---------------------------------------------------------------------------
# Minimal raw transaction parser
# ---------------------------------------------------------------------------

def _parse_raw_tx(data: bytes) -> dict:
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
        _ = read(script_len)  # skip scriptSig
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


def _encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)
