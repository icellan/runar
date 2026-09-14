"""State serialization — encode/decode state values as raw bytes matching NUM2BIN format."""

from __future__ import annotations
from runar.sdk.types import RunarArtifact, StateField


def _parse_fixed_array_dims(type_str: str) -> list[int]:
    """Parse outer dimensions from a nested FixedArray type string.

    ``"FixedArray<FixedArray<bigint, 2>, 3>"`` -> ``[3, 2]``.
    Non-FixedArray types return ``[]``.
    """
    dims: list[int] = []
    current = type_str.strip()
    while current.startswith("FixedArray<"):
        inner = current[len("FixedArray<"):-1]
        depth = 0
        split_at = -1
        for i in range(len(inner) - 1, -1, -1):
            ch = inner[i]
            if ch == ">":
                depth += 1
            elif ch == "<":
                depth -= 1
            elif ch == "," and depth == 0:
                split_at = i
                break
        if split_at < 0:
            return dims
        elem_type = inner[:split_at].strip()
        len_str = inner[split_at + 1:].strip()
        try:
            n = int(len_str)
        except ValueError:
            return dims
        if n <= 0:
            return dims
        dims.append(n)
        current = elem_type
    return dims


def _unwrap_fixed_array_leaf(type_str: str) -> str:
    """Return the innermost scalar type of a nested FixedArray string."""
    current = type_str.strip()
    while current.startswith("FixedArray<"):
        inner = current[len("FixedArray<"):-1]
        depth = 0
        split_at = -1
        for i in range(len(inner) - 1, -1, -1):
            ch = inner[i]
            if ch == ">":
                depth += 1
            elif ch == "<":
                depth -= 1
            elif ch == "," and depth == 0:
                split_at = i
                break
        if split_at < 0:
            return current
        current = inner[:split_at].strip()
    return current


def _flatten_nested(value, dims: list[int]) -> list:
    """Flatten a nested Python list of depth ``len(dims)`` to a flat leaf list."""
    if not dims:
        return [value]
    if not isinstance(value, (list, tuple)):
        total = 1
        for d in dims:
            total *= d
        return [None] * total
    rest = dims[1:]
    out: list = []
    for v in value:
        out.extend(_flatten_nested(v, rest))
    return out


def _regroup_nested(flat: list, dims: list[int], offset: int = 0):
    """Rebuild a nested list of depth ``len(dims)`` from ``flat``.

    Returns ``(value, consumed)``.
    """
    if not dims:
        return [], 0
    outer_len = dims[0]
    rest = dims[1:]
    value: list = [None] * outer_len
    consumed = 0
    if not rest:
        for i in range(outer_len):
            value[i] = flat[offset + i]
        consumed = outer_len
    else:
        for i in range(outer_len):
            sub, sub_consumed = _regroup_nested(flat, rest, offset + consumed)
            value[i] = sub
            consumed += sub_consumed
    return value, consumed


def serialize_state(fields: list[StateField], values: dict) -> str:
    """Encode state values into hex-encoded raw byte section (no push opcodes).

    Fields with a ``fixed_array`` annotation may be supplied either as a plain
    Python list on the grouped name (``values['board'] = [0, 0, ...]``) or as
    underlying scalar entries (``values['board__0'] = ...``). Scalars win if
    both are present.
    """
    sorted_fields = sorted(fields, key=lambda f: f.index)
    hex_str = ''
    for field in sorted_fields:
        fa = getattr(field, 'fixed_array', None)
        if fa:
            arr = values.get(field.name)
            names = fa['syntheticNames']
            leaf_type = _unwrap_fixed_array_leaf(field.type)
            dims = _parse_fixed_array_dims(field.type)
            flat_from_arr = _flatten_nested(arr, dims) if isinstance(arr, (list, tuple)) else None
            for i, synth_name in enumerate(names):
                if synth_name in values:
                    elem = values[synth_name]
                elif flat_from_arr is not None:
                    elem = flat_from_arr[i]
                else:
                    elem = None
                hex_str += _encode_state_value(elem, leaf_type, synth_name)
        else:
            value = values.get(field.name)
            hex_str += _encode_state_value(value, field.type, field.name)
    return hex_str


def deserialize_state(fields: list[StateField], script_hex: str) -> dict:
    """Decode state values from a hex-encoded raw byte section.

    Fields with a ``fixed_array`` annotation are returned as a plain Python
    list (possibly nested) on the grouped name, not as N individual scalars.
    """
    sorted_fields = sorted(fields, key=lambda f: f.index)
    result: dict = {}
    offset = 0
    for field in sorted_fields:
        fa = getattr(field, 'fixed_array', None)
        if fa:
            leaf_type = _unwrap_fixed_array_leaf(field.type)
            dims = _parse_fixed_array_dims(field.type)
            total = len(fa['syntheticNames'])
            flat: list = [None] * total
            for i in range(total):
                value, bytes_read = _decode_state_value(script_hex, offset, leaf_type)
                flat[i] = value
                offset += bytes_read
            result[field.name], _ = _regroup_nested(flat, dims)
        else:
            value, bytes_read = _decode_state_value(script_hex, offset, field.type)
            result[field.name] = value
            offset += bytes_read
    return result


def extract_state_from_script(artifact: RunarArtifact, script_hex: str) -> dict | None:
    """Extract state values from a full locking script hex."""
    if not artifact.state_fields:
        return None
    op_return_pos = find_last_op_return(script_hex)
    if op_return_pos == -1:
        return None
    state_hex = script_hex[op_return_pos + 2:]
    return deserialize_state(artifact.state_fields, state_hex)


def find_last_op_return(script_hex: str) -> int:
    """Find the last OP_RETURN (0x6a) at a real opcode boundary.

    Returns the hex-char offset, or -1 if not found.
    """
    last_pos = -1
    offset = 0
    length = len(script_hex)

    while offset + 2 <= length:
        opcode = int(script_hex[offset:offset + 2], 16)

        if opcode == 0x6A:
            # OP_RETURN at a real opcode boundary. Everything after is
            # raw state data (not opcodes), so stop walking immediately.
            return offset
        elif 0x01 <= opcode <= 0x4B:
            offset += 2 + opcode * 2
        elif opcode == 0x4C:
            if offset + 4 > length:
                break
            push_len = int(script_hex[offset + 2:offset + 4], 16)
            offset += 4 + push_len * 2
        elif opcode == 0x4D:
            if offset + 6 > length:
                break
            lo = int(script_hex[offset + 2:offset + 4], 16)
            hi = int(script_hex[offset + 4:offset + 6], 16)
            push_len = lo | (hi << 8)
            offset += 6 + push_len * 2
        elif opcode == 0x4E:
            if offset + 10 > length:
                break
            b = bytes.fromhex(script_hex[offset + 2:offset + 10])
            push_len = int.from_bytes(b, 'little')
            offset += 10 + push_len * 2
        else:
            offset += 2

    return last_pos


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _encode_num2bin(n: int, width: int, label: str = '?') -> str:
    """Encode an integer as fixed-width LE sign-magnitude bytes (NUM2BIN format).

    FAILS CLOSED on an out-of-range magnitude. ``width`` bytes of
    sign-magnitude hold ``8*width - 1`` magnitude bits — the top bit of the
    last byte is the sign. The loop below writes the low ``width`` bytes and
    drops everything above, then ORs the sign bit in on top of whatever landed
    there, so an oversized value used to serialise to a plausible but WRONG
    word::

        2^63      -> 0000000000000080   reads back as 0   (negative zero)
        2^63 + 5  -> 0500000000000080   reads back as -5  (sign flip)
        2^64      -> 0000000000000000   reads back as 0

    The deploy then succeeded and the UTXO was unspendable: the covenant
    rebuilds the continuation with the compiler's own OP_NUM2BIN ``width``,
    which cannot produce those bytes from that number, so ``hash256(outputs)``
    never matches. Raising here is the only place a runtime-computed state
    value can be stopped — ``±(2^(8*width-1) - 1)`` remains representable and
    is unaffected.
    """
    limit = 1 << (8 * width - 1)
    if n >= limit or n <= -limit:
        raise ValueError(
            f'serialize_state: bigint state field "{label}" = {n} does not fit the '
            f'fixed {width}-byte sign-magnitude state word (magnitude must be < '
            f'2^{8 * width - 1}). Serializing it would write a different number into '
            f"the state section than the contract's on-chain OP_NUM2BIN {width} "
            f'rebuilds, leaving the output unspendable.'
        )

    result_bytes = bytearray(width)
    negative = n < 0
    abs_val = abs(n)

    for i in range(width):
        if abs_val == 0:
            break
        result_bytes[i] = abs_val & 0xFF
        abs_val >>= 8

    if negative:
        result_bytes[width - 1] |= 0x80

    return result_bytes.hex()


def _decode_num2bin(hex_str: str) -> int:
    """Decode a fixed-width LE sign-magnitude number from hex."""
    if not hex_str:
        return 0

    b = bytearray.fromhex(hex_str)
    negative = (b[-1] & 0x80) != 0
    b[-1] &= 0x7F

    result = 0
    for i in range(len(b) - 1, -1, -1):
        result = (result << 8) | b[i]

    if result == 0:
        return 0
    return -result if negative else result


def encode_push_data_state(data_hex: str) -> str:
    """Frame hex data as a state-section field: ``<len><data>``.

    Deliberately NOT the MINIMALDATA push encoding used by
    :func:`encode_push_data`. The state section is raw data after ``OP_RETURN``
    in the locking script; the interpreter never executes it, so
    ``SCRIPT_VERIFY_MINIMALDATA`` — a rule applied to push opcodes as they are
    executed — does not reach it. What does read it is the compiler's on-chain
    state codec (``emitPushDataEncode`` in
    packages/runar-compiler/src/passes/05-stack-lower.ts), which writes and
    parses ``<len><data>``. Both sides must agree byte for byte or the
    continuation hash check fails and the contract is unspendable.

    #110 applied the MINIMALDATA short-circuit here, in all seven SDKs and none
    of the seven compilers, so a 1-byte ``0x05`` state field serialised
    off-chain as ``55`` while the script rebuilt it as ``0105``.
    Byte-identical with the other six SDKs.
    """
    data_len = len(data_hex) // 2

    if data_len <= 75:
        return f'{data_len:02x}' + data_hex
    elif data_len <= 0xFF:
        return '4c' + f'{data_len:02x}' + data_hex
    elif data_len <= 0xFFFF:
        return '4d' + data_len.to_bytes(2, 'little').hex() + data_hex
    else:
        return '4e' + data_len.to_bytes(4, 'little').hex() + data_hex


def encode_push_data(data_hex: str) -> str:
    """Wrap hex data in a Bitcoin Script push data opcode.

    Applies BSV consensus rule ``SCRIPT_VERIFY_MINIMALDATA`` for single-byte
    pushes: a 1-byte payload whose value is in ``{0x01..=0x10, 0x81}`` MUST use
    the corresponding minimal opcode (``OP_1..OP_16`` / ``OP_1NEGATE``) rather
    than the direct push ``01 NN``. Non-minimal direct pushes are rejected at
    the relay layer with
    ``non-mandatory-script-verify-flag (Data push larger than necessary)``.

    NOTE: 0x00 is deliberately NOT in that set. ``OP_0`` pushes the EMPTY byte
    array, not a 1-byte ``0x00`` — so the minimal encoding of a 1-byte ``0x00``
    payload is the direct push ``01 00`` (matching the compiler's
    ``encodePushBytesHex`` in push-encoding.ts), not ``OP_0`` (C9 / S1).
    """
    data_len = len(data_hex) // 2

    # MINIMALDATA: single-byte payloads in the OP_N range must use the
    # corresponding minimal opcode. The script-number encoder already
    # short-circuits OP_N for Int fields; this brings the ByteString push
    # path to the same standard so a 1-byte ByteString value does not emit
    # a relay-rejected non-minimal direct push.
    if data_len == 1:
        byte = int(data_hex, 16)
        if 0x01 <= byte <= 0x10:
            return f'{0x50 + byte:02x}'  # OP_1..OP_16
        if byte == 0x81:
            return '4f'  # OP_1NEGATE

    if data_len <= 75:
        return f'{data_len:02x}' + data_hex
    elif data_len <= 0xFF:
        return '4c' + f'{data_len:02x}' + data_hex
    elif data_len <= 0xFFFF:
        return '4d' + data_len.to_bytes(2, 'little').hex() + data_hex
    else:
        return '4e' + data_len.to_bytes(4, 'little').hex() + data_hex


def decode_push_data(hex_str: str, offset: int) -> tuple[str, int]:
    """Decode a Bitcoin Script push data at the given hex offset.

    Returns (data_hex, hex_chars_consumed).

    Exact inverse of :func:`encode_push_data_state`, and deliberately as
    strict as the compiler's on-chain state reader: only ``<len><data>``
    framing is understood. ``OP_1..OP_16`` (0x51..0x60) and ``OP_1NEGATE``
    (0x4f) are NOT decoded as single-byte values — accepting them would let
    the SDK read a state section the contract's own script cannot parse.
    ``OP_0`` (0x00) falls through to the ``opcode <= 75`` branch below and
    correctly decodes as the empty byte array (0-length push).
    """
    if offset >= len(hex_str):
        return '', 0

    opcode = int(hex_str[offset:offset + 2], 16)

    if opcode <= 75:
        data_len = opcode * 2
        return hex_str[offset + 2:offset + 2 + data_len], 2 + data_len
    elif opcode == 0x4C:
        length = int(hex_str[offset + 2:offset + 4], 16)
        data_len = length * 2
        return hex_str[offset + 4:offset + 4 + data_len], 4 + data_len
    elif opcode == 0x4D:
        lo = int(hex_str[offset + 2:offset + 4], 16)
        hi = int(hex_str[offset + 4:offset + 6], 16)
        length = lo | (hi << 8)
        data_len = length * 2
        return hex_str[offset + 6:offset + 6 + data_len], 6 + data_len
    elif opcode == 0x4E:
        b = bytes.fromhex(hex_str[offset + 2:offset + 10])
        length = int.from_bytes(b, 'little')
        data_len = length * 2
        return hex_str[offset + 10:offset + 10 + data_len], 10 + data_len

    return '', 2


# ---------------------------------------------------------------------------
# Internal encode/decode for state values
# ---------------------------------------------------------------------------

# Type width map (bytes) for known fixed-width types
_TYPE_WIDTHS = {
    'PubKey': 33,
    'Addr': 20,
    'Ripemd160': 20,
    'Sha256': 32,
    'Point': 64,
    # runar-lang's P256Point / P384Point cast constructors hard-assert 64 / 96
    # bytes and all seven compilers emit them as fixed raw slices; framing them
    # instead deploys a state section 1-2 bytes long and the first spend fails.
    'P256Point': 64,
    'P384Point': 96,
}


def _encode_state_value(value, field_type: str, label: str = '?') -> str:
    if field_type in ('int', 'bigint'):
        if value is None:
            n = 0
        elif isinstance(value, str) and value.endswith('n'):
            # BigInt string from JSON without reviver (e.g. "0n", "1000n")
            n = int(value[:-1])
        else:
            n = int(value)
        return _encode_num2bin(n, 8, label)
    elif field_type in ('bool', 'boolean'):
        # 1 raw byte. The canonical Runar primitive name is `boolean` — that is
        # what every compiler writes into stateFields[].type, alongside
        # encoding 'bool1' / byteLength 1 — and 'bool' is an accepted alias.
        # Matching only on 'bool' meant a REAL boolean state field fell through
        # to the push-data branch below, where a Python bool is not a str and
        # became the empty string, i.e. a constant '00' — the deploy always
        # said False whatever the caller passed, and the first call that set
        # the flag built a continuation the covenant rejects.
        return '01' if value else '00'
    elif field_type in _TYPE_WIDTHS:
        # Fixed-size byte types: raw hex, no framing needed.
        return value if isinstance(value, str) else ''
    else:
        # Variable-length types (ByteString, etc.): use push-data encoding
        # so the decoder can determine the length.
        hex_val = value if isinstance(value, str) else ''
        if not hex_val:
            return '00'  # OP_0
        return encode_push_data_state(hex_val)


def _decode_state_value(hex_str: str, offset: int, field_type: str) -> tuple:
    if field_type in ('bool', 'boolean'):
        # 1 raw byte: 0x00 = False, 0x01 = True. Both spellings, matching
        # _encode_state_value — a reader that knows only 'bool' walks a real
        # boolean field as push data and desynchronises every field after it.
        if offset + 2 > len(hex_str):
            return False, 2
        byte = hex_str[offset:offset + 2]
        return byte != '00', 2
    elif field_type in ('int', 'bigint'):
        # 8 raw bytes LE sign-magnitude
        hex_width = 16  # 8 bytes * 2
        if offset + hex_width > len(hex_str):
            return 0, hex_width
        data = hex_str[offset:offset + hex_width]
        return _decode_num2bin(data), hex_width
    elif field_type in _TYPE_WIDTHS:
        w = _TYPE_WIDTHS[field_type] * 2  # hex chars
        data = hex_str[offset:offset + w] if offset + w <= len(hex_str) else ''
        return data, w
    else:
        # Unknown type: fall back to push-data decoding
        data, bytes_read = decode_push_data(hex_str, offset)
        return data, bytes_read
