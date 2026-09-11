"""Script utilities — constructor arg extraction and artifact matching.

Ports extractConstructorArgs() and matchesArtifact() from the TypeScript SDK.
"""

from __future__ import annotations

from runar.sdk.types import RunarArtifact
from runar.sdk.state import find_last_op_return


# ---------------------------------------------------------------------------
# Script element reading
# ---------------------------------------------------------------------------

def _read_script_element(
    hex_str: str, offset: int
) -> tuple[str, int, int]:
    """Read a single script element at the given hex offset.

    Returns (data_hex, total_hex_chars, opcode).
    """
    opcode = int(hex_str[offset:offset + 2], 16)

    if opcode == 0x00:
        return '', 2, opcode
    if 0x01 <= opcode <= 0x4B:
        data_len = opcode * 2
        return hex_str[offset + 2:offset + 2 + data_len], 2 + data_len, opcode
    if opcode == 0x4C:
        length = int(hex_str[offset + 2:offset + 4], 16)
        data_len = length * 2
        return hex_str[offset + 4:offset + 4 + data_len], 4 + data_len, opcode
    if opcode == 0x4D:
        lo = int(hex_str[offset + 2:offset + 4], 16)
        hi = int(hex_str[offset + 4:offset + 6], 16)
        length = lo | (hi << 8)
        data_len = length * 2
        return hex_str[offset + 6:offset + 6 + data_len], 6 + data_len, opcode
    if opcode == 0x4E:
        b0 = int(hex_str[offset + 2:offset + 4], 16)
        b1 = int(hex_str[offset + 4:offset + 6], 16)
        b2 = int(hex_str[offset + 6:offset + 8], 16)
        b3 = int(hex_str[offset + 8:offset + 10], 16)
        length = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        data_len = length * 2
        return hex_str[offset + 10:offset + 10 + data_len], 10 + data_len, opcode

    # Single-byte opcode (no data)
    return '', 2, opcode


def _decode_script_number(data_hex: str) -> int:
    """Decode a Bitcoin Script number from hex (sign-magnitude LE)."""
    if not data_hex:
        return 0
    byte_list: list[int] = []
    for i in range(0, len(data_hex), 2):
        byte_list.append(int(data_hex[i:i + 2], 16))

    negative = (byte_list[-1] & 0x80) != 0
    byte_list[-1] &= 0x7F

    result = 0
    for i in range(len(byte_list) - 1, -1, -1):
        result = (result << 8) | byte_list[i]

    if result == 0:
        return 0
    return -result if negative else result


# How a constructor-slot value of a given ABI type is encoded in the script.
#
# TABLE, not a hand-maintained ``if`` chain: the two spellings missing from the
# old chain -- the ``bigint`` aliases ``RabinSig`` / ``RabinPubKey``, and the
# CANONICAL ``boolean`` (only the ``bool`` alias was handled) -- each silently
# turned a value into a hex string on the way back off chain. Mirrors
# ``packages/runar-ir-schema/src/abi-type-encoding.ts``, the same table the
# compiler stamps ``ConstructorSlot.valueEncoding`` from.
_ABI_VALUE_ENCODINGS = {
    'bigint': 'scriptnum',
    'int': 'scriptnum',
    # RabinSig / RabinPubKey are bigint aliases; ``verifyRabinSig`` lowers to
    # OP_MOD, which reads its operand as a little-endian sign-magnitude Script
    # number -- exactly what ``bigint`` gets.
    'RabinSig': 'scriptnum',
    'RabinPubKey': 'scriptnum',
    # ``boolean`` is canonical; ``bool`` is the alias several frontends spell.
    'boolean': 'bool',
    'bool': 'bool',
}


def _abi_value_encoding(type_name: str) -> str:
    """Classify an ABI type name: 'scriptnum', 'bool', or 'data'.

    ByteString and every fixed-width byte type default to 'data' (a raw push).
    """
    return _ABI_VALUE_ENCODINGS.get(type_name, 'data')


def _interpret_script_element(opcode: int, data_hex: str, field_type: str) -> object:
    """Interpret a script element based on the ABI parameter type."""
    encoding = _abi_value_encoding(field_type)
    if encoding == 'scriptnum':
        if opcode == 0x00:
            return 0
        if 0x51 <= opcode <= 0x60:
            return opcode - 0x50
        if opcode == 0x4F:
            return -1
        return _decode_script_number(data_hex)
    elif encoding == 'bool':
        if opcode == 0x00:
            return False
        if opcode == 0x51:
            return True
        return data_hex != '00'
    else:
        # S1: a ByteString (or other non-numeric) ctor arg whose 1-byte value
        # was MINIMALDATA-encoded as OP_1..OP_16 / OP_1NEGATE carries no
        # separate data bytes in the script — ``_read_script_element`` reports
        # an empty ``data_hex`` for these opcodes (they aren't direct pushes or
        # OP_PUSHDATA*). The opcode itself IS the value; reconstruct it instead
        # of forwarding the (empty) data_hex. OP_0 correctly falls through to
        # ``data_hex`` (the empty string), matching OP_0's true semantics
        # (pushes ``[]``, not a 1-byte ``0x00``).
        if 0x51 <= opcode <= 0x60:
            return f'{opcode - 0x50:02x}'
        if opcode == 0x4F:
            return '81'
        return data_hex


# ---------------------------------------------------------------------------
# Constructor arg extraction
# ---------------------------------------------------------------------------

def extract_constructor_args(
    artifact: RunarArtifact,
    script_hex: str,
) -> dict:
    """Extract constructor argument values from a compiled on-chain script.

    Uses artifact.constructor_slots to locate each constructor arg at its
    byte offset, reads the push data, and deserializes according to the
    ABI param type.
    """
    if not artifact.constructor_slots:
        return {}

    code_hex = script_hex
    if artifact.state_fields:
        op_return_pos = find_last_op_return(script_hex)
        if op_return_pos != -1:
            code_hex = script_hex[:op_return_pos]

    # Walk EVERY slot in byte order. A constructor param referenced more than
    # once in the contract body emits one slot per reference, and each
    # occurrence's encoded width contributes to the cumulative offset shift --
    # deduplicating before the walk drops those widths and mis-aligns every
    # later slot on artifacts with repeated references. The VALUE is taken
    # from the first occurrence per param.
    slots = sorted(artifact.constructor_slots, key=lambda s: s.byte_offset)

    result: dict = {}
    assigned: set[int] = set()
    cumulative_shift = 0

    for slot in slots:
        adjusted_hex_offset = (slot.byte_offset + cumulative_shift) * 2
        data_hex, total_hex_chars, opcode = _read_script_element(code_hex, adjusted_hex_offset)
        # Template placeholders are exactly 1 byte, so the shift contributed by
        # each occurrence is its encoded width minus that byte.
        cumulative_shift += total_hex_chars // 2 - 1

        if slot.param_index in assigned:
            continue
        assigned.add(slot.param_index)
        if slot.param_index >= len(artifact.abi.constructor_params):
            continue
        param = artifact.abi.constructor_params[slot.param_index]
        result[param.name] = _interpret_script_element(opcode, data_hex, param.type)

    return result


def restore_constructor_args(
    artifact: RunarArtifact,
    script_hex: str,
) -> list:
    """Recover the positional constructor argument list from a deployed locking
    script (issue #119), so a restored contract (``from_utxo`` / ``from_txid``)
    operates on the real baked-in values rather than ``0`` placeholders.

    ``extract_constructor_args`` returns a name→value map keyed by ABI param
    name; ``abi.constructor_params`` is already ordered by paramIndex, so
    mapping over it yields the positional list the ``RunarContract`` constructor
    expects.

    Params that carry no constructor slot (mutable state fields — their value
    lives in the OP_RETURN state section, restored separately) are absent from
    the extracted map; they fall back to ``0``, matching the prior placeholder
    behaviour, and are immediately overwritten by ``extract_state_from_script``.
    """
    params = artifact.abi.constructor_params
    if not params:
        return []
    extracted = extract_constructor_args(artifact, script_hex)
    return [extracted[p.name] if p.name in extracted else 0 for p in params]


# ---------------------------------------------------------------------------
# Script matching
# ---------------------------------------------------------------------------

def matches_artifact(
    artifact: RunarArtifact,
    script_hex: str,
) -> bool:
    """Determine whether a given on-chain script was produced from the given
    contract artifact (regardless of what constructor args were used).
    """
    code_hex = script_hex
    if artifact.state_fields:
        op_return_pos = find_last_op_return(script_hex)
        if op_return_pos != -1:
            code_hex = script_hex[:op_return_pos]

    template = artifact.script

    if not artifact.constructor_slots:
        return code_hex == template

    # Deduplicate by byte_offset, keeping first occurrence
    seen_offsets: set[int] = set()
    slots = sorted(artifact.constructor_slots, key=lambda s: s.byte_offset)
    unique_slots = []
    for slot in slots:
        if slot.byte_offset not in seen_offsets:
            seen_offsets.add(slot.byte_offset)
            unique_slots.append(slot)

    template_pos = 0
    code_pos = 0

    for slot in unique_slots:
        slot_hex_offset = slot.byte_offset * 2
        template_segment = template[template_pos:slot_hex_offset]
        code_segment = code_hex[code_pos:code_pos + len(template_segment)]
        if template_segment != code_segment:
            return False
        template_pos = slot_hex_offset + 2
        elem_offset = code_pos + len(template_segment)
        _, total_hex_chars, _ = _read_script_element(code_hex, elem_offset)
        code_pos = elem_offset + total_hex_chars

    return template[template_pos:] == code_hex[code_pos:]
