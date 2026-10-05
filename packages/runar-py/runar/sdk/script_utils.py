"""Script utilities — constructor arg extraction and artifact matching.

Ports extractConstructorArgs() and matchesArtifact() from the TypeScript SDK.
"""

from __future__ import annotations

from runar.sdk.errors import MalformedScriptError
from runar.sdk.types import RunarArtifact
from runar.sdk.state import find_last_op_return


# ---------------------------------------------------------------------------
# Script element reading
# ---------------------------------------------------------------------------

def _need(hex_str: str, offset: int, chars: int, what: str) -> None:
    """Raise :class:`MalformedScriptError` unless ``chars`` hex chars are
    available from ``offset`` (F-238). Mirrors the Java tier's
    ``ScriptUtils.need`` guard -- the pattern already used for the on-chain
    state-section reader, applied here to the push-data reader used by
    constructor-arg extraction and artifact matching.
    """
    if offset + chars > len(hex_str):
        remaining = max(0, len(hex_str) - offset)
        raise MalformedScriptError(
            f"_read_script_element: truncated script -- {what} runs past the end "
            f"(needs {chars // 2} byte(s) at hex offset {offset}, only {remaining // 2} remain)"
        )


def _read_script_element(
    hex_str: str, offset: int
) -> tuple[str, int, int]:
    """Read a single script element at the given hex offset.

    Returns (data_hex, total_hex_chars, opcode).

    Raises :class:`MalformedScriptError` (F-238) if the opcode byte itself,
    an OP_PUSHDATA1/2/4 length prefix, or the declared push payload runs past
    the end of ``hex_str`` -- a provider-supplied script is untrusted input,
    and a truncated push must never come back as a short, silently-wrong
    ``data_hex`` (it would also desynchronise every later slot's offset in
    the caller's walk).
    """
    _need(hex_str, offset, 2, 'push opcode')
    try:
        opcode = int(hex_str[offset:offset + 2], 16)
    except ValueError as exc:
        raise MalformedScriptError(
            f"_read_script_element: non-hex byte at hex offset {offset}"
        ) from exc

    if opcode == 0x00:
        return '', 2, opcode
    if 0x01 <= opcode <= 0x4B:
        data_len = opcode * 2
        _need(hex_str, offset, 2 + data_len, 'push payload')
        return hex_str[offset + 2:offset + 2 + data_len], 2 + data_len, opcode
    if opcode == 0x4C:
        _need(hex_str, offset, 4, 'OP_PUSHDATA1 length prefix')
        length = int(hex_str[offset + 2:offset + 4], 16)
        data_len = length * 2
        _need(hex_str, offset, 4 + data_len, 'OP_PUSHDATA1 payload')
        return hex_str[offset + 4:offset + 4 + data_len], 4 + data_len, opcode
    if opcode == 0x4D:
        _need(hex_str, offset, 6, 'OP_PUSHDATA2 length prefix')
        lo = int(hex_str[offset + 2:offset + 4], 16)
        hi = int(hex_str[offset + 4:offset + 6], 16)
        length = lo | (hi << 8)
        data_len = length * 2
        _need(hex_str, offset, 6 + data_len, 'OP_PUSHDATA2 payload')
        return hex_str[offset + 6:offset + 6 + data_len], 6 + data_len, opcode
    if opcode == 0x4E:
        _need(hex_str, offset, 10, 'OP_PUSHDATA4 length prefix')
        b0 = int(hex_str[offset + 2:offset + 4], 16)
        b1 = int(hex_str[offset + 4:offset + 6], 16)
        b2 = int(hex_str[offset + 6:offset + 8], 16)
        b3 = int(hex_str[offset + 8:offset + 10], 16)
        length = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        data_len = length * 2
        _need(hex_str, offset, 10 + data_len, 'OP_PUSHDATA4 payload')
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

    # Every OP_0 placeholder the SDK substitutes at deploy time -- constructor
    # args AND codeSepIndex slots -- is a variable element in the deployed
    # code. Skipping the codeSepIndex slots made every stateful artifact that
    # carries one (the placeholder bakes as OP_1) fail to match its own
    # honest deployment. Deduplicated, ascending.
    offsets = sorted(
        {s.byte_offset for s in artifact.constructor_slots}
        | {s.byte_offset for s in artifact.code_sep_index_slots}
    )

    # N-051: a `code_part_len_slots` field holds the DEPLOYED code-part length,
    # not the template's placeholder value. It must equal the length of the
    # code part being matched (everything before the state section,
    # inscription envelope included).
    len_fields = {s.byte_offset * 2 for s in artifact.code_part_len_slots}
    deployed_len = ((len(code_hex) // 2) & 0xFFFFFFFF).to_bytes(4, 'little').hex()

    def segment_matches(t_start: int, t_end: int, c_start: int) -> bool:
        t = t_start
        c = c_start
        while t < t_end:
            if t in len_fields:
                if c + 8 > len(code_hex) or code_hex[c:c + 8] != deployed_len:
                    return False
                t += 8
                c += 8
                continue
            if c >= len(code_hex) or template[t] != code_hex[c]:
                return False
            t += 1
            c += 1
        return True

    template_pos = 0
    code_pos = 0

    for offset in offsets:
        slot_hex_offset = offset * 2
        seg_len = slot_hex_offset - template_pos
        if code_pos + seg_len > len(code_hex):
            return False
        if not segment_matches(template_pos, slot_hex_offset, code_pos):
            return False
        template_pos = slot_hex_offset + 2
        elem_offset = code_pos + seg_len
        _, total_hex_chars, _ = _read_script_element(code_hex, elem_offset)
        code_pos = elem_offset + total_hex_chars

    return (
        len(code_hex) - code_pos == len(template) - template_pos
        and segment_matches(template_pos, len(template), code_pos)
    )
