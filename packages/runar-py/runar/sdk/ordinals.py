"""1sat ordinals support — build and parse inscription envelopes, BSV-20/BSV-21 helpers.

Envelope layout:
  OP_FALSE OP_IF PUSH("ord") OP_1 PUSH(<content-type>) OP_0 PUSH(<data>) OP_ENDIF

Hex:
  00 63 03 6f7264 51 <push content-type> 00 <push data> 68

The envelope is a no-op (OP_FALSE causes the IF block to be skipped)
and can be placed anywhere in a script without affecting execution.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class Inscription:
    """Inscription data: content type and hex-encoded payload."""
    content_type: str
    data: str  # hex-encoded content


@dataclass
class EnvelopeBounds:
    """Hex-char offsets bounding an inscription envelope within a script."""
    start_hex: int
    end_hex: int


# ---------------------------------------------------------------------------
# Push-data encoding (mirrors state.py encode_push_data, kept local to
# avoid circular imports)
# ---------------------------------------------------------------------------

def _encode_push_data(data_hex: str) -> str:
    """Wrap hex data in a Bitcoin Script push data opcode."""
    if not data_hex:
        return '00'  # OP_0
    data_len = len(data_hex) // 2

    if data_len <= 75:
        return f'{data_len:02x}' + data_hex
    elif data_len <= 0xFF:
        return '4c' + f'{data_len:02x}' + data_hex
    elif data_len <= 0xFFFF:
        return '4d' + data_len.to_bytes(2, 'little').hex() + data_hex
    else:
        return '4e' + data_len.to_bytes(4, 'little').hex() + data_hex


def _utf8_to_hex(s: str) -> str:
    """Convert a UTF-8 string to its hex representation."""
    return s.encode('utf-8').hex()


def _hex_to_utf8(h: str) -> str:
    """Convert a hex string to UTF-8."""
    return bytes.fromhex(h).decode('utf-8')


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_inscription_envelope(content_type: str, data: str) -> str:
    """Build a 1sat ordinals inscription envelope as hex.

    Args:
        content_type: MIME type (e.g. "image/png", "application/bsv-20")
        data: Hex-encoded inscription content

    Returns:
        Hex string of the full envelope script fragment.
    """
    content_type_hex = _utf8_to_hex(content_type)

    # OP_FALSE (00) OP_IF (63) PUSH "ord" (03 6f7264) OP_1 (51)
    hex_str = '006303' + '6f7264' + '51'
    # PUSH content-type
    hex_str += _encode_push_data(content_type_hex)
    # OP_0 (00) -- content delimiter
    hex_str += '00'
    # PUSH data
    hex_str += _encode_push_data(data)
    # OP_ENDIF (68)
    hex_str += '68'

    return hex_str


# ---------------------------------------------------------------------------
# Parse / Find
# ---------------------------------------------------------------------------

def _read_push_data(script_hex: str, offset: int) -> Optional[tuple[str, int]]:
    """Read a push-data value at the given hex offset.

    Returns (data_hex, hex_chars_consumed) or None if invalid.
    """
    if offset + 2 > len(script_hex):
        return None
    opcode = int(script_hex[offset:offset + 2], 16)

    if 0x01 <= opcode <= 0x4B:
        data_len = opcode * 2
        if offset + 2 + data_len > len(script_hex):
            return None
        return script_hex[offset + 2:offset + 2 + data_len], 2 + data_len

    elif opcode == 0x4C:
        # OP_PUSHDATA1
        if offset + 4 > len(script_hex):
            return None
        length = int(script_hex[offset + 2:offset + 4], 16)
        data_len = length * 2
        if offset + 4 + data_len > len(script_hex):
            return None
        return script_hex[offset + 4:offset + 4 + data_len], 4 + data_len

    elif opcode == 0x4D:
        # OP_PUSHDATA2
        if offset + 6 > len(script_hex):
            return None
        lo = int(script_hex[offset + 2:offset + 4], 16)
        hi = int(script_hex[offset + 4:offset + 6], 16)
        length = lo | (hi << 8)
        data_len = length * 2
        if offset + 6 + data_len > len(script_hex):
            return None
        return script_hex[offset + 6:offset + 6 + data_len], 6 + data_len

    elif opcode == 0x4E:
        # OP_PUSHDATA4
        if offset + 10 > len(script_hex):
            return None
        b0 = int(script_hex[offset + 2:offset + 4], 16)
        b1 = int(script_hex[offset + 4:offset + 6], 16)
        b2 = int(script_hex[offset + 6:offset + 8], 16)
        b3 = int(script_hex[offset + 8:offset + 10], 16)
        length = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        data_len = length * 2
        if offset + 10 + data_len > len(script_hex):
            return None
        return script_hex[offset + 10:offset + 10 + data_len], 10 + data_len

    return None


def _opcode_size(script_hex: str, offset: int) -> int:
    """Compute the number of hex chars an opcode occupies (including push data)."""
    if offset + 2 > len(script_hex):
        return 2
    opcode = int(script_hex[offset:offset + 2], 16)

    if 0x01 <= opcode <= 0x4B:
        return 2 + opcode * 2
    elif opcode == 0x4C:
        if offset + 4 > len(script_hex):
            return 2
        length = int(script_hex[offset + 2:offset + 4], 16)
        return 4 + length * 2
    elif opcode == 0x4D:
        if offset + 6 > len(script_hex):
            return 2
        lo = int(script_hex[offset + 2:offset + 4], 16)
        hi = int(script_hex[offset + 4:offset + 6], 16)
        return 6 + (lo | (hi << 8)) * 2
    elif opcode == 0x4E:
        if offset + 10 > len(script_hex):
            return 2
        b0 = int(script_hex[offset + 2:offset + 4], 16)
        b1 = int(script_hex[offset + 4:offset + 6], 16)
        b2 = int(script_hex[offset + 6:offset + 8], 16)
        b3 = int(script_hex[offset + 8:offset + 10], 16)
        return 10 + (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) * 2

    return 2  # all other opcodes are 1 byte


def find_inscription_envelope(script_hex: str) -> Optional[EnvelopeBounds]:
    """Find the inscription envelope within a script hex string.

    Walks the script as Bitcoin Script opcodes looking for the pattern:
      OP_FALSE(00) OP_IF(63) PUSH3 "ord"(03 6f7264) ...

    Returns hex-char offsets of the envelope, or None if not found.
    """
    offset = 0
    length = len(script_hex)

    while offset + 2 <= length:
        opcode = int(script_hex[offset:offset + 2], 16)

        # Look for OP_FALSE (0x00)
        if opcode == 0x00:
            # Check: OP_IF (63) PUSH3 (03) "ord" (6f7264)
            if (
                offset + 12 <= length
                and script_hex[offset + 2:offset + 4] == '63'   # OP_IF
                and script_hex[offset + 4:offset + 12] == '036f7264'  # PUSH3 "ord"
            ):
                envelope_start = offset
                # Skip: OP_FALSE(2) + OP_IF(2) + PUSH3 "ord"(8) = 12 hex chars
                pos = offset + 12

                # Expect OP_1 (0x51)
                if pos + 2 > length or script_hex[pos:pos + 2] != '51':
                    offset += 2
                    continue
                pos += 2  # skip OP_1

                # Read content-type push
                ct_push = _read_push_data(script_hex, pos)
                if ct_push is None:
                    offset += 2
                    continue
                pos += ct_push[1]

                # Expect OP_0 (0x00) -- content delimiter
                if pos + 2 > length or script_hex[pos:pos + 2] != '00':
                    offset += 2
                    continue
                pos += 2  # skip OP_0

                # Read data push
                data_push = _read_push_data(script_hex, pos)
                if data_push is None:
                    offset += 2
                    continue
                pos += data_push[1]

                # Expect OP_ENDIF (0x68)
                if pos + 2 > length or script_hex[pos:pos + 2] != '68':
                    offset += 2
                    continue
                pos += 2  # skip OP_ENDIF

                return EnvelopeBounds(start_hex=envelope_start, end_hex=pos)

        # Advance past this opcode
        offset += _opcode_size(script_hex, offset)

    return None


def parse_inscription_envelope(script_hex: str) -> Optional[Inscription]:
    """Parse an inscription envelope from a script hex string.

    Returns the inscription data, or None if no envelope is found.
    """
    bounds = find_inscription_envelope(script_hex)
    if bounds is None:
        return None

    envelope_hex = script_hex[bounds.start_hex:bounds.end_hex]

    # Parse the envelope contents:
    # 00 63 03 6f7264 51 <ct-push> 00 <data-push> 68
    pos = 12  # skip OP_FALSE + OP_IF + PUSH3 "ord"
    pos += 2  # skip OP_1

    ct_push = _read_push_data(envelope_hex, pos)
    if ct_push is None:
        return None
    pos += ct_push[1]

    pos += 2  # skip OP_0

    data_push = _read_push_data(envelope_hex, pos)
    if data_push is None:
        return None

    return Inscription(
        content_type=_hex_to_utf8(ct_push[0]),
        data=data_push[0],
    )


def strip_inscription_envelope(script_hex: str) -> str:
    """Remove the inscription envelope from a script, returning the bare script.

    Returns the script hex with the envelope removed, or the original if none found.
    """
    bounds = find_inscription_envelope(script_hex)
    if bounds is None:
        return script_hex
    return script_hex[:bounds.start_hex] + script_hex[bounds.end_hex:]


# ---------------------------------------------------------------------------
# BSV-20 (v1) -- tick-based fungible tokens
# ---------------------------------------------------------------------------

def _json_inscription(obj: dict) -> Inscription:
    """Create an inscription from a JSON-serializable dict."""
    return Inscription(
        content_type='application/bsv-20',
        data=_utf8_to_hex(json.dumps(obj, separators=(',', ':'))),
    )


def bsv20_deploy(
    tick: str,
    max_supply: str,
    lim: Optional[str] = None,
    dec: Optional[str] = None,
) -> Inscription:
    """Build a BSV-20 deploy inscription.

    Args:
        tick: Token ticker (e.g. "RUNAR")
        max_supply: Maximum supply as string
        lim: Optional mint limit per transaction
        dec: Optional decimal precision
    """
    obj: dict = {
        'p': 'bsv-20',
        'op': 'deploy',
        'tick': tick,
        'max': max_supply,
    }
    if lim is not None:
        obj['lim'] = lim
    if dec is not None:
        obj['dec'] = dec
    return _json_inscription(obj)


def bsv20_mint(tick: str, amt: str) -> Inscription:
    """Build a BSV-20 mint inscription."""
    return _json_inscription({
        'p': 'bsv-20',
        'op': 'mint',
        'tick': tick,
        'amt': amt,
    })


def bsv20_transfer(tick: str, amt: str) -> Inscription:
    """Build a BSV-20 transfer inscription."""
    return _json_inscription({
        'p': 'bsv-20',
        'op': 'transfer',
        'tick': tick,
        'amt': amt,
    })


# ---------------------------------------------------------------------------
# BSV-21 (v2) -- ID-based fungible tokens
# ---------------------------------------------------------------------------

def bsv21_deploy_mint(
    amt: str,
    dec: Optional[str] = None,
    sym: Optional[str] = None,
    icon: Optional[str] = None,
) -> Inscription:
    """Build a BSV-21 deploy+mint inscription.

    The token ID will be ``<txid>_<vout>`` of the output containing
    this inscription once broadcast.
    """
    obj: dict = {
        'p': 'bsv-20',
        'op': 'deploy+mint',
        'amt': amt,
    }
    if dec is not None:
        obj['dec'] = dec
    if sym is not None:
        obj['sym'] = sym
    if icon is not None:
        obj['icon'] = icon
    return _json_inscription(obj)


def bsv21_transfer(token_id: str, amt: str) -> Inscription:
    """Build a BSV-21 transfer inscription.

    Args:
        token_id: Token ID in format ``<txid>_<vout>``
        amt: Transfer amount as string
    """
    return _json_inscription({
        'p': 'bsv-20',
        'op': 'transfer',
        'id': token_id,
        'amt': amt,
    })
