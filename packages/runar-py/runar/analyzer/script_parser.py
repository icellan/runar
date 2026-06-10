"""Parse a hex-encoded Bitcoin Script into a list of ParsedOpcode.

Spec §4 (naming) and §6 (push encoding).
"""

from __future__ import annotations

from typing import List

from .types import (
    PUSH_ENCODING_DIRECT,
    PUSH_ENCODING_OPN,
    PUSH_ENCODING_PUSHDATA1,
    PUSH_ENCODING_PUSHDATA2,
    PUSH_ENCODING_PUSHDATA4,
    ParsedOpcode,
    RawScriptSpan,
)


# Canonical opcode-name table per spec §4.1
# Bytes not present here render as OP_UNKNOWN(0xNN).
_OPCODE_NAMES: dict = {
    0x00: "OP_0",
    0x4c: "OP_PUSHDATA1",
    0x4d: "OP_PUSHDATA2",
    0x4e: "OP_PUSHDATA4",
    0x4f: "OP_1NEGATE",
    0x51: "OP_1",
    0x52: "OP_2",
    0x53: "OP_3",
    0x54: "OP_4",
    0x55: "OP_5",
    0x56: "OP_6",
    0x57: "OP_7",
    0x58: "OP_8",
    0x59: "OP_9",
    0x5a: "OP_10",
    0x5b: "OP_11",
    0x5c: "OP_12",
    0x5d: "OP_13",
    0x5e: "OP_14",
    0x5f: "OP_15",
    0x60: "OP_16",
    0x61: "OP_NOP",
    0x63: "OP_IF",
    0x64: "OP_NOTIF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6a: "OP_RETURN",
    0x6b: "OP_TOALTSTACK",
    0x6c: "OP_FROMALTSTACK",
    0x6d: "OP_2DROP",
    0x6e: "OP_2DUP",
    0x6f: "OP_3DUP",
    0x70: "OP_2OVER",
    0x71: "OP_2ROT",
    0x72: "OP_2SWAP",
    0x73: "OP_IFDUP",
    0x74: "OP_DEPTH",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x77: "OP_NIP",
    0x78: "OP_OVER",
    0x79: "OP_PICK",
    0x7a: "OP_ROLL",
    0x7b: "OP_ROT",
    0x7c: "OP_SWAP",
    0x7d: "OP_TUCK",
    0x7e: "OP_CAT",
    0x7f: "OP_SPLIT",
    0x80: "OP_NUM2BIN",
    0x81: "OP_BIN2NUM",
    0x82: "OP_SIZE",
    0x83: "OP_INVERT",
    0x84: "OP_AND",
    0x85: "OP_OR",
    0x86: "OP_XOR",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0x8b: "OP_1ADD",
    0x8c: "OP_1SUB",
    0x8f: "OP_NEGATE",
    0x90: "OP_ABS",
    0x91: "OP_NOT",
    0x92: "OP_0NOTEQUAL",
    0x93: "OP_ADD",
    0x94: "OP_SUB",
    0x95: "OP_MUL",
    0x96: "OP_DIV",
    0x97: "OP_MOD",
    0x98: "OP_LSHIFT",
    0x99: "OP_RSHIFT",
    0x9a: "OP_BOOLAND",
    0x9b: "OP_BOOLOR",
    0x9c: "OP_NUMEQUAL",
    0x9d: "OP_NUMEQUALVERIFY",
    0x9e: "OP_NUMNOTEQUAL",
    0x9f: "OP_LESSTHAN",
    0xa0: "OP_GREATERTHAN",
    0xa1: "OP_LESSTHANOREQUAL",
    0xa2: "OP_GREATERTHANOREQUAL",
    0xa3: "OP_MIN",
    0xa4: "OP_MAX",
    0xa5: "OP_WITHIN",
    0xa6: "OP_RIPEMD160",
    0xa7: "OP_SHA1",
    0xa8: "OP_SHA256",
    0xa9: "OP_HASH160",
    0xaa: "OP_HASH256",
    0xab: "OP_CODESEPARATOR",
    0xac: "OP_CHECKSIG",
    0xad: "OP_CHECKSIGVERIFY",
    0xae: "OP_CHECKMULTISIG",
    0xaf: "OP_CHECKMULTISIGVERIFY",
}


def opcode_name(byte: int) -> str:
    name = _OPCODE_NAMES.get(byte)
    if name is not None:
        return name
    return f"OP_UNKNOWN(0x{byte:02x})"


def normalize_hex(hex_script: str) -> str:
    """Strip whitespace and lowercase; return canonical hex."""
    # Strip any whitespace anywhere (spaces, tabs, newlines).
    out_chars = []
    for ch in hex_script:
        if ch.isspace():
            continue
        out_chars.append(ch)
    return "".join(out_chars).lower()


def parse_script(hex_script: str) -> List[ParsedOpcode]:
    """Parse normalized lowercase-hex script bytes into ParsedOpcodes.

    Spec §6: truncated pushes silently use whatever data is available and
    stop the parser. No findings are emitted from this layer.
    """
    # Convert hex to bytes. Caller passes already-normalized hex.
    try:
        data = bytes.fromhex(hex_script)
    except ValueError:
        # Odd-length or invalid hex — treat as empty stream of bytes by
        # parsing as much as we can. The TS reference parses byte-by-byte
        # from the hex string; we mirror this by truncating to even length
        # then stopping on bad chars. The 8 canonical fixtures are all
        # valid hex, so this branch is defensive.
        clean = []
        for ch in hex_script:
            if ch in "0123456789abcdef":
                clean.append(ch)
            else:
                break
        if len(clean) % 2:
            clean.pop()
        data = bytes.fromhex("".join(clean))

    out: List[ParsedOpcode] = []
    i = 0
    n = len(data)

    while i < n:
        offset = i
        byte = data[i]
        i += 1

        # opN family: 0x00, 0x4f, 0x51..0x60 — no data payload.
        if byte == 0x00 or byte == 0x4f or (0x51 <= byte <= 0x60):
            out.append(
                ParsedOpcode(
                    offset=offset,
                    opcode=byte,
                    name=opcode_name(byte),
                    size=1,
                    push_encoding=PUSH_ENCODING_OPN,
                )
            )
            continue

        # Direct push 0x01..0x4b
        if 0x01 <= byte <= 0x4b:
            decl = byte
            avail = n - i
            payload_len = decl if avail >= decl else avail
            i += payload_len
            out.append(
                ParsedOpcode(
                    offset=offset,
                    opcode=byte,
                    name=f"PUSH_{decl}",
                    size=1 + payload_len,
                    data_length=decl,  # declared length, per spec §6.2 note
                    push_encoding=PUSH_ENCODING_DIRECT,
                    truncated=avail < decl,
                )
            )
            continue

        # OP_PUSHDATA1
        if byte == 0x4c:
            if i >= n:
                # Length prefix missing — emit as 0-length truncated push.
                out.append(
                    ParsedOpcode(
                        offset=offset,
                        opcode=byte,
                        name="OP_PUSHDATA1",
                        size=1,
                        data_length=0,
                        push_encoding=PUSH_ENCODING_PUSHDATA1,
                        truncated=True,
                    )
                )
                break
            decl = data[i]
            i += 1
            avail = n - i
            payload_len = decl if avail >= decl else avail
            i += payload_len
            out.append(
                ParsedOpcode(
                    offset=offset,
                    opcode=byte,
                    name="OP_PUSHDATA1",
                    size=2 + payload_len,
                    data_length=decl,
                    push_encoding=PUSH_ENCODING_PUSHDATA1,
                    truncated=avail < decl,
                )
            )
            continue

        # OP_PUSHDATA2 (LE)
        if byte == 0x4d:
            if i + 2 > n:
                out.append(
                    ParsedOpcode(
                        offset=offset,
                        opcode=byte,
                        name="OP_PUSHDATA2",
                        size=1,
                        data_length=0,
                        push_encoding=PUSH_ENCODING_PUSHDATA2,
                        truncated=True,
                    )
                )
                break
            decl = data[i] | (data[i + 1] << 8)
            i += 2
            avail = n - i
            payload_len = decl if avail >= decl else avail
            i += payload_len
            out.append(
                ParsedOpcode(
                    offset=offset,
                    opcode=byte,
                    name="OP_PUSHDATA2",
                    size=3 + payload_len,
                    data_length=decl,
                    push_encoding=PUSH_ENCODING_PUSHDATA2,
                    truncated=avail < decl,
                )
            )
            continue

        # OP_PUSHDATA4 (LE)
        if byte == 0x4e:
            if i + 4 > n:
                out.append(
                    ParsedOpcode(
                        offset=offset,
                        opcode=byte,
                        name="OP_PUSHDATA4",
                        size=1,
                        data_length=0,
                        push_encoding=PUSH_ENCODING_PUSHDATA4,
                        truncated=True,
                    )
                )
                break
            decl = (
                data[i]
                | (data[i + 1] << 8)
                | (data[i + 2] << 16)
                | (data[i + 3] << 24)
            )
            i += 4
            avail = n - i
            payload_len = decl if avail >= decl else avail
            i += payload_len
            out.append(
                ParsedOpcode(
                    offset=offset,
                    opcode=byte,
                    name="OP_PUSHDATA4",
                    size=5 + payload_len,
                    data_length=decl,
                    push_encoding=PUSH_ENCODING_PUSHDATA4,
                    truncated=avail < decl,
                )
            )
            continue

        # Non-push opcode
        out.append(
            ParsedOpcode(
                offset=offset,
                opcode=byte,
                name=opcode_name(byte),
                size=1,
            )
        )

    return out


def collapse_raw_script_spans(
    opcodes: List[ParsedOpcode], spans: List[RawScriptSpan]
) -> List[ParsedOpcode]:
    """Replace opcodes inside raw-span ranges with synthetic RAW_SPAN steps.

    Spec §12.
    """
    if not spans:
        return opcodes

    sorted_spans = sorted(spans, key=lambda s: s.offset)
    out: List[ParsedOpcode] = []
    span_idx = 0

    for op in opcodes:
        # Advance past any span that ends at or before this opcode.
        while span_idx < len(sorted_spans) and (
            sorted_spans[span_idx].offset + sorted_spans[span_idx].length
        ) <= op.offset:
            span_idx += 1

        if span_idx >= len(sorted_spans):
            out.append(op)
            continue

        span = sorted_spans[span_idx]
        span_end = span.offset + span.length
        op_end = op.offset + op.size

        if op_end <= span.offset:
            # Opcode entirely before the span.
            out.append(op)
            continue

        if op.offset >= span.offset and op_end <= span_end:
            # Opcode entirely inside span — drop; emit synthetic step
            # if not already emitted for this span.
            if not out or out[-1].opcode != -1 or out[-1].offset != span.offset:
                out.append(
                    ParsedOpcode(
                        offset=span.offset,
                        opcode=-1,
                        name="RAW_SPAN",
                        size=span.length,
                        raw_span_arity=(span.in_arity, span.out_arity),
                    )
                )
            continue

        # Partial overlap — drop opcode, emit synthetic step once.
        if not out or out[-1].opcode != -1 or out[-1].offset != span.offset:
            out.append(
                ParsedOpcode(
                    offset=span.offset,
                    opcode=-1,
                    name="RAW_SPAN",
                    size=span.length,
                    raw_span_arity=(span.in_arity, span.out_arity),
                )
            )

    return out
