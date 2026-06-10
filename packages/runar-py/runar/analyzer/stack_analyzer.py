"""Linear stack-effect analysis per spec §8."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .types import Finding, ParsedOpcode


# Per-opcode (pops, pushes), spec §8.1
_STACK_EFFECTS: dict = {
    0x61: (0, 0),  # OP_NOP
    0x63: (1, 0),  # OP_IF
    0x64: (1, 0),  # OP_NOTIF
    0x67: (0, 0),  # OP_ELSE
    0x68: (0, 0),  # OP_ENDIF
    0x69: (1, 0),  # OP_VERIFY
    0x6a: (0, 0),  # OP_RETURN
    0x6b: (1, 0),  # OP_TOALTSTACK
    0x6c: (0, 1),  # OP_FROMALTSTACK
    0x6d: (2, 0),  # OP_2DROP
    0x6e: (2, 4),  # OP_2DUP
    0x6f: (3, 6),  # OP_3DUP
    0x70: (4, 6),  # OP_2OVER
    0x71: (6, 6),  # OP_2ROT
    0x72: (4, 4),  # OP_2SWAP
    0x73: (1, 1),  # OP_IFDUP
    0x74: (0, 1),  # OP_DEPTH
    0x75: (1, 0),  # OP_DROP
    0x76: (1, 2),  # OP_DUP
    0x77: (2, 1),  # OP_NIP
    0x78: (2, 3),  # OP_OVER
    0x79: (1, 1),  # OP_PICK
    0x7a: (1, 0),  # OP_ROLL
    0x7b: (3, 3),  # OP_ROT
    0x7c: (2, 2),  # OP_SWAP
    0x7d: (2, 3),  # OP_TUCK
    0x7e: (2, 1),  # OP_CAT
    0x7f: (2, 2),  # OP_SPLIT
    0x80: (2, 1),  # OP_NUM2BIN
    0x81: (1, 1),  # OP_BIN2NUM
    0x82: (1, 2),  # OP_SIZE
    0x83: (1, 1),  # OP_INVERT
    0x84: (2, 1),  # OP_AND
    0x85: (2, 1),  # OP_OR
    0x86: (2, 1),  # OP_XOR
    0x87: (2, 1),  # OP_EQUAL
    0x88: (2, 0),  # OP_EQUALVERIFY
    0x8b: (1, 1),  # OP_1ADD
    0x8c: (1, 1),  # OP_1SUB
    0x8f: (1, 1),  # OP_NEGATE
    0x90: (1, 1),  # OP_ABS
    0x91: (1, 1),  # OP_NOT
    0x92: (1, 1),  # OP_0NOTEQUAL
    0x93: (2, 1),  # OP_ADD
    0x94: (2, 1),  # OP_SUB
    0x95: (2, 1),  # OP_MUL
    0x96: (2, 1),  # OP_DIV
    0x97: (2, 1),  # OP_MOD
    0x98: (2, 1),  # OP_LSHIFT
    0x99: (2, 1),  # OP_RSHIFT
    0x9a: (2, 1),  # OP_BOOLAND
    0x9b: (2, 1),  # OP_BOOLOR
    0x9c: (2, 1),  # OP_NUMEQUAL
    0x9d: (2, 0),  # OP_NUMEQUALVERIFY
    0x9e: (2, 1),  # OP_NUMNOTEQUAL
    0x9f: (2, 1),  # OP_LESSTHAN
    0xa0: (2, 1),  # OP_GREATERTHAN
    0xa1: (2, 1),  # OP_LESSTHANOREQUAL
    0xa2: (2, 1),  # OP_GREATERTHANOREQUAL
    0xa3: (2, 1),  # OP_MIN
    0xa4: (2, 1),  # OP_MAX
    0xa5: (3, 1),  # OP_WITHIN
    0xa6: (1, 1),  # OP_RIPEMD160
    0xa7: (1, 1),  # OP_SHA1
    0xa8: (1, 1),  # OP_SHA256
    0xa9: (1, 1),  # OP_HASH160
    0xaa: (1, 1),  # OP_HASH256
    0xac: (2, 1),  # OP_CHECKSIG
    0xad: (2, 0),  # OP_CHECKSIGVERIFY
    0xae: (3, 1),  # OP_CHECKMULTISIG
    0xaf: (3, 0),  # OP_CHECKMULTISIGVERIFY
}


def _is_push(op: ParsedOpcode) -> bool:
    """Any push operation contributes (0, 1)."""
    return op.push_encoding is not None


def stack_effect(op: ParsedOpcode) -> Tuple[int, int]:
    """Return (pops, pushes) for the given opcode, per spec §8.1."""
    if op.opcode == -1:
        # Synthetic RAW_SPAN step
        if op.raw_span_arity is not None:
            return (op.raw_span_arity[0], op.raw_span_arity[1])
        return (0, 0)
    if _is_push(op):
        return (0, 1)
    return _STACK_EFFECTS.get(op.opcode, (0, 0))


@dataclass
class LinearResult:
    findings: List[Finding]
    final_depth: int
    max_depth: int
    after_return: bool


def analyze_stack_linear(
    opcodes: List[ParsedOpcode], initial_depth: int = 0
) -> LinearResult:
    """Linear stack analysis (spec §8.2).

    Returns final depth, max depth, after_return state, and any findings
    (STACK_UNDERFLOW + UNREACHABLE_AFTER_RETURN).
    """
    depth = initial_depth
    max_depth = depth
    after_return = False
    findings: List[Finding] = []

    for op in opcodes:
        if after_return:
            findings.append(
                Finding(
                    severity="warning",
                    code="UNREACHABLE_AFTER_RETURN",
                    message=f"Unreachable opcode {op.name} after OP_RETURN",
                    offset=op.offset,
                    opcode=op.name,
                )
            )
            continue

        if op.opcode == 0x6a:  # OP_RETURN
            after_return = True
            continue

        pops, pushes = stack_effect(op)

        # Underflow check: only when initial_depth > 0 AND depth < pops.
        if initial_depth > 0 and depth < pops:
            findings.append(
                Finding(
                    severity="error",
                    code="STACK_UNDERFLOW",
                    message=(
                        f"{op.name} requires {pops} stack item(s) but only "
                        f"{depth} available"
                    ),
                    offset=op.offset,
                    opcode=op.name,
                )
            )

        depth = depth - pops + pushes
        if depth > max_depth:
            max_depth = depth

    return LinearResult(
        findings=findings,
        final_depth=depth,
        max_depth=max_depth,
        after_return=after_return,
    )
