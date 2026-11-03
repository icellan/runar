"""Opcode-concerns checks per spec §10."""

from __future__ import annotations

from typing import List

from .types import (
    PUSH_ENCODING_PUSHDATA1,
    PUSH_ENCODING_PUSHDATA2,
    PUSH_ENCODING_PUSHDATA4,
    Finding,
    ParsedOpcode,
)


LARGE_SCRIPT_THRESHOLD = 500_000


def _format_kb(n: int) -> str:
    """Format `n / 1024` with exactly one digit after decimal, matching
    JS `(n / 1024).toFixed(1)`.

    Per ECMA-262, toFixed picks the integer k for which k/10 - value is
    closest to zero, and on an exact tie picks the LARGER k -
    round-half-up (ties away from zero for our non-negative n), not
    IEEE-754 round-half-to-even. Verified live:
    `node -e "console.log((500992/1024).toFixed(1))"` prints "489.3",
    where round-half-to-even would give "489.2".

    Canonical formula (spec §5.1): `k = round_half_up(n * 10 / 1024) / 10`.
    """
    # n is a non-negative integer here.
    numer = n * 10
    denom = 1024
    q, r = divmod(numer, denom)
    # Doubled remainder vs denom for half comparison.
    doubled = r * 2
    if doubled >= denom:
        tenths_total = q + 1
    else:
        tenths_total = q
    int_part, tenth = divmod(tenths_total, 10)
    return f"{int_part}.{tenth}"


def analyze_opcode_concerns(
    opcodes: List[ParsedOpcode], script_size_bytes: int
) -> List[Finding]:
    findings: List[Finding] = []

    # LARGE_SCRIPT (spec §10): emit once if scriptSizeBytes > threshold.
    if script_size_bytes > LARGE_SCRIPT_THRESHOLD:
        kb = _format_kb(script_size_bytes)
        findings.append(
            Finding(
                severity="info",
                code="LARGE_SCRIPT",
                message=(
                    f"Script is {script_size_bytes} bytes ({kb} KB) — "
                    "consider if this is intentional"
                ),
            )
        )

    # CODESEPARATOR_PRESENT (spec §10): one per OP_CODESEPARATOR (0xab).
    for op in opcodes:
        if op.opcode == 0xab:
            findings.append(
                Finding(
                    severity="info",
                    code="CODESEPARATOR_PRESENT",
                    message=(
                        "OP_CODESEPARATOR found — expected for stateful "
                        "contracts, unusual otherwise"
                    ),
                    offset=op.offset,
                    opcode=op.name,
                )
            )

    # INEFFICIENT_PUSH (spec §6.2 + §10):
    # pushdata1 with data_length <= 75
    # pushdata2 with data_length <= 255
    # pushdata4 with data_length <= 65535
    for op in opcodes:
        enc = op.push_encoding
        n = op.data_length
        if enc is None or n is None:
            continue
        if enc == PUSH_ENCODING_PUSHDATA1 and n <= 75:
            hh = f"0x{n:02x}"
            findings.append(
                Finding(
                    severity="info",
                    code="INEFFICIENT_PUSH",
                    message=(
                        f"OP_PUSHDATA1 used for {n}-byte data — "
                        f"direct push (opcode {hh}) would be more efficient"
                    ),
                    offset=op.offset,
                    opcode=op.name,
                )
            )
        elif enc == PUSH_ENCODING_PUSHDATA2 and n <= 255:
            findings.append(
                Finding(
                    severity="info",
                    code="INEFFICIENT_PUSH",
                    message=(
                        f"OP_PUSHDATA2 used for {n}-byte data — "
                        "OP_PUSHDATA1 would be more efficient"
                    ),
                    offset=op.offset,
                    opcode=op.name,
                )
            )
        elif enc == PUSH_ENCODING_PUSHDATA4 and n <= 65535:
            findings.append(
                Finding(
                    severity="info",
                    code="INEFFICIENT_PUSH",
                    message=(
                        f"OP_PUSHDATA4 used for {n}-byte data — "
                        "OP_PUSHDATA2 would be more efficient"
                    ),
                    offset=op.offset,
                    opcode=op.name,
                )
            )

    return findings
