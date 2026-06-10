"""Signature-hygiene checks per spec §9."""

from __future__ import annotations

from typing import List

from .types import ExecutionPath, Finding, ParsedOpcode


def analyze_sig_hygiene(
    opcodes: List[ParsedOpcode], paths: List[ExecutionPath]
) -> List[Finding]:
    findings: List[Finding] = []

    # NO_SIG_CHECK: one per reachable path with has_check_sig == False.
    for p in paths:
        if p.reachable and not p.has_check_sig:
            findings.append(
                Finding(
                    severity="warning",
                    code="NO_SIG_CHECK",
                    message=(
                        "Execution path has no signature verification "
                        "(OP_CHECKSIG/OP_CHECKMULTISIG)"
                    ),
                    path=p.description,
                )
            )

    # CHECKSIG_RESULT_DROPPED: OP_CHECKSIG/CHECKMULTISIG immediately
    # followed by OP_DROP.
    for i in range(len(opcodes) - 1):
        op = opcodes[i]
        if op.opcode in (0xac, 0xae):  # OP_CHECKSIG, OP_CHECKMULTISIG
            nxt = opcodes[i + 1]
            if nxt.opcode == 0x75:  # OP_DROP
                findings.append(
                    Finding(
                        severity="warning",
                        code="CHECKSIG_RESULT_DROPPED",
                        message=(
                            f"{op.name} result is dropped by {nxt.name} — "
                            "signature check has no effect"
                        ),
                        offset=op.offset,
                        opcode=op.name,
                    )
                )

    return findings
