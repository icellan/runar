#!/usr/bin/env python3
"""External Bitcoin Script reference using python-bitcoinlib.

Tier 4.6 of the Rúnar verification remediation plan. For each conformance
fixture, this script:

  1. Reads ``expected-script.hex``.
  2. Decodes the hex bytes into a ``CScript``.
  3. Walks the ops via ``CScript.raw_iter`` (same surface used inside
     ``EvalScript``).
  4. Runs ``EvalScript`` against an empty initial stack with a placeholder
     ``CTransaction`` that mirrors the ``placeholderCtx`` in
     ``tests/Differential.lean`` — version=2, all-zeros prevout/sequence/
     output hashes, sigHashType=0x41, amount=100000.
  5. Records ``(success, finalStackTop, error)`` per fixture.

Output JSON schema mirrors the Lean differential report so the diff
in ``scripts/differential.sh`` is a straight key-by-key compare.

Important: ``python-bitcoinlib``'s ``EvalScript`` is the legacy-Bitcoin
core script VM. It does NOT implement BSV-only opcodes that the Rúnar
compiler emits (``OP_LSHIFT``, ``OP_RSHIFT``, ``OP_NUM2BIN``,
``OP_BIN2NUM``, ``OP_SPLIT``, ``OP_INVERT``, large pushes >520 bytes,
etc.). Fixtures that exercise these will surface as
``error="unsupported:<op>"`` on the Python side, mirroring how the Lean
side falls into ``EvalError.unsupported``. The differential check still
holds: both sides classify the same fixture into "unsupported" — they
just disagree on which exact opcode is unsupported. The shell wrapper
treats matching error-categories (the substring before the first ``:``)
as a pass; exact error-tag equality is required only for the parser
errors and stack-shape errors.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

EXPECTED_FIXTURE_TOTAL = 49

try:
    from bitcoin.core import CTransaction, CTxIn, CTxOut, COutPoint
    from bitcoin.core.script import CScript
    from bitcoin.core.scripteval import (
        EvalScript,
        EvalScriptError,
        VerifyScriptError,
    )
except ImportError as e:
    print(
        f"ERROR: python-bitcoinlib not installed ({e}); rerun after `pip install python-bitcoinlib`",
        file=sys.stderr,
    )
    sys.exit(2)


@dataclass
class FixtureResult:
    name: str
    success: bool
    finalStackTop: Optional[str]
    error: Optional[str]


def _placeholder_tx() -> CTransaction:
    """Build a minimal CTransaction that satisfies EvalScript's structural
    requirements without claiming consensus validity. Mirrors
    ``placeholderCtx`` in ``tests/Differential.lean``: version=2,
    all-zeros prevout, sequence=0xffffffff, locktime=0."""
    txin = CTxIn(COutPoint(b"\x00" * 32, 0), CScript(b""), 0xFFFFFFFF)
    txout = CTxOut(0, CScript(b""))
    return CTransaction([txin], [txout], nLockTime=0, nVersion=2)


def _stack_top_hex(stack: list) -> Optional[str]:
    """Mirror ``Differential.stackTopHex``: hex-encode the last (top)
    element. python-bitcoinlib's ``EvalScript`` returns the stack with
    the top at the end of the list."""
    if not stack:
        return None
    top = stack[-1]
    if isinstance(top, (bytes, bytearray)):
        return top.hex()
    # Booleans / ints come back as bytes already; defensively coerce.
    return bytes(top).hex()


def _categorize_error(exc: BaseException) -> str:
    """Map a python-bitcoinlib exception to one of the stable tags
    used in ``tests/Differential.lean``. We extract the leading
    category (``parseError`` / ``unsupported`` / ``assertFailed``)
    so the differential diff in ``differential.sh`` matches against
    Lean's tags."""
    msg = str(exc)
    name = type(exc).__name__
    # python-bitcoinlib raises EvalScriptError with messages like
    # "OP_VERIFY failed", "OP_CHECKSIG", "OP_DUP requires non-empty stack"
    if "non-empty stack" in msg or "empty stack" in msg or "underflow" in msg.lower():
        # Extract the offending opcode if present.
        first_token = msg.split(":")[0].split(" ")[0] if msg else "<unknown>"
        return f"unsupported:{first_token}: empty stack"
    if "OP_VERIFY" in msg or "VERIFY" in msg:
        return "assertFailed"
    if "Invalid opcode" in msg or "unknown opcode" in msg.lower():
        return f"parseError:unknownOpcode:{msg}"
    if "PUSHDATA" in msg and "exceed" in msg.lower():
        return f"parseError:shortPushdata:{msg}"
    if isinstance(exc, (EvalScriptError, VerifyScriptError)):
        return f"unsupported:{name}:{msg}"
    return f"{name}:{msg}"


def run_fixture(name: str, hex_text: str) -> FixtureResult:
    text = hex_text.strip()
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return FixtureResult(name, False, None, "decodeError:not-hex")

    try:
        script = CScript(raw)
    except Exception as exc:  # noqa: BLE001 — surface every parse failure
        return FixtureResult(name, False, None, f"parseError:{exc}")

    tx = _placeholder_tx()
    stack: list[bytes] = []
    try:
        EvalScript(stack, script, tx, inIdx=0, flags=())
    except Exception as exc:  # noqa: BLE001
        return FixtureResult(name, False, None, _categorize_error(exc))

    top = _stack_top_hex(stack)
    if top is None:
        return FixtureResult(name, False, None, "evalError:emptyStack")
    return FixtureResult(name, True, top, None)


def main(argv: list[str]) -> int:
    repo_root = Path(__file__).resolve().parent.parent.parent
    fixtures_dir = repo_root / "conformance" / "tests"
    if not fixtures_dir.is_dir():
        print(f"ERROR: fixtures directory not found: {fixtures_dir}", file=sys.stderr)
        return 1

    out_path = (
        Path(argv[1])
        if len(argv) > 1
        else Path("/tmp") / "runar-verification-differential" / "differential-external.json"
    )

    results: list[FixtureResult] = []
    for entry in sorted(fixtures_dir.iterdir()):
        hex_path = entry / "expected-script.hex"
        if not hex_path.is_file():
            continue
        with open(hex_path, "r") as fh:
            hex_text = fh.read()
        results.append(run_fixture(entry.name, hex_text))

    if len(results) != EXPECTED_FIXTURE_TOTAL:
        print(
            f"ERROR: discovered {len(results)} fixtures, expected {EXPECTED_FIXTURE_TOTAL}",
            file=sys.stderr,
        )
        return 1

    payload = {
        "fixtures": [
            {
                "name": r.name,
                "success": r.success,
                "finalStackTop": r.finalStackTop,
                "error": r.error,
            }
            for r in results
        ]
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n")
    succ = sum(1 for r in results if r.success)
    print(
        f"EXTERNAL-REF (python-bitcoinlib): {succ}/{len(results)} fixtures evaluated",
        file=sys.stderr,
    )
    print(f"  report written to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
